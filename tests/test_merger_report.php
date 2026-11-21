<?php
/**
 * The report of the mergers as data (MergerReport): exportJSON= / shadow-json carry the same report as the HTML of
 * exportCSV= - one source for the command line and the config viewer. Synthetic configurations only.
 *
 *   php tests/test_merger_report.php
 */
$repo = dirname( __DIR__ );
$checks = 0; $failed = array();
$ok = function( $cond, $msg ) use ( &$checks, &$failed ) { $checks++; print ( $cond ? "ok   " : "FAIL " ) . $msg . "\n"; if( !$cond ) $failed[] = $msg; };
$dir = sys_get_temp_dir() . '/mergerreport-' . getmypid();
@mkdir( $dir );
$run = function( $args ) use ( $repo, $dir ) {
    exec( 'cd ' . escapeshellarg( $dir ) . ' && ' . escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . $args . ' 2>&1', $o, $rc );
    return array( $rc, implode( "\n", $o ) );
};
// the data rows of an exportCSV HTML: a row whose first cell is its number
$rows = function( $file ) { $h = (string)@file_get_contents( $file ); return preg_match_all( '#<tr[^>]*>\s*<td[^>]*>[0-9]+</td>#', $h ); };
$pan = $repo . '/tests/input/panorama-10.0-merger.xml';

// ---- object-merger: the HTML rows and the JSON entries are the same data
list( $rc, $o ) = $run( 'type=object-merger in=' . escapeshellarg( $pan ) . ' out=om.xml objecttype=address,service location=any allowmergingwithupperlevel exportcsv=om.html exportjson=om.json' );
$j = json_decode( (string)@file_get_contents( $dir . '/om.json' ), TRUE );
$ok( $rc === 0 && is_array( $j ) && $j['type'] === 'object-merger', 'object-merger: exportJSON written' );
$ok( count( $j['merged'] ) === $rows( $dir . '/om.html' ) && count( $j['skipped'] ) === $rows( $dir . '/skipped-om.html' ), 'object-merger: as many entries as HTML rows (merged ' . count( $j['merged'] ) . ', skipped ' . count( $j['skipped'] ) . ')' );
$m = $j['merged'][0];
$ok( $m['objecttype'] === 'address' && $m['kept']['location'] !== '' && $m['kept']['name'] !== '' && strpos( (string)file_get_contents( $dir . '/om.html' ), htmlspecialchars( $m['removed'][0]['text'], ENT_QUOTES ) ) !== FALSE,
    'object-merger: kept / removed with location and name; the HTML shows the same text' );
$sk = array_values( array_filter( $j['skipped'], function( $x ) { return count( $x['reason'] ) > 0; } ) );
$ok( count( $sk ) > 0 && strpos( (string)file_get_contents( $dir . '/skipped-om.html' ), htmlspecialchars( trim( $sk[0]['reason'][0] ), ENT_QUOTES ) ) !== FALSE, 'object-merger: the reason of a skipped object, also in the HTML' );
$ok( $j['summary']['address']['merged'] === count( array_filter( $j['merged'], function( $x ) { return $x['objecttype'] === 'address'; } ) ), 'object-merger: summary per object type' );
list( $rc, $o ) = $run( 'type=object-merger in=' . escapeshellarg( $pan ) . ' objecttype=address location=any shadow-json' );
$sj = json_decode( substr( $o, (int)strpos( $o, '{' ) ), TRUE );
$ok( isset( $sj['merger-report']['merged'], $sj['merger-report']['summary']['address'] ), 'object-merger: shadow-json carries the report as data' );

// ---- rule-merger: merged rules, a skipped rule with its reason (also in the HTML), the field values
$fw = $repo . '/tests/input/merger/rule-merger-fw.xml';
list( $rc, $o ) = $run( 'type=rule-merger in=' . escapeshellarg( $fw ) . ' out=rm.xml location=vsys1 method=matchFromToSrcDstApp ' . escapeshellarg( 'filter=!(name eq r3)' ) . ' exportcsv=rm.html exportjson=rm.json' );
$j = json_decode( (string)@file_get_contents( $dir . '/rm.json' ), TRUE );
$ok( $rc === 0 && $j['type'] === 'rule-merger' && $j['summary'] === array( 'merged' => 1, 'removed' => 1, 'skipped' => 1 ), 'rule-merger: summary (1 kept, 1 merged into it, 1 not merged)' );
$ok( $j['merged'][0]['rule'] === 'r1' && $j['merged'][0]['removed'][0]['name'] === 'r2' && $j['merged'][0]['after']['service'] === array( 'tcp-81', 'tcp-82' )
    && $j['merged'][0]['before']['service'] === array( 'tcp-81' ) && $j['merged'][0]['location'] === 'vsys1', 'rule-merger: kept rule, merged rule, fields before / after' );
$n = $j['skipped'][0]['notMergedWith'][0] ?? array();
$ok( ( $n['name'] ?? '' ) === 'r3' && strpos( $n['reason'] ?? '', 'not matchin the filter query' ) !== FALSE, 'rule-merger: not merged with r3 - the reason' );
$ok( strpos( (string)file_get_contents( $dir . '/skipped-rm.html' ), 'not matchin the filter query' ) !== FALSE && strpos( (string)file_get_contents( $dir . '/rm.html' ), 'tcp-82' ) !== FALSE,
    'rule-merger: the HTML from the same values (reason row, field values)' );

// ---- merger-possible-report
list( $rc, $o ) = $run( 'type=merger-possible-report in=' . escapeshellarg( $pan ) . ' objecttype=address mergecheck exportjson=pr.json' );
$j = json_decode( (string)@file_get_contents( $dir . '/pr.json' ), TRUE );
$ok( $rc === 0 && $j['type'] === 'merger-possible-report' && isset( $j['summary']['address'] ) && count( $j['findings'] ) > 0 && isset( $j['findings'][0]['copies'] ), 'merger-possible-report: summary and findings' );
$st = array_count_values( array_column( $j['findings'], 'status' ) );
$conf = array_values( array_filter( $j['findings'], function( $f ) { return $f['kind'] === 'same name, different value'; } ) );
$okf = array_values( array_filter( $j['findings'], function( $f ) { return $f['status'] === 'merge-ok'; } ) );
$ok( isset( $st['conflict'], $st['merge-ok'] ) && ( $conf[0]['status'] ?? '' ) === 'conflict' && ( $okf[0]['keep'] ?? '' ) !== '' && is_array( $okf[0]['blocked'] ?? null ),
    'merger-possible-report: status per finding (conflict, merge-ok, …), the kept copy, the blocked copies with the reason' );
list( $rc, $o ) = $run( 'type=merger-possible-report in=' . escapeshellarg( $pan ) . ' objecttype=address mergecheck exportcsv=pr.html' );
$ok( strpos( (string)@file_get_contents( $dir . '/pr.html' ), '<th>merge</th>' ) !== FALSE && strpos( (string)@file_get_contents( $dir . '/pr.html' ), '<td>conflict</td>' ) !== FALSE,
    'merger-possible-report: the HTML shows the same status' );

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
