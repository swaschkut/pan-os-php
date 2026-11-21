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

// ---- copies with the same name and value in sibling device groups (do not see each other)
$sib = $repo . '/tests/input/merger/siblings-panorama.xml';
$om = function( $opts ) use ( $run, $sib, $dir ) {
    @unlink( $dir . '/sib.json' );
    $run( 'type=object-merger in=' . escapeshellarg( $sib ) . ' out=sib.xml objecttype=address location=any exportjson=sib.json ' . $opts );
    return json_decode( (string)@file_get_contents( $dir . '/sib.json' ), TRUE );
};
$j = $om( '' );
$ok( count( $j['merged'] ) === 0 && strpos( $j['skipped'][0]['reason'][0] ?? '', "common parent 'shared': needs allowMergingWithUpperLevel" ) !== FALSE && ( $j['skipped'][0]['key'] ?? '' ) === 'name: web01',
    'object-merger: sibling copies without allowMergingWithUpperLevel - not merged, with the reason (before: nothing said)' );
$j = $om( 'allowmergingwithupperlevel DupAlgorithm=Identical' );
$ok( count( $j['merged'] ) === 0 && strpos( $j['skipped'][0]['reason'][0] ?? '', "DupAlgorithm 'identical' does not create the object in the common parent 'shared'" ) !== FALSE,
    'object-merger: sibling copies with DupAlgorithm Identical - not merged, with the reason' );
$j = $om( 'allowmergingwithupperlevel' );
$ok( ( $j['merged'][0]['kept']['location'] ?? '' ) === 'shared' && count( $j['merged'][0]['removed'] ?? array() ) === 2 && count( $j['skipped'] ) === 0,
    'object-merger: sibling copies with allowMergingWithUpperLevel - created in the common parent, both removed' );
$run( 'type=merger-possible-report in=' . escapeshellarg( $sib ) . ' objecttype=address mergecheck exportjson=sibpr.json' );
$j = json_decode( (string)@file_get_contents( $dir . '/sibpr.json' ), TRUE );
$f = $j['findings'][0] ?? array();
$ok( ( $f['status'] ?? '' ) === 'merge-into-parent' && ( $f['parent'] ?? '' ) === 'shared' && ( $f['intoParent'] ?? null ) === array( 'DG-B:web01' ) && ( $j['summary']['address']['merge-into-parent'] ?? 0 ) === 1,
    'merger-possible-report: sibling copies - status merge-into-parent with the common parent (before: not-checked)' );

// ---- MergeSafety as data (the Explain of the config viewer): the check that refused a merge, with the resolution
// of the name level by level before / after and the simulated changes
$sh = $repo . '/tests/input/merger/safety-shadowed-panorama.xml';
$run( 'type=object-merger in=' . escapeshellarg( $sh ) . ' out=sh.xml objecttype=address location=DG-P ' . escapeshellarg( 'pickFilter=(name eq web2)' ) . ' exportjson=sh.json' );
$j = json_decode( (string)@file_get_contents( $dir . '/sh.json' ), TRUE );
$d = $j['skipped'][0]['safety'][0] ?? array();
$ok( ( $d['copy'] ?? '' ) === 'DG-P:web' && ( $d['firewalls'] ?? '' ) === 'DG-C' && ( $d['usedBy']['kind'] ?? '' ) === 'group' && ( $d['usedBy']['name'] ?? '' ) === 'G'
    && ( $d['before']['content'] ?? null ) === array( '10.9.9.9' ) && ( $d['after']['content'] ?? null ) === array( '10.1.1.1' ),
    'MergeSafety detail: firewalls, user of the name, content before / after' );
$lv = $d['before']['resolution'][0]['levels'] ?? array();
$ok( array_column( $lv, 'location' ) === array( 'DG-C', 'DG-P', 'shared' ) && array_column( $lv, 'state' ) === array( 'found', 'found', 'none' )
    && ( $d['before']['resolution'][0]['result']['location'] ?? '' ) === 'DG-C' && ( $d['after']['resolution'][0]['result']['location'] ?? '' ) === 'DG-P',
    'MergeSafety detail: resolution level by level - before the copy of DG-C shadows DG-P, after the kept object of DG-P' );
$ok( ( $d['changes']['removed'] ?? null ) === array( 'DG-P:web' ) && ( $d['changes']['memberRenamed'][0] ?? null ) === array( 'group' => 'DG-P:G', 'from' => 'web', 'to' => 'web2' ),
    'MergeSafety detail: the simulated changes (removed, member renamed)' );
$lp = $repo . '/tests/input/merger/safety-group-loop-panorama.xml';
$run( 'type=addressgroup-merger in=' . escapeshellarg( $lp ) . ' out=lp.xml location=DG-P ' . escapeshellarg( 'pickFilter=(name eq G-B)' ) . ' dupalgorithm=sameIP4mapping exportjson=lp.json' );
$j = json_decode( (string)@file_get_contents( $dir . '/lp.json' ), TRUE );
$d = $j['skipped'][0]['safety'][0] ?? array();
$mb = $d['after']['resolution'][0]['result']['members'][0] ?? array();
$ok( strpos( $j['skipped'][0]['reason'][0] ?? '', 'after []' ) !== FALSE && ( $d['after']['content'] ?? null ) === array() && ( $mb['renamedTo'] ?? '' ) === 'G-B' && !empty( $mb['loop'] ),
    'MergeSafety detail: "after []" of a group that would contain itself - the member marked as loop' );
$run( 'type=merger-possible-report in=' . escapeshellarg( $sh ) . ' objecttype=address mergecheck exportjson=shpr.json' );
$j = json_decode( (string)@file_get_contents( $dir . '/shpr.json' ), TRUE );
$bl = array();
foreach( $j['findings'] ?? array() as $f )
    foreach( $f['blocked'] ?? array() as $b )
        $bl[] = $b;
$ok( count( $bl ) > 0 && isset( $bl[0]['detail']['before']['resolution'], $bl[0]['detail']['after']['content'] ), 'merger-possible-report: a blocked copy carries the MergeSafety detail' );

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
