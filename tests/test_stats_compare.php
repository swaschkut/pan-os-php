<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 */

/**
 * StatsCompare (lib/misc-classes/StatsCompare.php): the compare of two stats results - used by
 * type=playbook-validation compare-stats-… and by the config viewer (stats compare of two runs).
 *
 *   php tests/test_stats_compare.php
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/misc-classes/StatsCompare.php';
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

// ---- the two forms of a stats result
$blockA = array( 'type' => 'PanoramaConf', 'header' => "Statistics for PanoramaConf 'full'", 'security rules' => 9, 'log at end' => 9, 'calc' => '9/9',
    'percentage' => array( 'visibility' => array( 'Logging' => array( 'value' => 100, 'group' => 'Logging' ) ) ) );
$blockB = array( 'type' => 'DeviceGroup', 'header' => "BP/Visibility Statistics for DeviceGroup 'dg1'", 'security rules' => 3 );
$folder = array( $blockA, $blockB );                                                                          // json-to-folder / debugapi
$shadow = array( 'PAN-OS-PHP' => array(), 'statistic' => array( array( $blockA['header'] => $blockA, $blockB['header'] => $blockB ) ) );   // shadow-json
$eq( array( array_keys( StatsCompare::blocks( $folder ) ), array_keys( StatsCompare::blocks( $shadow ) ) ),
    array( array( $blockA['header'], $blockB['header'] ), array( $blockA['header'], $blockB['header'] ) ), 'blocks by their header, from both forms of the JSON' );
$r = StatsCompare::compare( $folder, $shadow );
$eq( array( $r['equal'], $r['same'], $r['changed'], $r['blocks'] ), array( TRUE, TRUE, 0, array() ), 'the same figures in both forms: no difference' );
$eq( array( StatsCompare::blocks( null ), StatsCompare::blocks( 'text' ), StatsCompare::blocks( array( 'statistic' => 'x' ) ) ), array( array(), array(), array() ), 'not a stats result: no blocks' );
$eq( StatsCompare::flat( $blockA )['percentage / visibility / Logging / value'] ?? null, 100, 'a nested figure gets its path as name' );

// ---- what differs, what only one has
$other = $folder;
$other[0]['security rules'] = 8;                                          // changed
$other[0]['percentage']['visibility']['Logging']['value'] = 50;          // changed, nested
unset( $other[0]['log at end'] );                                         // only in A
$other[1]['new figure'] = 1;                                              // only in B
$other[] = array( 'header' => 'a block only B has', 'x' => 1 );
$r = StatsCompare::compare( $folder, $other );
$eq( array( $r['equal'], $r['same'], $r['changed'], $r['only_a'], $r['only_b'], $r['blocks_only_a'], $r['blocks_only_b'], $r['blocks_a'], $r['blocks_b'] ),
    array( FALSE, FALSE, 2, 1, 1, array(), array( 'a block only B has' ), 2, 3 ), 'counts: 2 changed, 1 only in A, 1 only in B, one block only in B' );
$eq( $r['blocks'][$blockA['header']], array( 'changed' => array( 'security rules' => array( 'from' => 9, 'to' => 8 ), 'percentage / visibility / Logging / value' => array( 'from' => 100, 'to' => 50 ) ),
    'only_a' => array( 'log at end' => 9 ), 'only_b' => array() ), 'a block: changed figures with from / to, the figure only A has' );
$eq( $r['blocks'][$blockB['header']], array( 'changed' => array(), 'only_a' => array(), 'only_b' => array( 'new figure' => 1 ) ), 'a block where only B has a figure more' );
// only-in-one alone: equal (as compare-stats always meant) but not the same
$more = $folder; $more[1]['new figure'] = 1;
$r = StatsCompare::compare( $folder, $more );
$eq( array( $r['equal'], $r['same'] ), array( TRUE, FALSE ), 'a figure only one result has: "equal" stays (no common figure differs), "same" is false' );
// value and type: 9 and "9" are different, as before
$typed = $folder; $typed[0]['security rules'] = '9';
$eq( StatsCompare::compare( $folder, $typed )['changed'], 1, 'a number and the same number as text differ' );
// the same header twice is kept apart
$twice = array( array( 'header' => 'h', 'x' => 1 ), array( 'header' => 'h', 'x' => 2 ) );
$eq( array_keys( StatsCompare::blocks( $twice ) ), array( 'h', 'h #2' ), 'the same header twice: two blocks' );

// ---- visibility not 100 % (compare-stats-not-100)
$pct = array( 'visibility' => array( 'Logging' => array( 'value' => 100, 'group' => 'Logging' ), 'Antivirus Profiles' => array( 'value' => 40, 'group' => 'Threat Prevention' ),
    'URL Filtering Profiles' => array( 'value' => 'N/A', 'group' => 'URL' ), 'App-ID' => array( 'value' => 10, 'group' => 'Apps, Users, Ports' ),
    'Zone Protection' => array( 'value' => 0, 'group' => 'Zone Protection' ) ), 'best-practice' => array( 'Logging' => array( 'value' => 20, 'group' => 'Logging' ) ) );
$full = array( 'header' => 'whole configuration', 'percentage' => $pct );
$eq( StatsCompare::notFull( $full ), array( 'Antivirus Profiles' => array( 'value' => 40, 'group' => 'Threat Prevention' ) ),
    'not 100 %: only what is not 100 - without "N/A" and without the components left out (App-ID, Zone Protection, …)' );
$eq( array( array_keys( StatsCompare::notFull( $full, 'best-practice' ) ), array_keys( StatsCompare::notFull( $full, 'visibility', array() ) ), StatsCompare::notFull( array( 'header' => 'x' ) ) ),
    array( array( 'Logging' ), array( 'Antivirus Profiles', 'App-ID', 'Zone Protection' ), array() ), 'not 100 %: another part, no exclusions, a block without percentages' );
// the first block of a result is the whole configuration - in both forms of the JSON (the old index statistic[0][0]
// does not exist in the form with headers: the check of the command line found nothing)
$shadowPct = array( 'statistic' => array( array( 'whole configuration' => $full, 'dg1' => array( 'header' => 'dg1', 'percentage' => $pct ) ) ) );
$b1 = StatsCompare::blocks( $shadowPct ); $b2 = StatsCompare::blocks( array( $full ) );
$eq( array( isset( $shadowPct['statistic'][0][0] ), array_keys( StatsCompare::notFull( reset( $b1 ) ) ), array_keys( StatsCompare::notFull( reset( $b2 ) ) ) ),
    array( FALSE, array( 'Antivirus Profiles' ), array( 'Antivirus Profiles' ) ), 'not 100 % of the first block, from both forms' );
// two results next to each other: B has brought Antivirus to 100, and has a component A does not know
$fullB = $full; $fullB['percentage']['visibility']['Antivirus Profiles']['value'] = 100;
$fullB['percentage']['visibility']['New Component'] = array( 'value' => 50, 'group' => 'New' );
$eq( StatsCompare::notFullBoth( array( $full ), array( $fullB ) ), array(
        array( 'block' => 'whole configuration', 'name' => 'Antivirus Profiles', 'group' => 'Threat Prevention', 'a' => 40, 'b' => 100 ),
        array( 'block' => 'whole configuration', 'name' => 'New Component', 'group' => 'New', 'a' => null, 'b' => 50 ) ),
    'not 100 % of two results: every component that is not 100 in one of them, with the value of both' );
$eq( StatsCompare::notFullBoth( array( $fullB ), array( $fullB ), 'visibility', array() )[0]['name'] ?? null, 'App-ID', 'not 100 % of two results: own list of exclusions' );

// ---- type=playbook-validation compare-stats-dev-beta uses it (synthetic working folder)
$dir = sys_get_temp_dir() . '/statscmp-' . getmypid();
foreach( array( 'origin', 'dev', 'beta', 'validation_files/playbook', 'validation_files/bp_setting' ) as $d )
    mkdir( $dir . '/' . $d, 0700, TRUE );
copy( $repo . '/tests/input/panorama-10.0-merger.xml', $dir . '/origin/c.xml' );
file_put_contents( $dir . '/validation_files/playbook/visibility.json', '{"command":[]}' );
file_put_contents( $dir . '/validation_files/bp_setting/02b_scm_bp_sp_panw.json', '{}' );
$cli = function( $devJson, $betaJson ) use ( $dir, $repo ) {
    file_put_contents( $dir . '/dev/c_stats.txt', json_encode( $devJson ) );
    file_put_contents( $dir . '/beta/c_stats.txt', json_encode( $betaJson ) );
    $out = array();
    exec( 'cd ' . escapeshellarg( $dir ) . ' && ' . escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=playbook-validation compare-stats-dev-beta tool=local 2>&1', $out );
    return implode( "\n", $out );
};
$otherShadow = $shadow;
$otherShadow['statistic'][0][$blockA['header']]['security rules'] = 8;
unset( $otherShadow['statistic'][0][$blockA['header']]['log at end'] );
$out = $cli( $shadow, $otherShadow );
$eq( array( (bool)preg_match( '/"security rules": \{\s*"from": 9,\s*"to": 8\s*\}/', $out ), strpos( $out, 'stats: => diff for c.xml' ) !== FALSE,
        strpos( $out, 'only in one of the two files' ) !== FALSE && strpos( $out, '"log at end"' ) !== FALSE ),
    array( TRUE, TRUE, TRUE ), 'compare-stats-dev-beta: the changed figure with from / to, the configuration counts as different, the figure only one file has is listed' );
$onlyMore = $shadow; $onlyMore['statistic'][0][$blockA['header']]['new figure'] = 1;
$out = $cli( $shadow, $onlyMore );
$eq( array( strpos( $out, 'stats: => diff for c.xml' ), strpos( $out, 'only in one of the two files' ) !== FALSE ), array( FALSE, TRUE ),
    'compare-stats-dev-beta: a figure only one file has is listed but is no difference (as before)' );
exec( 'rm -rf ' . escapeshellarg( $dir ) );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
