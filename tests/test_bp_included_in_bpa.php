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
 * 'included-in-bpa' of the BP JSON: which components the BPA diagram shows. A component that is not named there is
 * removed - so the names have to be the ones pan-os-php uses (bp_sp_panw.json had three of them misspelled: these
 * components were never shown). There is no code that accepts a misspelled name: the BP file is corrected.
 *
 *   php tests/test_bp_included_in_bpa.php
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

$panos = json_decode( file_get_contents( $repo . '/utils/api/v1/bp/bp_sp_panw.json' ), TRUE );
$scm = json_decode( file_get_contents( $repo . '/utils/api/v1/bp/scm_bp_sp_panw.json' ), TRUE );

// the names of the diagram: the keys of get_bp_percentageArray (StatCollectorTrait), "/" written as "_" in the JSON
$source = file_get_contents( $repo . '/lib/misc-classes/trait/StatCollectorTrait.php' );
$names = array();
foreach( array( 'adoption', 'visibility', 'best_practice' ) as $part )
{
    preg_match_all( '/\$percentageArray_' . $part . "\['([^']+)'\]\['value'\]/", $source, $m );
    $names[str_replace( '_', '-', $part )] = array_values( array_unique( array_map( function( $n ) { return str_replace( '/', '_', $n ); }, $m[1] ) ) );
}
$eq( count( $names['adoption'] ) > 10 && count( $names['visibility'] ) > 10 && count( $names['best-practice'] ) > 5, TRUE, 'the names of the diagram are read from StatCollectorTrait' );

$unknown = array();
foreach( array( 'bp_sp_panw.json' => $panos, 'scm_bp_sp_panw.json' => $scm ) as $file => $json )
    foreach( array( 'adoption', 'visibility', 'best-practice' ) as $part )
        foreach( array_keys( $json['included-in-bpa'][$part] ) as $key )
            // a name of another part (URL InLine ML under best-practice) has no effect, but is no misspelling
            if( !in_array( $key, array_merge( $names['adoption'], $names['visibility'], $names['best-practice'] ), TRUE ) )
                $unknown[] = $file . ' ' . $part . ': ' . $key;
$eq( $unknown, array(), "every name of 'included-in-bpa' in the two BP files is a component of the diagram" );

$run = function( array $included ) {
    PH::$shadow_bp_jsonfile = array( 'included-in-bpa' => array( 'adoption' => $included, 'visibility' => $included, 'best-practice' => $included ) );
    $all = array_fill_keys( array( 'Logging', 'Log Forwarding Profiles', 'Wildfire Analysis Profiles', 'Credential Theft Prevention', 'Service/Port', 'DNS Security' ), array( 'value' => 50 ) );
    $out = array( 'percentage' => array( 'adoption' => $all, 'visibility' => $all, 'best-practice' => $all ) );
    PH::validateIncludedInBPA( $out );
    return array_keys( $out['percentage']['adoption'] );
};
$eq( $run( array( 'Logging' => TRUE, 'Log Forwarding Profiles' => TRUE, 'Wildfire Analysis Profiles' => TRUE, 'Credential Theft Prevention' => TRUE, 'Service_Port' => TRUE, 'DNS Security' => FALSE ) ),
    array( 'Logging', 'Log Forwarding Profiles', 'Wildfire Analysis Profiles', 'Credential Theft Prevention', 'Service/Port' ), 'true: shown; false: removed' );
$eq( $run( array( 'Logging' => TRUE ) ), array( 'Logging' ), 'a component that is not named is removed' );
$eq( $run( array( 'Logging' => TRUE, 'LogForwarding Profiles' => TRUE, 'Wildfire Analysis Prifles' => TRUE, 'Credential lTheft Prevention' => TRUE ) ),
    array( 'Logging' ), 'a misspelled name is no name: only the names of the diagram count (the BP file has to be corrected)' );

// the shipped file: the three components are in the diagram again
PH::$shadow_bp_jsonfile = $panos;
$all = array_fill_keys( array( 'Logging', 'Log Forwarding Profiles', 'Wildfire Analysis Profiles', 'Credential Theft Prevention' ), array( 'value' => 50 ) );
$out = array( 'percentage' => array( 'adoption' => $all, 'visibility' => $all, 'best-practice' => $all ) );
PH::validateIncludedInBPA( $out );
$eq( array( array_keys( $out['percentage']['adoption'] ), array_keys( $out['percentage']['visibility'] ), array_keys( $out['percentage']['best-practice'] ) ),
    array( array_keys( $all ), array_keys( $all ), array( 'Logging', 'Wildfire Analysis Profiles', 'Credential Theft Prevention' ) ),
    'bp_sp_panw.json: Log Forwarding Profiles, Wildfire Analysis Profiles and Credential Theft Prevention are shown' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
