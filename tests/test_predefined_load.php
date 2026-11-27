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
 * predefined.xml (App-ID, threats, regions, predefined lists, ... - 31 MB): how it is read when a configuration is
 * loaded. Every pass over the file costs ~0.25 s, and that is paid by every call of pan-os-php:
 *  - a load reads the file 3 times (app names, app details, all small sections) - it was 6 times
 *  - with PANOSPHP_PREDEFINED_XML every store reads THAT file (before: the apps from it, everything else from the file
 *    of the installation, which was built as a whole DOM for it - 9 passes, 8 s)
 *
 *   php tests/test_predefined_load.php
 */
$repo = dirname( __DIR__ );
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

// what a process reads: asked in a process of its own (the stores are kept per process)
$probe = <<<'PHP'
require $argv[1] . '/lib/pan_php_framework.php';
$pan = new PanoramaConf();
$doc = new DOMDocument();
$doc->loadXML( '<config><shared><address-group><entry name="g1"><static><member>h1</member></static></entry></address-group>'
    . '<address><entry name="h1"><ip-netmask>192.0.2.1</ip-netmask></entry></address></shared><devices><entry name="localhost.localdomain"><device-group/></entry></devices></config>' );
$pan->load_from_domxml( $doc );
$apps = AppStore::getPredefinedStore( $pan );
$ssl = $apps->find( 'ssl' );
$edl = EDLStore::predefinedEDLNames();
$regions = AddressStore::predefinedRegionNames();
print json_encode( array(
    'passes' => PH::$predefinedFilePasses,
    'version' => $apps->predefinedStore_appid_version,
    'apps' => count( $apps->getAll() ),
    'ssl' => $ssl === null ? null : array( $ssl->category, $ssl->subCategory, $ssl->technology, $ssl->risk, isset( $ssl->tcp ) && count( (array)$ssl->tcp ) > 0 ),
    'edl' => $edl['panw-known-ip-list']['display'] ?? null,
    'edlTypes' => array_values( array_unique( array_column( $edl, 'type' ) ) ),
    'region' => $regions['DE'] ?? null,
    'urlCategories' => count( SecurityProfileStore::getURLPredefinedStore( $pan )->getAll() ) > 50,
) );
PHP;
$probeFile = tempnam( sys_get_temp_dir(), 'predef' ) . '.php';
file_put_contents( $probeFile, "<?php\n" . $probe );
$run = function( $env ) use ( $probeFile, $repo ) {
    $out = array();
    exec( ( $env === '' ? 'env -u PANOSPHP_PREDEFINED_XML' : 'env PANOSPHP_PREDEFINED_XML=' . escapeshellarg( $env ) )
        . ' ' . escapeshellarg( PHP_BINARY ) . ' -d memory_limit=2G ' . escapeshellarg( $probeFile ) . ' ' . escapeshellarg( $repo ) . ' 2>&1', $out, $rc );
    $j = json_decode( (string)end( $out ), TRUE );
    return is_array( $j ) ? $j : array( 'error' => implode( "\n", array_slice( $out, -6 ) ) );
};

// ---- the file of the installation
$own = $run( '' );
$eq( $own['passes'] ?? ( $own['error'] ?? null ), 3, 'a load reads predefined.xml 3 times: app names, app details, the small sections together' );
$eq( array( ( $own['apps'] ?? 0 ) > 4000, is_string( $own['version'] ?? null ) && preg_match( '/^\d+-\d+$/', $own['version'] ) === 1 ), array( TRUE, TRUE ), 'apps and the App-ID version are read' );
$eq( $own['ssl'] ?? null, array( 'networking', 'encrypted-tunnel', 'browser-based', '4', TRUE ), 'the details of an app (ssl): category, subcategory, technology, risk, ports' );
$eq( array( $own['edl'] ?? null, $own['edlTypes'] ?? null, $own['region'] ?? null, $own['urlCategories'] ?? null ),
    array( 'Palo Alto Networks - Known malicious IP addresses', array( 'predefined-ip', 'predefined-url' ), 'Germany', TRUE ),
    'predefined lists, regions and URL categories from the small sections' );

// ---- another file (PANOSPHP_PREDEFINED_XML): a copy with its own App-ID version, list name and region text
$other = tempnam( sys_get_temp_dir(), 'predef' ) . '.xml';
$xml = file_get_contents( $repo . '/lib/object-classes/predefined.xml' );
$xml = preg_replace( '#<application-version>[^<]*</application-version>#', '<application-version>1-2</application-version>', $xml, 1 );
$xml = str_replace( '<display-name>Palo Alto Networks - Known malicious IP addresses</display-name>', '<display-name>list of the other file</display-name>', $xml );
$xml = preg_replace( '#(<entry name="DE"[^>]*help-string=")[^"]*#', '$1region of the other file', $xml, 1 );
file_put_contents( $other, $xml );
unset( $xml );
$env = $run( $other );
$eq( array( $env['version'] ?? ( $env['error'] ?? null ), $env['edl'] ?? null, $env['region'] ?? null ), array( '1-2', 'list of the other file', 'region of the other file' ),
    'PANOSPHP_PREDEFINED_XML: App-ID version, predefined lists and regions come from that file' );
$eq( array( $env['passes'] ?? null, $env['apps'] ?? null, $env['ssl'] ?? null ), array( 3, $own['apps'] ?? -1, $own['ssl'] ?? -1 ),
    'PANOSPHP_PREDEFINED_XML: read 3 times as well, the same apps' );
@unlink( $other ); @unlink( $probeFile );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
