<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
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
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * Predefined objects: one answer (PH::isPredefinedObject) for the filter (object is.predefined) of every type with
 * predefined objects and for read only (CallContext::readOnlyReason, config viewer). Synthetic inputs.
 *
 *   php tests/test_predefined.php
 */
$repo = dirname( __DIR__ );
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$count = function( string $type, string $in, string $filter ) use ( $repo ) {
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=' . $type . ' in=' . escapeshellarg( $in ) .
        ' location=any ' . escapeshellarg( 'filter=' . $filter ) . ' actions=display 2>&1', $o, $rc );
    return $rc === 0 ? count( preg_grep( "/passing through Action='display'/", $o ) ) : -1;
};

// ---- the filter exists for every type with predefined objects and splits them from the objects of the configuration
$in = $repo . '/tests/input/applications.xml';
$got = array();
foreach( array( 'service', 'application', 'log-profile', 'securityprofile', 'region', 'threat-rule', 'address', 'tag', 'schedule', 'edl', 'securityprofilegroup' ) as $t )
    $got[$t] = array( $count( $t, $in, '(object is.predefined)' ) > 0, $count( $t, $in, '!(object is.predefined)' ) );
$eq( $got, array( 'service' => array( TRUE, 0 ), 'application' => array( TRUE, 4 ), 'log-profile' => array( TRUE, 0 ), 'securityprofile' => array( TRUE, 0 ),
    'region' => array( TRUE, 0 ), 'threat-rule' => array( TRUE, 0 ), 'address' => array( FALSE, 0 ), 'tag' => array( FALSE, 0 ), 'schedule' => array( FALSE, 0 ),
    'edl' => array( TRUE, 0 ), 'securityprofilegroup' => array( FALSE, 0 ) ),
    'object is.predefined: every type; not predefined = only the objects of the configuration (4 applications)' );

// ---- library: names the App-ID database uses without an entry of their own (ctd-dummy, ftp-data, …) are predefined
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/common/actions.php';
PH::$shadow_json = FALSE;
$pan = new PANConf();
$pan->load_from_file( $in );
$ctd = $pan->predefinedappStore->find( 'ctd-dummy' );
$eq( array( $ctd->isTmp(), PH::isPredefinedObject( $ctd ), CallContext::readOnlyReason( $ctd ) ), array( TRUE, TRUE, 'predefined' ),
    'an application the App-ID database names without an entry (ctd-dummy): predefined, read only' );
$custom = $pan->findVirtualSystem( 'vsys1' )->appStore->find( 'app-custom' );
$eq( array( PH::isPredefinedObject( $custom ), CallContext::readOnlyReason( $custom ) ), array( FALSE, null ), 'a custom application: not predefined' );
$eq( array( PH::isPredefinedObject( ServiceStore::getPredefinedStore( $pan )->find( 'service-http' ) ), PH::isPredefinedObject( $pan->addressStore->find( 'DE' ) ) ),
    array( TRUE, TRUE ), 'service-http, a predefined region' );

// ---- SCM: an object of the predefined snippet
$scm = new BuckbeakConf();
$scm->load_from_file( $repo . '/tests/input/SCM-import.xml' );
$snippets = $scm->getSnippets();
$snippet = $snippets[0];
$a = $snippet->addressStore->newAddress( 'a-snippet', 'ip-netmask', '192.0.2.1' );
$before = PH::isPredefinedObject( $a );
$snippet->setPredefined( TRUE );
$eq( array( $before, PH::isPredefinedObject( $a ), CallContext::readOnlyReason( $a ) ), array( FALSE, TRUE, 'predefined' ), 'SCM: an object of the predefined snippet is predefined' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
