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
 * Custom applications, application groups and application filters: detail-option-set, detail-entry-add / -remove,
 * name-rename (ApplicationFields); predefined applications read only; the types with location=predefined
 * (UTIL::predefinedTypes - the list the config viewer offers). Synthetic input tests/input/applications.xml.
 *
 *   php tests/test_applications.php
 */
$repo = dirname( __DIR__ );
$in = $repo . '/tests/input/applications.xml';
$tmp = sys_get_temp_dir() . '/applications-' . getmypid();
@mkdir( $tmp, 0700 );

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$step = 0;
$run = function( string $type, string $from, string $location, string $filter, string $actions ) use ( $repo, $tmp, &$step ) {
    $to = $tmp . '/' . ( ++$step ) . '.xml';
    $args = array( 'type=' . $type, 'in=' . $from, 'out=' . $to, 'location=' . $location, 'actions=' . $actions );
    if( $filter !== '' )
        $args[] = 'filter=' . $filter;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o );
    return array( $to, array_values( array_map( 'trim', preg_grep( '/^\s+\*+ (SKIPPED|[a-z])/', $o ) ) ), $o );
};
$xp = function( string $file, string $q ) {
    $d = new DOMDocument();
    $d->load( $file );
    $out = array();
    foreach( ( new DOMXPath( $d ) )->query( $q ) as $n )
        $out[] = trim( $n->textContent );
    return $out;
};
$v = "//devices/entry/vsys/entry[@name='vsys1']";
$S = '$$forwardslash$$';

// ---- custom application
list( $f, $l ) = $run( 'application', $in, 'vsys1', '(name eq app-custom)',
    "detail-option-set:risk,4/detail-option-set:category,networking/detail-option-set:evasive-behavior,yes/detail-option-set:description,/detail-option-set:tcp-timeout,120" .
    "/detail-entry-add:port,tcp{$S}8443/detail-entry-add:port,udp{$S}5000-5010/detail-entry-remove:port,tcp{$S}8080/detail-option-set:parent-app,ssl/name-rename:app-main" );
$a = "$v/application/entry[@name='app-main']";
$eq( array( null,
    $xp( $f, "$a/default/port/member" ), $xp( $f, "$a/risk" ), $xp( $f, "$a/category" ), $xp( $f, "$a/subcategory" ), $xp( $f, "$a/evasive-behavior" ),
    $xp( $f, "$a/description" ), $xp( $f, "$a/tcp-timeout" ), $xp( $f, "$a/parent-app" ) ),
    array( null, array( 'tcp/8443', 'udp/5000-5010' ), array( '4' ), array( 'networking' ), array( 'encrypted-tunnel' ), array( 'yes' ), array(), array( '120' ), array( 'ssl' ) ),
    'custom: options (a new category takes a fitting subcategory), description removed, ports, parent-app' );
$d = new DOMDocument(); $d->load( $f );
$order = array(); foreach( ( new DOMXPath( $d ) )->query( "$a/*" ) as $n ) $order[] = $n->nodeName;
$eq( $order, array( 'default', 'category', 'subcategory', 'technology', 'timeout', 'tcp-timeout', 'risk', 'evasive-behavior', 'parent-app' ), 'custom: elements in PAN-OS order' );
$eq( array( $xp( $f, "$v/rulebase/security/rules/entry[@name='r-app']/application/member" ), $xp( $f, "$v/application-group/entry[@name='ag-1']/members/member" ),
    $l[count( $l ) - 1] ), array( array( 'app-main', 'af-1' ), array( 'app-main', 'ssl' ), "* renamed 'app-custom' -> 'app-main' (users updated: 2)" ),
    'name-rename: rule and application group follow' );
list( , $l ) = $run( 'application', $in, 'vsys1', '(name eq app-custom)', "detail-option-set:risk,7/detail-option-set:category,/detail-option-set:subcategory,email" .
    "/detail-option-set:ip-protocol,6/detail-entry-add:port,tcp{$S}70000/detail-option-set:timeout,abc/detail-option-set:parent-app,app-custom/name-rename:ssl" );
$eq( array_map( function( $x ) { return substr( $x, 0, 50 ); }, array_values( preg_grep( '/SKIPPED/', $l ) ) ), array_map( function( $x ) { return substr( $x, 0, 50 ); }, array(
    "*** SKIPPED : risk '7': one of 1, 2, 3, 4, 5",
    "*** SKIPPED : category is needed by PAN-OS - it can be changed, no",
    "*** SKIPPED : subcategory 'email': one of artificial-intelligence, ",
    "*** SKIPPED : the application is identified by ports - remove th",
    "*** SKIPPED : port 'tcp/70000': tcp/<ports> or udp/<ports> - por",
    "*** SKIPPED : timeout 'abc': a number 1 - 604800",
    "*** SKIPPED : an application can not be its own parent",
    "*** SKIPPED : 'ssl' exists already (an application of the locati" ) ), 'custom: invalid values refused' );
list( $f, $l ) = $run( 'application', $in, 'vsys1', '(name eq app-proto)', "detail-entry-add:port,tcp{$S}1/detail-option-set:ip-protocol,/detail-entry-add:port,tcp{$S}1" );
$eq( array( $l[0], $xp( $f, "$v/application/entry[@name='app-proto']/default/port/member" ), $xp( $f, "$v/application/entry[@name='app-proto']/default/ident-by-ip-protocol" ) ),
    array( "*** SKIPPED : the application is identified by an IP protocol - remove it first (PAN-OS: ports or IP protocol)", array( 'tcp/1' ), array() ),
    'custom: ports or IP protocol' );

// ---- application group
list( $f, $l ) = $run( 'application', $in, 'vsys1', '(name eq ag-1)', 'detail-entry-add:member,dns/detail-entry-remove:member,ssl/detail-entry-add:member,nope/detail-entry-add:member,ag-1' );
$eq( array( $xp( $f, "$v/application-group/entry[@name='ag-1']/members/member" ), array_values( preg_grep( '/SKIPPED/', $l ) ) ),
    array( array( 'app-custom', 'dns' ), array( "*** SKIPPED : 'nope': no application, group or filter of the location, above it or predefined", "*** SKIPPED : a group can not be its own member" ) ),
    'group: members add / remove, unknown and itself refused' );

// ---- application filter
list( $f, $l ) = $run( 'application', $in, 'vsys1', '(name eq af-1)', 'detail-entry-add:category,media/detail-entry-add:risk,4/detail-entry-add:tag,Enterprise VoIP' .
    '/detail-entry-add:exclude,dns/detail-option-set:evasive,no/detail-option-set:prone-to-misuse,yes/detail-entry-remove:category,networking/detail-entry-add:category,nonsense' );
$fl = "$v/application-filter/entry[@name='af-1']";
$eq( array( $xp( $f, "$fl/category/member" ), $xp( $f, "$fl/risk/member" ), $xp( $f, "$fl/tagging/tag/member" ), $xp( $f, "$fl/exclude/member" ), $xp( $f, "$fl/evasive" ),
    $xp( $f, "$fl/prone-to-misuse" ), array_values( preg_grep( '/SKIPPED/', $l ) ) ),
    array( array( 'media' ), array( '5', '4' ), array( 'Enterprise VoIP' ), array( 'dns' ), array(), array( 'yes' ), array( "*** SKIPPED : category 'nonsense': not a category of the App-ID database" ) ),
    'filter: lists, characteristics, unknown category refused' );

// ---- predefined: read only
list( , $l ) = $run( 'application', $in, 'predefined', '(name eq ssl)', 'detail-option-set:risk,1/name-rename:x' );
$eq( $l, array( "*** SKIPPED : read-only object: predefined", "*** SKIPPED : read-only object: predefined" ), 'predefined application: read only' );

// ---- the types with location=predefined (the config viewer offers exactly these)
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/lib/UTIL.php';
$pan = new PANConf();
$pan->load_from_file( $in );
$got = array();
foreach( array( 'address', 'service', 'tag', 'application', 'log-profile', 'threat', 'securityprofile', 'region', 'edl', 'schedule' ) as $t )
{
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=' . $t . ' in=' . escapeshellarg( $in ) . ' location=predefined actions=display 2>&1', $o, $rc );
    if( $rc === 0 && preg_grep( "/passing through Action='display'/", $o ) )
        $got[] = $t;
    $o = array();
}
$eq( $got, array_values( array_intersect( array( 'address', 'service', 'tag', 'application', 'log-profile', 'threat', 'securityprofile', 'region', 'edl', 'schedule' ), UTIL::predefinedTypes( $pan ) ) ),
    'location=predefined lists objects exactly for UTIL::predefinedTypes() (the list of the config viewer)' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
