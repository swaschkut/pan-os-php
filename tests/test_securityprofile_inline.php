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
 * Security profile details of inline ML / inline cloud analysis and DNS (detail-entry-* / detail-option-set,
 * SecurityProfileFields): antivirus mlav-engine, anti-spyware and vulnerability mica-engine, WildFire inline cloud
 * analysis rules, cloud-inline-analysis, DNS lists / categories / exceptions (also the SCM DNS security profile);
 * the predefined lists of Palo Alto Networks (EDL, predefined.xml). Synthetic inputs.
 *
 *   php tests/test_securityprofile_inline.php
 */
$repo = dirname( __DIR__ );
$in = $repo . '/tests/input/securityprofile-inline.xml';
$tmp = sys_get_temp_dir() . '/spinline-' . getmypid();
@mkdir( $tmp, 0700 );
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$step = 0;
$run = function( string $type, string $from, string $extra, string $filter, string $actions ) use ( $repo, $tmp, &$step ) {
    $to = $tmp . '/' . ( ++$step ) . '.xml';
    $args = array( 'type=' . $type, 'in=' . $from, 'out=' . $to, 'location=vsys1', 'actions=' . $actions, 'filter=' . $filter );
    if( $extra !== '' )
        $args[] = $extra;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o );
    return array( $to, array_values( array_map( 'trim', preg_grep( '/^\s+\*+ (SKIPPED|[a-z])/', $o ) ) ) );
};
$xp = function( string $file, string $q ) {
    $d = new DOMDocument();
    $d->load( $file );
    $out = array();
    foreach( ( new DOMXPath( $d ) )->query( $q ) as $n )
        $out[] = trim( $n->textContent );
    return $out;
};
$p = "//devices/entry/vsys/entry[@name='vsys1']/profiles";

list( $f, $l ) = $run( 'securityprofile', $in, 'securityprofiletype=virus', '(name eq av-1)',
    'detail-entry-set:mlav-engine,Windows Executables,mlav-policy-action,enable(alert-only)/detail-entry-set:mlav-engine,MachO,mlav-policy-action,enable/detail-entry-set:mlav-engine,Nope,mlav-policy-action,enable' );
$eq( array( $xp( $f, "$p/virus/entry[@name='av-1']/mlav-engine-filebased-enabled/entry[@name='Windows Executables']/mlav-policy-action" ),
    $xp( $f, "$p/virus/entry[@name='av-1']/mlav-engine-filebased-enabled/entry[@name='MachO']/mlav-policy-action" ), strpos( end( $l ), "SKIPPED : mlav-engine 'Nope' not found" ) !== FALSE ),
    array( array( 'enable(alert-only)' ), array( 'enable' ), TRUE ), 'antivirus: inline ML models (mlav-engine) of predefined.xml' );

list( $f, $l ) = $run( 'securityprofile', $in, 'securityprofiletype=spyware', '(name eq as-1)',
    'detail-entry-set:mica-engine,SSL Command and Control detector,inline-policy-action,reset-both/detail-entry-add:dns-list,my-dns-edl/detail-entry-set:dns-list,my-dns-edl,action,block' .
    '/detail-entry-add:dns-exception,*.example.com/detail-entry-set:dns-exception,*.example.com,description,test/detail-option-set:cloud-inline-analysis,yes' );
$as = "$p/spyware/entry[@name='as-1']";
$eq( array( $xp( $f, "$as/mica-engine-spyware-enabled/entry[@name='SSL Command and Control detector']/inline-policy-action" ),
    array( count( $xp( $f, "$as/botnet-domains/lists/entry[@name='my-dns-edl']/action/block" ) ) ),
    $xp( $f, "$as/botnet-domains/whitelist/entry[@name='*.example.com']/description" ), $xp( $f, "$as/cloud-inline-analysis" ) ),
    array( array( 'reset-both' ), array( 1 ), array( 'test' ), array( 'yes' ) ), 'anti-spyware: mica-engine, DNS list (EDL) with action, DNS exception, cloud-inline-analysis' );

list( $f, ) = $run( 'securityprofile', $in, 'securityprofiletype=vulnerability', '(name eq vp-1)', 'detail-entry-set:mica-engine,Command Injection,inline-policy-action,drop/detail-option-set:cloud-inline-analysis,yes' );
$eq( array( $xp( $f, "$p/vulnerability/entry[@name='vp-1']/mica-engine-vulnerability-enabled/entry[@name='Command Injection']/inline-policy-action" ), $xp( $f, "$p/vulnerability/entry[@name='vp-1']/cloud-inline-analysis" ) ),
    array( array( 'drop' ), array( 'yes' ) ), 'vulnerability: mica-engine, cloud-inline-analysis' );

list( $f, ) = $run( 'securityprofile', $in, 'securityprofiletype=wildfire-analysis', '(name eq wf-1)', 'detail-entry-add:mica-engine,inline-1/detail-entry-set:mica-engine,inline-1,action,block/detail-option-set:cloud-inline-analysis,yes' );
$wf = "$p/wildfire-analysis/entry[@name='wf-1']";
$eq( array( $xp( $f, "$wf/mica-engine-wildfire-rules/entry[@name='inline-1']/action" ), $xp( $f, "$wf/mica-engine-wildfire-rules/entry[@name='inline-1']/direction" ), $xp( $f, "$wf/cloud-inline-analysis" ) ),
    array( array( 'block' ), array( 'both' ), array( 'yes' ) ), 'WildFire: inline cloud analysis rule, cloud-inline-analysis' );

// ---- SCM DNS security profile: the same DNS lists (SecurityProfileFields on its XML)
require_once $repo . '/lib/pan_php_framework.php';
$doc = new DOMDocument();
$doc->loadXML( '<entry name="dns-1"><botnet-domains><lists><entry name="default-paloalto-dns"><action><sinkhole/></action></entry></lists></botnet-domains></entry>' );
$dns = new class { public $secprof_type = 'dns-security'; public $xmlroot; public $owner = null; };
$dns->xmlroot = $doc->documentElement;
SecurityProfileFields::entryAdd( $dns, 'dns-exception', 'safe.example.com' );
SecurityProfileFields::entrySet( $dns, 'dns-list', 'default-paloalto-dns', 'action', 'block' );
SecurityProfileFields::entrySet( $dns, 'dns-category', 'pan-dns-sec-cc', 'action', 'sinkhole' );
$d = SecurityProfileFields::describe( $dns );
$eq( array( array_keys( $d['lists'] ), array_keys( $d['lists']['dns-exception']['entries'] ), $d['lists']['dns-list']['entries']['default-paloalto-dns']['action'],
    $d['lists']['dns-category']['entries']['pan-dns-sec-cc']['action'], array_keys( $d['options'] ) ),
    array( array( 'dns-list', 'dns-category', 'dns-exception' ), array( 'safe.example.com' ), 'block', 'sinkhole', array( 'sinkhole-ipv4', 'sinkhole-ipv6' ) ),
    'SCM DNS security profile: DNS lists, categories, exceptions, sinkhole' );

// ---- predefined lists of Palo Alto Networks (EDL)
$names = EDLStore::predefinedEDLNames();
$eq( array( $names['panw-known-ip-list']['type'] ?? null, $names['panw-auth-portal-exclude-list']['type'] ?? null ), array( 'predefined-ip', 'predefined-url' ),
    'predefined EDLs of predefined.xml (ip-block-list-v2, url-predefined)' );
$edlIn = $tmp . '/edl.xml';
file_put_contents( $edlIn, '<?xml version="1.0"?><config version="11.1.0" urldb="paloaltonetworks"><mgt-config><users/></mgt-config><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
    . '<external-list><entry name="my-edl"><type><predefined-ip><url>panw-highrisk-ip-list</url></predefined-ip></type></entry></external-list>'
    . '<rulebase><security><rules><entry name="r1"><from><member>any</member></from><to><member>any</member></to><source><member>panw-known-ip-list</member></source>'
    . '<destination><member>any</member></destination><source-user><member>any</member></source-user><category><member>any</member></category><application><member>any</member></application>'
    . '<service><member>any</member></service><action>deny</action></entry></rules></security></rulebase></entry></vsys></entry></devices></config>' );
$pan = new PANConf();
$pan->load_from_file( $edlIn );
$o = $pan->findVirtualSystem( 'vsys1' )->addressStore->find( 'panw-known-ip-list' );
$eq( array( get_class( $o ), $o->isPredefined(), PH::isPredefinedObject( $o ), $o->countReferences() ), array( 'EDL', TRUE, TRUE, 1 ),
    'a predefined list in a rule: the predefined EDL (before: a temporary address)' );
list( , $l ) = $run( 'edl', $edlIn, '', '(name eq my-edl)', 'source-set:panw-nope/source-set:panw-auth-portal-exclude-list/source-set:panw-torexit-ip-list' );
$eq( array_map( function( $x ) { return substr( $x, 0, 60 ); }, $l ), array( "*** SKIPPED : source 'panw-nope': no predefined list of type",
    "*** SKIPPED : source 'panw-auth-portal-exclude-list': no pre", "* source 'panw-torexit-ip-list'" ), 'EDL of type predefined-ip: only a predefined list of that type' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
