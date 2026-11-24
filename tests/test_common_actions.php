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
 * Common actions (utils/common/actions-common.php, CallContext::registerAction): one definition for several types -
 * add-member / remove-member (address / service groups), description-set (address, service, rule, security profile) -
 * and the value actions of address / service (value-set, protocol-set, dstport-set). Synthetic input
 * tests/input/group-members.xml.
 * php tests/test_common_actions.php
 */

$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/common/actions.php';

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

$dir = sys_get_temp_dir() . '/commonact-' . getmypid();
if( !is_dir( $dir ) )
    mkdir( $dir, 0700, TRUE );
$in = __DIR__ . '/input/group-members.xml';

$cli = function( string $type, ?string $out, string $filter, string $actions ) use ( $repo, &$in ) {
    $args = array( 'type=' . $type, 'in=' . $in, 'location=vsys1', 'filter=' . $filter, 'actions=' . $actions );
    if( $out !== null )
        $args[] = 'out=' . $out;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o, $rc );
    return array( $rc, implode( "\n", $o ) );
};
$x = function( string $file, string $xpath ) {
    $d = new DOMDocument();
    $d->load( $file );
    $r = array();
    foreach( ( new DOMXPath( $d ) )->query( $xpath ) as $n )
        $r[] = $n->textContent;
    return $r;
};

// ---- registration: one definition in both types, a type-specific action of the same name wins
$eq( array( AddressCallContext::$supportedActions['add-member']['MainFunction'] === ServiceCallContext::$supportedActions['add-member']['MainFunction'],
        AddressCallContext::$supportedActions['remove-member']['MainFunction'] === ServiceCallContext::$supportedActions['remove-member']['MainFunction'] ),
    array( TRUE, TRUE ), 'add-member / remove-member: one definition for address and service' );
$own = TagCallContext::$supportedActions['delete'];
CallContext::registerAction( array( 'TagCallContext' ), array( 'name' => 'delete', 'MainFunction' => function() {} ) );
$eq( TagCallContext::$supportedActions['delete'] === $own, TRUE, 'registerAction: a type-specific action of the same name is kept' );
CallContext::registerAction( array( 'TagCallContext' ), array( 'name' => 'zz-Common-Test', 'MainFunction' => function() {} ) );
$eq( array( isset( TagCallContext::$supportedActions['zz-common-test'] ), array_keys( TagCallContext::$supportedActions ) === array_values( array_unique( array_keys( TagCallContext::$supportedActions ) ) ) ),
    array( TRUE, TRUE ), 'registerAction: added under its lower case name' );

// ---- address groups
$G = "//address-group/entry";
list( $rc, $o ) = $cli( 'address', $dir . '/a.xml', '(name eq g-1)', 'add-member:h-3/add-member:h-shared/remove-member:h-1' );
$eq( array( $rc, $x( $dir . '/a.xml', $G . "[@name='g-1']/static/member" ) ), array( 0, array( 'h-2', 'h-3', 'h-shared' ) ),
    'address group: members added (also from shared) and removed' );
foreach( array(
        array( '(name eq g-1)', 'add-member:h-1', 'already a member' ),
        array( '(name eq g-1)', 'add-member:nope', "'nope' not found" ),
        array( '(name eq g-1)', 'add-member:w-1', 'wildcard' ),
        array( '(name eq g-1)', 'add-member:g-2', 'loop' ),
        array( '(name eq g-1)', 'add-member:g-1', 'loop' ),
        array( '(name eq g-1)', 'remove-member:h-3', 'not a member' ),
        array( '(name eq g-2)', 'remove-member:g-1', 'last member' ),
        array( '(name eq g-dyn)', 'add-member:h-1', 'dynamic' ),
        array( '(name eq h-1)', 'remove-member:h-2', 'not a group' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'address', $dir . '/b.xml', $t[0], $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE, $x( $dir . '/b.xml', $G . "/static/member" ) ),
        array( 0, TRUE, array( 'h-1', 'h-2', 'g-1' ) ), 'address ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . '), nothing changed, the run goes on' );
}
// a run over several groups: a skipped group does not stop the others
list( $rc, $o ) = $cli( 'address', $dir . '/c.xml', '(name regex /^g-/)', 'add-member:h-3' );
$eq( array( $rc, $x( $dir . '/c.xml', $G . "[@name='g-1']/static/member|" . $G . "[@name='g-2']/static/member" ) ), array( 0, array( 'h-1', 'h-2', 'h-3', 'g-1', 'h-3' ) ),
    'address: several groups (one dynamic: skipped) - the others changed' );

// ---- service groups
$S = "//service-group/entry";
list( $rc, $o ) = $cli( 'service', $dir . '/s.xml', '(name eq sg-1)', 'add-member:tcp-2/add-member:tcp-shared/remove-member:tcp-1' );
$eq( array( $rc, $x( $dir . '/s.xml', $S . "[@name='sg-1']/members/member" ) ), array( 0, array( 'tcp-2', 'tcp-shared' ) ),
    'service group: members added (also from shared) and removed' );
foreach( array(
        array( '(name eq sg-1)', 'add-member:tcp-1', 'already a member' ),
        array( '(name eq sg-1)', 'add-member:sg-2', 'loop' ),
        array( '(name eq sg-1)', 'remove-member:tcp-1', 'last member' ),
        array( '(name eq sg-1)', 'remove-member:tcp-2', 'not a member' ),
        array( '(name eq tcp-1)', 'add-member:tcp-2', 'not a group' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'service', $dir . '/b.xml', $t[0], $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE, $x( $dir . '/b.xml', $S . "/members/member" ) ),
        array( 0, TRUE, array( 'tcp-1', 'sg-1' ) ), 'service ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . '), nothing changed' );
}

// references follow the members
$pan = new PANConf();
ob_start();
$pan->load_from_file( $dir . '/s.xml' );
ob_end_clean();
$v = $pan->findVirtualSystem( 'vsys1' );
$names = function( $o ) { return array_map( function( $r ) { return $r->name(); }, $o->getReferences() ); };
$eq( array( in_array( 'sg-1', $names( $v->serviceStore->find( 'tcp-2' ) ), TRUE ), in_array( 'sg-1', $names( $v->serviceStore->find( 'tcp-1' ) ), TRUE ) ),
    array( TRUE, FALSE ), 'service group: references of the members' );

// ---- description-set (common): replaces, empty removes, aliases, UTF-8 kept as it is
$eq( array( AddressCallContext::$supportedActions['description-set']['MainFunction'] === RuleCallContext::$supportedActions['description-set']['MainFunction'],
        isset( SecurityProfileCallContext::$supportedActions['description-set'], ServiceCallContext::$supportedActions['description-set'] ) ),
    array( TRUE, TRUE ), 'description-set: one definition for address, service, rule, security profile' );
list( $rc, $o ) = $cli( 'address', $dir . '/d.xml', '(name eq h-1)', 'description-set:Prüfung$$comma$$ DMZ$$colon$$ a$$forwardslash$$b' );
$eq( array( $rc, $x( $dir . '/d.xml', "//address/entry[@name='h-1']/description" ) ), array( 0, array( 'Prüfung, DMZ: a/b' ) ), 'address description-set: aliases, umlaut not converted twice' );
list( $rc, $o ) = $cli( 'service', $dir . '/d2.xml', '(name eq tcp-1)', 'description-set:x/description-set' );
$eq( array( $rc, $x( $dir . '/d2.xml', "//service/entry[@name='tcp-1']/description" ) ), array( 0, array() ), 'service description-set: set, then empty removes it' );
list( $rc, $o ) = $cli( 'service', $dir . '/b.xml', '(name eq sg-1)', 'description-set:x' );
$eq( strpos( $o, 'has no description' ) !== FALSE, TRUE, 'service group: SKIPPED (no description)' );

// ---- address value-set
$A = "//vsys/entry/address/entry";
foreach( array(
        array( 'h-1', 'value-set:10.0.0.0//24', 'ip-netmask', '10.0.0.0/24' ),
        array( 'h-1', 'value-set:www.example.com,fqdn', 'fqdn', 'www.example.com' ),
        array( 'h-1', 'value-set:2001$$colon$$db8$$colon$$$$colon$$//32', 'ip-netmask', '2001:db8::/32' ),
        array( 'h-1', 'value-set:10.0.0.1-10.0.0.9,ip-range', 'ip-range', '10.0.0.1-10.0.0.9' ),
        array( 'w-1', 'value-set:10.1.0.1//0.0.255.255', 'ip-wildcard', '10.1.0.1/0.0.255.255' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'address', $dir . '/v.xml', '(name eq ' . $t[0] . ')', $t[1] );
    $eq( array( $rc, $x( $dir . '/v.xml', $A . "[@name='" . $t[0] . "']/" . $t[2] ), count( $x( $dir . '/v.xml', $A . "[@name='" . $t[0] . "']/*[not(self::description) and not(self::tag)]" ) ) ),
        array( 0, array( $t[3] ), 1 ), 'address ' . $t[0] . ' ' . $t[1] . ': ' . $t[2] . ' ' . $t[3] . ' (one value element)' );
}
foreach( array(
        array( 'h-1', 'value-set:10.0.0.0//33', 'mask 0-32' ),
        array( 'h-1', 'value-set:10.0.0.9-10.0.0.1,ip-range', 'above the last' ),
        array( 'h-1', 'value-set:10.0.0.1-2001$$colon$$db8$$colon$$$$colon$$1,ip-range', 'same family' ),
        array( 'h-1', 'value-set:a b,fqdn', 'without spaces' ),
        array( 'h-1', 'value-set:1.2.3.4,host', 'type:' ),
        array( 'h-1', 'value-set:10.0.0.1//0.255.0.255,ip-wildcard', "member of address group 'g-1'" ),
        array( 'h-1', 'value-set:192.0.2.1//32', 'the same' ),
        array( 'g-1', 'value-set:1.1.1.1', 'no address of type' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'address', $dir . '/b.xml', '(name eq ' . $t[0] . ')', $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE, $x( $dir . '/b.xml', $A . "[@name='h-1']/ip-netmask" ) ),
        array( 0, TRUE, array( '192.0.2.1/32' ) ), 'address ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . ')' );
}

// ---- service protocol-set / dstport-set (and Service::setProtocol: source port and timeout kept)
$in0 = $in;
$in = $dir . '/svc.xml';
file_put_contents( $in, str_replace( '<entry name="tcp-2"><protocol><tcp><port>8444</port></tcp></protocol></entry>',
    '<entry name="tcp-2"><protocol><tcp><port>8444</port><source-port>1024-2048</source-port><override><yes><timeout>600</timeout><halfclose-timeout>60</halfclose-timeout></yes></override></tcp></protocol></entry>',
    file_get_contents( $in0 ) ) );
$T = "//vsys/entry/service/entry[@name='tcp-2']/protocol";
list( $rc, $o ) = $cli( 'service', $dir . '/p.xml', '(name eq tcp-2)', 'protocol-set:udp/dstport-set:53|5353;6000-6010' );
$eq( array( $rc, $x( $dir . '/p.xml', $T . "/udp/port|" . $T . "/udp/source-port|" . $T . "/udp/override/yes/*" ), count( $x( $dir . '/p.xml', $T . "/tcp" ) ) ),
    array( 0, array( '53,5353,6000-6010', '1024-2048', '600' ), 0 ), 'service protocol-set udp: ports, source port and timeout kept, half-close gone; dstport-set with | and ;' );
foreach( array( array( 'tcp-1', 'dstport-set:70000', 'no list of ports' ), array( 'tcp-1', 'dstport-set:90-80', 'no list of ports' ),
        array( 'tcp-1', 'protocol-set:tcp', 'already' ), array( 'sg-1', 'dstport-set:80', 'no service of tcp' ) ) as $t )
{
    list( $rc, $o ) = $cli( 'service', $dir . '/b.xml', '(name eq ' . $t[0] . ')', $t[1] );
    $eq( array( $rc, strpos( $o, 'SKIPPED' ) !== FALSE && strpos( $o, $t[2] ) !== FALSE ), array( 0, TRUE ), 'service ' . $t[0] . ' ' . $t[1] . ': SKIPPED (' . $t[2] . ')' );
}
$in = $in0;

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
