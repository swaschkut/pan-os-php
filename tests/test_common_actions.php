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
 * Common actions (utils/common/actions-common.php, CallContext::registerAction): one definition for several types.
 * add-member / remove-member of address groups and service groups - synthetic input tests/input/group-members.xml.
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

$cli = function( string $type, ?string $out, string $filter, string $actions ) use ( $repo, $in ) {
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

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
