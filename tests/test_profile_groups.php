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
 * Security profile groups: securityProfile-Set / -Remove (profiles of the location, above it, predefined; references),
 * name-rename (the rules follow), the fields of the window. Synthetic input tests/input/profile-groups.xml.
 *
 *   php tests/test_profile_groups.php
 */
$repo = dirname( __DIR__ );
$in = $repo . '/tests/input/profile-groups.xml';
$tmp = sys_get_temp_dir() . '/profilegroups-' . getmypid();
@mkdir( $tmp, 0700 );

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$step = 0;
$run = function( string $type, string $from, string $filter, string $actions ) use ( $repo, $tmp, &$step ) {
    $to = $tmp . '/' . ( ++$step ) . '.xml';
    $args = array( 'type=' . $type, 'in=' . $from, 'out=' . $to, 'location=vsys1', 'actions=' . $actions );
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
$pg = "$v/profile-group/entry[@name='%s']";

// ---- set / remove
list( $f, $l ) = $run( 'securityprofilegroup', $in, '(name eq pg-1)',
    'securityProfile-Set:spyware,strict/securityProfile-Set:vulnerability,vp-1/securityProfile-Set:wildfire,default/securityProfile-Remove:virus' );
$eq( array( $xp( $f, sprintf( $pg, 'pg-1' ) . '/*' ), $xp( $f, sprintf( $pg, 'pg-1' ) . '/spyware/member' ), $xp( $f, sprintf( $pg, 'pg-1' ) . '/wildfire-analysis/member' ) ),
    array( array( 'strict', 'vp-1', 'default' ), array( 'strict' ), array( 'default' ) ),
    'set: a predefined profile (strict, default), a profile of the vsys; remove: virus - the slots in PAN-OS order' );
list( , $l ) = $run( 'securityprofilegroup', $f, '(name eq pg-1)',
    'securityProfile-Set:file-blocking,nope/securityProfile-Set:virus-and-wildfire,x/securityProfile-Remove:virus/securityProfile-Set:spyware,strict' );
$eq( array_values( preg_grep( '/SKIPPED/', $l ) ), array(
    "*** SKIPPED : no file-blocking profile 'nope' at the location of the group, above it or predefined",
    "*** SKIPPED : a profile group of this configuration has no profile type 'virus-and-wildfire' (virus, spyware, vulnerability, file-blocking, wildfire-analysis, url-filtering, data-filtering)",
    "*** SKIPPED : no virus profile in the group",
    "*** SKIPPED : spyware is 'strict' already" ),
    'refused: an unknown profile, a type of SCM, nothing to remove, the same profile' );
list( $f2, ) = $run( 'securityprofilegroup', $f, '(name eq pg-1)', 'securityProfile-Remove:any' );
$eq( $xp( $f2, sprintf( $pg, 'pg-1' ) . '/*' ), array(), 'remove any: every profile' );

// references follow (library)
require_once $repo . '/lib/pan_php_framework.php';
PH::$shadow_json = FALSE;
$pan = new PANConf();
$pan->load_from_file( $in );
$vsys = $pan->findVirtualSystem( 'vsys1' );
$g = $vsys->securityProfileGroupStore->find( 'pg-1' );
$as = $vsys->AntiSpywareProfileStore->find( 'as-1' );
$vp = $vsys->VulnerabilityProfileStore->find( 'vp-1' );
$before = array( $as->countReferences(), $vp->countReferences() );
$g->editProfileSet( 'spyware', 'strict' );
$g->editProfileSet( 'vulnerability', 'vp-1' );
$eq( array( $before, array( $as->countReferences(), $vp->countReferences() ) ), array( array( 1, 0 ), array( 0, 1 ) ), 'references: the old profile loses the group, the new one gets it' );
$fd = ObjectFieldData::of( $g );
$eq( array( $fd['kind'], array_column( $fd['slots'], 'slot' ), array_column( $fd['slots'], 'type' )[4], $fd['slots'][1]['value'], $fd['slots'][1]['pick'] ),
    array( 'securityprofilegroup', array( 'virus', 'spyware', 'vulnerability', 'file-blocking', 'wildfire-analysis', 'url-filtering', 'data-filtering' ), 'wildfire', 'strict', 'profile-spyware' ),
    'fields of the window: slots, the type of the actions, value, candidates kind' );

// ---- rename: the rules follow (also the old name-* actions)
list( $f, $l ) = $run( 'securityprofilegroup', $in, '(name eq pg-1)', 'name-rename:pg-main' );
$eq( array( $xp( $f, "$v/profile-group/entry/@name" ), $xp( $f, "$v/rulebase/security/rules/entry[@name='r-1']/profile-setting/group/member" ), $l ),
    array( array( 'pg-main', 'pg-2' ), array( 'pg-main' ), array( "* renamed 'pg-1' -> 'pg-main' (rules updated: 1)" ) ), 'name-rename: group and rule' );
list( $f, ) = $run( 'securityprofilegroup', $in, '(name eq pg-1)', 'name-addPrefix:x-' );
$eq( $xp( $f, "$v/rulebase/security/rules/entry[@name='r-1']/profile-setting/group/member" ), array( 'x-pg-1' ), 'name-addPrefix: the rule follows (before: the old name stayed in the rule)' );
list( , $l ) = $run( 'securityprofilegroup', $in, '(name eq pg-1)', 'name-rename:pg-2' );
$eq( $l, array( "*** SKIPPED : 'pg-2' exists already" ), 'name-rename: an existing name is refused' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
