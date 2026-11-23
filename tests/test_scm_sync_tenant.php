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
 * SCMPrismaAccessSync changes one tenant: a plan between two exports of the same TSG works (scm_pa_change.php:
 * as-is → to-be), a plan / apply between two tenants is refused unless 'cross_tenant' is set (plug-in scm-migration).
 * Synthetic exports only.
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/develop/sase/scm/lib/SCMPrismaAccessSync.php';
PH::$useExceptions = TRUE;

$dir = sys_get_temp_dir() . '/scmsync-' . getmypid();
$export = function( $tsg, $ts, array $dns ) use ( $dir ) {
    $d = $dir . '/' . $tsg . '/' . $ts;
    @mkdir( $d . '/infra', 0700, TRUE );
    $f = 'infra/03_internal-dns-servers.json';
    file_put_contents( $d . '/' . $f, json_encode( array( 'endpoint' => 'internal-dns-servers', 'area' => 'infra', 'status' => 'ok', 'data' => $dns ) ) );
    file_put_contents( $d . '/manifest.json', json_encode( array( 'format_version' => 8, 'tsg_id' => $tsg, 'areas' => array( 'infra' ),
        'created_at' => '2026-11-23T10:00:00+01:00',
        'endpoints' => array( array( 'area' => 'infra', 'order' => 3, 'name' => 'internal-dns-servers', 'file' => $f, 'status' => 'ok', 'count' => count( $dns ) ) ) ) ) );
    return $d;
};
$a1 = $export( '1111111111', '20261123-100000', array( array( 'name' => 'corp', 'domain_name' => array( 'corp.example' ), 'primary' => '10.1.1.1' ) ) );
$a2 = $export( '1111111111', '20261123-110000', array( array( 'name' => 'corp', 'domain_name' => array( 'corp.example' ), 'primary' => '10.1.1.1' ),
    array( 'name' => 'lab', 'domain_name' => array( 'lab.example' ), 'primary' => '10.2.2.2' ) ) );
$b1 = $export( '2222222222', '20261123-120000', array( array( 'name' => 'corp', 'domain_name' => array( 'corp.example' ), 'primary' => '10.1.1.1' ) ) );

$diff = function( $left, $right ) use ( $dir ) {
    $c = new SCMPrismaAccessCompare( $left, $right );
    $c->run();
    return $c->write( $dir . '/cmp-' . md5( $left . $right ) );
};
$plan = function( $d, array $opt = array() ) {
    try { $s = new SCMPrismaAccessSync( $d, $opt + array( 'source' => 'right', 'allow_infra' => TRUE ) ); $p = $s->buildPlans()[0];
        return count( $p['operations'] ?? $p['ops'] ?? array() ) . ' ops'; }
    catch( Exception $e ) { return strpos( $e->getMessage(), 'plug-in scm-migration' ) !== FALSE ? 'refused' : 'error: ' . $e->getMessage(); }
};
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

$same = $diff( $a1, $a2 );
$cross = $diff( $b1, $a2 );
$eq( $plan( $same ), '1 ops', 'same tenant (as-is → to-be): plan' );
$eq( $plan( $cross ), 'refused', 'two tenants: plan refused without cross_tenant' );
$eq( $plan( $cross, array( 'cross_tenant' => TRUE ) ), '1 ops', 'two tenants with cross_tenant (plug-in scm-migration): plan' );
$xp = ( new SCMPrismaAccessSync( $cross, array( 'source' => 'right', 'allow_infra' => TRUE, 'cross_tenant' => TRUE ) ) )->buildPlans()[0];
try { SCMPrismaAccessSync::apply( null, $xp, array( 'execute' => FALSE ) ); $r = 'applied'; }
catch( Exception $e ) { $r = strpos( $e->getMessage(), 'plug-in scm-migration' ) !== FALSE ? 'refused' : 'error: ' . $e->getMessage(); }
$eq( $r, 'refused', 'two tenants: apply of such a plan refused without cross_tenant' );
$eq( array( SCMPrismaAccessSync::crossTenant( '1', '1', FALSE ), SCMPrismaAccessSync::crossTenant( null, '2', FALSE ), SCMPrismaAccessSync::crossTenant( '1', '2', TRUE ),
    is_string( SCMPrismaAccessSync::crossTenant( '1', '2', FALSE ) ) ), array( null, null, null, TRUE ), 'crossTenant(): same / unknown / allowed / refused' );

exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( empty( $failed ) ? 0 : 1 );
