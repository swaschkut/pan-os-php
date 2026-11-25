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
 * NAT rule -> security rules (NatSecurityMatch, actions=display-nat-security / nat-security-fix, filters nat.security,
 * nat.security.mismatch). Synthetic inputs (rules of other vendors: asa-* post-NAT address / translated port, fw-zone-svc
 * pre-NAT zone):
 *   nat-security-fw.xml            firewall, virtual router: connected dmz, static route 10.20.0.0/16 -> srv, default route
 *   nat-security-fw-ar.xml         the same with advanced routing (logical router)
 *   nat-security-panorama.xml      DG1 (SER1: stack TS-A, SER2: stack TS-B with its own value of $dmz-ip), DG1-child
 *                                  (SER3: TS-A); TS-A has zone srv, TS-B zone srv-b; allow-app targets SER1 only
 *   nat-security-panorama-nodevice.xml  the same without firewalls: the template stacks
 *
 *   php tests/test_nat_security.php
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

// pan-os-php type=rule ruletype=nat … shadow-json; $action: display-nat-security (-> 'nat-security' per rule) or display
$run = function( string $file, string $filter, string $location = 'any', string $action = 'display-nat-security' ) use ( $repo ) {
    $args = array( 'type=rule', 'ruletype=nat', 'in=' . ( $file[0] === '/' ? $file : $repo . '/tests/input/' . $file ), 'location=' . $location, 'filter=' . $filter, 'actions=' . $action, 'shadow-json' );
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>/dev/null', $o );
    $t = implode( "\n", $o );
    $j = json_decode( substr( $t, (int)strpos( $t, '{' ) ), TRUE );
    $out = array();
    $walk = function( $x ) use ( &$walk, &$out ) {
        if( !is_array( $x ) )
            return;
        if( isset( $x['object'] ) && is_array( $x['object'] ) )
            foreach( $x['object'] as $k => $v )
                $out[(string)$k] = $v['nat-security'] ?? TRUE;
        foreach( $x as $v )
            $walk( $v );
    };
    $walk( $j );
    return $out;
};
$one = function( string $file, string $name, string $location = 'any' ) use ( $run ) {
    $r = $run( $file, '(name eq ' . $name . ')', $location );
    return is_array( $r[$name] ?? null ) ? $r[$name] : null;
};
// "#position rule state/coverage" of one context
$rows = function( array $ctx ) {
    return array_map( function( $m ) { return $m['rule'] . ':' . ( $m['state'] === 'shadowed' ? 'shadowed' : $m['coverage'] ); }, $ctx['matches'] );
};
$zones = function( array $ctx ) {
    return array_map( function( $z ) { return $z['zone'] . ( $z['uncertain'] ? '?' : '' ); }, $ctx['postNatZones'] );
};

// "rule:pattern+pattern:scope:fix[:covered]" of the security rules to adapt of one context
$adapt = function( array $ctx ) {
    return array_map( function( $m ) {
        return $m['rule'] . ':' . implode( '+', $m['patterns'] ) . ':' . $m['scope'] . ':' . $m['fix'] . ( $m['covered'] !== null ? ':covered' : '' );
    }, $ctx['mismatches'] );
};

foreach( array( 'nat-security-fw.xml' => 'virtual router', 'nat-security-fw-ar.xml' => 'logical router' ) as $file => $what )
{
    // destination NAT to the connected dmz: post-NAT zone dmz; allow-web covers it fully - only what allowed traffic
    // really reaches is listed (allow-dmz-any behind it: not listed; deny-partner: no allow rule)
    $a = $one( $file, 'dnat-web' );
    $c = $a['directions'][0]['contexts'][0];
    $eq( array( $a['kind'], $zones( $c ), $rows( $c ), $c['summary'] ),
        array( 'destination', array( 'dmz' ), array( 'allow-web:full' ), 'full' ),
        $what . ': DNAT to a connected network - post-NAT zone, only the allow rule that gets the traffic' );
    $eq( $c['matches'][0]['details'], array( 'zones' => 'full', 'source' => 'full', 'destination' => 'full', 'service' => 'full' ), $what . ': details of a full rule' );
    // written the way of other vendors: post-NAT address - not needed, allow-web allows the traffic already
    $eq( $adapt( $c ), array( 'wrong-post-nat-ip:post-nat-address:full:in-place:covered', 'asa-partial:post-nat-address:full:clone:covered' ),
        $what . ': rules with the post-NAT address - shown, not needed (covered)' );

    // destination NAT behind a static route: zone of the route's interface; service tcp/8443 inside tcp 8000-9000
    $c = $one( $file, 'dnat-app' )['directions'][0]['contexts'][0];
    $eq( array( $zones( $c ), $rows( $c ) ), array( array( 'srv' ), array( 'allow-app:full' ) ), $what . ': DNAT behind a static route - zone of the route, service range' );

    // destination NAT only by the default route: uncertain; disabled rule skipped; deny-ext blocks the traffic before
    // allow-ext: "blocked", allow-ext not listed, no proposal (uncertain zone)
    $c = $one( $file, 'dnat-ext' )['directions'][0]['contexts'][0];
    $eq( array( $zones( $c ), $rows( $c ), $c['summary'], $c['blockedBy']['rule'] ?? null, (bool)preg_grep( "/traffic blocked by rule 'deny-ext' \\(deny/", $c['notes'] ), $c['mismatches'] ),
        array( array( 'untrust?' ), array(), 'blocked', 'deny-ext', TRUE, array() ), $what . ': default route only - uncertain zone; traffic blocked by a deny rule' );

    // rules to adapt (no allow rule yet): pre-NAT zone (in place: only the NAT address), post-NAT address + translated
    // port (in place), post-NAT address in a network with more hosts (clone), a part of a translated pool (partial)
    $eq( $adapt( $one( $file, 'dnat-svc' )['directions'][0]['contexts'][0] ), array( 'fw-zone-svc:pre-nat-zone:full:in-place' ), $what . ': pre-NAT zone' );
    $eq( $adapt( $one( $file, 'dnat-port' )['directions'][0]['contexts'][0] ), array( 'asa-port:post-nat-address+translated-port:full:in-place' ), $what . ': post-NAT address and translated port' );
    $eq( $adapt( $one( $file, 'dnat-web2' )['directions'][0]['contexts'][0] ), array( 'asa-partial:post-nat-address:full:clone' ), $what . ': post-NAT address in a larger network - clone' );
    $m = $one( $file, 'dnat-pool' )['directions'][0]['contexts'][0]['mismatches'][0];
    $eq( array( $m['rule'], $m['scope'], $m['fix'], $m['target'] ), array( 'asa-pool-one', 'partial', 'clone', array( 'destination' => array( 'pub-pool' ), 'to' => array( 'dmz' ), 'from' => null, 'service' => null ) ),
        $what . ': a part of a translated pool - partial (would allow more)' );
}

// an internal rule to the real address (trust -> dmz) is not touched
$eq( in_array( 'trust-to-web', array_column( $one( 'nat-security-fw.xml', 'dnat-web' )['directions'][0]['contexts'][0]['mismatches'], 'rule' ), TRUE ), FALSE,
    'a rule from another source zone to the real address is not a rule to adapt' );

// source NAT: zones of the NAT rule; application-default is not a full match
$c = $one( 'nat-security-fw.xml', 'snat-out' )['directions'][0]['contexts'][0];
$eq( array( $zones( $c ), $rows( $c ), $c['matches'][0]['details']['service'], $c['mismatches'] ), array( array(), array( 'allow-out:partial', 'allow-out-all:full' ), 'unknown', array() ),
    'source NAT: no route lookup; application-default = not determined (partial)' );

// bi-directional static NAT: forward dmz -> untrust has no rule; reverse (untrust -> translated address) to dmz
$a = $one( 'nat-security-fw.xml', 'bidir-web' );
$eq( array( $a['kind'], array_column( $a['directions'], 'direction' ), array_column( $a['directions'], 'summary' ) ),
    array( 'bidirectional', array( 'forward', 'reverse' ), array( 'missing', 'full' ) ), 'bi-directional: both directions' );
$c = $a['directions'][1]['contexts'][0];
$eq( array( $zones( $c ), $rows( $c ) ), array( array( 'dmz' ), array( 'allow-web:partial', 'allow-dmz-any:full' ) ),
    'bi-directional reverse: post-NAT zone of the original source, any service' );

// filters
$names = function( string $file, string $filter ) use ( $run ) {
    $r = array_keys( $run( $file, $filter, 'any', 'display' ) );
    sort( $r );
    return $r;
};
$eq( $names( 'nat-security-fw.xml', '(nat.security is.full)' ), array( 'dnat-app', 'dnat-web', 'snat-out' ), 'filter nat.security is.full' );
$eq( $names( 'nat-security-fw.xml', '(nat.security is.missing)' ), array( 'bidir-web', 'dnat-pool', 'dnat-port', 'dnat-svc', 'dnat-web2' ), 'filter nat.security is.missing' );
$eq( $names( 'nat-security-fw.xml', '(nat.security is.blocked)' ), array( 'dnat-ext' ), 'filter nat.security is.blocked' );
$eq( $names( 'nat-security-fw.xml', '(nat.security has allow-web)' ), array( 'bidir-web', 'dnat-web' ), 'filter nat.security has <security rule>' );
$eq( $names( 'nat-security-fw.xml', '(nat.security has deny-partner)' ), array(), 'filter nat.security has: only allow rules' );
$eq( $names( 'nat-security-fw.xml', '(nat.security.mismatch is.set)' ), array( 'dnat-pool', 'dnat-port', 'dnat-svc', 'dnat-web', 'dnat-web2' ), 'filter nat.security.mismatch is.set' );
$eq( $names( 'nat-security-fw.xml', '(nat.security.mismatch is.partial)' ), array( 'dnat-pool' ), 'filter nat.security.mismatch is.partial' );
$eq( $names( 'nat-security-fw.xml', '(nat.security.mismatch has asa-port)' ), array( 'dnat-port' ), 'filter nat.security.mismatch has <security rule>' );

// nat-security-fix: adapt, then the NAT traffic is allowed; a second run changes nothing; partial only with approval
$tmp = sys_get_temp_dir() . '/natsec-' . getmypid();
@mkdir( $tmp, 0700 );
$fix = function( string $in, string $out, string $action, string $location = 'any', string $filter = '' ) use ( $repo ) {
    $args = array( 'type=rule', 'ruletype=nat', 'in=' . $in, 'out=' . $out, 'location=' . $location, 'actions=' . $action );
    if( $filter !== '' )
        $args[] = 'filter=' . $filter;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o );
    return array_values( array_map( 'trim', preg_grep( '/^\s+(CHANGED|CLONED|SKIPPED) /', $o ) ) );
};
$lines = $fix( $repo . '/tests/input/nat-security-fw.xml', $tmp . '/fixed.xml', 'nat-security-fix:fix' );
$eq( array_map( function( $l ) { return preg_replace( '/:.*$/', '', $l ); }, $lines ), array(
    "SKIPPED 'wrong-post-nat-ip' (vsys1, post-nat-address, full)", "SKIPPED 'asa-partial' (vsys1, post-nat-address, full)",
    "CLONED as 'asa-partial-nat' before 'asa-partial' (vsys1, post-nat-address, full)",
    "CHANGED 'fw-zone-svc' (vsys1, pre-nat-zone, full)",
    "CHANGED 'asa-port' (vsys1, post-nat-address + translated-port, full)",
    "SKIPPED 'asa-pool-one' (vsys1, post-nat-address, partial)" ), 'nat-security-fix:fix - covered skipped, clone, in place, partial skipped' );
$after = array();
foreach( $run( $tmp . '/fixed.xml', '(name eq dnat-web2) or (name eq dnat-svc) or (name eq dnat-port) or (name eq dnat-pool)' ) as $n => $a )
    $after[$n] = $a['directions'][0]['summary'];
ksort( $after );
$eq( $after, array( 'dnat-pool' => 'missing', 'dnat-port' => 'full', 'dnat-svc' => 'full', 'dnat-web2' => 'full' ), 'after the fix: the NAT traffic is allowed (partial pool not)' );
$c = $one( $tmp . '/fixed.xml', 'dnat-port' )['directions'][0]['contexts'][0];
$eq( array( $rows( $c ), $c['matches'][0]['details'] ), array( array( 'asa-port:full' ), array( 'zones' => 'full', 'source' => 'full', 'destination' => 'full', 'service' => 'full' ) ),
    'after the fix: asa-port - original address, post-NAT zone, original service' );
$again = $fix( $tmp . '/fixed.xml', $tmp . '/fixed2.xml', 'nat-security-fix:fix' );
$eq( count( preg_grep( '/^(CHANGED|CLONED) /', $again ) ), 0, 'nat-security-fix: a second run changes nothing' );
$appr = $fix( $repo . '/tests/input/nat-security-fw.xml', $tmp . '/approved.xml', 'nat-security-fix:clone,true', 'any', '(name eq dnat-pool)' );
$eq( array_map( function( $l ) { return preg_replace( '/:.*$/', '', $l ); }, $appr ), array( "CLONED as 'asa-pool-one-nat' before 'asa-pool-one' (vsys1, post-nat-address, partial)" ),
    'nat-security-fix:clone,true - a partial one with approval, as a clone' );

// Panorama: one context per device group / template stack / vsys; the stack merged (zone of TS-A / TS-B, variable
// of the firewall), targets of the security rules
$a = $one( 'nat-security-panorama.xml', 'dnat-app', 'DG1' );
$ctx = array();
foreach( $a['directions'][0]['contexts'] as $c )
    $ctx[$c['context']] = array( $c['devices'], $zones( $c ), $rows( $c ) );
$eq( $ctx, array(
    'device-group DG1 / template TS-A / vsys1' => array( array( 'SER1' ), array( 'srv' ), array( 'allow-app:full' ) ),
    'device-group DG1 / template TS-B / vsys1' => array( array( 'SER2' ), array( 'srv-b' ), array() ),
    'device-group DG1-child / template TS-A / vsys1' => array( array( 'SER3' ), array( 'srv' ), array() ),
), 'panorama: per firewall context - zone of its template stack, rule target SER1 only' );

$a = $one( 'nat-security-panorama.xml', 'dnat-web', 'DG1' );
$ctx = array();
foreach( $a['directions'][0]['contexts'] as $c )
    $ctx[$c['context']] = array( $zones( $c ), $c['summary'], count( $c['mismatches'] ) );
$eq( $ctx, array(
    'device-group DG1 / template TS-A / vsys1' => array( array( 'dmz' ), 'full', 2 ),
    'device-group DG1 / template TS-B / vsys1' => array( array( 'untrust?' ), 'missing', 0 ),
    'device-group DG1-child / template TS-A / vsys1' => array( array( 'dmz' ), 'full', 2 ),
), 'panorama: variable $dmz-ip of SER2 (other network) - default route only, no proposal there' );
$eq( $a['directions'][0]['contexts'][0]['matches'][0]['location'], 'DG1 (pre)', 'panorama: location of the security rule with pre / post' );

// Panorama: other post-NAT zones on other firewalls (srv / srv-b) - partial, not changed without approval
$pl = $fix( $repo . '/tests/input/nat-security-panorama.xml', $tmp . '/pano.xml', 'nat-security-fix:fix', 'DG1', '(name eq dnat-svc)' );
$eq( array( count( $pl ), (bool)preg_match( "/^SKIPPED 'fw-zone-svc' .*partial.*other post-NAT zones: srv, srv-b/", $pl[0] ?? '' ) ), array( 1, TRUE ),
    'panorama: post-NAT zones differ per firewall - partial, skipped' );

// Panorama without firewalls: the template stacks (not their templates alone)
$a = $one( 'nat-security-panorama-nodevice.xml', 'dnat-app', 'DG1' );
$ctx = array();
foreach( $a['directions'][0]['contexts'] as $c )
    $ctx[$c['context']] = array( $zones( $c ), $rows( $c ) );
$eq( $ctx, array(
    'template-stack TS-A / vsys1 (no device assigned)' => array( array( 'srv' ), array( 'allow-app:full' ) ),
    'template-stack TS-B / vsys1 (no device assigned)' => array( array( 'srv-b' ), array( 'allow-app:full' ) ),
), 'panorama without firewalls: every template stack with the source zones' );

foreach( glob( $tmp . '/*' ) as $f )
    @unlink( $f );
@rmdir( $tmp );

// the range helpers
$eq( NatSecurityMatchTest::ranges(), array( array( array( 1, 4 ), array( 8, 10 ) ), array( array( 3, 4 ) ), array( array( 1, 10 ) ) ), 'ranges: subtract, intersect, normalize' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );

class NatSecurityMatchTest
{
    static function ranges(): array
    {
        return array( NatSecurityMatch::rangesSubtract( array( array( 1, 10 ) ), array( array( 5, 7 ) ) ),
            NatSecurityMatch::rangesIntersect( array( array( 1, 4 ) ), array( array( 3, 9 ) ) ),
            NatSecurityMatch::rangesNormalize( array( array( 5, 10 ), array( 1, 4 ) ) ) );
    }
}
