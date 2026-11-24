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
 * Network types and location / template=: the objects live on the PANConf (location=shared) of the firewall or of a
 * template / template-stack; a vsys lists what it imports (interfaces, virtual / logical routers and their static
 * routes, virtual wires, DHCP of the imported interfaces). Synthetic configurations, pan-os-php type=… as on the
 * command line.
 *
 *   php tests/test_network_vsys_import.php
 */
$repo = dirname( __DIR__ );

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

$dir = sys_get_temp_dir() . '/netvsys-' . getmypid();
if( !is_dir( $dir ) )
    mkdir( $dir, 0700, TRUE );

// ---- synthetic configurations: $p prefixes the names per template, so template= is visible in the result
$interfaces = '<interface><ethernet>'
    . '<entry name="ethernet1/1"><layer3><ip><entry name="198.51.100.1/24"/></ip></layer3></entry>'
    . '<entry name="ethernet1/2"><layer3><ip><entry name="192.0.2.1/24"/></ip></layer3></entry>'
    . '<entry name="ethernet1/3"><virtual-wire/></entry><entry name="ethernet1/4"><virtual-wire/></entry>'
    . '</ethernet></interface>';
$rest = function( string $p ) {
    return '<virtual-wire><entry name="' . $p . 'vw-1"><interface1>ethernet1/3</interface1><interface2>ethernet1/4</interface2></entry></virtual-wire>'
        . '<dhcp><interface><entry name="ethernet1/2"><server><mode>auto</mode></server></entry></interface></dhcp>'
        . '<profiles><interface-management-profile><entry name="' . $p . 'imp-1"><ping>yes</ping></entry></interface-management-profile></profiles>';
};
$route = function( string $n, string $dst, string $nh ) {
    return '<static-route><entry name="' . $n . '"><destination>' . $dst . '</destination><nexthop><ip-address>' . $nh . '</ip-address></nexthop><metric>10</metric></entry></static-route>';
};
$vr = function( string $p ) use ( $route ) {
    return '<virtual-router>'
        . '<entry name="' . $p . 'vr-1"><interface><member>ethernet1/1</member></interface><routing-table><ip>' . $route( $p . 'r-1', '10.1.0.0/16', '198.51.100.254' ) . '</ip></routing-table></entry>'
        . '<entry name="' . $p . 'vr-2"><interface><member>ethernet1/2</member></interface><routing-table><ip>' . $route( $p . 'r-2', '10.2.0.0/16', '192.0.2.254' ) . '</ip></routing-table></entry>'
        . '</virtual-router>';
};
$lr = function( string $p ) use ( $route ) {
    $one = function( string $n, string $if, string $r, string $dst, string $nh ) use ( $route ) {
        return '<entry name="' . $n . '"><vrf><entry name="default"><interface><member>' . $if . '</member></interface><routing-table><ip>' . $route( $r, $dst, $nh ) . '</ip></routing-table></entry></vrf></entry>';
    };
    return '<logical-router>' . $one( $p . 'lr-1', 'ethernet1/1', $p . 'r-1', '10.1.0.0/16', '198.51.100.254' )
        . $one( $p . 'lr-2', 'ethernet1/2', $p . 'r-2', '10.2.0.0/16', '192.0.2.254' ) . '</logical-router>';
};
$vsys = function( string $p, string $routerTag ) {
    return '<vsys>'
        . '<entry name="vsys1"><import><network><interface><member>ethernet1/1</member><member>ethernet1/3</member><member>ethernet1/4</member></interface>'
        . '<' . $routerTag . '><member>' . $p . ( $routerTag == 'virtual-router' ? 'vr' : 'lr' ) . '-1</member></' . $routerTag . '><virtual-wire><member>' . $p . 'vw-1</member></virtual-wire></network></import>'
        . '<zone><entry name="' . $p . 'z1"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone></entry>'
        . '<entry name="vsys2"><import><network><interface><member>ethernet1/2</member></interface>'
        . '<' . $routerTag . '><member>' . $p . ( $routerTag == 'virtual-router' ? 'vr' : 'lr' ) . '-2</member></' . $routerTag . '></network></import>'
        . '<zone><entry name="' . $p . 'z2"><network><layer3><member>ethernet1/2</member></layer3></network></entry></zone></entry>'
        . '</vsys>';
};
$head = '<?xml version="1.0"?><config version="11.1.0" urldb="paloaltonetworks"><mgt-config><users/></mgt-config><shared/><devices><entry name="localhost.localdomain">';
$tail = '</entry></devices></config>';
file_put_contents( $dir . '/fw.xml', $head . '<network>' . $interfaces . $vr( '' ) . $rest( '' ) . '</network>' . $vsys( '', 'virtual-router' ) . $tail );
file_put_contents( $dir . '/fw-ar.xml', $head . '<deviceconfig><setting><advance-routing>yes</advance-routing></setting></deviceconfig>'
    . '<network>' . $interfaces . $lr( '' ) . $rest( '' ) . '</network>' . $vsys( '', 'logical-router' ) . $tail );
$tpl = function( string $p ) use ( $interfaces, $vr, $rest, $vsys ) {
    return '<config><devices><entry name="localhost.localdomain"><network>' . $interfaces . $vr( $p ) . $rest( $p ) . '</network>' . $vsys( $p, 'virtual-router' ) . '</entry></devices></config>';
};
file_put_contents( $dir . '/pano.xml', $head . '<device-group/>'
    . '<template><entry name="T1"><settings><default-vsys>vsys1</default-vsys></settings>' . $tpl( 't1-' ) . '</entry></template>'
    . '<template-stack><entry name="TS1"><templates><member>T1</member></templates><settings/>' . $tpl( 'ts-' ) . '</entry></template-stack>'
    . $tail );

// the object names pan-os-php selects (display, shadow-json); null: the location is refused
$names = function( string $file, string $type, string $location, ?string $template = null ) use ( $repo ) {
    $args = array( 'type=' . $type, 'in=' . $file, 'location=' . $location, 'actions=display', 'shadow-json' );
    if( $template !== null )
        $args[] = 'template=' . $template;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>/dev/null', $o, $rc );
    $t = implode( "\n", $o );
    $j = json_decode( substr( $t, (int)strpos( $t, '{' ) ), TRUE );
    if( !is_array( $j ) || isset( $j['error'] ) )
        return null;
    $out = array();
    $walk = function( $x ) use ( &$walk, &$out ) {
        if( !is_array( $x ) )
            return;
        if( isset( $x['object'] ) && is_array( $x['object'] ) )
            foreach( array_keys( $x['object'] ) as $k )
                $out[] = (string)$k;
        foreach( $x as $v )
            $walk( $v );
    };
    $walk( $j );
    // no unique(): each object once (location=any must not list an imported router twice)
    sort( $out );
    return $out;
};

// ---- firewall: PANConf = location shared, a vsys lists what it imports
$fw = $dir . '/fw.xml';
$eq( $names( $fw, 'routing', 'shared' ), array( 'vr-1', 'vr-2' ), 'firewall: routing at shared (PANConf) - all virtual routers' );
$eq( $names( $fw, 'routing', 'vsys1' ), array( 'vr-1' ), 'firewall: routing at vsys1 - the imported virtual router' );
$eq( $names( $fw, 'routing', 'vsys2' ), array( 'vr-2' ), 'firewall: routing at vsys2 - the imported virtual router' );
$eq( $names( $fw, 'static-route', 'shared' ), array( 'r-1', 'r-2' ), 'firewall: static-route at shared' );
$eq( $names( $fw, 'static-route', 'vsys1' ), array( 'r-1' ), 'firewall: static-route at vsys1 - routes of the imported router' );
$eq( $names( $fw, 'virtualwire', 'shared' ), array( 'vw-1' ), 'firewall: virtualwire at shared' );
$eq( $names( $fw, 'virtualwire', 'vsys1' ), array( 'vw-1' ), 'firewall: virtualwire at vsys1 - imported' );
$eq( $names( $fw, 'virtualwire', 'vsys2' ), array(), 'firewall: virtualwire at vsys2 - not imported' );
$eq( $names( $fw, 'dhcp', 'shared' ), array( 'ethernet1/2' ), 'firewall: dhcp at shared' );
$eq( $names( $fw, 'dhcp', 'vsys1' ), array(), 'firewall: dhcp at vsys1 - no imported interface with DHCP' );
$eq( $names( $fw, 'dhcp', 'vsys2' ), array( 'ethernet1/2' ), 'firewall: dhcp at vsys2 - DHCP of the imported interface' );
$eq( $names( $fw, 'interface', 'vsys1' ), array( 'ethernet1/1', 'ethernet1/3', 'ethernet1/4' ), 'firewall: interface at vsys1 - imported' );
$eq( $names( $fw, 'interface', 'vsys2' ), array( 'ethernet1/2' ), 'firewall: interface at vsys2 - imported' );
$eq( $names( $fw, 'zone', 'vsys2' ), array( 'z2' ), 'firewall: zone at vsys2' );
$eq( $names( $fw, 'interface-management-profile', 'shared' ), array( 'imp-1' ), 'firewall: interface-management-profile at shared' );
$eq( $names( $fw, 'interface-management-profile', 'vsys1' ), array(), 'firewall: interface-management-profile is not imported into a vsys' );
$eq( $names( $fw, 'routing', 'any' ), array( 'vr-1', 'vr-2' ), 'firewall: routing at any - each router once' );

// ---- firewall with advanced routing: logical routers
$ar = $dir . '/fw-ar.xml';
$eq( $names( $ar, 'routing', 'shared' ), array( 'lr-1', 'lr-2' ), 'advanced routing: routing at shared - all logical routers' );
$eq( $names( $ar, 'routing', 'vsys2' ), array( 'lr-2' ), 'advanced routing: routing at vsys2 - the imported logical router' );
$eq( $names( $ar, 'static-route', 'vsys1' ), array( 'r-1' ), 'advanced routing: static-route at vsys1 - routes of the imported logical router' );

// ---- Panorama: template / template-stack, each a PANConf with vsys
$pa = $dir . '/pano.xml';
$eq( $names( $pa, 'routing', 'shared', 'T1' ), array( 't1-vr-1', 't1-vr-2' ), 'panorama: routing template=T1 location=shared - PANConf of the template' );
$eq( $names( $pa, 'routing', 'shared', 'TS1' ), array( 'ts-vr-1', 'ts-vr-2' ), 'panorama: routing template=TS1 (stack) location=shared' );
$eq( $names( $pa, 'routing', 'vsys1', 'T1' ), array( 't1-vr-1' ), 'panorama: routing template=T1 location=vsys1 - imported' );
$eq( $names( $pa, 'static-route', 'vsys2', 'TS1' ), array( 'ts-r-2' ), 'panorama: static-route template=TS1 location=vsys2' );
$eq( $names( $pa, 'virtualwire', 'vsys1', 'T1' ), array( 't1-vw-1' ), 'panorama: virtualwire template=T1 location=vsys1' );
$eq( $names( $pa, 'virtualwire', 'vsys2', 'T1' ), array(), 'panorama: virtualwire template=T1 location=vsys2 - not imported' );
$eq( $names( $pa, 'dhcp', 'vsys2', 'T1' ), array( 'ethernet1/2' ), 'panorama: dhcp template=T1 location=vsys2' );
$eq( $names( $pa, 'interface', 'vsys2', 'TS1' ), array( 'ethernet1/2' ), 'panorama: interface template=TS1 location=vsys2' );
$eq( $names( $pa, 'zone', 'vsys1', 'T1' ), array( 't1-z1' ), 'panorama: zone template=T1 location=vsys1' );
$eq( $names( $pa, 'zone', 'vsys1', 'any' ), array( 't1-z1', 'ts-z1' ), 'panorama: zone template=any location=vsys1 - every template and stack' );
$eq( $names( $pa, 'routing', 'any', 'any' ), array( 't1-vr-1', 't1-vr-2', 'ts-vr-1', 'ts-vr-2' ), 'panorama: routing template=any location=any' );
$eq( $names( $pa, 'routing', 'vsys9', 'T1' ), null, 'panorama: unknown vsys is refused' );

// cleanup
foreach( glob( $dir . '/*' ) as $f )
    @unlink( $f );
@rmdir( $dir );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
