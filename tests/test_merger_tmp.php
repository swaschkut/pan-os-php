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
 * object-merger (address) and values used directly (tmp objects): the merger never keeps a tmp or a predefined object.
 * A tmp of the same name above an object to merge (e.g. a shared rule uses the IP value): a real object of that name is
 * created at the location of the tmp and everything uses it. Synthetic inputs tests/input/merger-tmp-*.xml.
 *
 *   php tests/test_merger_tmp.php
 */
$repo = dirname( __DIR__ );
$tmp = sys_get_temp_dir() . '/mergertmp-' . getmypid();
@mkdir( $tmp, 0700 );
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$php = function( array $args ) use ( $repo ) {
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o, $rc );
    return array( $rc, $o );
};
// the addresses of a configuration: "<location>/<name>" => type
$addresses = function( string $file ) use ( $php ) {
    list( , $o ) = $php( array( 'type=address', 'in=' . $file, 'location=any', 'actions=display' ) );
    $out = array(); $loc = '';
    foreach( $o as $l )
    {
        if( preg_match( "/processing store '.*?(?:DeviceGroup:([^ ]+) )?\/ AddressStore/", $l, $m ) )
            $loc = isset( $m[1] ) && $m[1] !== '' ? $m[1] : 'shared';
        if( preg_match( "/\* Address '([^']+)'  type: '([^']+)'  value: '([^']*)'/", $l, $m ) )
            $out[$loc . '/' . $m[1]] = $m[2] . ' ' . $m[3];
    }
    ksort( $out );
    return $out;
};
$sources = function( string $file ) {
    $d = new DOMDocument(); $d->load( $file );
    $out = array();
    foreach( ( new DOMXPath( $d ) )->query( '//security/rules/entry[source]' ) as $r )
        $out[$r->getAttribute( 'name' )] = trim( ( new DOMXPath( $d ) )->query( 'source/member', $r )->item( 0 )->textContent );
    ksort( $out );
    return $out;
};

foreach( array( '' => 'without', 'allowMergingWithUpperLevel' => 'with' ) as $arg => $label )
{
    // ---- ghost mode: a shared rule uses the value, the device groups have objects of other names with this value
    $in = $repo . '/tests/input/merger-tmp-ghost.xml';
    $out = $tmp . '/g-' . $label . '.xml';
    list( $rc, $o ) = $php( array_values( array_filter( array( 'type=object-merger', 'objecttype=address', 'in=' . $in, 'out=' . $out, 'location=any', $arg ) ) ) );
    $log = implode( "\n", $o );
    $kept = preg_match_all( "/keeping object '[^']*Address:192\.0\.2\.16'/", $log );
    $names = array_keys( $addresses( $out ) );
    $sourcesOk = TRUE;
    foreach( $sources( $out ) as $rule => $src )
        if( $src !== '192.0.2.16' && !in_array( true, array_map( function( $n ) use ( $src ) { return substr( $n, -strlen( '/' . $src ) ) === '/' . $src; }, $names ), TRUE ) )
            $sourcesOk = FALSE;
    $eq( array( $rc, $kept, $sourcesOk ), array( 0, 0, TRUE ), $label . ' allowMergingWithUpperLevel, ghost mode: the value used directly is never the kept object; every rule names an object that exists (or the value)' );
    // ---- a shared rule uses 192.0.2.16 directly (tmp in shared); device groups have the object of that name
    $in = $repo . '/tests/input/merger-tmp-ancestor.xml';
    $out = $tmp . '/a-' . $label . '.xml';
    list( $rc, $o ) = $php( array_values( array_filter( array( 'type=object-merger', 'objecttype=address', 'in=' . $in, 'out=' . $out, 'location=any', $arg ) ) ) );
    $log = implode( "\n", $o );
    $after = $addresses( $out );
    if( $arg === '' )
    {
        // not merged into the upper level: the device group objects stay, the shared rule keeps using the value
        $eq( array( $rc, preg_match( "/keeping object '[^']*PanoramaConf:\/AddressStore\/Address:192\.0\.2\.16'/", $log ), $after['shared/192.0.2.16'] ?? null,
            $after['C1/192.0.2.16'] ?? null, $after['S1/192.0.2.16'] ?? null ),
            array( 0, 0, 'tmp 192.0.2.16', 'ip-netmask 192.0.2.16/32', 'ip-netmask 192.0.2.16/32' ), 'without allowMergingWithUpperLevel: the tmp in shared is never kept, the objects stay' );
        continue;
    }
    $eq( array( $rc, preg_match( "/keeping object '[^']*PanoramaConf:\/AddressStore\/Address:192\.0\.2\.16'/", $log ), strpos( $log, "create object in DG: 'shared' : '192.0.2.16'" ) !== FALSE ),
        array( 0, 0, TRUE ), 'allowMergingWithUpperLevel: the tmp in shared is never kept - a real object of the same name is created in shared' );
    $eq( array_filter( $after, function( $t ) { return strpos( $t, 'tmp' ) === 0; } ), array(),
        'allowMergingWithUpperLevel: after the merge no object is a tmp (before: every user of the merged objects was)' );
    $eq( $after['shared/192.0.2.16'] ?? null, 'ip-netmask 192.0.2.16/32', 'allowMergingWithUpperLevel: shared/192.0.2.16 is an ip-netmask object' );

}

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
