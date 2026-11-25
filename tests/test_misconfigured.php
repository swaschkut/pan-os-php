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
 * Filter (object is.missconfigured) - also spelled is.missconfigured: services whose name says the other protocol,
 * addresses whose name names another IPv4 value. Synthetic input tests/input/misconfigured.xml.
 *
 *   php tests/test_misconfigured.php
 */
$repo = dirname( __DIR__ );
$in = $repo . '/tests/input/misconfigured.xml';
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
$names = function( string $type, string $filter ) use ( $repo, $in ) {
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=' . $type . ' in=' . escapeshellarg( $in ) .
        ' location=any ' . escapeshellarg( 'filter=' . $filter ) . ' actions=display 2>&1', $o );
    preg_match_all( "/- object '(?:\e\[1m)?([^'\e]+)/", implode( "\n", $o ), $m );
    return $m[1];
};
$eq( $names( 'service', '(object is.missconfigured)' ), array( 'udp-53-wrong', 'tcp-8080-wrong' ),
    'service: /udp/i with protocol tcp, /tcp/i with protocol udp; a name with both, groups and other names not' );
$eq( $names( 'address', '(object is.missconfigured)' ), array( 'h-192.0.2.11-wrong', 'n-198.51.100.0-25-wrong', 'r-192.0.2.100-192.0.2.120-wrong', 'f-192.0.2.5' ),
    'address: another address / prefix / range end in the name, an IPv4 address in the name of an fqdn object; /32, _24, dotted netmask, names without an IPv4 address: fine' );
$eq( count( $names( 'service', '(object is.misconfigured)' ) ), 0, 'only is.missconfigured (no is.misconfigured)' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
