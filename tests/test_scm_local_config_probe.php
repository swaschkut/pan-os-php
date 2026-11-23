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
 * scm_local_config_probe.php file=… (offline): the pre-shared keys of the IKE gateways of a synthetic configuration -
 * default master key, own master key, another format; no secret in the output.
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/pan_php_framework.php';
$c = new PanosCrypto();
$dir = sys_get_temp_dir() . '/lcprobe-' . getmypid();
@mkdir( $dir, 0700, TRUE );
$file = $dir . '/fw.xml';
file_put_contents( $file, '<config version="11.1.0"><devices><entry name="localhost.localdomain"><network><ike><gateway>'
    . '<entry name="gw-default"><authentication><pre-shared-key><key>' . $c->encrypt( 'synthetic-psk-1' ) . '</key></pre-shared-key></authentication></entry>'
    . '<entry name="gw-own"><authentication><pre-shared-key><key>' . $c->encrypt( 'synthetic-psk-2', 'abcdefghijklmnop' ) . '</key></pre-shared-key></authentication></entry>'
    . '<entry name="gw-level2"><authentication><pre-shared-key><key>-AA==xyz</key></pre-shared-key></authentication></entry>'
    . '<entry name="gw-cert"><authentication><certificate/></authentication></entry>'
    . '</gateway></ike></network></entry></devices></config>' );
$run = function( array $args ) use ( $repo ) {
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=scm-local-config-probe ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $out, $rc );
    return array( $rc, implode( "\n", $out ) );
};
$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};
list( $rc1, $o1 ) = $run( array( 'file=' . $file ) );
list( $rc2, $o2 ) = $run( array( 'file=' . $file, 'master-key=abcdefghijklmnop' ) );
$eq( array( strpos( $o1, 'gw-default: level 1, decryptable with the DEFAULT master key' ) !== FALSE, strpos( $o1, 'gw-own: level 1, NOT decryptable' ) !== FALSE,
        strpos( $o1, 'gw-level2: other format (prefix -AA==)' ) !== FALSE, strpos( $o1, '4 IKE gateway(s), 3 with pre-shared key' ) !== FALSE ),
    array( TRUE, TRUE, TRUE, TRUE ), 'file=: default master key, unknown one, other format, counts' );
$eq( array( strpos( $o2, 'gw-own: level 1, decryptable with the given master key' ) !== FALSE, strpos( $o2, '1 default master key, 1 given master key, 0 not decryptable' ) !== FALSE ),
    array( TRUE, TRUE ), 'file= master-key=: the own master key' );
$eq( array( strpos( $o1 . $o2, 'synthetic-psk' ), $rc1 ), array( FALSE, 1 ), 'no secret in the output; exit code 1 when a key can not be decrypted' );
exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( empty( $failed ) ? 0 : 1 );
