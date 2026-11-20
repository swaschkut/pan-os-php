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
 * Test helpers: a signing key, licences and encrypted packages made the same way as the licence tool of the maker
 * (private repository, license/license.php). Only for tests - the key lives in memory of the test and is given to
 * pan-os-php through PANOSPHP_LICENSE_TEST_KEYS.
 */
function testLicenceKeys(): array
{
    $pair = sodium_crypto_sign_keypair();
    return array( 'kid' => 'test-' . bin2hex( random_bytes( 3 ) ), 'secret' => sodium_crypto_sign_secretkey( $pair ), 'public' => sodium_crypto_sign_publickey( $pair ) );
}

function testTrustedJson( array $k ): string
{
    return json_encode( array( 'keys' => array( array( 'kid' => $k['kid'], 'public' => base64_encode( $k['public'] ) ) ) ) );
}

/** @param array $data id, customer, valid_until, grace_days, features, keys (kid => raw key) */
function testLicence( array $k, array $data ): string
{
    $data += array( 'format' => 1, 'id' => 'L-TEST', 'customer' => 'Test', 'issued' => gmdate( 'Y-m-d' ), 'valid_until' => gmdate( 'Y-m-d', time() + 86400 * 365 ),
        'grace_days' => 14, 'features' => array(), 'keys' => array() );
    $data['keys'] = array_map( 'base64_encode', $data['keys'] );
    $payload = json_encode( $data, JSON_UNESCAPED_SLASHES );
    $block = base64_encode( json_encode( array( 'kid' => $k['kid'], 'payload' => base64_encode( $payload ), 'sig' => base64_encode( sodium_crypto_sign_detached( $payload, $k['secret'] ) ) ) ) );
    return "test licence\n\n" . PluginLicense::BEGIN . "\n" . chunk_split( $block, 64, "\n" ) . PluginLicense::END . "\n";
}

/** writes <dir>/<name>.ppp; @return array kid, key (raw) */
function testPack( string $dir, string $name, string $version, string $feature, array $files ): array
{
    $kid = $name . '-' . $version . '-' . bin2hex( random_bytes( 3 ) );
    $key = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
    $nonce = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
    $head = json_encode( array( 'name' => $name, 'version' => $version, 'feature' => $feature, 'kid' => $kid, 'nonce' => base64_encode( $nonce ) ), JSON_UNESCAPED_SLASHES );
    $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt( json_encode( array( 'files' => array_map( 'base64_encode', $files ) ) ), $head, $nonce, $key );
    file_put_contents( $dir . '/' . $name . '.ppp', PluginPackage::MAGIC . "\n" . $head . "\n" . base64_encode( $cipher ) . "\n" );
    return array( 'kid' => $kid, 'key' => $key );
}
