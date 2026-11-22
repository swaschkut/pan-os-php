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
 * Support files (todo/support-file.md): a zip with what support needs (environment, logs, a configuration excerpt,
 * reports), encrypted for the maker of pan-os-php - only the holder of the support key can read it.
 *
 * Format 1 (one file, *.tsf):
 *   line 1  "PAN-OS-PHP-SUPPORT-FILE 1"
 *   line 2  JSON header: kid (support key), created, size, sealed (the file key sealed with the public X25519 key of
 *           the support key - sodium_crypto_box_seal), nonce
 *   rest    the zip, XChaCha20-Poly1305 (sodium, IETF) with the file key; the two lines are the additional data
 *           (a changed header does not open)
 *
 * The public keys: lib/resources/support/keys.json (only public keys; the key pair stays with the maker - licence tool
 * of the private repository, "support-keygen"). Tests: PANOSPHP_SUPPORT_TEST_KEYS (JSON like keys.json).
 */
class SupportFile
{
    const MAGIC = 'PAN-OS-PHP-SUPPORT-FILE 1';
    /** a support file is read into memory: 1 GiB at most */
    const MAX_SIZE = 1073741824;

    /** kid => public key (raw, X25519) */
    public static function trustedKeys(): array
    {
        $out = array();
        $lists = array( (string)@file_get_contents( dirname( __FILE__ ) . '/../resources/support/keys.json' ) );
        if( getenv( 'PANOSPHP_SUPPORT_TEST_KEYS' ) )
            $lists[] = (string)getenv( 'PANOSPHP_SUPPORT_TEST_KEYS' );
        foreach( $lists as $json )
        {
            $j = json_decode( $json, TRUE );
            foreach( (array)( $j['keys'] ?? array() ) as $k )
            {
                $pub = base64_decode( (string)( $k['public'] ?? '' ), TRUE );
                if( is_string( $k['kid'] ?? null ) && preg_match( '/^[A-Za-z0-9._-]{1,64}$/', $k['kid'] ) && $pub !== FALSE && strlen( $pub ) === SODIUM_CRYPTO_BOX_PUBLICKEYBYTES )
                    $out[$k['kid']] = $pub;
            }
        }
        return $out;
    }

    /** the key to encrypt for: the last one of the list (a new key is added at the end) */
    public static function currentKey(): array
    {
        if( !function_exists( 'sodium_crypto_box_seal' ) )
            throw new Exception( 'support file: the PHP extension sodium is missing' );
        $keys = self::trustedKeys();
        if( count( $keys ) === 0 )
            throw new Exception( 'support file: no support key in lib/resources/support/keys.json - this pan-os-php can not make support files' );
        $kid = array_key_last( $keys );
        return array( $kid, $keys[$kid] );
    }

    /** the zip (bytes) encrypted as support file */
    public static function encrypt( string $zip, ?string $kid = null ): string
    {
        if( $kid === null )
            list( $kid, $pub ) = self::currentKey();
        else
        {
            $keys = self::trustedKeys();
            if( !isset( $keys[$kid] ) )
                throw new Exception( 'support file: unknown support key ' . $kid );
            $pub = $keys[$kid];
        }
        $fileKey = sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
        $nonce = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
        $head = self::MAGIC . "\n" . json_encode( array( 'kid' => $kid, 'created' => gmdate( 'Y-m-d\TH:i:s\Z' ), 'size' => strlen( $zip ),
                'sealed' => base64_encode( sodium_crypto_box_seal( $fileKey, $pub ) ), 'nonce' => base64_encode( $nonce ) ), JSON_UNESCAPED_SLASHES ) . "\n";
        $c = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt( $zip, $head, $nonce, $fileKey );
        sodium_memzero( $fileKey );
        return $head . $c;
    }

    /** the header of a support file (readable without a key: kid, created, size) */
    public static function header( string $data ): array
    {
        $a = strpos( $data, "\n" );
        $b = $a === FALSE ? FALSE : strpos( $data, "\n", $a + 1 );
        if( $a === FALSE || $b === FALSE || substr( $data, 0, $a ) !== self::MAGIC )
            throw new Exception( 'support file: not a support file of pan-os-php (or of a newer format)' );
        $h = json_decode( substr( $data, $a + 1, $b - $a - 1 ), TRUE );
        if( !is_array( $h ) || !is_string( $h['kid'] ?? null ) || !is_string( $h['sealed'] ?? null ) || !is_string( $h['nonce'] ?? null ) )
            throw new Exception( 'support file: the header is damaged' );
        $h['_end'] = $b + 1;
        return $h;
    }

    /**
     * the zip of a support file, with the key pair of the support key (file of the licence tool: JSON kid + keypair)
     * @throws Exception wrong key, changed file
     */
    public static function decrypt( string $data, string $keyFileText ): string
    {
        $h = self::header( $data );
        $k = json_decode( $keyFileText, TRUE );
        $pair = is_array( $k ) ? base64_decode( (string)( $k['keypair'] ?? '' ), TRUE ) : FALSE;
        if( $pair === FALSE || strlen( $pair ) !== SODIUM_CRYPTO_BOX_KEYPAIRBYTES )
            throw new Exception( 'support file: the key file is no support key (licence tool: support-keygen)' );
        if( ( $k['kid'] ?? null ) !== $h['kid'] )
            throw new Exception( 'support file: made for the support key ' . preg_replace( '/[^A-Za-z0-9._-]/', '', $h['kid'] ) . ', the key file is ' . preg_replace( '/[^A-Za-z0-9._-]/', '', (string)( $k['kid'] ?? '?' ) ) );
        $fileKey = sodium_crypto_box_seal_open( (string)base64_decode( $h['sealed'], TRUE ), $pair );
        if( $fileKey === FALSE )
            throw new Exception( 'support file: the key does not open it' );
        $zip = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt( substr( $data, $h['_end'] ), substr( $data, 0, $h['_end'] ), (string)base64_decode( $h['nonce'], TRUE ), $fileKey );
        sodium_memzero( $fileKey );
        if( $zip === FALSE )
            throw new Exception( 'support file: damaged or changed (the content does not match)' );
        return $zip;
    }

    /** a new key pair: the key file (JSON, secret) and the line for keys.json (public) */
    public static function keygen( string $kid ): array
    {
        if( !preg_match( '/^[A-Za-z0-9._-]{1,64}$/', $kid ) )
            throw new Exception( 'kid: letters, digits, . _ - (1-64)' );
        $pair = sodium_crypto_box_keypair();
        return array( 'secret' => json_encode( array( 'kid' => $kid, 'keypair' => base64_encode( $pair ), 'created' => gmdate( 'Y-m-d' ),
                'about' => 'support key of pan-os-php - SECRET: opens every support file made for it; keep it out of every repository' ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n",
            'public' => array( 'kid' => $kid, 'public' => base64_encode( sodium_crypto_box_publickey( $pair ) ) ) );
    }
}
