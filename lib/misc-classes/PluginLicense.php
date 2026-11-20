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
 * Licences for licensed plug-ins of pan-os-php (todo/config-viewer-license.md).
 *
 * A licence is a signed text block (Ed25519, PHP sodium). It names the customer, the end date, a grace period, the
 * licensed features (e.g. "migration-cisco") and the keys of the encrypted plug-in packages it unlocks
 * (PluginPackage). Licences are made with the licence tool at the side of the maker of the plug-ins; this class only
 * checks them. The public keys that may sign licences: lib/resources/license/keys.json. Withdrawn licence ids:
 * lib/resources/license/revoked.json (ships with every release).
 *
 * What it protects: nobody can make or extend a licence, and the code of an encrypted plug-in is only readable with the
 * key from a licence. What it can not do: stop a customer who changes the code of pan-os-php on his own computer.
 */
class PluginLicense
{
    const BEGIN = '-----BEGIN PAN-OS-PHP LICENSE-----';
    const END = '-----END PAN-OS-PHP LICENSE-----';
    const WARN_DAYS = 30;

    /** @var array the signed content */
    public $data = array();
    /** @var string the licence as text (for runs: PANOSPHP_LICENSE) */
    public $text = '';

    /**
     * @param string $text the licence block (other text around it is ignored)
     * @throws Exception when it is not a valid licence of a trusted key (the message says why, without key material)
     */
    public static function parse( string $text ): PluginLicense
    {
        if( !function_exists( 'sodium_crypto_sign_verify_detached' ) )
            throw new Exception( 'licence: the PHP extension sodium is missing' );
        $a = strpos( $text, self::BEGIN );
        $b = strpos( $text, self::END );
        if( $a === FALSE || $b === FALSE || $b < $a )
            throw new Exception( 'licence: no licence block found' );
        $raw = base64_decode( preg_replace( '/\s+/', '', substr( $text, $a + strlen( self::BEGIN ), $b - $a - strlen( self::BEGIN ) ) ), TRUE );
        $outer = $raw === FALSE ? null : json_decode( $raw, TRUE );
        if( !is_array( $outer ) || !isset( $outer['kid'], $outer['payload'], $outer['sig'] ) || !is_string( $outer['kid'] ) || !is_string( $outer['payload'] ) || !is_string( $outer['sig'] ) )
            throw new Exception( 'licence: the block is damaged' );
        $keys = self::trustedKeys();
        if( !isset( $keys[$outer['kid']] ) )
            throw new Exception( 'licence: signed with an unknown key (' . preg_replace( '/[^A-Za-z0-9._-]/', '', $outer['kid'] ) . ')' );
        $payload = base64_decode( $outer['payload'], TRUE );
        $sig = base64_decode( $outer['sig'], TRUE );
        if( $payload === FALSE || $sig === FALSE || strlen( $sig ) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached( $sig, $payload, $keys[$outer['kid']] ) )
            throw new Exception( 'licence: the signature does not match - the licence was changed or is not genuine' );
        $d = json_decode( $payload, TRUE );
        if( !is_array( $d ) || ( $d['format'] ?? null ) !== 1 || !is_string( $d['id'] ?? null ) || !is_string( $d['customer'] ?? null )
            || !preg_match( '/^\d{4}-\d{2}-\d{2}$/', (string)( $d['valid_until'] ?? '' ) ) || !is_array( $d['features'] ?? null ) )
            throw new Exception( 'licence: content not understood (format)' );
        if( in_array( $d['id'], self::revoked(), TRUE ) )
            throw new Exception( 'licence: this licence was withdrawn' );
        $l = new PluginLicense();
        $l->data = $d + array( 'grace_days' => 0, 'keys' => array() );
        $l->text = substr( $text, $a, $b - $a + strlen( self::END ) );
        return $l;
    }

    /** the licence block on one line (for the environment of a run) */
    public function compact(): string
    {
        $a = strpos( $this->text, self::BEGIN ) + strlen( self::BEGIN );
        $b = strpos( $this->text, self::END );
        return self::BEGIN . preg_replace( '/\s+/', '', substr( $this->text, $a, $b - $a ) ) . self::END;
    }

    /** kid => public key (raw). keys.json; for tests also PANOSPHP_LICENSE_TEST_KEYS (JSON list like keys.json) */
    public static function trustedKeys(): array
    {
        $out = array();
        $lists = array( (string)@file_get_contents( dirname( __FILE__ ) . '/../resources/license/keys.json' ) );
        // tests only: a key added here can sign licences, but an encrypted plug-in still needs its own key, which only
        // a licence of the maker holds
        if( getenv( 'PANOSPHP_LICENSE_TEST_KEYS' ) )
            $lists[] = (string)getenv( 'PANOSPHP_LICENSE_TEST_KEYS' );
        foreach( $lists as $json )
        {
            $j = json_decode( $json, TRUE );
            foreach( (array)( $j['keys'] ?? array() ) as $k )
            {
                $pub = base64_decode( (string)( $k['public'] ?? '' ), TRUE );
                if( is_string( $k['kid'] ?? null ) && $pub !== FALSE && strlen( $pub ) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES )
                    $out[$k['kid']] = $pub;
            }
        }
        return $out;
    }

    public static function revoked(): array
    {
        $j = json_decode( (string)@file_get_contents( dirname( __FILE__ ) . '/../resources/license/revoked.json' ), TRUE );
        return array_values( array_filter( (array)( $j['revoked'] ?? array() ), 'is_string' ) );
    }

    /** last second of the end date (UTC) */
    public function endsAt(): int
    {
        return (int)strtotime( $this->data['valid_until'] . ' 23:59:59 UTC' );
    }

    /** valid / warning (30 days before the end) / grace (after the end, within the grace days) / expired */
    public function state( ?int $now = null ): string
    {
        $now = $now ?? time();
        $end = $this->endsAt();
        if( $now > $end + 86400 * (int)$this->data['grace_days'] )
            return 'expired';
        if( $now > $end )
            return 'grace';
        return $now > $end - 86400 * self::WARN_DAYS ? 'warning' : 'valid';
    }

    public function usable( ?int $now = null ): bool
    {
        return $this->state( $now ) !== 'expired';
    }

    public function hasFeature( string $feature, ?int $now = null ): bool
    {
        return $this->usable( $now ) && in_array( $feature, $this->data['features'], TRUE );
    }

    /** the key of an encrypted plug-in package (raw), or null */
    public function packageKey( string $kid ): ?string
    {
        $k = $this->data['keys'][$kid] ?? null;
        $raw = is_string( $k ) ? base64_decode( $k, TRUE ) : FALSE;
        return $raw !== FALSE && strlen( $raw ) === SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES ? $raw : null;
    }

    /** what may be shown: everything but the keys */
    public function summary( ?int $now = null ): array
    {
        return array( 'id' => $this->data['id'], 'customer' => $this->data['customer'], 'issued' => $this->data['issued'] ?? null,
            'valid_until' => $this->data['valid_until'], 'grace_days' => (int)$this->data['grace_days'], 'features' => array_values( $this->data['features'] ),
            'packages' => count( $this->data['keys'] ), 'state' => $this->state( $now ),
            'days_left' => (int)floor( ( $this->endsAt() - ( $now ?? time() ) ) / 86400 ) );
    }
}
