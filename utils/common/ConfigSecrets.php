<?php
/**
 * ISC License
 *
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
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
 * Master-key encrypted values of a PAN-OS / Panorama configuration (type=master-key).
 *
 * Works on the XML as stored (DOMDocument) - every text node, not only what pan-os-php models.
 * Never returns or prints a decrypted value.
 *
 * Format of an encrypted value: '-' + base64(version byte) + ...
 *   version 1 ("-AQ=="): base64(SHA-1 of the clear text, 28 chars) + base64(AES-256-CBC ciphertext) - PanosCrypto
 *   other versions (e.g. AES-256-GCM, encryption level 2): reported as 'unknown', not decrypted
 */
class ConfigSecrets
{
    /** '-' + base64 of one version byte ('AQ==' = 1) + base64 payload */
    const PATTERN = '/^-([A-Za-z0-9+\/]{2}==)([A-Za-z0-9+\/=]{16,})$/';

    const FORMAT_CBC = 'aes-256-cbc';
    const FORMAT_GCM = 'aes-256-gcm';
    const FORMAT_UNKNOWN = 'unknown';
    const FORMAT_MALFORMED = 'malformed';

    /** prefix of an AES-256-GCM value (encryption level 2) - observed from a real level-2 configuration: '-#A...' */
    const GCM_PREFIX = '-#';

    const KEY_DEFAULT = 'default';
    const KEY_GIVEN = 'given';
    const KEY_UNKNOWN = 'unknown';

    /**
     * @return array|null array( 'version' => int, 'format' => FORMAT_* ) when $value looks like an encrypted value
     */
    public static function parse( $value )
    {
        if( !is_string($value) || $value === '' || $value[0] !== '-' )
            return null;
        // AES-256-GCM (encryption level 2, PAN-OS 10.0+): a different framing, prefix '-#' + base64.
        // Only detected / labelled - the format is not parsed or decrypted (see utils/README_master-key.md).
        if( substr($value, 0, 2) === self::GCM_PREFIX )
        {
            if( preg_match( '#^[A-Za-z0-9+/]{16,}={0,2}$#', substr($value, 2) ) )
                return array( 'version' => 2, 'format' => self::FORMAT_GCM );
            return null;
        }
        if( !preg_match( self::PATTERN, $value, $m ) )
            return null;
        $v = base64_decode( $m[1], TRUE );
        if( $v === FALSE || strlen($v) != 1 )
            return null;
        $version = ord( $v );
        if( $version != 1 )
            return array( 'version' => $version, 'format' => self::FORMAT_UNKNOWN );

        // version 1: 28 characters SHA-1, then ciphertext in 16 byte blocks
        $hash = base64_decode( substr($value, 5, 28), TRUE );
        $ct = base64_decode( substr($value, 33), TRUE );
        if( $hash === FALSE || strlen($hash) != 20 || $ct === FALSE || $ct === '' || strlen($ct) % 16 != 0 )
            return array( 'version' => 1, 'format' => self::FORMAT_MALFORMED );
        return array( 'version' => 1, 'format' => self::FORMAT_CBC );
    }

    /**
     * which master key decrypts $value: KEY_DEFAULT, KEY_GIVEN ($masterKey) or KEY_UNKNOWN; the clear text is dropped
     */
    public static function keyOf( $value, $masterKey = null )
    {
        static $crypto = null;
        if( $crypto === null )
            $crypto = new PanosCrypto();
        $info = self::parse( $value );
        if( $info === null || $info['format'] !== self::FORMAT_CBC )
            return self::KEY_UNKNOWN;
        $r = $crypto->decrypt( $value );
        if( $r !== FALSE && $r !== '' )
            return self::KEY_DEFAULT;
        if( $masterKey !== null && $masterKey !== '' )
        {
            $r = $crypto->decrypt( $value, $masterKey );
            if( $r !== FALSE && $r !== '' )
                return self::KEY_GIVEN;
        }
        return self::KEY_UNKNOWN;
    }

    /**
     * all encrypted values of $doc
     * @return array list of array( xpath, location, field, version, format, length, key ) - never the value
     */
    public static function scan( DOMDocument $doc, $masterKey = null, $withCleartext = FALSE )
    {
        $crypto = $withCleartext ? new PanosCrypto() : null;
        $out = array();
        $x = new DOMXPath( $doc );
        foreach( $x->query('//text()[starts-with(normalize-space(.),"-")]') as $t )
        {
            $value = trim( $t->nodeValue );
            $info = self::parse( $value );
            if( $info === null )
                continue;
            $el = $t->parentNode;
            // only leaf elements hold a value
            if( $el === null || $el->nodeType != XML_ELEMENT_NODE || DH::firstChildElement($el) !== FALSE )
                continue;
            list( $location, $field ) = self::locate( $el );
            $item = array(
                'xpath' => DH::elementToPanXPath( $el ),
                'location' => $location,
                'field' => $field,
                'version' => $info['version'],
                'format' => $info['format'],
                'length' => strlen( $value ),
                'key' => self::keyOf( $value, $masterKey ),
            );
            // cleartext only for values that decrypt (default master key is public, or the given key); opt-in
            if( $withCleartext )
            {
                $clear = null;
                if( $item['key'] === self::KEY_DEFAULT )
                    $clear = $crypto->decrypt( $value );
                elseif( $item['key'] === self::KEY_GIVEN )
                    $clear = $crypto->decrypt( $value, $masterKey );
                $item['cleartext'] = ( $clear === FALSE || $clear === '' ) ? null : $clear;
            }
            $out[] = $item;
        }
        return $out;
    }

    const REKEYED = 'rekeyed';
    const ALREADY = 'already-target-key';
    const FAILED = 'failed';
    const UNSUPPORTED = 'unsupported';

    /**
     * Re-encrypts every encrypted value of $doc (in place) with the target master key.
     * A value is decrypted with $oldKey (custom master key, may be null) or with the default master key - whichever
     * fits (SHA-1 check) - and encrypted with $newKey (null = default master key). Values that already decrypt with the
     * target key stay as they are; values that no key decrypts and values of another format stay unchanged.
     * The clear text only exists inside this function.
     * @return array list of array( xpath, location, field, status (REKEYED|ALREADY|FAILED|UNSUPPORTED), from (default|given|null) )
     */
    public static function rekey( DOMDocument $doc, $oldKey = null, $newKey = null )
    {
        $crypto = new PanosCrypto();
        $oldKey = $oldKey === '' ? null : $oldKey;
        $newKey = $newKey === '' ? null : $newKey;
        $out = array();
        $x = new DOMXPath( $doc );
        foreach( iterator_to_array( $x->query('//text()[starts-with(normalize-space(.),"-")]') ) as $t )
        {
            $value = trim( $t->nodeValue );
            $info = self::parse( $value );
            if( $info === null )
                continue;
            $el = $t->parentNode;
            if( $el === null || $el->nodeType != XML_ELEMENT_NODE || DH::firstChildElement($el) !== FALSE )
                continue;
            list( $location, $field ) = self::locate( $el );
            $item = array( 'xpath' => DH::elementToPanXPath( $el ), 'location' => $location, 'field' => $field, 'status' => self::UNSUPPORTED, 'from' => null );
            if( $info['format'] === self::FORMAT_CBC )
            {
                $item['status'] = self::FAILED;
                $ok = function( $r ) { return $r !== FALSE && $r !== ''; };
                if( $ok( $crypto->decrypt( $value, $newKey ) ) )
                    $item['status'] = self::ALREADY;
                else
                {
                    // the old (custom) key first, then the default key - a configuration can hold both
                    $clear = $oldKey !== null ? $crypto->decrypt( $value, $oldKey ) : FALSE;
                    $from = self::KEY_GIVEN;
                    if( !$ok($clear) )
                    {
                        $clear = $crypto->decrypt( $value );
                        $from = self::KEY_DEFAULT;
                    }
                    if( $ok($clear) )
                    {
                        $new = $crypto->encrypt( $clear, $newKey );
                        $check = $crypto->decrypt( $new, $newKey );
                        // same clear text: decrypts with the target key and carries the same SHA-1
                        if( $check === $clear && substr($new, 0, 33) === substr($value, 0, 33) )
                        {
                            DH::setDomNodeText( $el, $new );
                            $item['status'] = self::REKEYED;
                            $item['from'] = $from;
                        }
                        unset( $check );
                    }
                    unset( $clear );
                }
            }
            $out[] = $item;
        }
        return $out;
    }

    /** algorithm of a password hash (crypt format), by its prefix */
    public static function hashAlgorithm( $value )
    {
        $value = (string)$value;
        if( preg_match( '/^\$([0-9a-z]+)\$/', $value, $m ) )
        {
            $map = array( '1' => 'MD5-crypt', '2a' => 'bcrypt', '2b' => 'bcrypt', '2y' => 'bcrypt', '5' => 'SHA-256-crypt', '6' => 'SHA-512-crypt' );
            return isset($map[$m[1]]) ? $map[$m[1]] : 'crypt $' . $m[1] . '$';
        }
        if( $value === '*' || $value === '!' || $value === '' )
            return 'no password (locked)';
        if( strlen($value) == 13 && preg_match( '/^[.\/0-9A-Za-z]{13}$/', $value ) )
            return 'DES-crypt';
        return 'unknown';
    }

    /**
     * password hashes (phash) of $doc - one-way hashes, independent of the master key
     * @return array list of array( xpath, location, field, algorithm, weak ) - never the hash
     */
    public static function scanHashes( DOMDocument $doc )
    {
        $out = array();
        $x = new DOMXPath( $doc );
        foreach( $x->query('//phash') as $el )
        {
            list( $location, $field ) = self::locate( $el );
            $algo = self::hashAlgorithm( trim($el->textContent) );
            $out[] = array( 'xpath' => DH::elementToPanXPath( $el ), 'location' => $location, 'field' => $field,
                'algorithm' => $algo, 'weak' => in_array( $algo, array( 'MD5-crypt', 'DES-crypt' ), TRUE ) );
        }
        return $out;
    }

    /** number of hashed values (phash) - hashes are not master-key encrypted, listed for information only */
    public static function countHashes( DOMDocument $doc )
    {
        $x = new DOMXPath( $doc );
        return $x->query('//phash')->length;
    }

    /**
     * @return array( location, field ) - location: shared, device-group NAME, template NAME[ / vsys NAME],
     *   template-stack NAME, vsys NAME, mgt-config, device, readonly, ...; field: element path below the location
     *   without entry names (same kind of secret = same field)
     */
    public static function locate( DOMElement $el )
    {
        $chain = array();
        for( $n = $el; $n !== null && $n->nodeType == XML_ELEMENT_NODE; $n = $n->parentNode )
            array_unshift( $chain, $n );

        $location = array();
        $start = 0;
        foreach( $chain as $i => $n )
        {
            $parent = $i > 0 ? $chain[$i - 1]->nodeName : '';
            if( $n->nodeName == 'entry' && in_array( $parent, array( 'device-group', 'template', 'template-stack', 'vsys' ), TRUE ) )
            {
                $location[] = $parent . ' ' . $n->getAttribute('name');
                $start = $i + 1;
            }
            elseif( $i == 1 && in_array( $n->nodeName, array( 'shared', 'mgt-config', 'readonly', 'panorama' ), TRUE ) )
            {
                $location[] = $n->nodeName;
                $start = $i + 1;
            }
            elseif( $n->nodeName == 'entry' && $parent == 'devices' && $i == 2 )
            {
                // /config/devices/entry[localhost.localdomain]: the device itself unless a device group / template follows
                $start = $i + 1;
            }
            elseif( $n->nodeName == 'config' && $i > 0 && $parent == 'entry' )
            {
                // template / template stack: .../entry/config/... - continue with the inner configuration
                $start = $i + 1;
            }
            elseif( $n->nodeName == 'entry' && $parent == 'devices' && $i >= 2 && $chain[$i - 2]->nodeName == 'config' )
            {
                // .../config/devices/entry[localhost.localdomain] inside a template
                $start = $i + 1;
            }
        }
        if( count($location) == 0 )
            $location[] = 'device';

        $field = array();
        for( $i = $start; $i < count($chain); $i++ )
            $field[] = $chain[$i]->nodeName;

        return array( implode( ' / ', $location ), implode( '/', $field ) );
    }

    /**
     * summary of a scan(): totals by key, format, field; 'other_master_key' = well-formed values that neither the
     * default nor the given master key decrypts
     */
    public static function summary( array $items )
    {
        $s = array( 'total' => count($items), 'other_master_key' => 0, 'by_key' => array(), 'by_format' => array(), 'by_field' => array(), 'by_location' => array() );
        foreach( $items as $i )
        {
            if( $i['format'] === self::FORMAT_CBC && $i['key'] === self::KEY_UNKNOWN )
                $s['other_master_key']++;
            foreach( array( 'key' => 'by_key', 'format' => 'by_format', 'field' => 'by_field', 'location' => 'by_location' ) as $k => $b )
                $s[$b][$i[$k]] = isset($s[$b][$i[$k]]) ? $s[$b][$i[$k]] + 1 : 1;
        }
        foreach( array( 'by_field', 'by_location' ) as $b )
            arsort( $s[$b] );
        return $s;
    }
}
