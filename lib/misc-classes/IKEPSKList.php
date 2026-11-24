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
 * The IKE gateways of a configuration (firewall, Panorama templates, SCM folders / snippets / devices) and their
 * pre-shared keys: the PSK list (clear text, a file with chmod 600 only), the SHA-1 list (no clear text) and the
 * comparison of two SHA-1 lists - by the SHA-1 of the clear text that PAN-OS keeps in an encrypted value (level 1,
 * "-AQ=="), so without decrypting.
 *
 * Used by type=scm-ngfw-psk-list (a configuration file, or the firewalls managed by SCM) and type=scm-local-config-probe;
 * the config viewer runs type=scm-ngfw-psk-list. Nothing here prints or logs a secret.
 */
class IKEPSKList
{
    const PSK_LIST_COLUMNS = array( 'serial', 'firewall', 'config_version', 'config_timestamp', 'location', 'ike_gateway',
        'peer_address', 'local_address', 'ike_version', 'psk_status', 'psk_current', 'psk_sha1' );
    /** the SHA-1 list: the columns of the PSK list without the clear text */
    const SHA1_LIST_COLUMNS = array( 'serial', 'firewall', 'config_version', 'config_timestamp', 'location', 'ike_gateway',
        'peer_address', 'local_address', 'ike_version', 'psk_status', 'psk_sha1' );
    const COMPARE_COLUMNS = array( 'ike_gateway', 'result', 'a_where', 'a_peer_address', 'a_psk_status', 'b_where', 'b_peer_address', 'b_psk_status' );

    /** psk_status of a gateway */
    const PSK_DEFAULT = 'default-master-key';
    const PSK_GIVEN = 'given-master-key';
    const PSK_NOT_DECRYPTABLE = 'not-decryptable';
    const PSK_OTHER_FORMAT = 'other-format';
    const PSK_NONE = 'no-psk';

    /** result of a comparison */
    const SAME = 'same';
    const DIFFERENT = 'different';
    const ONLY_A = 'only-a';
    const ONLY_B = 'only-b';
    const UNKNOWN = 'unknown';

    /** an encrypted value of level 1: "-AQ==" + base64 SHA-1 of the clear text (28) + cipher text */
    const ENCRYPTED_V1_PATTERN = '#^-AQ==([A-Za-z0-9+/]{27}=)[A-Za-z0-9+/]+={0,2}$#';

    /** the elements whose entry names the place of a gateway (vsys, template, SCM folder / snippet / device, …) */
    const LOCATION_PARENTS = array( 'vsys', 'template', 'template-stack', 'device-group', 'container', 'snippet', 'cloud', 'on-prem' );

    /** base64 SHA-1 of the clear text kept in an encrypted value of level 1 (null: no such value) */
    public static function encryptedSha1( $value ): ?string
    {
        if( !is_string($value) || !preg_match(self::ENCRYPTED_V1_PATTERN, $value, $m) )
            return null;
        return $m[1];
    }

    /** base64 SHA-1 of a clear text (the format of encryptedSha1()) */
    public static function cleartextSha1( $cleartext ): string
    {
        return base64_encode( sha1( (string)$cleartext, true ) );
    }

    /**
     * the IKE gateways of a configuration
     * @return array of ['location', 'ike_gateway', 'peer_address', 'local_address', 'ike_version', 'psk_status',
     *               'psk_current' (clear text, only when decrypted), 'psk_sha1' (base64 SHA-1 of the clear text, from the
     *               encrypted value - also when it can not be decrypted), 'psk_prefix' (first 5 characters of the encrypted
     *               value: its format)]
     */
    public static function gateways( DOMXPath $xp, ?string $masterKey = null ): array
    {
        $crypto = new PanosCrypto();
        $where = "ancestor::entry[" . implode( " or ", array_map( function( $p ) { return "parent::" . $p; }, self::LOCATION_PARENTS ) ) . "][1]";
        $out = array();
        foreach( $xp->query("//network/ike/gateway/entry") as $gw )
        {
            $at = $xp->query($where, $gw)->item(0);
            $peer = array();
            foreach( $xp->query("peer-address/ip|peer-address/fqdn", $gw) as $n )
                $peer[] = trim($n->textContent);
            if( empty($peer) && $xp->query("peer-address/dynamic", $gw)->length > 0 )
                $peer[] = 'dynamic';
            $local = array();
            foreach( $xp->query("local-address/interface|local-address/ip", $gw) as $n )
                $local[] = trim($n->textContent);
            $ver = $xp->query("protocol/version", $gw)->item(0);

            $row = array( 'location' => $at !== null ? $at->parentNode->nodeName . " " . $at->getAttribute('name') : '',
                'ike_gateway' => $gw->getAttribute('name'), 'peer_address' => implode(" | ", $peer), 'local_address' => implode(" | ", $local),
                'ike_version' => $ver !== null ? trim($ver->textContent) : '', 'psk_status' => self::PSK_NONE, 'psk_current' => '', 'psk_sha1' => '', 'psk_prefix' => '' );

            $key = $xp->query("authentication/pre-shared-key/key", $gw)->item(0);
            if( $key !== null )
            {
                $value = trim($key->textContent);
                $row['psk_prefix'] = substr($value, 0, 5);
                if( strpos($value, "-AQ==") !== 0 )
                    $row['psk_status'] = self::PSK_OTHER_FORMAT;
                else
                {
                    $row['psk_sha1'] = (string)self::encryptedSha1( $value );
                    // PanosCrypto::decrypt(): '' when the key does not fit (the SHA-1 in the value is checked)
                    $clear = $crypto->decrypt( $value, null );
                    $status = self::PSK_DEFAULT;
                    if( $clear === '' && $masterKey !== null )
                    {
                        $clear = $crypto->decrypt( $value, $masterKey );
                        $status = self::PSK_GIVEN;
                    }
                    if( $clear === '' )
                        $status = self::PSK_NOT_DECRYPTABLE;
                    $row['psk_status'] = $status;
                    $row['psk_current'] = $clear;
                }
            }
            $out[] = $row;
        }
        return $out;
    }

    /** a gateway for an output line: never the clear text */
    public static function gatewayLine( array $g ): string
    {
        $text = array( self::PSK_DEFAULT => 'decryptable with the DEFAULT master key', self::PSK_GIVEN => 'decryptable with the given master key',
            self::PSK_NOT_DECRYPTABLE => 'NOT decryptable', self::PSK_OTHER_FORMAT => 'other format - not readable by pan-os-php',
            self::PSK_NONE => 'no pre-shared key' );
        return $g['ike_gateway'] . ( $g['location'] !== '' ? " (" . $g['location'] . ")" : "" )
            . ( $g['peer_address'] !== '' ? "  peer " . $g['peer_address'] : "" ) . ": " . $text[$g['psk_status']];
    }

    /** opens a file for secrets: its folder (0700) and the file created with chmod 600 */
    public static function openSecretFile( string $file )
    {
        $dir = dirname( $file );
        if( !is_dir( $dir ) && !mkdir( $dir, 0700, TRUE ) )
            throw new Exception( "not possible to create " . $dir );
        $old = umask(0077);
        $fh = fopen( $file, "w" );
        umask($old);
        if( $fh === false )
            throw new Exception( "not possible to write " . $file );
        chmod( $file, 0600 );
        return $fh;
    }

    /** the rows of the firewalls / configurations: one per gateway, the columns given */
    private static function rows( array $firewalls, array $columns ): array
    {
        $out = array();
        foreach( $firewalls as $fw )
            foreach( $fw['gateways'] as $g )
            {
                $line = array();
                foreach( $columns as $col )
                    $line[$col] = (string)( array_key_exists($col, $g) ? $g[$col] : ( $fw[$col] ?? '' ) );
                $out[] = $line;
            }
        return $out;
    }

    private static function writeCsv( $fh, array $columns, array $rows ): void
    {
        fputcsv( $fh, $columns, ',', '"', '' );
        foreach( $rows as $r )
            fputcsv( $fh, array_values($r), ',', '"', '' );
        fclose( $fh );
    }

    /**
     * the PSK list: one row per IKE gateway of every firewall / configuration, the clear text when decrypted (chmod 600)
     * @param array $firewalls of ['serial', 'firewall', 'config_version', 'config_timestamp', 'gateways' => gateways()]
     */
    public static function writePSKList( string $file, array $firewalls ): int
    {
        $rows = self::rows( $firewalls, self::PSK_LIST_COLUMNS );
        self::writeCsv( self::openSecretFile( $file ), self::PSK_LIST_COLUMNS, $rows );
        return count( $rows );
    }

    /** the SHA-1 list: the PSK list without the clear text (for a comparison) */
    public static function writeSHA1List( string $file, array $firewalls ): int
    {
        $rows = self::rows( $firewalls, self::SHA1_LIST_COLUMNS );
        $dir = dirname( $file );
        if( !is_dir( $dir ) && !mkdir( $dir, 0700, TRUE ) )
            throw new Exception( "not possible to create " . $dir );
        $fh = fopen( $file, "w" );
        if( $fh === false )
            throw new Exception( "not possible to write " . $file );
        self::writeCsv( $fh, self::SHA1_LIST_COLUMNS, $rows );
        return count( $rows );
    }

    /** a SHA-1 list (or PSK list - the clear text is not read) */
    public static function readSHA1List( string $file ): array
    {
        $fh = @fopen( $file, "r" );
        if( $fh === false )
            throw new Exception( "not possible to read " . $file );
        $head = fgetcsv( $fh, 0, ',', '"', '' );
        if( !is_array($head) || !in_array( 'ike_gateway', $head, TRUE ) || !in_array( 'psk_sha1', $head, TRUE ) )
            throw new Exception( $file . ": no SHA-1 / PSK list (columns ike_gateway, psk_sha1)" );
        $out = array();
        while( ( $l = fgetcsv( $fh, 0, ',', '"', '' ) ) !== FALSE )
        {
            if( count($l) !== count($head) )
                continue;
            $r = array_combine( $head, $l );
            unset( $r['psk_current'] );
            $out[] = $r;
        }
        fclose( $fh );
        return $out;
    }

    /** where a row is: firewall / serial and location */
    public static function where( array $r ): string
    {
        $fw = trim( ( $r['firewall'] ?? '' ) !== '' ? $r['firewall'] . ( ( $r['serial'] ?? '' ) !== '' ? " (" . $r['serial'] . ")" : "" ) : (string)( $r['serial'] ?? '' ) );
        $loc = (string)( $r['location'] ?? '' );
        return trim( $fw . ( $fw !== '' && $loc !== '' ? " / " : "" ) . $loc );
    }

    /**
     * two lists compared by the name of the IKE gateway and the SHA-1 of the pre-shared key: same (every SHA-1 of the
     * name the same on both sides), different, only-a, only-b, unknown (a side without SHA-1: no PSK, other format)
     * @return array rows of COMPARE_COLUMNS, sorted by gateway
     */
    public static function compare( array $a, array $b ): array
    {
        $group = function( array $rows ) {
            $g = array();
            foreach( $rows as $r )
                $g[(string)$r['ike_gateway']][] = $r;
            return $g;
        };
        $ga = $group( $a );
        $gb = $group( $b );
        $names = array_unique( array_merge( array_keys($ga), array_keys($gb) ) );
        sort( $names, SORT_STRING );
        $join = function( array $rows, string $col ) { return implode( "; ", array_unique( array_map( function( $r ) use ( $col ) { return (string)( $r[$col] ?? '' ); }, $rows ) ) ); };
        $out = array();
        foreach( $names as $n )
        {
            $ra = $ga[$n] ?? array();
            $rb = $gb[$n] ?? array();
            $sa = array_unique( array_map( function( $r ) { return (string)$r['psk_sha1']; }, $ra ) );
            $sb = array_unique( array_map( function( $r ) { return (string)$r['psk_sha1']; }, $rb ) );
            if( empty($ra) )
                $result = self::ONLY_B;
            elseif( empty($rb) )
                $result = self::ONLY_A;
            elseif( in_array( '', $sa, TRUE ) || in_array( '', $sb, TRUE ) )
                $result = self::UNKNOWN;
            else
            {
                sort( $sa ); sort( $sb );
                $result = $sa === $sb && count($sa) === 1 ? self::SAME : self::DIFFERENT;
            }
            $out[] = array( 'ike_gateway' => (string)$n, 'result' => $result,
                'a_where' => implode( "; ", array_unique( array_map( array( 'IKEPSKList', 'where' ), $ra ) ) ), 'a_peer_address' => $join( $ra, 'peer_address' ), 'a_psk_status' => $join( $ra, 'psk_status' ),
                'b_where' => implode( "; ", array_unique( array_map( array( 'IKEPSKList', 'where' ), $rb ) ) ), 'b_peer_address' => $join( $rb, 'peer_address' ), 'b_psk_status' => $join( $rb, 'psk_status' ) );
        }
        return $out;
    }

    /** the comparison as CSV (no secret, no SHA-1) */
    public static function writeCompare( string $file, array $rows ): void
    {
        $fh = fopen( $file, "w" );
        if( $fh === false )
            throw new Exception( "not possible to write " . $file );
        self::writeCsv( $fh, self::COMPARE_COLUMNS, $rows );
    }

    /** counts per result */
    public static function compareSummary( array $rows ): array
    {
        $s = array( self::SAME => 0, self::DIFFERENT => 0, self::ONLY_A => 0, self::ONLY_B => 0, self::UNKNOWN => 0 );
        foreach( $rows as $r )
            $s[$r['result']]++;
        return $s;
    }
}
