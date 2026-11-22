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
 * Prisma Access egress IPs (getPrismaAccessIP/v2, PanSCMAPIConnector::getPrismaAccessEgressIP) - one method for the CLI
 * (scm_egress_ip.php) and the config viewer (SCM tab):
 *   request()      the request body: arguments, or the option file of the Palo Alto documentation (option.txt)
 *   rows()         the answer as flat rows (service type, location / zone, address, address type, …)
 *   fromFile()     the answer of an export (infra/92_egress-ip.json) or a saved snapshot
 *   compare()      added / removed / changed addresses between two states
 *   format()       table / csv / json / list (one address per line, e.g. an external dynamic list)
 */
class SCMEgressIP
{
    const SERVICE_TYPES = array( 'all', 'gp_gateway', 'gp_portal', 'remote_network', 'clean_pipe', 'swg_proxy', 'rbi' );
    const ADDR_TYPES = array( 'all', 'active', 'service_ip', 'auth_cache_service', 'network_load_balancer', 'zti_controller', 'reserved' );
    const LOCATIONS = array( 'all', 'deployed' );
    const COLUMNS = array( 'service_type', 'location', 'address', 'address_type', 'zone_subnet', 'create_time', 'allow_listed' );

    /** environment of the egress-IP API: prod6 for most tenants (default), prod only for older tenants */
    const ENVIRONMENTS = array( 'prod6', 'prod' );
    const ENV_DEFAULT = 'prod6';

    /**
     * Hint for an error of the egress-IP API: HTTP 401 / 403 (login) - a wrong key, a key of another tenant or the other
     * environment (most tenants prod6, older tenants prod); '' for other errors
     */
    public static function loginHint( string $error, string $env, string $tsg = '' ): string
    {
        if( preg_match( '/HTTP 40[13]\b|\b40[13]\b.*(Unauthori[sz]ed|Forbidden)|Unauthori[sz]ed|Forbidden/i', $error ) !== 1 )
            return '';
        $other = $env === 'prod' ? 'prod6' : 'prod';
        return ' - login failed: check the egress-IP API key' . ( $tsg !== '' ? ' of TSG ' . $tsg : '' )
            . ' (Prisma Access > Infrastructure Settings > Egress IP API) and the environment: now ' . $env
            . ', try env=' . $other . ' (most tenants prod6, older tenants prod)';
    }

    /**
     * the request body: $file (option.txt: {"serviceType": …, "addrType": …, "location": …} - also key=value lines),
     * then the arguments (they win). Unknown values: an exception with the known ones (the API may know more: $strict)
     */
    public static function request( ?string $file = null, array $args = array(), bool $strict = TRUE ): array
    {
        $req = array( 'serviceType' => 'all', 'addrType' => 'all', 'location' => 'all' );
        if( $file !== null && $file !== '' )
        {
            if( !is_file( $file ) || !is_readable( $file ) )
                throw new Exception( "option file '" . $file . "' not found" );
            $text = trim( (string)file_get_contents( $file ) );
            $json = json_decode( $text, TRUE );
            if( is_array( $json ) )
                foreach( $json as $k => $v )
                    $req[self::key( $k )] = is_scalar( $v ) ? (string)$v : $v;
            else
                foreach( preg_split( '/\r?\n/', $text ) as $line )
                    if( preg_match( '/^\s*"?([A-Za-z_]+)"?\s*[:=]\s*"?([^",]*)"?\s*,?\s*$/', $line, $m ) )
                        $req[self::key( $m[1] )] = trim( $m[2] );
        }
        foreach( array( 'servicetype' => 'serviceType', 'addrtype' => 'addrType', 'location' => 'location' ) as $a => $k )
            if( isset( $args[$a] ) && $args[$a] !== '' && $args[$a] !== TRUE )
                $req[$k] = (string)$args[$a];
        foreach( array( 'serviceType' => self::SERVICE_TYPES, 'addrType' => self::ADDR_TYPES, 'location' => self::LOCATIONS ) as $k => $known )
        {
            if( !is_string( $req[$k] ) || !preg_match( '/^[a-z_]{1,40}$/', $req[$k] ) )
                throw new Exception( $k . ": '" . json_encode( $req[$k] ) . "' is not valid" );
            if( $strict && !in_array( $req[$k], $known, TRUE ) )
                throw new Exception( $k . ": '" . $req[$k] . "' - known: " . implode( ', ', $known ) );
        }
        return $req;
    }

    private static function key( $k ): string
    {
        $l = strtolower( str_replace( '_', '', (string)$k ) );
        return array( 'servicetype' => 'serviceType', 'addrtype' => 'addrType', 'location' => 'location' )[$l] ?? (string)$k;
    }

    /**
     * the answer ('result' of the API: per location / zone the addresses - address_details [{address, serviceType,
     * addressType, create_time, allow_listed}] or addresses [..]) as flat rows, sorted (service type, location, address)
     */
    public static function rows( $result, string $requestedType = 'all' ): array
    {
        $rows = array();
        foreach( is_array( $result ) ? $result : array() as $entry )
        {
            if( !is_array( $entry ) )
                continue;
            $loc = (string)( $entry['zone'] ?? $entry['location'] ?? $entry['compute_location'] ?? '' );
            $subnets = isset( $entry['zone_subnet'] ) && is_array( $entry['zone_subnet'] ) ? implode( ' ', array_map( 'strval', $entry['zone_subnet'] ) ) : '';
            $details = array();
            if( isset( $entry['address_details'] ) && is_array( $entry['address_details'] ) )
                $details = $entry['address_details'];
            elseif( isset( $entry['addresses'] ) && is_array( $entry['addresses'] ) )
                foreach( $entry['addresses'] as $a )
                    $details[] = is_array( $a ) ? $a : array( 'address' => $a );
            foreach( $details as $d )
            {
                if( !is_array( $d ) || !isset( $d['address'] ) || !is_scalar( $d['address'] ) )
                    continue;
                $rows[] = array(
                    'service_type' => (string)( $d['serviceType'] ?? $d['service_type'] ?? $entry['serviceType'] ?? $requestedType ),
                    'location' => $loc,
                    'address' => (string)$d['address'],
                    'address_type' => (string)( $d['addressType'] ?? $d['address_type'] ?? '' ),
                    'zone_subnet' => $subnets,
                    'create_time' => isset( $d['create_time'] ) && is_scalar( $d['create_time'] ) ? (string)$d['create_time'] : '',
                    'allow_listed' => isset( $d['allow_listed'] ) ? ( is_bool( $d['allow_listed'] ) ? ( $d['allow_listed'] ? 'yes' : 'no' ) : (string)$d['allow_listed'] ) : '',
                );
            }
        }
        usort( $rows, function( $a, $b ) { return array( $a['service_type'], $a['location'], $a['address'] ) <=> array( $b['service_type'], $b['location'], $b['address'] ); } );
        return $rows;
    }

    /**
     * rows of an earlier state: an export directory (infra/92_egress-ip.json), that file, or a snapshot of this script
     * (save=: {"request", "fetched_at", "rows"})
     */
    public static function fromFile( string $path ): array
    {
        if( is_dir( $path ) )
            $path = rtrim( $path, '/' ) . '/infra/92_egress-ip.json';
        if( !is_file( $path ) )
            throw new Exception( "no egress IPs in '" . $path . "' (an export with egressip, its infra/92_egress-ip.json or a snapshot of save=)" );
        $j = json_decode( (string)file_get_contents( $path ), TRUE );
        if( !is_array( $j ) )
            throw new Exception( "'" . $path . "' is no JSON" );
        if( isset( $j['rows'] ) && is_array( $j['rows'] ) )
            return array( 'rows' => $j['rows'], 'request' => $j['request'] ?? null, 'fetched_at' => $j['fetched_at'] ?? null );
        // the answer of the API itself ({"status": "success", "result": [...]})
        if( isset( $j['result'] ) && is_array( $j['result'] ) )
            return array( 'rows' => self::rows( $j['result'] ), 'request' => null, 'fetched_at' => null );
        if( !array_key_exists( 'data', $j ) )
            throw new Exception( "'" . $path . "' holds no egress IPs (rows, data or result)" );
        if( ( $j['status'] ?? 'ok' ) !== 'ok' && ( $j['data'] ?? null ) === null )
            throw new Exception( "'" . $path . "': the egress IPs were not read in this export (" . json_encode( $j['error'] ?? $j['status'] ) . ")" );
        return array( 'rows' => self::rows( $j['data'] ?? array(), $j['request']['serviceType'] ?? 'all' ), 'request' => $j['request'] ?? null, 'fetched_at' => $j['fetched_at'] ?? null );
    }

    /** added / removed addresses (service type + location + address) and changed address types */
    public static function compare( array $old, array $new ): array
    {
        $key = function( $r ) { return $r['service_type'] . '|' . $r['location'] . '|' . $r['address']; };
        $o = array();
        foreach( $old as $r )
            $o[$key( $r )] = $r;
        $n = array();
        foreach( $new as $r )
            $n[$key( $r )] = $r;
        $out = array( 'added' => array(), 'removed' => array(), 'changed' => array() );
        foreach( $n as $k => $r )
            if( !isset( $o[$k] ) )
                $out['added'][] = $r;
            elseif( $o[$k]['address_type'] !== $r['address_type'] || ( $o[$k]['allow_listed'] ?? '' ) !== ( $r['allow_listed'] ?? '' ) )
                $out['changed'][] = array( 'old' => $o[$k], 'new' => $r );
        foreach( $o as $k => $r )
            if( !isset( $n[$k] ) )
                $out['removed'][] = $r;
        return $out;
    }

    /** table / csv / json / list */
    public static function format( array $rows, string $format ): string
    {
        if( $format === 'json' )
            return json_encode( $rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
        if( $format === 'list' )
        {
            $a = array_values( array_unique( array_column( $rows, 'address' ) ) );
            sort( $a, SORT_NATURAL );
            return implode( "\n", $a ) . ( count( $a ) ? "\n" : '' );
        }
        if( $format === 'csv' )
        {
            $h = fopen( 'php://temp', 'r+' );
            fputcsv( $h, self::COLUMNS, ',', '"', '\\' );
            foreach( $rows as $r )
                fputcsv( $h, array_map( function( $c ) use ( $r ) { $v = (string)( $r[$c] ?? '' ); return preg_match( '/^[=+\-@]/', $v ) ? "'" . $v : $v; }, self::COLUMNS ), ',', '"', '\\' );
            rewind( $h );
            return stream_get_contents( $h );
        }
        $cols = array( 'service_type', 'location', 'address', 'address_type', 'allow_listed' );
        $w = array();
        foreach( $cols as $c )
        {
            $w[$c] = strlen( $c );
            foreach( $rows as $r )
                $w[$c] = max( $w[$c], strlen( (string)( $r[$c] ?? '' ) ) );
        }
        $line = function( $r ) use ( $cols, $w ) { return implode( '  ', array_map( function( $c ) use ( $r, $w ) { return str_pad( (string)( $r[$c] ?? '' ), $w[$c] ); }, $cols ) ); };
        $out = $line( array_combine( $cols, $cols ) ) . "\n";
        foreach( $rows as $r )
            $out .= $line( $r ) . "\n";
        return $out;
    }
}
