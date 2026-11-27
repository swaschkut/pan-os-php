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
 * Part of ViewerApp (trait: the same class - $this, private methods and self:: are those of ViewerApp):
 * the network allowed for runs, the API keys of a user (key store, generate, import, connection test).
 */
trait ViewerAppKeys
{
    // ------------------------------------------------------------------ network for runs, API keys of a user, import

    /**
     * Network for runs (administrator): off by default. 'allow' / 'deny': one entry per line - a host name, *.domain,
     * an IP address, a network (10.0.0.0/8), tsg:<id> / tsg:* for SCM tenants, * for everything. A target is allowed
     * when it matches 'allow' and does not match 'deny' (deny wins; an empty allow list allows nothing).
     */
    public function networkGet(): array
    {
        $row = $this->q( "SELECT value FROM settings WHERE name = 'network'" )->fetch();
        $n = $row ? json_decode( $row['value'], TRUE ) : null;
        return array( 'enabled' => !empty( $n['enabled'] ), 'allow' => array_values( (array)( $n['allow'] ?? array() ) ), 'deny' => array_values( (array)( $n['deny'] ?? array() ) ),
            // who: 'all' users or the 'selected' ones (Account, Users; administrators always) - before: all
            'users' => in_array( $n['users'] ?? 'all', array( 'all', 'selected' ), TRUE ) ? ( $n['users'] ?? 'all' ) : 'all',
            // the connection test: 'all' users or the 'selected' ones (administrators and the users allowed per user)
            'conntest' => ( $n['conntest'] ?? 'selected' ) === 'all' ? 'all' : 'selected' );
    }

    public function networkSet( array $in ): array
    {
        $lists = array();
        foreach( array( 'allow', 'deny' ) as $k )
        {
            $v = $in[$k] ?? array();
            if( is_string( $v ) )
                $v = preg_split( '/[\r\n,]+/', $v );
            if( !is_array( $v ) )
                throw new ViewerException( $k . ': a list of hosts / networks', 400 );
            $lists[$k] = array();
            foreach( $v as $e )
            {
                $e = strtolower( trim( (string)$e ) );
                if( $e === '' )
                    continue;
                if( !self::networkPattern( $e ) )
                    throw new ViewerException( $k . ': "' . substr( $e, 0, 80 ) . '" is no host, *.domain, IP address, network (a.b.c.d/n), tsg:<id> or *', 400 );
                $lists[$k][] = $e;
            }
            $lists[$k] = array_values( array_unique( $lists[$k] ) );
        }
        $old = $this->networkGet();
        $users = $in['users'] ?? $old['users'];
        if( !in_array( $users, array( 'all', 'selected' ), TRUE ) )
            throw new ViewerException( 'users: all or selected', 400 );
        $ct = $in['conntest'] ?? $old['conntest'];
        if( !in_array( $ct, array( 'all', 'selected' ), TRUE ) )
            throw new ViewerException( 'conntest: all or selected', 400 );
        $n = array( 'enabled' => !empty( $in['enabled'] ) && $in['enabled'] !== 'false', 'allow' => $lists['allow'], 'deny' => $lists['deny'], 'users' => $users, 'conntest' => $ct );
        $this->q( "INSERT INTO settings (name, value) VALUES ('network', ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value", array( json_encode( $n ) ) );
        return $n;
    }

    private static function networkPattern( string $e ): bool
    {
        return $e === '*' || $e === 'tsg:*' || preg_match( '/^tsg:[0-9]{1,20}$/', $e ) || filter_var( $e, FILTER_VALIDATE_IP ) !== FALSE
            || ( preg_match( '#^([0-9a-f:.]+)/([0-9]{1,3})$#', $e, $m ) && filter_var( $m[1], FILTER_VALIDATE_IP ) !== FALSE )
            || preg_match( '/^(\*\.)?[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$/', $e );
    }

    private static function ipInNet( string $ip, string $net ): bool
    {
        list( $base, $bits ) = explode( '/', $net );
        $a = @inet_pton( $ip );
        $b = @inet_pton( $base );
        if( $a === FALSE || $b === FALSE || strlen( $a ) !== strlen( $b ) )
            return FALSE;
        $bits = (int)$bits;
        if( $bits > strlen( $a ) * 8 )
            return FALSE;
        $bytes = intdiv( $bits, 8 );
        if( substr( $a, 0, $bytes ) !== substr( $b, 0, $bytes ) )
            return FALSE;
        if( $bits % 8 === 0 )
            return TRUE;
        $mask = chr( ( 0xff << ( 8 - $bits % 8 ) ) & 0xff );
        return ( $a[$bytes] & $mask ) === ( $b[$bytes] & $mask );
    }

    /** does one entry of a list match the target (kind panos: host / IP; scm: TSG id)? $ips: the addresses of a host name */
    private static function networkMatch( string $e, string $kind, string $target, array $ips ): bool
    {
        if( $e === '*' )
            return TRUE;
        if( $kind === 'scm' )
            return $e === 'tsg:*' || $e === 'tsg:' . $target;
        if( strpos( $e, 'tsg:' ) === 0 )
            return FALSE;
        if( strpos( $e, '/' ) !== FALSE )
        {
            $cand = filter_var( $target, FILTER_VALIDATE_IP ) !== FALSE ? array( $target ) : $ips;
            foreach( $cand as $ip )
                if( self::ipInNet( $ip, $e ) )
                    return TRUE;
            return FALSE;
        }
        if( strpos( $e, '*.' ) === 0 )
            return substr( $target, -strlen( $e ) + 1 ) === substr( $e, 1 ) && strlen( $target ) > strlen( $e ) - 1;
        if( $e === $target )
            return TRUE;
        // an IP entry and a host name that resolves to it
        return filter_var( $e, FILTER_VALIDATE_IP ) !== FALSE && in_array( $e, $ips, TRUE );
    }

    /**
     * may runs reach this target? null = yes, else the reason why not. With $user (whoever starts it): the deny list of
     * the administrator wins; allowed is what the user's own entries cover (granted by the administrator, e.g. on a
     * request) and - when the user may use the network at all (all users, or this one selected) - the allow list
     */
    public function networkRefusal( string $kind, string $target, ?array $user = null ): ?string
    {
        $n = $this->networkGet();
        if( !$n['enabled'] )
            return 'network for runs is off (an administrator turns it on: Account, Network for runs)';
        $target = strtolower( $target );
        $ips = array();
        if( $kind === 'panos' && filter_var( $target, FILTER_VALIDATE_IP ) === FALSE )
        {
            $needIps = FALSE;
            foreach( array_merge( $n['allow'], $n['deny'] ) as $e )
                $needIps = $needIps || strpos( $e, '/' ) !== FALSE || filter_var( $e, FILTER_VALIDATE_IP ) !== FALSE;
            if( $needIps )
                $ips = @gethostbynamel( $target ) ?: array();
        }
        $own = $user !== null ? $this->userHosts( $user ) : array();
        if( $kind === 'panos' && $ips === array() && filter_var( $target, FILTER_VALIDATE_IP ) === FALSE )
            foreach( $own as $e )
                if( strpos( $e, '/' ) !== FALSE || filter_var( $e, FILTER_VALIDATE_IP ) !== FALSE )
                    $ips = @gethostbynamel( $target ) ?: array();
        foreach( $n['deny'] as $e )
            if( self::networkMatch( $e, $kind, $target, $ips ) )
                return $target . ' is on the deny list of the administrator';
        foreach( $own as $e )
            if( self::networkMatch( $e, $kind, $target, $ips ) )
                return null;
        $userWhy = $user !== null ? $this->networkUserRefusal( $user ) : null;
        if( $userWhy === null )
            foreach( $n['allow'] as $e )
                if( self::networkMatch( $e, $kind, $target, $ips ) )
                    return null;
        return $userWhy !== null ? $target . ': ' . $userWhy . ' - or request this host: Account, Requests'
            : $target . ' is not on the allow list of the administrator' . ( $user !== null ? ' - request it: Account, Requests' : '' );
    }

    /** the owner turns network for the runs of the project on / off (works only while the administrator allows it) */
    public function projectNetworkSet( array $user, $pid, $enabled ): array
    {
        $p = $this->projectGet( $user, $pid, 'owner' );
        $this->q( 'UPDATE projects SET network = ? WHERE id = ?', array( !empty( $enabled ) && $enabled !== 'false' ? 1 : 0, $p['id'] ) );
        return self::projectPublic( $this->projectGet( $user, $pid, 'owner' ) );
    }

    /** the key of the installation for the secrets of the API keys (data directory, readable only by the viewer) */
    private function secretKey(): string
    {
        $f = $this->dataDir . '/keys.secret';
        $k = @file_get_contents( $f );
        if( !is_string( $k ) || strlen( $k ) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES )
        {
            $k = random_bytes( SODIUM_CRYPTO_SECRETBOX_KEYBYTES );
            $old = umask( 0177 );
            $tmp = $f . '.' . getmypid();
            file_put_contents( $tmp, $k );
            umask( $old );
            // two requests at the same time: the first file wins
            if( !@link( $tmp, $f ) )
                $k = (string)file_get_contents( $f );
            @unlink( $tmp );
        }
        return $k;
    }

    private function seal( string $plain ): string
    {
        $nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
        return base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, $this->secretKey() ) );
    }

    private function unseal( string $sealed ): ?string
    {
        $raw = base64_decode( $sealed, TRUE );
        if( $raw === FALSE || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES )
            return null;
        $p = sodium_crypto_secretbox_open( substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), $this->secretKey() );
        return $p === FALSE ? null : $p;
    }

    /** the target of an entry: host name / IP (panos), TSG id (scm, egressip), the entry name (named, other) */
    private static function keyTarget( string $kind, $target ): string
    {
        $t = is_string( $target ) ? trim( $target ) : '';
        if( $kind === 'scm' || $kind === 'egressip' )
        {
            if( !preg_match( '/^[0-9]{1,20}$/', $t ) )
                throw new ViewerException( 'target: the TSG id of the tenant (digits)', 400 );
            return $t;
        }
        if( $kind === 'ldap' )
        {
            // the bind user of the key store entry ldap_user<user>: UPN or DOMAIN\user; pan-os-php reads the entry names in
            // lower case and ':' / '%' / '/' have a meaning there; ',' separates the arguments of user-check-ldap
            if( $t === '' || strlen( $t ) > 200 || preg_match( '#[\x00-\x20\x7F:%/,]#', $t ) )
                throw new ViewerException( 'target: the LDAP bind user (UPN or DOMAIN\\user; no spaces, ":", "%", "/", ",")', 400 );
            return strtolower( $t );
        }
        if( $kind === 'named' )
        {
            if( !in_array( strtolower( $t ), self::KEY_NAMED, TRUE ) )
                throw new ViewerException( 'target: one of ' . implode( ', ', self::KEY_NAMED ), 400 );
            return strtolower( $t );
        }
        if( $kind === 'other' )
        {
            if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9._@-]{0,99}$/', $t ) || self::keyKindOf( $t ) !== 'other' )
                throw new ViewerException( 'target: an entry name (letters, digits, . _ @ -) that is no host, TSG or named entry', 400 );
            return $t;
        }
        $t = strtolower( $t );
        if( filter_var( $t, FILTER_VALIDATE_IP ) === FALSE && !preg_match( '/^[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$/', $t ) )
            throw new ViewerException( 'target: host name or IP address of the firewall / Panorama', 400 );
        return $t;
    }

    /** the kind of a key store entry name (without the port) */
    private static function keyKindOf( string $name ): string
    {
        if( preg_match( '/^tsg_id[0-9]{1,20}$/', $name ) )
            return 'scm';
        if( preg_match( '/^egressip_tsg_id[0-9]{1,20}$/', $name ) )
            return 'egressip';
        if( stripos( $name, 'ldap_user' ) === 0 && strlen( $name ) > 9 )
            return 'ldap';
        if( in_array( strtolower( $name ), self::KEY_NAMED, TRUE ) )
            return 'named';
        $l = strtolower( $name );
        if( filter_var( $l, FILTER_VALIDATE_IP ) !== FALSE || ( strpos( $l, '.' ) !== FALSE && preg_match( '/^[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$/', $l ) ) )
            return 'panos';
        return 'other';
    }

    /** the line of the key store of pan-os-php for an entry */
    private static function keystoreLine( string $kind, string $target, ?int $port, string $secret ): string
    {
        if( $kind === 'scm' )
            return 'tsg_id' . $target . ':' . $secret;
        if( $kind === 'egressip' )
            return 'egressip_tsg_id' . $target . ':' . $secret;
        if( $kind === 'ldap' )
            return 'ldap_user' . $target . ':' . $secret;
        if( $kind === 'panos' && $port !== null && $port !== 443 )
            return $target . '%' . $port . ':' . $secret;
        return $target . ':' . $secret;
    }

    /**
     * the secret of an entry, as the key store loader of pan-os-php reads it: after the first ":" of the line, with at
     * most one more ":" (PAN-OS keys of the newer algorithm); no line breaks. Keys: no spaces; passwords may have them.
     */
    private static function keySecret( $v, string $what, bool $spaces ): string
    {
        if( !is_string( $v ) || $v === '' || strlen( $v ) > 4000 || preg_match( '/[\x00-\x1F\x7F]/', $v ) || substr_count( $v, ':' ) > 1
            || ( !$spaces && strpos( $v, ' ' ) !== FALSE ) )
            throw new ViewerException( $what . ': 1-4000 characters, at most one ":", no line breaks' . ( $spaces ? '' : ', no spaces' ), 400 );
        return $v;
    }

    /** the API keys / entries of the user - never the secret, only its last 4 characters; 'refused': why an import can not use it now */
    public function keyList( array $user ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $out = array();
        foreach( $this->q( 'SELECT kid, kind, target, port, label, hint, created, last_used FROM user_keys WHERE user_id = ? ORDER BY kind, target', array( $user['id'] ) )->fetchAll() as $k )
            $out[] = array( 'kid' => $k['kid'], 'kind' => $k['kind'], 'target' => $k['target'], 'port' => $k['port'] !== null ? (int)$k['port'] : null, 'label' => $k['label'],
                'hint' => '…' . $k['hint'], 'created' => (int)$k['created'], 'last_used' => $k['last_used'] !== null ? (int)$k['last_used'] : null,
                'import' => in_array( $k['kind'], array( 'panos', 'scm' ), TRUE ),
                'refused' => in_array( $k['kind'], array( 'panos', 'scm' ), TRUE ) ? $this->networkRefusal( $k['kind'], $k['target'], $user ) : null );
        return $out;
    }

    private function keyStore( array $user, string $kind, string $target, ?int $port, string $label, string $secret ): void
    {
        $label = trim( $label );
        $label = $label === '' ? $target : self::checkLabel( $label, 'label' );
        $this->q( 'INSERT INTO user_keys (kid, user_id, kind, target, port, label, secret, hint, created) VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(user_id, kind, target) DO UPDATE SET secret = excluded.secret, hint = excluded.hint, label = excluded.label, port = excluded.port, created = excluded.created',
            array( self::randomId( 8 ), $user['id'], $kind, $target, $port, $label, $this->seal( $secret ), substr( $secret, -4 ), time() ) );
    }

    /**
     * a new entry of the user (or a new secret for the same one): panos - target, port (optional), key; scm - target
     * (TSG), client_id, client_secret; egressip - target (TSG), key; named / other - target (the entry name), key
     */
    public function keyAdd( array $user, array $in ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $kind = $in['kind'] ?? '';
        if( !is_string( $kind ) || !isset( self::KEY_KINDS[$kind] ) )
            throw new ViewerException( 'kind: ' . implode( ', ', array_keys( self::KEY_KINDS ) ), 400 );
        $target = self::keyTarget( $kind, $in['target'] ?? null );
        $port = null;
        if( $kind === 'panos' && isset( $in['port'] ) && $in['port'] !== '' && $in['port'] !== null )
        {
            if( !ctype_digit( (string)$in['port'] ) || (int)$in['port'] < 1 || (int)$in['port'] > 65535 )
                throw new ViewerException( 'port: 1-65535', 400 );
            $port = (int)$in['port'];
        }
        if( $kind === 'scm' )
        {
            $id = self::keySecret( $in['client_id'] ?? null, 'client_id', FALSE );
            $sec = self::keySecret( $in['client_secret'] ?? null, 'client_secret', FALSE );
            if( strpos( $id . $sec, '%' ) !== FALSE || strpos( $id . $sec, ':' ) !== FALSE )
                throw new ViewerException( 'client_id / client_secret: no "%" or ":"', 400 );
            $secret = $id . '%' . $sec;
        }
        else
            $secret = self::keySecret( $in['key'] ?? null, 'key', in_array( $kind, array( 'named', 'other', 'ldap' ), TRUE ) );
        if( !in_array( $kind, array( 'named', 'other', 'ldap' ), TRUE ) && strlen( $secret ) < 8 )
            throw new ViewerException( 'key: at least 8 characters', 400 );
        $this->keyStore( $user, $kind, $target, $port, (string)( $in['label'] ?? '' ), $secret );
        foreach( $this->keyList( $user ) as $k )
            if( $k['kind'] === $kind && $k['target'] === $target )
                return $k;
        throw new ViewerException( 'key not stored', 500 );
    }

    /**
     * one HTTP(S) call to a device with a trace for the user (key from a device, connection test): the connection
     * (IP, time, HTTP status), TLS (verify result, the certificates: subject, issuer, validity, SAN, SHA-256), the
     * curl log (TLS handshake, request / answer headers - keys, cookies and authorization masked; the request body is
     * never in it) and a hint for the usual errors. $o: post (body), headers, verify, tls ('1.2' / '1.3' / ''), proxy
     * (FALSE: no proxy of the environment), connect (IP to connect to while the URL keeps the name: TLS name / SNI).
     * Only http(s), no redirects, at most 1 MB.
     */
    private function curlTraced( string $url, array $o, array &$trace ): array
    {
        $verify = !empty( $o['verify'] );
        $verbose = fopen( 'php://temp', 'w+' );
        $ch = curl_init( $url );
        $opt = array(
            CURLOPT_RETURNTRANSFER => TRUE, CURLOPT_FOLLOWLOCATION => FALSE, CURLOPT_CONNECTTIMEOUT => 7, CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => $verify, CURLOPT_SSL_VERIFYHOST => $verify ? 2 : 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP, CURLOPT_MAXFILESIZE => 1000000,
            CURLOPT_HEADER => TRUE, CURLOPT_CERTINFO => TRUE, CURLOPT_VERBOSE => TRUE, CURLOPT_STDERR => $verbose,
        );
        if( isset( $o['post'] ) )
        {
            $opt[CURLOPT_POST] = TRUE;
            $opt[CURLOPT_POSTFIELDS] = $o['post'];
        }
        if( !empty( $o['headers'] ) )
            $opt[CURLOPT_HTTPHEADER] = $o['headers'];
        if( ( $o['tls'] ?? '' ) === '1.2' )
            $opt[CURLOPT_SSLVERSION] = CURL_SSLVERSION_TLSv1_2 | ( defined( 'CURL_SSLVERSION_MAX_TLSv1_2' ) ? CURL_SSLVERSION_MAX_TLSv1_2 : 0 );
        elseif( ( $o['tls'] ?? '' ) === '1.3' )
            $opt[CURLOPT_SSLVERSION] = CURL_SSLVERSION_TLSv1_3;
        if( array_key_exists( 'proxy', $o ) && $o['proxy'] === FALSE )
            $opt[CURLOPT_PROXY] = '';
        if( !empty( $o['connect'] ) )
            $opt[CURLOPT_CONNECT_TO] = array( $o['connect'] );
        curl_setopt_array( $ch, $opt );
        $raw = curl_exec( $ch );
        $r = array( 'raw' => $raw, 'err' => curl_error( $ch ), 'errno' => curl_errno( $ch ), 'code' => (int)curl_getinfo( $ch, CURLINFO_RESPONSE_CODE ) );
        $hsize = (int)curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
        $ip = (string)curl_getinfo( $ch, CURLINFO_PRIMARY_IP );
        $time = (float)curl_getinfo( $ch, CURLINFO_TOTAL_TIME );
        $sslv = curl_getinfo( $ch, CURLINFO_SSL_VERIFYRESULT );
        $certs = curl_getinfo( $ch, CURLINFO_CERTINFO );
        $https = stripos( $url, 'https:' ) === 0;
        curl_close( $ch );
        rewind( $verbose );
        $vlog = (string)stream_get_contents( $verbose, 64000 );
        fclose( $verbose );
        // the connection as curl saw it - secrets masked (the request body is not in it)
        $vlog = preg_replace( array( '/(password=)[^&\s]*/i', '/(key=)[^&\s]*/i', '/^([<>]? *(x-pan-key|authorization|cookie|set-cookie|x-auth-token): *).*$/mi' ),
            array( '$1********', '$1********', '$1********' ), $vlog );
        $trace[] = 'connection: ' . ( $ip !== '' ? $ip : '-' ) . ', ' . sprintf( '%.2f', $time ) . 's, HTTP ' . ( $r['code'] ?: '-' )
            . ( $https && $sslv !== FALSE ? ', certificate verify result ' . (int)$sslv . ( (int)$sslv === 0 ? ' (ok)' : ( $verify ? ' (not trusted)' : ' (not trusted - ignored, check off)' ) ) : '' );
        foreach( is_array( $certs ) ? $certs : array() as $i => $c )
            if( is_array( $c ) )
            {
                $fp = '';
                if( isset( $c['Cert'] ) && function_exists( 'openssl_x509_fingerprint' ) )
                    $fp = (string)@openssl_x509_fingerprint( $c['Cert'], 'sha256' );
                $trace[] = 'certificate ' . $i . ': subject ' . ( $c['Subject'] ?? '?' ) . ' | issuer ' . ( $c['Issuer'] ?? '?' )
                    . ' | valid ' . ( $c['Start date'] ?? '?' ) . ' - ' . ( $c['Expire date'] ?? '?' )
                    . ( isset( $c['X509v3 Subject Alternative Name'] ) ? ' | SAN ' . $c['X509v3 Subject Alternative Name'] : '' )
                    . ( $fp !== '' ? ' | SHA-256 ' . strtoupper( implode( ':', str_split( $fp, 2 ) ) ) : '' );
            }
        $trace[] = '--- curl ---';
        foreach( preg_split( '/\r?\n/', trim( $vlog ) ) as $l )
            if( $l !== '' && !preg_match( '/^[<>] *$/', $l ) )
                // the list of hosts without proxy is long and says little: only that it is set
                $trace[] = substr( preg_replace( "/^(\* Uses proxy env variable no_proxy) == .*/i", '$1 (set)', $l ), 0, 300 );
        $trace[] = '---';
        // what usually helps with the error of curl
        $hint = array( 6 => 'the name does not resolve on the server of the viewer (DNS) - try the IP address',
            7 => 'connection refused / no route - management IP, port, the interface management profile (HTTPS) and permitted IPs of the device, firewalls between',
            28 => 'timeout - the device does not answer: routing, a firewall between, the permitted IPs of the management interface',
            35 => 'TLS handshake failed - TLS version / ciphers of the device (SSL/TLS service profile of the management) and of the server, or not HTTPS on that port',
            51 => 'the certificate does not match the name / IP - use the name of the certificate or turn the certificate check off',
            60 => 'the certificate is not trusted by the server of the viewer (self-signed / own CA) - turn the certificate check off or add the CA on the server',
            56 => 'the connection was closed - proxy, TLS inspection between, or the device', 52 => 'empty answer - not the XML API on that port?' )[$r['errno']] ?? null;
        if( $hint !== null )
            $trace[] = 'hint: ' . $hint;
        $r['headers'] = $raw === FALSE ? '' : substr( (string)$raw, 0, $hsize );
        $r['body'] = $raw === FALSE ? '' : substr( (string)$raw, $hsize );
        return $r;
    }

    /**
     * the connection test (Account): one call to a firewall / Panorama as curl -v would show it - DNS, TCP, TLS
     * (version, cipher, certificate chain, verify result), HTTP status / headers / answer - for the hosts this user may
     * reach (network rules), by the users the administrator allows (conntest). Fixed fields instead of a command line:
     * only http(s), no files, no other options. mode 'reach': GET <path>; 'api': with an own API key (kid) the XML API
     * call show system info (the key in the header X-PAN-KEY, never shown). Returns ok, a summary, the trace and the
     * curl command line to do the same elsewhere.
     */
    public function connTest( array $user, array $in ): array
    {
        if( ( $why = $this->conntestRefusal( $user ) ) !== null )
            throw new ViewerException( $why, 403 );
        $target = self::keyTarget( 'panos', $in['target'] ?? null );
        $port = null;
        if( isset( $in['port'] ) && $in['port'] !== '' && $in['port'] !== null )
        {
            if( !ctype_digit( (string)$in['port'] ) || (int)$in['port'] < 1 || (int)$in['port'] > 65535 )
                throw new ViewerException( 'port: 1-65535', 400 );
            $port = (int)$in['port'];
        }
        $mode = $in['mode'] ?? 'reach';
        if( !in_array( $mode, array( 'reach', 'api' ), TRUE ) )
            throw new ViewerException( 'mode: reach or api', 400 );
        $path = $in['path'] ?? '/api/';
        if( !in_array( $path, array( '/api/', '/', '/php/login.php' ), TRUE ) )
            throw new ViewerException( 'path: /api/, / or /php/login.php', 400 );
        $tls = (string)( $in['tls'] ?? '' );
        if( !in_array( $tls, array( '', '1.2', '1.3' ), TRUE ) )
            throw new ViewerException( 'tls: empty (auto), 1.2 or 1.3', 400 );
        $verify = !empty( $in['verify'] ) && $in['verify'] !== 'false';
        $proxy = !( isset( $in['proxy'] ) && ( $in['proxy'] === FALSE || $in['proxy'] === 'false' ) );
        $sni = trim( strtolower( (string)( $in['servername'] ?? '' ) ) );
        if( $sni !== '' && ( strlen( $sni ) > 253 || !preg_match( '/^[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$/', $sni ) ) )
            throw new ViewerException( 'servername: the host name of the certificate (only the name is sent, the connection goes to the target)', 400 );
        if( ( $why = $this->networkRefusal( 'panos', $target, $user ) ) !== null )
            throw new ViewerException( 'can not reach ' . $target . ': ' . $why, 403 );
        $secret = null;
        if( $mode === 'api' )
        {
            $k = $this->q( "SELECT * FROM user_keys WHERE kid = ? AND user_id = ? AND kind = 'panos'", array( (string)( $in['kid'] ?? '' ), $user['id'] ) )->fetch();
            if( !$k )
                throw new ViewerException( 'kid: one of your API keys of a firewall / Panorama (Account, My API keys)', 400 );
            $secret = $this->unseal( $k['secret'] );
            if( $secret === null )
                throw new ViewerException( 'the API key can not be read (key of the installation changed?) - store it again', 400 );
            $path = '/api/';
        }
        if( !function_exists( 'curl_init' ) )
            throw new ViewerException( 'the PHP curl extension is missing on the server', 500 );

        $scheme = getenv( 'PANOSPHP_VIEWER_TEST_KEYGEN_PLAIN_HTTP' ) === '1' ? 'http' : 'https';
        $hostOf = function( string $h ) { return filter_var( $h, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) !== FALSE ? '[' . $h . ']' : $h; };
        $p = $port ?? ( $scheme === 'https' ? 443 : 80 );
        $url = $scheme . '://' . $hostOf( $sni !== '' ? $sni : $target ) . ( $port !== null ? ':' . $port : '' ) . $path;
        $post = $mode === 'api' ? 'type=op&cmd=' . rawurlencode( '<show><system><info></info></system></show>' ) : null;
        // the same with curl on another computer
        $cmd = 'curl -v' . ( $verify ? '' : ' -k' ) . ( $tls === '1.2' ? ' --tlsv1.2 --tls-max 1.2' : ( $tls === '1.3' ? ' --tlsv1.3' : '' ) )
            . ( $proxy ? '' : " --noproxy '*'" ) . ( $sni !== '' ? ' --connect-to ' . $sni . ':' . $p . ':' . $hostOf( $target ) . ':' . $p : '' )
            . ( $mode === 'api' ? " -H 'X-PAN-KEY: <your API key>' --data '" . $post . "'" : '' ) . " '" . $url . "'";
        $trace = array( ' * connection test to ' . $target . ( $port !== null ? ' port ' . $port : '' ) . ( $sni !== '' ? ' as ' . $sni : '' ) . ' ...',
            'same with curl: ' . $cmd,
            'TLS certificate check: ' . ( $scheme === 'http' ? 'plain HTTP (test simulation)' : ( $verify ? 'on' : 'off' ) ) . ', TLS version: ' . ( $tls === '' ? 'auto' : $tls )
                . ', proxy of the server environment: ' . ( $proxy ? 'yes (if set)' : 'no' ) );
        $c = $this->curlTraced( $url, array( 'post' => $post, 'verify' => $verify, 'tls' => $tls, 'proxy' => $proxy ? null : FALSE,
            'connect' => $sni !== '' ? $sni . ':' . $p . ':' . $target . ':' . $p : null, 'headers' => $secret !== null ? array( 'X-PAN-KEY: ' . $secret ) : array() ), $trace );
        $mask = function( string $t ) use ( $secret ) {
            if( $secret !== null && $secret !== '' )
                $t = str_replace( $secret, '********', $t );
            $t = preg_replace( '#(<key>)(.*?)(</key>)#s', '$1********$3', $t );
            return preg_replace( '/^(set-cookie|x-pan-key|authorization): *.*$/mi', '$1: ********', $t );
        };
        $summary = array();
        $ok = $c['raw'] !== FALSE;
        if( $ok )
        {
            $trace[] = 'answer headers: ' . trim( preg_replace( '/\r?\n/', ' | ', $mask( $c['headers'] ) ) );
            $trace[] = 'answer (' . strlen( $c['body'] ) . ' bytes): ' . substr( preg_replace( '/\s+/', ' ', $mask( $c['body'] ) ), 0, 4000 );
            $summary[] = 'reached ' . $target . ', HTTP ' . $c['code'];
            if( $mode === 'api' )
            {
                $doc = new DOMDocument();
                $resp = trim( $c['body'] ) !== '' && @$doc->loadXML( trim( $c['body'] ), LIBXML_NONET ) ? $doc->documentElement : null;
                if( $resp !== null && $resp->nodeName === 'response' && $resp->getAttribute( 'status' ) === 'success' )
                {
                    $info = array();
                    foreach( array( 'hostname', 'model', 'serial', 'sw-version', 'ip-address' ) as $f )
                        foreach( $doc->getElementsByTagName( $f ) as $e )
                        {
                            $info[] = $f . ' ' . trim( $e->textContent );
                            break;
                        }
                    $summary[] = 'XML API with your key: ok' . ( $info ? ' - ' . implode( ', ', $info ) : '' );
                }
                else
                {
                    $ok = FALSE;
                    $summary[] = 'XML API with your key: ' . ( $resp !== null && $resp->nodeName === 'response' ? substr( trim( preg_replace( '/\s+/', ' ', $mask( $resp->textContent ) ) ), 0, 200 ) ?: 'refused' : 'no XML API answer' );
                }
            }
        }
        else
            $summary[] = 'no answer: ' . ( $c['errno'] ? '[' . $c['errno'] . '] ' : '' ) . substr( $c['err'], 0, 200 );
        foreach( $trace as $l )
            if( strpos( $l, 'hint: ' ) === 0 )
                $summary[] = $l;
        unset( $secret );
        return array( 'ok' => $ok, 'summary' => $summary, 'curl' => $cmd, 'debug' => $mask( implode( "\n", $trace ) ) );
    }

    /**
     * the API key of a firewall / Panorama from its management address with user name + password (as pan-os-php
     * type=key-manager add=<host>: the XML API type=keygen), stored as an own entry of kind panos (personal, encrypted;
     * an entry of the same host is replaced). The password is only sent to the device (POST, never in the URL) - it is
     * not stored, not logged and not in the audit log (fields 'username' / 'password' are not kept there). Only to hosts
     * the administrator allows for runs (Account, Network for runs). TLS: the certificate is checked only with
     * 'verify' (firewalls mostly have their own certificate - as pan-os-php, which does not check it).
     * Returns the entry as keyList (never the key).
     */
    public function keyGenerate( array $user, array $in ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $target = self::keyTarget( 'panos', $in['target'] ?? null );
        $port = null;
        if( isset( $in['port'] ) && $in['port'] !== '' && $in['port'] !== null )
        {
            if( !ctype_digit( (string)$in['port'] ) || (int)$in['port'] < 1 || (int)$in['port'] > 65535 )
                throw new ViewerException( 'port: 1-65535', 400 );
            $port = (int)$in['port'];
        }
        $name = $in['username'] ?? null;
        if( !is_string( $name ) || trim( $name ) === '' || strlen( $name ) > 200 || preg_match( '/[\x00-\x1F\x7F]/', $name ) )
            throw new ViewerException( 'username: the administrator of the firewall / Panorama', 400 );
        $password = $in['password'] ?? null;
        if( !is_string( $password ) || $password === '' || strlen( $password ) > 1000 )
            throw new ViewerException( 'password: the password of the administrator', 400 );
        $why = $this->networkRefusal( 'panos', $target, $user );
        if( $why !== null )
            throw new ViewerException( 'can not reach ' . $target . ': ' . $why, 403 );
        if( !function_exists( 'curl_init' ) )
            throw new ViewerException( 'the PHP curl extension is missing on the server', 500 );

        $host = filter_var( $target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) !== FALSE ? '[' . $target . ']' : $target;
        // tests only: a plain HTTP device simulation (never set in an installation - the password would go unencrypted)
        $scheme = getenv( 'PANOSPHP_VIEWER_TEST_KEYGEN_PLAIN_HTTP' ) === '1' ? 'http' : 'https';
        $verify = !empty( $in['verify'] ) && $in['verify'] !== 'false';
        $url = $scheme . '://' . $host . ( $port !== null ? ':' . $port : '' ) . '/api/';
        // the debug trace for the user (as pan-os-php debugapi): the call, TLS, the answer - never the password, the key
        // only shortened as pan-os-php prints it
        $trace = array( " * generating an API key from '" . $target . "'" . ( $port !== null ? ' port ' . $port : '' ) . '...',
            'API call through POST: "' . $url . '?type=keygen"',
            'RAW HTTP POST Content: user=' . rawurlencode( $name ) . '&password=********',
            'TLS certificate check: ' . ( $scheme === 'http' ? 'plain HTTP (test simulation)' : ( $verify ? 'on' : 'off (as pan-os-php)' ) ) );
        // as pan-os-php (12 ... 12) for a key of usual length, a short one less (never more than a third of it)
        $short = function( string $k ) { $n = strlen( $k ) >= 72 ? 12 : ( strlen( $k ) >= 24 ? 4 : 0 );
            return $n > 0 ? substr( $k, 0, $n ) . '...' . substr( $k, -$n ) : str_repeat( '*', strlen( $k ) ); };
        $fail = function( string $msg, int $code ) use ( &$trace ) {
            $trace[] = ' FAILED: ' . $msg;
            throw new ViewerDetailException( $msg, $code, implode( "\n", $trace ) );
        };
        $c = $this->curlTraced( $url, array( 'post' => 'type=keygen&user=' . rawurlencode( $name ) . '&password=' . rawurlencode( $password ), 'verify' => $verify ), $trace );
        unset( $password, $in['password'] );
        $raw = $c['raw']; $errno = $c['errno']; $err = $c['err']; $code = $c['code'];
        if( $raw === FALSE )
            $fail( 'no answer from ' . $target . ( $port !== null ? ':' . $port : '' ) . ': ' . ( $errno ? '[' . $errno . '] ' : '' ) . substr( $err, 0, 200 ), 502 );
        $body = $c['body'];
        // the answer for the trace: the key shortened, at most 4000 characters
        $shown = preg_replace_callback( '#(<key>)(.*?)(</key>)#s', function( $m ) use ( $short ) { return $m[1] . $short( trim( $m[2] ) ) . $m[3]; }, $body );
        $trace[] = 'answer (' . strlen( $body ) . ' bytes): ' . substr( preg_replace( '/\s+/', ' ', $shown ), 0, 4000 );
        $doc = new DOMDocument();
        $ok = trim( $body ) !== '' && @$doc->loadXML( trim( $body ), LIBXML_NONET );
        $resp = $ok ? $doc->documentElement : null;
        if( $resp === null || $resp->nodeName !== 'response' )
            $fail( $target . ' did not answer as a PAN-OS XML API (HTTP ' . $code . ')', 502 );
        if( $resp->getAttribute( 'status' ) !== 'success' )
        {
            // the message of the device (e.g. "Invalid Credentials.") - a little pause against guessing passwords
            usleep( 1000000 );
            $msg = trim( preg_replace( '/\s+/', ' ', $resp->textContent ) );
            $fail( $target . ': ' . ( $msg !== '' ? substr( $msg, 0, 200 ) : 'key generation refused' ), 400 );
        }
        // as pan-os-php: response / result / key
        $key = null;
        foreach( $resp->childNodes as $r )
            if( $r instanceof DOMElement && $r->nodeName === 'result' )
                foreach( $r->childNodes as $k )
                    if( $k instanceof DOMElement && $k->nodeName === 'key' && $key === null )
                        $key = trim( $k->textContent );
        if( $key === null || $key === '' )
            $fail( $target . ' answered without <result><key> - see the answer in the debug output', 502 );
        if( preg_match( '/[\x00-\x20\x7F]/', $key ) || substr_count( $key, ':' ) > 1 || strlen( $key ) > 4000 )
            $fail( $target . ' answered a key the key store can not hold (' . strlen( $key ) . ' characters'
                . ( preg_match( '/[\x00-\x20\x7F]/', $key ) ? ', with spaces / line breaks' : '' ) . ( substr_count( $key, ':' ) > 1 ? ', more than one ":"' : '' ) . ')', 502 );
        $trace[] = ' OK, key is ' . $short( $key );
        try
        {
            $this->keyStore( $user, 'panos', $target, $port, (string)( $in['label'] ?? '' ), $key );
        }
        catch( ViewerException $e )
        {
            $fail( 'key received, but not stored: ' . $e->getMessage(), $e->getCode() ?: 400 );
        }
        foreach( $this->keyList( $user ) as $k )
            if( $k['kind'] === 'panos' && $k['target'] === $target )
                return $k + array( 'debug' => implode( "\n", $trace ) );
        $fail( 'key not stored', 500 );
    }

    /**
     * takes the entries of an existing .panconfkeystore (the text of the file) as entries of the user: every line
     * "<name>[%<port>]:<value>" by its kind; an entry of the same kind and target is replaced. Lines that do not fit are
     * skipped - with the line number and the reason, never their content.
     */
    public function keyImport( array $user, $text ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        if( !is_string( $text ) || $text === '' || strlen( $text ) > 1048576 )
            throw new ViewerException( 'keystore: the content of a .panconfkeystore file (at most 1 MB)', 400 );
        $lines = preg_split( '/\r?\n/', $text );
        if( count( $lines ) > 5000 )
            throw new ViewerException( 'keystore: at most 5000 lines', 400 );
        $done = array();
        $skipped = array();
        foreach( $lines as $i => $line )
        {
            if( trim( $line ) === '' || $line[0] === '#' )
                continue;
            $pos = strpos( $line, ':' );
            if( $pos === FALSE || $pos === 0 )
            {
                $skipped[] = array( 'line' => $i + 1, 'reason' => 'no "<name>:<value>"' );
                continue;
            }
            $name = substr( $line, 0, $pos );
            $value = substr( $line, $pos + 1 );
            $port = null;
            if( strpos( $name, '%' ) !== FALSE )
            {
                list( $name, $p ) = explode( '%', $name, 2 );
                if( ctype_digit( $p ) && (int)$p >= 1 && (int)$p <= 65535 )
                    $port = (int)$p;
            }
            $kind = self::keyKindOf( $name );
            try
            {
                $in = array( 'kind' => $kind, 'port' => $kind === 'panos' ? $port : null );
                if( $kind === 'scm' )
                {
                    $in['target'] = substr( $name, 6 );
                    list( $in['client_id'], $in['client_secret'] ) = array_pad( explode( '%', $value, 2 ), 2, '' );
                }
                else
                {
                    $in['target'] = $kind === 'egressip' ? substr( $name, 15 ) : ( $kind === 'ldap' ? substr( $name, 9 ) : $name );
                    $in['key'] = $value;
                }
                $k = $this->keyAdd( $user, $in );
                $done[] = array( 'kind' => $k['kind'], 'target' => $k['target'] );
            }
            catch( ViewerException $e )
            {
                $skipped[] = array( 'line' => $i + 1, 'reason' => $kind . ': ' . $e->getMessage() );
            }
        }
        return array( 'imported' => $done, 'skipped' => $skipped );
    }

    /** change an entry of the user: the label, and - when given - a new secret (as keyAdd: key / client_id + client_secret) */
    public function keyUpdate( array $user, $kid, array $in ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)$kid, $user['id'] ) )->fetch();
        if( !$k )
            throw new ViewerException( 'not found', 404 );
        $newSecret = ( isset( $in['key'] ) && $in['key'] !== '' ) || ( isset( $in['client_id'] ) && $in['client_id'] !== '' ) || ( isset( $in['client_secret'] ) && $in['client_secret'] !== '' );
        if( $newSecret )
            // the same checks as a new entry; it replaces the secret of this kind and target
            return $this->keyAdd( $user, array( 'kind' => $k['kind'], 'target' => $k['target'], 'port' => $in['port'] ?? $k['port'], 'label' => $in['label'] ?? $k['label'] ) + $in );
        $label = trim( (string)( $in['label'] ?? '' ) );
        $label = $label === '' ? $k['target'] : self::checkLabel( $label, 'label' );
        $port = $k['port'];
        if( $k['kind'] === 'panos' && array_key_exists( 'port', $in ) )
        {
            if( $in['port'] === '' || $in['port'] === null )
                $port = null;
            elseif( !ctype_digit( (string)$in['port'] ) || (int)$in['port'] < 1 || (int)$in['port'] > 65535 )
                throw new ViewerException( 'port: 1-65535', 400 );
            else
                $port = (int)$in['port'];
        }
        $this->q( 'UPDATE user_keys SET label = ?, port = ? WHERE id = ?', array( $label, $port, $k['id'] ) );
        foreach( $this->keyList( $user ) as $x )
            if( $x['kid'] === $k['kid'] )
                return $x;
        throw new ViewerException( 'not found', 404 );
    }
}
