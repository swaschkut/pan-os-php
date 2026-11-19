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
 * type=config-anonymize: anonymise a Panorama / firewall / SCM configuration (XML) or an SCM export (JSON files).
 *
 * The configuration logic is kept: the XML structure is not changed (same elements, same order), every name is replaced
 * by one pseudonym everywhere it is used (so references, same-name override and shadowing stay as they are), IP
 * addresses are mapped prefix preserving (subnet relations, netmasks, private ranges kept), predefined names
 * (applications, services, URL categories, profiles, interfaces, vsys, keywords) are kept.
 * Nothing customer specific is left: secrets / hashes (placeholder), certificates (new self-signed certificate with the
 * pseudonym name), FQDN / URL / email / LDAP DN / domain\user, serial numbers, MAC addresses, host names, free text
 * (descriptions, banners, response pages), images / logos.
 *
 * Pseudonyms are deterministic for one salt (HMAC-SHA256): Panorama and firewall files anonymised with the same salt
 * keep their relations. Without a salt a random one is used (nothing can be linked to other runs).
 */
class ConfigAnonymizer
{
    const PLACEHOLDER_SECRET = 'Dummy-1234567890';
    const FREE_TEXT = 'anonymized';
    // 1x1 transparent PNG - replaces images / logos
    const IMAGE_1X1 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';

    /** element names whose text is a secret (clear text or encrypted) */
    const SECRET_TAGS = array( 'password', 'phash', 'secret', 'shared-secret', 'pre-shared-key', 'key', 'community',
        'auth-password', 'priv-password', 'authpwd', 'privpwd', 'api-key', 'bind-password', 'passphrase', 'private-key',
        'client-secret', 'psk', 'passwd', 'authentication-key', 'auth-key', 'md5-key', 'encryption-key', 'vm-auth-key',
        'authcode', 'auth-code', 'otp', 'token', 'access-key', 'secret-key', 'private_key', 'client_secret', 'api_key' );

    /** element names with free text - always replaced */
    const FREE_TEXT_TAGS = array( 'description', 'comment', 'comments', 'login-banner', 'motd', 'banner', 'contact',
        'note', 'notes', 'audit-comment', 'custom-message' );

    /** element names that hold free text or an enum value: replaced when the value is text (blank, capitals) */
    const MAYBE_TEXT_TAGS = array( 'location', 'message', 'welcome-page', 'help-page', 'disclaimer', 'header', 'footer',
        'title', 'label', 'company', 'organization', 'locality', 'state', 'country', 'organizational-unit' );

    /** parents whose entry names are PAN-OS models / categories / decoders (kept) */
    const STRUCTURAL_PARENTS = array( 'mlav-engine-filebased-enabled', 'mica-engine-spyware-enabled',
        'mica-engine-vulnerability-enabled', 'mica-engine-wildfire-rules', 'decoder', 'dns-security-categories',
        'advanced-dns-security-categories' );

    /** element names with an image / HTML page (replaced completely) */
    const PAGE_TAGS = array( 'page', 'response-page', 'custom-logo', 'logo', 'image', 'favicon', 'content', 'html' );

    /** element names with match patterns (custom application / threat signatures, data patterns) - may contain customer strings */
    const PATTERN_TAGS = array( 'property-value', 'regex', 'pattern', 'string', 'keyword', 'match-value', 'qualifier-value' );

    /** element names with a host name */
    const HOST_TAGS = array( 'hostname', 'host-name', 'device-name', 'devicename', 'system-name' );

    /** names / values that are kept (PAN-OS keywords, predefined objects that are not in predefined.xml, SCM containers) */
    const KEEP = array( 'any', 'all', 'none', 'yes', 'no', 'default', 'shared', 'predefined', 'panorama', 'localhost.localdomain',
        'enable', 'disable', 'alert', 'allow', 'deny', 'drop', 'block', 'continue', 'override', 'sinkhole', 'reset-both',
        'reset-client', 'reset-server', 'block-ip', 'application-default', 'known-user', 'unknown', 'pre-logon',
        'select', 'strict', 'default-paloalto-dns', 'default-paloalto-cloud', 'pan-sinkhole-default-ip',
        'web-browsing', 'ssl', 'service-http', 'service-https', 'intrazone-default', 'interzone-default',
        'HTTP Command and Control detector', 'HTTP2 Command and Control detector', 'SSL Command and Control detector',
        'Unknown-TCP Command and Control detector', 'Unknown-UDP Command and Control detector',
        'SQL Injection', 'Command Injection',
        'Windows Executables', 'PowerShell Script 1', 'PowerShell Script 2', 'Executable Linked Format', 'MSOffice',
        'Shell', 'OOXML', 'MachO', 'Script', 'Windows Executable',
        'ftp', 'http', 'http2', 'imap', 'pop3', 'smb', 'smtp',
        'All', 'Shared', 'ngfw-shared', 'Prisma Access', 'Mobile Users', 'Remote Networks', 'Service Connections',
        'Mobile Users Container', 'Mobile Users Explicit Proxy', 'Colo Connect', 'Explicit Proxy', 'GlobalProtect',
        'default-route', 'trust', 'untrust', 'predefined-snippet',
        // names of the iron-skillet / best-practice objects pan-os-php creates (public, same in every config)
        'Custom-No-Decrypt', 'Alert_Only_Zone_Protection', 'Recommended_Zone_Protection', 'Forward-All', 'recommended', 'Pre', 'Post', 'pre', 'post', 'admin' );

    /** entry names kept by pattern (interfaces, vsys, IDs, PAN-OS categories) */
    const KEEP_PATTERNS = array(
        '/^vsys\d+$/', '/^(ethernet|ae|tunnel|loopback|vlan|ha|mgmt|management|aux|hsci)[\d\/.]*$/i',
        '/^\d{1,9}$/', '/^pan-(a?dns-sec|sinkhole)-[a-z0-9-]+$/', '/^(critical|high|medium|low|informational)$/',
        '/^(ipv4|ipv6|tcp|udp|icmp|icmp6|sctp)$/i', '/^(aes|des|3des|sha|md5|group|dh|null|ecdh|gcm|aes-\d+)[\w-]*$/i',
        '/^[A-Z]{2}$/',   // region / country codes
        '/^(Alert-Only|Outbound|Inbound|Internal|Exception)(-[A-Za-z]+)?$/',   // iron-skillet profile / group names
    );

    private $salt;
    private $options;
    /** original string => pseudonym (names) */
    public $names = array();
    /** kinds per original name */
    private $nameKinds = array();
    /** caches */
    private $map = array( 'fqdn' => array(), 'label' => array(), 'ip' => array(), 'mac' => array(), 'serial' => array(),
        'text' => array(), 'user' => array() );
    private $bitCache = array();
    private $used = array();
    private $keep = array();
    /** originals replaced (for the leak scan) */
    public $originals = array();
    public $stats = array();

    public function __construct( $salt = null, array $options = array() )
    {
        $this->salt = ( $salt === null || $salt === '' ) ? bin2hex( random_bytes(32) ) : (string)$salt;
        $this->options = $options + array( 'ip' => 'remap', 'predefined' => null );
        foreach( self::KEEP as $k )
            $this->keep[strtolower($k)] = TRUE;
        $this->loadPredefined( $this->options['predefined'] );
    }

    /** names of predefined.xml (applications, services, URL categories, threats, profiles, tags, ...) are kept */
    private function loadPredefined( $file )
    {
        if( $file === null )
            $file = dirname(__FILE__) . '/../../lib/object-classes/predefined.xml';
        if( !is_file($file) )
            return;
        $doc = new DOMDocument();
        if( !@$doc->load( $file, LIBXML_PARSEHUGE ) )
            return;
        $x = new DOMXPath( $doc );
        foreach( $x->query('//@name') as $a )
            $this->keep[strtolower($a->value)] = TRUE;
        foreach( $x->query('//member') as $m )
            $this->keep[strtolower(trim($m->textContent))] = TRUE;
    }

    public function isKept( $value )
    {
        $v = (string)$value;
        if( $v === '' )
            return TRUE;
        if( isset($this->keep[strtolower($v)]) )
            return TRUE;
        foreach( self::KEEP_PATTERNS as $p )
            if( preg_match( $p, $v ) )
                return TRUE;
        return FALSE;
    }

    private function h( $kind, $value, $len = 6 )
    {
        return substr( hash_hmac( 'sha256', $kind . "\0" . $value, $this->salt ), 0, $len );
    }

    /** unique pseudonym: prefix + hash, longer hash on collision */
    private function pseudo( $prefix, $kind, $value )
    {
        for( $len = 6; $len <= 64; $len += 2 )
        {
            $p = $prefix . $this->h( $kind, $value, $len );
            if( !isset($this->used[$p]) || $this->used[$p] === $kind . "\0" . $value )
            {
                $this->used[$p] = $kind . "\0" . $value;
                return $p;
            }
        }
        return $prefix . hash_hmac( 'sha256', $kind . $value . 'x', $this->salt );
    }

    private function remember( $original )
    {
        $o = (string)$original;
        if( strlen($o) >= 3 && !$this->isKept($o) )
            $this->originals[$o] = TRUE;
    }

    private function count( $what )
    {
        $this->stats[$what] = ( $this->stats[$what] ?? 0 ) + 1;
    }

    // ------------------------------------------------------------------ names

    const KIND_PREFIX = array(
        'address' => 'addr', 'address-group' => 'addrgrp', 'service' => 'svc', 'service-group' => 'svcgrp',
        'tag' => 'tag', 'application-group' => 'appgrp', 'application-filter' => 'appflt', 'application' => 'app',
        'external-list' => 'edl', 'schedule' => 'sched', 'region' => 'region', 'zone' => 'zone', 'rules' => 'rule',
        'device-group' => 'dg', 'template' => 'tpl', 'template-stack' => 'stack', 'certificate' => 'cert',
        'profile-group' => 'spg', 'log-settings' => 'log', 'profiles' => 'prof', 'virtual-router' => 'vr',
        'logical-router' => 'lr', 'ike-gateway' => 'ikegw', 'ipsec-tunnel' => 'ipsec', 'variable' => 'var',
        'folder' => 'folder', 'snippet' => 'snippet', 'users' => 'user', 'user-group' => 'usergrp',
        'custom-url-category' => 'urlcat', 'vsys' => 'vsys', 'interface' => 'if', 'server-profile' => 'srvprof',
        'authentication-profile' => 'authprof', 'ssl-tls-service-profile' => 'tlsprof', 'certificate-profile' => 'certprof',
    );

    /** pseudonym of a defined name (entry / object name); null when the name is kept */
    public function name( $original, $kind = 'obj' )
    {
        $o = (string)$original;
        if( isset($this->names[$o]) )
            return $this->names[$o];
        if( $this->isKept($o) )
            return null;
        // names that are addresses / FQDNs / serials keep their kind
        $v = $this->value( $o, TRUE );
        if( $v !== null && $v !== $o )
            return $this->names[$o] = $v;
        if( $o[0] === '$' )
            $p = $this->pseudo( '$var-', 'name', $o );
        else
        {
            $prefix = self::KIND_PREFIX[$kind] ?? ( isset(self::KIND_PREFIX[rtrim($kind, 's')]) ? self::KIND_PREFIX[rtrim($kind, 's')] : 'obj' );
            $p = $this->pseudo( $prefix . '-', 'name', $o );
        }
        $this->remember( $o );
        $this->count( 'names' );
        return $this->names[$o] = $p;
    }

    /** register the defined names first (kind = container element), so references are mapped in any order */
    public function collectNamesXml( DOMDocument $doc )
    {
        $x = new DOMXPath( $doc );
        foreach( $x->query('//*[@name]') as $e )
        {
            $n = $e->getAttribute('name');
            if( $this->isKept($n) || isset($this->names[$n]) )
                continue;
            if( $e->parentNode instanceof DOMElement && in_array( $e->parentNode->nodeName, self::STRUCTURAL_PARENTS, TRUE ) )
            {
                $this->keep[strtolower($n)] = TRUE;
                continue;
            }
            $kind = $e->parentNode instanceof DOMElement ? $e->parentNode->nodeName : 'obj';
            if( $kind === 'entry' || $kind === 'devices' || $kind === 'config' )
                $kind = 'obj';
            $this->nameKinds[$n][$kind] = TRUE;
        }
        // deterministic kind: the alphabetically first one (independent of the order in the file)
        $all = array_keys( $this->nameKinds );
        sort( $all, SORT_STRING );
        foreach( $all as $n )
        {
            $kinds = array_keys( $this->nameKinds[$n] );
            sort( $kinds, SORT_STRING );
            $this->name( $n, $kinds[0] );
        }
    }

    // ------------------------------------------------------------------ values

    /**
     * anonymised form of a text value; null when it is kept as it is.
     * $isName: the value is an entry name (no free text handling)
     */
    public function value( $value, $isName = FALSE )
    {
        $v = (string)$value;
        $t = trim( $v );
        if( $t === '' )
            return null;
        if( !$isName && isset($this->names[$t]) )
            return $this->names[$t];
        if( $this->isKept($t) )
            return null;
        // template / snippet variable referenced only
        if( !$isName && preg_match( '/^\$[A-Za-z0-9_.-]+$/', $t ) )
            return $this->name( $t, 'variable' );

        // PEM, base64 blobs
        if( strpos( $t, '-----BEGIN' ) !== FALSE )
            return '';
        if( strlen($t) > 200 && preg_match( '/^[A-Za-z0-9+\/=\s]+$/', $t ) )
        {
            $this->count( 'images' );
            return self::IMAGE_1X1;
        }
        // IPv4 / IPv6 (address, CIDR, range)
        if( ( $r = $this->ipValue( $t ) ) !== null )
            return $r;
        // MAC
        if( preg_match( '/^([0-9a-f]{2})([:-][0-9a-f]{2}){5}$/i', $t ) )
            return $this->mac( $t );
        // serial number (10-20 digits)
        if( preg_match( '/^\d{10,20}$/', $t ) )
            return $this->serial( $t );
        // URL
        if( preg_match( '#^([a-z][a-z0-9+.-]*)://([^/:?\#]+)(:\d+)?(.*)$#i', $t, $m ) )
            return $m[1] . '://' . ( $this->ipValue($m[2]) ?? $this->fqdn( $m[2] ) ) . $m[3] . $this->path( $m[4] );
        // email
        if( preg_match( '/^([^@\s]+)@([a-z0-9.-]+\.[a-z]{2,63})$/i', $t, $m ) )
            return $this->user( $m[1] ) . '@' . $this->fqdn( $m[2] );
        // LDAP DN
        if( preg_match( '/^(cn|ou|dc|o|uid|c|l|st)=[^,]+(,\s*(cn|ou|dc|o|uid|c|l|st)=[^,]+)+$/i', $t ) )
            return $this->dn( $t );
        // domain\user
        if( preg_match( '/^([^\\\\\s]+)\\\\([^\\\\]+)$/', $t, $m ) )
            return $this->label( $m[1] ) . '\\' . $this->user( $m[2] );
        // URL category entry / host with path: host/path, *.host, host
        if( preg_match( '#^(\^?\*?\.?)((?:[a-z0-9_*-]+\.)+[a-z]{2,63}\.?)(/.*)?$#i', $t, $m ) )
            return $m[1] . $this->fqdn( $m[2] ) . ( isset($m[3]) ? $this->path( $m[3] ) : '' );
        if( $isName )
            return null;
        // free text (more than one word)
        if( preg_match( '/\s/', $t ) )
        {
            $this->remember( $t );
            $this->count( 'free-text' );
            return self::FREE_TEXT;
        }
        return null;
    }

    private function path( $p )
    {
        if( $p === '' || $p === '/' )
            return $p;
        $out = preg_replace_callback( '#[^/?&=*.]+#', function( $m ) {
            if( preg_match( '/^\d+$/', $m[0] ) || $this->isKept($m[0]) )
                return $m[0];
            $this->remember( $m[0] );
            return 'p' . $this->h( 'path', $m[0], 6 );
        }, $p );
        return $out;
    }

    public function user( $u )
    {
        if( $this->isKept($u) )
            return $u;
        if( !isset($this->map['user'][$u]) )
        {
            $this->remember( $u );
            $this->count( 'users' );
            $this->map['user'][$u] = $this->pseudo( 'user-', 'user', strtolower($u) );
        }
        return $this->map['user'][$u];
    }

    private function label( $l )
    {
        $k = strtolower( $l );
        if( !isset($this->map['label'][$k]) )
        {
            $this->remember( $l );
            $this->map['label'][$k] = $this->pseudo( 'd', 'label', $k );
        }
        return $this->map['label'][$k];
    }

    /**
     * FQDN: the registrable domain (last two labels) becomes d<hash>.example, every further label is hashed with its
     * parent, so a.b.customer.com -> l<h>.l<h>.d<h>.example (label structure kept, RFC 2606 reserved TLD).
     */
    public function fqdn( $fqdn )
    {
        $f = rtrim( strtolower( $fqdn ), '.' );
        if( isset($this->map['fqdn'][$f]) )
            return $this->map['fqdn'][$f];
        if( $this->isKept($f) )
            return $fqdn;
        $labels = explode( '.', $f );
        $n = count( $labels );
        if( $n < 2 )
            return $this->map['fqdn'][$f] = $this->label( $f );
        $base = 'd' . $this->h( 'domain', $labels[$n - 2] . '.' . $labels[$n - 1] ) . '.example';
        $out = $base;
        $parent = $labels[$n - 2] . '.' . $labels[$n - 1];
        for( $i = $n - 3; $i >= 0; $i-- )
        {
            $parent = $labels[$i] . '.' . $parent;
            $out = ( $labels[$i] === '*' ? '*' : 'l' . $this->h( 'fqdn', $parent, 6 ) ) . '.' . $out;
        }
        $this->remember( $f );
        $this->remember( $labels[$n - 2] . '.' . $labels[$n - 1] );
        $this->count( 'fqdn' );
        return $this->map['fqdn'][$f] = $out;
    }

    private function dn( $dn )
    {
        $parts = preg_split( '/\s*,\s*/', $dn );
        $dc = array();
        $out = array();
        foreach( $parts as $p )
        {
            list( $k, $v ) = array_pad( explode( '=', $p, 2 ), 2, '' );
            if( strtolower($k) === 'dc' )
                $dc[] = $v;
            else
                $out[] = $k . '=' . ( strtolower($k) === 'c' ? 'XX' : $this->user( $v ) );
        }
        if( count($dc) )
        {
            $mapped = explode( '.', $this->fqdn( implode( '.', $dc ) ) );
            foreach( $mapped as $l )
                $out[] = 'dc=' . $l;
        }
        $this->remember( $dn );
        return implode( ',', $out );
    }

    private function serial( $s )
    {
        if( !isset($this->map['serial'][$s]) )
        {
            $this->remember( $s );
            $this->count( 'serials' );
            $num = hexdec( $this->h( 'serial', $s, 12 ) ) % (int)str_repeat( '9', min( 15, strlen($s) - 1 ) );
            $this->map['serial'][$s] = str_pad( (string)$num, strlen($s), '0', STR_PAD_LEFT );
        }
        return $this->map['serial'][$s];
    }

    private function mac( $m )
    {
        $k = strtolower( $m );
        if( !isset($this->map['mac'][$k]) )
        {
            $this->remember( $m );
            $sep = strpos( $m, '-' ) !== FALSE ? '-' : ':';
            // locally administered unicast address
            $h = $this->h( 'mac', $k, 10 );
            $this->map['mac'][$k] = '02' . $sep . implode( $sep, str_split( $h, 2 ) );
        }
        return $this->map['mac'][$k];
    }

    // ------------------------------------------------------------------ IP addresses

    const SPECIAL4 = array( array( '10.0.0.0', 8, 'private' ), array( '172.16.0.0', 12, 'private' ), array( '192.168.0.0', 16, 'private' ),
        array( '100.64.0.0', 10, 'private' ), array( '169.254.0.0', 16, 'keep' ), array( '127.0.0.0', 8, 'keep' ),
        array( '224.0.0.0', 4, 'keep' ), array( '0.0.0.0', 8, 'keep' ), array( '240.0.0.0', 4, 'keep' ) );
    const SPECIAL6 = array( array( 'fe80::', 10, 'keep' ), array( 'ff00::', 8, 'keep' ), array( 'fc00::', 7, 'private' ),
        array( '::', 96, 'keep' ) );

    /** IPv4 / IPv6 address, CIDR, range, or null when $t is not an address */
    private function ipValue( $t )
    {
        if( preg_match( '#^([0-9a-f.:]+)/(\d{1,3})$#i', $t, $m ) && filter_var( $m[1], FILTER_VALIDATE_IP ) )
        {
            $bits = strpos( $m[1], ':' ) !== FALSE ? 128 : 32;
            if( (int)$m[2] > $bits )
                return null;
            return $this->ip( $m[1], (int)$m[2] ) . '/' . $m[2];
        }
        if( preg_match( '#^([0-9a-f.:]+)-([0-9a-f.:]+)$#i', $t, $m ) && filter_var( $m[1], FILTER_VALIDATE_IP ) && filter_var( $m[2], FILTER_VALIDATE_IP ) )
            return $this->ip( $m[1] ) . '-' . $this->ip( $m[2] );
        if( filter_var( $t, FILTER_VALIDATE_IP ) )
            return $this->ip( $t );
        return null;
    }

    private static function toBits( $ip )
    {
        $bin = inet_pton( $ip );
        $s = '';
        foreach( str_split( $bin ) as $c )
            $s .= str_pad( decbin( ord($c) ), 8, '0', STR_PAD_LEFT );
        return $s;
    }

    private static function fromBits( $bits )
    {
        $bin = '';
        foreach( str_split( $bits, 8 ) as $b )
            $bin .= chr( bindec($b) );
        return inet_ntop( $bin );
    }

    /** a netmask (contiguous ones) such as 255.255.255.0 - kept */
    private static function isNetmask( $bits )
    {
        return (bool)preg_match( '/^1*0*$/', $bits ) && strpos( $bits, '1' ) !== FALSE;
    }

    /**
     * prefix-preserving mapping (Crypto-PAn style, keyed with the salt): two addresses with a common prefix of n bits
     * have a common prefix of n bits afterwards. Special ranges keep their prefix (private stays private, link local /
     * multicast / loopback unchanged). $prefixLen: CIDR length - host bits that are all 0 / all 1 stay so.
     */
    public function ip( $ip, $prefixLen = null )
    {
        $key = $ip . '/' . ( $prefixLen === null ? '' : $prefixLen );
        if( isset($this->map['ip'][$key]) )
            return $this->map['ip'][$key];
        $bits = self::toBits( $ip );
        $n = strlen( $bits );
        if( $n == 32 && ( $bits === str_repeat('0', 32) || $bits === str_repeat('1', 32) || ( $prefixLen === null && self::isNetmask($bits) ) ) )
            return $this->map['ip'][$key] = $ip;
        if( $n == 128 && ( $bits === str_repeat('0', 128) || $bits === str_repeat('0', 127) . '1' ) )
            return $this->map['ip'][$key] = $ip;

        $keep = 0;
        foreach( ( $n == 32 ? self::SPECIAL4 : self::SPECIAL6 ) as $sp )
        {
            if( strncmp( $bits, self::toBits( $sp[0] ), $sp[1] ) === 0 )
            {
                if( $sp[2] === 'keep' || ( $sp[2] === 'private' && $this->options['ip'] === 'keep-private' ) )
                    return $this->map['ip'][$key] = $ip;
                $keep = $sp[1];
                break;
            }
        }
        // public addresses must stay public: IPv4 - the first octet is mapped by a keyed permutation of the public
        // first octets (never 0, 10, 127, 224-255); octets with a special sub-block keep the bits that decide it
        // (100.64/10, 169.254/16, 172.16/12, 192.168/16). IPv6 - global unicast 2000::/3 stays in 2000::/3
        $out = null;
        if( $keep == 0 && $n == 32 )
        {
            $first = bindec( substr( $bits, 0, 8 ) );
            $partial = array( 100 => 10, 169 => 16, 172 => 12, 192 => 16 );
            if( isset($partial[$first]) )
                $keep = $partial[$first];
            else
            {
                $out = str_pad( decbin( $this->publicOctet( $first ) ), 8, '0', STR_PAD_LEFT );
                $keep = 8;
            }
        }
        elseif( $keep == 0 && $n == 128 )
            $keep = substr( $bits, 0, 3 ) === '001' ? 3 : 8;
        if( $out === null )
            $out = substr( $bits, 0, $keep );
        for( $i = $keep; $i < $n; $i++ )
        {
            $prefix = substr( $bits, 0, $i );
            $ck = $n . ':' . $prefix;
            if( !isset($this->bitCache[$ck]) )
                $this->bitCache[$ck] = ord( hash_hmac( 'sha256', 'ip' . $ck, $this->salt, TRUE )[0] ) & 1;
            $out .= ( (int)$bits[$i] ^ $this->bitCache[$ck] ) ? '1' : '0';
        }
        if( $prefixLen !== null && $prefixLen < $n )
        {
            $host = substr( $bits, $prefixLen );
            if( $host === str_repeat( '0', $n - $prefixLen ) )
                $out = substr( $out, 0, $prefixLen ) . $host;
            elseif( $host === str_repeat( '1', $n - $prefixLen ) )
                $out = substr( $out, 0, $prefixLen ) . $host;
        }
        $res = self::fromBits( $out );
        if( $keep == 0 )
            $this->remember( $ip );
        $this->count( 'ip' );
        return $this->map['ip'][$key] = $res;
    }

    private $octetPerm = null;

    /** keyed permutation of the public IPv4 first octets */
    private function publicOctet( $o )
    {
        if( $this->octetPerm === null )
        {
            $pub = array();
            for( $i = 1; $i <= 223; $i++ )
                if( !in_array( $i, array( 10, 127, 100, 169, 172, 192 ), TRUE ) )
                    $pub[] = $i;
            $sorted = $pub;
            usort( $sorted, function( $a, $b ) { return strcmp( $this->h( 'octet', (string)$a, 16 ), $this->h( 'octet', (string)$b, 16 ) ); } );
            $this->octetPerm = array_combine( $pub, $sorted );
        }
        return $this->octetPerm[$o] ?? $o;
    }

    // ------------------------------------------------------------------ XML

    /** anonymise a configuration DOM in place */
    public function anonymizeXml( DOMDocument $doc )
    {
        $this->collectNamesXml( $doc );
        $this->certificates( $doc );
        $this->walk( $doc->documentElement );
        self::cleanup( $doc );
    }

    private function secret( $tag, $value )
    {
        $this->count( 'secrets' );
        $t = trim( $value );
        if( preg_match( '/^\$\d\$/', $t ) || $tag === 'phash' )
            return crypt( self::PLACEHOLDER_SECRET, '$5$anonymz$' );
        if( class_exists('ConfigSecrets') && preg_match( ConfigSecrets::PATTERN, $t ) || strpos( $t, '-AQ==' ) === 0 || strpos( $t, ConfigSecrets::GCM_PREFIX ) === 0 )
        {
            $crypto = new PanosCrypto();
            return $crypto->encrypt( self::PLACEHOLDER_SECRET, null );
        }
        return self::PLACEHOLDER_SECRET;
    }

    private function walk( DOMElement $e )
    {
        if( $e->hasAttribute( 'anonymized-tmp' ) )
            return;
        foreach( iterator_to_array( $e->attributes ) as $a )
        {
            if( $a->name === 'name' )
            {
                $n = $this->names[$a->value] ?? null;
                if( $n !== null )
                    $e->setAttribute( 'name', $n );
            }
            elseif( $a->name === 'admin' )
                $e->setAttribute( 'admin', 'admin' );
            elseif( in_array( $a->name, array( 'serial', 'hostname', 'ip-address', 'tsg_id', 'tenant' ), TRUE ) )
            {
                $v = $this->value( $a->value, TRUE );
                $e->setAttribute( $a->name, $v === null ? $a->value : $v );
            }
        }

        $children = array();
        $hasElement = FALSE;
        foreach( $e->childNodes as $c )
        {
            if( $c->nodeType === XML_ELEMENT_NODE )
                $hasElement = TRUE;
            $children[] = $c;
        }

        if( !$hasElement )
        {
            $text = $e->textContent;
            if( $text === '' )
                return;
            $new = $this->elementText( $e->nodeName, $text );
            if( $new !== null && $new !== $text )
            {
                while( $e->firstChild )
                    $e->removeChild( $e->firstChild );
                if( $new !== '' )
                    $e->appendChild( $e->ownerDocument->createTextNode( $new ) );
            }
            return;
        }
        foreach( $children as $c )
            if( $c->nodeType === XML_ELEMENT_NODE )
                $this->walk( $c );
            elseif( $c->nodeType === XML_COMMENT_NODE )
                $e->removeChild( $c );
    }

    /** new text of a leaf element, null: unchanged */
    public function elementText( $tag, $text )
    {
        $tag = strtolower( $tag );
        $t = trim( $text );
        if( in_array( $tag, self::SECRET_TAGS, TRUE ) || preg_match( '/(password|passwd|secret|psk)$/', $tag ) )
            return $this->secret( $tag, $text );
        if( class_exists('ConfigSecrets') && preg_match( ConfigSecrets::PATTERN, $t ) )
            return $this->secret( $tag, $text );
        if( in_array( $tag, self::PAGE_TAGS, TRUE ) && strlen($t) > 40 )
        {
            $this->count( 'pages' );
            return preg_match( '/^[A-Za-z0-9+\/=\s]+$/', $t ) ? self::IMAGE_1X1 : '<html><body>' . self::FREE_TEXT . '</body></html>';
        }
        if( in_array( $tag, self::FREE_TEXT_TAGS, TRUE ) )
        {
            if( $this->isKept($t) || isset($this->names[$t]) )
                return $this->names[$t] ?? null;
            $this->remember( $t );
            $this->count( 'free-text' );
            return self::FREE_TEXT;
        }
        if( in_array( $tag, self::MAYBE_TEXT_TAGS, TRUE ) && !isset($this->names[$t]) && !$this->isKept($t)
            && ( preg_match( '/\s|[A-Z]/', $t ) ) )
        {
            $this->remember( $t );
            $this->count( 'free-text' );
            return self::FREE_TEXT;
        }
        if( in_array( $tag, self::PATTERN_TAGS, TRUE ) && !isset($this->names[$t]) && !$this->isKept($t) )
        {
            $this->remember( $t );
            $this->count( 'patterns' );
            return 'pattern' . $this->h( 'pattern', $t, 8 );
        }
        if( $tag === 'timezone' )
            return 'UTC';
        if( $tag === 'display-name' )
            return $this->names[$t] ?? ( $this->isKept($t) ? null : $this->pseudo( 'name-', 'display', $t ) );
        if( in_array( $tag, self::HOST_TAGS, TRUE ) )
        {
            if( $this->isKept($t) )
                return null;
            $v = $this->value( $t, TRUE );
            if( $v !== null )
                return $v;
            $this->remember( $t );
            return $this->pseudo( 'host-', 'host', strtolower($t) );
        }
        if( $tag === 'domain' || $tag === 'search-domain' || $tag === 'dns-suffix' || $tag === 'realm' )
        {
            if( $this->isKept($t) )
                return null;
            return strpos( $t, '.' ) !== FALSE ? $this->fqdn( $t ) : $this->label( $t );
        }
        return $this->value( $text );
    }

    /** certificates: new self-signed certificate (subject CN = pseudonym of the entry), encrypted key placeholder */
    private function certificates( DOMDocument $doc )
    {
        $x = new DOMXPath( $doc );
        $crypto = new PanosCrypto();
        foreach( $x->query('//certificate/entry[public-key or private-key or common-name]') as $e )
        {
            $name = $e->getAttribute('name');
            $cn = $this->names[$name] ?? $this->pseudo( 'cert-', 'name', $name );
            $isCa = FALSE;
            $ca = DH::findFirstElement( 'ca', $e );
            if( $ca !== FALSE && trim($ca->textContent) === 'yes' )
                $isCa = TRUE;
            $pem = null;
            $keyPem = null;
            $hash = null;
            if( function_exists('openssl_pkey_new') )
            {
                $key = @openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048 ) );
                if( $key !== FALSE )
                {
                    $csr = @openssl_csr_new( array( 'commonName' => $cn ), $key, array( 'digest_alg' => 'sha256' ) );
                    $crt = $csr ? @openssl_csr_sign( $csr, null, $key, 3650, array( 'digest_alg' => 'sha256' ), random_int( 1, PHP_INT_MAX ) ) : FALSE;
                    if( $crt && @openssl_x509_export( $crt, $pem ) && @openssl_pkey_export( $key, $keyPem ) )
                    {
                        $parsed = openssl_x509_parse( $pem );
                        $hash = $parsed['hash'] ?? null;
                    }
                }
            }
            $this->count( 'certificates' );
            foreach( iterator_to_array( $e->childNodes ) as $c )
            {
                if( $c->nodeType !== XML_ELEMENT_NODE )
                    continue;
                $tag = $c->nodeName;
                $set = null;
                if( $tag === 'public-key' )
                    $set = $pem !== null ? $pem : '';
                elseif( $tag === 'private-key' )
                    $set = $crypto->encrypt( $keyPem !== null ? $keyPem : self::PLACEHOLDER_SECRET, null );
                elseif( $tag === 'common-name' )
                    $set = $cn;
                elseif( $tag === 'subject' || $tag === 'issuer' )
                    $set = '/CN=' . $cn;
                elseif( ( $tag === 'subject-hash' || $tag === 'issuer-hash' ) && $hash !== null )
                    $set = $hash;
                if( $set === null )
                    continue;
                $old = trim( $c->textContent );
                if( $tag === 'common-name' || $tag === 'subject' || $tag === 'issuer' )
                {
                    $this->remember( $old );
                    if( preg_match_all( '/CN=([^\/,]+)/', $old, $mm ) )
                        foreach( $mm[1] as $v )
                            $this->remember( $v );
                }
                while( $c->firstChild )
                    $c->removeChild( $c->firstChild );
                if( $set !== '' )
                    $c->appendChild( $doc->createTextNode( $set ) );
                // the walk must not touch these again
                $c->setAttribute( 'anonymized-tmp', '1' );
            }
        }
    }

    /** remove the temporary markers of certificates() */
    public static function cleanup( DOMDocument $doc )
    {
        $x = new DOMXPath( $doc );
        foreach( $x->query('//*[@anonymized-tmp]') as $e )
            $e->removeAttribute( 'anonymized-tmp' );
    }

    // ------------------------------------------------------------------ JSON (SCM export)

    const JSON_NAME_KEYS = array( 'name', 'folder', 'snippet', 'device', 'container' );
    const JSON_KEEP_KEYS = array( 'id', 'uuid', 'type', 'action', 'severity', 'version', 'protocol', 'port', 'category' );

    public function collectNamesJson( $data, $parentKey = 'obj' )
    {
        if( !is_array($data) )
            return;
        foreach( $data as $k => $v )
        {
            if( is_string($v) && in_array( $k, self::JSON_NAME_KEYS, TRUE ) && !$this->isKept($v) )
            {
                $kind = $k !== 'name' ? $k : explode( '|', is_string($parentKey) ? $parentKey : 'obj' )[0];
                $this->nameKinds[$v][$kind] = TRUE;
            }
            elseif( is_array($v) )
                $this->collectNamesJson( $v, is_string($k) ? $k : $parentKey );
        }
    }

    public function finishNames()
    {
        $all = array_keys( $this->nameKinds );
        sort( $all, SORT_STRING );
        foreach( $all as $n )
        {
            if( isset($this->names[$n]) )
                continue;
            $kinds = array_keys( $this->nameKinds[$n] );
            sort( $kinds, SORT_STRING );
            $this->name( $n, $kinds[0] );
        }
    }

    public function anonymizeJson( $data, $key = null )
    {
        if( is_array($data) )
        {
            $out = array();
            foreach( $data as $k => $v )
            {
                $nk = $k;
                if( is_string($k) )
                {
                    // keys such as "addresses|folder|<folder>|pre": every part mapped
                    $parts = explode( '|', $k );
                    foreach( $parts as $i => $part )
                        if( isset($this->names[$part]) )
                            $parts[$i] = $this->names[$part];
                    $nk = implode( '|', $parts );
                }
                $out[$nk] = $this->anonymizeJson( $v, is_string($k) ? $k : $key );
            }
            return $out;
        }
        if( !is_string($data) )
            return $data;
        $k = strtolower( (string)$key );
        if( in_array( $k, self::JSON_KEEP_KEYS, TRUE ) && !isset($this->names[$data]) )
            return $data;
        $new = $this->elementText( str_replace( '_', '-', $k ), $data );
        return $new === null ? $data : $new;
    }

    // ------------------------------------------------------------------ checks

    /**
     * leak scan: every replaced original that still appears in $text as a whole value or as a token
     * @return string[] originals found
     */
    public function leakScan( $text )
    {
        $tokens = array();
        if( preg_match_all( '/>([^<]+)</', $text, $m ) )
            foreach( $m[1] as $v )
                $tokens[html_entity_decode( trim($v), ENT_QUOTES | ENT_XML1 )] = TRUE;
        if( preg_match_all( '/"([^"]*)"/', $text, $m ) )
            foreach( $m[1] as $v )
                $tokens[html_entity_decode( $v, ENT_QUOTES | ENT_XML1 )] = TRUE;
        $parts = array();
        foreach( array_keys($tokens) as $t )
        {
            $parts[strtolower($t)] = TRUE;
            foreach( preg_split( '#[\s/\\\\@,;=:|]+#', $t ) as $p )
                if( $p !== '' )
                    $parts[strtolower($p)] = TRUE;
        }
        $found = array();
        foreach( array_keys($this->originals) as $o )
        {
            $lo = strtolower( (string)$o );
            if( isset($parts[$lo]) && !$this->isKept($o) && !$this->isPseudonym($lo) )
                $found[] = $o;
        }
        return $found;
    }

    private function isPseudonym( $v )
    {
        foreach( array_keys($this->used) as $p )
            if( strtolower($p) === $v )
                return TRUE;
        return FALSE;
    }

    /** structure signature: count of element paths (tag names only) - must be the same before / after */
    public static function structure( DOMDocument $doc )
    {
        $sig = array();
        $stack = array( array( $doc->documentElement, '' ) );
        while( $stack )
        {
            list( $e, $path ) = array_pop( $stack );
            $p = $path . '/' . $e->nodeName;
            $sig[$p] = ( $sig[$p] ?? 0 ) + 1;
            foreach( $e->childNodes as $c )
                if( $c->nodeType === XML_ELEMENT_NODE )
                    $stack[] = array( $c, $p );
        }
        ksort( $sig );
        return $sig;
    }

    public function mapping()
    {
        return array( 'names' => $this->names, 'fqdn' => $this->map['fqdn'], 'ip' => $this->map['ip'],
            'users' => $this->map['user'], 'serials' => $this->map['serial'], 'mac' => $this->map['mac'] );
    }
}
