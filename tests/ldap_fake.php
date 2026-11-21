<?php
/**
 * tests only (tests/test_ldap_query.php, as auto_prepend_file): the ldap_* functions pan-os-php type=ldap-query uses,
 * against a small directory in memory. Every bind / search is written to LDAP_FAKE_LOG.
 */
if( extension_loaded( 'ldap' ) )
    return;
define( 'LDAP_OPT_PROTOCOL_VERSION', 17 );
define( 'LDAP_OPT_REFERRALS', 8 );
define( 'LDAP_OPT_NETWORK_TIMEOUT', 20485 );
define( 'LDAP_ESCAPE_FILTER', 1 );
define( 'LDAP_ESCAPE_DN', 2 );

function ldapFakeLog( string $line ) { if( getenv( 'LDAP_FAKE_LOG' ) ) file_put_contents( getenv( 'LDAP_FAKE_LOG' ), $line . "\n", FILE_APPEND ); }
function ldapFakeTime( int $unix ): string { return (string)( ( $unix + 11644473600 ) * 10000000 ); }
function ldapFakeDir(): array
{
    $b = 'OU=Users,DC=example,DC=com';
    $u = function( $sam, $cn, $uac, $exp, $memberof ) use ( $b ) {
        return array( 'dn' => 'CN=' . $cn . ',' . $b, 'objectclass' => array( 'top', 'person', 'user' ), 'objectcategory' => array( 'person' ), 'cn' => array( $cn ),
            'samaccountname' => array( $sam ), 'mail' => array( $sam . '@example.com' ), 'useraccountcontrol' => array( (string)$uac ), 'accountexpires' => array( $exp ),
            'pwdlastset' => array( ldapFakeTime( 1700000000 ) ), 'memberof' => array_map( function( $g ) use ( $b ) { return 'CN=' . $g . ',' . $b; }, $memberof ) );
    };
    $g = function( $cn, $memberof, $members ) use ( $b ) {
        return array( 'dn' => 'CN=' . $cn . ',' . $b, 'objectclass' => array( 'top', 'group' ), 'objectcategory' => array( 'group' ), 'cn' => array( $cn ), 'samaccountname' => array( $cn ),
            'memberof' => array_map( function( $x ) use ( $b ) { return 'CN=' . $x . ',' . $b; }, $memberof ), 'member' => array_map( function( $x ) use ( $b ) { return 'CN=' . $x . ',' . $b; }, $members ) );
    };
    return array(
        $u( 'bob', 'Bob', 512, '0', array( 'VPN', 'Staff' ) ),
        $u( 'carol', 'Carol', 514, ldapFakeTime( 1600000000 ), array( 'VPN' ) ),
        $u( 'dave', 'Dave', 512, ldapFakeTime( 4000000000 ), array( 'Staff' ) ),
        $g( 'VPN', array( 'All' ), array( 'Bob', 'Carol' ) ),
        $g( 'Staff', array( 'All' ), array( 'Bob', 'Dave', 'Eve' ) ),
        $g( 'All', array(), array( 'VPN', 'Staff', 'Bob', 'Carol', 'Dave' ) ),
    );
}
function ldapFakeUnescape( string $v ): string { return preg_replace_callback( '/\\\\([0-9a-fA-F]{2})/', function( $m ) { return chr( hexdec( $m[1] ) ); }, $v ); }
/** a filter: (&...), (|...), (attr=value) - parsed from $f at $i */
function ldapFakeMatch( array $e, string $f, int &$i ): bool
{
    if( $f[$i] !== '(' )
        throw new Exception( 'bad filter ' . $f );
    $i++;
    if( $f[$i] === '&' || $f[$i] === '|' )
    {
        $op = $f[$i++];
        $res = $op === '&';
        while( $f[$i] === '(' )
        {
            $m = ldapFakeMatch( $e, $f, $i );
            $res = $op === '&' ? ( $res && $m ) : ( $res || $m );
        }
        $i++;
        return $res;
    }
    $end = strpos( $f, ')', $i );
    list( $a, $v ) = explode( '=', substr( $f, $i, $end - $i ), 2 );
    $i = $end + 1;
    $v = strtolower( ldapFakeUnescape( $v ) );
    foreach( $e[strtolower( $a )] ?? array() as $x )
        if( strtolower( $x ) === $v )
            return TRUE;
    return FALSE;
}
function ldapFakeEntries( array $list, array $attrs ): array
{
    $out = array( 'count' => count( $list ) );
    foreach( $list as $n => $e )
    {
        $one = array( 'dn' => $e['dn'] );
        $c = 0;
        foreach( $e as $k => $v )
            if( $k !== 'dn' && ( count( $attrs ) === 0 || in_array( $k, array_map( 'strtolower', $attrs ), TRUE ) ) )
            {
                $one[$k] = array( 'count' => count( $v ) ) + $v;
                $one[$c++] = $k;
            }
        $one['count'] = $c;
        $out[$n] = $one;
    }
    return $out;
}
class LdapFakeConn { public $uri; public $error = 'Success'; }
function ldap_connect( $uri = null ) { return preg_match( '#^ldaps?://#', (string)$uri ) ? ( function( $u ) { $c = new LdapFakeConn(); $c->uri = $u; return $c; } )( $uri ) : FALSE; }
function ldap_set_option( $c, $o, $v ) { return TRUE; }
function ldap_bind( $c, $u = null, $p = null )
{
    ldapFakeLog( 'bind ' . $c->uri . ' ' . $u . ' ' . $p . ' reqcert=' . getenv( 'LDAPTLS_REQCERT' ) );
    // a real ldap_bind() warns when it fails (pan-os-php: myErrorHandler dies on warnings) - the same here
    if( strpos( $c->uri, 'tls.example.com' ) !== FALSE )
    {
        $c->error = "Can't contact LDAP server";
        trigger_error( "ldap_bind(): Unable to bind to server: Can't contact LDAP server", E_USER_WARNING );
        return FALSE;
    }
    if( $p === 'bind-geheim' )
        return TRUE;
    $c->error = 'Invalid credentials';
    trigger_error( "ldap_bind(): Unable to bind to server: Invalid credentials", E_USER_WARNING );
    return FALSE;
}
function ldap_error( $c ) { return $c->error; }
function ldap_unbind( $c ) { return TRUE; }
function ldap_close( $c ) { return TRUE; }
function ldap_escape( $v, $ignore = '', $flags = 0 )
{
    return preg_replace_callback( '/[\\\\*()\x00]/', function( $m ) { return '\\' . bin2hex( $m[0] ); }, $v );
}
function ldap_search( $c, $base, $filter, $attrs = array() )
{
    ldapFakeLog( 'search ' . $base . ' ' . $filter );
    $hits = array();
    foreach( ldapFakeDir() as $e )
    {
        $i = 0;
        if( stripos( $e['dn'], $base ) !== FALSE && ldapFakeMatch( $e, $filter, $i ) )
            $hits[] = $e;
    }
    return ldapFakeEntries( $hits, $attrs );
}
function ldap_read( $c, $dn, $filter, $attrs = array() )
{
    // RootDSE (anonymous): only dc1 answers
    if( $dn === '' )
    {
        ldapFakeLog( 'rootdse ' . $c->uri );
        if( strpos( $c->uri, 'dc1.example.com' ) === FALSE )
        {
            $c->error = "Can't contact LDAP server";
            return FALSE;
        }
        return ldapFakeEntries( array( array( 'dn' => '', 'defaultnamingcontext' => array( 'DC=example,DC=com' ), 'rootdomainnamingcontext' => array( 'DC=example,DC=com' ),
            'dnshostname' => array( 'dc1.example.com' ), 'namingcontexts' => array( 'DC=example,DC=com', 'CN=Configuration,DC=example,DC=com' ) ) ), array() );
    }
    foreach( ldapFakeDir() as $e )
        if( strcasecmp( $e['dn'], $dn ) === 0 )
            return ldapFakeEntries( array( $e ), $attrs );
    return FALSE;
}
function ldap_get_entries( $c, $r ) { return $r; }

/** DNS SRV for type=ldap-query mode=discover (LDAP_FAKE_SRV: JSON name => records) */
function panosphp_test_dns_srv( $name )
{
    $all = json_decode( (string)getenv( 'LDAP_FAKE_SRV' ), TRUE ) ?: array();
    ldapFakeLog( 'srv ' . $name );
    return $all[$name] ?? array();
}

/** name / port of an LDAP server (LDAPQUERY__::reach): nohost.* is not in DNS, closed.* has the port closed */
function panosphp_test_reach( $host, $port )
{
    ldapFakeLog( 'reach ' . $host . ':' . $port );
    if( strpos( $host, 'nohost.' ) === 0 )
        return array( 'ips' => array(), 'tcp' => null );
    if( strpos( $host, 'closed.' ) === 0 )
        return array( 'ips' => array( '10.9.9.9' ), 'tcp' => 'Connection refused (111)' );
    return array( 'ips' => array( '10.1.1.1' ), 'tcp' => TRUE );
}
