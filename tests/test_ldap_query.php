<?php
/**
 * pan-os-php type=ldap-query (utils/lib/LDAPQUERY__.php) against a small directory in memory: the ldap_* functions are
 * defined by tests/ldap_fake.php (auto_prepend_file) - only possible where the PHP extension ldap is NOT loaded; with
 * the extension the test is skipped (then: test with a real LDAP).
 *
 *   php tests/test_ldap_query.php
 */
$repo = dirname( __DIR__ );
if( extension_loaded( 'ldap' ) )
{
    print "the PHP extension ldap is loaded - the fake directory can not be used, skipped\n";
    exit( 0 );
}
$checks = 0;
$failed = array();
function eq( $actual, $expected, $msg )
{
    global $checks, $failed;
    $checks++;
    if( $actual === $expected )
        print "ok   " . $msg . "\n";
    else
    {
        print "FAIL " . $msg . "\n      expected " . json_encode( $expected ) . "\n      got      " . json_encode( $actual ) . "\n";
        $failed[] = $msg;
    }
}
$home = sys_get_temp_dir() . '/ldapq-' . getmypid();
@mkdir( $home, 0700, TRUE );
// the password of the bind user: key store entry ldap_user<user> (read in lower case); the old ldap-password is not used
file_put_contents( $home . '/.panconfkeystore', "ldap-password:old-wrong\nldap_userAlice@Example.com:bind-geheim\nldap_userbob@example.com:other\n" );
$log = $home . '/ldap.log';

function q( array $args, &$out = null ): array
{
    global $repo, $home, $log;
    @unlink( $home . '/r.json' );
    $cmd = array( PHP_BINARY, '-d', 'auto_prepend_file=' . __DIR__ . '/ldap_fake.php', $repo . '/utils/pan-os-php.php', 'type=ldap-query',
        'ldapServer=ldaps://dc1.example.com:636', 'ldapUser=alice@example.com', 'dn=OU=Users;DC=example;DC=com', 'out=' . $home . '/r.json', 'csv=' . $home . '/r.csv' );
    // an argument of the test replaces the one given here
    $names = array_map( function( $a ) { return strtolower( strstr( $a, '=', TRUE ) ?: $a ); }, $args );
    $cmd = array_values( array_filter( $cmd, function( $a ) use ( $names ) { return strpos( $a, '=' ) === FALSE || !in_array( strtolower( strstr( $a, '=', TRUE ) ), $names, TRUE ); } ) );
    global $srv;
    $p = proc_open( array_merge( $cmd, $args ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, $home, array( 'HOME' => $home, 'PATH' => getenv( 'PATH' ), 'LDAP_FAKE_LOG' => $log, 'LDAP_FAKE_SRV' => json_encode( $srv ) ) );
    $out = stream_get_contents( $pipes[1] ) . stream_get_contents( $pipes[2] );
    proc_close( $p );
    return json_decode( (string)@file_get_contents( $home . '/r.json' ), TRUE ) ?: array();
}

$r = q( array( 'mode=validation', 'users=bob,EXAMPLE\\carol,gone,x*)(cn=*' ), $o );
$rows = array_column( $r['rows'] ?? array(), null, 'user' );
$fl = file( $log, FILE_IGNORE_NEW_LINES ) ?: array();
eq( array( $r['mode'] ?? null, $r['base'] ?? null, count( $rows ), $rows['bob']['status'] ?? null, $rows['EXAMPLE\\carol']['status'] ?? null, $rows['EXAMPLE\\carol']['expired'] ?? null,
    $rows['gone']['found'] ?? null, $r['missing'] ?? null ),
    array( 'validation', 'OU=Users,DC=example,DC=com', 4, 'active', 'disabled', TRUE, FALSE, 2 ), 'validation: found / not found, active / disabled (userAccountControl), expired (accountExpires), DOMAIN\\user' );
eq( array( in_array( 'bind ldaps://dc1.example.com:636 alice@example.com bind-geheim reqcert=allow', $fl, TRUE ), in_array( 'search OU=Users,DC=example,DC=com (sAMAccountName=x\\2a\\29\\28cn=\\2a)', $fl, TRUE ) ),
    array( TRUE, TRUE ), 'validation: bind with the key store entry ldap_user<bind user> (not ldap-password), values escaped in the filter (ldap_escape)' );
eq( array( strpos( $o, 'bind-geheim' ), is_file( $home . '/r.csv' ) && strpos( (string)file_get_contents( $home . '/r.csv' ), 'bob' ) !== FALSE ), array( FALSE, TRUE ), 'validation: the password not in the output; CSV written' );
eq( $rows['bob']['pwdLastSet'] ?? null, date( 'c', 1700000000 ), 'validation: pwdLastSet converted (Windows file time)' );

$r = q( array( 'mode=user-groups', 'users=bob' ) );
$g = array_column( $r['rows'] ?? array(), 'direct', 'group' );
eq( $g, array( 'VPN' => TRUE, 'Staff' => TRUE, 'All' => FALSE ), 'user-groups: direct and nested groups' );

$r = q( array( 'mode=common-groups', 'users=bob,dave' ) );
eq( array_column( $r['rows'] ?? array(), 'members', 'group' ), array( 'Staff' => 3 ), 'common-groups: direct only' );
$r = q( array( 'mode=common-groups', 'users=bob,dave,nobody', 'transitive=yes' ) );
eq( array( array_column( $r['rows'] ?? array(), 'members', 'group' ), $r['notFound'] ?? null, $r['rows'][1]['how'] ?? null ),
    array( array( 'Staff' => 3, 'All' => 5 ), array( 'nobody' ), array( 'bob' => 'nested', 'dave' => 'nested' ) ), 'common-groups: with nested groups, fewest members first, users not found named' );

$r = q( array( 'mode=group-members', 'group=VPN' ) );
eq( array( $r['group'] ?? null, array_column( $r['rows'] ?? array(), 'sAMAccountName' ) ), array( 'VPN', array( 'carol', 'bob' ) ), 'group-members: soonest expiry first, never-expiring last' );

q( array( 'mode=group-members', 'group=Nope' ), $o );
eq( strpos( $o, "group 'Nope' not found" ) !== FALSE, TRUE, 'group-members: unknown group named' );
foreach( array( array( 'mode=drop' ), array( 'mode=validation' ), array( 'mode=group-members' ), array( 'mode=validation', 'users=a', 'ldapServer=dc1.example.com' ), array( 'mode=validation', 'users=a', 'ldapServer=ldaps://dc1.example.com/x' ) ) as $bad )
{
    $r = q( $bad, $o );
    eq( array( $r, strpos( $o, 'ERROR' ) !== FALSE ), array( array(), TRUE ), 'arguments checked: ' . implode( ' ', $bad ) );
}
// mode=discover: the domain controllers from DNS SRV, the base DN from the RootDSE of the first that answers (no login)
$srv = array( '_ldap._tcp.dc._msdcs.example.com' => array( array( 'target' => 'dc2.example.com', 'pri' => 0, 'weight' => 100, 'port' => 389 ),
    array( 'target' => 'dc1.example.com', 'pri' => 0, 'weight' => 50, 'port' => 389 ), array( 'target' => 'evil.other.org', 'pri' => 0, 'weight' => 200, 'port' => 389 ) ) );
@unlink( $log );
$r = q( array( 'mode=discover', 'domain=Example.com' ), $o );
$fl = file( $log, FILE_IGNORE_NEW_LINES ) ?: array();
eq( array( array_column( $r['servers'] ?? array(), 'uri' ), $r['source'] ?? null, $r['rootDse']['server'] ?? null, $r['suggestion'] ?? null ),
    array( array( 'ldaps://evil.other.org:636', 'ldaps://dc2.example.com:636', 'ldaps://dc1.example.com:636' ), '_ldap._tcp.dc._msdcs.example.com', 'ldaps://dc1.example.com:636',
        array( 'server' => 'ldaps://dc1.example.com:636', 'base_dn' => 'DC=example,DC=com', 'base_from' => 'rootdse', 'bind_user' => '@example.com' ) ),
    'discover: SRV of the domain controllers (priority / weight), RootDSE of the first that answers, base DN from it' );
eq( array_values( preg_grep( '/^(rootdse|bind)/', $fl ) ), array( 'rootdse ldaps://dc2.example.com:636', 'rootdse ldaps://dc1.example.com:636' ),
    'discover: no login, a server outside the domain is not asked' );
$srv = array( '_ldap._tcp.example.com' => array( array( 'target' => 'dc1.example.com.', 'pri' => 0, 'weight' => 0, 'port' => 3268 ) ) );
$r = q( array( 'mode=discover', 'domain=example.com', 'ldaps=no' ) );
eq( array( array_column( $r['servers'] ?? array(), 'uri' ), $r['source'] ?? null ), array( array( 'ldap://dc1.example.com:3268' ), '_ldap._tcp.example.com' ), 'discover: _ldap._tcp.<domain> as the second choice, ldaps=no: ldap:// with the SRV port' );
$srv = array();
$r = q( array( 'mode=discover', 'domain=corp.example.org' ) );
eq( array( array_column( $r['servers'] ?? array(), 'uri' ), array_key_exists( 'rootDse', $r ) ? $r['rootDse'] : 'x', $r['suggestion']['base_dn'] ?? null, $r['suggestion']['base_from'] ?? null ),
    array( array( 'ldaps://corp.example.org:636' ), null, 'DC=corp,DC=example,DC=org', 'domain' ), 'discover: no SRV - the domain name, base DN from the domain name when nobody answers' );
q( array( 'mode=discover', 'domain=no domain' ), $o );
eq( strpos( $o, 'domain: the DNS name' ) !== FALSE, TRUE, 'discover: the domain checked' );
file_put_contents( $home . '/.panconfkeystore', "ldap-password:bind-geheim\nldap_useralice@example.com:wrong\n" );
q( array( 'mode=validation', 'users=bob' ), $o );
eq( strpos( $o, 'LDAP bind failed' ) !== FALSE, TRUE, 'a wrong password: bind failed' );
q( array( 'mode=validation', 'users=bob', 'ldapUser=al:ice' ), $o );
eq( strpos( $o, "no spaces, ':'" ) !== FALSE, TRUE, 'a bind user with ":" can not be an entry name' );

array_map( 'unlink', glob( $home . '/{,.}[!.]*', GLOB_BRACE ) ?: array() );
@rmdir( $home );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
if( count( $failed ) )
{
    foreach( $failed as $m )
        print " - " . $m . "\n";
    exit( 1 );
}
exit( 0 );
