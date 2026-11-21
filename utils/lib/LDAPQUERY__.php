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
 * pan-os-php type=ldap-query - the LDAP / Active Directory tools of utils/develop/ldap without questions (all values
 * as arguments, the password of the bind user from the key store entry ldap_user<bind user>), e.g. for the config viewer:
 *
 *   mode=validation     users=a,b,c   do the accounts still exist? status, password last set, expiry  (ldap_validation.php)
 *   mode=user-groups    users=a       groups of a user, direct and nested                                 (ldap_groups.php)
 *   mode=common-groups  users=a,b,c   groups ALL users are in, fewest members first [transitive=yes]     (ldap_groups_per_users_sort.php)
 *   mode=group-members  group=NAME    members of a group with status and expiry, soonest expiry first     (ldap_user_per_group_table.php)
 *
 *   ldapServer=ldaps://dc1.example.com:636  ldapUser=<bind user, UPN or DN>  dn=<base DN, ',' or ';'>
 *   [filtercriteria=sAMAccountName]  [out=<result.json>]  [csv=<result.csv>]
 *
 * The server is given explicitly (no DNS SRV discovery: the config viewer checks it against its allow list). Values
 * in LDAP filters are escaped (ldap_escape).
 */
class LDAPQUERY__
{
    const MODES = array( 'validation', 'user-groups', 'common-groups', 'group-members' );

    /** @var resource|LDAP\Connection */
    private $conn;
    private $base;
    private $attr;
    public $result = array();

    function __construct()
    {
        // the names of the arguments in lower case (PH::processCliArgs: ldapServer = ldapserver)
        $args = array_change_key_case( PH::$args, CASE_LOWER );
        if( isset($args['help']) )
        {
            PH::print_stdout( "pan-os-php type=ldap-query mode=" . implode('|', self::MODES) . " ldapServer=<uri> ldapUser=<bind user> dn=<base DN>"
                . " [filtercriteria=sAMAccountName] [users=a,b,c] [group=NAME] [transitive=yes] [out=<file.json>] [csv=<file.csv>]" );
            PH::print_stdout( "  the password: key store entry ldap_user<bind user> (.panconfkeystore), e.g. ldap_useralice@example.com:<password>" );
            return;
        }
        if( !function_exists('ldap_connect') )
            derr( "the PHP extension ldap is missing", null, FALSE );
        $mode = isset($args['mode']) ? (string)$args['mode'] : '';
        if( !in_array($mode, self::MODES, TRUE) )
            derr( "mode: one of " . implode(', ', self::MODES), null, FALSE );
        foreach( array( 'ldapserver', 'ldapuser', 'dn' ) as $need )
            if( !isset($args[$need]) || !is_string($args[$need]) || $args[$need] === '' )
                derr( "argument '" . $need . "' is missing", null, FALSE );
        if( !preg_match( '#^ldaps?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$#', $args['ldapserver'] ) )
            derr( "ldapServer: ldap://host[:port] or ldaps://host[:port]", null, FALSE );
        $this->base = str_replace( ';', ',', $args['dn'] );
        $this->attr = isset($args['filtercriteria']) && preg_match( '/^[A-Za-z][A-Za-z0-9-]{0,62}$/', $args['filtercriteria'] ) ? $args['filtercriteria'] : 'sAMAccountName';
        $users = isset($args['users']) ? array_values( array_filter( array_map( 'trim', explode( ',', (string)$args['users'] ) ), 'strlen' ) ) : array();
        $group = isset($args['group']) ? trim( (string)$args['group'] ) : '';
        $transitive = isset($args['transitive']) && in_array( strtolower( (string)$args['transitive'] ), array( 'yes', 'y', '1', 'true' ), TRUE );
        if( in_array($mode, array( 'validation', 'user-groups', 'common-groups' ), TRUE) && count($users) === 0 )
            derr( "users: the users to check (comma separated)", null, FALSE );
        if( $mode === 'group-members' && $group === '' )
            derr( "group: the name of the group (CN or sAMAccountName)", null, FALSE );

        // the password of the bind user: key store entry ldap_user<bind user> (asked for and stored when missing)
        $password = PanAPIConnector::ldapPassword( $args['ldapuser'] );

        // internal LDAPS with an own certificate authority (as the scripts of utils/develop/ldap)
        putenv('LDAPTLS_REQCERT=allow');
        PH::print_stdout( "Connecting to LDAP server: " . $args['ldapserver'] . " ..." );
        $this->conn = @ldap_connect( $args['ldapserver'] );
        if( !$this->conn )
            derr( "could not parse the LDAP server URI", null, FALSE );
        ldap_set_option( $this->conn, LDAP_OPT_PROTOCOL_VERSION, 3 );
        ldap_set_option( $this->conn, LDAP_OPT_REFERRALS, 0 );
        ldap_set_option( $this->conn, LDAP_OPT_NETWORK_TIMEOUT, 15 );
        if( !@ldap_bind( $this->conn, $args['ldapuser'], $password ) )
            derr( "LDAP bind failed as '" . $args['ldapuser'] . "': " . ldap_error( $this->conn ), null, FALSE );
        PH::print_stdout( "LDAP bind successful (" . $args['ldapuser'] . ")" );
        PH::print_stdout();

        if( $mode === 'validation' )
            $this->result = $this->validation( $users );
        elseif( $mode === 'user-groups' )
            $this->result = $this->userGroups( $users[0] );
        elseif( $mode === 'common-groups' )
            $this->result = $this->commonGroups( $users, $transitive );
        else
            $this->result = $this->groupMembers( $group );
        @ldap_unbind( $this->conn );

        $this->result = array( 'mode' => $mode, 'server' => $args['ldapserver'], 'base' => $this->base, 'time' => date('c') ) + $this->result;
        if( isset($args['out']) && is_string($args['out']) && $args['out'] !== '' )
            file_put_contents( $args['out'], json_encode( $this->result, JSON_PRETTY_PRINT | JSON_INVALID_UTF8_SUBSTITUTE ) );
        if( isset($args['csv']) && is_string($args['csv']) && $args['csv'] !== '' )
            $this->writeCsv( $args['csv'], $this->result['rows'] ?? array() );
    }

    private static function esc( string $v ): string
    {
        return ldap_escape( $v, '', LDAP_ESCAPE_FILTER );
    }

    public static function cnFromDn( string $dn ): string
    {
        return preg_match( '/^CN=([^,]+)/i', $dn, $m ) ? $m[1] : $dn;
    }

    public static function winTime( $filetime ): ?int
    {
        if( empty($filetime) || $filetime == "9223372036854775807" || $filetime == "0" )
            return null;
        return (int)( $filetime / 10000000 ) - 11644473600;
    }

    private static function fmtTime( ?int $t ): string
    {
        return $t === null ? "Never / Unlimited" : date( 'Y-m-d H:i:s T', $t );
    }

    /** status of an account: Active / Disabled (userAccountControl bit 2), Expired (accountExpires in the past) */
    private static function account( array $e ): array
    {
        $uac = isset($e['useraccountcontrol'][0]) ? (int)$e['useraccountcontrol'][0] : null;
        $expires = self::winTime( $e['accountexpires'][0] ?? '0' );
        $pwd = self::winTime( $e['pwdlastset'][0] ?? '0' );
        return array( 'cn' => $e['cn'][0] ?? '', 'mail' => $e['mail'][0] ?? '', 'sAMAccountName' => $e['samaccountname'][0] ?? '',
            'status' => $uac === null ? 'unknown' : ( ( $uac & 2 ) !== 0 ? 'disabled' : 'active' ),
            'expired' => $expires !== null && $expires < time(), 'accountExpires' => $expires !== null ? date( 'c', $expires ) : null,
            'pwdLastSet' => $pwd !== null ? date( 'c', $pwd ) : null );
    }

    private function search( string $filter, array $attrs )
    {
        $sr = @ldap_search( $this->conn, $this->base, $filter, $attrs );
        if( !$sr )
            return null;
        return ldap_get_entries( $this->conn, $sr );
    }

    /** do the accounts still exist? (a DOMAIN\user is searched by its user part) */
    private function validation( array $users ): array
    {
        $rows = array();
        $attrs = array( 'cn', 'mail', 'samaccountname', 'pwdlastset', 'accountexpires', 'useraccountcontrol', $this->attr );
        foreach( $users as $user )
        {
            $person = strpos( $user, "\\" ) !== FALSE ? substr( $user, strpos( $user, "\\" ) + 1 ) : $user;
            $info = $this->search( '(' . $this->attr . '=' . self::esc( $person ) . ')', $attrs );
            if( $info === null )
            {
                $rows[] = array( 'user' => $user, 'found' => null, 'error' => ldap_error( $this->conn ) );
                PH::print_stdout( "  ? " . $user . ": search failed - " . ldap_error( $this->conn ) );
                continue;
            }
            if( $info['count'] === 0 )
            {
                $rows[] = array( 'user' => $user, 'found' => FALSE );
                PH::print_stdout( "  - " . $user . ": NOT found" );
                continue;
            }
            $a = self::account( $info[0] );
            $rows[] = array( 'user' => $user, 'found' => TRUE ) + $a;
            PH::print_stdout( "  + " . $user . ": " . $a['status'] . ( $a['expired'] ? ', EXPIRED' : '' ) . " - " . $a['cn'] . " " . $a['mail']
                . " - password set " . ( $a['pwdLastSet'] ?? '-' ) . " - expires " . ( $a['accountExpires'] ?? 'never' ) );
        }
        $missing = count( array_filter( $rows, function( $r ) { return $r['found'] === FALSE; } ) );
        PH::print_stdout();
        PH::print_stdout( count($rows) . " user(s) checked, " . $missing . " not found" );
        return array( 'rows' => $rows, 'missing' => $missing );
    }

    /** the user and its groups: direct (memberOf), and all with the nested ones */
    private function userGroups( string $user ): array
    {
        $info = $this->search( '(' . $this->attr . '=' . self::esc( $user ) . ')', array( 'dn', 'cn', 'memberof' ) );
        if( $info === null )
            derr( "user search failed: " . ldap_error( $this->conn ), null, FALSE );
        if( $info['count'] === 0 )
            derr( "user '" . $user . "' not found under '" . $this->base . "'", null, FALSE );
        $direct = array();
        for( $i = 0; $i < ( $info[0]['memberof']['count'] ?? 0 ); $i++ )
            $direct[] = $info[0]['memberof'][$i];
        $all = $this->groupsRecursive( $direct );
        $rows = array();
        foreach( $all as $dn => $cn )
            $rows[] = array( 'group' => $cn, 'dn' => $dn, 'direct' => in_array( $dn, $direct, TRUE ) );
        PH::print_stdout( "User: " . ( $info[0]['cn'][0] ?? $user ) . " (" . $info[0]['dn'] . ")" );
        foreach( $rows as $r )
            PH::print_stdout( "  - " . $r['group'] . ( $r['direct'] ? " [direct]" : " [nested]" ) );
        PH::print_stdout( count($direct) . " direct group(s), " . count($rows) . " with the nested ones" );
        return array( 'user' => $user, 'userDn' => $info[0]['dn'], 'rows' => $rows );
    }

    /** groups and their parent groups (memberOf of each group), DN => CN */
    private function groupsRecursive( array $start ): array
    {
        $all = array();
        $queue = $start;
        while( count($queue) > 0 && count($all) < 5000 )
        {
            $dn = array_shift( $queue );
            if( isset($all[$dn]) )
                continue;
            $all[$dn] = self::cnFromDn( $dn );
            $r = @ldap_read( $this->conn, $dn, "(objectClass=*)", array( 'memberof' ) );
            if( $r )
            {
                $e = ldap_get_entries( $this->conn, $r );
                for( $i = 0; $i < ( $e[0]['memberof']['count'] ?? 0 ); $i++ )
                    if( !isset($all[$e[0]['memberof'][$i]]) )
                        $queue[] = $e[0]['memberof'][$i];
            }
        }
        return $all;
    }

    /** groups ALL users are in, fewest members first */
    private function commonGroups( array $users, bool $transitive ): array
    {
        $perUser = array();
        $directOf = array();
        $notFound = array();
        foreach( $users as $user )
        {
            $info = $this->search( '(' . $this->attr . '=' . self::esc( $user ) . ')', array( 'dn', 'cn', 'memberof' ) );
            if( $info === null || $info['count'] === 0 )
            {
                $notFound[] = $user;
                PH::print_stdout( "  - " . $user . ": not found - skipped" );
                continue;
            }
            $direct = array();
            for( $i = 0; $i < ( $info[0]['memberof']['count'] ?? 0 ); $i++ )
                $direct[] = $info[0]['memberof'][$i];
            $directOf[$user] = $direct;
            $perUser[$user] = $transitive ? array_keys( $this->groupsRecursive( $direct ) ) : $direct;
            PH::print_stdout( "  + " . $user . ": " . count($perUser[$user]) . " group(s)" );
        }
        if( count($perUser) === 0 )
            derr( "none of the users was found", null, FALSE );
        $common = null;
        foreach( $perUser as $g )
            $common = $common === null ? $g : array_values( array_intersect( $common, $g ) );
        $rows = array();
        foreach( array_unique( $common ) as $dn )
        {
            $count = 0;
            $r = @ldap_read( $this->conn, $dn, "(objectClass=*)", array( 'member' ) );
            if( $r )
            {
                $e = ldap_get_entries( $this->conn, $r );
                $count = (int)( $e[0]['member']['count'] ?? 0 );
            }
            $how = array();
            foreach( array_keys( $perUser ) as $u )
                $how[$u] = in_array( $dn, $directOf[$u], TRUE ) ? 'direct' : 'nested';
            $rows[] = array( 'group' => self::cnFromDn( $dn ), 'dn' => $dn, 'members' => $count, 'how' => $how );
        }
        usort( $rows, function( $a, $b ) { return $a['members'] <=> $b['members']; } );
        PH::print_stdout();
        PH::print_stdout( count($rows) . " common group(s) of " . implode( ', ', array_keys( $perUser ) ) . ( $transitive ? " (with nested groups)" : "" ) );
        foreach( $rows as $r )
            PH::print_stdout( "  - " . $r['group'] . " (" . $r['members'] . " members)" );
        return array( 'users' => array_keys( $perUser ), 'notFound' => $notFound, 'transitive' => $transitive, 'rows' => $rows );
    }

    /** members of a group with status and expiry, soonest expiry first */
    private function groupMembers( string $group ): array
    {
        $g = $this->search( '(&(objectClass=group)(|(cn=' . self::esc( $group ) . ')(sAMAccountName=' . self::esc( $group ) . ')))', array( 'dn', 'cn' ) );
        if( $g === null )
            derr( "group search failed: " . ldap_error( $this->conn ), null, FALSE );
        if( $g['count'] === 0 )
            derr( "group '" . $group . "' not found under '" . $this->base . "'", null, FALSE );
        $gdn = $g[0]['dn'];
        $info = $this->search( '(&(objectCategory=person)(objectClass=user)(memberOf=' . self::esc( $gdn ) . '))',
            array( 'samaccountname', 'cn', 'mail', 'pwdlastset', 'accountexpires', 'useraccountcontrol' ) );
        if( $info === null )
            derr( "member search failed: " . ldap_error( $this->conn ), null, FALSE );
        $rows = array();
        for( $i = 0; $i < $info['count']; $i++ )
            $rows[] = self::account( $info[$i] );
        usort( $rows, function( $a, $b ) {
            $x = $a['accountExpires'] === null ? PHP_INT_MAX : strtotime( $a['accountExpires'] );
            $y = $b['accountExpires'] === null ? PHP_INT_MAX : strtotime( $b['accountExpires'] );
            return $x <=> $y;
        } );
        PH::print_stdout( "Group: " . ( $g[0]['cn'][0] ?? $group ) . " (" . $gdn . ") - " . count($rows) . " member(s)" );
        foreach( $rows as $r )
            PH::print_stdout( "  - " . $r['sAMAccountName'] . " | " . $r['cn'] . " | " . $r['mail'] . " | " . $r['status'] . ( $r['expired'] ? ', EXPIRED' : '' )
                . " | password set " . ( $r['pwdLastSet'] ?? '-' ) . " | expires " . ( $r['accountExpires'] ?? 'never' ) );
        return array( 'group' => $g[0]['cn'][0] ?? $group, 'groupDn' => $gdn, 'rows' => $rows );
    }

    private function writeCsv( string $file, array $rows ): void
    {
        $f = fopen( $file, 'w' );
        if( !$f )
            return;
        $cols = array();
        foreach( $rows as $r )
            foreach( $r as $k => $v )
                $cols[$k] = TRUE;
        fputcsv( $f, array_keys( $cols ), ',', '"', '\\' );
        foreach( $rows as $r )
        {
            $line = array();
            foreach( array_keys( $cols ) as $k )
            {
                $v = $r[$k] ?? '';
                $line[] = is_array( $v ) ? json_encode( $v ) : ( is_bool( $v ) ? ( $v ? 'yes' : 'no' ) : (string)$v );
            }
            fputcsv( $f, $line, ',', '"', '\\' );
        }
        fclose( $f );
    }

    function endOfScript()
    {
    }
}
