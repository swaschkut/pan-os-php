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
 * the LDAP queries of a user (type=ldap-query, user-check-ldap).
 */
trait ViewerAppLdap
{
    // ------------------------------------------------------------------ LDAP queries of a user (type=ldap-query, user-check-ldap)

    private static function ldapQueryCheck( array $in ): array
    {
        $txt = function( $v, string $what, int $max, string $deny = '' ) {
            $v = is_string( $v ) ? trim( $v ) : '';
            if( $v === '' || strlen( $v ) > $max || preg_match( '/[\x00-\x1F\x7F' . $deny . ']/', $v ) )
                throw new ViewerException( $what . ': 1-' . $max . ' characters' . ( $deny !== '' ? ', no "' . stripslashes( $deny ) . '"' : '' ), 400 );
            return $v;
        };
        // the server: given (ldaps://host[:port]), or empty = automatic: the domain controllers of the domain from DNS,
        // the first one that works (pan-os-php ldapServer=auto) - then the allow list must cover the hosts of the domain
        $server = is_string( $in['server'] ?? null ) ? trim( $in['server'] ) : '';
        $domain = strtolower( trim( (string)( $in['domain'] ?? '' ) ) );
        if( $domain !== '' && ( strlen( $domain ) > 253 || !preg_match( '/^([a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/', $domain ) ) )
            throw new ViewerException( 'domain: the DNS name of the AD domain, e.g. example.local', 400 );
        $m = array( 2 => '' );
        if( $server === '' )
        {
            if( $domain === '' )
                throw new ViewerException( 'server or domain: a server (ldaps://host[:port]), or the domain - then the first domain controller of it from DNS that works', 400 );
        }
        elseif( !preg_match( '#^(ldaps?)://([A-Za-z0-9.-]{1,253})(:([0-9]{1,5}))?$#', $server, $m ) || ( isset( $m[4] ) && ( (int)$m[4] < 1 || (int)$m[4] > 65535 ) ) )
            throw new ViewerException( 'server: ldaps://host[:port] or ldap://host[:port] - or empty with the domain (automatic)', 400 );
        $mode = $in['mode'] ?? '';
        if( !is_string( $mode ) || !isset( self::LDAP_MODES[$mode] ) )
            throw new ViewerException( 'mode: ' . implode( ', ', array_keys( self::LDAP_MODES ) ), 400 );
        $attr = trim( (string)( $in['attribute'] ?? 'sAMAccountName' ) );
        if( !preg_match( '/^[A-Za-z][A-Za-z0-9-]{0,62}$/', $attr ) )
            throw new ViewerException( 'attribute: an LDAP attribute name (e.g. sAMAccountName)', 400 );
        $users = array();
        foreach( preg_split( '/[\r\n,]+/', (string)( $in['users'] ?? '' ) ) as $u )
            if( ( $u = trim( $u ) ) !== '' )
                $users[] = $txt( $u, 'users: a user', 200, ',' );
        if( count( $users ) > 500 )
            throw new ViewerException( 'users: at most 500', 400 );
        $group = trim( (string)( $in['group'] ?? '' ) );
        if( $mode === 'group-members' )
            $group = $txt( $group, 'group', 200, ',' );
        elseif( $mode !== 'validation' && count( $users ) === 0 )
            throw new ViewerException( 'users: at least one user', 400 );
        return array( 'name' => self::checkLabel( $in['name'] ?? null, 'name' ), 'server' => $server, 'host' => strtolower( $m[2] ), 'domain' => $domain,
            'ldaps' => !array_key_exists( 'ldaps', $in ) || ( $in['ldaps'] !== FALSE && $in['ldaps'] !== 0 && $in['ldaps'] !== '0' && $in['ldaps'] !== 'false' && $in['ldaps'] !== 'no' ) ? 1 : 0,
            // the bind user goes into the arguments of a pan-os-php action (comma separated): UPN or DOMAIN\user
            'bind_user' => $txt( $in['bind_user'] ?? null, 'bind_user (UPN or DOMAIN\\user)', 200, ',' ),
            'base_dn' => $txt( $in['base_dn'] ?? null, 'base_dn', 500 ), 'attribute' => $attr, 'mode' => $mode, 'users' => implode( ',', $users ),
            'grp' => $group, 'transitive' => !empty( $in['transitive'] ) && $in['transitive'] !== 'false' ? 1 : 0 );
    }

    private static function ldapQueryPublic( array $q ): array
    {
        return array( 'qid' => $q['qid'], 'name' => $q['name'], 'server' => $q['server'], 'domain' => (string)( $q['domain'] ?? '' ), 'ldaps' => (bool)( $q['ldaps'] ?? 1 ),
            'auto' => $q['server'] === '', 'bind_user' => $q['bind_user'], 'base_dn' => $q['base_dn'],
            'attribute' => $q['attribute'], 'mode' => $q['mode'], 'users' => $q['users'] === '' ? array() : explode( ',', $q['users'] ), 'group' => $q['grp'],
            'transitive' => (bool)$q['transitive'], 'created' => (int)$q['created'], 'updated' => (int)$q['updated'] );
    }

    /** the saved LDAP queries of the user (personal), and the LDAP accounts of the user (key store entries ldap_user<user>) */
    public function ldapQueries( array $user ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $rows = $this->q( 'SELECT * FROM ldap_queries WHERE user_id = ? ORDER BY name', array( $user['id'] ) )->fetchAll();
        $accounts = $this->q( "SELECT target FROM user_keys WHERE user_id = ? AND kind = 'ldap' ORDER BY target", array( $user['id'] ) )->fetchAll( PDO::FETCH_COLUMN );
        return array( 'queries' => array_map( array( self::class, 'ldapQueryPublic' ), $rows ), 'modes' => self::LDAP_MODES, 'accounts' => $accounts );
    }

    public function ldapQuerySave( array $user, ?string $qid, array $in ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $q = self::ldapQueryCheck( $in );
        if( $qid === null )
        {
            $qid = self::randomId( 8 );
            $this->q( 'INSERT INTO ldap_queries (qid, user_id, name, server, domain, ldaps, bind_user, base_dn, attribute, mode, users, grp, transitive, created, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                array( $qid, $user['id'], $q['name'], $q['server'], $q['domain'], $q['ldaps'], $q['bind_user'], $q['base_dn'], $q['attribute'], $q['mode'], $q['users'], $q['grp'], $q['transitive'], time(), time() ) );
        }
        elseif( $this->q( 'UPDATE ldap_queries SET name = ?, server = ?, domain = ?, ldaps = ?, bind_user = ?, base_dn = ?, attribute = ?, mode = ?, users = ?, grp = ?, transitive = ?, updated = ? WHERE qid = ? AND user_id = ?',
            array( $q['name'], $q['server'], $q['domain'], $q['ldaps'], $q['bind_user'], $q['base_dn'], $q['attribute'], $q['mode'], $q['users'], $q['grp'], $q['transitive'], time(), $qid, $user['id'] ) )->rowCount() === 0 )
            throw new ViewerException( 'not found', 404 );
        return self::ldapQueryPublic( $this->q( 'SELECT * FROM ldap_queries WHERE qid = ?', array( $qid ) )->fetch() );
    }

    /**
     * the result of an ldap-discover run of the project, with whether the network rules allow each server now
     * ('allowed' / 'refused') - the suggestion for a new query takes the first allowed one
     */
    public function ldapDiscoverResult( array $user, $pid, $jid ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $j = $this->jobRow( $p, $jid );
        if( $j['type'] !== 'ldap-discover' || $j['state'] !== 'done' )
            throw new ViewerException( 'not a finished search for LDAP servers', 400 );
        $r = json_decode( (string)@file_get_contents( $this->jobDir( $p, $j['jid'] ) . '/ldap.json' ), TRUE );
        if( !is_array( $r ) || !isset( $r['servers'] ) || !is_array( $r['servers'] ) )
            throw new ViewerException( 'the run has no result (see run.log)', 400 );
        $first = null;
        $servers = array();
        foreach( $r['servers'] as $s )
        {
            if( !is_array( $s ) || !is_string( $s['uri'] ?? null ) || !preg_match( '#^ldaps?://([a-z0-9.-]+)(:[0-9]{1,5})?$#', $s['uri'], $m ) )
                continue;
            $why = $this->networkRefusal( 'panos', $m[1], $user );
            $servers[] = array( 'uri' => $s['uri'], 'host' => $m[1], 'priority' => (int)( $s['priority'] ?? 0 ), 'weight' => (int)( $s['weight'] ?? 0 ),
                'answered' => ( $r['rootDse']['server'] ?? null ) === $s['uri'], 'refused' => $why );
            if( $why === null && $first === null )
                $first = $s['uri'];
        }
        // the server that answered first, if allowed; else the first allowed one
        $answered = $r['rootDse']['server'] ?? null;
        foreach( $servers as $s )
            if( $s['uri'] === $answered && $s['refused'] === null )
                $first = $answered;
        $mine = $this->q( "SELECT target FROM user_keys WHERE user_id = ? AND kind = 'ldap' ORDER BY target", array( $user['id'] ) )->fetchAll( PDO::FETCH_COLUMN );
        $domain = (string)( $r['domain'] ?? '' );
        $bind = null;
        foreach( $mine as $a )
            if( $domain !== '' && substr( $a, -strlen( '@' . $domain ) ) === '@' . $domain )
                $bind = $bind ?? $a;
        return array( 'domain' => $domain, 'servers' => $servers, 'rootDse' => is_array( $r['rootDse'] ?? null ) ? $r['rootDse'] : null,
            'suggestion' => array( 'name' => $domain, 'server' => $first, 'base_dn' => (string)( $r['suggestion']['base_dn'] ?? '' ),
                'base_from' => (string)( $r['suggestion']['base_from'] ?? '' ), 'bind_user' => $bind, 'bind_hint' => '<user>@' . $domain, 'attribute' => 'sAMAccountName' ) );
    }

    /**
     * network rules for an LDAP target: a host, or auto:<domain> (the domain controllers of the domain from DNS - the
     * allow list must cover the domain or its hosts, e.g. *.example.local; pan-os-php only asks hosts in the domain)
     */
    private function ldapRefusal( string $target, ?array $user = null ): ?string
    {
        if( strpos( $target, 'auto:' ) !== 0 )
            return $this->networkRefusal( 'panos', $target, $user );
        $domain = substr( $target, 5 );
        if( $this->networkRefusal( 'panos', $domain, $user ) === null )
            return null;
        $why = $this->networkRefusal( 'panos', 'dc.' . $domain, $user );
        return $why === null ? null : $why . ' - the administrator puts *.' . $domain . ' on the allow list';
    }

    public function ldapQueryDelete( array $user, $qid ): void
    {
        if( isset( $user['token'] ) || $this->q( 'DELETE FROM ldap_queries WHERE qid = ? AND user_id = ?', array( (string)$qid, $user['id'] ) )->rowCount() === 0 )
            throw new ViewerException( 'not found', 404 );
    }

    public function keyDelete( array $user, $kid ): void
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $r = $this->q( 'DELETE FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)$kid, $user['id'] ) );
        if( $r->rowCount() === 0 )
            throw new ViewerException( 'not found', 404 );
    }

    /** TRUE when the grant of the user on the project is limited to some types or to some locations */
    private static function limited( array $p ): bool
    {
        return $p['types'] !== null || $p['scope'] !== null;
    }

    /** whole-configuration operations (download, upload, delete a version) need a grant without type / scope limit */
    private static function needUnlimited( array $p, string $what ): void
    {
        if( self::limited( $p ) )
            throw new ViewerException( 'not allowed: ' . $what . ' needs access to the whole configuration (your access is limited to some types or locations)', 403 );
    }

    public function projectDelete( array $user, $pid ): void
    {
        $p = $this->projectGet( $user, $pid, 'owner' );
        $this->projectStopAll( $p );
        $this->q( 'DELETE FROM projects WHERE id = ?', array( $p['id'] ) );
        self::rmTree( $this->projectDir( $p['pid'] ) );
    }

    public function memberList( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $list = array( array( 'user' => $p['owner'], 'role' => 'owner' ) );
        foreach( $this->q( 'SELECT u.name AS user, m.role, m.types, m.scope FROM members m JOIN users u ON u.id = m.user_id WHERE m.project_id = ? ORDER BY u.name',
            array( $p['id'] ) )->fetchAll() as $m )
        {
            $m['types'] = $m['types'] !== null ? json_decode( $m['types'], TRUE ) : null;
            $m['scope'] = $m['scope'] !== null ? json_decode( $m['scope'], TRUE ) : null;
            $list[] = $m;
        }
        return $list;
    }

    /**
     * @param array|null $types offered types the member may use (null = all)
     * @param array|null $scope locations (device group, vsys, 'shared', template, SCM folder / snippet) the member may use (null = whole configuration)
     */
    public function memberSet( array $user, $pid, $memberName, $role, $types = null, $scope = null ): void
    {
        $p = $this->projectGet( $user, $pid, 'owner' );
        if( !in_array( $role, self::ROLES, TRUE ) )
            throw new ViewerException( 'role must be one of: ' . implode( ', ', self::ROLES ), 400 );
        $m = $this->userByName( $memberName );
        if( $m === null )
            throw new ViewerException( 'unknown user', 404 );
        if( (int)$m['id'] === (int)$p['owner_id'] )
            throw new ViewerException( 'the owner has all permissions already', 400 );
        if( $types !== null )
        {
            $offered = array_keys( $this->meta()['types'] );
            if( !is_array( $types ) || count( $types ) == 0 || count( array_diff( $types, $offered ) ) > 0 )
                throw new ViewerException( 'types: a list out of ' . implode( ', ', $offered ) . ' (or leave it out for all)', 400 );
            $types = json_encode( array_values( array_unique( $types ) ) );
        }
        if( $scope !== null )
        {
            if( !is_array( $scope ) || count( $scope ) == 0 || count( $scope ) > 200 )
                throw new ViewerException( 'scope: a list of locations (or leave it out for the whole configuration)', 400 );
            foreach( $scope as $loc )
                if( !is_string( $loc ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,63}$/', $loc ) || strtolower( $loc ) === 'any' )
                    throw new ViewerException( 'scope: location names with letters, digits, space and . _ - only, not "any"', 400 );
            $scope = json_encode( array_values( array_unique( $scope ) ) );
        }
        $this->q( 'INSERT INTO members (project_id, user_id, role, types, scope) VALUES (?,?,?,?,?)
            ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role, types = excluded.types, scope = excluded.scope',
            array( $p['id'], $m['id'], $role, $types, $scope ) );
    }

    public function memberRemove( array $user, $pid, $memberName ): void
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $m = $this->userByName( $memberName );
        // the owner removes anybody, a member can leave the project
        if( $m === null || ( $p['role'] !== 'owner' && (int)$m['id'] !== (int)$user['id'] ) )
            throw new ViewerException( $p['role'] !== 'owner' ? 'not allowed' : 'unknown user', $p['role'] !== 'owner' ? 403 : 404 );
        $this->q( 'DELETE FROM members WHERE project_id = ? AND user_id = ?', array( $p['id'], $m['id'] ) );
        $this->q( 'DELETE FROM tokens WHERE project_id = ? AND user_id = ?', array( $p['id'], $m['id'] ) );
    }
}
