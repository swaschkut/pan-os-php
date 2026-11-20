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
 * Prototype: configuration viewer / editor on top of pan-os-php with users, projects and project members.
 *
 * Security model (see README.md):
 *  - every request needs a logged in user (session cookie), every changing request the CSRF token of the session
 *  - a project is visible only to its owner and its members; no access is answered like "does not exist" (404)
 *  - roles per project: owner (members, delete project), write (upload, run actions, delete versions), read
 *  - files are stored under random names in the data directory, which must be outside the web root; no file name,
 *    path or shell string is ever built from request input
 *  - one worker process per opened version keeps the configuration loaded in memory (loaded once); reads and
 *    changes work on that memory; "save" writes the memory into a NEW version file, nothing is overwritten
 *  - the web server process starts no process: workers are started by the config-viewer service (bin/service.php),
 *    which accepts only paths inside the data directory; a worker only gets validated arguments (whitelist of types
 *    and actions, no file / API input)
 */
require_once dirname(__FILE__) . '/ViewerPlugins.php';

class ViewerException extends Exception
{
}

class ViewerApp
{
    const ROLES = array( 'read', 'write' );
    const TYPES = array( 'address', 'service', 'tag', 'rule', 'zone', 'schedule', 'securityprofile', 'securityprofilegroup' );
    const RULETYPES = array( 'any', 'security', 'nat', 'decryption', 'appoverride', 'captiveportal', 'authentication', 'pbf', 'qos', 'dos',
        'tunnelinspection', 'defaultsecurity', 'networkpacketbroker', 'sdwan' );
    const SPTYPES = array( 'any', 'url-filtering', 'virus', 'vulnerability', 'spyware', 'file-blocking', 'data-filtering', 'wildfire-analysis',
        'custom-url-category', 'dns-security', 'saas-security' );

    /** types a grant limited to locations (scope) can use: their objects live in a location (device group, vsys, shared, SCM folder) */
    const SCOPE_TYPES = array( 'address', 'service', 'tag', 'rule', 'schedule', 'securityprofile', 'securityprofilegroup', 'edl', 'log-profile' );
    /** REST resource name of a type, where "<type>s" does not fit */
    const RESOURCES = array( 'address' => 'addresses', 'securityprofile' => 'security-profiles', 'securityprofilegroup' => 'security-profile-groups',
        'routing' => 'routing', 'dhcp' => 'dhcp', 'virtualwire' => 'virtual-wires' );
    /**
     * resources with the SCM object model (ApiObjectModel, todo/json-object-model.md): SCM resource => pan-os-php type.
     * Their items are in the SCM shape (model 'scm-v1'); '?model=display-v0' gives the display fields of the type.
     */
    const SCM_RESOURCES = array( 'tags' => 'tag', 'addresses' => 'address', 'address-groups' => 'address', 'services' => 'service', 'service-groups' => 'service',
        'schedules' => 'schedule', 'url-categories' => 'securityprofile', 'external-dynamic-lists' => 'edl', 'log-forwarding-profiles' => 'log-profile',
        'anti-spyware-profiles' => 'securityprofile', 'vulnerability-protection-profiles' => 'securityprofile', 'url-access-profiles' => 'securityprofile',
        'file-blocking-profiles' => 'securityprofile', 'dns-security-profiles' => 'securityprofile', 'wildfire-anti-virus-profiles' => 'securityprofile',
        // own resources (Panorama / firewall keep antivirus and WildFire analysis apart)
        'antivirus-profiles' => 'securityprofile', 'wildfire-analysis-profiles' => 'securityprofile',
        'profile-groups' => 'securityprofilegroup', 'zones' => 'zone', 'zone-protection-profiles' => 'zone-protection-profile',
        // rules: one resource per rule type (SCM names; the last six are own resources)
        'security-rules' => 'rule', 'nat-rules' => 'rule', 'decryption-rules' => 'rule', 'app-override-rules' => 'rule', 'authentication-rules' => 'rule',
        'pbf-rules' => 'rule', 'qos-policy-rules' => 'rule', 'dos-rules' => 'rule', 'tunnel-inspection-rules' => 'rule', 'captive-portal-rules' => 'rule',
        'default-security-rules' => 'rule', 'sdwan-rules' => 'rule', 'network-packet-broker-rules' => 'rule' );
    /** arguments a SCM resource fixes for its pan-os-php type */
    const SCM_RESOURCE_ARGS = array(
        // all profile kinds are read (also the predefined profiles), the resource picks its class
        'url-categories' => array( 'securityprofiletype' => 'any' ),
        'anti-spyware-profiles' => array( 'securityprofiletype' => 'any' ),
        'vulnerability-protection-profiles' => array( 'securityprofiletype' => 'any' ),
        'url-access-profiles' => array( 'securityprofiletype' => 'any' ),
        'file-blocking-profiles' => array( 'securityprofiletype' => 'any' ),
        'dns-security-profiles' => array( 'securityprofiletype' => 'any' ),
        'wildfire-anti-virus-profiles' => array( 'securityprofiletype' => 'any' ),
        'antivirus-profiles' => array( 'securityprofiletype' => 'any' ),
        'wildfire-analysis-profiles' => array( 'securityprofiletype' => 'any' ),
        'security-rules' => array( 'ruletype' => 'security' ), 'nat-rules' => array( 'ruletype' => 'nat' ), 'decryption-rules' => array( 'ruletype' => 'decryption' ),
        'app-override-rules' => array( 'ruletype' => 'appoverride' ), 'authentication-rules' => array( 'ruletype' => 'authentication' ),
        'pbf-rules' => array( 'ruletype' => 'pbf' ), 'qos-policy-rules' => array( 'ruletype' => 'qos' ), 'dos-rules' => array( 'ruletype' => 'dos' ),
        'tunnel-inspection-rules' => array( 'ruletype' => 'tunnelinspection' ), 'captive-portal-rules' => array( 'ruletype' => 'captiveportal' ),
        'default-security-rules' => array( 'ruletype' => 'defaultsecurity' ), 'sdwan-rules' => array( 'ruletype' => 'sdwan' ),
        'network-packet-broker-rules' => array( 'ruletype' => 'networkpacketbroker' ),
    );
    const PAGE_DEFAULT = 1000;
    const PAGE_MAX = 5000;

    /** actions that read / write other files or reach other systems are not offered by the prototype */
    const ACTION_DENY_NAME = '/^export|^upload-|-fastapi$|reverse-dns|^decommission$|from-file|-edl-/';
    const ACTION_DENY_ARG = '/(?<!pro)file|path|folder/i';

    const LOGIN_MAX_FAILS = 5;
    const LOGIN_WINDOW = 900;
    const PASSWORD_MIN = 10;

    /** @var PDO */
    private $db;
    public $dataDir;
    public $repoDir;
    private $meta = null;
    /** @var ViewerPlugins */
    public $plugins;

    public function __construct( ?string $dataDir = null )
    {
        $this->repoDir = realpath( dirname(__FILE__) . '/../../../..' );
        if( $dataDir === null )
            $dataDir = getenv( 'PANOSPHP_VIEWER_DATA' ) ?: dirname( $this->repoDir ) . '/pan-os-php-viewer-data';
        if( !is_dir( $dataDir ) && !@mkdir( $dataDir, 0700, TRUE ) )
            throw new ViewerException( 'data directory can not be created (set PANOSPHP_VIEWER_DATA)', 500 );
        $this->dataDir = realpath( $dataDir );

        // the data directory holds configurations and the user DB - it must never be served by the web server
        $docRoot = isset( $_SERVER['DOCUMENT_ROOT'] ) && $_SERVER['DOCUMENT_ROOT'] !== '' ? realpath( $_SERVER['DOCUMENT_ROOT'] ) : FALSE;
        if( PHP_SAPI !== 'cli' && $docRoot !== FALSE && strpos( $this->dataDir . '/', rtrim( $docRoot, '/' ) . '/' ) === 0 )
            throw new ViewerException( 'data directory is inside the web root - set PANOSPHP_VIEWER_DATA to a folder outside of it', 500 );

        $this->plugins = ViewerPlugins::load( dirname( __FILE__, 2 ) );
        @mkdir( $this->dataDir . '/projects', 0700, TRUE );
        @mkdir( $this->dataDir . '/run', 0700, TRUE );
        if( strlen( $this->dataDir ) > 60 )
            throw new ViewerException( 'the path of the data directory is too long (60 characters at most)', 500 );
        $this->db = new PDO( 'sqlite:' . $this->dataDir . '/viewer.sqlite' );
        $this->db->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
        $this->db->setAttribute( PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC );
        $this->db->exec( 'PRAGMA foreign_keys = ON' );
        $this->db->exec( 'PRAGMA busy_timeout = 5000' );
        @chmod( $this->dataDir . '/viewer.sqlite', 0600 );
        $this->schema();
    }

    private function schema(): void
    {
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE COLLATE NOCASE, pass TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL)' );
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS projects (id INTEGER PRIMARY KEY, pid TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
            owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created INTEGER NOT NULL)' );
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS members (project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, role TEXT NOT NULL, PRIMARY KEY (project_id, user_id))' );
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS configs (id INTEGER PRIMARY KEY, cid TEXT NOT NULL UNIQUE,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, name TEXT NOT NULL, file TEXT NOT NULL, size INTEGER NOT NULL,
            parent_id INTEGER, note TEXT NOT NULL DEFAULT \'\', created_by INTEGER, created INTEGER NOT NULL)' );
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            config_id INTEGER NOT NULL, created INTEGER NOT NULL)' );
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS login_fail (name TEXT NOT NULL, ip TEXT NOT NULL, ts INTEGER NOT NULL)' );
        // API tokens: only the hash of the secret is stored; bound to one user and one project, role capped by 'role'
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS tokens (id INTEGER PRIMARY KEY, tid TEXT NOT NULL UNIQUE, hash TEXT NOT NULL,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
            role TEXT NOT NULL, label TEXT NOT NULL, expires INTEGER NOT NULL, created INTEGER NOT NULL, last_used INTEGER)' );
        // jobs: CLI-like runs (stats, ...) started by bin/jobs.php, never by the web server process
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS jobs (id INTEGER PRIMARY KEY, jid TEXT NOT NULL UNIQUE,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, config_id INTEGER NOT NULL, user_id INTEGER,
            type TEXT NOT NULL, args TEXT NOT NULL, state TEXT NOT NULL, created INTEGER NOT NULL, started INTEGER, finished INTEGER, error TEXT)' );
        // project files: playbook JSON and BP JSON, used by runs
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, fid TEXT NOT NULL UNIQUE,
            project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE, kind TEXT NOT NULL, name TEXT NOT NULL, file TEXT NOT NULL,
            size INTEGER NOT NULL, created_by INTEGER, created INTEGER NOT NULL)' );
        // audit log: who did what (logins, every request that is not a plain read, downloads)
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, user TEXT, token TEXT, ip TEXT,
            pid TEXT, method TEXT NOT NULL, route TEXT NOT NULL, status INTEGER NOT NULL, detail TEXT)' );
        $this->db->exec( 'CREATE INDEX IF NOT EXISTS audit_pid ON audit (pid, id)' );
        // grants of a member: types (JSON list, NULL = all offered types) and scope (JSON list of locations, NULL = whole configuration)
        $cols = array_column( $this->db->query( 'PRAGMA table_info(members)' )->fetchAll(), 'name' );
        if( !in_array( 'types', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE members ADD COLUMN types TEXT' );
        if( !in_array( 'scope', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE members ADD COLUMN scope TEXT' );
    }

    private function q( string $sql, array $args = array() ): PDOStatement
    {
        $st = $this->db->prepare( $sql );
        $st->execute( $args );
        return $st;
    }

    private static function randomId( int $bytes = 16 ): string
    {
        return bin2hex( random_bytes( $bytes ) );
    }

    // ------------------------------------------------------------------ users / login

    public static function checkUserName( $name ): string
    {
        if( !is_string( $name ) || !preg_match( '/^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$/', $name ) )
            throw new ViewerException( 'user name: 3-64 characters, letters, digits and . _ @ -', 400 );
        return $name;
    }

    public static function checkPassword( $password ): string
    {
        if( !is_string( $password ) || strlen( $password ) < self::PASSWORD_MIN || strlen( $password ) > 200 )
            throw new ViewerException( 'password: at least ' . self::PASSWORD_MIN . ' characters', 400 );
        return $password;
    }

    public function userCreate( $name, $password, bool $admin = FALSE ): array
    {
        $name = self::checkUserName( $name );
        $password = self::checkPassword( $password );
        if( $this->q( 'SELECT 1 FROM users WHERE name = ?', array( $name ) )->fetch() )
            throw new ViewerException( 'user exists already', 409 );
        $this->q( 'INSERT INTO users (name, pass, is_admin, created) VALUES (?,?,?,?)',
            array( $name, password_hash( $password, PASSWORD_DEFAULT ), $admin ? 1 : 0, time() ) );
        return array( 'name' => $name, 'admin' => $admin );
    }

    public function userSetPassword( int $userId, $password ): void
    {
        $this->q( 'UPDATE users SET pass = ? WHERE id = ?', array( password_hash( self::checkPassword( $password ), PASSWORD_DEFAULT ), $userId ) );
    }

    public function userByName( $name ): ?array
    {
        if( !is_string( $name ) || $name === '' )
            return null;
        $u = $this->q( 'SELECT * FROM users WHERE name = ?', array( $name ) )->fetch();
        return $u ?: null;
    }

    public function userById( int $id ): ?array
    {
        $u = $this->q( 'SELECT * FROM users WHERE id = ?', array( $id ) )->fetch();
        return $u ?: null;
    }

    public function userList(): array
    {
        return $this->q( 'SELECT name, is_admin AS admin, created FROM users ORDER BY name' )->fetchAll();
    }

    public function userDelete( string $name ): void
    {
        $u = $this->userByName( $name );
        if( $u === null )
            throw new ViewerException( 'not found', 404 );
        foreach( $this->q( 'SELECT id, pid FROM projects WHERE owner_id = ?', array( $u['id'] ) )->fetchAll() as $p )
        {
            $this->projectStopAll( $p );
            self::rmTree( $this->projectDir( $p['pid'] ) );
        }
        $this->q( 'DELETE FROM users WHERE id = ?', array( $u['id'] ) );
    }

    /** @return array user row; throws 401 on wrong credentials, 429 when too many failed logins */
    public function login( $name, $password, string $ip ): array
    {
        $name = is_string( $name ) ? substr( $name, 0, 64 ) : '';
        $this->q( 'DELETE FROM login_fail WHERE ts < ?', array( time() - self::LOGIN_WINDOW ) );
        $fails = (int)$this->q( 'SELECT COUNT(*) AS c FROM login_fail WHERE name = ? COLLATE NOCASE', array( $name ) )->fetch()['c'];
        if( $fails >= self::LOGIN_MAX_FAILS )
            throw new ViewerException( 'too many failed logins - try again later', 429 );

        $u = $this->userByName( $name );
        // same work and same answer for an unknown user and a wrong password
        $hash = $u !== null ? $u['pass'] : '$2y$10$usesomesillystringfore7hnbRJHxXVLeakoG8K30oukPsA.ztMG';
        $ok = is_string( $password ) && password_verify( $password, $hash ) && $u !== null;
        if( !$ok )
        {
            $this->q( 'INSERT INTO login_fail (name, ip, ts) VALUES (?,?,?)', array( $name, $ip, time() ) );
            throw new ViewerException( 'user name or password wrong', 401 );
        }
        $this->q( 'DELETE FROM login_fail WHERE name = ? COLLATE NOCASE', array( $name ) );
        if( password_needs_rehash( $u['pass'], PASSWORD_DEFAULT ) )
            $this->userSetPassword( (int)$u['id'], $password );
        return $u;
    }

    // ------------------------------------------------------------------ projects / members

    private static function checkLabel( $text, string $what, int $max = 80 ): string
    {
        if( !is_string( $text ) )
            throw new ViewerException( $what . ' missing', 400 );
        $text = trim( preg_replace( '/[\x00-\x1F\x7F]+/', ' ', $text ) );
        if( $text === '' || strlen( $text ) > $max )
            throw new ViewerException( $what . ': 1-' . $max . ' characters', 400 );
        return $text;
    }

    private function projectDir( string $pid ): string
    {
        if( !preg_match( '/^[0-9a-f]{32}$/', $pid ) )
            throw new ViewerException( 'not found', 404 );
        return $this->dataDir . '/projects/' . $pid;
    }

    public function projectCreate( array $user, $name ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        $name = self::checkLabel( $name, 'project name' );
        $pid = self::randomId();
        if( !mkdir( $this->projectDir( $pid ), 0700, TRUE ) )
            throw new ViewerException( 'project folder can not be created', 500 );
        $this->q( 'INSERT INTO projects (pid, name, owner_id, created) VALUES (?,?,?,?)', array( $pid, $name, $user['id'], time() ) );
        return $this->projectGet( $user, $pid );
    }

    public function projectList( array $user ): array
    {
        $rows = $this->q( 'SELECT p.pid, p.name, p.created, o.name AS owner,
                CASE WHEN p.owner_id = :u THEN \'owner\' ELSE m.role END AS role
            FROM projects p JOIN users o ON o.id = p.owner_id
            LEFT JOIN members m ON m.project_id = p.id AND m.user_id = :u
            WHERE p.owner_id = :u OR m.user_id = :u ORDER BY p.name', array( ':u' => $user['id'] ) )->fetchAll();
        if( isset( $user['token'] ) )
        {
            $out = array();
            foreach( $rows as $r )
            {
                try { $out[] = self::projectPublic( $this->projectGet( $user, $r['pid'] ) ); }
                catch( ViewerException $e ) { }
            }
            return $out;
        }
        return $rows;
    }

    /**
     * The one place that decides about access to a project. No access and unknown project give the same 404.
     * @param string $need 'read' | 'write' | 'owner'
     * @return array project row with 'role'
     */
    public function projectGet( array $user, $pid, string $need = 'read' ): array
    {
        $p = null;
        $types = null;
        $scope = null;
        if( is_string( $pid ) && preg_match( '/^[0-9a-f]{32}$/', $pid ) )
            $p = $this->q( 'SELECT p.*, o.name AS owner FROM projects p JOIN users o ON o.id = p.owner_id WHERE p.pid = ?', array( $pid ) )->fetch();
        $role = null;
        if( $p )
        {
            if( (int)$p['owner_id'] === (int)$user['id'] )
                $role = 'owner';
            else
            {
                $m = $this->q( 'SELECT role, types, scope FROM members WHERE project_id = ? AND user_id = ?', array( $p['id'], $user['id'] ) )->fetch();
                if( $m && in_array( $m['role'], self::ROLES, TRUE ) )
                {
                    $role = $m['role'];
                    $types = $m['types'] !== null ? json_decode( $m['types'], TRUE ) : null;
                    $scope = $m['scope'] !== null ? json_decode( $m['scope'], TRUE ) : null;
                }
            }
            // a request with an API token: only the project of the token, at most the role of the token,
            // never 'owner' (no member / token / project management with a token)
            if( $role !== null && isset( $user['token'] ) )
            {
                if( (int)$user['token']['project_id'] !== (int)$p['id'] )
                    $role = null;
                else
                    $role = ( $role === 'read' || $user['token']['role'] === 'read' ) ? 'read' : 'write';
            }
        }
        if( $role === null )
            throw new ViewerException( 'not found', 404 );

        $rank = array( 'read' => 1, 'write' => 2, 'owner' => 3 );
        if( !isset( $rank[$need] ) || $rank[$role] < $rank[$need] )
            throw new ViewerException( 'not allowed: this needs the project permission "' . $need . '" (yours: "' . $role . '")', 403 );
        $p['role'] = $role;
        $p['types'] = is_array( $types ) ? $types : null;
        $p['scope'] = is_array( $scope ) ? $scope : null;
        return $p;
    }

    public static function projectPublic( array $p ): array
    {
        return array( 'pid' => $p['pid'], 'name' => $p['name'], 'owner' => $p['owner'], 'role' => $p['role'], 'created' => (int)$p['created'],
            'types' => $p['types'] ?? null, 'scope' => $p['scope'] ?? null );
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

    // ------------------------------------------------------------------ jobs (CLI-like runs with result files)

    /**
     * Job types: the pan-os-php arguments are built here from checked values only - never an argument, file name or
     * path of the request. 'in=' is the version file, the working directory is the folder of the job.
     */
    const JOB_TYPES = array( 'stats', 'playbook' );
    const JOB_QUEUE_MAX = 20;          // queued + running jobs per project
    const JOB_FILE_MAX = 104857600;    // largest result file that can be downloaded

    private function jobDir( array $project, string $jid ): string
    {
        if( !preg_match( '/^[0-9a-f]{32}$/', $jid ) )
            throw new ViewerException( 'not found', 404 );
        return $this->projectDir( $project['pid'] ) . '/jobs/' . $jid;
    }

    /** POST …/configs/<cid>/<type>/runs - queues a run; bin/jobs.php executes it */
    /**
     * is a licensed feature switched on ? The one place for the licence check (todo/config-viewer-license.md).
     * Until licences are built every feature is on; null = basic.
     */
    public function featureOn( ?string $feature ): bool
    {
        return TRUE;
    }

    /** run types of the plug-ins that are switched on: name => description */
    public function pluginRuns(): array
    {
        return $this->plugins->runs( function( $p ) { return $this->featureOn( $p['feature'] ); } );
    }

    private function pluginKinds(): array
    {
        return $this->plugins->kinds( function( $p ) { return $this->featureOn( $p['feature'] ); } );
    }

    /** all run types: the ones of the viewer and of the plug-ins */
    public function jobTypes(): array
    {
        return array_merge( self::JOB_TYPES, array_keys( $this->pluginRuns() ) );
    }

    /** for the browser page / scripts: plug-ins with their run types, fields and file kinds (admins: also the refused ones) */
    public function pluginMeta( bool $admin ): array
    {
        $out = array( 'runs' => array(), 'kinds' => array(), 'rawKinds' => array(), 'plugins' => array() );
        foreach( $this->plugins->plugins as $p )
        {
            $on = $this->featureOn( $p['feature'] );
            $out['plugins'][] = array( 'name' => $p['name'], 'title' => $p['title'], 'version' => $p['version'], 'feature' => $p['feature'], 'on' => $on );
            if( !$on )
                continue;
            foreach( $p['runs'] as $name => $r )
                $out['runs'][$name] = array( 'title' => $r['title'], 'fields' => $r['fields'], 'bp' => $r['bp'], 'result' => $r['result'] !== null, 'input' => $r['input'] );
            foreach( $p['kinds'] as $name => $k )
            {
                $out['kinds'][$name] = $k['title'];
                if( $k['format'] === 'raw' )
                    $out['rawKinds'][] = $name;
            }
        }
        if( $admin )
            $out['errors'] = $this->plugins->errors;
        return $out;
    }

    public function jobCreate( array $user, $pid, $cid, $type, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        if( !is_string( $type ) || !in_array( $type, $this->jobTypes(), TRUE ) )
            throw new ViewerException( 'not found', 404 );
        $plugin = $this->pluginRuns()[$type] ?? null;
        // a run works on the whole configuration
        self::needUnlimited( $p, 'a ' . $type . ' run' );
        // a run type of a plug-in with 'input' => 'none' has no version (its input is a project file)
        $noVersion = $plugin !== null && $plugin['input'] === 'none';
        if( $noVersion !== ( $cid === null ) )
            throw new ViewerException( 'not found', 404 );
        $c = $noVersion ? array( 'id' => 0 ) : $this->configGet( $p, $cid );

        $args = array();
        if( $type === 'stats' )
        {
            $location = $in['location'] ?? 'any';
            if( !is_string( $location ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,63}$/', $location ) )
                throw new ViewerException( 'location: letters, digits, space and . _ - only', 400 );
            $args = array( 'location=' . $location, 'actions=display-bpa', 'json-to-folder', 'debugapi' );
        }
        if( $type === 'playbook' )
        {
            // the playbook file of the project, checked again now (PLAYBOOK_* rules); the stage files, the set commands
            // and the result configuration stay in the folder of the run
            $pb = $this->fileGet( $p, $in['playbook'] ?? null, 'playbook' );
            $this->playbookCheck( json_decode( (string)file_get_contents( $pb['path'] ), TRUE ) );
            $args = array( 'json=%FILES%/' . $pb['file'], 'out=%JOB%/out.xml', 'stagename=stage/step-', 'outputformatset=set-commands.txt' );
        }
        if( $plugin !== null )
        {
            // a run type of a plug-in: it builds the arguments from checked values (ViewerPluginRun); in= is always
            // the version, files only from this project, results only in the folder of the run
            foreach( $plugin['fields'] as $f )
                if( $f['required'] && ( !isset( $in[$f['name']] ) || $in[$f['name']] === '' || $in[$f['name']] === array() ) )
                    throw new ViewerException( $f['name'] . ' is needed', 400 );
            $run = new ViewerPluginRun( $in, function( $fid, $kind ) use ( $p ) { return $this->fileGet( $p, $fid, $kind ); }, $plugin['fields'] );
            $args = ( $plugin['args'] )( $run );
            if( !is_array( $args ) )
                throw new ViewerException( 'plug-in: no arguments', 500 );
            foreach( $args as $a )
                if( !is_string( $a ) || strlen( $a ) > 4000 || preg_match( '/[\x00-\x1f]/', $a ) || preg_match( '/^(in|type|projectfolder)=/i', $a )
                    || ( preg_match( '/^out=/i', $a ) && strpos( $a, 'out=%JOB%/' ) !== 0 ) )
                    throw new ViewerException( 'plug-in: an argument is not allowed', 500 );
            $args = array_values( $args );
            if( !$plugin['bp'] )
                unset( $in['bp'] );
        }
        // the BP JSON of the project instead of the one shipped with pan-os-php
        if( isset( $in['bp'] ) )
            $args[] = 'shadow-bpjsonfile=%FILES%/' . $this->fileGet( $p, $in['bp'], 'bp' )['file'];
        $open = (int)$this->q( "SELECT COUNT(*) AS c FROM jobs WHERE project_id = ? AND state IN ('queued','running')", array( $p['id'] ) )->fetch()['c'];
        if( $open >= self::JOB_QUEUE_MAX )
            throw new ViewerException( 'too many open runs in this project - wait for them or cancel one', 429 );
        $jid = self::randomId();
        $this->q( 'INSERT INTO jobs (jid, project_id, config_id, user_id, type, args, state, created) VALUES (?,?,?,?,?,?,?,?)',
            array( $jid, $p['id'], $c['id'], $user['id'], $type, json_encode( $args ), 'queued', time() ) );
        return $this->jobGet( $user, $pid, $jid );
    }

    private function jobRow( array $project, $jid ): array
    {
        $j = is_string( $jid ) && preg_match( '/^[0-9a-f]{32}$/', $jid )
            ? $this->q( 'SELECT j.*, u.name AS user, c.cid FROM jobs j LEFT JOIN users u ON u.id = j.user_id LEFT JOIN configs c ON c.id = j.config_id
                WHERE j.jid = ? AND j.project_id = ?', array( $jid, $project['id'] ) )->fetch() : FALSE;
        if( !$j )
            throw new ViewerException( 'not found', 404 );
        return $j;
    }

    private static function jobPublic( array $j ): array
    {
        return array( 'jid' => $j['jid'], 'type' => $j['type'], 'cid' => $j['cid'], 'args' => json_decode( $j['args'], TRUE ), 'state' => $j['state'], 'user' => $j['user'],
            'created' => (int)$j['created'], 'started' => $j['started'] !== null ? (int)$j['started'] : null,
            'finished' => $j['finished'] !== null ? (int)$j['finished'] : null, 'error' => $j['error'] );
    }

    /** result files of a job: names relative to the folder of the job */
    private function jobFiles( array $project, string $jid ): array
    {
        $dir = $this->jobDir( $project, $jid );
        $files = array();
        if( is_dir( $dir ) )
        {
            $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
            foreach( $it as $f )
                if( $f->isFile() && !$f->isLink() )
                    $files[] = array( 'name' => substr( $f->getPathname(), strlen( $dir ) + 1 ), 'size' => $f->getSize() );
            usort( $files, function( $a, $b ) { return strcmp( $a['name'], $b['name'] ); } );
        }
        return $files;
    }

    public function jobList( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the list of runs' );
        $rows = $this->q( 'SELECT j.*, u.name AS user, c.cid FROM jobs j LEFT JOIN users u ON u.id = j.user_id LEFT JOIN configs c ON c.id = j.config_id
            WHERE j.project_id = ? ORDER BY j.id DESC LIMIT 200', array( $p['id'] ) )->fetchAll();
        return array_map( array( 'ViewerApp', 'jobPublic' ), $rows );
    }

    public function jobGet( array $user, $pid, $jid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'a run' );
        $j = $this->jobRow( $p, $jid );
        return self::jobPublic( $j ) + array( 'files' => in_array( $j['state'], array( 'done', 'failed' ), TRUE ) ? $this->jobFiles( $p, $j['jid'] ) : array() );
    }

    /** @return array 'name', 'content' of one result file; server paths are replaced in the content */
    public function jobFile( array $user, $pid, $jid, string $name ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'a run' );
        $j = $this->jobRow( $p, $jid );
        if( !in_array( $j['state'], array( 'done', 'failed' ), TRUE ) )
            throw new ViewerException( 'the run is not finished', 409 );
        foreach( $this->jobFiles( $p, $j['jid'] ) as $f )
            if( $f['name'] === $name )
            {
                if( $f['size'] > self::JOB_FILE_MAX )
                    throw new ViewerException( 'file too large', 413 );
                // the name comes from the list of the folder, never from the request
                return array( 'name' => basename( $f['name'] ), 'content' => $this->hidePaths( (string)file_get_contents( $this->jobDir( $p, $j['jid'] ) . '/' . $f['name'] ) ) );
            }
        throw new ViewerException( 'not found', 404 );
    }

    /** cancel an open run (the runner stops it) or delete a finished one with its files; who started it, or write */
    public function jobDelete( array $user, $pid, $jid ): void
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'a run' );
        $j = $this->jobRow( $p, $jid );
        if( $p['role'] === 'read' && (int)$j['user_id'] !== (int)$user['id'] )
            throw new ViewerException( 'not allowed: only who started the run, or the project permission "write"', 403 );
        if( in_array( $j['state'], array( 'queued', 'running' ), TRUE ) )
        {
            $this->q( "UPDATE jobs SET state = 'cancelled', finished = ? WHERE id = ? AND state IN ('queued','running')", array( time(), $j['id'] ) );
            return;
        }
        $this->q( 'DELETE FROM jobs WHERE id = ?', array( $j['id'] ) );
        self::rmTree( $this->jobDir( $p, $j['jid'] ) );
    }

    /** the result configuration of a finished playbook run (out.xml) becomes a new version of the project */
    public function jobSaveConfig( array $user, $pid, $jid, $targetPid = null ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'a new version' );
        $j = $this->jobRow( $p, $jid );
        // into another project (e.g. the result of a migration into the project where it is optimised): write there too
        $target = $p;
        if( $targetPid !== null && $targetPid !== $p['pid'] )
        {
            $target = $this->projectGet( $user, $targetPid, 'write' );
            self::needUnlimited( $target, 'a new version' );
        }
        // playbook runs write out.xml; a run type of a plug-in names its result configuration
        $result = $j['type'] === 'playbook' ? 'out.xml' : ( $this->pluginRuns()[$j['type']]['result'] ?? null );
        $out = $this->jobDir( $p, $j['jid'] ) . '/' . ( $result ?? 'out.xml' );
        if( $j['state'] !== 'done' || $result === null || !is_file( $out ) || is_link( $out ) || !self::isPanosConfig( $out ) )
            throw new ViewerException( 'this run has no result configuration', 409 );
        $other = $target['id'] !== $p['id'];
        $parent = $other ? FALSE : $this->q( 'SELECT id, name FROM configs WHERE id = ? AND project_id = ?', array( $j['config_id'], $p['id'] ) )->fetch();
        $file = self::randomId() . '.xml';
        if( !copy( $out, $this->projectDir( $target['pid'] ) . '/' . $file ) )
            throw new ViewerException( 'file can not be stored', 500 );
        @chmod( $this->projectDir( $target['pid'] ) . '/' . $file, 0600 );
        // the note says where a version comes from: the run, and the project when it is another one
        $note = $j['type'] . ' run ' . substr( $j['jid'], 0, 8 ) . ( $other ? ' of project "' . $p['name'] . '"' : '' );
        return $this->configInsert( $target, $user, $parent ? $parent['name'] : $j['type'] . ' result', $file, $parent ? (int)$parent['id'] : null, $note )
            + array( 'pid' => $target['pid'] );
    }

    // ------------------------------------------------------------------ project files (playbook JSON, BP JSON)

    const FILE_KINDS = array( 'playbook', 'bp' );
    const FILE_MAX = 2097152;

    /** types a playbook step may run: they work on the configuration file only (no device, no other system) */
    const PLAYBOOK_TYPES = array( 'xml-issue', 'address', 'service', 'tag', 'schedule', 'rule', 'zone', 'zone-protection-profile', 'securityprofile',
        'securityprofilegroup', 'log-profile', 'device', 'edl', 'application', 'threat-rule', 'dns-rule', 'interface', 'routing', 'static-route', 'stats', 'html-merger' );
    /** arguments a playbook step may have (lower case name); everything else - in, out, json, projectfolder, shadow-bpjsonfile, … - is refused */
    const PLAYBOOK_ARGS = array( 'actions', 'filter', 'location', 'template', 'ruletype', 'securityprofiletype', 'devicetype', 'outputformatset', 'exportcsv',
        'adddefaulthtml', 'json-to-folder', 'debugapi', 'stats', 'shadow-ignoreinvalidaddressobjects' );
    /** keys of a step that are no arguments (PLAYBOOK__.php removes them) */
    const PLAYBOOK_NOARG_KEYS = '/^(comment|pie_slice|platform|html-merger-.*)$/';
    /** actions of a step that reach other systems or read files of the server */
    const PLAYBOOK_ACTION_DENY = '/^upload-|-fastapi$|reverse-dns|^decommission$|from-file|-edl-/';
    const PLAYBOOK_FILENAME = '/^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$/';

    /**
     * Checks a playbook before it is stored and before every run: every step, every argument. A playbook can only
     * work on the configuration of the run and write plain file names into the folder of the run.
     */
    public function playbookCheck( $j ): void
    {
        $bad = function( string $msg ) { throw new ViewerException( 'playbook: ' . $msg, 400 ); };
        if( !is_array( $j ) || !isset( $j['command'] ) || !is_array( $j['command'] ) || count( $j['command'] ) == 0 )
            $bad( 'JSON object with a list "command" expected' );
        foreach( array( 'in', 'out', 'projectfolder', 'json' ) as $k )
            if( array_key_exists( $k, $j ) )
                $bad( 'the key "' . $k . '" is not allowed (input, output and folders are set by the run)' );
        if( count( $j['command'] ) > 500 )
            $bad( 'too many steps' );
        foreach( array_values( $j['command'] ) as $n => $step )
        {
            $at = 'step ' . ( $n + 1 ) . ': ';
            if( !is_array( $step ) || !isset( $step['type'] ) || !is_string( $step['type'] ) )
                $bad( $at . '"type" missing' );
            if( !in_array( $step['type'], self::PLAYBOOK_TYPES, TRUE )
                && !in_array( $step['type'], $this->plugins->playbookTypes( function( $p ) { return $this->featureOn( $p['feature'] ); } ), TRUE ) )
                $bad( $at . 'type "' . substr( $step['type'], 0, 40 ) . '" is not available in a playbook here' );
            $values = array();
            foreach( $step as $key => $value )
            {
                if( $key === 'type' || preg_match( self::PLAYBOOK_NOARG_KEYS, (string)$key ) )
                {
                    if( !is_string( $value ) )
                        $bad( $at . '"' . $key . '" must be text' );
                    continue;
                }
                // "scm": false / { … } - other arguments on SCM input: checked like the step itself
                if( $key === 'scm' )
                {
                    if( is_array( $value ) )
                    {
                        foreach( $value as $k2 => $v2 )
                            if( !preg_match( self::PLAYBOOK_NOARG_KEYS, (string)$k2 ) )
                                $values[] = $v2;
                    }
                    elseif( !is_bool( $value ) )
                        $bad( $at . '"scm" must be false or an object' );
                    continue;
                }
                $values[] = $value;
            }
            foreach( $values as $value )
                $this->playbookCheckArg( $step['type'], $value, $at, $bad );
        }
    }

    private function playbookCheckArg( string $type, $value, string $at, callable $bad ): void
    {
        if( !is_string( $value ) || strlen( $value ) > 4000 || preg_match( '/[\x00-\x1F\x7F]/', $value ) )
            $bad( $at . 'every argument must be text without control characters' );
        $parts = explode( '=', $value, 2 );
        $name = strtolower( $parts[0] );
        $arg = $parts[1] ?? null;
        // subquery1=…: part of a filter, checked like a filter
        $subquery = (bool)preg_match( '/^subquery[0-9]{1,2}$/', $name );
        if( !$subquery && !in_array( $name, self::PLAYBOOK_ARGS, TRUE ) )
            $bad( $at . 'argument "' . substr( $parts[0], 0, 40 ) . '" is not allowed' );
        if( $arg === null )
            return;
        if( $name === 'outputformatset' || $name === 'exportcsv' )
        {
            if( !preg_match( self::PLAYBOOK_FILENAME, $arg ) )
                $bad( $at . $parts[0] . ': a plain file name (letters, digits, . _ -), it is written into the folder of the run' );
            return;
        }
        if( $name === 'filter' || $subquery )
        {
            if( preg_match( '/\.file\b/i', $arg ) )
                $bad( $at . 'filter operators that read a file are not available' );
            return;
        }
        if( $name === 'actions' )
        {
            foreach( explode( '/', str_replace( '//', "\x01", $arg ) ) as $one )
            {
                $one = str_replace( "\x01", '/', $one );
                $ap = explode( ':', $one, 2 );
                $action = strtolower( trim( $ap[0] ) );
                if( $action === '' || preg_match( self::PLAYBOOK_ACTION_DENY, $action ) )
                    $bad( $at . 'action "' . substr( $ap[0], 0, 40 ) . '" is not available in a playbook here' );
                // allow list per action (action-classes.json): only actions that show, change or write a file into the
                // folder of the run; an action that is not in the list, reads a server file or reaches another system is refused
                $fileAt = null;
                if( isset( $this->actionClasses()['types'][$type] ) )
                {
                    $class = $this->actionClass( $type, $action );
                    if( $class === null || !in_array( $class['class'], array( 'read', 'change', 'writes-file' ), TRUE ) )
                        $bad( $at . 'action "' . substr( $ap[0], 0, 40 ) . '" is not available in a playbook here' . ( $class !== null ? ' (' . $class['class'] . ')' : '' ) );
                    if( $class['class'] === 'writes-file' && isset( $class['file_arg'] ) )
                        $fileAt = (int)$class['file_arg'];
                }
                elseif( preg_match( '/^export/', $action ) )
                    $fileAt = 0;
                // the file name argument of an action that writes a file: a plain file name
                if( $fileAt !== null )
                {
                    $file = explode( ',', $ap[1] ?? '' )[$fileAt] ?? '';
                    if( !preg_match( self::PLAYBOOK_FILENAME, $file ) )
                        $bad( $at . 'action ' . $ap[0] . ': a plain file name (letters, digits, . _ -) as file argument' );
                }
            }
            return;
        }
        if( !preg_match( '/^[A-Za-z0-9 _.,:|\-]{0,300}$/', $arg ) )
            $bad( $at . $parts[0] . ': letters, digits, space and . _ - , : | only' );
    }

    /** @return array file row incl. absolute 'path'; the file must belong to the project and be of $kind */
    private function fileGet( array $project, $fid, ?string $kind = null ): array
    {
        $f = is_string( $fid ) && preg_match( '/^[0-9a-f]{32}$/', $fid )
            ? $this->q( 'SELECT * FROM files WHERE fid = ? AND project_id = ?', array( $fid, $project['id'] ) )->fetch() : FALSE;
        if( !$f || !preg_match( '/^[0-9a-f]{32}\.(json|dat)$/', $f['file'] ) || ( $kind !== null && $f['kind'] !== $kind ) )
            throw new ViewerException( $kind === null ? 'not found' : 'unknown ' . ( $kind === 'bp' ? 'BP JSON' : $kind ) . ' file of this project', $kind === null ? 404 : 400 );
        $f['path'] = $this->projectDir( $project['pid'] ) . '/files/' . $f['file'];
        if( !is_file( $f['path'] ) )
            throw new ViewerException( 'not found', 404 );
        return $f;
    }

    public function fileList( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        return $this->q( 'SELECT f.fid, f.kind, f.name, f.size, f.created, u.name AS created_by FROM files f LEFT JOIN users u ON u.id = f.created_by
            WHERE f.project_id = ? ORDER BY f.id DESC', array( $p['id'] ) )->fetchAll();
    }

    /** upload of a playbook JSON (checked: playbookCheck()) or a BP JSON; stored under a random name */
    public function fileUpload( array $user, $pid, $kind, ?array $upload ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'uploading a project file' );
        $pluginKinds = $this->pluginKinds();
        if( !is_string( $kind ) || ( !in_array( $kind, self::FILE_KINDS, TRUE ) && !isset( $pluginKinds[$kind] ) ) )
            throw new ViewerException( 'kind must be one of: ' . implode( ', ', array_merge( self::FILE_KINDS, array_keys( $pluginKinds ) ) ), 400 );
        if( $upload === null || !isset( $upload['tmp_name'], $upload['error'] ) || is_array( $upload['tmp_name'] ) || $upload['error'] !== UPLOAD_ERR_OK || !is_uploaded_file( $upload['tmp_name'] ) )
            throw new ViewerException( 'no file uploaded (field "file")', 400 );
        // a file kind of a plug-in can be any file ('format' => 'raw', e.g. a 3rd party configuration) with its own limit
        $raw = ( $pluginKinds[$kind]['format'] ?? 'json' ) === 'raw';
        if( filesize( $upload['tmp_name'] ) > ( $pluginKinds[$kind]['max'] ?? self::FILE_MAX ) )
            throw new ViewerException( 'file too large', 413 );
        $j = null;
        if( !$raw )
        {
            $j = json_decode( (string)file_get_contents( $upload['tmp_name'] ), TRUE );
            if( !is_array( $j ) )
                throw new ViewerException( 'not a JSON file', 400 );
        }
        if( $kind === 'playbook' )
            $this->playbookCheck( $j );
        $ext = $raw ? '.dat' : '.json';
        if( isset( $pluginKinds[$kind]['check'] ) )
        {
            // the plug-in says what is wrong with the file (text), or nothing. JSON: the decoded content; raw: the path
            $why = ( $pluginKinds[$kind]['check'] )( $raw ? $upload['tmp_name'] : $j );
            if( is_string( $why ) && $why !== '' )
                throw new ViewerException( substr( $why, 0, 300 ), 400 );
        }
        $label = self::checkLabel( basename( str_replace( '\\', '/', (string)( $upload['name'] ?? 'file.json' ) ) ), 'file name', 120 );
        $dir = $this->projectDir( $p['pid'] ) . '/files';
        if( !is_dir( $dir ) && !@mkdir( $dir, 0700, TRUE ) )
            throw new ViewerException( 'file can not be stored', 500 );
        $fid = self::randomId();
        if( !move_uploaded_file( $upload['tmp_name'], $dir . '/' . $fid . $ext ) )
            throw new ViewerException( 'file can not be stored', 500 );
        @chmod( $dir . '/' . $fid . $ext, 0600 );
        $this->q( 'INSERT INTO files (fid, project_id, kind, name, file, size, created_by, created) VALUES (?,?,?,?,?,?,?,?)',
            array( $fid, $p['id'], $kind, $label, $fid . $ext, filesize( $dir . '/' . $fid . $ext ), $user['id'], time() ) );
        return array( 'fid' => $fid, 'kind' => $kind, 'name' => $label );
    }

    public function fileDownload( array $user, $pid, $fid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $f = $this->fileGet( $p, $fid );
        $raw = substr( $f['file'], -4 ) === '.dat';
        // a raw file (e.g. a 3rd party configuration) is a whole configuration: not for members limited to types / locations
        if( $raw )
            self::needUnlimited( $p, 'this file' );
        return array( 'name' => preg_replace( '/[^A-Za-z0-9._-]/', '_', $f['name'] ), 'content' => (string)file_get_contents( $f['path'] ), 'raw' => $raw );
    }

    public function fileDelete( array $user, $pid, $fid ): void
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'deleting a project file' );
        $f = $this->fileGet( $p, $fid );
        $this->q( 'DELETE FROM files WHERE id = ?', array( $f['id'] ) );
        @unlink( $f['path'] );
    }

    // ---- used by bin/jobs.php only (CLI)

    /** @return array|null the next queued job with 'dir', 'config' (absolute paths) - marked as running */
    public function runnerTake(): ?array
    {
        $this->db->beginTransaction();
        $j = $this->q( "SELECT j.*, p.pid, c.file FROM jobs j JOIN projects p ON p.id = j.project_id LEFT JOIN configs c ON c.id = j.config_id
            WHERE j.state = 'queued' ORDER BY j.id LIMIT 1" )->fetch();
        if( $j )
            $this->q( "UPDATE jobs SET state = 'running', started = ? WHERE id = ?", array( time(), $j['id'] ) );
        $this->db->commit();
        if( !$j )
            return null;
        $dir = $this->dataDir . '/projects/' . $j['pid'];
        $config = $j['file'] !== null && preg_match( '/^[0-9a-f]{32}\.xml$/', $j['file'] ) ? $dir . '/' . $j['file'] : null;
        $args = json_decode( $j['args'], TRUE );
        // a run type of a plug-in without a version: no in=
        $noVersion = ( $this->pluginRuns()[$j['type']]['input'] ?? 'version' ) === 'none' && (int)$j['config_id'] === 0;
        if( ( !$noVersion && ( $config === null || !is_file( $config ) ) ) || !in_array( $j['type'], $this->jobTypes(), TRUE ) || !is_array( $args ) || !preg_match( '/^[0-9a-f]{32}$/', $j['jid'] ) )
        {
            $this->runnerFinish( (int)$j['id'], 'failed', 'the configuration version does not exist any more' );
            return $this->runnerTake();
        }
        $jobDir = $dir . '/jobs/' . $j['jid'];
        if( !is_dir( $jobDir ) && !@mkdir( $jobDir, 0700, TRUE ) )
        {
            $this->runnerFinish( (int)$j['id'], 'failed', 'the folder of the run can not be created' );
            return $this->runnerTake();
        }
        // %FILES% / %JOB%: the folders of the project files and of this run - set here, never by a request
        $args = array_values( array_filter( $args, 'is_string' ) );
        $rawArgs = $args;
        foreach( $args as $i => $a )
        {
            if( preg_match( '#^[a-z-]+=%FILES%/([0-9a-f]{32}\.(?:json|dat))$#', $a, $m ) && !is_file( $dir . '/files/' . $m[1] ) )
            {
                $this->runnerFinish( (int)$j['id'], 'failed', 'a file of the run (playbook / BP JSON) does not exist any more' );
                return $this->runnerTake();
            }
            $args[$i] = str_replace( array( '%FILES%', '%JOB%' ), array( $dir . '/files', $jobDir ), $a );
        }
        // pid / jid / file / rawArgs: for a run in a container (ViewerContainer), where the folders have other paths
        // 'tool': the pan-os-php type that runs - for a run type of a plug-in the one it names
        // environment a run type of a plug-in asks for: %PLUGIN% is the folder of the plug-in (in a container: where it is mounted)
        $pr = $this->pluginRuns()[$j['type']] ?? null;
        $env = array();
        foreach( $pr['env'] ?? array() as $k => $v )
            $env[$k] = str_replace( '%PLUGIN%', $pr['dir'], $v );
        return array( 'env' => $env, 'rawEnv' => $pr['env'] ?? array(), 'plugin' => $pr['plugin'] ?? null, 'pluginBuiltin' => $pr['builtin'] ?? FALSE,
            'id' => (int)$j['id'], 'type' => $j['type'], 'tool' => $this->pluginRuns()[$j['type']]['tool'] ?? $j['type'], 'args' => $args, 'dir' => $jobDir, 'config' => $noVersion ? null : $config,
            'pid' => $j['pid'], 'jid' => $j['jid'], 'file' => $noVersion ? null : $j['file'], 'rawArgs' => $rawArgs );
    }

    /** 'running' (still wanted), 'cancelled', or null when the job / project was deleted */
    public function runnerState( int $id ): ?string
    {
        $r = $this->q( 'SELECT state FROM jobs WHERE id = ?', array( $id ) )->fetch();
        return $r ? $r['state'] : null;
    }

    public function runnerFinish( int $id, string $state, ?string $error = null ): void
    {
        $this->q( "UPDATE jobs SET state = ?, finished = ?, error = ? WHERE id = ? AND state = 'running'", array( $state, time(), $error, $id ) );
    }

    /** after a restart of the runner: nothing is running any more */
    public function runnerReset(): void
    {
        $this->q( "UPDATE jobs SET state = 'failed', finished = ?, error = 'the job runner was stopped' WHERE state = 'running'", array( time() ) );
    }

    // ------------------------------------------------------------------ audit log

    /** fields of a request body that are kept in the audit log - never passwords, tokens or file content */
    const AUDIT_FIELDS = array( 'type', 'location', 'filter', 'actions', 'ruletype', 'securityprofiletype', 'user', 'role', 'types', 'scope', 'label', 'days',
        'name', 'playbook', 'bp', 'admin', 'kind' );

    /** one line of the audit log; old lines are removed after PANOSPHP_VIEWER_AUDIT_DAYS (default 365) */
    public function auditWrite( ?string $user, ?string $token, string $ip, ?string $pid, string $method, string $route, int $status, array $detail = array() ): void
    {
        try
        {
            $keep = array();
            foreach( self::AUDIT_FIELDS as $k )
                if( isset( $detail[$k] ) && ( is_scalar( $detail[$k] ) || is_array( $detail[$k] ) ) )
                    $keep[$k] = is_string( $detail[$k] ) ? substr( $detail[$k], 0, 2000 ) : $detail[$k];
            $this->q( 'INSERT INTO audit (ts, user, token, ip, pid, method, route, status, detail) VALUES (?,?,?,?,?,?,?,?,?)',
                array( time(), $user !== null ? substr( $user, 0, 64 ) : null, $token, substr( $ip, 0, 64 ), $pid !== null && preg_match( '/^[0-9a-f]{32}$/', $pid ) ? $pid : null,
                    substr( $method, 0, 10 ), substr( $route, 0, 300 ), $status, count( $keep ) > 0 ? json_encode( $keep ) : null ) );
            if( random_int( 1, 200 ) === 1 )
                $this->q( 'DELETE FROM audit WHERE ts < ?', array( time() - max( 1, (int)( getenv( 'PANOSPHP_VIEWER_AUDIT_DAYS' ) ?: 365 ) ) * 86400 ) );
        }
        catch( Throwable $e )
        {
            error_log( 'config-viewer audit: ' . $e->getMessage() );
        }
    }

    /**
     * the audit log, newest first: of one project (its owner) or of everything (admin, $pid null).
     * Not with an API token. Filters: 'user', 'before' (id), 'limit' (1-1000, default 200).
     */
    public function auditList( array $user, $pid, array $in ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $where = array();
        $args = array();
        if( $pid !== null )
        {
            $p = $this->projectGet( $user, $pid, 'owner' );
            $where[] = 'pid = ?';
            $args[] = $p['pid'];
        }
        elseif( empty( $user['is_admin'] ) )
            throw new ViewerException( 'not found', 404 );
        if( isset( $in['user'] ) && is_string( $in['user'] ) && $in['user'] !== '' )
        {
            $where[] = 'user = ? COLLATE NOCASE';
            $args[] = $in['user'];
        }
        if( isset( $in['before'] ) && is_numeric( $in['before'] ) )
        {
            $where[] = 'id < ?';
            $args[] = (int)$in['before'];
        }
        $limit = isset( $in['limit'] ) && is_numeric( $in['limit'] ) ? max( 1, min( 1000, (int)$in['limit'] ) ) : 200;
        $rows = $this->q( 'SELECT id, ts, user, token, ip, pid, method, route, status, detail FROM audit' . ( count( $where ) ? ' WHERE ' . implode( ' AND ', $where ) : '' )
            . ' ORDER BY id DESC LIMIT ' . $limit, $args )->fetchAll();
        foreach( $rows as $i => $r )
            $rows[$i]['detail'] = $r['detail'] !== null ? json_decode( $r['detail'], TRUE ) : null;
        return $rows;
    }

    // ------------------------------------------------------------------ API tokens (scripts)

    const TOKEN_MAX_DAYS = 365;

    /**
     * A new API token of $user for one project. The secret is returned once and never stored (only its hash).
     * The token acts as the user, on this project only, with at most $role - and with the types / scope of the member.
     * @return array token (incl. 'token' = the value for "Authorization: Bearer")
     */
    public function tokenCreate( array $user, $pid, $label, $role, $days ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        $p = $this->projectGet( $user, $pid, 'read' );
        $label = self::checkLabel( $label, 'label' );
        if( !in_array( $role, self::ROLES, TRUE ) )
            throw new ViewerException( 'role must be one of: ' . implode( ', ', self::ROLES ), 400 );
        if( $role === 'write' && $p['role'] === 'read' )
            throw new ViewerException( 'not allowed: your own permission on this project is "read"', 403 );
        if( !is_int( $days ) || $days < 1 || $days > self::TOKEN_MAX_DAYS )
            throw new ViewerException( 'days: 1-' . self::TOKEN_MAX_DAYS, 400 );
        $tid = self::randomId( 8 );
        $secret = self::randomId( 32 );
        $expires = time() + $days * 86400;
        $this->q( 'INSERT INTO tokens (tid, hash, user_id, project_id, role, label, expires, created) VALUES (?,?,?,?,?,?,?,?)',
            array( $tid, hash( 'sha256', $secret ), $user['id'], $p['id'], $role, $label, $expires, time() ) );
        return array( 'tid' => $tid, 'label' => $label, 'role' => $role, 'expires' => $expires, 'token' => 'pvt_' . $tid . '_' . $secret );
    }

    /** tokens of a project: the owner sees all, a member its own. Never the secret. */
    public function tokenList( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $sql = 'SELECT t.tid, t.label, t.role, t.expires, t.created, t.last_used, u.name AS user FROM tokens t JOIN users u ON u.id = t.user_id WHERE t.project_id = ?';
        $args = array( $p['id'] );
        if( $p['role'] !== 'owner' )
        {
            $sql .= ' AND t.user_id = ?';
            $args[] = $user['id'];
        }
        return $this->q( $sql . ' ORDER BY t.id', $args )->fetchAll();
    }

    public function tokenDelete( array $user, $pid, $tid ): void
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        $p = $this->projectGet( $user, $pid, 'read' );
        $t = is_string( $tid ) ? $this->q( 'SELECT id, user_id FROM tokens WHERE tid = ? AND project_id = ?', array( $tid, $p['id'] ) )->fetch() : FALSE;
        if( !$t || ( $p['role'] !== 'owner' && (int)$t['user_id'] !== (int)$user['id'] ) )
            throw new ViewerException( 'not found', 404 );
        $this->q( 'DELETE FROM tokens WHERE id = ?', array( $t['id'] ) );
    }

    /**
     * The user of an "Authorization: Bearer" value; null when the token is unknown, wrong or expired.
     * The one place that checks a token - another source (OIDC) can be added next to it.
     * @return array|null user row with 'token' => array( project_id, role )
     */
    public function userByToken( $bearer ): ?array
    {
        if( !is_string( $bearer ) || !preg_match( '/^pvt_([0-9a-f]{16})_([0-9a-f]{64})$/', $bearer, $m ) )
            return null;
        $t = $this->q( 'SELECT * FROM tokens WHERE tid = ?', array( $m[1] ) )->fetch();
        if( !$t || !hash_equals( $t['hash'], hash( 'sha256', $m[2] ) ) || (int)$t['expires'] < time() )
            return null;
        $u = $this->userById( (int)$t['user_id'] );
        if( $u === null )
            return null;
        if( (int)$t['last_used'] < time() - 60 )
            $this->q( 'UPDATE tokens SET last_used = ? WHERE id = ?', array( time(), $t['id'] ) );
        $u['token'] = array( 'project_id' => (int)$t['project_id'], 'role' => $t['role'], 'tid' => $t['tid'] );
        return $u;
    }

    // ------------------------------------------------------------------ configurations (versions)

    public function configList( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        return $this->q( 'SELECT c.cid, c.name, c.size, c.note, c.created, u.name AS created_by, pc.cid AS parent
            FROM configs c LEFT JOIN users u ON u.id = c.created_by LEFT JOIN configs pc ON pc.id = c.parent_id
            WHERE c.project_id = ? ORDER BY c.id DESC', array( $p['id'] ) )->fetchAll();
    }

    /** @return array config row incl. absolute 'path'; the config must belong to the project */
    private function configGet( array $project, $cid ): array
    {
        $c = null;
        if( is_string( $cid ) && preg_match( '/^[0-9a-f]{32}$/', $cid ) )
            $c = $this->q( 'SELECT * FROM configs WHERE cid = ? AND project_id = ?', array( $cid, $project['id'] ) )->fetch();
        if( !$c || !preg_match( '/^[0-9a-f]{32}\.xml$/', $c['file'] ) )
            throw new ViewerException( 'not found', 404 );
        $c['path'] = $this->projectDir( $project['pid'] ) . '/' . $c['file'];
        if( !is_file( $c['path'] ) )
            throw new ViewerException( 'not found', 404 );
        return $c;
    }

    public static function maxUpload(): int
    {
        $mb = (int)( getenv( 'PANOSPHP_VIEWER_MAX_UPLOAD_MB' ) ?: 200 );
        return max( 1, $mb ) * 1048576;
    }

    /** a PAN-OS configuration starts with the element <config>; read with XMLReader (no entity expansion, no network) */
    private static function isPanosConfig( string $path ): bool
    {
        $r = new XMLReader();
        if( !@$r->open( $path, null, LIBXML_NONET ) )
            return FALSE;
        $ok = FALSE;
        while( @$r->read() )
        {
            if( $r->nodeType == XMLReader::DOC_TYPE )
                break;
            if( $r->nodeType == XMLReader::ELEMENT )
            {
                $ok = $r->name === 'config';
                break;
            }
        }
        $r->close();
        return $ok;
    }

    public function configUpload( array $user, $pid, ?array $upload ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'upload' );
        if( $upload === null || !isset( $upload['tmp_name'], $upload['error'] ) || is_array( $upload['tmp_name'] ) )
            throw new ViewerException( 'no file uploaded (field "config")', 400 );
        if( $upload['error'] !== UPLOAD_ERR_OK || !is_uploaded_file( $upload['tmp_name'] ) )
            throw new ViewerException( 'upload failed (file too large?)', 400 );
        if( filesize( $upload['tmp_name'] ) > self::maxUpload() )
            throw new ViewerException( 'file too large', 413 );
        if( !self::isPanosConfig( $upload['tmp_name'] ) )
            throw new ViewerException( 'not a PAN-OS configuration (XML with root element <config> expected)', 400 );

        // the original file name is only a label in the DB - the file on disk gets a random name
        $label = self::checkLabel( basename( str_replace( '\\', '/', (string)( $upload['name'] ?? 'config.xml' ) ) ), 'file name', 120 );
        $file = self::randomId() . '.xml';
        if( !move_uploaded_file( $upload['tmp_name'], $this->projectDir( $p['pid'] ) . '/' . $file ) )
            throw new ViewerException( 'file can not be stored', 500 );
        @chmod( $this->projectDir( $p['pid'] ) . '/' . $file, 0600 );
        return $this->configInsert( $p, $user, $label, $file, null, 'upload' );
    }

    private function configInsert( array $p, array $user, string $label, string $file, ?int $parentId, string $note ): array
    {
        $cid = self::randomId();
        $this->q( 'INSERT INTO configs (cid, project_id, name, file, size, parent_id, note, created_by, created) VALUES (?,?,?,?,?,?,?,?,?)',
            array( $cid, $p['id'], $label, $file, filesize( $this->projectDir( $p['pid'] ) . '/' . $file ), $parentId, $note, $user['id'], time() ) );
        return array( 'cid' => $cid, 'name' => $label, 'note' => $note );
    }

    public function configDelete( array $user, $pid, $cid ): void
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'deleting a version' );
        $c = $this->configGet( $p, $cid );
        $this->sessionStop( $p, (int)$c['id'] );
        $this->q( 'UPDATE configs SET parent_id = NULL WHERE parent_id = ?', array( $c['id'] ) );
        $this->q( 'DELETE FROM configs WHERE id = ?', array( $c['id'] ) );
        @unlink( $c['path'] );
    }

    /** @return array ['path' => ..., 'name' => download file name] */
    public function configDownload( array $user, $pid, $cid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'download' );
        $c = $this->configGet( $p, $cid );
        $name = preg_replace( '/[^A-Za-z0-9._-]+/', '_', $c['name'] );
        if( !preg_match( '/\.xml$/i', $name ) )
            $name .= '.xml';
        return array( 'path' => $c['path'], 'name' => $name );
    }

    // ------------------------------------------------------------------ pan-os-php: meta data, read, change

    /** types, actions and filters the prototype offers (from utils/lib/util_action_filter.json) */
    private $actionClasses = null;

    /**
     * the risk class of every action (action-classes.json, built by bin/action-classes.php): the allow list per action.
     * @return array 'reviewed' => types a person has checked, 'types' => type => action => array( 'class', 'file_arg' )
     */
    public function actionClasses(): array
    {
        if( $this->actionClasses === null )
        {
            $j = json_decode( (string)@file_get_contents( dirname(__FILE__) . '/../action-classes.json' ), TRUE );
            $this->actionClasses = array( 'reviewed' => is_array( $j['reviewed'] ?? null ) ? $j['reviewed'] : array(),
                'types' => is_array( $j['types'] ?? null ) ? $j['types'] : array() );
        }
        return $this->actionClasses;
    }

    /** class of an action of a type: 'read', 'change', 'writes-file', 'reads-file', 'network'; null: not in the list (never offered) */
    public function actionClass( string $type, string $action ): ?array
    {
        $e = $this->actionClasses()['types'][$type][strtolower( $action )] ?? null;
        return is_array( $e ) && isset( $e['class'] ) ? $e : null;
    }

    public function meta(): array
    {
        if( $this->meta !== null )
            return $this->meta;
        $j = json_decode( (string)@file_get_contents( $this->repoDir . '/utils/lib/util_action_filter.json' ), TRUE );
        $meta = array();
        foreach( self::TYPES as $type )
        {
            if( !isset( $j[$type] ) )
                continue;
            $actions = array();
            foreach( (array)$j[$type]['action'] as $name => $a )
            {
                if( $name === 'display' || preg_match( self::ACTION_DENY_NAME, $name ) )
                    continue;
                // allow list per action: only actions that change the configuration in memory (or only show it)
                $class = $this->actionClass( $type, (string)$name );
                if( $class === null || !in_array( $class['class'], array( 'read', 'change' ), TRUE ) )
                    continue;
                $args = array();
                $deny = FALSE;
                foreach( (array)( $a['args'] ?? array() ) as $argName => $arg )
                {
                    if( preg_match( self::ACTION_DENY_ARG, (string)$argName ) )
                        $deny = TRUE;
                    $args[] = array( 'name' => (string)$argName, 'default' => isset( $arg['default'] ) && is_scalar( $arg['default'] ) ? (string)$arg['default'] : '',
                        'help' => isset( $arg['help'] ) && is_string( $arg['help'] ) ? $arg['help'] : '' );
                }
                if( !$deny )
                    $actions[$name] = $args;
            }
            ksort( $actions );
            $filters = array();
            foreach( (array)$j[$type]['filter'] as $field => $f )
            {
                $ops = array();
                foreach( array_keys( (array)( $f['operators'] ?? array() ) ) as $op )
                    if( !preg_match( '/\.file$|\.file\./', (string)$op ) )
                        $ops[] = (string)$op;
                $filters[(string)$field] = $ops;
            }
            $meta[$type] = array( 'actions' => $actions, 'filters' => $filters, 'readonly' => FALSE, 'resource' => self::resourceName( $type ) );
        }
        // every other type that shows objects (action 'display'): read only, until its actions are in a reviewed allow list
        foreach( $j as $type => $def )
        {
            if( isset( $meta[$type] ) || !is_array( $def ) || !isset( $def['action']['display'] ) || !preg_match( '/^[a-z][a-z0-9-]{1,40}$/', (string)$type ) )
                continue;
            $filters = array();
            foreach( (array)( $def['filter'] ?? array() ) as $field => $f )
            {
                $ops = array();
                foreach( array_keys( (array)( $f['operators'] ?? array() ) ) as $op )
                    if( !preg_match( '/\.file$|\.file\./', (string)$op ) )
                        $ops[] = (string)$op;
                $filters[(string)$field] = $ops;
            }
            // a type a person has reviewed (action-classes.json "reviewed") can be changed: its 'read' / 'change' actions
            $actions = array();
            if( in_array( $type, $this->actionClasses()['reviewed'], TRUE ) )
                foreach( (array)$def['action'] as $name => $a )
                {
                    $class = $this->actionClass( (string)$type, (string)$name );
                    if( $name === 'display' || preg_match( self::ACTION_DENY_NAME, (string)$name ) || $class === null || !in_array( $class['class'], array( 'read', 'change' ), TRUE ) )
                        continue;
                    $args = array();
                    foreach( (array)( $a['args'] ?? array() ) as $argName => $arg )
                        $args[] = array( 'name' => (string)$argName, 'default' => isset( $arg['default'] ) && is_scalar( $arg['default'] ) ? (string)$arg['default'] : '',
                            'help' => isset( $arg['help'] ) && is_string( $arg['help'] ) ? $arg['help'] : '' );
                    $actions[(string)$name] = $args;
                }
            ksort( $actions );
            $meta[$type] = array( 'actions' => $actions, 'filters' => $filters, 'readonly' => count( $actions ) == 0, 'resource' => self::resourceName( $type ) );
        }
        $this->meta = array( 'types' => $meta, 'ruletypes' => self::RULETYPES, 'securityprofiletypes' => self::SPTYPES,
            'resources' => array_map( function( $t ) { return array( 'type' => $t, 'model' => 'scm-v1' ); }, self::SCM_RESOURCES ) );
        return $this->meta;
    }

    public static function resourceName( string $type ): string
    {
        return self::RESOURCES[$type] ?? ( substr( $type, -1 ) === 's' ? $type . 'es' : $type . 's' );
    }

    /** the type of a REST resource name (e.g. 'addresses' -> 'address'); null: unknown */
    public function resourceType( $resource ): ?string
    {
        if( !is_string( $resource ) )
            return null;
        if( isset( self::SCM_RESOURCES[$resource] ) )
            return self::SCM_RESOURCES[$resource];
        foreach( $this->meta()['types'] as $type => $m )
            if( $m['resource'] === $resource )
                return $type;
        return null;
    }

    /** validates the query of a read / change request and returns the pan-os-php arguments (without in / out / actions) */
    private function queryArgs( array $in, array $project ): array
    {
        $type = $in['type'] ?? '';
        if( !is_string( $type ) || !isset( $this->meta()['types'][$type] ) )
            throw new ViewerException( 'type must be one of: ' . implode( ', ', array_keys( $this->meta()['types'] ) ), 400 );
        if( $project['types'] !== null && !in_array( $type, $project['types'], TRUE ) )
            throw new ViewerException( 'not allowed: your access to this project does not include type ' . $type, 403 );
        // only types whose objects live in a location are covered by a location scope (templates: not yet)
        if( $project['scope'] !== null && !in_array( $type, self::SCOPE_TYPES, TRUE ) )
            throw new ViewerException( 'not allowed: type ' . $type . ' is not available with access limited to locations', 403 );
        $args = array( 'type=' . $type );

        $location = $in['location'] ?? 'any';
        if( $location === '' )
            $location = 'any';
        // limited to locations: exactly one location of the scope per request (no 'any', no list) - enforced here, not in the UI
        if( $project['scope'] !== null && !in_array( $location, $project['scope'], TRUE ) )
            throw new ViewerException( 'not allowed: your access is limited to the locations: ' . implode( ', ', $project['scope'] ), 403 );
        if( !is_string( $location ) || !preg_match( '/^[A-Za-z0-9 _.,:\-]{1,200}$/', $location ) )
            throw new ViewerException( 'location: letters, digits, space and . _ - , : only', 400 );
        $args[] = 'location=' . $location;

        if( $type === 'rule' )
        {
            $rt = $in['ruletype'] ?? 'security';
            if( !in_array( $rt, self::RULETYPES, TRUE ) )
                throw new ViewerException( 'unknown ruletype', 400 );
            $args[] = 'ruletype=' . $rt;
        }
        if( $type === 'securityprofile' )
        {
            $st = $in['securityprofiletype'] ?? 'any';
            if( !in_array( $st, self::SPTYPES, TRUE ) )
                throw new ViewerException( 'unknown securityprofiletype', 400 );
            $args[] = 'securityprofiletype=' . $st;
        }

        $filter = $in['filter'] ?? '';
        if( !is_string( $filter ) )
            throw new ViewerException( 'filter must be text', 400 );
        $filter = trim( $filter );
        if( $filter !== '' )
        {
            if( strlen( $filter ) > 2000 || preg_match( '/[\x00-\x1F\x7F]/', $filter ) )
                throw new ViewerException( 'filter too long or with control characters', 400 );
            // operators like 'is.in.file' read a file on the server
            if( preg_match( '/\.file\b/i', $filter ) )
                throw new ViewerException( 'filter operators that read a file are not available here', 400 );
            $args[] = 'filter=' . $filter;
        }
        return $args;
    }

    /** validates "actions" of a change request: every action must be an offered action of the type */
    private function actionsArg( string $type, $actions, array $project ): string
    {
        if( !is_string( $actions ) || trim( $actions ) === '' )
            throw new ViewerException( 'actions missing', 400 );
        $actions = trim( $actions );
        if( strlen( $actions ) > 2000 || preg_match( '/[\x00-\x1F\x7F]/', $actions ) )
            throw new ViewerException( 'actions too long or with control characters', 400 );
        $offered = $this->meta()['types'][$type]['actions'];
        foreach( explode( '/', str_replace( '//', "\x01", $actions ) ) as $one )
        {
            $name = strtolower( trim( explode( ':', $one )[0] ) );
            if( !isset( $offered[$name] ) )
                throw new ViewerException( 'action "' . substr( $name, 0, 60 ) . '" is not available here for type ' . $type, 400 );
            // an action that moves / copies objects to another location would act outside the scope
            if( $project['scope'] !== null && preg_match( '/move|copy|clone|replace-by|merge/', $name ) )
                throw new ViewerException( 'not allowed: action "' . substr( $name, 0, 60 ) . '" can act outside your locations', 403 );
        }
        return 'actions=' . $actions;
    }

    // ------------------------------------------------------------------ worker (configuration loaded once, kept in memory)

    private function workDir( array $project ): string
    {
        $work = $this->projectDir( $project['pid'] ) . '/work';
        @mkdir( $work, 0700, TRUE );
        return $work;
    }

    /** the socket lives in <data>/run: the path of a unix socket is limited to about 100 characters */
    private function sessionFiles( string $work, string $sid ): array
    {
        return array( 'sock' => $this->dataDir . '/run/' . $sid . '.sock', 'pid' => $work . '/' . $sid . '.pid', 'log' => $work . '/' . $sid . '.log',
            'autosave' => $work . '/' . $sid . '.autosave.xml' );
    }

    private static function workerAlive( array $files ): bool
    {
        $pid = (int)@file_get_contents( $files['pid'] );
        return $pid > 1 && function_exists( 'posix_kill' ) && @posix_kill( $pid, 0 ) && file_exists( $files['sock'] );
    }

    /** one request to the worker: one JSON line, answer until the worker closes the connection */
    private function workerCall( array $files, array $cmd, int $timeout = 300 ): array
    {
        $conn = @stream_socket_client( 'unix://' . $files['sock'], $errno, $errstr, 5 );
        if( !$conn )
            throw new ViewerException( 'the loaded configuration is not reachable - open the version again', 503 );
        stream_set_timeout( $conn, $timeout );
        fwrite( $conn, json_encode( $cmd ) . "\n" );
        $answer = stream_get_contents( $conn );
        $meta = stream_get_meta_data( $conn );
        fclose( $conn );
        if( !empty( $meta['timed_out'] ) )
            throw new ViewerException( 'the run took longer than ' . $timeout . ' seconds', 504 );
        $r = json_decode( (string)$answer, TRUE );
        if( !is_array( $r ) )
            throw new ViewerException( 'the run stopped without an answer', 500 );
        if( empty( $r['ok'] ) )
            throw new ViewerException( $this->hidePaths( isset( $r['error'] ) && is_string( $r['error'] ) && $r['error'] !== '' ? $r['error'] : 'pan-os-php stopped with an error' ), 400 );
        return $r;
    }

    /**
     * The worker of a version: started on first use (loads the configuration once), then reused by every request
     * of every member of the project. A stopped worker that left unsaved changes behind (autosave file) gets its
     * autosave registered as a version first.
     * @return array session files
     */
    private function session( array $project, array $config, array $user ): array
    {
        $work = $this->workDir( $project );
        $row = $this->q( 'SELECT sid FROM sessions WHERE project_id = ? AND config_id = ?', array( $project['id'], $config['id'] ) )->fetch();
        if( $row )
        {
            $files = $this->sessionFiles( $work, $row['sid'] );
            if( self::workerAlive( $files ) )
                return $files;
            $this->sessionCleanup( $project, $row['sid'], $config, $user );
        }

        $sid = self::randomId();
        $files = $this->sessionFiles( $work, $sid );
        // the web server process never starts a process itself: the config-viewer service does (bin/service.php)
        $service = @stream_socket_client( 'unix://' . $this->dataDir . '/service.sock', $errno, $errstr, 5 );
        if( !$service )
            throw new ViewerException( 'the config-viewer service is not running (php utils/develop/config-viewer/bin/service.php)', 503 );
        stream_set_timeout( $service, 20 );
        fwrite( $service, json_encode( array( 'cmd' => 'start', 'config' => $config['path'] ) + $files ) . "\n" );
        $answer = json_decode( (string)stream_get_contents( $service ), TRUE );
        fclose( $service );
        if( !is_array( $answer ) || empty( $answer['ok'] ) )
            throw new ViewerException( 'the config-viewer service did not start the worker', 500 );

        $this->q( 'INSERT INTO sessions (sid, project_id, config_id, created) VALUES (?,?,?,?)', array( $sid, $project['id'], $config['id'], time() ) );
        $deadline = microtime( TRUE ) + max( 10, (int)( getenv( 'PANOSPHP_VIEWER_LOAD_TIMEOUT' ) ?: 600 ) );
        while( microtime( TRUE ) < $deadline )
        {
            if( file_exists( $files['sock'] ) )
                return $files;
            // the worker ended while loading (a pid file without a process id yet is not an ended worker)
            if( file_exists( $files['pid'] ) && trim( (string)@file_get_contents( $files['pid'] ) ) !== ''
                && !self::workerAlive( array( 'pid' => $files['pid'], 'sock' => $files['pid'] ) ) )
                break;
            usleep( 100000 );
        }
        $log = $this->hidePaths( trim( (string)@file_get_contents( $files['log'] ) ) );
        $this->sessionCleanup( $project, $sid, null, $user );
        throw new ViewerException( 'the configuration could not be loaded' . ( $log !== '' ? ': ' . substr( $log, -400 ) : '' ), 500 );
    }

    /** removes the files of a stopped worker; unsaved work that was autosaved becomes a version */
    private function sessionCleanup( array $project, string $sid, ?array $config, array $user ): ?array
    {
        $files = $this->sessionFiles( $this->workDir( $project ), $sid );
        $recovered = null;
        if( $config !== null && is_file( $files['autosave'] ) && self::isPanosConfig( $files['autosave'] ) )
        {
            $file = self::randomId() . '.xml';
            if( @rename( $files['autosave'], $this->projectDir( $project['pid'] ) . '/' . $file ) )
                $recovered = $this->configInsert( $project, $user, $config['name'], $file, (int)$config['id'], 'autosave (recovered, the loaded configuration was stopped before it was saved)' );
        }
        foreach( $files as $f )
            @unlink( $f );
        $this->q( 'DELETE FROM sessions WHERE sid = ?', array( $sid ) );
        return $recovered;
    }

    private function sessionStop( array $project, int $configId ): void
    {
        $row = $this->q( 'SELECT sid FROM sessions WHERE project_id = ? AND config_id = ?', array( $project['id'], $configId ) )->fetch();
        if( !$row )
            return;
        $files = $this->sessionFiles( $this->workDir( $project ), $row['sid'] );
        if( self::workerAlive( $files ) )
        {
            try { $this->workerCall( $files, array( 'cmd' => 'close' ), 20 ); } catch( Exception $e ) { }
            $pid = (int)@file_get_contents( $files['pid'] );
            for( $i = 0; $i < 30 && $pid > 1 && @posix_kill( $pid, 0 ); $i++ )
                usleep( 100000 );
            if( $pid > 1 && @posix_kill( $pid, 0 ) )
                @posix_kill( $pid, 9 );
        }
        foreach( $files as $f )
            @unlink( $f );
        $this->q( 'DELETE FROM sessions WHERE sid = ?', array( $row['sid'] ) );
    }

    private function projectStopAll( array $project ): void
    {
        foreach( $this->q( 'SELECT config_id FROM sessions WHERE project_id = ?', array( $project['id'] ) )->fetchAll() as $r )
            $this->sessionStop( $project, (int)$r['config_id'] );
    }

    private static function flatten( $v ): array
    {
        if( !is_array( $v ) )
            return array( $v );
        $r = array();
        foreach( $v as $x )
            foreach( self::flatten( $x ) as $y )
                $r[] = $y;
        return $r;
    }

    /** server paths never leave the server */
    private function hidePaths( string $text ): string
    {
        $text = str_replace( array( $this->dataDir, $this->repoDir ), array( '<data>', '<pan-os-php>' ), $text );
        return preg_replace( '#<data>/projects/[0-9a-f]{32}/(work/)?[0-9a-f]{32}(\.autosave)?\.xml#', '<config>', $text );
    }

    /** objects of the display output as flat rows */
    private static function rows( array $json ): array
    {
        $rows = array();
        foreach( $json as $key => $stores )
        {
            if( !preg_match( '/Conf$/', (string)$key ) || !is_array( $stores ) )
                continue;
            foreach( $stores as $store )
            {
                $sub = $store['sub'] ?? null;
                if( !is_array( $sub ) || !isset( $sub['object'] ) || !is_array( $sub['object'] ) )
                    continue;
                $location = isset( $sub['name'] ) && $sub['name'] !== '' ? (string)$sub['name'] : 'shared';
                foreach( $sub['object'] as $o )
                {
                    if( !is_array( $o ) )
                        continue;
                    unset( $o['actions'] );
                    $row = array( 'location' => $location );
                    if( isset( $sub['store'] ) && is_string( $sub['store'] ) )
                        $row['store'] = $sub['store'];
                    foreach( $o as $k => $v )
                        $row[(string)$k] = ( is_array( $v ) && $k !== 'model' ) ? array_map( 'strval', self::flatten( $v ) ) : $v;
                    $rows[] = $row;
                }
            }
        }
        return $rows;
    }

    /** 'bp' of a request: a BP JSON file of the project (file id) for this one read / change; the worker gets its path */
    private function bpArg( array $project, array $in ): array
    {
        if( !isset( $in['bp'] ) || $in['bp'] === '' )
            return array();
        return array( 'x-bp=' . $this->fileGet( $project, $in['bp'], 'bp' )['path'] );
    }

    /** read: all objects of one type, filtered by pan-os-php, from the configuration in memory */
    public function objects( array $user, $pid, $cid, array $in, int $max = 50000, bool $computed = FALSE ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $args = $this->queryArgs( $in, $p );
        $type = substr( array_shift( $args ), 5 );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'read', 'type' => $type,
            'args' => array_merge( $args, array( 'actions=display' ), $computed ? array( 'x-computed' ) : array(), $this->bpArg( $p, $in ) ) ) );
        $rows = self::rows( is_array( $r['json'] ?? null ) ? $r['json'] : array() );
        if( $max !== PHP_INT_MAX )
            foreach( $rows as $i => $row )
                unset( $rows[$i]['model'] );

        $columns = array();
        foreach( $rows as $row )
            foreach( $row as $k => $v )
                $columns[$k] = TRUE;
        return array( 'total' => count( $rows ), 'truncated' => count( $rows ) > $max, 'columns' => array_keys( $columns ),
            'rows' => array_slice( $rows, 0, $max ), 'status' => $r['status'] ?? null );
    }

    /**
     * REST: GET …/configs/<cid>/<resource>[/<name>] - the objects of one type as items, with paging.
     * 'model' names the shape of an item: 'display-v0' = the fields of pan-os-php actions=display (not a stable model yet).
     */
    public function resourceList( array $user, $pid, $cid, string $type, array $in, ?string $name = null, ?string $resource = null ): array
    {
        $model = $in['model'] ?? ( isset( self::SCM_RESOURCES[(string)$resource] ) ? 'scm-v1' : 'display-v0' );
        if( $model !== 'display-v0' && !( $model === 'scm-v1' && isset( self::SCM_RESOURCES[(string)$resource] ) ) )
            throw new ViewerException( 'model: display-v0' . ( isset( self::SCM_RESOURCES[(string)$resource] ) ? ' or scm-v1' : ' (this resource has no scm-v1 model yet)' ), 400 );
        $in['type'] = $type;
        foreach( self::SCM_RESOURCE_ARGS[(string)$resource] ?? array() as $k => $v )
            $in[$k] = $v;
        if( $name !== null )
        {
            // the name goes into a pan-os-php filter: only characters that can not change the filter
            if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._\-]{0,127}$/', $name ) )
                throw new ViewerException( 'object name: letters, digits, space and . _ - only (use ?filter= for other names)', 400 );
            $in['filter'] = '(name eq ' . $name . ')';
        }
        $limit = $in['limit'] ?? self::PAGE_DEFAULT;
        $offset = $in['offset'] ?? 0;
        if( !is_numeric( $limit ) || (int)$limit < 1 || (int)$limit > self::PAGE_MAX || !is_numeric( $offset ) || (int)$offset < 0 )
            throw new ViewerException( 'limit: 1-' . self::PAGE_MAX . ', offset: 0 or more', 400 );
        // ?computed=1: the values pan-os-php calculates (references, visibility, best practice, checks) as _panosphp
        $computed = isset( $in['computed'] ) && (string)$in['computed'] === '1';
        if( $computed && $model !== 'scm-v1' )
            throw new ViewerException( 'computed=1 needs the scm-v1 model', 400 );
        $r = $this->objects( $user, $pid, $cid, $in, PHP_INT_MAX, $computed );
        $items = $r['rows'];
        if( $model === 'scm-v1' )
        {
            // the SCM shaped object of the library (ApiObjectModel); one pan-os-php type can hold several SCM resources
            $scm = array();
            foreach( $items as $o )
                if( isset( $o['model']['resource'], $o['model']['item'] ) && $o['model']['resource'] === $resource && is_array( $o['model']['item'] ) )
                    $scm[] = $o['model']['item'];
            $items = $scm;
        }
        else
            foreach( $items as $i => $o )
                unset( $items[$i]['model'] );
        if( $name !== null )
        {
            $items = array_values( array_filter( $items, function( $o ) use ( $name ) { return isset( $o['name'] ) && (string)$o['name'] === $name; } ) );
            if( count( $items ) == 0 )
                throw new ViewerException( 'not found', 404 );
        }
        return array( 'type' => $type, 'resource' => $resource ?? self::resourceName( $type ), 'model' => $model, 'total' => count( $items ),
            'offset' => (int)$offset, 'limit' => (int)$limit, 'items' => array_slice( $items, (int)$offset, (int)$limit ), 'status' => $r['status'] );
    }

    /** change: runs actions on the configuration in memory. Nothing is written until save(). */
    public function change( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $args = $this->queryArgs( $in, $p );
        $type = substr( array_shift( $args ), 5 );
        $args[] = $this->actionsArg( $type, $in['actions'] ?? null, $p );
        $bpArg = $this->bpArg( $p, $in );
        $note = 'type=' . $type . ' ' . implode( ' ', $args ) . ' [' . $user['name'] . ']';
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'change', 'type' => $type, 'args' => array_merge( $args, $bpArg ), 'note' => $note ) );
        return array( 'processed' => count( self::rows( is_array( $r['json'] ?? null ) ? $r['json'] : array() ) ),
            'log' => isset( $r['json']['log'] ) && is_string( $r['json']['log'] ) ? substr( $this->hidePaths( $r['json']['log'] ), 0, 200000 ) : '',
            'status' => $r['status'] ?? null );
    }

    /** state of the loaded configuration: unsaved changes, last autosave. Does not start a worker. */
    public function status( array $user, $pid, $cid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $row = $this->q( 'SELECT sid FROM sessions WHERE project_id = ? AND config_id = ?', array( $p['id'], $c['id'] ) )->fetch();
        if( $row )
        {
            $files = $this->sessionFiles( $this->workDir( $p ), $row['sid'] );
            if( self::workerAlive( $files ) )
                return array( 'loaded' => TRUE ) + (array)( $this->workerCall( $files, array( 'cmd' => 'status' ), 30 )['status'] ?? array() );
        }
        return array( 'loaded' => FALSE, 'dirty' => FALSE, 'changes' => array() );
    }

    /** save: writes the configuration in memory into a NEW version; the loaded configuration continues as that version */
    public function save( array $user, $pid, $cid ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $files = $this->session( $p, $c, $user );
        $file = self::randomId() . '.xml';
        $target = $this->projectDir( $p['pid'] ) . '/' . $file;
        $r = $this->workerCall( $files, array( 'cmd' => 'save', 'file' => $target ) );
        if( empty( $r['saved'] ) )
            return array( 'saved' => FALSE, 'cid' => $c['cid'], 'status' => $r['status'] ?? null );
        if( !is_file( $target ) || !self::isPanosConfig( $target ) )
        {
            @unlink( $target );
            throw new ViewerException( 'saving did not write a configuration', 500 );
        }
        @chmod( $target, 0600 );
        $note = implode( "\n", array_map( 'strval', (array)( $r['changes'] ?? array() ) ) );
        $new = $this->configInsert( $p, $user, $c['name'], $file, (int)$c['id'], substr( $note, 0, 4000 ) );
        $newId = (int)$this->q( 'SELECT id FROM configs WHERE cid = ?', array( $new['cid'] ) )->fetch()['id'];
        $this->q( 'UPDATE sessions SET config_id = ? WHERE project_id = ? AND config_id = ?', array( $newId, $p['id'], $c['id'] ) );
        return array( 'saved' => TRUE, 'cid' => $new['cid'], 'status' => $r['status'] ?? null );
    }

    /** discard: stops the loaded configuration without saving */
    public function discard( array $user, $pid, $cid ): void
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $this->sessionStop( $p, (int)$c['id'] );
    }

    public static function rmTree( string $dir ): void
    {
        if( !is_dir( $dir ) || is_link( $dir ) )
            return;
        foreach( scandir( $dir ) as $e )
        {
            if( $e === '.' || $e === '..' )
                continue;
            $path = $dir . '/' . $e;
            if( is_dir( $path ) && !is_link( $path ) )
                self::rmTree( $path );
            else
                @unlink( $path );
        }
        @rmdir( $dir );
    }
}
