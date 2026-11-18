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
        if( is_string( $pid ) && preg_match( '/^[0-9a-f]{32}$/', $pid ) )
            $p = $this->q( 'SELECT p.*, o.name AS owner FROM projects p JOIN users o ON o.id = p.owner_id WHERE p.pid = ?', array( $pid ) )->fetch();
        $role = null;
        if( $p )
        {
            if( (int)$p['owner_id'] === (int)$user['id'] )
                $role = 'owner';
            else
            {
                $m = $this->q( 'SELECT role FROM members WHERE project_id = ? AND user_id = ?', array( $p['id'], $user['id'] ) )->fetch();
                if( $m && in_array( $m['role'], self::ROLES, TRUE ) )
                    $role = $m['role'];
            }
        }
        if( $role === null )
            throw new ViewerException( 'not found', 404 );

        $rank = array( 'read' => 1, 'write' => 2, 'owner' => 3 );
        if( !isset( $rank[$need] ) || $rank[$role] < $rank[$need] )
            throw new ViewerException( 'not allowed: this needs the project permission "' . $need . '" (yours: "' . $role . '")', 403 );
        $p['role'] = $role;
        return $p;
    }

    public static function projectPublic( array $p ): array
    {
        return array( 'pid' => $p['pid'], 'name' => $p['name'], 'owner' => $p['owner'], 'role' => $p['role'], 'created' => (int)$p['created'] );
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
        foreach( $this->q( 'SELECT u.name AS user, m.role FROM members m JOIN users u ON u.id = m.user_id WHERE m.project_id = ? ORDER BY u.name',
            array( $p['id'] ) )->fetchAll() as $m )
            $list[] = $m;
        return $list;
    }

    public function memberSet( array $user, $pid, $memberName, $role ): void
    {
        $p = $this->projectGet( $user, $pid, 'owner' );
        if( !in_array( $role, self::ROLES, TRUE ) )
            throw new ViewerException( 'role must be one of: ' . implode( ', ', self::ROLES ), 400 );
        $m = $this->userByName( $memberName );
        if( $m === null )
            throw new ViewerException( 'unknown user', 404 );
        if( (int)$m['id'] === (int)$p['owner_id'] )
            throw new ViewerException( 'the owner has all permissions already', 400 );
        $this->q( 'INSERT INTO members (project_id, user_id, role) VALUES (?,?,?)
            ON CONFLICT(project_id, user_id) DO UPDATE SET role = excluded.role', array( $p['id'], $m['id'], $role ) );
    }

    public function memberRemove( array $user, $pid, $memberName ): void
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $m = $this->userByName( $memberName );
        // the owner removes anybody, a member can leave the project
        if( $m === null || ( $p['role'] !== 'owner' && (int)$m['id'] !== (int)$user['id'] ) )
            throw new ViewerException( $p['role'] !== 'owner' ? 'not allowed' : 'unknown user', $p['role'] !== 'owner' ? 403 : 404 );
        $this->q( 'DELETE FROM members WHERE project_id = ? AND user_id = ?', array( $p['id'], $m['id'] ) );
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
        $c = $this->configGet( $p, $cid );
        $name = preg_replace( '/[^A-Za-z0-9._-]+/', '_', $c['name'] );
        if( !preg_match( '/\.xml$/i', $name ) )
            $name .= '.xml';
        return array( 'path' => $c['path'], 'name' => $name );
    }

    // ------------------------------------------------------------------ pan-os-php: meta data, read, change

    /** types, actions and filters the prototype offers (from utils/lib/util_action_filter.json) */
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
            $meta[$type] = array( 'actions' => $actions, 'filters' => $filters );
        }
        $this->meta = array( 'types' => $meta, 'ruletypes' => self::RULETYPES, 'securityprofiletypes' => self::SPTYPES );
        return $this->meta;
    }

    /** validates the query of a read / change request and returns the pan-os-php arguments (without in / out / actions) */
    private function queryArgs( array $in ): array
    {
        $type = $in['type'] ?? '';
        if( !is_string( $type ) || !isset( $this->meta()['types'][$type] ) )
            throw new ViewerException( 'type must be one of: ' . implode( ', ', array_keys( $this->meta()['types'] ) ), 400 );
        $args = array( 'type=' . $type );

        $location = $in['location'] ?? 'any';
        if( $location === '' )
            $location = 'any';
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
    private function actionsArg( string $type, $actions ): string
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
            if( file_exists( $files['pid'] ) && !self::workerAlive( array( 'pid' => $files['pid'], 'sock' => $files['pid'] ) ) )
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
                        $row[(string)$k] = is_array( $v ) ? array_map( 'strval', self::flatten( $v ) ) : $v;
                    $rows[] = $row;
                }
            }
        }
        return $rows;
    }

    /** read: all objects of one type, filtered by pan-os-php, from the configuration in memory */
    public function objects( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $args = $this->queryArgs( $in );
        $type = substr( array_shift( $args ), 5 );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'read', 'type' => $type, 'args' => array_merge( $args, array( 'actions=display' ) ) ) );
        $rows = self::rows( is_array( $r['json'] ?? null ) ? $r['json'] : array() );

        $columns = array();
        foreach( $rows as $row )
            foreach( $row as $k => $v )
                $columns[$k] = TRUE;
        $max = 50000;
        return array( 'total' => count( $rows ), 'truncated' => count( $rows ) > $max, 'columns' => array_keys( $columns ),
            'rows' => array_slice( $rows, 0, $max ), 'status' => $r['status'] ?? null );
    }

    /** change: runs actions on the configuration in memory. Nothing is written until save(). */
    public function change( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $args = $this->queryArgs( $in );
        $type = substr( array_shift( $args ), 5 );
        $args[] = $this->actionsArg( $type, $in['actions'] ?? null );
        $note = 'type=' . $type . ' ' . implode( ' ', $args ) . ' [' . $user['name'] . ']';
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'change', 'type' => $type, 'args' => $args, 'note' => $note ) );
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
