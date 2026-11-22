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
// licences and encrypted plug-in packages (no other part of the pan-os-php library is loaded by the web part)
require_once dirname(__FILE__) . '/../../../../lib/misc-classes/PluginLicense.php';
require_once dirname(__FILE__) . '/../../../../lib/misc-classes/PluginPackage.php';
require_once dirname(__FILE__) . '/ViewerPlugins.php';
require_once dirname(__FILE__) . '/ViewerGit.php';
require_once dirname(__FILE__) . '/../../../../lib/misc-classes/ConfigObjectSplit.php';

class ViewerException extends Exception
{
}

/** an error with a debug text for the user (e.g. the key generation: the call, TLS, the answer - never a secret) */
class ViewerDetailException extends ViewerException
{
    public $details;

    public function __construct( string $message, int $code, string $details )
    {
        parent::__construct( $message, $code );
        $this->details = $details;
    }
}

class ViewerApp
{
    const ROLES = array( 'read', 'write' );
    const TYPES = array( 'address', 'service', 'tag', 'rule', 'zone', 'schedule', 'securityprofile', 'securityprofilegroup' );
    const RULETYPES = array( 'any', 'security', 'nat', 'decryption', 'appoverride', 'captiveportal', 'authentication', 'pbf', 'qos', 'dos',
        'tunnelinspection', 'defaultsecurity', 'networkpacketbroker', 'sdwan' );
    /** type=device: devicetype (pan-os-php DEVICEUTIL; which ones a configuration has: Panorama / firewall / SCM) */
    const DEVICETYPES = array( 'any', 'devicegroup', 'template', 'templatestack', 'manageddevice', 'logcollector', 'logcollectorgroup', 'vsys',
        'container', 'devicecloud', 'deviceonprem', 'snippet' );
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
    /**
     * actions of the class 'network' that are offered when their arguments can not reach the network: type => action =>
     * pattern the actions argument must NOT match. address name-rename: only the alias $$reverse-dns$$ does a DNS lookup
     * (gethostbyaddr) - a plain new name (the object window) does not.
     */
    const ACTION_GUARDED = array( 'address' => array( 'name-rename' => '/\$\$reverse-dns\$\$/i' ) );
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

        $this->plugins = ViewerPlugins::load( dirname( __FILE__, 2 ), $this->licence(), function( $f ) { return $this->featureOn( $f ); } );
        $this->refreshPlugins();
        @mkdir( $this->dataDir . '/projects', 0700, TRUE );
        @mkdir( $this->dataDir . '/run', 0700, TRUE );
        // data of the installation for every run: App-ID database (predefined.xml), MaxMind GeoLite2 (geoip/data)
        @mkdir( $this->dataDir . '/central', 0700, TRUE );
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
        // settings of the installation an administrator makes (e.g. the predefined playbooks that are offered)
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)' );
        // grants of a member: types (JSON list, NULL = all offered types) and scope (JSON list of locations, NULL = whole configuration)
        $cols = array_column( $this->db->query( 'PRAGMA table_info(members)' )->fetchAll(), 'name' );
        if( !in_array( 'types', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE members ADD COLUMN types TEXT' );
        if( !in_array( 'scope', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE members ADD COLUMN scope TEXT' );
        // network for runs (import from a firewall / Panorama / SCM): the project switch of the owner - it works only while
        // an administrator allows network for runs (settings 'network')
        // per user (administrator, Account, Users): network for this user (when network is 'selected' users), the
        // connection test (when it is for 'selected' users)
        $cols = array_column( $this->db->query( 'PRAGMA table_info(users)' )->fetchAll(), 'name' );
        if( !in_array( 'network', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE users ADD COLUMN network INTEGER NOT NULL DEFAULT 0' );
        if( !in_array( 'conntest', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE users ADD COLUMN conntest INTEGER NOT NULL DEFAULT 0' );
        // hosts / networks the administrator allows one user (own allow list, e.g. from an approved request)
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS user_hosts (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            entry TEXT NOT NULL, created INTEGER NOT NULL, UNIQUE (user_id, entry))' );
        // requests of a user to the administrators: network to hosts, the connection test
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS access_requests (id INTEGER PRIMARY KEY, rid TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL, hosts TEXT NOT NULL, reason TEXT NOT NULL,
            state TEXT NOT NULL, created INTEGER NOT NULL, decided INTEGER, decided_by TEXT, note TEXT)' );
        $cols = array_column( $this->db->query( 'PRAGMA table_info(projects)' )->fetchAll(), 'name' );
        if( !in_array( 'network', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE projects ADD COLUMN network INTEGER NOT NULL DEFAULT 0' );
        // API keys of a user (personal: only this user uses them, in any of the user's projects); the secret encrypted
        // with the key of the installation (keys.secret in the data directory), never sent back
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS user_keys (id INTEGER PRIMARY KEY, kid TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, kind TEXT NOT NULL, target TEXT NOT NULL, label TEXT NOT NULL,
            secret TEXT NOT NULL, hint TEXT NOT NULL, created INTEGER NOT NULL, last_used INTEGER, UNIQUE (user_id, kind, target))' );
        $cols = array_column( $this->db->query( 'PRAGMA table_info(user_keys)' )->fetchAll(), 'name' );
        if( !in_array( 'port', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE user_keys ADD COLUMN port INTEGER' );
        // saved LDAP queries of a user (server, bind user, base DN, what to ask); the password: the user's key store entry
        // ldap_user<bind user> (kind ldap)
        $this->db->exec( 'CREATE TABLE IF NOT EXISTS ldap_queries (id INTEGER PRIMARY KEY, qid TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, server TEXT NOT NULL, bind_user TEXT NOT NULL,
            base_dn TEXT NOT NULL, attribute TEXT NOT NULL, mode TEXT NOT NULL, users TEXT NOT NULL, grp TEXT NOT NULL, transitive INTEGER NOT NULL,
            created INTEGER NOT NULL, updated INTEGER NOT NULL)' );
        // the changes a saved version was made of (the change list as data, JSON) - for the playbook of a version
        $cols = array_column( $this->db->query( 'PRAGMA table_info(configs)' )->fetchAll(), 'name' );
        if( !in_array( 'changes', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE configs ADD COLUMN changes TEXT' );
        // the server of a query: given, or automatic (server '') - the domain controllers of 'domain' from DNS
        $cols = array_column( $this->db->query( 'PRAGMA table_info(ldap_queries)' )->fetchAll(), 'name' );
        if( !in_array( 'domain', $cols, TRUE ) )
            $this->db->exec( "ALTER TABLE ldap_queries ADD COLUMN domain TEXT NOT NULL DEFAULT ''" );
        if( !in_array( 'ldaps', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE ldap_queries ADD COLUMN ldaps INTEGER NOT NULL DEFAULT 1' );
        // why a run failed: memory (killed / out of memory), timeout, error
        $cols = array_column( $this->db->query( 'PRAGMA table_info(jobs)' )->fetchAll(), 'name' );
        if( !in_array( 'reason', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE jobs ADD COLUMN reason TEXT' );
        // command line use an administrator has seen (shown once after the login: cliNotices)
        $cols = array_column( $this->db->query( 'PRAGMA table_info(users)' )->fetchAll(), 'name' );
        if( !in_array( 'cli_seen', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE users ADD COLUMN cli_seen INTEGER NOT NULL DEFAULT 0' );
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

    // ------------------------------------------------------------------ first administrator (a new installation)

    public function adminExists(): bool
    {
        return (bool)$this->q( 'SELECT 1 FROM users WHERE is_admin = 1 LIMIT 1' )->fetch();
    }

    /** a new installation: no administrator yet - the page offers to create the first one */
    public function firstAdminNeeded(): bool
    {
        return !$this->adminExists();
    }

    // ------------------------------------------------------------------ command line (bin/user.php, bin/token.php)

    const CLI_REFUSED = 'refused: this viewer has an administrator - users, passwords and API tokens are managed in the browser by an administrator (Account)';

    /**
     * The command line may change users, passwords, projects and tokens only while there is no administrator (the
     * first setup). Afterwards everything is done in the browser by an administrator - whoever can run commands on
     * the computer can not reset passwords or make himself an administrator. A refused try goes into the audit log and
     * is shown to the administrators after their next login.
     */
    public function cliChange( string $what, array $detail = array() ): void
    {
        if( $this->adminExists() )
        {
            $this->auditWrite( '(command line)', null, 'local', null, 'CLI', 'cli/' . $what, 403, $detail );
            throw new ViewerException( self::CLI_REFUSED, 403 );
        }
    }

    /** a change on the command line that was done (audit log; shown to the administrators after their next login) */
    public function cliDone( string $what, array $detail = array() ): void
    {
        $this->auditWrite( '(command line)', null, 'local', null, 'CLI', 'cli/' . $what, 200, $detail );
    }

    /** command line use since the administrator saw it last (refused tries and changes); afterwards marked as seen */
    public function cliNotices( array $user ): array
    {
        if( empty( $user['is_admin'] ) )
            return array();
        $rows = $this->q( "SELECT id, ts, route, status, detail FROM audit WHERE method = 'CLI' AND id > ? ORDER BY id DESC LIMIT 50",
            array( (int)( $user['cli_seen'] ?? 0 ) ) )->fetchAll();
        if( count( $rows ) === 0 )
            return array();
        $this->q( 'UPDATE users SET cli_seen = ? WHERE id = ?', array( (int)$rows[0]['id'], (int)$user['id'] ) );
        $out = array();
        foreach( array_reverse( $rows ) as $r )
            $out[] = array( 'ts' => (int)$r['ts'], 'what' => substr( $r['route'], 4 ), 'refused' => (int)$r['status'] !== 200,
                'detail' => $r['detail'] !== null ? json_decode( $r['detail'], TRUE ) : null );
        return $out;
    }

    /** an administrator gives a user a new password (made here, returned once) */
    public function userNewPassword( string $name ): string
    {
        $u = $this->userByName( $name );
        if( $u === null )
            throw new ViewerException( 'not found', 404 );
        $abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
        $pw = '';
        for( $i = 0; $i < 20; $i++ )
            $pw .= $abc[random_int( 0, strlen( $abc ) - 1 )];
        $this->userSetPassword( (int)$u['id'], $pw );
        return $pw;
    }

    /**
     * the one-time code that creating the first administrator needs (data directory: first-admin.code). Made when it
     * is asked for the first time; null when there is an administrator. Shown on the computer the viewer runs on only
     * (panosphp-viewer start / bin/user.php first-code) - whoever reaches the page first can not take it over.
     */
    public function firstAdminCode(): ?string
    {
        $file = $this->dataDir . '/first-admin.code';
        if( !$this->firstAdminNeeded() )
        {
            @unlink( $file );
            return null;
        }
        $code = trim( (string)@file_get_contents( $file ) );
        if( !preg_match( '/^[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}$/', $code ) )
        {
            $abc = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
            $code = '';
            for( $i = 0; $i < 16; $i++ )
                $code .= ( $i && $i % 4 === 0 ? '-' : '' ) . $abc[random_int( 0, strlen( $abc ) - 1 )];
            $old = umask( 0177 );
            file_put_contents( $file, $code . "\n" );
            umask( $old );
        }
        return $code;
    }

    /** create the first administrator with the one-time code; afterwards the code is gone */
    public function firstAdminCreate( $code, $name, $password, string $ip ): array
    {
        $this->q( 'DELETE FROM login_fail WHERE ts < ?', array( time() - self::LOGIN_WINDOW ) );
        if( (int)$this->q( "SELECT COUNT(*) AS c FROM login_fail WHERE name = '#first-admin'" )->fetch()['c'] >= self::LOGIN_MAX_FAILS )
            throw new ViewerException( 'too many wrong codes - try again later', 429 );
        if( !$this->firstAdminNeeded() )
            throw new ViewerException( 'there is an administrator already - log in', 409 );
        $want = (string)$this->firstAdminCode();
        $given = strtoupper( preg_replace( '/[^A-Za-z0-9]/', '', is_string( $code ) ? $code : '' ) );
        if( $want === '' || !hash_equals( str_replace( '-', '', $want ), $given ) )
        {
            $this->q( 'INSERT INTO login_fail (name, ip, ts) VALUES (?,?,?)', array( '#first-admin', $ip, time() ) );
            throw new ViewerException( 'the code is wrong - it is shown by ./panosphp-viewer start on the computer the viewer runs on', 403 );
        }
        $this->userCreate( $name, $password, TRUE );
        @unlink( $this->dataDir . '/first-admin.code' );
        $this->q( "DELETE FROM login_fail WHERE name = '#first-admin'" );
        return $this->userByName( self::checkUserName( $name ) );
    }

    // ------------------------------------------------------------------ help pages (Markdown, shown next to the login)

    /** the help pages of the viewer: docs/*.md (shipped with the viewer, no secrets) - name => title */
    public static function docsList(): array
    {
        $out = array();
        foreach( glob( dirname( __FILE__, 2 ) . '/docs/*.md' ) ?: array() as $f )
        {
            $name = basename( $f, '.md' );
            if( !preg_match( '/^[a-z0-9][a-z0-9-]{0,60}$/', $name ) )
                continue;
            $first = (string)fgets( fopen( $f, 'r' ) );
            $out[$name] = preg_match( '/^#\s+(.+)$/', trim( $first ), $m ) ? trim( $m[1] ) : $name;
        }
        uksort( $out, function( $a, $b ) { return strnatcmp( $a, $b ); } );
        return $out;
    }

    public static function docsGet( $name ): array
    {
        if( !is_string( $name ) || !preg_match( '/^[a-z0-9][a-z0-9-]{0,60}$/', $name ) || !is_file( dirname( __FILE__, 2 ) . '/docs/' . $name . '.md' ) )
            throw new ViewerException( 'not found', 404 );
        return array( 'name' => $name, 'title' => self::docsList()[$name] ?? $name, 'markdown' => (string)file_get_contents( dirname( __FILE__, 2 ) . '/docs/' . $name . '.md' ) );
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
        return array_map( function( $u ) { $u['network'] = (bool)$u['network']; $u['conntest'] = (bool)$u['conntest'];
                $u['hosts'] = $this->userHosts( array( 'id' => $u['id'] ) ); unset( $u['id'] ); return $u; },
            $this->q( 'SELECT id, name, is_admin AS admin, created, network, conntest FROM users ORDER BY name' )->fetchAll() );
    }

    /** administrator: what a user may beyond the projects - network (runs, key from a device), the connection test */
    public function userPermissions( string $name, array $in ): array
    {
        $u = $this->userByName( $name );
        if( $u === null )
            throw new ViewerException( 'not found', 404 );
        foreach( array( 'network', 'conntest' ) as $k )
            if( array_key_exists( $k, $in ) )
            {
                if( !is_bool( $in[$k] ) && !in_array( $in[$k], array( 0, 1, '0', '1' ), TRUE ) )
                    throw new ViewerException( $k . ': true or false', 400 );
                $this->q( 'UPDATE users SET ' . $k . ' = ? WHERE id = ?', array( $in[$k] ? 1 : 0, $u['id'] ) );
            }
        // the user's own hosts: the whole list (one entry per line, as the allow list)
        if( array_key_exists( 'hosts', $in ) )
        {
            $list = self::hostList( $in['hosts'], 'hosts', TRUE );
            $this->q( 'DELETE FROM user_hosts WHERE user_id = ?', array( $u['id'] ) );
            foreach( $list as $e )
                $this->q( 'INSERT INTO user_hosts (user_id, entry, created) VALUES (?, ?, ?)', array( $u['id'], $e, time() ) );
        }
        foreach( $this->userList() as $x )
            if( $x['name'] === $u['name'] )
                return $x;
        throw new ViewerException( 'not found', 404 );
    }

    /**
     * may this user use the network (runs that reach a device / tenant / LDAP, the key from a device, the connection
     * test)? null = yes. Network for 'all' users: every user; for 'selected' users: administrators and the users the
     * administrator allows (Account, Users). The lists of hosts apply in any case.
     */
    public function networkUserRefusal( array $user ): ?string
    {
        if( $this->networkGet()['users'] === 'all' )
            return null;
        $u = isset( $user['id'] ) ? $this->q( 'SELECT is_admin, network FROM users WHERE id = ?', array( $user['id'] ) )->fetch() : FALSE;
        if( $u && ( !empty( $u['is_admin'] ) || !empty( $u['network'] ) ) )
            return null;
        return 'network is not allowed for you (an administrator allows it per user: Account, Users)';
    }

    /** a list of hosts / networks (array or text, one per line / comma): checked, lower case, unique */
    private static function hostList( $v, string $what, bool $wide ): array
    {
        if( is_string( $v ) )
            $v = preg_split( '/[\r\n,]+/', $v );
        if( !is_array( $v ) )
            throw new ViewerException( $what . ': a list of hosts / networks', 400 );
        $out = array();
        foreach( $v as $e )
        {
            $e = strtolower( trim( (string)$e ) );
            if( $e === '' )
                continue;
            if( !self::networkPattern( $e ) )
                throw new ViewerException( $what . ': "' . substr( $e, 0, 80 ) . '" is no host, *.domain, IP address, network (a.b.c.d/n) or tsg:<id>', 400 );
            if( !$wide && ( $e === '*' || $e === 'tsg:*' ) )
                throw new ViewerException( $what . ': "' . $e . '" - name the hosts / networks', 400 );
            $out[] = $e;
        }
        $out = array_values( array_unique( $out ) );
        if( count( $out ) > 100 )
            throw new ViewerException( $what . ': at most 100 entries', 400 );
        return $out;
    }

    /**
     * a request of the user to the administrators: 'network' (hosts / networks the user wants to reach - devices,
     * tenants, LDAP) or 'conntest' (the connection test; optionally with hosts as well), with a reason. At most 10
     * open requests per user.
     */
    public function requestCreate( array $user, array $in ): array
    {
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not with an API token', 403 );
        $kind = $in['kind'] ?? '';
        if( !in_array( $kind, array( 'network', 'conntest' ), TRUE ) )
            throw new ViewerException( 'kind: network or conntest', 400 );
        $hosts = self::hostList( $in['hosts'] ?? array(), 'hosts', FALSE );
        if( $kind === 'network' && count( $hosts ) === 0 )
            throw new ViewerException( 'hosts: the firewalls / Panoramas / LDAP servers (name, IP address, network, *.domain, tsg:<id>) you want to reach', 400 );
        $reason = trim( (string)( $in['reason'] ?? '' ) );
        if( $reason === '' || strlen( $reason ) > 1000 || preg_match( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $reason ) )
            throw new ViewerException( 'reason: why you need it (1-1000 characters)', 400 );
        if( (int)$this->q( "SELECT COUNT(*) FROM access_requests WHERE user_id = ? AND state = 'open'", array( $user['id'] ) )->fetchColumn() >= 10 )
            throw new ViewerException( 'you have 10 open requests - wait for the administrator or withdraw one', 400 );
        $rid = bin2hex( random_bytes( 8 ) );
        $this->q( "INSERT INTO access_requests (rid, user_id, kind, hosts, reason, state, created) VALUES (?, ?, ?, ?, ?, 'open', ?)",
            array( $rid, $user['id'], $kind, json_encode( $hosts ), $reason, time() ) );
        return $this->requestGet( $rid );
    }

    private function requestGet( string $rid ): array
    {
        $r = $this->q( 'SELECT r.*, u.name AS user FROM access_requests r JOIN users u ON u.id = r.user_id WHERE r.rid = ?', array( $rid ) )->fetch();
        if( !$r )
            throw new ViewerException( 'not found', 404 );
        return array( 'rid' => $r['rid'], 'user' => $r['user'], 'kind' => $r['kind'], 'hosts' => json_decode( $r['hosts'], TRUE ) ?: array(),
            'reason' => $r['reason'], 'state' => $r['state'], 'created' => (int)$r['created'], 'decided' => $r['decided'] !== null ? (int)$r['decided'] : null,
            'decided_by' => $r['decided_by'], 'note' => $r['note'], '_uid' => (int)$r['user_id'] );
    }

    /** the requests of the user; an administrator with $all: every request (open first) */
    public function requestList( array $user, bool $all ): array
    {
        $rows = $all ? $this->q( "SELECT rid FROM access_requests ORDER BY state = 'open' DESC, created DESC LIMIT 500" )->fetchAll()
            : $this->q( 'SELECT rid FROM access_requests WHERE user_id = ? ORDER BY created DESC LIMIT 100', array( $user['id'] ) )->fetchAll();
        return array_map( function( $r ) { $x = $this->requestGet( $r['rid'] ); unset( $x['_uid'] ); return $x; }, $rows );
    }

    /** the user withdraws an open request */
    public function requestWithdraw( array $user, string $rid ): void
    {
        if( $this->q( "DELETE FROM access_requests WHERE rid = ? AND user_id = ? AND state = 'open'", array( $rid, $user['id'] ) )->rowCount() === 0 )
            throw new ViewerException( 'not found', 404 );
    }

    /**
     * administrator: approve (network: the hosts - as requested or changed by the administrator - become own entries of
     * the user; conntest: the user may use the connection test, hosts given go to the own entries as well) or reject,
     * with a note for the user
     */
    public function requestDecide( array $admin, string $rid, array $in ): array
    {
        $r = $this->requestGet( $rid );
        if( $r['state'] !== 'open' )
            throw new ViewerException( 'the request is ' . $r['state'] . ' already', 400 );
        $decision = $in['decision'] ?? '';
        if( !in_array( $decision, array( 'approve', 'reject' ), TRUE ) )
            throw new ViewerException( 'decision: approve or reject', 400 );
        $note = trim( (string)( $in['note'] ?? '' ) );
        if( strlen( $note ) > 1000 )
            throw new ViewerException( 'note: at most 1000 characters', 400 );
        if( $decision === 'approve' )
        {
            $hosts = array_key_exists( 'hosts', $in ) ? self::hostList( $in['hosts'], 'hosts', TRUE ) : $r['hosts'];
            if( $r['kind'] === 'network' && count( $hosts ) === 0 )
                throw new ViewerException( 'hosts: at least one', 400 );
            foreach( $hosts as $e )
                $this->q( 'INSERT OR IGNORE INTO user_hosts (user_id, entry, created) VALUES (?, ?, ?)', array( $r['_uid'], $e, time() ) );
            if( $r['kind'] === 'conntest' )
                $this->q( 'UPDATE users SET conntest = 1 WHERE id = ?', array( $r['_uid'] ) );
            $this->q( 'UPDATE access_requests SET hosts = ? WHERE rid = ?', array( json_encode( $hosts ), $rid ) );
        }
        $this->q( 'UPDATE access_requests SET state = ?, decided = ?, decided_by = ?, note = ? WHERE rid = ?',
            array( $decision === 'approve' ? 'approved' : 'rejected', time(), $admin['name'], $note, $rid ) );
        $x = $this->requestGet( $rid );
        unset( $x['_uid'] );
        return $x;
    }

    /** what the user may (for Account): network in general, own hosts, the connection test, open requests (administrator: of all users) */
    public function accessInfo( array $user ): array
    {
        $admin = !empty( $user['is_admin'] );
        return array( 'access' => array( 'network' => $this->networkGet()['enabled'] && $this->networkUserRefusal( $user ) === null, 'hosts' => $this->userHosts( $user ),
            'conntest' => $this->conntestRefusal( $user ) === null,
            'openRequests' => (int)( $admin ? $this->q( "SELECT COUNT(*) FROM access_requests WHERE state = 'open'" )->fetchColumn()
                : $this->q( "SELECT COUNT(*) FROM access_requests WHERE state = 'open' AND user_id = ?", array( $user['id'] ) )->fetchColumn() ) ) );
    }

    /** the hosts / networks the administrator allows this user (own entries; e.g. from an approved request) */
    public function userHosts( array $user ): array
    {
        if( !isset( $user['id'] ) )
            return array();
        return array_column( $this->q( 'SELECT entry FROM user_hosts WHERE user_id = ? ORDER BY entry', array( $user['id'] ) )->fetchAll(), 'entry' );
    }

    /** may this user use the connection test? null = yes (admins always; all users / selected users by the administrator) */
    public function conntestRefusal( array $user ): ?string
    {
        if( isset( $user['token'] ) )
            return 'not with an API token';
        $mode = $this->networkGet()['conntest'];
        $u = isset( $user['id'] ) ? $this->q( 'SELECT is_admin, conntest FROM users WHERE id = ?', array( $user['id'] ) )->fetch() : FALSE;
        if( $u && ( !empty( $u['is_admin'] ) || $mode === 'all' || !empty( $u['conntest'] ) ) )
            return null;
        return 'the connection test is not allowed for you - request it: Account, Requests';
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
            WHERE ( p.owner_id = :u OR m.user_id = :u ) AND p.pid != :s ORDER BY p.name', array( ':u' => $user['id'], ':s' => self::SYSTEM_PID ) )->fetchAll();
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
        // the project of the installation-wide runs: every administrator (never with an API token)
        if( $p && $p['pid'] === self::SYSTEM_PID )
            $p = !empty( $user['is_admin'] ) && !isset( $user['token'] ) ? $p : FALSE;
        if( $p && $p['pid'] === self::SYSTEM_PID )
            $role = 'owner';
        elseif( $p )
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
            'types' => $p['types'] ?? null, 'scope' => $p['scope'] ?? null, 'network' => !empty( $p['network'] ) );
    }

    // ------------------------------------------------------------------ network for runs, API keys of a user, import

    /**
     * the kinds of entries of the pan-os-php key store (.panconfkeystore) a user can keep: devices / tenants an import can
     * reach, and named entries for other pan-os-php types (stored; used by the runs that need them - see
     * todo/config-viewer-device-access.md). 'other': any further entry name, kept as it is.
     */
    const KEY_KINDS = array( 'panos' => 'PAN-OS firewall / Panorama (XML API key)', 'scm' => 'SCM / SASE tenant (client id + secret)',
        'egressip' => 'Prisma Access egress-IP API key (tenant)', 'ldap' => 'LDAP account (bind user + password)',
        'named' => 'named entry (BPA / licence / MaxMind key, GCP MySQL password, old ldap-password)',
        'other' => 'other entry (name as in .panconfkeystore)' );
    /** named entries pan-os-php knows (PanAPIConnector::findOrCreateConnectorFromHost) */
    const KEY_NAMED = array( 'ldap-password', 'bpa-apikey', 'license-apikey', 'maxmind-licensekey', 'gcp-mysql-password' );

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

    // ------------------------------------------------------------------ LDAP queries of a user (type=ldap-query, user-check-ldap)

    const LDAP_MODES = array( 'validation' => 'do the accounts still exist?', 'user-groups' => 'groups of a user', 'common-groups' => 'groups all users are in',
        'group-members' => 'members of a group' );

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

    // ------------------------------------------------------------------ jobs (CLI-like runs with result files)

    /**
     * Job types: the pan-os-php arguments are built here from checked values only - never an argument, file name or
     * path of the request. 'in=' is the version file, the working directory is the folder of the job.
     */
    const JOB_TYPES = array( 'stats', 'playbook', 'diff', 'import', 'appid', 'geoip', 'ldap', 'ldap-users', 'ldap-discover',
        'object-merger', 'rule-merger', 'merger-possible-report', 'support-file', 'egress-ip' );
    /** the mergers of the Merger tab: their arguments (checked here, the merger checks their combination again) */
    const MERGER_OBJECTTYPES = array( 'tag', 'address', 'service', 'edl', 'region', 'application-custom', 'application-filter', 'addressgroup',
        'servicegroup', 'application-group', 'custom-url-category', 'schedule', 'log-profile', 'decryption-profile', 'hip-object', 'hip-profile',
        'securityprofile', 'securityprofilegroup' );
    const MERGER_DUPALGORITHMS = array( 'SameAddress', 'Identical', 'WhereUsed', 'SameDstSrcPorts', 'SamePorts', 'SameMembers', 'SameIP4Mapping',
        'SamePortMapping', 'SameColor', 'SameName', 'SameValue' );
    const RULEMERGER_METHODS = array( 'matchFromToSrcDstApp', 'matchFromToSrcDstSvc', 'matchFromToSrcSvcApp', 'matchFromToDstSvcApp',
        'matchFromSrcDstSvcApp', 'matchToSrcDstSvcApp', 'matchToDstSvcApp', 'matchFromSrcSvcApp', 'identical' );
    const RULEMERGER_ADDITIONAL = array( 'tag', 'secprof', 'user', 'urlcategory', 'target', 'logsetting', 'schedule' );
    /** where type=maxmind-update downloads from (must be on the allow list of the administrator) */
    const MAXMIND_HOST = 'download.maxmind.com';
    /** the project of the installation-wide runs (App-ID / MaxMind of the administrator): not listed, only administrators */
    const SYSTEM_PID = '00000000000000000000000000000000';
    const JOB_QUEUE_MAX = 20;          // queued + running jobs per project
    const JOB_FILE_MAX = 104857600;    // largest result file that can be downloaded

    private function jobDir( array $project, string $jid ): string
    {
        if( !preg_match( '/^[0-9a-f]{32}$/', $jid ) )
            throw new ViewerException( 'not found', 404 );
        return $this->projectDir( $project['pid'] ) . '/jobs/' . $jid;
    }

    /** POST …/configs/<cid>/<type>/runs - queues a run; bin/jobs.php executes it */
    // ------------------------------------------------------------------ licence (todo/config-viewer-license.md)

    private $licenceCache = FALSE;

    /** the installed licence (data directory: license.txt), or null when there is none or it is not valid */
    public function licence(): ?PluginLicense
    {
        if( $this->licenceCache === FALSE )
        {
            $this->licenceCache = null;
            $text = @file_get_contents( $this->dataDir . '/license.txt' );
            if( is_string( $text ) && $text !== '' )
                try
                {
                    $this->licenceCache = PluginLicense::parse( $text );
                }
                catch( Exception $e )
                {
                    $this->licenceError = $e->getMessage();
                }
        }
        return $this->licenceCache;
    }

    private $licenceError = null;
    private $licenceStamp = null;

    /**
     * long running processes (job runner): load the plug-ins again when the licence or a plug-in was installed,
     * changed or removed since they were loaded
     */
    public function refreshPlugins(): void
    {
        clearstatcache();
        $stamp = @filemtime( $this->dataDir . '/license.txt' ) . ':' . @filesize( $this->dataDir . '/license.txt' );
        // a plug-in added, changed or removed (e.g. panosphp-viewer plugin add)
        foreach( array_filter( array( dirname( __FILE__, 2 ) . '/plugins', (string)getenv( 'PANOSPHP_VIEWER_PLUGINS' ) ) ) as $d )
            foreach( array_merge( glob( rtrim( $d, '/' ) . '/*.ppp' ) ?: array(), glob( rtrim( $d, '/' ) . '/*/plugin.php' ) ?: array() ) as $f )
                $stamp .= '|' . $f . ':' . @filemtime( $f );
        if( $this->licenceStamp === null )
            $this->licenceStamp = $stamp;
        if( $stamp === $this->licenceStamp )
            return;
        $this->licenceStamp = $stamp;
        $this->licenceCache = FALSE;
        $this->licenceError = null;
        $this->plugins = ViewerPlugins::load( dirname( __FILE__, 2 ), $this->licence(), function( $f ) { return $this->featureOn( $f ); } );
    }

    /**
     * "now" for the licence: the newest time the viewer has seen (data directory: license-clock). A clock that is set
     * back more than an hour before it is noted - licensed features stop until the clock is right again.
     * @return int|null null = the clock was set back
     */
    private function licenceNow(): ?int
    {
        $file = $this->dataDir . '/license-clock';
        $now = time();
        $last = (int)@file_get_contents( $file );
        if( $last > $now + 3600 )
            return null;
        if( $now - $last > 600 )
            @file_put_contents( $file, (string)$now, LOCK_EX );
        return max( $now, $last );
    }

    /**
     * is a licensed feature switched on ? The one place for the licence check. null = basic (always on). Plug-ins in
     * folders (source) are not checked here - only encrypted packages need the licence (ViewerPlugins).
     */
    public function featureOn( ?string $feature ): bool
    {
        if( $feature === null )
            return TRUE;
        $l = $this->licence();
        $now = $this->licenceNow();
        return $l !== null && $now !== null && $l->hasFeature( $feature, $now );
    }

    /** for the page (admins): the licence without its keys, its state, and what it unlocks */
    public function licenceInfo(): array
    {
        $l = $this->licence();
        $now = $this->licenceNow();
        return array( 'licence' => $l !== null ? $l->summary( $now ?? time() ) : null, 'error' => $this->licenceError, 'clock' => $now === null ? 'set back' : 'ok',
            'trusted_keys' => count( PluginLicense::trustedKeys() ) );
    }

    /** install a licence (admin): it must be valid for this installation, then it replaces the one before */
    public function licenceSet( $text ): array
    {
        if( !is_string( $text ) || strlen( $text ) > 200000 )
            throw new ViewerException( 'licence: text expected', 400 );
        try
        {
            $l = PluginLicense::parse( $text );
        }
        catch( Exception $e )
        {
            throw new ViewerException( $e->getMessage(), 400 );
        }
        if( !$l->usable() )
            throw new ViewerException( 'licence: ended on ' . $l->data['valid_until'], 400 );
        $tmp = $this->dataDir . '/license.txt.tmp';
        file_put_contents( $tmp, $l->text . "\n" );
        @chmod( $tmp, 0600 );
        rename( $tmp, $this->dataDir . '/license.txt' );
        $this->licenceCache = FALSE;
        return $this->licenceInfo();
    }

    public function licenceDelete(): void
    {
        @unlink( $this->dataDir . '/license.txt' );
        $this->licenceCache = FALSE;
    }

    /** run types of the plug-ins that are switched on: name => description */
    public function pluginRuns(): array
    {
        return $this->plugins->runs();
    }

    private function pluginKinds(): array
    {
        return $this->plugins->kinds();
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
            // a package is loaded only when it is licensed; a plug-in in a folder is the source (development / basic)
            $on = TRUE;
            $out['plugins'][] = array( 'name' => $p['name'], 'title' => $p['title'], 'version' => $p['version'], 'feature' => $p['feature'], 'on' => $on,
                'form' => isset( $p['package'] ) ? 'package' : 'folder' );
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
        foreach( $this->plugins->locked as $name => $l )
            $out['plugins'][] = array( 'name' => $name, 'title' => $name, 'version' => $l['version'], 'feature' => $l['feature'], 'on' => FALSE, 'form' => 'package',
                'why' => $admin ? $l['why'] : null );
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
        // a run type of a plug-in with 'input' => 'none' has no version (its input is a project file); an import neither
        $noVersion = ( $plugin !== null && $plugin['input'] === 'none' ) || in_array( $type, array( 'import', 'appid', 'geoip', 'ldap', 'ldap-discover', 'egress-ip' ), TRUE );
        // the project of the installation-wide runs has only App-ID / MaxMind runs; MaxMind is installation-wide only
        if( ( $p['pid'] === self::SYSTEM_PID && !in_array( $type, array( 'appid', 'geoip' ), TRUE ) ) || ( $type === 'geoip' && $p['pid'] !== self::SYSTEM_PID ) )
            throw new ViewerException( 'not found', 404 );
        if( $noVersion !== ( $cid === null ) )
            throw new ViewerException( 'not found', 404 );
        $c = $noVersion ? array( 'id' => 0 ) : $this->configGet( $p, $cid );

        $args = array();
        if( $type === 'import' )
        {
            // the configuration of a firewall / Panorama (XML API) or an SCM tenant, read only, with an API key of this
            // user; becomes a new version. Needs: network for runs (administrator), network of this project (owner),
            // the target allowed by the lists of the administrator, write permission.
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)( $in['kid'] ?? '' ), $user['id'] ) )->fetch();
            if( !$k || !in_array( $k['kind'], array( 'panos', 'scm' ), TRUE ) )
                throw new ViewerException( 'kid: one of your API keys of a firewall / Panorama or an SCM tenant (Account, My API keys)', 400 );
            // the order of the reasons: installation, project, target
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( $k['kind'], $k['target'], $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->networkRefusal( $k['kind'], $k['target'], $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            $source = $in['source'] ?? 'candidate';
            if( !in_array( $source, array( 'candidate', 'running' ), TRUE ) || ( $k['kind'] === 'scm' && $source !== 'candidate' ) )
                throw new ViewerException( 'source: candidate or running (PAN-OS)', 400 );
            // only references here - the runner builds the steps and the key store of the run when it starts
            $args = array( 'x-import-key=' . $k['kid'], 'x-import-target=' . $k['kind'] . ':' . $k['target'], 'x-import-source=' . $source );
        }
        if( $type === 'egress-ip' )
        {
            // SCM tab: the egress IPs of a Prisma Access tenant, live with the egress-IP API key of this user (key store
            // kind egress IP, target = TSG). Network as for an import of the tenant (tsg:<TSG> on the allow list).
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)( $in['kid'] ?? '' ), $user['id'] ) )->fetch();
            if( !$k || $k['kind'] !== 'egressip' )
                throw new ViewerException( 'kid: one of your egress-IP API keys (Account, My API keys, kind egress IP)', 400 );
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( 'scm', $k['target'], $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->networkRefusal( 'scm', $k['target'], $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            self::egressLib();
            try
            {
                $req = SCMEgressIP::request( null, array( 'servicetype' => (string)( $in['servicetype'] ?? 'all' ), 'addrtype' => (string)( $in['addrtype'] ?? 'all' ),
                    'location' => (string)( $in['location'] ?? 'all' ) ) );
            }
            catch( Exception $e )
            {
                throw new ViewerException( $e->getMessage(), 400 );
            }
            $env = (string)( $in['env'] ?? 'prod' );
            if( !in_array( $env, array( 'prod', 'prod6' ), TRUE ) )
                throw new ViewerException( 'env: prod or prod6', 400 );
            $args = array( 'x-egress-key=' . $k['kid'], 'x-egress-target=egressip:' . $k['target'], 'servicetype=' . $req['serviceType'],
                'addrtype=' . $req['addrType'], 'location=' . $req['location'], 'env=' . $env );
        }
        if( $type === 'ldap-discover' )
        {
            // help for a first LDAP query: the domain controllers of an AD domain (DNS SRV) and the base DN (RootDSE of
            // the first that answers - anonymous, no password, no key). Network as for an import; the allow list must
            // cover the hosts of the domain (e.g. *.example.local) - only servers in the domain are asked.
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $domain = strtolower( trim( (string)( $in['domain'] ?? '' ) ) );
            if( strlen( $domain ) > 253 || !preg_match( '/^([a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/', $domain ) )
                throw new ViewerException( 'domain: the DNS name of the AD domain, e.g. example.local', 400 );
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( 'panos', 'dc.' . $domain, $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( $this->networkRefusal( 'panos', $domain, $user ) !== null && ( $why = $this->networkRefusal( 'panos', 'dc.' . $domain, $user ) ) !== null )
                throw new ViewerException( $why . ' - the administrator puts *.' . $domain . ' on the allow list', 403 );
            $args = array( 'x-ldap-discover-target=' . $domain, 'mode=discover', 'domain=' . $domain, 'out=%JOB%/ldap.json' );
            if( isset( $in['ldaps'] ) && ( $in['ldaps'] === FALSE || $in['ldaps'] === 'no' || $in['ldaps'] === 'false' ) )
                $args[] = 'ldaps=no';
        }
        if( $type === 'ldap' || $type === 'ldap-users' )
        {
            // an LDAP query of the user (type=ldap-query) or the users of the security rules of this version
            // (type=rule actions=user-check-ldap: show the ones that do not exist any more, or remove them - a result
            // configuration). The password: the user's key store entry ldap_user<bind user>. Network as for an import.
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $qr = $this->q( 'SELECT * FROM ldap_queries WHERE qid = ? AND user_id = ?', array( (string)( $in['qid'] ?? '' ), $user['id'] ) )->fetch();
            if( !$qr )
                throw new ViewerException( 'qid: one of your saved LDAP queries', 400 );
            $k = $this->q( "SELECT * FROM user_keys WHERE user_id = ? AND kind = 'ldap' AND target = ?", array( $user['id'], strtolower( $qr['bind_user'] ) ) )->fetch();
            if( !$k )
                throw new ViewerException( 'no LDAP account ' . $qr['bind_user'] . ' under Account, My API keys (kind LDAP account: bind user + password)', 400 );
            $q = self::ldapQueryCheck( array( 'name' => $qr['name'], 'server' => $qr['server'], 'domain' => $qr['domain'] ?? '', 'ldaps' => (int)( $qr['ldaps'] ?? 1 ), 'bind_user' => $qr['bind_user'], 'base_dn' => $qr['base_dn'],
                'attribute' => $qr['attribute'], 'mode' => $type === 'ldap' ? $qr['mode'] : 'validation', 'users' => $qr['users'], 'group' => $qr['grp'], 'transitive' => $qr['transitive'] ) );
            // automatic server: the target is the domain (auto:<domain>) - the allow list must cover its hosts
            $target = $q['server'] === '' ? 'auto:' . $q['domain'] : $q['host'];
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->ldapRefusal( $target, $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->ldapRefusal( $target, $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            $args = array( 'x-' . $type . '-key=' . $k['kid'], 'x-' . $type . '-target=' . $target );
            if( $type === 'ldap' )
            {
                if( $q['mode'] === 'validation' && $q['users'] === '' )
                    throw new ViewerException( 'the query has no users to check', 400 );
                array_push( $args, 'mode=' . $q['mode'], 'ldapServer=' . ( $q['server'] === '' ? 'auto' : $q['server'] ), 'ldapUser=' . $q['bind_user'], 'dn=' . $q['base_dn'], 'filtercriteria=' . $q['attribute'] );
                if( $q['server'] === '' )
                {
                    $args[] = 'domain=' . $q['domain'];
                    if( !$q['ldaps'] )
                        $args[] = 'ldaps=no';
                }
                if( $q['users'] !== '' )
                    $args[] = 'users=' . $q['users'];
                if( $q['grp'] !== '' )
                    $args[] = 'group=' . $q['grp'];
                if( $q['transitive'] )
                    $args[] = 'transitive=yes';
                array_push( $args, 'out=%JOB%/ldap.json', 'csv=%JOB%/ldap.csv' );
            }
            else
            {
                $remove = ( $in['action'] ?? 'show' ) === 'remove';
                // the arguments of the action (separated by ',', no ':' / '/'): show|remove, bind user, server as
                // ldaps%host[%port], base DN (';' instead of ','), attribute, existentUser
                if( preg_match( '#[:/]#', $q['bind_user'] . $q['base_dn'] ) )
                    throw new ViewerException( 'bind user and base DN: no ":" or "/" for the check of the rules', 400 );
                if( $q['server'] === '' )
                    // automatic: auto%<domain> (LDAPS) / auto-ldap%<domain>
                    $server = ( $q['ldaps'] ? 'auto' : 'auto-ldap' ) . '%' . $q['domain'];
                else
                {
                    preg_match( '#^(ldaps?)://([^:]+)(?::([0-9]+))?$#', $q['server'], $s );
                    $server = $s[1] . '%' . $s[2] . ( isset( $s[3] ) ? '%' . $s[3] : '' );
                }
                $args[] = 'location=any';
                $args[] = 'actions=user-check-ldap:' . ( $remove ? 'remove' : 'show' ) . ',' . $q['bind_user'] . ',' . $server . ',' . str_replace( ',', ';', $q['base_dn'] ) . ',' . $q['attribute'] . ',false';
                if( $remove )
                    $args[] = 'out=%JOB%/out.xml';
            }
        }
        if( $type === 'appid' || $type === 'geoip' )
        {
            // App-ID database from a firewall / Panorama (type=download-predefined, read only): for the installation
            // (administrator, project of the installation) or for one project (write); MaxMind GeoLite2 (installation):
            // download with the maxmind-licensekey of the administrator, or an uploaded zip (geoipUpload)
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $central = $p['pid'] === self::SYSTEM_PID;
            if( !$central )
                $this->projectGet( $user, $pid, 'write' );
            $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)( $in['kid'] ?? '' ), $user['id'] ) )->fetch();
            $want = $type === 'appid' ? 'panos' : 'named';
            if( !$k || $k['kind'] !== $want || ( $type === 'geoip' && $k['target'] !== 'maxmind-licensekey' ) )
                throw new ViewerException( 'kid: ' . ( $type === 'appid' ? 'one of your API keys of a firewall / Panorama' : 'your maxmind-licensekey' ) . ' (Account, My API keys)', 400 );
            $host = $type === 'appid' ? $k['target'] : self::MAXMIND_HOST;
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( 'panos', $host, $user ), 403 );
            if( !$central && empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->networkRefusal( 'panos', $host, $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            $args = array( 'x-' . $type . '-key=' . $k['kid'], 'x-' . $type . '-target=' . $host );
        }
        if( in_array( $type, array( 'object-merger', 'rule-merger', 'merger-possible-report' ), TRUE ) )
            $args = $this->mergerArgs( $user, $pid, $type, $in );
        if( $type === 'stats' )
        {
            $location = $in['location'] ?? 'any';
            if( !is_string( $location ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,63}$/', $location ) )
                throw new ViewerException( 'location: letters, digits, space and . _ - only', 400 );
            $args = array( 'location=' . $location, 'actions=display-bpa', 'json-to-folder', 'debugapi' );
        }
        if( $type === 'diff' )
        {
            // two versions of the project: this one (file1, the original) and 'other' (file2, the newer one); no in= -
            // with in= type=diff compares inside one file. Set commands from file1 to file2 on request.
            $other = $this->configGet( $p, $in['other'] ?? null );
            if( (int)$other['id'] === (int)$c['id'] )
                throw new ViewerException( 'diff: choose two different versions', 400 );
            $args = array( 'file1=%PROJECT%/' . $c['file'], 'file2=%PROJECT%/' . $other['file'] );
            if( !empty( $in['setcommands'] ) )
                $args[] = 'outputformatset=set-commands.txt';
            if( !empty( $in['noruleordercheck'] ) )
                $args[] = 'noruleordercheck';
            // filter: an XPath of the configuration (never a file - type=diff reads a filter that is a file name)
            $xf = $in['xpath'] ?? '';
            if( $xf !== '' && $xf !== null )
            {
                if( !is_string( $xf ) || strlen( $xf ) > 2000 || preg_match( '/[\x00-\x1F\x7F]|\.\./', $xf )
                    || !preg_match( '#^/(config|policy|template|template-stack|cloud_services|device-group)(/|\[|$)#', $xf ) )
                    throw new ViewerException( 'diff: xpath - an XPath of the configuration, e.g. /config/devices/entry[@name=\'localhost.localdomain\']/device-group', 400 );
                $args[] = 'filter=' . $xf;
            }
        }
        if( $type === 'playbook' )
        {
            // a playbook file of the project or a predefined one (turned on by an administrator), checked again now
            // (PLAYBOOK_* rules); the stage files, the set commands and the result configuration stay in the folder of the run
            $predefined = $in['predefined'] ?? null;
            if( $predefined !== null && $predefined !== '' )
            {
                if( isset( $in['playbook'] ) && $in['playbook'] !== '' )
                    throw new ViewerException( 'playbook or predefined - not both', 400 );
                if( !self::playbookName( $predefined ) || !in_array( $predefined, array_column( $this->playbooksPredefined(), 'name' ), TRUE ) )
                    throw new ViewerException( 'predefined playbook not offered here (an administrator turns them on)', 400 );
                $this->playbookCheck( json_decode( (string)file_get_contents( $this->playbookDir() . '/' . $predefined ), TRUE ) );
                $json = 'json=$$playbook$$/' . $predefined;
            }
            else
            {
                $pb = $this->fileGet( $p, $in['playbook'] ?? null, 'playbook' );
                $this->playbookCheck( json_decode( (string)file_get_contents( $pb['path'] ), TRUE ) );
                $json = 'json=%FILES%/' . $pb['file'];
            }
            $args = array_merge( array( $json, 'out=%JOB%/out.xml', 'stagename=stage/step-', 'outputformatset=set-commands.txt' ), self::playbookOptions( $in ) );
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
        // a support file: what goes in is put next to the run now (hidden folder .support of the run)
        if( $type === 'support-file' )
            $args = $this->supportStage( $user, $p, $c, $jid, $in );
        $this->q( 'INSERT INTO jobs (jid, project_id, config_id, user_id, type, args, state, created) VALUES (?,?,?,?,?,?,?,?)',
            array( $jid, $p['id'], $c['id'], $user['id'], $type, json_encode( $args ), 'queued', time() ) );
        return $this->jobGet( $user, $pid, $jid );
    }

    /**
     * a support file (todo/support-file.md): pan-os-php type=support-file on the version, with - in the hidden folder
     * .support of the run - the files of the viewer for it: the case (a run of the project: its settings, report,
     * result, run.log), project and versions, the last runs, the audit of the project, the browser errors the page
     * collected, the environment of the viewer. Never in it: API keys, the key store, passwords, sessions, licence keys,
     * other projects. Options: names (objects for the excerpt), rules, full (the whole configuration), anonymize (the
     * mapping is a file of the run - for the customer only, never in the support file), note.
     */
    private function supportStage( array $user, array $p, array $c, string $jid, array $in ): array
    {
        $this->projectGet( $user, $p['pid'], 'write' );
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        if( !class_exists( 'SupportFile' ) )
            require_once $this->repoDir . '/lib/misc-classes/SupportFile.php';
        try
        {
            SupportFile::currentKey();
        }
        catch( Exception $e )
        {
            throw new ViewerException( $e->getMessage(), 400 );
        }
        $stage = $this->jobDir( $p, $jid ) . '/.support';
        if( !is_dir( $stage . '/extra' ) && !@mkdir( $stage . '/extra', 0700, TRUE ) )
            throw new ViewerException( 'the folder of the run can not be created', 500 );
        $put = function( string $name, $data ) use ( $stage ) {
            file_put_contents( $stage . '/extra/' . $name, is_string( $data ) ? $data : json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );
        };
        $args = array( 'out=%JOB%/support.tsf', 'extra=%JOB%/.support/extra' );
        // the case: a run of this project on this version
        if( isset( $in['run'] ) && $in['run'] !== '' && $in['run'] !== null )
        {
            $r = $this->jobRow( $p, $in['run'] );
            if( (int)$r['config_id'] !== (int)$c['id'] )
                throw new ViewerException( 'run: a run on this version', 400 );
            $rdir = $this->jobDir( $p, $r['jid'] );
            $put( 'run.json', array( 'jid' => $r['jid'], 'type' => $r['type'], 'args' => array_values( array_filter( (array)json_decode( $r['args'], TRUE ), function( $a ) {
                    return is_string( $a ) && strpos( $a, 'x-' ) !== 0; } ) ), 'state' => $r['state'], 'error' => $r['error'], 'created' => (int)$r['created'],
                'started' => $r['started'] !== null ? (int)$r['started'] : null, 'finished' => $r['finished'] !== null ? (int)$r['finished'] : null ) );
            foreach( glob( $rdir . '/run*.log' ) ?: array() as $f )
                if( is_file( $f ) && !is_link( $f ) && filesize( $f ) < 50000000 )
                    $put( basename( $f ), $this->hidePaths( (string)file_get_contents( $f ) ) );
            foreach( array( 'merger.json' => 'report', 'out.xml' => 'result' ) as $f => $arg )
                if( is_file( $rdir . '/' . $f ) && !is_link( $rdir . '/' . $f ) && copy( $rdir . '/' . $f, $stage . '/' . $f ) )
                    $args[] = $arg . '=%JOB%/.support/' . $f;
        }
        // project, versions, last runs, audit of the project - without the names of other users
        // anonymised: no names of the project / the versions (often the name of the customer)
        $anonymous = !empty( $in['anonymize'] ) && $in['anonymize'] !== 'false';
        $vn = 0;
        $put( 'project.json', array( 'name' => $anonymous ? 'project' : $p['name'], 'pid' => $p['pid'], 'created' => (int)( $p['created'] ?? 0 ),
            'versions' => array_map( function( $v ) use ( $anonymous, &$vn ) { $vn++; return array( 'name' => $anonymous ? 'version-' . $vn : $v['name'], 'size' => (int)( $v['size'] ?? 0 ),
                    'note' => $anonymous ? '' : ( $v['note'] ?? '' ), 'created' => (int)( $v['created'] ?? 0 ), 'cid' => $v['cid'] ); },
                $this->q( 'SELECT * FROM configs WHERE project_id = ? ORDER BY id', array( $p['id'] ) )->fetchAll() ),
            'version' => array( 'name' => $anonymous ? '' : ( $c['name'] ?? '' ), 'cid' => $c['cid'] ?? '' ) ) );
        $put( 'runs.json', array_map( function( $j ) { return array( 'jid' => $j['jid'], 'type' => $j['type'], 'state' => $j['state'], 'error' => $j['error'],
                'created' => (int)$j['created'], 'started' => $j['started'] !== null ? (int)$j['started'] : null, 'finished' => $j['finished'] !== null ? (int)$j['finished'] : null,
                'args' => array_values( array_filter( (array)json_decode( $j['args'], TRUE ), function( $a ) { return is_string( $a ) && strpos( $a, 'x-' ) !== 0; } ) ) ); },
            $this->q( 'SELECT * FROM jobs WHERE project_id = ? ORDER BY id DESC LIMIT 50', array( $p['id'] ) )->fetchAll() ) );
        $put( 'audit.json', array_map( function( $a ) { return array( 'ts' => (int)$a['ts'], 'method' => $a['method'], 'route' => $a['route'], 'status' => (int)$a['status'],
                'detail' => $a['detail'] !== null ? json_decode( $a['detail'], TRUE ) : null ); },
            $this->q( 'SELECT ts, method, route, status, detail FROM audit WHERE pid = ? ORDER BY id DESC LIMIT 300', array( $p['pid'] ) )->fetchAll() ) );
        // the viewer: version, settings (no host lists), licence (summary), the browser of the user
        $net = $this->networkGet();
        $browser = array_slice( array_values( array_filter( (array)( $in['browser'] ?? array() ), 'is_array' ) ), 0, 200 );
        $put( 'viewer.json', array( 'git' => trim( (string)@shell_exec( 'git -C ' . escapeshellarg( $this->repoDir ) . ' log -1 --format=%H%x20%cs 2>/dev/null' ) ) ?: null,
            'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'container' => getenv( 'PANOSPHP_VIEWER_CONTAINER' ) ?: null,
            'network' => array( 'enabled' => $net['enabled'], 'users' => $net['users'], 'conntest' => $net['conntest'], 'allow' => count( $net['allow'] ), 'deny' => count( $net['deny'] ) ),
            'userAgent' => substr( (string)( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 300 ) ) );
        if( $browser )
            $put( 'browser.json', array_map( function( $b ) { return array_map( function( $v ) { return is_scalar( $v ) ? substr( (string)$v, 0, 2000 ) : null; }, array_slice( $b, 0, 10, TRUE ) ); }, $browser ) );
        // options
        $names = trim( (string)( $in['names'] ?? '' ) );
        if( $names !== '' )
        {
            if( strlen( $names ) > 20000 || preg_match( '/[\x00-\x1f]/', $names ) )
                throw new ViewerException( 'names: object names, comma separated', 400 );
            $args[] = 'names=' . $names;
        }
        if( isset( $in['rules'] ) && ( $in['rules'] === FALSE || $in['rules'] === 'false' ) )
            $args[] = 'rules=no';
        if( !empty( $in['full'] ) && $in['full'] !== 'false' )
            $args[] = 'full';
        if( !empty( $in['anonymize'] ) && $in['anonymize'] !== 'false' )
        {
            array_push( $args, 'anonymize', 'mapping=%JOB%/mapping-SENSITIVE.json' );
            if( ( $in['ip'] ?? '' ) === 'keep-private' )
                $args[] = 'ip=keep-private';
        }
        $note = trim( (string)( $in['note'] ?? '' ) );
        if( $note !== '' )
            $args[] = 'note=' . substr( preg_replace( '/[\x00-\x1f]+/', ' ', $note ), 0, 4000 );
        return $args;
    }

    /**
     * the arguments of a merger run (Merger tab): object-merger / rule-merger on a copy of the version - the result
     * configuration out.xml (Result as new version), the report as exportJSON (merger.json: the tables of the page) and
     * exportCSV (merger.html, skipped-merger.html: download); merger-possible-report only reports (read). Every value
     * from a fixed list or checked; filters are pan-os-php filters (one argument each, no shell).
     */
    private function mergerArgs( array $user, $pid, string $type, array $in ): array
    {
        if( $type !== 'merger-possible-report' )
            $this->projectGet( $user, $pid, 'write' );
        $bool = function( $k ) use ( $in ) { $v = $in[$k] ?? FALSE; return $v === TRUE || $v === 'yes' || $v === 'true' || $v === 1 || $v === '1'; };
        $location = $in['location'] ?? 'any';
        if( $location === '' || $location === null )
            $location = 'any';
        if( !is_string( $location ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,63}(,[A-Za-z0-9 _.\-]{1,63}){0,49}$/', $location ) )
            throw new ViewerException( 'location: any, or location names (, separated) with letters, digits, space and . _ -', 400 );
        $filter = function( $k ) use ( $in ) {
            $v = $in[$k] ?? '';
            if( $v === '' || $v === null )
                return null;
            if( !is_string( $v ) || strlen( $v ) > 2000 || preg_match( '/[\x00-\x1F\x7F]/', $v ) || !preg_match( '/^[!(]/', trim( $v ) ) )
                throw new ViewerException( $k . ': a pan-os-php filter, e.g. (name regex /^H-/)', 400 );
            return trim( $v );
        };
        $types = function( array $allowed ) use ( $in ) {
            $v = $in['objecttype'] ?? 'any';
            $list = is_array( $v ) ? $v : explode( ',', (string)$v );
            $list = array_values( array_unique( array_filter( array_map( 'trim', $list ), 'strlen' ) ) );
            if( count( $list ) === 0 || in_array( 'any', $list, TRUE ) )
                return 'any';
            foreach( $list as $t )
                if( !in_array( $t, $allowed, TRUE ) && !( $allowed === array() && preg_match( '/^[a-z0-9-]{1,60}$/', $t ) ) )
                    throw new ViewerException( 'objecttype: any or ' . implode( ', ', $allowed ), 400 );
            return implode( ',', $list );
        };
        $report = array( 'exportjson=merger.json', 'exportcsv=merger.html' );
        if( $type === 'merger-possible-report' )
        {
            // the report types of pan-os-php (address, service, …, securityprofile-<type>): checked by the report
            // over all locations (the report has no location choice)
            $args = array( 'objecttype=' . $types( array() ) );
            if( $bool( 'mergecheck' ) )
                $args[] = 'mergecheck';
            return array_merge( $args, $report );
        }
        $args = array( 'location=' . $location, 'out=%JOB%/out.xml' );
        if( $type === 'object-merger' )
        {
            $args[] = 'objecttype=' . $types( self::MERGER_OBJECTTYPES );
            $dup = $in['dupalgorithm'] ?? '';
            if( $dup !== '' && $dup !== null )
            {
                if( !in_array( $dup, self::MERGER_DUPALGORITHMS, TRUE ) )
                    throw new ViewerException( 'DupAlgorithm: ' . implode( ', ', self::MERGER_DUPALGORITHMS ), 400 );
                $args[] = 'DupAlgorithm=' . $dup;
            }
            $limit = $in['mergecountlimit'] ?? '';
            if( $limit !== '' && $limit !== null )
            {
                if( !preg_match( '/^[0-9]{1,6}$/', (string)$limit ) )
                    throw new ViewerException( 'mergecountlimit: a number', 400 );
                $args[] = 'mergecountlimit=' . (int)$limit;
            }
            foreach( array( 'pickfilter' => 'pickFilter', 'excludefilter' => 'excludeFilter' ) as $k => $name )
                if( ( $f = $filter( $k ) ) !== null )
                    $args[] = $name . '=' . $f;
            if( $bool( 'allowmergingwithupperlevel' ) )
                $args[] = 'allowMergingWithUpperLevel';
            return array_merge( $args, $report );
        }
        // rule-merger
        $method = $in['method'] ?? 'matchFromToSrcDstApp';
        if( !in_array( $method, self::RULEMERGER_METHODS, TRUE ) )
            throw new ViewerException( 'method: ' . implode( ', ', self::RULEMERGER_METHODS ), 400 );
        $args[] = 'method=' . $method;
        $rb = $in['rulebase'] ?? 'pre';
        if( !in_array( $rb, array( 'pre', 'post' ), TRUE ) )
            throw new ViewerException( 'rulebase: pre or post (Panorama)', 400 );
        $args[] = $rb === 'post' ? 'panoramaPostRules' : 'panoramaPreRules';
        foreach( array( 'mergedenyrules' => 'mergeDenyRules', 'stopmergingifdenyseen' => 'stopMergingIfDenySeen', 'mergeadjacentonly' => 'mergeAdjacentOnly' ) as $k => $name )
            if( isset( $in[$k] ) )
                $args[] = $name . '=' . ( $bool( $k ) ? 'yes' : 'no' );
        if( ( $f = $filter( 'filter' ) ) !== null )
            $args[] = 'filter=' . $f;
        $add = $in['additionalmatch'] ?? array();
        $add = is_array( $add ) ? $add : array_filter( explode( ',', (string)$add ), 'strlen' );
        foreach( $add as $a )
            if( !in_array( $a, self::RULEMERGER_ADDITIONAL, TRUE ) )
                throw new ViewerException( 'additionalMatch: ' . implode( ', ', self::RULEMERGER_ADDITIONAL ), 400 );
        if( count( $add ) )
            $args[] = 'additionalMatch=' . implode( ',', array_values( array_unique( $add ) ) );
        return array_merge( $args, $report );
    }

    /**
     * a failed SCM import again from its export: only the conversion (type=scm-export-xml) on the JSON the run has
     * already downloaded - no network, no key. The run is queued again (its run.log stays as run-<n>.log); when it
     * is done the configuration becomes a new version, as after an import.
     */
    public function jobConvert( array $user, $pid, $jid ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        $j = $this->jobRow( $p, $jid );
        $args = (array)json_decode( $j['args'], TRUE );
        $tsg = null;
        foreach( $args as $a )
            if( is_string( $a ) && preg_match( '/^x-import-target=scm:([0-9]{1,20})$/', $a, $m ) )
                $tsg = $m[1];
        if( $j['type'] !== 'import' || $tsg === null )
            throw new ViewerException( 'only an SCM import can be converted again', 400 );
        if( $j['state'] !== 'failed' )
            throw new ViewerException( 'only a failed import can be converted again (state: ' . $j['state'] . ')', 409 );
        $dir = $this->jobDir( $p, $j['jid'] );
        $export = $dir . '/scm-export/' . $tsg;
        if( !is_dir( $export ) || is_link( $export ) || count( glob( $export . '/*/manifest.json' ) ?: array() ) === 0 )
            throw new ViewerException( 'the run has no complete SCM export to convert (the download did not finish) - import again', 409 );
        // the log of the attempt before
        for( $n = 1; is_file( $dir . '/run-' . $n . '.log' ) && $n < 100; $n++ );
        if( is_file( $dir . '/run.log' ) )
            @rename( $dir . '/run.log', $dir . '/run-' . $n . '.log' );
        @unlink( $dir . '/out.xml' );
        $args = array_values( array_filter( $args, function( $a ) { return $a !== 'x-import-resume=convert'; } ) );
        $args[] = 'x-import-resume=convert';
        if( $this->q( "UPDATE jobs SET state = 'queued', args = ?, error = NULL, reason = NULL, started = NULL, finished = NULL WHERE id = ? AND state = 'failed'",
            array( json_encode( $args ), $j['id'] ) )->rowCount() === 0 )
            throw new ViewerException( 'the run changed - try again', 409 );
        return $this->jobGet( $user, $pid, $j['jid'] );
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
            'finished' => $j['finished'] !== null ? (int)$j['finished'] : null, 'error' => $j['error'], 'reason' => $j['reason'] ?? null );
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
                // never a hidden file (the key store of an import: .panconfkeystore)
                if( $f->isFile() && !$f->isLink() && !preg_match( '#(^|/)\.#', substr( $f->getPathname(), strlen( $dir ) + 1 ) ) )
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
            // an import: its key store goes at once (the job runner stops the run)
            @unlink( $this->jobDir( $p, $j['jid'] ) . '/.panconfkeystore' );
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
        $result = in_array( $j['type'], array( 'playbook', 'ldap-users', 'object-merger', 'rule-merger' ), TRUE ) ? 'out.xml' : ( $this->pluginRuns()[$j['type']]['result'] ?? null );
        $out = $this->jobDir( $p, $j['jid'] ) . '/' . ( $result ?? 'out.xml' );
        if( $j['state'] !== 'done' || $result === null || !is_file( $out ) || is_link( $out ) || !self::isPanosConfig( $out ) )
            throw new ViewerException( 'this run has no result configuration', 409 );
        $other = $target['id'] !== $p['id'];
        $parent = $other ? FALSE : $this->q( 'SELECT id, name, file FROM configs WHERE id = ? AND project_id = ?', array( $j['config_id'], $p['id'] ) )->fetch();
        $file = self::randomId() . '.xml';
        if( !copy( $out, $this->projectDir( $target['pid'] ) . '/' . $file ) )
            throw new ViewerException( 'file can not be stored', 500 );
        @chmod( $this->projectDir( $target['pid'] ) . '/' . $file, 0600 );
        // the note says where a version comes from: the run, and the project when it is another one
        $note = $j['type'] . ' run ' . substr( $j['jid'], 0, 8 ) . ( $other ? ' of project "' . $p['name'] . '"' : '' );
        // the history on object level: the result as one commit on the history of the version the run ran on
        if( $parent )
            $this->runHistory( $p, $j, $user, $parent['file'], $file );
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
                && !in_array( $step['type'], $this->plugins->playbookTypes(), TRUE ) )
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

    /**
     * Optional arguments of type=playbook for large configurations (PLAYBOOK__.php; utils/api/v1/playbook/README.md):
     *   subprocess        every step as its own PHP process - its memory is free again after the step (slower)
     *   memorythreshold   MB: a step runs as its own process when the run uses more than this (memory of the container)
     *   debugmemory       memory use after every step in run.log
     *   removestagefiles  remove a stage file once the next step has written its own (less disk / page cache)
     */
    const PLAYBOOK_OPTIONS = array( 'subprocess', 'memorythreshold', 'debugmemory', 'removestagefiles' );

    public static function playbookOptions( array $in ): array
    {
        $flag = function( string $k ) use ( $in ) {
            $v = $in[$k] ?? null;
            if( $v === null || $v === FALSE || $v === '' || $v === '0' || $v === 0 || $v === 'false' )
                return FALSE;
            if( $v === TRUE || $v === '1' || $v === 1 || $v === 'true' )
                return TRUE;
            throw new ViewerException( $k . ': true or false', 400 );
        };
        $out = array();
        foreach( array( 'subprocess', 'debugmemory', 'removestagefiles' ) as $k )
            if( $flag( $k ) )
                $out[] = $k;
        $mb = $in['memorythreshold'] ?? null;
        if( $mb !== null && $mb !== '' && $mb !== 0 && $mb !== '0' )
        {
            if( !( is_int( $mb ) || ( is_string( $mb ) && ctype_digit( $mb ) ) ) || (int)$mb < 64 || (int)$mb > 1048576 )
                throw new ViewerException( 'memorythreshold: MB, 64 - 1048576', 400 );
            $out[] = 'memorythreshold=' . (int)$mb;
        }
        return $out;
    }

    // ------------------------------------------------------------------ predefined playbooks (shipped with pan-os-php)

    /** offered when nothing was set by an administrator */
    const PLAYBOOKS_DEFAULT = array( 'visibility.json' );

    /** the playbooks shipped with pan-os-php (utils/api/v1/playbook; a run names them json=$$playbook$$/<name>) */
    private function playbookDir(): string
    {
        return $this->repoDir . '/utils/api/v1/playbook';
    }

    private static function playbookName( $name ): bool
    {
        return is_string( $name ) && preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.json$/', $name ) === 1;
    }

    /** the predefined playbooks an administrator turned on (default: visibility.json) */
    private function playbooksOn(): array
    {
        $row = $this->q( "SELECT value FROM settings WHERE name = 'playbooks'" )->fetch();
        $on = $row ? json_decode( $row['value'], TRUE ) : self::PLAYBOOKS_DEFAULT;
        return is_array( $on ) ? array_values( array_filter( $on, array( self::class, 'playbookName' ) ) ) : array();
    }

    /**
     * The predefined playbooks: every one shipped with pan-os-php, whether an administrator turned it on, and whether it
     * can run here at all (playbookCheck - e.g. no *-merger, no in= / projectfolder). With $all FALSE only the ones a
     * run can use: turned on and usable.
     */
    public function playbooksPredefined( bool $all = FALSE ): array
    {
        $on = $this->playbooksOn();
        $out = array();
        foreach( glob( $this->playbookDir() . '/*.json' ) ?: array() as $f )
        {
            $name = basename( $f );
            if( !self::playbookName( $name ) || is_link( $f ) )
                continue;
            $j = json_decode( (string)file_get_contents( $f ), TRUE );
            $why = null;
            try
            {
                $this->playbookCheck( $j );
            }
            catch( ViewerException $e )
            {
                $why = $e->getMessage();
            }
            $row = array( 'name' => $name, 'steps' => is_array( $j['command'] ?? null ) ? count( $j['command'] ) : 0, 'on' => in_array( $name, $on, TRUE ) && $why === null,
                'usable' => $why === null, 'why' => $why );
            if( $all || $row['on'] )
                $out[] = $all ? $row : array( 'name' => $name, 'steps' => $row['steps'] );
        }
        usort( $out, function( $a, $b ) { return strnatcasecmp( $a['name'], $b['name'] ); } );
        return $out;
    }

    /** administrator: the predefined playbooks that are offered (only usable ones) */
    public function playbooksSet( $names ): array
    {
        if( !is_array( $names ) )
            throw new ViewerException( 'enabled: a list of playbook names', 400 );
        $known = array();
        foreach( $this->playbooksPredefined( TRUE ) as $p )
            $known[$p['name']] = $p;
        $on = array();
        foreach( $names as $n )
        {
            if( !is_string( $n ) || !isset( $known[$n] ) )
                throw new ViewerException( 'unknown predefined playbook: ' . ( is_string( $n ) ? substr( $n, 0, 80 ) : '?' ), 400 );
            if( !$known[$n]['usable'] )
                throw new ViewerException( $n . ' can not run here - ' . $known[$n]['why'], 400 );
            $on[$n] = TRUE;
        }
        $this->q( "INSERT INTO settings (name, value) VALUES ('playbooks', ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            array( json_encode( array_keys( $on ) ) ) );
        return $this->playbooksPredefined( TRUE );
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
        $this->refreshPlugins();
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
        $noVersion = ( ( $this->pluginRuns()[$j['type']]['input'] ?? 'version' ) === 'none' || in_array( $j['type'], array( 'import', 'appid', 'geoip', 'ldap', 'ldap-discover', 'egress-ip' ), TRUE ) ) && (int)$j['config_id'] === 0;
        // type=diff: its versions are file1= / file2= (%PROJECT%), never in=
        $noIn = $noVersion || $j['type'] === 'diff';
        // App-ID database / MaxMind data of the installation or of the project: for every run (not for the runs that
        // fetch them) - %CENTRAL% / %PROJECT% / %JOB% become the folders of the run (ViewerContainer: /central, …)
        $dataEnv = in_array( $j['type'], array( 'appid', 'geoip' ), TRUE ) ? array() : $this->dataEnv( $j['pid'] );
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
            // %PROJECT%: a version of this project (type=diff) - only <32 hex>.xml, and it must still exist
            if( strpos( $a, '%PROJECT%' ) !== FALSE && ( !preg_match( '#^[a-z0-9-]+=%PROJECT%/([0-9a-f]{32}\.xml)$#', $a, $m ) || !is_file( $dir . '/' . $m[1] ) ) )
            {
                $this->runnerFinish( (int)$j['id'], 'failed', 'a version of the run does not exist any more' );
                return $this->runnerTake();
            }
            $args[$i] = str_replace( array( '%FILES%', '%JOB%', '%PROJECT%' ), array( $dir . '/files', $jobDir, $dir ), $a );
        }
        // an import: checked again now (the administrator / owner may have turned network off, the lists may have changed),
        // the key store of the run (only this one entry; removed when the run ends: runnerFinish), and its steps
        $steps = null;
        if( in_array( $j['type'], array( 'import', 'appid', 'geoip', 'ldap', 'ldap-users', 'ldap-discover', 'egress-ip' ), TRUE ) )
        {
            try
            {
                $steps = $this->importSteps( $j, $args, $jobDir );
            }
            catch( ViewerException $e )
            {
                $this->runnerFinish( (int)$j['id'], 'failed', $e->getMessage() );
                return $this->runnerTake();
            }
            $args = $steps[0]['args'];
            $rawArgs = $steps[0]['rawArgs'];
        }
        // pid / jid / file / rawArgs: for a run in a container (ViewerContainer), where the folders have other paths
        // 'tool': the pan-os-php type that runs - for a run type of a plug-in the one it names
        // environment a run type of a plug-in asks for: %PLUGIN% is the folder of the plug-in (in a container: where it is mounted)
        $pr = $this->pluginRuns()[$j['type']] ?? null;
        $env = array();
        foreach( $pr['env'] ?? array() as $k => $v )
            $env[$k] = str_replace( '%PLUGIN%', $pr['dir'], $v );
        // an encrypted plug-in: the run mounts the package itself (pan-os-php: PluginPackage::bootFromEnv) - with the licence
        $package = $pr['package'] ?? null;
        $licenceText = null;
        if( $package !== null )
        {
            $l = $this->licence();
            if( $l === null || !$this->featureOn( $pr['feature'] ?? '' ) )
            {
                $this->runnerFinish( (int)$j['id'], 'failed', 'not licensed (any more)' );
                return $this->runnerTake();
            }
            $licenceText = $l->compact();
            $env['PANOSPHP_PLUGIN_PACKAGES'] = $package;
            $env['PANOSPHP_LICENSE'] = $licenceText;
        }
        return array( 'env' => $env, 'rawEnv' => $pr['env'] ?? array(), 'plugin' => $pr['plugin'] ?? null, 'pluginBuiltin' => $pr['builtin'] ?? FALSE,
            'pluginPackage' => $package, 'licence' => $licenceText,
            'id' => (int)$j['id'], 'type' => $j['type'], 'tool' => $this->pluginRuns()[$j['type']]['tool'] ?? $j['type'], 'args' => $args, 'dir' => $jobDir, 'config' => $noIn ? null : $config,
            'pid' => $j['pid'], 'jid' => $j['jid'], 'file' => $noIn ? null : $j['file'], 'rawArgs' => $rawArgs,
            // steps of a run with more than one pan-os-php call (import); 'network': only this step reaches the network
            'steps' => $steps ?? array( array( 'tool' => $this->pluginRuns()[$j['type']]['tool'] ?? $j['type'], 'args' => $args, 'rawArgs' => $rawArgs, 'network' => FALSE,
                'rawEnv' => $dataEnv, 'env' => $this->resolveEnv( $dataEnv, $j['pid'], $jobDir ) ) ) );
    }

    /** 'running' (still wanted), 'cancelled', or null when the job / project was deleted */
    public function runnerState( int $id ): ?string
    {
        $r = $this->q( 'SELECT state FROM jobs WHERE id = ?', array( $id ) )->fetch();
        return $r ? $r['state'] : null;
    }

    /**
     * the steps of an import: PAN-OS - type=upload in=api://<host>[/running-config] out=out.xml (downloads only);
     * SCM - type=scm-export in=scm-api://<TSG> (read only) and, offline, type=scm-export-xml -> out.xml.
     * Writes the key store of the run (HOME of the run): only the entry of this target.
     */
    private function importSteps( array $j, array $args, string $jobDir ): array
    {
        $type = $j['type'];
        $x = array();
        foreach( $args as $a )
            if( preg_match( '/^x-[a-z-]+?-(key|target|source|zip|resume)=(.*)$/', $a, $m ) )
                $x[$m[1]] = $m[2];
        $step = function( string $tool, array $raw, bool $network, array $rawEnv = array() ) use ( $jobDir, $j ) {
            return array( 'tool' => $tool, 'rawArgs' => $raw, 'network' => $network, 'rawEnv' => $rawEnv, 'env' => $this->resolveEnv( $rawEnv, $j['pid'], $jobDir ),
                'args' => array_map( function( $a ) use ( $jobDir ) { return str_replace( '%JOB%', $jobDir, $a ); }, $raw ) );
        };
        // help for the first LDAP query (no key): the network rules again, then type=ldap-query mode=discover
        if( $type === 'ldap-discover' )
        {
            $p = $this->q( 'SELECT network FROM projects WHERE pid = ?', array( $j['pid'] ) )->fetch();
            $domain = (string)( $x['target'] ?? '' );
            if( !$p || empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project' );
            $ju = array( 'id' => (int)$j['user_id'] );
            if( $this->networkRefusal( 'panos', $domain, $ju ) !== null && ( $why = $this->networkRefusal( 'panos', 'dc.' . $domain, $ju ) ) !== null )
                throw new ViewerException( $why );
            return array( $step( 'ldap-query', array_values( array_filter( $args, function( $a ) { return strpos( $a, 'x-' ) !== 0; } ) ), TRUE ) );
        }
        // a failed SCM import converted again (jobConvert): only the offline step, on the export the run has
        if( $type === 'import' && ( $x['resume'] ?? '' ) === 'convert' )
        {
            if( !preg_match( '/^scm:([0-9]{1,20})$/', (string)( $x['target'] ?? '' ), $m ) || !is_dir( $jobDir . '/scm-export/' . $m[1] ) )
                throw new ViewerException( 'the SCM export of the run is not there any more' );
            return array( $step( 'scm-export-xml', array( 'in=scm-export://%JOB%/scm-export/' . $m[1], 'out=%JOB%/out.xml' ), FALSE ) );
        }
        // MaxMind from an uploaded zip: no key, no network
        if( $type === 'geoip' && isset( $x['zip'] ) )
        {
            if( !is_file( $jobDir . '/GeoLite2-Country-CSV-upload.zip' ) )
                throw new ViewerException( 'the uploaded zip is not there any more' );
            return array( $step( 'maxmind-update', array( 'maxmind-zip=%JOB%/GeoLite2-Country-CSV-upload.zip' ), FALSE, array( 'PANOSPHP_GEOIP_DIR' => '%JOB%/geoip' ) ) );
        }
        $kinds = array( 'import' => array( 'panos', 'scm' ), 'appid' => array( 'panos' ), 'geoip' => array( 'named' ), 'ldap' => array( 'ldap' ), 'ldap-users' => array( 'ldap' ),
            'egress-ip' => array( 'egressip' ) )[$type];
        $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)( $x['key'] ?? '' ), (int)$j['user_id'] ) )->fetch();
        if( !$k || !in_array( $k['kind'], $kinds, TRUE ) )
            throw new ViewerException( 'the API key of the run does not exist any more' );
        $p = $this->q( 'SELECT network FROM projects WHERE pid = ?', array( $j['pid'] ) )->fetch();
        if( $j['pid'] !== self::SYSTEM_PID && ( !$p || empty( $p['network'] ) ) )
            throw new ViewerException( 'network is off for this project' );
        // an LDAP run: the bind user of its arguments must be the one of the key store entry (ldap_user<user>)
        if( $type === 'ldap' || $type === 'ldap-users' )
        {
            $bind = null;
            foreach( $args as $a )
                if( preg_match( '/^ldapUser=(.*)$/', $a, $m ) || preg_match( '/^actions=user-check-ldap:[a-z]+,([^,]*),/', $a, $m ) )
                    $bind = strtolower( $m[1] );
            if( $bind !== $k['target'] )
                throw new ViewerException( 'the LDAP account of the run does not fit its bind user any more' );
        }
        $host = $type === 'geoip' ? self::MAXMIND_HOST : ( $type === 'ldap' || $type === 'ldap-users' ? (string)( $x['target'] ?? '' ) : $k['target'] );
        // the rules again when the run starts, for the user who started it (the administrator may have changed them)
        $ju = array( 'id' => (int)$j['user_id'] );
        $why = $type === 'ldap' || $type === 'ldap-users' ? $this->ldapRefusal( $host, $ju )
            : $this->networkRefusal( $type === 'geoip' ? 'panos' : ( $k['kind'] === 'egressip' ? 'scm' : $k['kind'] ), $host, $ju );
        if( $why !== null )
            throw new ViewerException( $why );
        $secret = $this->unseal( $k['secret'] );
        if( $secret === null )
            throw new ViewerException( 'the API key can not be read (key of the installation changed?) - store it again' );
        $line = self::keystoreLine( $k['kind'], $k['target'], $k['port'] !== null ? (int)$k['port'] : null, $secret );
        $store = $jobDir . '/.panconfkeystore';
        $old = umask( 0077 );
        $ok = file_put_contents( $store, $line . "\n" ) !== FALSE;
        umask( $old );
        if( !$ok )
            throw new ViewerException( 'the key store of the run can not be written' );
        $this->q( 'UPDATE user_keys SET last_used = ? WHERE id = ?', array( time(), $k['id'] ) );
        // the LDAP runs: their arguments were made when the run was queued (no secret in them)
        if( $type === 'ldap' || $type === 'ldap-users' )
        {
            $raw = array_values( array_filter( $args, function( $a ) { return strpos( $a, 'x-' ) !== 0; } ) );
            return array( $step( $type === 'ldap' ? 'ldap-query' : 'rule', $raw, TRUE, $type === 'ldap-users' ? $this->dataEnv( $j['pid'] ) : array() ) );
        }
        // the egress IPs of the tenant: scm_egress_ip.php (pan-os-php type=scm-egress-ip), the request checked at queueing
        if( $type === 'egress-ip' )
        {
            $req = array_values( array_filter( $args, function( $a ) { return preg_match( '/^(servicetype|addrtype|location|env)=[a-z0-9_]{1,40}$/', $a ); } ) );
            return array( $step( 'scm-egress-ip', array_merge( array( 'tsg=' . $k['target'] ), $req, array( 'save=%JOB%/egress.json', 'format=list', 'out=%JOB%/egress.txt' ) ), TRUE ) );
        }
        if( $type === 'appid' )
            return array( $step( 'download-predefined', array( 'in=api://' . $k['target'], 'predefined-out=%JOB%/predefined.xml' ), TRUE ) );
        if( $type === 'geoip' )
            return array( $step( 'maxmind-update', array(), TRUE, array( 'PANOSPHP_GEOIP_DIR' => '%JOB%/geoip' ) ) );
        if( $k['kind'] === 'panos' )
            return array( $step( 'upload', array( 'in=api://' . $k['target'] . ( ( $x['source'] ?? '' ) === 'running' ? '/running-config' : '' ), 'out=%JOB%/out.xml' ), TRUE ) );
        return array(
            $step( 'scm-export', array( 'in=scm-api://' . $k['target'], 'area=config', 'outdir=%JOB%/scm-export', 'config-internal=no' ), TRUE ),
            $step( 'scm-export-xml', array( 'in=scm-export://%JOB%/scm-export/' . $k['target'], 'out=%JOB%/out.xml' ), FALSE ) );
    }

    // ------------------------------------------------------------------ App-ID database / MaxMind data

    /**
     * environment of a run of project $pid for the App-ID database and MaxMind data (pan-os-php: PANOSPHP_PREDEFINED_XML,
     * PANOSPHP_GEOIP_DIR): the App-ID database of the project, else the one of the installation; MaxMind of the
     * installation. Nothing set = the data shipped in the image.
     */
    private function dataEnv( string $pid ): array
    {
        $env = array();
        if( is_file( $this->dataDir . '/projects/' . $pid . '/predefined.xml' ) )
            $env['PANOSPHP_PREDEFINED_XML'] = '%PROJECT%/predefined.xml';
        elseif( is_file( $this->dataDir . '/central/predefined.xml' ) )
            $env['PANOSPHP_PREDEFINED_XML'] = '%CENTRAL%/predefined.xml';
        if( is_file( $this->dataDir . '/central/geoip/data/RegionCCipv4.json' ) )
            $env['PANOSPHP_GEOIP_DIR'] = '%CENTRAL%/geoip';
        return $env;
    }

    /** %JOB% / %PROJECT% / %CENTRAL% of an environment of a run as paths of this computer (run without a container) */
    private function resolveEnv( array $env, string $pid, string $jobDir ): array
    {
        foreach( $env as $k => $v )
            $env[$k] = str_replace( array( '%JOB%', '%PROJECT%', '%CENTRAL%' ), array( $jobDir, $this->dataDir . '/projects/' . $pid, $this->dataDir . '/central' ), $v );
        return $env;
    }

    /** the App-ID version of a predefined.xml (<predefined><application-version>), null when it is no predefined.xml */
    private static function predefinedVersion( string $file ): ?string
    {
        $r = new XMLReader();
        if( !is_file( $file ) || !@$r->open( $file, null, LIBXML_NONET | LIBXML_PARSEHUGE ) )
            return null;
        $version = null;
        $depth = 0;
        while( @$r->read() )
        {
            if( $r->nodeType == XMLReader::DOC_TYPE )
                break;
            if( $r->nodeType != XMLReader::ELEMENT )
                continue;
            if( $r->depth === 0 && $r->name !== 'predefined' )
                break;
            if( $r->depth === 1 && $r->name === 'application-version' )
            {
                $version = trim( (string)$r->readString() );
                break;
            }
        }
        $r->close();
        return $version !== null && preg_match( '/^[0-9]{1,6}-[0-9]{1,6}$/', $version ) ? $version : null;
    }

    private function dataMeta( string $file ): ?array
    {
        $m = json_decode( (string)@file_get_contents( $file ), TRUE );
        return is_array( $m ) ? $m : null;
    }

    /** puts a predefined.xml in place (installation: central/, project: projects/<pid>/) with its description */
    private function appidInstall( string $from, string $targetDir, string $source, string $user ): array
    {
        $version = self::predefinedVersion( $from );
        if( $version === null )
            throw new ViewerException( 'no App-ID database: a predefined.xml (<predefined> with <application-version>) is needed', 400 );
        $tmp = $targetDir . '/predefined.xml.' . getmypid() . '.tmp';
        if( !copy( $from, $tmp ) )
            throw new ViewerException( 'the App-ID database can not be stored', 500 );
        @chmod( $tmp, 0600 );
        if( is_file( $targetDir . '/predefined.xml' ) )
            @rename( $targetDir . '/predefined.xml', $targetDir . '/predefined.prev.xml' );
        rename( $tmp, $targetDir . '/predefined.xml' );
        $meta = array( 'version' => $version, 'source' => $source, 'user' => $user, 'time' => time(), 'size' => filesize( $targetDir . '/predefined.xml' ) );
        file_put_contents( $targetDir . '/predefined.json', json_encode( $meta ) );
        return $meta;
    }

    /** MaxMind data from the folder of a run (geoip/data/RegionCCipv4.json, …) into central/geoip */
    private function geoipInstall( string $fromDir, string $source, string $user ): array
    {
        $files = array();
        foreach( array( 'RegionCCipv4.json', 'RegionCCipv6.json' ) as $f )
        {
            $c = @file_get_contents( $fromDir . '/data/' . $f );
            if( !is_string( $c ) || !is_array( json_decode( $c, TRUE ) ) )
                throw new ViewerException( 'the MaxMind data was not created (see run.log)' );
            $files[$f] = $c;
        }
        $dir = $this->dataDir . '/central/geoip';
        $tmp = $dir . '.' . getmypid() . '.tmp';
        self::rmTree( $tmp );
        mkdir( $tmp . '/data', 0700, TRUE );
        foreach( $files as $f => $c )
            file_put_contents( $tmp . '/data/' . $f, $c );
        $meta = array( 'source' => $source, 'user' => $user, 'time' => time(), 'countries' => count( (array)json_decode( $files['RegionCCipv4.json'], TRUE ) ) );
        file_put_contents( $tmp . '/geoip.json', json_encode( $meta ) );
        self::rmTree( $dir . '.prev' );
        if( is_dir( $dir ) )
            rename( $dir, $dir . '.prev' );
        rename( $tmp, $dir );
        return $meta;
    }

    /** App-ID of the image (lib/object-classes/predefined.xml) */
    private function imageAppidVersion(): ?string
    {
        return self::predefinedVersion( $this->repoDir . '/lib/object-classes/predefined.xml' );
    }

    /** the App-ID database / MaxMind data of the installation (administrator) and their runs */
    public function centralInfo( array $user ): array
    {
        if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $c = $this->dataDir . '/central';
        $runs = array();
        $sys = $this->q( 'SELECT id FROM projects WHERE pid = ?', array( self::SYSTEM_PID ) )->fetch();
        if( $sys )
            $runs = $this->jobList( $user, self::SYSTEM_PID );
        return array( 'pid' => self::SYSTEM_PID, 'image' => array( 'version' => $this->imageAppidVersion() ),
            'appid' => is_file( $c . '/predefined.xml' ) ? $this->dataMeta( $c . '/predefined.json' ) : null,
            'geoip' => is_file( $c . '/geoip/data/RegionCCipv4.json' ) ? $this->dataMeta( $c . '/geoip/geoip.json' ) : null,
            'runs' => $runs );
    }

    /** the project of the installation-wide runs (made on first use, owned by the first administrator who needs it) */
    public function systemProject( array $user ): array
    {
        if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        if( !$this->q( 'SELECT 1 FROM projects WHERE pid = ?', array( self::SYSTEM_PID ) )->fetch() )
        {
            $this->q( 'INSERT INTO projects (pid, name, owner_id, created) VALUES (?,?,?,?)', array( self::SYSTEM_PID, '#installation', $user['id'], time() ) );
            @mkdir( $this->projectDir( self::SYSTEM_PID ), 0700, TRUE );
        }
        return $this->projectGet( $user, self::SYSTEM_PID, 'owner' );
    }

    /** an uploaded App-ID database (predefined.xml): installation ($pid null, administrator) or project (write) */
    public function appidUpload( array $user, ?string $pid, ?array $upload ): array
    {
        if( $pid === null )
        {
            if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
                throw new ViewerException( 'not found', 404 );
            $dir = $this->dataDir . '/central';
        }
        else
        {
            $p = $this->projectGet( $user, $pid, 'write' );
            self::needUnlimited( $p, 'the App-ID database' );
            $dir = $this->projectDir( $p['pid'] );
        }
        if( $upload === null || ( $upload['error'] ?? 1 ) !== UPLOAD_ERR_OK || !is_uploaded_file( $upload['tmp_name'] ) )
            throw new ViewerException( 'file: a predefined.xml', 400 );
        return $this->appidInstall( $upload['tmp_name'], $dir, 'upload ' . substr( basename( (string)( $upload['name'] ?? '' ) ), 0, 80 ), $user['name'] );
    }

    /** back to the App-ID database of the image (installation) / of the installation (project) */
    public function appidReset( array $user, ?string $pid ): void
    {
        if( $pid === null )
        {
            if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
                throw new ViewerException( 'not found', 404 );
            $dir = $this->dataDir . '/central';
        }
        else
            $dir = $this->projectDir( $this->projectGet( $user, $pid, 'write' )['pid'] );
        foreach( array( 'predefined.xml', 'predefined.json', 'predefined.prev.xml' ) as $f )
            @unlink( $dir . '/' . $f );
    }

    /** the App-ID database a project uses: its own, the one of the installation, or the one of the image */
    public function appidInfo( array $user, string $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $own = $this->projectDir( $p['pid'] ) . '/predefined.xml';
        $central = $this->dataDir . '/central/predefined.xml';
        if( is_file( $own ) )
            return array( 'from' => 'project', 'meta' => $this->dataMeta( $this->projectDir( $p['pid'] ) . '/predefined.json' ) );
        if( is_file( $central ) )
            return array( 'from' => 'installation', 'meta' => $this->dataMeta( $this->dataDir . '/central/predefined.json' ) );
        return array( 'from' => 'image', 'meta' => array( 'version' => $this->imageAppidVersion() ) );
    }

    /** the PHP extension zip (ZipArchive) on the server: a clear error instead of "Class ZipArchive not found" */
    public static function needZip(): void
    {
        if( !class_exists( 'ZipArchive' ) )
            throw new ViewerException( 'the PHP extension zip is missing on the server (php' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION
                . '-zip / docker-php-ext-install zip) - a zip can not be read; JSON files can still be imported', 500 );
    }

    /** MaxMind data from an uploaded GeoLite2-Country-CSV zip (air gap): a run without network makes the data */
    public function geoipUpload( array $user, ?array $upload ): array
    {
        $p = $this->systemProject( $user );
        if( $upload === null || ( $upload['error'] ?? 1 ) !== UPLOAD_ERR_OK || !is_uploaded_file( $upload['tmp_name'] ) )
            throw new ViewerException( 'file: the GeoLite2-Country-CSV zip of MaxMind', 400 );
        self::needZip();
        $zip = new ZipArchive();
        $ok = $zip->open( $upload['tmp_name'] ) === TRUE;
        $names = array();
        for( $i = 0; $ok && $i < $zip->numFiles; $i++ )
            $names[] = (string)$zip->getNameIndex( $i );
        if( $ok )
            $zip->close();
        if( !$ok || count( preg_grep( '#^GeoLite2-Country-CSV_[0-9]{8}/GeoLite2-Country-Blocks-IPv4\.csv$#', $names ) ) !== 1
            || count( preg_grep( '#(^/|\.\./|^\.\.)#', $names ) ) > 0 )
            throw new ViewerException( 'file: the GeoLite2-Country-CSV zip of MaxMind (folder GeoLite2-Country-CSV_<date> with the CSV files)', 400 );
        $jid = self::randomId();
        $dir = $this->jobDir( $p, $jid );
        mkdir( $dir, 0700, TRUE );
        move_uploaded_file( $upload['tmp_name'], $dir . '/GeoLite2-Country-CSV-upload.zip' );
        $this->q( 'INSERT INTO jobs (jid, project_id, config_id, user_id, type, args, state, created) VALUES (?,?,?,?,?,?,?,?)',
            array( $jid, $p['id'], 0, $user['id'], 'geoip', json_encode( array( 'x-geoip-zip=upload' ) ), 'queued', time() ) );
        return $this->jobGet( $user, self::SYSTEM_PID, $jid );
    }

    public function geoipReset( array $user ): void
    {
        if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        self::rmTree( $this->dataDir . '/central/geoip' );
        self::rmTree( $this->dataDir . '/central/geoip.prev' );
    }

    /** $reason of a failed run: 'memory' (killed - out of memory), 'timeout', 'error' */
    public function runnerFinish( int $id, string $state, ?string $error = null, ?string $reason = null ): void
    {
        if( $state === 'failed' && $reason === null )
            $reason = 'error';
        $changed = $this->q( "UPDATE jobs SET state = ?, finished = ?, error = ?, reason = ? WHERE id = ? AND state = 'running'", array( $state, time(), $error, $reason, $id ) )->rowCount();
        if( $changed === 0 )
            return;
        $j = $this->q( 'SELECT j.*, p.pid FROM jobs j JOIN projects p ON p.id = j.project_id WHERE j.id = ?', array( $id ) )->fetch();
        if( $j && in_array( $j['type'], array( 'import', 'appid', 'geoip', 'ldap', 'ldap-users', 'ldap-discover' ), TRUE ) )
            $this->importFinish( $j );
    }

    /**
     * the end of an import: the key store of the run goes (the key itself stays with the user), secrets are taken out
     * of run.log, and a downloaded configuration becomes a new version of the project
     */
    private function importFinish( array $j ): void
    {
        $dir = $this->dataDir . '/projects/' . $j['pid'] . '/jobs/' . $j['jid'];
        $store = $dir . '/.panconfkeystore';
        $secret = null;
        if( is_file( $store ) )
        {
            $line = trim( (string)file_get_contents( $store ) );
            $secret = substr( $line, strpos( $line, ':' ) + 1 );
            @unlink( $store );
        }
        if( $secret !== null && $secret !== '' && is_file( $dir . '/run.log' ) )
        {
            $log = (string)file_get_contents( $dir . '/run.log' );
            $clean = str_replace( array_filter( array_merge( array( $secret ), explode( '%', $secret ) ), function( $s ) { return strlen( $s ) >= 8; } ), '********', $log );
            if( $clean !== $log )
                file_put_contents( $dir . '/run.log', $clean );
        }
        // LDAP runs: their results stay in the folder of the run (ldap.json / ldap.csv, out.xml of a remove)
        if( in_array( $j['type'], array( 'ldap', 'ldap-users', 'ldap-discover' ), TRUE ) )
            return;
        // App-ID database / MaxMind data: in place for the installation (project of the installation) or the project
        if( $j['type'] === 'appid' || $j['type'] === 'geoip' )
        {
            if( $j['state'] !== 'done' )
                return;
            $u = $this->userById( (int)$j['user_id'] );
            $target = '';
            foreach( (array)json_decode( $j['args'], TRUE ) as $a )
                if( is_string( $a ) && preg_match( '/^x-[a-z]+-(target|zip)=(.*)$/', $a, $m ) )
                    $target = $m[1] === 'zip' ? 'uploaded zip' : $m[2];
            try
            {
                $f = $dir . '/predefined.xml';
                if( $j['type'] === 'appid' && ( !is_file( $f ) || is_link( $f ) ) )
                    throw new ViewerException( 'no App-ID database was downloaded (see run.log)' );
                if( $j['type'] === 'appid' )
                    $this->appidInstall( $f, $j['pid'] === self::SYSTEM_PID ? $this->dataDir . '/central' : $this->projectDir( $j['pid'] ), 'run ' . substr( $j['jid'], 0, 8 ) . ' from ' . $target, $u['name'] ?? '?' );
                else
                    $this->geoipInstall( $dir . '/geoip', 'run ' . substr( $j['jid'], 0, 8 ) . ' (' . ( $target === 'uploaded zip' ? 'uploaded zip' : $target ) . ')', $u['name'] ?? '?' );
                // the large files of the run are not kept twice
                @unlink( $f );
                @unlink( $dir . '/GeoLite2-Country-CSV-upload.zip' );
            }
            catch( ViewerException $e )
            {
                $this->q( "UPDATE jobs SET state = 'failed', error = ?, reason = 'error' WHERE id = ?", array( $e->getMessage(), $j['id'] ) );
            }
            return;
        }
        $out = $dir . '/out.xml';
        if( $j['state'] !== 'done' || !is_file( $out ) || is_link( $out ) || !self::isPanosConfig( $out ) )
        {
            if( $j['state'] === 'done' )
                $this->q( "UPDATE jobs SET state = 'failed', error = ?, reason = 'error' WHERE id = ?", array( 'no configuration was downloaded (see run.log)', $j['id'] ) );
            return;
        }
        $target = '';
        foreach( (array)json_decode( $j['args'], TRUE ) as $a )
            if( is_string( $a ) && strpos( $a, 'x-import-target=' ) === 0 )
                $target = substr( $a, 16 );
        $p = $this->q( 'SELECT p.*, o.name AS owner FROM projects p JOIN users o ON o.id = p.owner_id WHERE p.pid = ?', array( $j['pid'] ) )->fetch();
        $u = $this->userById( (int)$j['user_id'] );
        if( !$p || !$u )
            return;
        $file = self::randomId() . '.xml';
        if( !copy( $out, $this->projectDir( $p['pid'] ) . '/' . $file ) )
            return;
        @chmod( $this->projectDir( $p['pid'] ) . '/' . $file, 0600 );
        list( $kind, $host ) = array_pad( explode( ':', $target, 2 ), 2, '' );
        $this->configInsert( $p, $u, ( $kind === 'scm' ? 'scm-' . $host : $host ) . '.xml', $file, null, 'import run ' . substr( $j['jid'], 0, 8 ) . ' from ' . $target );
    }

    /**
     * Why a run ended with an error: out of memory or something else. Out of memory: the process of the run was killed
     * (exit code 137 / signal 9 - the memory limit of its container or of the computer), a playbook step in a subprocess
     * was killed (PLAYBOOK__: "most likely out of memory"), or PHP's own memory_limit was reached.
     * @return array [reason, message]
     */
    public static function runFailure( int $exitCode, ?int $signal, string $logTail, ?string $memoryLimit ): array
    {
        $killed = $exitCode === 137 || $signal === 9;
        $oomLog = preg_match( '/most likely out of memory|Allowed memory size of \d+ bytes exhausted|Out of memory \(allocated|exit code 137\b/i', $logTail ) === 1;
        if( $killed || $oomLog )
            return array( 'memory', 'out of memory: the run was stopped because it needed more memory than it may use'
                . ( $memoryLimit !== null ? ' (limit per run: ' . $memoryLimit . ' - setting VIEWER_RUN_MEMORY)' : '' )
                . '. For a playbook: options "subprocess" or "memory threshold"; see run.log' );
        $line = self::lastErrorLine( $logTail );
        return array( 'error', 'pan-os-php ended with an error' . ( $line !== null ? ': ' . $line : '' ) . ' (see run.log)' );
    }

    /**
     * The last error pan-os-php wrote into run.log ("ERROR: …" of a script, "* ** ERROR ** * …" of derr, "PHP Fatal
     * error: …"), shown with a failed run: without colours, one line, at most 400 characters, values of key / password /
     * secret / token masked (an error never carries the secret itself, but to be sure).
     */
    public static function lastErrorLine( string $logTail ): ?string
    {
        $text = preg_replace( '/\x1b\[[0-9;]*[A-Za-z]/', '', $logTail );
        if( preg_match_all( '/^\s*(?:\* \*\* ERROR \*\* \*|ERROR:|PHP Fatal error:)\s*(.+)$/m', $text, $m ) === 0 )
            return null;
        $line = trim( preg_replace( '/\s+/', ' ', end( $m[1] ) ) );
        $line = preg_replace( '/\b(api[_-]?key|key|password|passwd|secret|client_secret|token)(\s*[=:]\s*)("?)[^\s",&]+/i', '$1$2$3***', $line );
        if( $line === '' )
            return null;
        return strlen( $line ) > 400 ? substr( $line, 0, 400 ) . ' …' : $line;
    }

    /** after a restart of the runner: nothing is running any more */
    public function runnerReset(): void
    {
        $this->q( "UPDATE jobs SET state = 'failed', finished = ?, error = 'the job runner was stopped', reason = 'error' WHERE state = 'running'", array( time() ) );
        // key stores of imports that were running
        foreach( glob( $this->dataDir . '/projects/*/jobs/*/.panconfkeystore' ) ?: array() as $f )
            @unlink( $f );
    }

    // ------------------------------------------------------------------ audit log

    /** fields of a request body that are kept in the audit log - never passwords, tokens or file content */
    const AUDIT_FIELDS = array( 'type', 'location', 'filter', 'actions', 'ruletype', 'securityprofiletype', 'user', 'role', 'types', 'scope', 'label', 'days',
        'name', 'playbook', 'predefined', 'bp', 'admin', 'kind', 'enabled', 'subprocess', 'memorythreshold', 'debugmemory', 'removestagefiles', 'other', 'setcommands', 'noruleordercheck', 'xpath',
        'kid', 'source', 'target', 'allow', 'deny', 'qid', 'mode', 'server', 'action', 'domain', 'field', 'hosts', 'decision', 'users', 'conntest', 'network', 'port', 'path' );

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
        $rows = $this->q( 'SELECT c.cid, c.name, c.size, c.note, c.created, u.name AS created_by, pc.cid AS parent, c.changes
            FROM configs c LEFT JOIN users u ON u.id = c.created_by LEFT JOIN configs pc ON pc.id = c.parent_id
            WHERE c.project_id = ? ORDER BY c.id DESC', array( $p['id'] ) )->fetchAll();
        // 'playbook': the version was saved from changes of the viewer - they can be exported as a playbook
        foreach( $rows as $i => $r )
        {
            $rows[$i]['playbook'] = count( self::playbookSteps( (array)json_decode( (string)$r['changes'], TRUE ) ) ) > 0;
            unset( $rows[$i]['changes'] );
        }
        return $rows;
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

    /**
     * filters of a type for the page: field => operator => arg (needs a value), example (from the test of the operator,
     * e.g. "(name eq new test 1)"), help. Operators that read a file are left out.
     */
    private static function filterMeta( array $def ): array
    {
        $filters = array();
        foreach( $def as $field => $f )
        {
            $ops = array();
            foreach( (array)( $f['operators'] ?? array() ) as $op => $o )
            {
                if( preg_match( '/\.file$|\.file\./', (string)$op ) )
                    continue;
                $fs = is_array( $o ) && is_string( $o['ci']['fString'] ?? null ) ? $o['ci']['fString'] : null;
                $ops[(string)$op] = array( 'arg' => is_array( $o ) && !empty( $o['arg'] ),
                    'example' => $fs !== null ? str_replace( '%PROP%', $field . ' ' . $op, $fs ) : null,
                    'help' => is_array( $o ) && is_string( $o['help'] ?? null ) ? $o['help'] : '' );
            }
            if( count( $ops ) > 0 )
                $filters[(string)$field] = $ops;
        }
        ksort( $filters );
        return $filters;
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
                // allow list per action: only actions that change the configuration in memory (or only show it) - and the
                // guarded ones (ACTION_GUARDED: checked in actionsArg)
                $class = $this->actionClass( $type, (string)$name );
                if( ( $class === null || !in_array( $class['class'], array( 'read', 'change' ), TRUE ) ) && !isset( self::ACTION_GUARDED[$type][(string)$name] ) )
                    continue;
                $args = array();
                $deny = FALSE;
                foreach( (array)( $a['args'] ?? array() ) as $argName => $arg )
                {
                    if( preg_match( self::ACTION_DENY_ARG, (string)$argName ) )
                        $deny = TRUE;
                    $args[] = array( 'name' => (string)$argName, 'default' => isset( $arg['default'] ) && is_scalar( $arg['default'] ) ? (string)$arg['default'] : '',
                        'help' => isset( $arg['help'] ) && is_string( $arg['help'] ) ? $arg['help'] : '' )
                        // the values an argument can have (e.g. the colors of color-set): a select in the object window
                        + ( isset( $arg['choices'] ) && is_array( $arg['choices'] ) ? array( 'choices' => array_values( array_map( 'strval', array_filter( $arg['choices'], 'is_scalar' ) ) ) ) : array() );
                }
                if( !$deny )
                    $actions[$name] = $args;
            }
            ksort( $actions );
            $filters = self::filterMeta( (array)$j[$type]['filter'] );
            // 'references': the type has displayreferences - the page offers "References" per object
            $meta[$type] = array( 'actions' => $actions, 'filters' => $filters, 'readonly' => FALSE, 'resource' => self::resourceName( $type ),
                'references' => isset( $j[$type]['action']['displayreferences'] ), 'columns' => self::exportColumns( $j[$type] ) );
        }
        // every other type that shows objects (action 'display'): read only, until its actions are in a reviewed allow list
        foreach( $j as $type => $def )
        {
            if( isset( $meta[$type] ) || !is_array( $def ) || !isset( $def['action']['display'] ) || !preg_match( '/^[a-z][a-z0-9-]{1,40}$/', (string)$type ) )
                continue;
            $filters = self::filterMeta( (array)( $def['filter'] ?? array() ) );
            // a type a person has reviewed (action-classes.json "reviewed") can be changed: its 'read' / 'change' actions
            $actions = array();
            // "reviewed": a whole type, or single actions of a type as "<type>:<action>" (e.g. the assignments of
            // Panorama: device:devicegroup-addserial) - the other actions of the type stay read only
            $reviewed = $this->actionClasses()['reviewed'];
            $whole = in_array( $type, $reviewed, TRUE );
            $single = array();
            foreach( $reviewed as $r )
                if( is_string( $r ) && strpos( $r, $type . ':' ) === 0 )
                    $single[strtolower( substr( $r, strlen( $type ) + 1 ) )] = TRUE;
            if( $whole || count( $single ) > 0 )
                foreach( (array)$def['action'] as $name => $a )
                {
                    if( !$whole && !isset( $single[strtolower( (string)$name )] ) )
                        continue;
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
            $meta[$type] = array( 'actions' => $actions, 'filters' => $filters, 'readonly' => count( $actions ) == 0, 'resource' => self::resourceName( $type ),
                'references' => isset( $def['action']['displayreferences'] ), 'columns' => self::exportColumns( $def ) );
        }
        $this->meta = array( 'types' => $meta, 'ruletypes' => self::RULETYPES, 'securityprofiletypes' => self::SPTYPES, 'devicetypes' => self::DEVICETYPES,
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

    /**
     * the additional fields of exportToExcel of a type that the list can show as columns ("Extra columns"): the
     * choices of its argument additionalFields - not the references (WhereUsed, UsedInLocation: the list has its
     * References), not what needs a live device (HitCount, ApplicationSeen) and never a secret (PSKcleartext)
     */
    const EXPORT_COLUMNS_NOT = array( 'WhereUsed', 'UsedInLocation', 'HitCount', 'ApplicationSeen', 'PSKcleartext' );

    private static function exportColumns( array $def ): array
    {
        $choices = $def['action']['exporttoexcel']['args']['additionalFields']['choices'] ?? array();
        return array_values( array_filter( is_array( $choices ) ? $choices : array(), function( $c ) {
            return is_string( $c ) && preg_match( '/^[A-Za-z][A-Za-z0-9-]{0,60}$/', $c ) && !in_array( $c, self::EXPORT_COLUMNS_NOT, TRUE );
        } ) );
    }

    /**
     * the extra columns of a list: exportToExcel of pan-os-php with these additional fields (its table as data,
     * shadow-json "export-table" - the same code as the HTML export), the columns it adds compared to an export without
     * them, matched to the rows by location and name
     */
    private function exportExtraColumns( array $files, string $type, array $args, array $columns, array $rows ): array
    {
        $read = function( string $actionArgs, ?string $filter ) use ( $files, $type, $args ) {
            $a = $args;
            if( $filter !== null )
                foreach( $a as $i => $x )
                    if( strpos( $x, 'filter=' ) === 0 )
                        unset( $a[$i] );
            if( $filter !== null )
                $a[] = 'filter=' . $filter;
            // the export file is not used ('/' is written '//' in an action argument)
            $r = $this->workerCall( $files, array( 'cmd' => 'read', 'type' => $type, 'args' => array_merge( array_values( $a ), array( 'actions=exportToExcel://dev//null' . $actionArgs ) ) ) );
            return is_array( $r['json']['export-table'] ?? null ) ? $r['json']['export-table'] : array( 'columns' => array(), 'rows' => array() );
        };
        $base = $read( '', '(name eq x-config-viewer-no-object)' )['columns'];
        $full = $read( ',' . implode( '|', $columns ), null );
        $extra = array();
        foreach( $full['columns'] as $i => $col )
            if( !in_array( $col, $base, TRUE ) )
                $extra[$i] = $col;
        $iLoc = array_search( 'location', $full['columns'], TRUE );
        $iName = array_search( 'name', $full['columns'], TRUE );
        if( !$extra || $iLoc === FALSE || $iName === FALSE )
            return array( 'rows' => $rows, 'columns' => array() );
        $by = array();
        foreach( $full['rows'] as $cells )
        {
            $k = ( is_string( $cells[$iLoc] ?? null ) ? $cells[$iLoc] : '' ) . '|' . ( is_string( $cells[$iName] ?? null ) ? $cells[$iName] : '' );
            if( !isset( $by[$k] ) )
                $by[$k] = $cells;
        }
        $names = array();
        foreach( $extra as $i => $col )
            $names[$i] = isset( $rows[0] ) && array_key_exists( $col, $rows[0] ) ? '+' . $col : $col;
        foreach( $rows as $n => $row )
        {
            $cells = $by[( $row['location'] ?? '' ) . '|' . ( $row['name'] ?? '' )] ?? null;
            foreach( $extra as $i => $col )
                $rows[$n][$names[$i]] = $cells !== null ? ( $cells[$i] ?? '' ) : null;
        }
        return array( 'rows' => $rows, 'columns' => array_values( $names ) );
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
        if( !is_string( $location ) || !preg_match( '/^[A-Za-z0-9 _.,:\-]{1,2000}$/', $location ) )
            throw new ViewerException( 'location: letters, digits, space and . _ - , : only', 400 );
        $args[] = 'location=' . $location;
        // Panorama: the template of network / device objects (zones, interfaces, …) - the same vsys exists in several
        // templates, a change of the object window names its template
        $template = $in['template'] ?? '';
        if( $template !== '' && $template !== null )
        {
            if( !is_string( $template ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,200}$/', $template ) )
                throw new ViewerException( 'template: letters, digits, space and . _ - only', 400 );
            if( $project['scope'] !== null )
                throw new ViewerException( 'not allowed: templates are not available with access limited to locations', 403 );
            $args[] = 'template=' . $template;
        }

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
        // devices: device groups, templates, template stacks, managed firewalls, … (before: only the default of
        // pan-os-php, the device groups)
        if( $type === 'device' )
        {
            $dt = $in['devicetype'] ?? 'any';
            if( !in_array( $dt, self::DEVICETYPES, TRUE ) )
                throw new ViewerException( 'devicetype: ' . implode( ', ', self::DEVICETYPES ), 400 );
            $args[] = 'devicetype=' . $dt;
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
            if( isset( self::ACTION_GUARDED[$type][$name] ) && preg_match( self::ACTION_GUARDED[$type][$name], $one ) )
                throw new ViewerException( 'action "' . $name . '": this argument would reach the network (e.g. $$reverse-dns$$) - not allowed here', 400 );
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

    /**
     * is the worker of a session alive and ready ? By its files only: the web part may run in another container than
     * the service and its workers (no shared process ids). The worker writes its pid file at start and removes it with
     * its socket when it ends; the service removes both when it has reaped the worker (also after a crash or a kill)
     * and removes left-overs when it starts.
     */
    private static function workerAlive( array $files ): bool
    {
        return trim( (string)@file_get_contents( $files['pid'] ) ) !== '' && file_exists( $files['sock'] );
    }

    /** ask the service to stop a worker (only the service knows its process) */
    private function serviceStop( array $files ): void
    {
        $service = @stream_socket_client( 'unix://' . $this->dataDir . '/service.sock', $errno, $errstr, 5 );
        if( !$service )
            return;
        stream_set_timeout( $service, 10 );
        fwrite( $service, json_encode( array( 'cmd' => 'stop', 'pid' => $files['pid'] ) ) . "\n" );
        stream_get_contents( $service );
        fclose( $service );
    }

    /** one request to the worker: one JSON line, answer until the worker closes the connection */
    private function workerCall( array $files, array $cmd, int $timeout = 300 ): array
    {
        $conn = @stream_socket_client( 'unix://' . $files['sock'], $errno, $errstr, 5 );
        if( !$conn )
        {
            // nobody listens: the worker is gone (e.g. the service was restarted) - the next request starts a new one
            @unlink( $files['sock'] );
            @unlink( $files['pid'] );
            throw new ViewerException( 'the loaded configuration is not reachable - open the version again', 503 );
        }
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
        $started = FALSE;
        while( microtime( TRUE ) < $deadline )
        {
            if( file_exists( $files['sock'] ) )
                return $files;
            // the worker ended while loading: its pid file was there and is gone (worker or service removed it)
            if( trim( (string)@file_get_contents( $files['pid'] ) ) !== '' )
                $started = TRUE;
            elseif( $started )
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
            // the worker removes its pid file when it ends; if it does not end, the service stops it
            for( $i = 0; $i < 30 && file_exists( $files['pid'] ); $i++ )
                usleep( 100000 );
            if( file_exists( $files['pid'] ) )
                $this->serviceStop( $files );
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
    private static function rows( array $json, bool $nested = FALSE ): array
    {
        $rows = array();
        foreach( $json as $key => $stores )
        {
            // the stores, under the class of the root (PANConf, PanoramaConf, …) or of a template (Template,
            // TemplateStack: network objects of a template - IKE, …)
            if( !preg_match( '/Conf$|^Template$|^TemplateStack$/', (string)$key ) || !is_array( $stores ) )
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
                    // devices: pan-os-php names the templates of a template stack 'template' (a list), the template of
                    // a firewall 'template' and its stack 'templatestack' (name => name + templates) - for the page
                    // 'template' is the template an object is in: before, a template stack had the badge "template
                    // T1,T2" and its window asked for the wrong object (no XML, no references), its members were not shown
                    $cls = is_string( $o['type'] ?? null ) ? $o['type'] : '';
                    if( $cls === 'TemplateStack' && isset( $o['template'] ) )
                    {
                        $o['templates'] = array_values( (array)$o['template'] );
                        unset( $o['template'] );
                    }
                    if( $cls === 'ManagedDevice' )
                    {
                        if( isset( $o['template'] ) )
                        {
                            $o['device-template'] = $o['template'];
                            unset( $o['template'] );
                        }
                        if( isset( $o['templatestack'] ) && is_array( $o['templatestack'] ) )
                        {
                            $ts = array_values( $o['templatestack'] )[0] ?? array();
                            $o['templatestack'] = is_array( $ts ) && isset( $ts['name'] ) ? (string)$ts['name'] : null;
                            $o['templates'] = is_array( $ts ) && isset( $ts['templates'] ) ? array_values( (array)$ts['templates'] ) : array();
                        }
                    }
                    $row = array( 'location' => $location );
                    // Panorama: the template of a network / device object (zone, interface, …)
                    if( isset( $o['model']['item']['template'] ) && is_string( $o['model']['item']['template'] ) && $o['model']['item']['template'] !== '' )
                        $row['template'] = $o['model']['item']['template'];
                    // the template pan-os-php names (CallContext: every object of a template)
                    elseif( isset( $o['template'] ) && is_string( $o['template'] ) && $o['template'] !== '' )
                    {
                        $row['template'] = $o['template'];
                        if( $row['location'] === $o['template'] )
                            $row['location'] = 'shared';
                    }
                    // an object of the shared part of a template / template stack (certificates, certificate
                    // profiles, …): pan-os-php names the template as location - for pan-os-php it is template=<name>
                    // location=shared (before: location <template> - "location not found", no references)
                    elseif( in_array( $sub['type'] ?? '', array( 'Template', 'TemplateStack' ), TRUE ) && $location !== 'shared' )
                    {
                        $row['location'] = 'shared';
                        $row['template'] = $location;
                    }
                    if( isset( $sub['store'] ) && is_string( $sub['store'] ) )
                        $row['store'] = $sub['store'];
                    // variables of a device: in the list only their names (the window has them with values and origin)
                    if( !$nested && isset( $o['effective'] ) && is_array( $o['effective'] ) )
                    {
                        $o['variables'] = array_keys( $o['effective'] );
                        unset( $o['effective'], $o['devicevariables'] );
                    }
                    foreach( $o as $k => $v )
                        // the list: nested values flat (a list of texts); the object window: as they are ($nested)
                        $row[(string)$k] = ( is_array( $v ) && $k !== 'model' && !$nested ) ? array_map( 'strval', self::flatten( $v ) ) : $v;
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
    public function objects( array $user, $pid, $cid, array $in, int $max = 50000, bool $computed = FALSE, bool $nested = FALSE ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        // "<location>:effective": the objects a firewall of this location gets - the location and every level above it
        // (Panorama: parent device groups, shared; SCM: snippets, parent folders with their snippets); each row is
        // marked: the copy that wins for this location, or the one it is hidden by (same name, other level)
        $effective = null;
        if( is_string( $in['location'] ?? null ) && preg_match( '/^(.+):effective$/', $in['location'], $m ) )
        {
            if( $p['scope'] !== null )
                throw new ViewerException( 'not allowed: the effective view reads the levels above your locations', 403 );
            $locs = $this->locations( $user, $pid, $cid );
            foreach( $locs['locations'] as $l )
                if( $l['name'] === $m[1] )
                    $effective = array( 'levels' => $l['levels'], 'ancestor' => $locs['ancestor'] && $locs['config'] === 'panorama', 'at' => $m[1] );
            if( $effective === null )
                throw new ViewerException( 'location ' . $m[1] . ' not found', 400 );
            $in['location'] = implode( ',', $effective['levels'] );
        }
        // several levels in one list (any, a device group / folder with the ones below or above, a list): which object
        // overrides a copy of the same name on another level and where it is overridden (columns, page only)
        $locArg = is_string( $in['location'] ?? null ) ? $in['location'] : 'any';
        $overrideView = $max !== PHP_INT_MAX && !$nested && ( $locArg === 'any' || $locArg === '' || strpos( $locArg, ',' ) !== FALSE || preg_match( '/:(includechilddgs|excludemaindg)$/i', $locArg ) );
        $args = $this->queryArgs( $in, $p );
        $type = substr( array_shift( $args ), 5 );
        // the page (not REST): how many objects use each object - a 'refcount' column after 'name', for the References button
        $refcount = $max !== PHP_INT_MAX && !empty( $this->meta()['types'][$type]['references'] );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'read', 'type' => $type,
            'args' => array_merge( $args, array( 'actions=display' ), $computed ? array( 'x-computed' ) : array(), $refcount ? array( 'x-refcount' ) : array(),
                $nested ? array( 'x-xml' ) : array(), $effective !== null ? array( 'x-effective=' . $effective['at'] ) : array(),
                $overrideView ? array( 'x-override' ) : array(),
                $this->bpArg( $p, $in ) ) ) );
        $rows = self::rows( is_array( $r['json'] ?? null ) ? $r['json'] : array(), $nested );
        // "Extra columns" of the list: additional fields of exportToExcel (e.g. NestedMembers, ResolveIP), by name
        $extra = $in['columns'] ?? '';
        if( $extra !== '' && $extra !== null && $max !== PHP_INT_MAX )
        {
            $want = is_array( $extra ) ? $extra : explode( '|', (string)$extra );
            $allowed = $this->meta()['types'][$type]['columns'] ?? array();
            foreach( $want as $w )
                if( !is_string( $w ) || !in_array( $w, $allowed, TRUE ) )
                    throw new ViewerException( 'columns: ' . ( $allowed ? implode( ', ', $allowed ) : 'none for type ' . $type ), 400 );
            if( $want )
                $rows = $this->exportExtraColumns( $this->session( $p, $c, $user ), $type, array_merge( $args, $this->bpArg( $p, $in ) ), array_values( array_unique( $want ) ), $rows )['rows'];
        }
        if( $refcount && is_array( $r['refcounts'] ?? null ) )
            foreach( $rows as $i => $row )
            {
                $n = $r['refcounts'][( $row['location'] ?? '' ) . '|' . ( $row['template'] ?? '' ) . '|' . ( isset( $row['profile'] ) && is_string( $row['profile'] ) ? $row['profile'] . '/' : '' ) . ( $row['name'] ?? '' )] ?? null;
                $new = array();
                foreach( $row as $k => $v )
                {
                    $new[$k] = $v;
                    if( $k === 'name' )
                        $new['refcount'] = $n;
                }
                $rows[$i] = $new;
            }
        if( $max !== PHP_INT_MAX )
            foreach( $rows as $i => $row )
                unset( $rows[$i]['model'] );
        if( $overrideView && is_array( $r['override'] ?? null ) && count( $r['override'] ) )
            foreach( $rows as $i => $row )
            {
                $o = $r['override'][( $row['location'] ?? '' ) . '|' . ( $row['template'] ?? '' ) . '|' . ( $row['name'] ?? '' )] ?? null;
                $new = array();
                // after the name (and its refcount)
                $after = array_key_exists( 'refcount', $row ) ? 'refcount' : 'name';
                foreach( $row as $k => $v )
                {
                    $new[$k] = $v;
                    if( $k === $after )
                    {
                        $new['overrides'] = $o !== null ? $o['overrides'] : array();
                        $new['overridden in'] = $o !== null ? $o['overridden'] : array();
                    }
                }
                $rows[$i] = $new;
            }
        if( $effective !== null )
            $rows = self::effectiveRows( $rows, $effective['levels'], $effective['ancestor'], is_array( $r['effective'] ?? null ) ? $r['effective'] : array() );

        $columns = array();
        foreach( $rows as $row )
            foreach( $row as $k => $v )
                $columns[$k] = TRUE;
        return array( 'total' => count( $rows ), 'truncated' => count( $rows ) > $max, 'columns' => array_keys( $columns ),
            'rows' => array_slice( $rows, 0, $max ), 'status' => $r['status'] ?? null ) + ( $nested ? array( 'xml' => is_array( $r['xml'] ?? null ) ? $r['xml'] : array() ) : array() );
    }

    /**
     * the effective view: rows of all levels (nearest first in $levels), sorted from the top level down; per name the
     * copy that wins ('effective' => 'used') - the nearest, or the highest with ancestor precedence (Panorama) - and the
     * others 'overridden by <location>' (an address and an address group share their names, so the name decides)
     */
    private static function effectiveRows( array $rows, array $levels, bool $ancestor, array $marks = array() ): array
    {
        $pos = array_flip( $levels );
        $win = array();
        foreach( $rows as $row )
        {
            $n = (string)( $row['name'] ?? '' );
            $l = $pos[$row['location'] ?? ''] ?? PHP_INT_MAX;
            if( !isset( $win[$n] ) || ( $ancestor ? $l > $win[$n] : $l < $win[$n] ) )
                $win[$n] = $l;
        }
        $out = array();
        foreach( $rows as $row )
        {
            $n = (string)( $row['name'] ?? '' );
            $l = $pos[$row['location'] ?? ''] ?? PHP_INT_MAX;
            $new = array();
            foreach( $row as $k => $v )
            {
                $new[$k] = $v;
                if( $k === 'location' )
                {
                    $new['level'] = $l === PHP_INT_MAX ? null : count( $levels ) - $l;
                    // the lookup of pan-os-php (worker: EDL before address / group / region, parents, snippets,
                    // ancestor precedence) - else (types without such a lookup) the nearest level / the highest one
                    $mark = $marks[( $row['location'] ?? '' ) . '|' . ( $row['template'] ?? '' ) . '|' . $n] ?? null;
                    if( $mark === 'used' )
                        $new['effective'] = 'used';
                    elseif( is_array( $mark ) )
                        $new['effective'] = 'overridden by ' . ( $mark['by'] ?? '?' ) . ( in_array( $mark['class'] ?? '', array( 'EDL', 'Region', 'AddressGroup', 'ServiceGroup' ), TRUE ) && $mark['class'] !== ( $row['type'] ?? '' )
                            ? ' (' . array( 'EDL' => 'EDL', 'Region' => 'region', 'AddressGroup' => 'address group', 'ServiceGroup' => 'service group' )[$mark['class']] . ')' : '' );
                    else
                        $new['effective'] = $l === $win[$n] ? 'used' : 'overridden by ' . ( $levels[$win[$n]] ?? '?' );
                }
            }
            $out[] = $new;
        }
        // from the top (shared / All) down to the location; within a level the order of pan-os-php
        $order = array_keys( $out );
        usort( $order, function( $a, $b ) use ( $out ) { return ( $out[$a]['level'] ?? 0 ) <=> ( $out[$b]['level'] ?? 0 ) ?: $a <=> $b; } );
        return array_map( function( $i ) use ( $out ) { return $out[$i]; }, $order );
    }

    /**
     * Who uses an object: GET …/configs/<cid>/references?type=&location=&name= (+ ruletype / securityprofiletype as for a
     * read). Every object of that name in the location, with the objects that reference it (type, location, name, rule
     * type / pre-post, fields). A member limited to types / locations sees only references inside them (the others are
     * counted as 'hidden').
     */
    public function references( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $name = $in['name'] ?? null;
        if( !is_string( $name ) || $name === '' || strlen( $name ) > 300 || preg_match( '/[\x00-\x1F\x7F]/', $name ) )
            throw new ViewerException( 'name: the name of the object', 400 );
        $args = $this->queryArgs( array( 'filter' => '' ) + $in, $p );
        $type = substr( array_shift( $args ), 5 );
        if( empty( $this->meta()['types'][$type]['references'] ) )
            throw new ViewerException( 'type ' . $type . ' has no references', 400 );
        $profile = $in['profile'] ?? '';
        if( !is_string( $profile ) || strlen( $profile ) > 300 || preg_match( '/[\x00-\x1F\x7F]/', $profile ) )
            throw new ViewerException( 'profile: the security profile of the rule', 400 );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'references', 'type' => $type, 'args' => $args, 'name' => $name, 'profile' => $profile ), 300 );
        if( empty( $r['ok'] ) )
            throw new ViewerException( is_string( $r['error'] ?? null ) ? $this->hidePaths( $r['error'] ) : 'the references could not be read', 500 );
        $objects = array();
        foreach( is_array( $r['objects'] ?? null ) ? $r['objects'] : array() as $o )
        {
            $refs = array();
            $hidden = 0;
            foreach( is_array( $o['references'] ?? null ) ? $o['references'] : array() as $ref )
            {
                $t = $ref['type'] ?? null;
                if( ( $p['types'] !== null && !in_array( $t, $p['types'], TRUE ) ) || ( $p['scope'] !== null && !in_array( $ref['location'] ?? null, $p['scope'], TRUE ) ) )
                {
                    $hidden++;
                    continue;
                }
                // a reference the page can open: a type the viewer shows
                $ref['open'] = $t !== null && isset( $this->meta()['types'][$t] ) && is_string( $ref['location'] ?? null );
                $refs[] = $ref;
            }
            $objects[] = array( 'location' => $o['location'] ?? null, 'class' => $o['class'] ?? null, 'references' => $refs, 'hidden' => $hidden );
        }
        return array( 'type' => $type, 'name' => $name, 'objects' => $objects );
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

    /**
     * one object for the object window: GET …/configs/<cid>/object?type=&location=&name= (+ ruletype /
     * securityprofiletype) - its fields as the table shows them ('row') and its structured form ('model', the scm-v1
     * item of the library: values, members, tags as lists)
     */
    public function objectGet( array $user, $pid, $cid, array $in ): array
    {
        $name = $in['name'] ?? null;
        if( !is_string( $name ) || $name === '' || strlen( $name ) > 300 || preg_match( '/[\x00-\x1F\x7F()]/', $name ) || trim( $name ) !== $name )
            throw new ViewerException( 'name: the name of the object (no brackets)', 400 );
        $location = $in['location'] ?? '';
        $tpl = is_string( $in['template'] ?? null ) && $in['template'] !== '';
        if( !is_string( $location ) || $location === '' || ( $location === 'any' && !$tpl ) )
            throw new ViewerException( 'location: the location of the object', 400 );
        $template = is_string( $in['template'] ?? null ) ? $in['template'] : '';
        // an object of a template (Panorama): pan-os-php takes location=any with template= (the vsys of the template is
        // no location of the configuration) - the row is matched by its vsys and template
        $r = $this->objects( $user, $pid, $cid, array( 'filter' => '(name eq ' . $name . ')' ) + ( $template !== '' ? array( 'location' => 'any' ) : array() ) + $in, PHP_INT_MAX, FALSE, TRUE );
        // a DNS rule / threat rule: the one of this security profile
        $profile = is_string( $in['profile'] ?? null ) ? $in['profile'] : '';
        foreach( $r['rows'] as $row )
            if( ( $row['name'] ?? null ) === $name && ( $location === 'any' || ( $row['location'] ?? null ) === $location ) && ( $template === '' || ( $row['template'] ?? '' ) === $template )
                && ( $profile === '' || ( $row['profile'] ?? '' ) === $profile ) )
            {
                $model = is_array( $row['model']['item'] ?? null ) ? $row['model']['item'] : null;
                unset( $row['model'] );
                // its XML and its history (git, the commits that changed its entry - the unsaved ones first)
                $x = $r['xml'][( $row['location'] ?? '' ) . '|' . ( $row['template'] ?? '' ) . '|' . ( isset( $row['profile'] ) && is_string( $row['profile'] ) ? $row['profile'] . '/' : '' ) . $name] ?? null;
                $path = is_array( $x ) && is_string( $x['path'] ?? null ) ? $x['path'] : null;
                return array( 'row' => $row, 'model' => $model, 'xml' => is_array( $x ) && is_string( $x['xml'] ?? null ) ? $x['xml'] : null,
                    'history' => $path !== null ? $this->objectHistory( $user, $pid, $cid, $path, ( $row['location'] ?? '' ) . ':' . $name ) : null, 'status' => $r['status'] );
            }
        throw new ViewerException( 'not found', 404 );
    }

    /**
     * "Result as new version" of a run (object-merger, rule-merger, playbook, …): the result configuration as one commit
     * on the history of the version the run ran on (refs/viewer/versions/<parent> - created from the parent file when
     * that version was never opened) into refs/viewer/versions/<new>. The objects the run changed or removed get this
     * commit in their History; the message names the run and its settings, for a merger also per object what happened
     * (Merged: removed -> kept, Not-merged: copy (kept …): reason) - so the kept object shows the run as well although
     * its own entry did not change. Never stops the save: errors only end up in the PHP error log.
     */
    private function runHistory( array $p, array $j, array $user, string $parentFile, string $newFile ): void
    {
        if( getenv( 'PANOSPHP_VIEWER_GIT' ) === '0' )
            return;
        try
        {
            $dir = $this->projectDir( $p['pid'] );
            $git = new ViewerGit( $dir . '/history.git' );
            if( !$git->ready() )
                return;
            $load = function( string $f ) {
                $d = new DOMDocument();
                if( !@$d->load( $f, LIBXML_PARSEHUGE | LIBXML_NONET ) )
                    throw new Exception( 'can not read ' . basename( $f ) );
                return ConfigObjectSplit::files( ConfigObjectSplit::state( $d ) );
            };
            $parentKey = basename( $parentFile, '.xml' );
            $head = $git->ref( 'refs/viewer/versions/' . $parentKey );
            if( $head === null )
                $head = $git->commit( 'refs/viewer/versions/' . $parentKey, null, $load( $dir . '/' . $parentFile ), array(),
                    "version " . $parentKey . "\n\nVersion: " . $parentKey . "\n", 'config-viewer', time(), TRUE );
            $git->commit( 'refs/viewer/versions/' . basename( $newFile, '.xml' ), $head, $load( $dir . '/' . $newFile ), array(),
                $this->runMessage( $p, $j, $user ), (string)$user['name'], time(), TRUE );
        }
        catch( Throwable $e )
        {
            error_log( 'config-viewer history (run ' . substr( $j['jid'], 0, 8 ) . '): ' . $e->getMessage() );
        }
    }

    /** the message of the commit of a run result: subject, per object of a merger what happened, the trailers */
    private function runMessage( array $p, array $j, array $user ): string
    {
        $args = array();
        foreach( (array)json_decode( (string)$j['args'], TRUE ) as $a )
            if( is_string( $a ) && !preg_match( '/^(in|out|exportjson|exportcsv|json)=/i', $a ) )
                $args[] = $a;
        $settings = $this->hidePaths( implode( ' ', $args ) );
        $m = ViewerGit::oneLine( substr( $j['type'] . ' run ' . substr( $j['jid'], 0, 8 ) . ( $settings !== '' ? ': ' . $settings : '' ), 0, 200 ) ) . "\n\n";
        $rep = $this->jobDir( $p, $j['jid'] ) . '/merger.json';
        $r = is_file( $rep ) && !is_link( $rep ) && filesize( $rep ) < 200000000 ? json_decode( (string)file_get_contents( $rep ), TRUE ) : null;
        $ref = function( $x ) { return is_array( $x ) ? ( ( $x['location'] ?? '' ) !== '' ? $x['location'] . ':' : '' ) . ( $x['name'] ?? '' ) : ''; };
        $lines = array();
        if( is_array( $r ) && ( $r['type'] ?? '' ) === 'rule-merger' )
        {
            foreach( $r['merged'] ?? array() as $x )
                foreach( $x['removed'] ?? array() as $o )
                    $lines[] = 'Merged: ' . ( $x['location'] ?? '' ) . ':' . ( $o['name'] ?? '' ) . ' -> ' . ( $x['location'] ?? '' ) . ':' . ( $x['rule'] ?? '' );
            foreach( $r['skipped'] ?? array() as $x )
                foreach( $x['notMergedWith'] ?? array() as $o )
                    $lines[] = 'Not-merged: ' . ( $x['location'] ?? '' ) . ':' . ( $x['rule'] ?? '' ) . ( ( $o['name'] ?? '' ) !== '' ? ' (with ' . $o['name'] . ')' : '' ) . ': ' . ( $o['reason'] ?? '' );
        }
        elseif( is_array( $r ) )
        {
            foreach( $r['merged'] ?? array() as $x )
                foreach( $x['removed'] ?? array() as $o )
                    $lines[] = 'Merged: ' . $ref( $o ) . ' -> ' . $ref( $x['kept'] ?? null );
            foreach( $r['skipped'] ?? array() as $x )
                foreach( $x['notMergedWith'] ?? array() as $o )
                    $lines[] = 'Not-merged: ' . $ref( $o ) . ( isset( $x['kept'] ) ? ' (kept ' . $ref( $x['kept'] ) . ')' : '' ) . ': ' . trim( implode( ' ', (array)( $x['reason'] ?? array() ) ) );
        }
        foreach( $lines as $l )
            $m .= ViewerGit::oneLine( substr( $l, 0, 2000 ) ) . "\n";
        if( count( $lines ) )
            $m .= "\n";
        $m .= 'Type: ' . ViewerGit::oneLine( (string)$j['type'] ) . "\n" . 'Run: ' . substr( $j['jid'], 0, 8 ) . "\n";
        if( $settings !== '' )
            $m .= 'Settings: ' . ViewerGit::oneLine( $settings ) . "\n";
        return $m;
    }

    /**
     * the commits of the history of the version (unsaved changes, then the versions it came from) that changed one
     * entry: commit, time, user, subject, the change (trailers), the text of the entry after it (null: removed)
     */
    private function objectHistory( array $user, $pid, $cid, string $path, string $object = '' ): ?array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $git = new ViewerGit( $this->projectDir( $p['pid'] ) . '/history.git' );
        if( !is_file( $git->dir() . '/HEAD' ) )
            return null;
        $key = basename( $c['file'], '.xml' );
        $ref = $git->ref( 'refs/viewer/work/' . $key ) !== null ? 'refs/viewer/work/' . $key : 'refs/viewer/versions/' . $key;
        $list = array();
        $seen = array();
        // the lines of a run commit (Merged: / Not-merged:) about this object: "<location>:<name>" as a whole
        $about = function( array $e ) use ( $object ) {
            if( $object === '' )
                return array();
            $q = preg_quote( $object, '/' );
            return array_values( array_filter( $e['notes'] ?? array(), function( $l ) use ( $q ) {
                return preg_match( '/(?:^[A-Za-z-]+: |-> |\(kept |\(with )' . $q . '(?=$| |:|\))/', $l ) === 1; } ) );
        };
        foreach( $git->log( $ref, 30, $path ) as $e )
        {
            $e['text'] = $git->show( $e['commit'], $path );
            $e['notes'] = $about( $e );
            $seen[$e['commit']] = TRUE;
            $list[] = $e;
        }
        // run results (merger) that name this object without changing its entry (e.g. the kept object of a merge)
        $order = array();
        foreach( $git->log( $ref, 200 ) as $i => $e )
        {
            $order[$e['commit']] = $i;
            if( !isset( $seen[$e['commit']] ) && isset( $e['change']['run'] ) && count( $notes = $about( $e ) ) > 0 )
            {
                $e['text'] = $git->show( $e['commit'], $path );
                $e['notes'] = $notes;
                $list[] = $e;
            }
        }
        // newest first: the order of git (commits of the same second keep their order)
        usort( $list, function( $a, $b ) use ( $order ) {
            return ( $order[$a['commit']] ?? PHP_INT_MAX ) <=> ( $order[$b['commit']] ?? PHP_INT_MAX ) ?: $b['time'] <=> $a['time']; } );
        foreach( $list as &$e )
            unset( $e['change']['settings'] );
        unset( $e );
        return array( 'path' => $path, 'commits' => array_slice( $list, 0, 40 ) );
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
        // the change as data (change list of the page; later: the trailers of a git commit) - see
        // todo/config-viewer-panos-style-edit.md
        $note = array( 'time' => time(), 'user' => (string)$user['name'], 'type' => $type, 'args' => $args );
        foreach( $args as $a )
            if( preg_match( '/^(location|template|filter|actions|ruletype|securityprofiletype)=(.*)$/s', $a, $m ) )
                $note[$m[1]] = $m[2];
        if( isset( $in['field'] ) && is_string( $in['field'] ) && preg_match( '/^[a-z][a-z0-9_-]{0,40}$/', $in['field'] ) )
            $note['field'] = $in['field'];
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'change', 'type' => $type, 'args' => array_merge( $args, $bpArg ), 'note' => $note ) );
        return array( 'processed' => count( self::rows( is_array( $r['json'] ?? null ) ? $r['json'] : array() ) ),
            'log' => isset( $r['json']['log'] ) && is_string( $r['json']['log'] ) ? substr( $this->hidePaths( $r['json']['log'] ), 0, 200000 ) : '',
            'status' => $r['status'] ?? null );
    }

    /**
     * undo of one unsaved change (POST …/configs/<cid>/undo, body index = its place in the change list): git takes its
     * commit back on the current state, the worker loads the result again (bin/worker.php viewerUndo). Refused when a
     * later change touched the same objects. A member limited to types / locations may undo only a change he could
     * have made.
     */
    public function undo( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $index = $in['index'] ?? null;
        if( !is_int( $index ) || $index < 0 )
            throw new ViewerException( 'index: the number of the change in the list (from 0)', 400 );
        $files = $this->session( $p, $c, $user );
        $changes = (array)( $this->workerCall( $files, array( 'cmd' => 'status' ), 30 )['status']['changes'] ?? array() );
        $ch = $changes[$index] ?? null;
        if( !is_array( $ch ) || !is_string( $ch['type'] ?? null ) || $ch['type'] === 'undo' )
            throw new ViewerException( 'no change with this number that can be taken back', 404 );
        // a change of the system settings (type=config-section): only without type / location limits
        if( $ch['type'] === 'config-section' )
            self::needUnlimited( $p, 'undo of a change of the system settings' );
        else
        {
            $q = array( 'type' => $ch['type'] );
            foreach( array( 'location', 'template', 'ruletype', 'securityprofiletype' ) as $k )
                if( isset( $ch[$k] ) && is_string( $ch[$k] ) )
                    $q[$k] = $ch[$k];
            $this->queryArgs( $q, $p );
        }
        $r = $this->workerCall( $files, array( 'cmd' => 'undo', 'index' => $index, 'note' => array( 'time' => time(), 'user' => (string)$user['name'] ) ) );
        return array( 'undone' => TRUE, 'unresolved' => array_values( array_filter( (array)( $r['unresolved'] ?? array() ), 'is_string' ) ),
            'warning' => is_string( $r['warning'] ?? null ) ? $r['warning'] : null, 'status' => $r['status'] ?? null );
    }

    /**
     * The locations of a version, for the location choice: Panorama - shared + device groups, firewall - shared + vsys,
     * SCM - containers + snippets (loads the version like a read). A member limited to locations gets only those, and
     * no 'any'.
     */
    public function locations( array $user, $pid, $cid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'locations' ), 120 );
        $list = array();
        foreach( is_array( $r['locations'] ?? null ) ? $r['locations'] : array() as $l )
            if( is_array( $l ) && is_string( $l['name'] ?? null ) && is_string( $l['kind'] ?? null ) )
                $list[] = array( 'name' => $l['name'], 'kind' => $l['kind'], 'levels' => is_array( $l['levels'] ?? null ) ? array_values( array_filter( $l['levels'], 'is_string' ) ) : array( $l['name'] ) );
        if( $p['scope'] !== null )
        {
            $scope = array_map( 'strtolower', $p['scope'] );
            $list = array_values( array_filter( $list, function( $l ) use ( $scope ) { return in_array( strtolower( $l['name'] ), $scope, TRUE ); } ) );
        }
        return array( 'config' => is_string( $r['config'] ?? null ) ? $r['config'] : 'unknown', 'any' => $p['scope'] === null, 'locations' => $list,
            'ancestor' => !empty( $r['ancestor'] ) );
    }

    /**
     * System: GET …/configs/<cid>/system?template=<template of Panorama>&location=<SCM folder / snippet / device> - the
     * settings of the configuration (management, system, administrators, authentication, logging, updates) as
     * type=config-section reads them; secrets never. Not for members limited to types / locations (it is the whole
     * device).
     */
    public function system( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        self::needUnlimited( $p, 'the system information' );
        $cmd = array( 'cmd' => 'system' );
        foreach( array( 'template', 'location' ) as $k )
            if( isset( $in[$k] ) && $in[$k] !== '' )
            {
                if( !is_string( $in[$k] ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,200}$/', $in[$k] ) )
                    throw new ViewerException( $k . ': letters, digits, space and . _ - only', 400 );
                $cmd[$k] = $in[$k];
            }
        $r = $this->workerCall( $this->session( $p, $c, $user ), $cmd, 120 );
        if( empty( $r['ok'] ) )
            throw new ViewerException( (string)( $r['error'] ?? 'system information not available' ), 400 );
        unset( $r['ok'] );
        // a section can be changed here: reviewed in action-classes.json ("config-section:<section>") and write permission
        $reviewed = $this->actionClasses()['reviewed'];
        $write = in_array( $p['role'], array( 'write', 'owner' ), TRUE );
        foreach( $r['sections'] as $i => $s )
            $r['sections'][$i]['editable'] = $write && in_array( 'config-section:' . $s['name'], $reviewed, TRUE );
        return $r;
    }

    /**
     * A change of a system setting: POST …/configs/<cid>/system/change - section, action (set / add-member /
     * remove-member / remove-field / delete), entry (entries sections; set on a missing entry creates it), path, value,
     * template (Panorama) / location (SCM). Runs pan-os-php type=config-section on the loaded configuration (the same
     * as the CLI), as one change of the change list (history, undo). Only sections that are reviewed in
     * action-classes.json ("config-section:<section>"); secret fields (password, keys, secrets) never.
     */
    public function systemChange( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        self::needUnlimited( $p, 'a change of the system settings' );
        require_once dirname( __FILE__ ) . '/../../../common/ConfigSection.php';
        $name = $in['section'] ?? '';
        $reg = ConfigSection::registry();
        if( !is_string( $name ) || !isset( $reg[$name] ) )
            throw new ViewerException( 'section: one of type=config-section section=list', 400 );
        if( !in_array( 'config-section:' . $name, $this->actionClasses()['reviewed'], TRUE ) )
            throw new ViewerException( 'section ' . $name . ' can not be changed here (not reviewed in action-classes.json)', 403 );
        $action = $in['action'] ?? '';
        if( !in_array( $action, array( 'set', 'add-member', 'remove-member', 'remove-field', 'delete' ), TRUE ) )
            throw new ViewerException( 'action: set, add-member, remove-member, remove-field or delete', 400 );
        $text = function( $k, $max, $re ) use ( $in ) {
            $v = $in[$k] ?? '';
            if( !is_string( $v ) || strlen( $v ) > $max || preg_match( '/[\x00-\x1F\x7F]/', $v ) || ( $v !== '' && !preg_match( $re, $v ) ) )
                throw new ViewerException( $k . ': not valid', 400 );
            return $v;
        };
        $path = $text( 'path', 300, '/^[A-Za-z0-9_.\-\[\] \/:@]+$/' );
        $value = $text( 'value', 2000, '/^[^\x00-\x1F]*$/' );
        $entry = $text( 'entry', 200, '/^[A-Za-z0-9 _.\-\/:@$]+$/' );
        $template = $text( 'template', 200, '/^[A-Za-z0-9 _.\-]+$/' );
        $location = $text( 'location', 200, '/^[A-Za-z0-9 _.\-]+$/' );
        if( $action !== 'delete' && $path === '' )
            throw new ViewerException( 'path: the field (elements joined by ".", named entries as [name])', 400 );
        if( in_array( $action, array( 'set', 'add-member', 'remove-member' ), TRUE ) && $value === '' )
            throw new ViewerException( 'value: needed for ' . $action, 400 );
        // a secret field is never written from here (its value is not shown either) - nor a masked value
        if( $path !== '' && ConfigSection::isSecret( '', $path ) )
            throw new ViewerException( 'field ' . $path . ' holds a secret - not changed here', 403 );
        if( preg_match( '/^\*\*\* (hidden|encrypted) \*\*\*$/', $value ) || ConfigSection::isSecret( $value ) )
            throw new ViewerException( 'value: a hidden / encrypted value can not be set here', 400 );
        if( $action === 'delete' && $entry === '' )
            throw new ViewerException( 'entry: the entry to delete', 400 );
        // the actions syntax of type=config-section: '/' between actions ('//' = '/')
        $act = $action . ( $path !== '' ? ':' . str_replace( '/', '//', $path ) . ( $value !== '' ? ',' . str_replace( '/', '//', $value ) : '' ) : '' );
        $args = array( 'section=' . $name, 'actions=' . $act );
        if( $entry !== '' )
            $args[] = 'entry=' . $entry;
        if( $template !== '' )
            $args[] = 'template=' . $template;
        if( $location !== '' )
            $args[] = 'location=' . $location;
        $note = array( 'time' => time(), 'user' => (string)$user['name'], 'type' => 'config-section', 'args' => $args, 'section' => $name,
            'actions' => $act ) + ( $entry !== '' ? array( 'filter' => $entry ) : array() ) + ( $template !== '' ? array( 'template' => $template ) : array() )
            + ( $location !== '' ? array( 'location' => $location ) : array() );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'change', 'type' => 'config-section', 'args' => $args, 'note' => $note ) );
        return array( 'log' => isset( $r['json']['log'] ) && is_string( $r['json']['log'] ) ? substr( $this->hidePaths( $r['json']['log'] ), 0, 200000 ) : '',
            'status' => $r['status'] ?? null );
    }

    // ------------------------------------------------------------------ SCM tab (SCM_TAB.md): egress IP

    private static function egressLib(): void
    {
        require_once dirname( __FILE__ ) . '/../../sase/scm/lib/SCMEgressIP.php';
    }

    private function egressDir( array $p ): string
    {
        return $this->projectDir( $p['pid'] ) . '/scm/egress';
    }

    /**
     * the states of the egress IPs of the project (SCM tab): imports (an export / its 92_egress-ip.json / a snapshot)
     * and live reads (runs egress-ip - taken over here when they are done), newest first; the egress-IP keys of the user
     */
    public function scmEgressList( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the SCM tab' );
        $dir = $this->egressDir( $p );
        // live reads that are done: their result into the states of the project (once)
        foreach( $this->q( "SELECT j.*, u.name AS user FROM jobs j LEFT JOIN users u ON u.id = j.user_id WHERE j.project_id = ? AND j.type = 'egress-ip' AND j.state = 'done'",
            array( $p['id'] ) )->fetchAll() as $j )
        {
            $f = $this->jobDir( $p, $j['jid'] ) . '/egress.json';
            if( is_file( $dir . '/' . $j['jid'] . '.json' ) || !is_file( $f ) )
                continue;
            $snap = json_decode( (string)file_get_contents( $f ), TRUE );
            if( !is_array( $snap ) || !isset( $snap['rows'] ) || !is_array( $snap['rows'] ) )
                continue;
            $this->egressStore( $dir, $j['jid'], array( 'source' => 'live', 'user' => (string)$j['user'], 'time' => (int)( $j['finished'] ?? $j['created'] ?? time() ),
                'tsg' => isset( $snap['tsg_id'] ) ? (string)$snap['tsg_id'] : null, 'request' => $snap['request'] ?? null, 'fetched_at' => $snap['fetched_at'] ?? null, 'rows' => $snap['rows'] ) );
        }
        $states = array();
        foreach( glob( $dir . '/*.json' ) ?: array() as $f )
        {
            $s = json_decode( (string)file_get_contents( $f ), TRUE );
            if( !is_array( $s ) )
                continue;
            $states[] = array( 'id' => basename( $f, '.json' ), 'source' => $s['source'] ?? '', 'user' => $s['user'] ?? '', 'time' => (int)( $s['time'] ?? 0 ),
                'tsg' => $s['tsg'] ?? null, 'request' => $s['request'] ?? null, 'fetched_at' => $s['fetched_at'] ?? null, 'name' => $s['name'] ?? null,
                'count' => count( $s['rows'] ?? array() ) );
        }
        usort( $states, function( $a, $b ) { return $b['time'] <=> $a['time'] ?: strcmp( $b['id'], $a['id'] ); } );
        $keys = array();
        if( !isset( $user['token'] ) )
            foreach( $this->keyList( $user ) as $k )
                if( $k['kind'] === 'egressip' )
                    $keys[] = array( 'kid' => $k['kid'], 'target' => $k['target'], 'label' => $k['label'], 'refused' => $this->networkRefusal( 'scm', $k['target'], $user ) );
        self::egressLib();
        return array( 'states' => $states, 'keys' => $keys, 'network' => !empty( $p['network'] ),
            'options' => array( 'servicetype' => SCMEgressIP::SERVICE_TYPES, 'addrtype' => SCMEgressIP::ADDR_TYPES, 'location' => SCMEgressIP::LOCATIONS ) );
    }

    private function egressStore( string $dir, string $id, array $state ): void
    {
        if( !is_dir( $dir ) )
            mkdir( $dir, 0700, TRUE );
        $tmp = $dir . '/.' . $id . '.' . getmypid();
        file_put_contents( $tmp, json_encode( $state, JSON_UNESCAPED_SLASHES ) );
        rename( $tmp, $dir . '/' . $id . '.json' );
    }

    /** one state: its rows; with $compare (an older state) the added / removed / changed addresses */
    public function scmEgressGet( array $user, $pid, $id, $compare = null ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::egressLib();
        $read = function( $id ) use ( $p ) {
            if( !is_string( $id ) || !preg_match( '/^[0-9a-z]{1,40}$/', $id ) || !is_file( $this->egressDir( $p ) . '/' . $id . '.json' ) )
                throw new ViewerException( 'not found', 404 );
            return json_decode( (string)file_get_contents( $this->egressDir( $p ) . '/' . $id . '.json' ), TRUE );
        };
        $s = $read( $id );
        $out = array( 'id' => $id, 'source' => $s['source'] ?? '', 'tsg' => $s['tsg'] ?? null, 'request' => $s['request'] ?? null, 'fetched_at' => $s['fetched_at'] ?? null,
            'time' => (int)( $s['time'] ?? 0 ), 'rows' => $s['rows'] ?? array() );
        if( $compare !== null && $compare !== '' )
        {
            $o = $read( $compare );
            $out['compare'] = array( 'with' => $compare ) + SCMEgressIP::compare( $o['rows'] ?? array(), $out['rows'] );
        }
        return $out;
    }

    /**
     * an import (SCM tab): the egress IPs of an export (zip of a scm_pa_export.php directory, its
     * infra/92_egress-ip.json) or a snapshot of scm_egress_ip.php save=
     */
    public function scmEgressImport( array $user, $pid, $upload ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::egressLib();
        if( !is_array( $upload ) || ( $upload['error'] ?? 1 ) !== 0 || is_array( $upload['tmp_name'] ?? null ) || !is_uploaded_file( (string)$upload['tmp_name'] ) )
            throw new ViewerException( 'file: the egress IPs (92_egress-ip.json of an export, a zip of the export, or a snapshot of scm_egress_ip.php)', 400 );
        if( (int)$upload['size'] > 52428800 )
            throw new ViewerException( 'file: at most 50 MB', 400 );
        $tmp = $this->projectDir( $p['pid'] ) . '/scm/.import-' . bin2hex( random_bytes( 6 ) );
        @mkdir( $tmp, 0700, TRUE );
        try
        {
            $src = (string)$upload['tmp_name'];
            $head = (string)file_get_contents( $src, FALSE, null, 0, 4 );
            if( $head === "PK\x03\x04" )
            {
                // a zip of the export: only its infra/92_egress-ip.json is read (no secrets of the export are kept)
                self::needZip();
                $z = new ZipArchive();
                if( $z->open( $src ) !== TRUE )
                    throw new ViewerException( 'file: the zip can not be read', 400 );
                $found = null;
                for( $i = 0; $i < $z->numFiles; $i++ )
                {
                    $n = (string)$z->getNameIndex( $i );
                    if( preg_match( '#(^|/)infra/92_egress-ip\.json$#', $n ) && strpos( $n, '..' ) === FALSE )
                        $found = $n;
                }
                if( $found === null || ( $z->statName( $found )['size'] ?? 0 ) > 52428800 )
                {
                    $z->close();
                    throw new ViewerException( 'file: the zip has no infra/92_egress-ip.json (export with egressip)', 400 );
                }
                file_put_contents( $tmp . '/egress.json', $z->getFromName( $found ) );
                $z->close();
            }
            else
                copy( $src, $tmp . '/egress.json' );
            try
            {
                $state = SCMEgressIP::fromFile( $tmp . '/egress.json' );
            }
            catch( Exception $e )
            {
                throw new ViewerException( 'file: ' . preg_replace( '#\S*' . preg_quote( $tmp, '#' ) . '\S*#', 'the file', $e->getMessage() ), 400 );
            }
            $raw = json_decode( (string)file_get_contents( $tmp . '/egress.json' ), TRUE );
            $id = 'i' . time() . bin2hex( random_bytes( 2 ) );
            $this->egressStore( $this->egressDir( $p ), $id, array( 'source' => 'import', 'user' => (string)$user['name'], 'time' => time(),
                'tsg' => is_array( $raw ) && isset( $raw['tsg_id'] ) && is_scalar( $raw['tsg_id'] ) ? (string)$raw['tsg_id'] : null,
                'request' => $state['request'], 'fetched_at' => $state['fetched_at'], 'name' => substr( basename( (string)( $upload['name'] ?? '' ) ), 0, 120 ), 'rows' => $state['rows'] ) );
        }
        finally
        {
            array_map( 'unlink', glob( $tmp . '/*' ) ?: array() );
            @rmdir( $tmp );
        }
        return array( 'id' => $id, 'count' => count( $state['rows'] ) );
    }

    /** a state deleted (write permission) */
    public function scmEgressDelete( array $user, $pid, $id ): void
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'the SCM tab' );
        if( !is_string( $id ) || !preg_match( '/^[0-9a-z]{1,40}$/', $id ) || !is_file( $this->egressDir( $p ) . '/' . $id . '.json' ) )
            throw new ViewerException( 'not found', 404 );
        unlink( $this->egressDir( $p ) . '/' . $id . '.json' );
        // a live read stays deleted (not taken over again)
        if( preg_match( '/^[0-9a-f]{32}$/', $id ) )
            @file_put_contents( $this->jobDir( $p, $id ) . '/egress.json', '' );
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
        $note = implode( "\n", array_map( array( self::class, 'changeText' ), (array)( $r['changes'] ?? array() ) ) );
        $new = $this->configInsert( $p, $user, $c['name'], $file, (int)$c['id'], substr( $note, 0, 4000 ) );
        $this->q( 'UPDATE configs SET changes = ? WHERE cid = ?', array( json_encode( array_values( (array)( $r['changes'] ?? array() ) ) ), $new['cid'] ) );
        $newId = (int)$this->q( 'SELECT id FROM configs WHERE cid = ?', array( $new['cid'] ) )->fetch()['id'];
        $this->q( 'UPDATE sessions SET config_id = ? WHERE project_id = ? AND config_id = ?', array( $newId, $p['id'], $c['id'] ) );
        return array( 'saved' => TRUE, 'cid' => $new['cid'], 'status' => $r['status'] ?? null );
    }

    /** one step of a playbook per change of the change list (changes as data only; older text lines are skipped) */
    public static function playbookSteps( array $changes ): array
    {
        $steps = array();
        foreach( $changes as $c )
        {
            // an undone change and the undo itself are no steps (the other changes replayed give the same result)
            if( !is_array( $c ) || !is_string( $c['type'] ?? null ) || !is_string( $c['actions'] ?? null ) || $c['actions'] === '' || !empty( $c['undone'] ) || $c['type'] === 'undo' )
                continue;
            $step = array( 'comment' => trim( ( isset( $c['time'] ) ? date( 'Y-m-d H:i T', (int)$c['time'] ) : '' ) . ' ' . (string)( $c['user'] ?? '' )
                . ( isset( $c['field'] ) ? ( $c['field'] === 'multi-edit' ? ' - multi-edit' : ' - field ' . $c['field'] ) : '' ) ), 'type' => $c['type'] );
            foreach( array( 'location', 'template', 'ruletype', 'securityprofiletype', 'filter' ) as $k )
                if( isset( $c[$k] ) && is_string( $c[$k] ) && $c[$k] !== '' )
                    $step[$k] = $k . '=' . $c[$k];
            $step['actions'] = 'actions=' . $c['actions'];
            $steps[] = $step;
        }
        return $steps;
    }

    /**
     * the change list as a pan-os-php playbook (type=playbook): GET …/configs/<cid>/playbook?source=unsaved (the
     * unsaved changes of the loaded version) or source=version (the changes this version was saved from). One step per
     * change: type, location, rule type, filter, actions - and a comment (when, who, field).
     */
    public function playbook( array $user, $pid, $cid, string $source ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        if( $source === 'version' )
            $changes = (array)json_decode( (string)( $this->q( 'SELECT changes FROM configs WHERE id = ?', array( $c['id'] ) )->fetch()['changes'] ?? '' ), TRUE );
        elseif( $source === 'unsaved' )
        {
            $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'status' ) );
            $changes = (array)( $r['status']['changes'] ?? array() );
        }
        else
            throw new ViewerException( 'source: unsaved or version', 400 );
        $steps = self::playbookSteps( $changes );
        if( count( $steps ) === 0 )
            throw new ViewerException( $source === 'version' ? 'this version was not saved from changes of the viewer' : 'no changes', 400 );
        $pb = array( 'header-comment' => 'changes of the config viewer - project "' . $p['name'] . '", ' . ( $source === 'version' ? 'version ' : 'unsaved changes of version ' )
            . $c['name'] . ' (' . date( 'Y-m-d H:i T', (int)$c['created'] ) . '); exported ' . date( 'Y-m-d H:i T' ) . ' by ' . $user['name'], 'command' => $steps );
        // what the viewer would refuse to run is not exported
        $this->playbookCheck( $pb );
        return $pb;
    }

    /** one line of the change list as text (the note of a saved version): a change is data now, older ones text */
    public static function changeText( $c ): string
    {
        if( !is_array( $c ) )
            return (string)$c;
        if( ( $c['type'] ?? '' ) === 'undo' )
            return 'undo of change ' . ( (int)( $c['index'] ?? -1 ) + 1 ) . ': ' . (string)( $c['undoes'] ?? '' ) . ' [' . ( $c['user'] ?? '?' ) . ']';
        return ( !empty( $c['undone'] ) ? '(undone) ' : '' ) . 'type=' . ( $c['type'] ?? '?' ) . ' ' . implode( ' ', array_map( 'strval', (array)( $c['args'] ?? array() ) ) ) . ' [' . ( $c['user'] ?? '?' ) . ']';
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
