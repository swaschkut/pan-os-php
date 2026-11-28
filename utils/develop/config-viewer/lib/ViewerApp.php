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
// parts of ViewerApp in files of their own (traits: the same class, the same methods)
require_once dirname(__FILE__) . '/ViewerAppScmTab.php';
require_once dirname(__FILE__) . '/ViewerAppWorker.php';
require_once dirname(__FILE__) . '/ViewerAppPluginPages.php';
require_once dirname(__FILE__) . '/ViewerAppJobs.php';
require_once dirname(__FILE__) . '/ViewerAppKeys.php';
require_once dirname(__FILE__) . '/ViewerAppContentData.php';
require_once dirname(__FILE__) . '/ViewerAppLdap.php';
require_once dirname(__FILE__) . '/../../../../lib/misc-classes/ConfigObjectSplit.php';
// compare of two stats results: the same code as type=playbook-validation compare-stats-…
require_once dirname(__FILE__) . '/../../../../lib/misc-classes/StatsCompare.php';
require_once dirname(__FILE__) . '/../../../../lib/misc-classes/DiffLog.php';

class ViewerException extends Exception
{
}

/** an error of a form: field => what is wrong with it ('' : the form as a whole) */
class ViewerFieldException extends ViewerException
{
    public $fields;

    public function __construct( string $message, array $fields )
    {
        parent::__construct( $message, 400 );
        $this->fields = $fields;
    }
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
    use ViewerAppScmTab;
    use ViewerAppWorker;
    use ViewerAppPluginPages;
    use ViewerAppJobs;
    use ViewerAppKeys;
    use ViewerAppContentData;
    use ViewerAppLdap;

    const ROLES = array( 'read', 'write' );
    const TYPES = array( 'address', 'service', 'tag', 'rule', 'zone', 'schedule', 'securityprofile', 'securityprofilegroup' );
    const RULETYPES = array( 'any', 'security', 'nat', 'decryption', 'appoverride', 'captiveportal', 'authentication', 'pbf', 'qos', 'dos',
        'tunnelinspection', 'defaultsecurity', 'networkpacketbroker', 'sdwan' );
    /** type=device: devicetype (pan-os-php DEVICEUTIL; which ones a configuration has: Panorama / firewall / SCM) */
    const DEVICETYPES = array( 'any', 'devicegroup', 'template', 'templatestack', 'manageddevice', 'logcollector', 'logcollectorgroup', 'vsys',
        'container', 'devicecloud', 'deviceonprem', 'snippet' );
    const SPTYPES = array( 'any', 'url-filtering', 'virus', 'vulnerability', 'spyware', 'file-blocking', 'data-filtering', 'wildfire-analysis',
        'custom-url-category', 'dns-security', 'saas-security', 'virus-and-wildfire-analysis' );
    /** the profile types of the list (Profile type): Panorama / firewall keep antivirus and WildFire analysis apart, SCM has
     * one virus-and-wildfire-analysis profile instead (SecurityProfileStore::$secprof_fawkes_array) */
    const SPTYPES_PANOS = array( 'any', 'url-filtering', 'virus', 'vulnerability', 'spyware', 'file-blocking', 'data-filtering', 'wildfire-analysis',
        'custom-url-category', 'dns-security', 'saas-security' );
    const SPTYPES_SCM = array( 'any', 'url-filtering', 'virus-and-wildfire-analysis', 'vulnerability', 'spyware', 'file-blocking', 'dns-security',
        'custom-url-category', 'saas-security' );
    /** the securityprofiletype of a profile by its class (the 'type' of a row): the window and the references of a row
     * read exactly this profile - not the first profile of the same name of another type (an URL profile, …) */
    const SPCLASSES = array( 'URLProfile' => 'url-filtering', 'AntiVirusProfile' => 'virus', 'VirusAndWildfireProfile' => 'virus-and-wildfire-analysis',
        'VulnerabilityProfile' => 'vulnerability', 'AntiSpywareProfile' => 'spyware', 'FileBlockingProfile' => 'file-blocking',
        'DataFilteringProfile' => 'data-filtering', 'WildfireProfile' => 'wildfire-analysis', 'customURLProfile' => 'custom-url-category',
        'DNSSecurityProfile' => 'dns-security', 'SaasSecurityProfile' => 'saas-security' );

    /** does a row (its class) belong to the profile type asked for - SCM: virus / wildfire-analysis select the
     * virus-and-wildfire-analysis profiles (as SECURITYPROFILEUTIL) */
    public static function spTypeMatches( $class, $st ): bool
    {
        if( !is_string( $st ) || $st === '' || $st === 'any' )
            return TRUE;
        $own = is_string( $class ) ? ( self::SPCLASSES[$class] ?? null ) : null;
        if( $own === null )
            return TRUE;
        return $own === $st || ( $own === 'virus-and-wildfire-analysis' && in_array( $st, array( 'virus', 'wildfire-analysis' ), TRUE ) );
    }

    /** types a grant limited to locations (scope) can use: their objects live in a location (device group, vsys, shared, SCM folder) */
    const SCOPE_TYPES = array( 'address', 'service', 'tag', 'rule', 'schedule', 'securityprofile', 'securityprofilegroup', 'edl', 'log-profile', 'region' );
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
        // the kind of device a project is bound to by its first import / read from an API: 'panos' (firewall /
        // Panorama) or 'scm' (with the TSG of the tenant in bind_target); set from the runs a project already has
        // the scope of the SCM import of the project (JSON: kind, areas, egress, config scope; null = all)
        if( !in_array( 'import_scope', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE projects ADD COLUMN import_scope TEXT' );
        // approvals of plug-in pages: 1 = an area is approved by another person than the one who made the plan
        if( !in_array( 'approval_four_eyes', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE projects ADD COLUMN approval_four_eyes INTEGER NOT NULL DEFAULT 0' );
        // project type of a plug-in (<plugin>-<type>) and its roles, each with its own binding (JSON role => title, kind,
        // write, target) - a project without a type has the one binding of bind_kind / bind_target
        if( !in_array( 'ptype', $cols, TRUE ) )
        {
            $this->db->exec( 'ALTER TABLE projects ADD COLUMN ptype TEXT' );
            $this->db->exec( 'ALTER TABLE projects ADD COLUMN roles TEXT' );
        }
        $bindNew = !in_array( 'bind_kind', $cols, TRUE );
        if( $bindNew )
        {
            $this->db->exec( 'ALTER TABLE projects ADD COLUMN bind_kind TEXT' );
            $this->db->exec( 'ALTER TABLE projects ADD COLUMN bind_target TEXT' );
        }
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
        // the run a version was made from ("Result as new version" in the same project): offered once per run
        if( !in_array( 'from_run', array_column( $this->db->query( 'PRAGMA table_info(configs)' )->fetchAll(), 'name' ), TRUE ) )
            $this->db->exec( 'ALTER TABLE configs ADD COLUMN from_run TEXT' );
        // the server of a query: given, or automatic (server '') - the domain controllers of 'domain' from DNS
        $cols = array_column( $this->db->query( 'PRAGMA table_info(ldap_queries)' )->fetchAll(), 'name' );
        if( !in_array( 'domain', $cols, TRUE ) )
            $this->db->exec( "ALTER TABLE ldap_queries ADD COLUMN domain TEXT NOT NULL DEFAULT ''" );
        if( !in_array( 'ldaps', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE ldap_queries ADD COLUMN ldaps INTEGER NOT NULL DEFAULT 1' );
        // why a run failed: memory (killed / out of memory), timeout, error
        if( $bindNew )
            foreach( $this->db->query( 'SELECT id FROM projects' )->fetchAll() as $row )
                $this->bindFromRuns( (int)$row['id'] );
        $cols = array_column( $this->db->query( 'PRAGMA table_info(jobs)' )->fetchAll(), 'name' );
        if( !in_array( 'reason', $cols, TRUE ) )
            $this->db->exec( 'ALTER TABLE jobs ADD COLUMN reason TEXT' );
        // the image a run asked for by name (a run type of a plug-in with a field of kind "image"); NULL: the image of the viewer
        if( !in_array( 'image', array_column( $this->db->query( 'PRAGMA table_info(jobs)' )->fetchAll(), 'name' ), TRUE ) )
            $this->db->exec( 'ALTER TABLE jobs ADD COLUMN image TEXT' );
        // what a run was started with, for the pages of plug-ins (JSON; a playbook run: playbook, then, bp - file ids)
        if( !in_array( 'meta', array_column( $this->db->query( 'PRAGMA table_info(jobs)' )->fetchAll(), 'name' ), TRUE ) )
            $this->db->exec( 'ALTER TABLE jobs ADD COLUMN meta TEXT' );
        // the id of the image a run ran with (docker / podman: sha256:…; set by the job runner) - "outdated" when the
        // image of that name is another one now (runImageIds)
        if( !in_array( 'image_id', array_column( $this->db->query( 'PRAGMA table_info(jobs)' )->fetchAll(), 'name' ), TRUE ) )
            $this->db->exec( 'ALTER TABLE jobs ADD COLUMN image_id TEXT' );
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
            'types' => $p['types'] ?? null, 'scope' => $p['scope'] ?? null, 'network' => !empty( $p['network'] ),
            'binding' => !empty( $p['bind_kind'] ) ? array( 'kind' => $p['bind_kind'], 'target' => $p['bind_target'] ?? null ) : null,
            'import_scope' => self::scopeOf( $p ), 'scm_areas' => self::scmPaAreas(), 'scm_config_groups' => self::SCM_CONFIG_GROUPS,
            'four_eyes' => !empty( $p['approval_four_eyes'] ),
            'type' => !empty( $p['ptype'] ) ? array( 'key' => $p['ptype'], 'roles' => array_values( self::rolesOf( $p ) ) ) : null );
    }

    // ------------------------------------------------------------------ project types of plug-ins: roles, each bound

    /** the roles of a project with a project type: name => [name, title, kind, write, target] (empty: no type) */
    private static function rolesOf( array $p ): array
    {
        $r = !empty( $p['ptype'] ) && is_string( $p['roles'] ?? null ) ? json_decode( $p['roles'], TRUE ) : null;
        return is_array( $r ) ? $r : array();
    }

    /**
     * PUT …/projects/<pid>/type {type: <plugin>-<type> | null} - the owner, while the project has read nothing from an
     * API yet (no binding, no import / SCM read / egress run): its roles come from the plug-in, each bound later by its
     * first import / read
     */
    public function projectTypeSet( array $user, $pid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'owner' );
        $type = $in['type'] ?? null;
        foreach( self::rolesOf( $p ) as $r )
            if( $r['target'] !== null )
                throw new ViewerException( 'the role ' . $r['name'] . ' is bound already - the project type stays (a new project for another one)', 409 );
        if( !empty( $p['bind_kind'] ) || $this->q( "SELECT 1 FROM jobs WHERE project_id = ? AND type IN ('import', 'scm-pa', 'egress-ip') AND state = 'done' LIMIT 1", array( $p['id'] ) )->fetch() )
            throw new ViewerException( 'this project has read from a device / tenant already - a project type is set for a new project', 409 );
        if( $type === null )
        {
            $this->q( 'UPDATE projects SET ptype = NULL, roles = NULL WHERE id = ?', array( $p['id'] ) );
            return self::projectPublic( $this->projectGet( $user, $pid, 'read' ) );
        }
        $t = is_string( $type ) ? ( $this->plugins->projectTypes()[$type] ?? null ) : null;
        if( $t === null )
            throw new ViewerException( 'type: a project type of a plug-in (meta: plugins.projectTypes)', 400 );
        $plugin = $this->plugins->plugins[$t['plugin']] ?? array();
        if( isset( $plugin['package'] ) && !$this->featureOn( $t['feature'] ) )
            throw new ViewerException( 'not licensed (any more): ' . $t['feature'], 403 );
        $roles = array();
        foreach( $t['roles'] as $name => $r )
            $roles[$name] = $r + array( 'target' => null );
        $this->q( 'UPDATE projects SET ptype = ?, roles = ? WHERE id = ?', array( $type, json_encode( $roles ), $p['id'] ) );
        return self::projectPublic( $this->projectGet( $user, $pid, 'read' ) );
    }

    /** the role of a run (x-role=<role> in its arguments) */
    private static function runRole( array $j ): ?string
    {
        foreach( (array)json_decode( (string)$j['args'], TRUE ) as $a )
            if( is_string( $a ) && preg_match( '/^x-role=([a-z][a-z0-9-]{0,20})$/', $a, $m ) )
                return $m[1];
        return null;
    }

    /**
     * a run that reads from $kind / $target: a project without a type - its one binding (bindCheck); with a type - the
     * role bound to this target, or the free role $role of this kind (bound when the run is done). Returns the role.
     */
    private static function bindRole( array $p, string $kind, ?string $target, $role ): ?string
    {
        $roles = self::rolesOf( $p );
        if( count( $roles ) === 0 )
        {
            self::bindCheck( $p, $kind, $target );
            return null;
        }
        foreach( $roles as $r )
            if( $r['kind'] === $kind && $r['target'] !== null && (string)$r['target'] === (string)$target )
            {
                if( $role !== null && $role !== '' && $role !== $r['name'] )
                    throw new ViewerException( 'this ' . ( $kind === 'scm' ? 'tenant TSG ' : 'device ' ) . $target . ' is bound to the role ' . $r['name'] . ' of this project', 403 );
                return $r['name'];
            }
        $free = array_keys( array_filter( $roles, function( $r ) use ( $kind ) { return $r['kind'] === $kind && $r['target'] === null; } ) );
        if( $role === null || $role === '' )
            throw new ViewerException( count( $free ) > 0 ? 'role: this project has the roles ' . implode( ', ', array_keys( $roles ) ) . ' - choose the role of ' . $target . ' (free: ' . implode( ', ', $free ) . ')'
                : 'this project has no free role for ' . ( $kind === 'scm' ? 'an SCM tenant' : 'a firewall / Panorama' ) . ' - ' . $target . ' needs a project of its own', 403 );
        if( !is_string( $role ) || !isset( $roles[$role] ) )
            throw new ViewerException( 'role: one of ' . implode( ', ', array_keys( $roles ) ), 400 );
        if( $roles[$role]['kind'] !== $kind )
            throw new ViewerException( 'the role ' . $role . ' is for ' . ( $roles[$role]['kind'] === 'scm' ? 'an SCM tenant' : 'a firewall / Panorama' ), 403 );
        if( $roles[$role]['target'] !== null )
            throw new ViewerException( 'the role ' . $role . ' is bound to ' . $roles[$role]['target'] . ' - ' . $target . ' needs another role / project', 403 );
        return $role;
    }

    /** a key / a file of $kind / $target fits the project: its binding (no type), a role bound to it or a free role of that kind */
    private static function bindFits( array $p, string $kind, ?string $target ): bool
    {
        $roles = self::rolesOf( $p );
        if( count( $roles ) === 0 )
            return empty( $p['bind_kind'] ) || ( $p['bind_kind'] === $kind && ( $kind !== 'scm' || (string)$target === (string)$p['bind_target'] ) );
        foreach( $roles as $r )
            if( $r['kind'] === $kind && ( $r['target'] === null || (string)$r['target'] === (string)$target ) )
                return TRUE;
        return FALSE;
    }

    /**
     * writing into $kind / $target (e.g. an upload into an SCM tenant): a project without a type - its binding; with a
     * type - only into a role marked 'write' that is bound to this target
     */
    public static function writeAllowed( array $p, string $kind, ?string $target ): bool
    {
        $roles = self::rolesOf( $p );
        if( count( $roles ) === 0 )
            return self::bindFits( $p, $kind, $target );
        foreach( $roles as $r )
            if( $r['kind'] === $kind && $r['target'] !== null && (string)$r['target'] === (string)$target )
                return $r['write'];
        return FALSE;
    }

    /** PUT …/projects/<pid>/approvals {four_eyes}: the owner - approvals of plug-in pages by another person than the one who made the plan */
    public function approvalSettingSet( array $user, $pid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'owner' );
        if( !is_bool( $in['four_eyes'] ?? null ) )
            throw new ViewerException( 'four_eyes: true or false', 400 );
        $this->q( 'UPDATE projects SET approval_four_eyes = ? WHERE id = ?', array( $in['four_eyes'] ? 1 : 0, $p['id'] ) );
        return self::projectPublic( $this->projectGet( $user, $pid, 'read' ) );
    }

    // ------------------------------------------------------------------ scope of the SCM import

    /** groups of the config area (scm_pa_export.php config-scope=, SCMPrismaAccessExport::CONFIG_GROUPS) */
    const SCM_CONFIG_GROUPS = array( 'objects', 'policies', 'network', 'identity', 'device' );

    /**
     * a scope as given (import form / PUT): kind config (configuration only), areas (the areas given + egress IPs yes /
     * no), all (every area the viewer knows now, egress IPs), future (every area of the viewer version that runs the
     * import); config_scope: groups of the config area (empty = all). The egress IPs need the area infra (the key).
     */
    private static function scopeCheck( $in ): array
    {
        if( !is_array( $in ) )
            throw new ViewerException( 'scope: an object (kind, areas, egress, config_scope)', 400 );
        $kind = (string)( $in['kind'] ?? '' );
        if( !in_array( $kind, array( 'config', 'areas', 'all', 'future' ), TRUE ) )
            throw new ViewerException( 'scope.kind: config | areas | all | future', 400 );
        $areas = array();
        if( $kind === 'areas' )
        {
            foreach( (array)( $in['areas'] ?? array() ) as $a )
                if( !in_array( $a, self::scmPaAreas(), TRUE ) )
                    throw new ViewerException( 'scope.areas: ' . implode( ', ', self::scmPaAreas() ), 400 );
            $areas = array_values( array_intersect( self::scmPaAreas(), (array)( $in['areas'] ?? array() ) ) );
        }
        elseif( $kind === 'all' )
            $areas = self::scmPaAreas();
        $egress = $kind === 'all' || $kind === 'future' || ( $kind === 'areas' && !empty( $in['egress'] ) && $in['egress'] !== 'false' );
        if( $egress && $kind === 'areas' && !in_array( 'infra', $areas, TRUE ) )
            array_unshift( $areas, 'infra' );
        $cs = array();
        foreach( (array)( $in['config_scope'] ?? array() ) as $g )
            if( !in_array( $g, self::SCM_CONFIG_GROUPS, TRUE ) )
                throw new ViewerException( 'scope.config_scope: ' . implode( ', ', self::SCM_CONFIG_GROUPS ), 400 );
        $cs = array_values( array_intersect( self::SCM_CONFIG_GROUPS, (array)( $in['config_scope'] ?? array() ) ) );
        if( count( $cs ) === count( self::SCM_CONFIG_GROUPS ) )
            $cs = array();
        return array( 'kind' => $kind, 'areas' => $kind === 'future' ? null : $areas, 'egress' => $egress, 'config_scope' => $cs );
    }

    /** the scope of the project (null: not chosen yet - an import reads all, as "future") */
    private static function scopeOf( array $p ): ?array
    {
        $s = isset( $p['import_scope'] ) && is_string( $p['import_scope'] ) ? json_decode( $p['import_scope'], TRUE ) : null;
        return is_array( $s ) && isset( $s['kind'] ) ? $s : null;
    }

    /** the areas an import with $scope reads (besides config) */
    private static function scopeAreas( ?array $scope ): array
    {
        if( $scope === null || $scope['kind'] === 'future' )
            return self::scmPaAreas();
        // an area the viewer does not know any more is left out
        return array_values( array_intersect( (array)( $scope['areas'] ?? array() ), self::scmPaAreas() ) );
    }

    /**
     * the scope of the SCM import of a project: chosen by a writer while there is none, changed later by the owner
     */
    public function importScopeSet( array $user, $pid, $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        if( ( $p['bind_kind'] ?? null ) === 'panos' )
            throw new ViewerException( 'this project is bound to PAN-OS (firewall / Panorama) - the scope is for an SCM import', 403 );
        if( self::scopeOf( $p ) !== null && $p['role'] !== 'owner' )
            throw new ViewerException( 'not allowed: the scope of the SCM import is changed by the owner', 403 );
        $scope = self::scopeCheck( $in );
        $this->q( 'UPDATE projects SET import_scope = ? WHERE id = ?', array( json_encode( $scope ), $p['id'] ) );
        return self::projectPublic( $this->projectGet( $user, $pid, 'read' ) );
    }

    // ------------------------------------------------------------------ binding of a project (PAN-OS / SCM tenant)

    /** kind and target of a run that reads from an API: panos / scm:<TSG> (egress IPs belong to the tenant) */
    private static function runTarget( array $j ): ?array
    {
        foreach( (array)json_decode( (string)$j['args'], TRUE ) as $a )
            if( is_string( $a ) && preg_match( '/^x-(import|scmpa|egress)-target=(panos|scm|egressip):(.+)$/', $a, $m ) )
                return $m[2] === 'panos' ? array( 'panos', null ) : array( 'scm', $m[3] );
        return null;
    }

    /**
     * a project without binding: bound by the runs it has done (imports, SCM tab reads) when they agree - all PAN-OS,
     * or one SCM tenant; runs of different kinds / tenants leave it unbound (the next run binds it)
     */
    private function bindFromRuns( int $projectId ): void
    {
        $seen = array();
        foreach( $this->q( "SELECT args FROM jobs WHERE project_id = ? AND state = 'done' AND type IN ('import', 'scm-pa', 'egress-ip')", array( $projectId ) )->fetchAll() as $j )
            if( ( $t = self::runTarget( $j ) ) !== null )
                $seen[$t[0] . ':' . $t[1]] = $t;
        if( count( $seen ) === 1 )
        {
            $t = array_values( $seen )[0];
            $this->q( 'UPDATE projects SET bind_kind = ?, bind_target = ? WHERE id = ? AND bind_kind IS NULL', array( $t[0], $t[1], $projectId ) );
        }
    }

    /** a run reading from $kind ('panos' / 'scm') / TSG $target: refused when the project is bound to something else */
    private static function bindCheck( array $p, string $kind, ?string $target ): void
    {
        if( empty( $p['bind_kind'] ) )
            return;
        if( $p['bind_kind'] !== $kind )
            throw new ViewerException( 'this project is bound to ' . ( $p['bind_kind'] === 'scm' ? 'the SCM tenant TSG ' . $p['bind_target'] : 'PAN-OS (firewall / Panorama)' )
                . ' - ' . ( $kind === 'scm' ? 'an SCM tenant' : 'a firewall / Panorama' ) . ' needs a project of its own', 403 );
        if( $kind === 'scm' && (string)$p['bind_target'] !== (string)$target )
            throw new ViewerException( 'this project is bound to the SCM tenant TSG ' . $p['bind_target'] . ' - TSG ' . $target . ' needs a project of its own', 403 );
    }

    /** the first run that read from an API binds the project - with a project type: the role of the run */
    private function bindSet( string $pid, string $kind, ?string $target, ?string $role = null ): void
    {
        $p = $this->q( 'SELECT id, ptype, roles FROM projects WHERE pid = ?', array( $pid ) )->fetch();
        if( $p && !empty( $p['ptype'] ) )
        {
            $roles = self::rolesOf( $p );
            if( $role === null || !isset( $roles[$role] ) || $roles[$role]['kind'] !== $kind || $roles[$role]['target'] !== null || $target === null )
                return;
            foreach( $roles as $r )
                if( $r['target'] !== null && (string)$r['target'] === (string)$target )
                    return;
            $roles[$role]['target'] = (string)$target;
            $this->q( 'UPDATE projects SET roles = ? WHERE id = ? AND roles = ?', array( json_encode( $roles ), $p['id'], $p['roles'] ) );
            return;
        }
        $this->q( 'UPDATE projects SET bind_kind = ?, bind_target = ? WHERE pid = ? AND bind_kind IS NULL', array( $kind, $kind === 'scm' ? $target : null, $pid ) );
    }

    /** administrator: the binding of a project removed (the next import / read binds it again) */
    public function projectBindingReset( array $user, $pid ): array
    {
        if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
            throw new ViewerException( 'only an administrator', 403 );
        if( !is_string( $pid ) || !preg_match( '/^[0-9a-f]{32}$/', $pid ) || $pid === self::SYSTEM_PID
            || $this->q( 'UPDATE projects SET bind_kind = NULL, bind_target = NULL WHERE pid = ?', array( $pid ) )->rowCount() === 0 )
            throw new ViewerException( 'not found', 404 );
        // a project with a project type: the bindings of its roles as well
        $p = $this->q( 'SELECT id, ptype, roles FROM projects WHERE pid = ?', array( $pid ) )->fetch();
        if( $p && !empty( $p['ptype'] ) )
        {
            $roles = self::rolesOf( $p );
            foreach( $roles as $k => $r )
                $roles[$k]['target'] = null;
            $this->q( 'UPDATE projects SET roles = ? WHERE id = ?', array( json_encode( $roles ), $p['id'] ) );
        }
        return array( 'ok' => TRUE );
    }

    /** the SCM tab: not for a project bound to PAN-OS */
    private static function needScmProject( array $p ): void
    {
        if( ( $p['bind_kind'] ?? null ) === 'panos' )
            throw new ViewerException( 'this project is bound to PAN-OS (firewall / Panorama) - the SCM tab is for an SCM tenant', 403 );
    }

    // ------------------------------------------------------------------ network for runs, API keys of a user, import
    // the methods: trait ViewerAppKeys (lib/ViewerAppKeys.php); its constants (a trait holds none before PHP 8.2):

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

    // ------------------------------------------------------------------ LDAP queries of a user (type=ldap-query, user-check-ldap)
    // the methods: trait ViewerAppLdap (lib/ViewerAppLdap.php); its constants (a trait holds none before PHP 8.2):

    const LDAP_MODES = array( 'validation' => 'do the accounts still exist?', 'user-groups' => 'groups of a user', 'common-groups' => 'groups all users are in',
        'group-members' => 'members of a group' );

    // ------------------------------------------------------------------ jobs (CLI-like runs with result files)

    /**
     * Job types: the pan-os-php arguments are built here from checked values only - never an argument, file name or
     * path of the request. 'in=' is the version file, the working directory is the folder of the job.
     */
    const JOB_TYPES = array( 'stats', 'playbook', 'diff', 'import', 'appid', 'geoip', 'ldap', 'ldap-users', 'ldap-discover',
        'object-merger', 'rule-merger', 'merger-possible-report', 'support-file', 'egress-ip', 'scm-pa', 'psk-list' );
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
    // runs started from a page of a plug-in (a matrix) when the queue is full: they wait - with every check done - and the
    // job runner queues them as the queue of the project has room again (state 'waiting'); at most this many per project
    const JOB_WAIT_MAX = 2000;
    /** run types that may wait (no secret / sensitive input that would sit in the folder of the run longer) */
    const JOB_WAIT_TYPES = array( 'playbook', 'stats', 'diff' );
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

    /** built-in run types that can run with another pan-os-php image (request: image = a name of runImages()) */
    const RUN_IMAGE_TYPES = array( 'stats', 'playbook' );

    /**
     * the names of the further images a run may use (PANOSPHP_VIEWER_CONTAINER_IMAGES - the same setting for web part
     * and job runner). The web part knows only the names; a setting that is not valid offers none (the job runner
     * does not start with it and says why).
     * @return string[]
     */
    public function runImages(): array
    {
        if( !class_exists( 'ViewerContainer' ) )
            require_once dirname( __FILE__ ) . '/ViewerContainer.php';
        try
        {
            return array_keys( ViewerContainer::imagesFromEnv() );
        }
        catch( Exception $e )
        {
            return array();
        }
    }

    /** the file in the data folder with the ids of the images as the job runner saw them last (runnerImageIds) */
    const RUN_IMAGE_IDS_FILE = 'run-images.json';

    /**
     * the id each image has now (the job runner looks them up when it starts and every few minutes):
     * name => id ('@viewer': the image of the viewer); null: not known (no container runtime, image not pulled yet)
     * @return array<string,?string>
     */
    public function runImageIds(): array
    {
        $out = array( '@viewer' => null );
        foreach( $this->runImages() as $n )
            $out[$n] = null;
        $f = $this->dataDir . '/' . self::RUN_IMAGE_IDS_FILE;
        $saved = is_file( $f ) && !is_link( $f ) ? json_decode( (string)file_get_contents( $f ), TRUE ) : null;
        foreach( is_array( $saved['ids'] ?? null ) ? $saved['ids'] : array() as $n => $id )
            if( array_key_exists( (string)$n, $out ) && is_string( $id ) && self::isImageId( $id ) )
                $out[(string)$n] = $id;
        return $out;
    }

    /** an image id as docker / podman report it: sha256:<64 hex> (podman: 64 hex) */
    public static function isImageId( string $id ): bool
    {
        return (bool)preg_match( '/^(sha256:)?[0-9a-f]{64}$/', $id );
    }

    /** job runner: the ids of the images now (name => id or null) */
    public function runnerImageIds( array $ids ): void
    {
        $f = $this->dataDir . '/' . self::RUN_IMAGE_IDS_FILE;
        $clean = array();
        foreach( $ids as $n => $id )
            $clean[(string)$n] = is_string( $id ) && self::isImageId( $id ) ? $id : null;
        file_put_contents( $f . '.tmp', json_encode( array( 'checked' => time(), 'ids' => $clean ) ) );
        rename( $f . '.tmp', $f );
    }

    /** job runner: the id of the image a run runs with */
    public function runnerImageId( int $id, ?string $imageId ): void
    {
        if( $imageId !== null && self::isImageId( $imageId ) )
            $this->q( 'UPDATE jobs SET image_id = ? WHERE id = ? AND image_id IS NULL', array( $imageId, $id ) );
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
        $out = array( 'runs' => array(), 'kinds' => array(), 'rawKinds' => array(), 'plugins' => array(), 'pages' => array(), 'projectTypes' => array(),
            // what a field of kind "image" offers: the names of the further images of this installation
            'images' => $this->runImages() );
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
            foreach( $p['pages'] ?? array() as $name => $pg )
                $out['pages'][$name] = array( 'title' => $pg['title'], 'plugin' => $p['name'], 'types' => $pg['types'] );
            foreach( $p['projectTypes'] ?? array() as $name => $t )
                $out['projectTypes'][$name] = array( 'title' => $t['title'], 'text' => $t['text'], 'plugin' => $p['name'], 'roles' => array_values( $t['roles'] ) );
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

    // ------------------------------------------------------------------ pages of plug-ins (interface 2)
    // the methods: trait ViewerAppPluginPages (lib/ViewerAppPluginPages.php)

    // ------------------------------------------------------------------ jobs: create a run, its arguments, list, result files
    // the methods: trait ViewerAppJobs (lib/ViewerAppJobs.php)

    // ------------------------------------------------------------------ sensitive files of runs (plug-in interface 2)

    /** an upload for a field 'secret' stays at most this long before a run takes it */
    const SECRET_UPLOAD_TTL = 3600;
    const SECRET_UPLOAD_MAX = 20971520;

    private function secretUploadDir( array $p ): string
    {
        return $this->projectDir( $p['pid'] ) . '/.secret-uploads';
    }

    /** uploads no run took in time are removed */
    private function secretUploadsClean( array $p ): void
    {
        foreach( glob( $this->secretUploadDir( $p ) . '/*.json' ) ?: array() as $f )
        {
            $m = json_decode( (string)@file_get_contents( $f ), TRUE );
            if( !is_array( $m ) || (int)( $m['created'] ?? 0 ) < time() - self::SECRET_UPLOAD_TTL )
            {
                @unlink( substr( $f, 0, -5 ) . '.dat' );
                @unlink( $f );
            }
        }
    }

    /**
     * POST …/projects/<pid>/secret-uploads (file): a file for a field 'secret' of a plug-in run - kept hidden, for this
     * user, at most an hour; the token is the value of the field. Never a project file, never downloadable.
     */
    public function secretUpload( array $user, $pid, ?array $upload ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'a sensitive upload' );
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        if( $upload === null || ( $upload['error'] ?? 1 ) !== UPLOAD_ERR_OK || !is_uploaded_file( $upload['tmp_name'] ) )
            throw new ViewerException( 'file: the file for the run', 400 );
        if( (int)$upload['size'] < 1 || (int)$upload['size'] > self::SECRET_UPLOAD_MAX )
            throw new ViewerException( 'file: 1 byte to ' . ( self::SECRET_UPLOAD_MAX / 1048576 ) . ' MB', 400 );
        $this->secretUploadsClean( $p );
        $dir = $this->secretUploadDir( $p );
        if( !is_dir( $dir ) )
            mkdir( $dir, 0700, TRUE );
        $token = self::randomId();
        move_uploaded_file( $upload['tmp_name'], $dir . '/' . $token . '.dat' );
        @chmod( $dir . '/' . $token . '.dat', 0600 );
        file_put_contents( $dir . '/' . $token . '.json', json_encode( array( 'user' => (int)$user['id'], 'created' => time() ) ) );
        return array( 'token' => $token, 'size' => (int)$upload['size'], 'expires' => time() + self::SECRET_UPLOAD_TTL );
    }

    /** the fields 'secret' of a plug-in run: their uploads (of this user, not expired) into <run>/.secret/<field> */
    private function secretMove( array $user, array $p, array $plugin, array $in, string $jid ): void
    {
        $moves = array();
        foreach( $plugin['fields'] as $f )
        {
            if( $f['kind'] !== 'secret' || ( $in[$f['name']] ?? '' ) === '' )
                continue;
            $token = $in[$f['name']];
            $base = is_string( $token ) && preg_match( '/^[0-9a-f]{32}$/', $token ) ? $this->secretUploadDir( $p ) . '/' . $token : null;
            $m = $base !== null ? json_decode( (string)@file_get_contents( $base . '.json' ), TRUE ) : null;
            if( !is_array( $m ) || !is_file( $base . '.dat' ) || (int)( $m['user'] ?? 0 ) !== (int)$user['id'] || (int)( $m['created'] ?? 0 ) < time() - self::SECRET_UPLOAD_TTL )
                throw new ViewerException( $f['name'] . ': no upload of yours with this token (an upload is kept for an hour) - upload the file again', 400 );
            $moves[$f['name']] = $base;
        }
        if( count( $moves ) === 0 )
            return;
        $dir = $this->jobDir( $p, $jid ) . '/.secret';
        mkdir( $dir, 0700, TRUE );
        foreach( $moves as $field => $base )
        {
            rename( $base . '.dat', $dir . '/' . $field );
            @chmod( $dir . '/' . $field, 0600 );
            @unlink( $base . '.json' );
        }
    }

    /** results of a run a write member may download once: <run>/.sensitive/* - removed after the download or after these days */
    private static function sensitiveDays(): int
    {
        return max( 1, (int)( getenv( 'PANOSPHP_VIEWER_SENSITIVE_DAYS' ) ?: 7 ) );
    }

    private function sensitiveFiles( array $p, array $j ): array
    {
        $dir = $this->jobDir( $p, $j['jid'] ) . '/.sensitive';
        $out = array();
        foreach( glob( $dir . '/*' ) ?: array() as $f )
        {
            if( !is_file( $f ) || is_link( $f ) )
                continue;
            $expires = filemtime( $f ) + self::sensitiveDays() * 86400;
            if( $expires < time() )
            {
                @unlink( $f );
                continue;
            }
            $out[] = array( 'name' => basename( $f ), 'size' => filesize( $f ), 'expires' => $expires );
        }
        return $out;
    }

    /**
     * GET …/runs/<jid>/sensitive/<name>: a sensitive result (e.g. the PSK list for the customer) - once: it is removed
     * when it was read. Write members, not with an API token; the audit log gets who and when.
     */
    public function sensitiveTake( array $user, $pid, $jid, string $name ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'a run' );
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        $j = $this->jobRow( $p, $jid );
        if( !in_array( $j['state'], array( 'done', 'failed' ), TRUE ) )
            throw new ViewerException( 'the run is not finished', 409 );
        foreach( $this->sensitiveFiles( $p, $j ) as $f )
            if( $f['name'] === $name )
            {
                $path = $this->jobDir( $p, $j['jid'] ) . '/.sensitive/' . $f['name'];
                $content = (string)file_get_contents( $path );
                @unlink( $path );
                return array( 'name' => $f['name'], 'content' => $content );
            }
        throw new ViewerException( 'not found (a sensitive file is downloaded once, or it expired)', 404 );
    }

    /** cancel an open run (the runner stops it) or delete a finished one with its files; who started it, or write */
    public function jobDelete( array $user, $pid, $jid ): void
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'a run' );
        $j = $this->jobRow( $p, $jid );
        if( $p['role'] === 'read' && (int)$j['user_id'] !== (int)$user['id'] )
            throw new ViewerException( 'not allowed: only who started the run, or the project permission "write"', 403 );
        if( in_array( $j['state'], array( 'waiting', 'queued', 'running' ), TRUE ) )
        {
            $this->q( "UPDATE jobs SET state = 'cancelled', finished = ? WHERE id = ? AND state IN ('waiting','queued','running')", array( time(), $j['id'] ) );
            // an import: its key store goes at once (the job runner stops the run); sensitive inputs and what the run has
            // written of its sensitive results as well (a cancelled run never offers them)
            @unlink( $this->jobDir( $p, $j['jid'] ) . '/.panconfkeystore' );
            self::rmTree( $this->jobDir( $p, $j['jid'] ) . '/.secret' );
            self::rmTree( $this->jobDir( $p, $j['jid'] ) . '/.sensitive' );
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
        $result = $this->jobResultName( $j );
        $out = $this->jobDir( $p, $j['jid'] ) . '/' . ( $result ?? 'out.xml' );
        if( $j['state'] !== 'done' || $result === null || !is_file( $out ) || is_link( $out ) || !self::isPanosConfig( $out ) )
            throw new ViewerException( 'this run has no result configuration', 409 );
        $other = $target['id'] !== $p['id'];
        // once per run and project: the result of this run is a version of the project already (deleted: possible again)
        if( !$other && ( $has = $this->jobVersion( $p, $j ) ) !== null )
            throw new ViewerException( 'the result of this run is a version of the project already (' . $has['name'] . ')', 409 );
        $parent = $other ? FALSE : $this->q( 'SELECT id, name, file FROM configs WHERE id = ? AND project_id = ?', array( $j['config_id'], $p['id'] ) )->fetch();
        $file = self::randomId() . '.xml';
        if( !copy( $out, $this->projectDir( $target['pid'] ) . '/' . $file ) )
            throw new ViewerException( 'file can not be stored', 500 );
        @chmod( $this->projectDir( $target['pid'] ) . '/' . $file, 0600 );
        // the note says where a version comes from: the run, and the project when it is another one
        $note = $j['type'] . ' run ' . substr( $j['jid'], 0, 8 ) . ( $other ? ' of project "' . $p['name'] . '"' : '' );
        // … and with which pan-os-php image, where the installation offers more than one: results of the same run type
        // on the same version differ only by that (e.g. the same playbook with beta and with alpha, then a diff)
        if( ( $j['image'] ?? '' ) !== '' )
            $note .= ', image ' . $j['image'];
        elseif( count( $this->runImages() ) > 0
            && ( in_array( $j['type'], self::RUN_IMAGE_TYPES, TRUE ) || ( $this->pluginRuns()[$j['type']]['imageField'] ?? null ) !== null ) )
            $note .= ', image of the viewer';
        // the history on object level: the result as one commit on the history of the version the run ran on
        if( $parent )
            $this->runHistory( $p, $j, $user, $parent['file'], $file );
        return $this->configInsert( $target, $user, $parent ? $parent['name'] : $j['type'] . ' result', $file, $parent ? (int)$parent['id'] : null, $note, $other ? null : $j['jid'] )
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
            if( self::filterTouchesFile( $arg ) )
                $bad( $at . 'filter operators that read a file are not available' );
            if( strpos( $arg, '`' ) !== FALSE )
                $bad( $at . 'filter: the character ` is not allowed' );
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
        // waiting runs (started from a matrix when the queue was full): queued as the queue of their project has room
        foreach( $this->q( "SELECT DISTINCT project_id FROM jobs WHERE state = 'waiting'" )->fetchAll() as $w )
        {
            $open = (int)$this->q( "SELECT COUNT(*) AS c FROM jobs WHERE project_id = ? AND state IN ('queued','running')", array( $w['project_id'] ) )->fetch()['c'];
            if( $open < self::JOB_QUEUE_MAX )
                $this->q( "UPDATE jobs SET state = 'queued' WHERE id IN ( SELECT id FROM jobs WHERE project_id = ? AND state = 'waiting' ORDER BY id LIMIT " . (int)( self::JOB_QUEUE_MAX - $open ) . " )",
                    array( $w['project_id'] ) );
        }
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
        $noVersion = ( ( $this->pluginRuns()[$j['type']]['input'] ?? 'version' ) === 'none' || in_array( $j['type'], array( 'import', 'appid', 'geoip', 'ldap', 'ldap-discover', 'egress-ip', 'scm-pa', 'psk-list' ), TRUE ) ) && (int)$j['config_id'] === 0;
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
            // %PROJECT%: a version of this project (type=diff) - only <32 hex>.xml, and it must still exist; the approved plan
            // of a plug-in run (plugin-pages/<page>/approved/<32 hex>.json); the result configuration of another run of
            // the project (type=diff of two run results: jobs/<32 hex>/<name>.xml)
            if( strpos( $a, '%PROJECT%' ) !== FALSE && ( !preg_match( '#^[a-z0-9-]+=%PROJECT%/((?:plugin-pages/[a-z][a-z0-9-]{0,62}/approved/)?[0-9a-f]{32}\.(?:xml|json)|jobs/[0-9a-f]{32}/[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.xml)$#', $a, $m )
                || ( substr( $m[1], -5 ) === '.json' && strpos( $m[1], 'plugin-pages/' ) !== 0 ) || !is_file( $dir . '/' . $m[1] ) ) )
            {
                $this->runnerFinish( (int)$j['id'], 'failed', 'a version of the run does not exist any more' );
                return $this->runnerTake();
            }
            $args[$i] = str_replace( array( '%FILES%', '%JOB%', '%PROJECT%' ), array( $dir . '/files', $jobDir, $dir ), $a );
        }
        // an import: checked again now (the administrator / owner may have turned network off, the lists may have changed),
        // the key store of the run (only this one entry; removed when the run ends: runnerFinish), and its steps
        $steps = null;
        if( in_array( $j['type'], array( 'import', 'appid', 'geoip', 'ldap', 'ldap-users', 'ldap-discover', 'egress-ip', 'scm-pa', 'psk-list' ), TRUE ) )
        {
            try
            {
                // with the arguments as they were queued ( %JOB% / %FILES% / %PROJECT% ): a step keeps them as 'rawArgs'
                // for a run in a container, where the folders have other paths, and resolves them for this computer
                $steps = $this->importSteps( $j, $rawArgs, $jobDir );
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
            // the image the run asked for by name ('' : the one of the viewer) - looked up by the job runner (ViewerContainer)
            'image' => (string)( $j['image'] ?? '' ),
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
            if( preg_match( '/^x-[a-z-]+?-(key|target|source|zip|resume|areas|egress|cscope)=(.*)$/', $a, $m ) )
                $x[$m[1]] = $m[2];
        $projectDir = $this->dataDir . '/projects/' . $j['pid'];
        $step = function( string $tool, array $raw, bool $network, array $rawEnv = array() ) use ( $jobDir, $projectDir, $j ) {
            return array( 'tool' => $tool, 'rawArgs' => $raw, 'network' => $network, 'rawEnv' => $rawEnv, 'env' => $this->resolveEnv( $rawEnv, $j['pid'], $jobDir ),
                'args' => array_map( function( $a ) use ( $jobDir, $projectDir ) {
                    return str_replace( array( '%FILES%', '%JOB%', '%PROJECT%' ), array( $projectDir . '/files', $jobDir, $projectDir ), $a ); }, $raw ) );
        };
        // the PSK list: first the version (offline - the first step gets in=), then with a key the firewalls managed by SCM
        // (network), compared with the version
        $pskSteps = array();
        if( $type === 'psk-list' && (int)$j['config_id'] !== 0 )
            $pskSteps[] = $step( 'scm-ngfw-psk-list', array( 'psk-list=%JOB%/.sensitive/psk-list-version.csv', 'sha1-list=%JOB%/psk-sha1-version.csv' ), FALSE );
        if( $type === 'psk-list' && !isset( $x['key'] ) )
        {
            if( count( $pskSteps ) === 0 )
                throw new ViewerException( 'the run has neither a version nor a key' );
            return $pskSteps;
        }
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
            'egress-ip' => array( 'egressip' ), 'scm-pa' => array( 'scm' ), 'psk-list' => array( 'scm' ) )[$type];
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
        // the PSK list of the firewalls managed by SCM (read only), compared with the one of the version
        if( $type === 'psk-list' )
            return array_merge( $pskSteps, array( $step( 'scm-ngfw-psk-list', array_merge( array( 'in=scm-api://' . $k['target'],
                'psk-list=%JOB%/.sensitive/psk-list-firewalls.csv', 'sha1-list=%JOB%/psk-sha1-firewalls.csv' ),
                count( $pskSteps ) > 0 ? array( 'compare=%JOB%/psk-sha1-version.csv', 'compare-out=%JOB%/psk-compare.csv' ) : array() ), TRUE ) ) );
        // the egress IPs of the tenant: scm_egress_ip.php (pan-os-php type=scm-egress-ip), the request checked at queueing
        if( $type === 'egress-ip' )
        {
            $req = array_values( array_filter( $args, function( $a ) { return preg_match( '/^(servicetype|addrtype|location)=[a-z0-9_]{1,40}$/', $a ) || preg_match( '/^env=prod[0-9]{0,2}$/', $a ); } ) );
            return array( $step( 'scm-egress-ip', array_merge( array( 'tsg=' . $k['target'] ), $req, array( 'save=%JOB%/egress.json', 'format=list', 'out=%JOB%/egress.txt' ) ), TRUE ) );
        }
        // SCM tab, Prisma Access read live: scm_pa_export.php (type=scm-export) of the area of the page, read only
        if( $type === 'scm-pa' )
        {
            $page = '';
            foreach( $args as $a )
                if( preg_match( '/^x-scmpa-page=([a-z-]+)$/', $a, $m ) )
                    $page = $m[1];
            if( $page !== 'all' && !isset( self::SCM_PA_PAGES[$page] ) )
                throw new ViewerException( 'unknown page of the SCM tab' );
            // all: every area of the pages and the egress IPs (as the SCM import, without the configuration)
            if( $page === 'all' )
                return array( $step( 'scm-export', array( 'in=scm-api://' . $k['target'], 'area=' . implode( ',', self::scmPaAreas() ), 'outdir=%JOB%/scm-export',
                    'egressip-key-out=%JOB%/.egress-key', 'egressip', 'egressip-env=auto' ), TRUE ) );
            $area = self::SCM_PA_PAGES[$page]['area'];
            return array( $step( 'scm-export', array_merge( array( 'in=scm-api://' . $k['target'], 'area=' . $area, 'outdir=%JOB%/scm-export' ),
                $area === 'infra' ? array( 'egressip-key-out=%JOB%/.egress-key' ) : array() ), TRUE ) );
        }
        if( $type === 'appid' )
            return array( $step( 'download-predefined', array( 'in=api://' . $k['target'], 'predefined-out=%JOB%/predefined.xml' ), TRUE ) );
        if( $type === 'geoip' )
            return array( $step( 'maxmind-update', array(), TRUE, array( 'PANOSPHP_GEOIP_DIR' => '%JOB%/geoip' ) ) );
        if( $k['kind'] === 'panos' )
            return array( $step( 'upload', array( 'in=api://' . $k['target'] . ( ( $x['source'] ?? '' ) === 'running' ? '/running-config' : '' ), 'out=%JOB%/out.xml' ), TRUE ) );
        // SCM: the areas of the scope of the run (a run queued before the scope existed: every area + egress IPs)
        $areas = array( 'config' );
        foreach( explode( ',', $x['areas'] ?? implode( ',', array_merge( array( 'config' ), self::scmPaAreas() ) ) ) as $a )
            if( in_array( $a, self::scmPaAreas(), TRUE ) )
                $areas[] = $a;
        $egress = ( $x['egress'] ?? 'yes' ) === 'yes' && in_array( 'infra', $areas, TRUE );
        $cscope = array_values( array_intersect( self::SCM_CONFIG_GROUPS, explode( ',', $x['cscope'] ?? '' ) ) );
        return array(
            $step( 'scm-export', array_merge( array( 'in=scm-api://' . $k['target'], 'area=' . implode( ',', array_unique( $areas ) ), 'outdir=%JOB%/scm-export', 'config-internal=no' ),
                count( $cscope ) > 0 ? array( 'config-scope=' . implode( ',', $cscope ) ) : array(),
                in_array( 'infra', $areas, TRUE ) ? array( 'egressip-key-out=%JOB%/.egress-key' ) : array(),
                $egress ? array( 'egressip', 'egressip-env=auto' ) : array() ), TRUE ),
            $step( 'scm-export-xml', array( 'in=scm-export://%JOB%/scm-export/' . $k['target'], 'out=%JOB%/out.xml' ), FALSE ) );
    }

    // ------------------------------------------------------------------ App-ID database / MaxMind data
    // the methods: trait ViewerAppContentData (lib/ViewerAppContentData.php)

    // ------------------------------------------------------------------ runs: what the runner reports, the result of an import

    /** $reason of a failed run: 'memory' (killed - out of memory), 'timeout', 'error' */
    public function runnerFinish( int $id, string $state, ?string $error = null, ?string $reason = null ): void
    {
        if( $state === 'failed' && $reason === null )
            $reason = 'error';
        $changed = $this->q( "UPDATE jobs SET state = ?, finished = ?, error = ?, reason = ? WHERE id = ? AND state = 'running'", array( $state, time(), $error, $reason, $id ) )->rowCount();
        if( $changed === 0 )
            return;
        $j = $this->q( 'SELECT j.*, p.pid FROM jobs j JOIN projects p ON p.id = j.project_id WHERE j.id = ?', array( $id ) )->fetch();
        // sensitive inputs of the run (fields 'secret' of a plug-in): gone when the run ends
        if( $j )
            self::rmTree( $this->dataDir . '/projects/' . $j['pid'] . '/jobs/' . $j['jid'] . '/.secret' );
        if( $j && in_array( $j['type'], array( 'import', 'appid', 'geoip', 'ldap', 'ldap-users', 'ldap-discover', 'egress-ip', 'scm-pa', 'psk-list' ), TRUE ) )
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
        // the egress-IP API key the SCM API gave (shared-infrastructure-settings api_key; scm_pa_export.php
        // egressip-key-out=): into the key store of the user who ran the import / live read, the file goes at once
        if( in_array( $j['type'], array( 'import', 'scm-pa' ), TRUE ) && is_file( $dir . '/.egress-key' ) )
        {
            $egressKey = trim( (string)file_get_contents( $dir . '/.egress-key' ) );
            @unlink( $dir . '/.egress-key' );
            $x = $this->jobArgsX( $j );
            $u = $this->userById( (int)$j['user_id'] );
            if( $j['state'] === 'done' && $u && preg_match( '/^scm:([0-9]{1,20})$/', $x['target'] ?? '', $m ) )
                $this->egressKeyFromScm( $u, $m[1], $egressKey );
        }
        // LDAP runs: their results stay in the folder of the run (ldap.json / ldap.csv, out.xml of a remove); egress IPs:
        // taken over by the SCM tab (scmEgressList)
        if( $j['type'] === 'egress-ip' && $j['state'] === 'done' && ( $t = self::runTarget( $j ) ) !== null )
            $this->bindSet( $j['pid'], $t[0], $t[1], self::runRole( $j ) );
        // the PSK list: its results stay in the folder of the run (the PSK lists in .sensitive/, downloadable once)
        if( in_array( $j['type'], array( 'ldap', 'ldap-users', 'ldap-discover', 'egress-ip', 'psk-list' ), TRUE ) )
            return;
        // SCM tab, Prisma Access read live: the export of the run becomes a state of its page
        if( $j['type'] === 'scm-pa' )
        {
            if( $j['state'] !== 'done' )
                return;
            $x = $this->jobArgsX( $j );
            $p = $this->q( 'SELECT * FROM projects WHERE pid = ?', array( $j['pid'] ) )->fetch();
            $u = $this->userById( (int)$j['user_id'] );
            $page = $x['page'] ?? '';
            $n = 0;
            if( $p && preg_match( '/^scm:([0-9]{1,20})$/', $x['target'] ?? '', $m ) && ( $page === 'all' || isset( self::SCM_PA_PAGES[$page] ) ) )
            {
                $n = $this->paCollect( $p, $dir, $m[1], $j['jid'], 'live', $u['name'] ?? '?', (int)( $j['finished'] ?? time() ),
                    $page === 'all' ? array_keys( self::SCM_PA_PAGES ) : self::scmPaPagesOfArea( self::SCM_PA_PAGES[$page]['area'] ) );
                if( $page === 'all' && $this->egressFromExport( $p, $dir, $m[1], $j['jid'], $u['name'] ?? '?', 'live' ) )
                    $n++;
                if( $n > 0 )
                    $this->bindSet( $j['pid'], 'scm', $m[1], self::runRole( $j ) );
            }
            if( $n === 0 )
                $this->q( "UPDATE jobs SET state = 'failed', error = ?, reason = 'error' WHERE id = ?", array( 'nothing was read (see run.log)', $j['id'] ) );
            return;
        }
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
        $role = self::runRole( $j );
        $again = in_array( 'x-import-again=yes', (array)json_decode( $j['args'], TRUE ), TRUE );
        $this->configInsert( $p, $u, ( $kind === 'scm' ? 'scm-' . $host : $host ) . '.xml', $file, null, 'import run ' . substr( $j['jid'], 0, 8 ) . ' from ' . $target
            . ( $role !== null ? ' (role ' . $role . ')' : '' ) . ( $again ? ' - converted again' : '' ) );
        if( in_array( $kind, array( 'panos', 'scm' ), TRUE ) )
            $this->bindSet( $p['pid'], $kind, $host, $role );
        // the SCM import reads the Prisma Access areas as well (scm-export area=config,infra): a state of their pages
        if( $kind === 'scm' && preg_match( '/^[0-9]{1,20}$/', $host ) && !$again )
        {
            $this->paCollect( $p, $dir, $host, $j['jid'], 'import', $u['name'] ?? '?', time(), array_keys( self::SCM_PA_PAGES ) );
            // the egress IPs (scm-export egressip with the api_key of the tenant, prod8 / prod6 / prod): a state of Egress IP
            $this->egressFromExport( $p, $dir, $host, $j['jid'], $u['name'] ?? '?' );
        }
    }

    /**
     * the egress-IP API key of TSG $tsg as the SCM API gave it: a new egress-IP key of the user (label "TSG … (from
     * SCM)"), or the new value of the one the user has (its label stays); an equal value changes nothing
     */
    private function egressKeyFromScm( array $u, string $tsg, string $key ): ?string
    {
        if( strlen( $key ) < 8 || strlen( $key ) > 4000 || preg_match( '/[\s%]/', $key ) )
            return null;
        $old = $this->q( "SELECT * FROM user_keys WHERE user_id = ? AND kind = 'egressip' AND target = ?", array( $u['id'], $tsg ) )->fetch();
        if( !$old )
        {
            $this->keyStore( $u, 'egressip', $tsg, null, 'TSG ' . $tsg . ' (from SCM)', $key );
            return 'added';
        }
        if( $this->unseal( $old['secret'] ) === $key )
            return 'same';
        $this->q( 'UPDATE user_keys SET secret = ?, hint = ?, created = ? WHERE id = ?', array( $this->seal( $key ), substr( $key, -4 ), time(), $old['id'] ) );
        return 'updated';
    }

    /** infra/92_egress-ip.json of the export of a run (read without error) as a state of the egress IPs */
    private function egressFromExport( array $p, string $jobDir, string $tsg, string $id, string $user, string $source = 'SCM import' ): bool
    {
        $files = glob( $jobDir . '/scm-export/' . $tsg . '/*/infra/92_egress-ip.json' ) ?: array();
        if( count( $files ) === 0 || is_file( $this->egressDir( $p ) . '/' . $id . '.json' ) )
            return FALSE;
        rsort( $files );
        self::egressLib();
        try
        {
            $state = SCMEgressIP::fromFile( $files[0] );
        }
        catch( Exception $e )
        {
            return FALSE;
        }
        $raw = (array)json_decode( (string)file_get_contents( $files[0] ), TRUE );
        $this->egressStore( $this->egressDir( $p ), $id, array( 'source' => $source, 'user' => $user, 'time' => time(), 'tsg' => $tsg,
            'request' => $state['request'], 'fetched_at' => $state['fetched_at'], 'name' => isset( $raw['environment'] ) && is_string( $raw['environment'] ) ? $raw['environment'] : null,
            'rows' => $state['rows'] ) );
        return TRUE;
    }

    /** the x-<name>-<field>= arguments of a run (key, target, source, page, …) */
    private function jobArgsX( array $j ): array
    {
        $x = array();
        foreach( (array)json_decode( $j['args'], TRUE ) as $a )
            if( is_string( $a ) && preg_match( '/^x-[a-z]+-([a-z]+)=(.*)$/', $a, $m ) )
                $x[$m[1]] = $m[2];
        return $x;
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
        foreach( array_merge( glob( $this->dataDir . '/projects/*/jobs/*/.panconfkeystore' ) ?: array(), glob( $this->dataDir . '/projects/*/jobs/*/.egress-key' ) ?: array() ) as $f )
            @unlink( $f );
    }

    // ------------------------------------------------------------------ audit log

    /** fields of a request body that are kept in the audit log - never passwords, tokens or file content */
    const AUDIT_FIELDS = array( 'type', 'location', 'filter', 'actions', 'ruletype', 'securityprofiletype', 'user', 'role', 'types', 'scope', 'label', 'days',
        'name', 'playbook', 'predefined', 'bp', 'admin', 'kind', 'enabled', 'subprocess', 'memorythreshold', 'debugmemory', 'removestagefiles', 'other', 'setcommands', 'noruleordercheck', 'xpath',
        'kid', 'source', 'target', 'allow', 'deny', 'qid', 'mode', 'server', 'action', 'domain', 'field', 'hosts', 'decision', 'users', 'conntest', 'network', 'port', 'path', 'row', 'column' );

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

    private function configInsert( array $p, array $user, string $label, string $file, ?int $parentId, string $note, ?string $fromRun = null ): array
    {
        $cid = self::randomId();
        $this->q( 'INSERT INTO configs (cid, project_id, name, file, size, parent_id, note, created_by, created, from_run) VALUES (?,?,?,?,?,?,?,?,?,?)',
            array( $cid, $p['id'], $label, $file, filesize( $this->projectDir( $p['pid'] ) . '/' . $file ), $parentId, $note, $user['id'], time(), $fromRun ) );
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
                if( preg_match( '/\.file$|\.file\./', (string)$op ) || self::filterTouchesFile( 'x ' . $op . ' y' ) )
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
        $this->meta = array( 'types' => $meta, 'ruletypes' => self::RULETYPES, 'securityprofiletypes' => self::SPTYPES_PANOS, 'securityprofiletypes_scm' => self::SPTYPES_SCM, 'securityprofileclasses' => self::SPCLASSES, 'devicetypes' => self::DEVICETYPES,
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
            if( self::filterTouchesFile( $filter ) )
                throw new ViewerException( 'filter operators that read a file are not available here', 400 );
            // nothing of a filter is a shell command: refused here already (pan-os-php never evaluates a filter value)
            if( strpos( $filter, '`' ) !== FALSE )
                throw new ViewerException( 'filter: the character ` is not allowed', 400 );
            $args[] = 'filter=' . $filter;
        }
        return $args;
    }

    /**
     * A filter that reads or writes a file on the server: an operator *.file ( is.in.file, ip4.match.exact.from.file,
     * … ), is.in.csv-report-file, find.dnat.sec.pair.beta ( writes dnatfile.txt ), and the list operators with
     * "@file" instead of a list ( src is.fully.included.in.list @/path - pan-os-php reads the list from that file ).
     */
    private static function filterTouchesFile( string $filter ): bool
    {
        return (bool)preg_match( '/\.file\b|\bis\.in\.csv-report-file\b|\bfind\.dnat\.sec\.pair\b|\.list\s+@/i', $filter );
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
    // the methods: trait ViewerAppWorker (lib/ViewerAppWorker.php)

    // ------------------------------------------------------------------ SCM tab (SCM_TAB.md): egress IP, Prisma Access pages
    // the methods: trait ViewerAppScmTab (lib/ViewerAppScmTab.php); its constants (a trait holds none before PHP 8.2):

    /**
     * the pages of SCM > Prisma Access that show the endpoints of an area of scm_pa_export.php; their states come from
     * the SCM import of the project (it reads these areas too) or from "Read live" (run scm-pa); compared with
     * SCMPrismaAccessCompare (the same as scm_pa_compare.php on the CLI)
     */
    const SCM_PA_PAGES = array(
        // endpoints: those of the area shown on the page (null = every endpoint of the area)
        'infra' => array( 'area' => 'infra', 'endpoints' => array( 'shared-infrastructure-settings', 'bgp-routing', 'internal-dns-servers', 'locations' ) ),
        'sc' => array( 'area' => 'service-connections', 'endpoints' => null ),
        'rn' => array( 'area' => 'remote-networks', 'endpoints' => null ),
        'mugw' => array( 'area' => 'mobile-users', 'endpoints' => array( 'mobile-agent-infrastructure-settings', 'mobile-agent-locations', 'mobile-agent-enable' ) ),
        'mugp' => array( 'area' => 'mobile-users', 'endpoints' => array( 'mobile-agent-authentication-settings', 'mobile-agent-tunnel-profiles', 'mobile-agent-agent-profiles',
            'mobile-agent-global-settings', 'mobile-agent-agent-versions', 'gp-portals', 'gp-clientless-apps', 'gp-clientless-app-groups', 'gp-trusted-zones',
            'certificates', 'trusted-certificate-authorities', 'certificate-profiles', 'tls-service-profiles', 'saml-server-profiles', 'ldap-server-profiles',
            'radius-server-profiles', 'tacacs-server-profiles', 'kerberos-server-profiles', 'mfa-servers', 'local-users', 'local-user-groups',
            'authentication-profiles', 'authentication-sequences' ) ),
        'mupaa' => array( 'area' => 'mobile-users', 'endpoints' => array( 'pa-agent-app-settings', 'pa-agent-client-auth', 'pa-agent-global-settings',
            'pa-agent-token-lifetime', 'pa-agent-staged-rollout', 'pa-agent-tenant-settings', 'pa-agent-project-based-access' ) ),
        'muep' => array( 'area' => 'explicit-proxy', 'endpoints' => null ),
        'pb' => array( 'area' => 'prisma-browser', 'endpoints' => null ),
        'sa' => array( 'area' => 'iam', 'endpoints' => null ),
    );

    /** at most so many keys / changes per list of a compare (the counts are always complete) */
    const PA_COMPARE_MAX = 1000;
}
