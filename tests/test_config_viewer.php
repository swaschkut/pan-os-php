<?php
/**
 * Tests of the config-viewer prototype (utils/develop/config-viewer): login, separation between users, project
 * permissions (read / write / owner), CSRF, input checks, load-once worker, change in memory, save, autosave recovery,
 * service stop.
 *
 *   cd tests && php test_config_viewer.php
 *
 * Starts the PHP built-in web server on a free local port with a temporary data directory. Needs the PHP
 * extensions pdo_sqlite, pcntl, posix. Exit code 0 = all passed.
 */
$here = dirname(__FILE__);
$viewer = realpath( $here . '/../utils/develop/config-viewer' );
$data = sys_get_temp_dir() . '/pan-os-php-test-viewer-' . getmypid();
$input = $here . '/input/panorama-10.0-merger.xml';

foreach( array( 'pdo_sqlite', 'pcntl', 'posix' ) as $ext )
    if( !extension_loaded( $ext ) )
    {
        print "SKIPPED: PHP extension " . $ext . " missing\n";
        exit( 0 );
    }

$failed = array();
$checks = 0;
function eq( $actual, $expected, $msg )
{
    global $failed, $checks;
    $checks++;
    if( $actual !== $expected )
        $failed[] = $msg . "\n      expected " . json_encode($expected) . "\n      got      " . json_encode($actual);
}

// ---- plug-ins: the example plug-in and three that must be refused
$plugins = $data . '-plugins';
foreach( array( 'example', 'wrongapi', 'othername', 'badargs', 'mig' ) as $d )
    mkdir( $plugins . '/' . $d, 0700, TRUE );
copy( $viewer . '/examples/plugins/example/plugin.php', $plugins . '/example/plugin.php' );
file_put_contents( $plugins . '/wrongapi/plugin.php', "<?php return array( 'api' => 99, 'name' => 'wrongapi' );" );
file_put_contents( $plugins . '/othername/plugin.php', "<?php return array( 'api' => 1, 'name' => 'stats' );" );
foreach( array( 'badenv' => "'PANOSPHP_VIEWER_DATA' => '/tmp'", 'badenv2' => "'PANOSPHP_X' => '../../etc'" ) as $d => $e )
{
    mkdir( $plugins . '/' . $d );
    file_put_contents( $plugins . '/' . $d . '/plugin.php', "<?php return array( 'api' => 1, 'name' => '" . $d . "', 'runs' => array( 'r' => array( 'tool' => 'address', 'env' => array( " . $e . " ),
        'args' => function( \$run ) { return array(); } ) ) );" );
}
file_put_contents( $plugins . '/badargs/plugin.php', "<?php return array( 'api' => 1, 'name' => 'badargs', 'runs' => array(
    'in' => array( 'tool' => 'address', 'args' => function( \$run ) { return array( 'in=/etc/passwd' ); } ),
    'out' => array( 'tool' => 'address', 'args' => function( \$run ) { return array( 'actions=display', 'out=/tmp/x.xml' ); } ) ) );" );
// a run type without a version: its input is a raw project file (a small Cisco switch configuration, migrated)
file_put_contents( $plugins . '/mig/plugin.php', "<?php return array( 'api' => 1, 'name' => 'mig',
    'kinds' => array( 'source' => array( 'title' => 'source', 'format' => 'raw', 'max' => 2000,
        'check' => function( \$path ) { if( strpos( file_get_contents( \$path ), 'access-list' ) === FALSE ) return 'no access-list in the file'; } ) ),
    'runs' => array( 'import' => array( 'tool' => 'vendor-migration', 'input' => 'none', 'result' => 'out.xml',
        'fields' => array( array( 'name' => 'vendor', 'kind' => 'select', 'required' => TRUE, 'options' => array( 'ciscoswitch' => 'Cisco switch', 'ciscoisr' => 'Cisco router' ) ),
            array( 'name' => 'kinds', 'kind' => 'multi', 'options' => array( 'address' => 'addresses', 'rule' => 'rules' ) ),
            array( 'name' => 'source', 'kind' => 'file:source', 'required' => TRUE ) ),
        'env' => array( 'PANOSPHP_MIGRATION_PARSERS' => '%PLUGIN%/none' ),
        'args' => function( \$run ) { return array( 'vendor=' . \$run->choice( 'vendor' ), 'file=' . \$run->file( 'source', 'mig-source' ), 'out=' . \$run->out( 'out.xml' ),
            'shadow-ignoreinvalidaddressobjects', '#kinds=' . implode( '+', \$run->choices( 'kinds' ) ) ); } ) ) );" );

// an encrypted plug-in package (licensed feature "test-pack"): its run uses a vendor parser from the package
require_once $here . '/../lib/misc-classes/PluginLicense.php';
require_once $here . '/../lib/misc-classes/PluginPackage.php';
require_once $here . '/plugin_license_helper.php';
$licKeys = testLicenceKeys();
$pkFiles = array( 'plugin.php' => "<?php return array( 'api' => 1, 'name' => 'pack', 'title' => 'Packed', 'version' => '1.0', 'feature' => 'test-pack',
    'kinds' => array( 'cfg' => array( 'title' => 'router configuration', 'format' => 'raw' ) ),
    'runs' => array( 'import' => array( 'title' => 'Packed import', 'tool' => 'vendor-migration', 'input' => 'none', 'result' => 'out.xml',
        'env' => array( 'PANOSPHP_MIGRATION_PARSERS' => '%PLUGIN%/parser' ),
        'fields' => array( array( 'name' => 'source', 'kind' => 'file:cfg', 'required' => TRUE ) ),
        'args' => function( \$run ) { return array( 'vendor=ciscoisr', 'file=' . \$run->file( 'source', 'pack-cfg' ), 'out=' . \$run->out( 'out.xml' ) ); } ) ) );" );
foreach( glob( $here . '/../migration/parser/CISCOISR/*.php' ) as $f )
    $pkFiles['parser/CISCOISR/' . basename( $f )] = file_get_contents( $f );
$pkRel = testPack( $plugins, 'pack', '1.0', 'test-pack', $pkFiles );

// ---- users, server
$env = array( 'PANOSPHP_VIEWER_DATA' => $data, 'PATH' => getenv('PATH'), 'PANOSPHP_VIEWER_AUTOSAVE_MIN' => '1', 'PANOSPHP_VIEWER_PLUGINS' => $plugins,
    'PANOSPHP_LICENSE_TEST_KEYS' => testTrustedJson( $licKeys ) );
// the command line makes users only until there is an administrator: alice (admin) last
foreach( array( 'bob' => 'bob-secret-12', 'carol' => 'carol-secret-3', 'alice' => 'alice-secret-1 admin' ) as $name => $spec )
{
    $parts = explode( ' ', $spec );
    $p = proc_open( array( PHP_BINARY, $viewer . '/bin/user.php', 'add', $name, $parts[1] ?? '' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null,
        $env + array( 'VIEWER_PASSWORD' => $parts[0] ) );
    stream_get_contents( $pipes[1] );
    proc_close( $p );
}
$null = array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'file', '/dev/null', 'w' ), 2 => array( 'file', '/dev/null', 'w' ) );
$service = proc_open( array( PHP_BINARY, $viewer . '/bin/service.php' ), $null, $pipes, $viewer, $env );
for( $i = 0; $i < 50 && !file_exists( $data . '/service.sock' ); $i++ )
    usleep( 100000 );
$jobs = proc_open( array( PHP_BINARY, $viewer . '/bin/jobs.php' ), $null, $pipes, $viewer, $env + array( 'PANOSPHP_VIEWER_JOBS' => '1' ) );
$sock = stream_socket_server( 'tcp://127.0.0.1:0' );
$port = (int)substr( strrchr( stream_socket_get_name( $sock, FALSE ), ':' ), 1 );
fclose( $sock );
$server = proc_open( array( PHP_BINARY, '-d', 'upload_max_filesize=200M', '-d', 'post_max_size=210M', '-S', '127.0.0.1:' . $port, '-t', $viewer ), array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'file', '/dev/null', 'w' ),
    2 => array( 'file', '/dev/null', 'w' ) ), $pipes, $viewer, $env + array( 'PHP_CLI_SERVER_WORKERS' => '4' ) );
$base = 'http://127.0.0.1:' . $port . '/';
for( $i = 0; $i < 50 && @file_get_contents( $base . 'index.html' ) === FALSE; $i++ )
    usleep( 100000 );

function cleanup()
{
    global $server, $data;
    foreach( glob( $data . '/projects/*/work/*.pid' ) ?: array() as $f )
        @posix_kill( (int)file_get_contents( $f ), SIGKILL );
    foreach( array( $server, $GLOBALS['service'], $GLOBALS['jobs'] ) as $proc )
        if( is_resource( $proc ) )
        {
            proc_terminate( $proc );
            proc_close( $proc );
        }
    exec( 'rm -rf ' . escapeshellarg( $data ) . ' ' . escapeshellarg( $data . '-plugins' ) );
}
register_shutdown_function( 'cleanup' );

/** a browser: keeps the session cookie and the CSRF token of one user */
class Client
{
    public $cookie = '';
    public $csrf = null;
    public $sendCsrf = TRUE;
    public $bearer = null;

    /** @return array [ status, decoded JSON or raw body ] */
    function call( $method, $path, $body = null, $upload = null )
    {
        global $base;
        $headers = array();
        if( $this->bearer !== null ) $headers[] = 'Authorization: Bearer ' . $this->bearer;
        if( $this->cookie !== '' ) $headers[] = 'Cookie: ' . $this->cookie;
        if( $method !== 'GET' && $this->csrf !== null && $this->sendCsrf ) $headers[] = 'X-CSRF-Token: ' . $this->csrf;
        $content = null;
        if( $upload !== null )
        {
            $b = '----viewertest' . bin2hex( random_bytes( 6 ) );
            $headers[] = 'Content-Type: multipart/form-data; boundary=' . $b;
            $content = "--" . $b . "\r\nContent-Disposition: form-data; name=\"" . ( $upload[2] ?? 'config' ) . "\"; filename=\"" . $upload[0] . "\"\r\nContent-Type: text/xml\r\n\r\n" . $upload[1] . "\r\n--" . $b . "--\r\n";
        }
        elseif( $body !== null )
        {
            $headers[] = 'Content-Type: application/json';
            $content = json_encode( $body );
        }
        $ctx = stream_context_create( array( 'http' => array( 'method' => $method, 'header' => implode( "\r\n", $headers ), 'content' => $content,
            'ignore_errors' => TRUE, 'timeout' => 120 ) ) );
        $raw = file_get_contents( $base . 'api.php/' . $path, FALSE, $ctx );
        $status = 0;
        foreach( $http_response_header ?? array() as $h )
        {
            if( preg_match( '#^HTTP/\S+ (\d+)#', $h, $m ) ) $status = (int)$m[1];
            if( preg_match( '#^Set-Cookie: (PANOSPHPVIEWER=[^;]*)#i', $h, $m ) ) $this->cookie = $m[1];
        }
        $json = json_decode( (string)$raw, TRUE );
        return array( $status, is_array( $json ) ? $json : $raw );
    }

    function login( $user, $password )
    {
        $r = $this->call( 'POST', 'login', array( 'user' => $user, 'password' => $password ) );
        if( $r[0] === 200 ) $this->csrf = $r[1]['csrf'];
        return $r;
    }
}
function status( $r ) { return $r[0]; }

$xml = file_get_contents( $input );
$anon = new Client();
$alice = new Client();
$bob = new Client();
$carol = new Client();

// ---- 1. nothing without login
eq( status( $anon->call( 'GET', 'projects' ) ), 401, 'no login: projects' );
eq( status( $anon->call( 'GET', 'meta' ) ), 401, 'no login: meta' );
eq( status( $anon->call( 'POST', 'projects', array( 'name' => 'x' ) ) ), 401, 'no login: create project' );
eq( status( $anon->call( 'GET', 'projects/' . str_repeat( 'a', 32 ) . '/configs/' . str_repeat( 'b', 32 ) . '/objects?type=address' ) ), 401, 'no login: objects' );
eq( status( $anon->login( 'alice', 'wrong-password' ) ), 401, 'wrong password' );
eq( status( $anon->login( 'nobody', 'wrong-password' ) ), 401, 'unknown user gives the same answer' );
foreach( array( 'bin/worker.php', 'bin/user.php', 'bin/jobs.php' ) as $f )
{
    @file_get_contents( $base . $f );
    eq( (int)substr( $http_response_header[0], 9, 3 ), 404, $f . ' is not callable through the web server' );
}

// ---- 2. login, CSRF
eq( status( $alice->login( 'alice', 'alice-secret-1' ) ), 200, 'alice logs in' );
eq( status( $bob->login( 'bob', 'bob-secret-12' ) ), 200, 'bob logs in' );
eq( status( $carol->login( 'carol', 'carol-secret-3' ) ), 200, 'carol logs in' );
$alice->sendCsrf = FALSE;
eq( status( $alice->call( 'POST', 'projects', array( 'name' => 'no token' ) ) ), 403, 'changing request without CSRF token' );
$alice->sendCsrf = TRUE;

// ---- 3. alice: project, upload
$r = $alice->call( 'POST', 'projects', array( 'name' => 'Alice project' ) );
eq( status( $r ), 201, 'alice creates a project' );
$pid = $r[1]['pid'] ?? '';
$P = 'projects/' . $pid;
eq( status( $alice->call( 'POST', $P . '/configs', null, array( 'notes.xml', 'hello' ) ) ), 400, 'upload: not XML' );
eq( status( $alice->call( 'POST', $P . '/configs', null, array( 'other.xml', '<?xml version="1.0"?><other><config/></other>' ) ) ), 400, 'upload: XML with another root element' );
$r = $alice->call( 'POST', $P . '/configs', null, array( '../../evil name.xml', $xml ) );
eq( status( $r ), 201, 'alice uploads a configuration' );
$cid = $r[1]['cid'] ?? '';
$C = $P . '/configs/' . $cid;
$stored = glob( $data . '/projects/' . $pid . '/*.xml' );
eq( count( $stored ) === 1 && (bool)preg_match( '/^[0-9a-f]{32}\.xml$/', basename( $stored[0] ) ), TRUE, 'the upload is stored under a random name, not the given file name' );

// ---- 4. full separation: bob has no access and can not tell the project exists
eq( $bob->call( 'GET', 'projects' )[1], array( 'projects' => array() ), 'bob: project list is empty' );
foreach( array( array( 'GET', $P ), array( 'GET', $P . '/members' ), array( 'GET', $P . '/configs' ), array( 'GET', $C . '/objects?type=address' ),
             array( 'GET', $C . '/download' ), array( 'GET', $C . '/status' ), array( 'POST', $C . '/change', array( 'type' => 'address', 'actions' => 'delete' ) ),
             array( 'POST', $C . '/save' ), array( 'POST', $C . '/discard' ), array( 'DELETE', $C ), array( 'DELETE', $P ),
             array( 'PUT', $P . '/members', array( 'user' => 'bob', 'role' => 'write' ) ) ) as $t )
    eq( status( $bob->call( $t[0], $t[1], $t[2] ?? null ) ), 404, 'bob without access: ' . $t[0] . ' ' . preg_replace( '/[0-9a-f]{32}/', '…', $t[1] ) . ' -> 404' );
eq( status( $bob->call( 'POST', $P . '/configs', null, array( 'b.xml', $xml ) ) ), 404, 'bob without access: upload -> 404' );
eq( status( $bob->call( 'GET', 'users' ) ), 404, 'bob is no admin: user list' );
eq( status( $bob->call( 'POST', 'users', array( 'user' => 'mallory', 'password' => 'mallory-secret' ) ) ), 404, 'bob is no admin: create user' );

// ---- 5. input checks (alice, owner)
eq( status( $alice->call( 'GET', 'projects/' . str_repeat( '.', 32 ) . '/configs' ) ), 404, 'project id that is not an id (dots)' );
eq( status( $alice->call( 'GET', 'projects/' . $pid . '%00/configs' ) ), 404, 'project id with a NUL byte' );
eq( status( $alice->call( 'GET', 'projects/' . strtoupper( $pid ) . 'x/configs' ) ), 404, 'project id with extra characters' );
eq( status( $alice->call( 'GET', $P . '/configs/' . basename( $stored[0], '.xml' ) . '/download' ) ), 404, 'the file name on disk is not a usable config id' );
eq( status( $alice->call( 'GET', $C . '/objects?type=upload' ) ), 400, 'type outside the whitelist' );
eq( status( $alice->call( 'GET', $C . '/objects?type=address&location=' . urlencode( '../../x' ) ) ), 400, 'location with path characters' );
eq( status( $alice->call( 'GET', $C . '/objects?type=address&filter=' . urlencode( '(name is.in.file /etc/passwd)' ) ) ), 400, 'filter that reads a file' );
eq( status( $alice->call( 'POST', $C . '/change', array( 'type' => 'address', 'actions' => 'exporttoexcel:/tmp/x.xls' ) ) ), 400, 'action that writes a file' );
eq( status( $alice->call( 'POST', $C . '/change', array( 'type' => 'address', 'actions' => 'display/create-address-from-file:/etc/passwd' ) ) ), 400, 'second action not offered' );

// ---- 6. read: loaded once
$t = microtime( TRUE );
$r = $alice->call( 'GET', $C . '/objects?type=address&location=any' );
$first = microtime( TRUE ) - $t;
eq( status( $r ), 200, 'alice reads addresses' );
eq( $r[1]['total'] ?? null, 27, 'all 27 address objects' );
$t = microtime( TRUE );
$r = $alice->call( 'GET', $C . '/objects?type=rule&location=any' );
$second = microtime( TRUE ) - $t;
eq( status( $r ) === 200 && $r[1]['total'] > 0, TRUE, 'alice reads rules' );
eq( $second < $first, TRUE, 'second request does not load the configuration again (' . round( $first, 2 ) . ' s / ' . round( $second, 2 ) . ' s)' );
eq( count( glob( $data . '/projects/' . $pid . '/work/*.pid' ) ), 1, 'exactly one worker for the version' );
$r = $alice->call( 'GET', $C . '/objects?type=address&location=nosuchlocation' );
eq( status( $r ), 400, 'unknown location is an error (400), not 200' );
eq( strpos( json_encode( $r[1] ), $data ) === FALSE && strpos( json_encode( $r[1] ), dirname( $viewer ) ) === FALSE, TRUE, 'error text without server paths' );
eq( status( $alice->call( 'GET', $C . '/objects?type=address&filter=' . urlencode( '(name nosuchoperator x)' ) ) ), 400, 'bad filter is an error' );
eq( status( $alice->call( 'GET', $C . '/objects?type=tag' ) ), 200, 'the loaded configuration still answers after errors' );

// ---- 7. member with read: sees, can not change
eq( status( $alice->call( 'PUT', $P . '/members', array( 'user' => 'bob', 'role' => 'owner' ) ) ), 400, 'role outside read / write' );
eq( status( $alice->call( 'PUT', $P . '/members', array( 'user' => 'bob', 'role' => 'read' ) ) ), 200, 'alice gives bob read' );
eq( count( $bob->call( 'GET', 'projects' )[1]['projects'] ), 1, 'bob sees the project now' );
eq( $bob->call( 'GET', $C . '/objects?type=address&location=any' )[1]['total'] ?? null, 27, 'bob (read) reads addresses' );
eq( status( $bob->call( 'GET', $C . '/download' ) ), 200, 'bob (read) downloads' );
$change = array( 'type' => 'address', 'location' => 'shared', 'filter' => '(name eq shared-host1)', 'actions' => 'description-append:VIEWERTEST' );
foreach( array( array( 'POST', $C . '/change', $change ), array( 'POST', $C . '/save' ), array( 'POST', $C . '/discard' ), array( 'DELETE', $C ),
             array( 'DELETE', $P ), array( 'PUT', $P . '/members', array( 'user' => 'carol', 'role' => 'write' ) ) ) as $t )
    eq( status( $bob->call( $t[0], $t[1], $t[2] ?? null ) ), 403, 'bob (read): ' . $t[0] . ' ' . preg_replace( '/[0-9a-f]{32}/', '…', $t[1] ) . ' -> 403' );
eq( status( $bob->call( 'POST', $P . '/configs', null, array( 'b.xml', $xml ) ) ), 403, 'bob (read): upload -> 403' );
eq( status( $carol->call( 'GET', $C . '/objects?type=address' ) ), 404, 'carol still has no access' );

// ---- 8. member with write: change in memory, nothing written until save
eq( status( $alice->call( 'PUT', $P . '/members', array( 'user' => 'bob', 'role' => 'write' ) ) ), 200, 'alice gives bob write' );
$r = $bob->call( 'POST', $C . '/change', array( 'type' => 'address', 'location' => 'shared', 'actions' => 'tag-add:tag-that-does-not-exist' ) );
eq( status( $r ), 400, 'failing action is an error' );
eq( $bob->call( 'GET', $C . '/status' )[1]['dirty'] ?? null, FALSE, 'a failing action changes nothing' );
$r = $bob->call( 'POST', $C . '/change', $change );
eq( status( $r ), 200, 'bob (write) changes an object' );
eq( $r[1]['status']['dirty'] ?? null, TRUE, 'unsaved change is reported' );
$r = $alice->call( 'GET', $C . '/objects?type=address&location=shared&filter=' . urlencode( '(name eq shared-host1)' ) );
eq( $r[1]['rows'][0]['description'] ?? null, 'VIEWERTEST', 'the change is visible in the loaded configuration (also for alice)' );
eq( strpos( file_get_contents( $stored[0] ), 'VIEWERTEST' ), FALSE, 'the file of the version is not touched by a change' );
// the change list: every change as data (time, user, type, location, filter, actions, field) - the object window
$ch = end( $r[1]['status']['changes'] );
eq( array( is_array( $ch ), $ch['user'] ?? null, $ch['type'] ?? null, $ch['location'] ?? null, $ch['actions'] ?? null, is_int( $ch['time'] ?? null ) ),
    array( TRUE, 'bob', 'address', 'shared', 'description-append:VIEWERTEST', TRUE ), 'change list: the change as data' );
// the object window: one object with its fields and its structured model
$r = $bob->call( 'GET', $C . '/object?type=address&location=shared&name=shared-host1' );
eq( array( status( $r ), $r[1]['row']['name'] ?? null, $r[1]['row']['description'] ?? null, $r[1]['model']['ip_netmask'] ?? null, $r[1]['model']['tag'] ?? null, isset( $r[1]['row']['model'] ) ),
    array( 200, 'shared-host1', 'VIEWERTEST', '1.2.2.3/32', array( 'grp.shared-group1' ), FALSE ), 'object window: one object, fields and model' );
eq( array( status( $bob->call( 'GET', $C . '/object?type=address&location=shared&name=nope' ) ), status( $bob->call( 'GET', $C . '/object?type=address&location=any&name=shared-host1' ) ),
    status( $bob->call( 'GET', $C . '/object?type=address&location=shared&name=' . urlencode( 'a) or (name regex /./' ) ) ) ), array( 404, 400, 400 ),
    'object window: not found; a location is needed; no brackets in the name' );
$r = $bob->call( 'POST', $C . '/change', array( 'type' => 'address', 'location' => 'Datacenter-Firewalls', 'filter' => '(name eq new test 1)', 'actions' => 'tag-add:tag-that-does-not-exist', 'field' => 'tag' ) );
eq( status( $r ), 400, 'object window: a name with spaces in the filter, a failing action is an error' );
// address name-rename: offered (its class is "network" only because of $$reverse-dns$$) - that alias is refused
eq( isset( $alice->call( 'GET', 'meta' )[1]['types']['address']['actions']['name-rename'] ), TRUE, 'meta: address name-rename offered (guarded)' );
$r = $bob->call( 'POST', $C . '/change', array( 'type' => 'address', 'location' => 'shared', 'filter' => '(name eq shared-host2)', 'actions' => 'name-rename:$$reverse-dns$$' ) );
eq( array( status( $r ), strpos( $r[1]['error'] ?? '', 'reach the network' ) !== FALSE ), array( 400, TRUE ), 'name-rename with $$reverse-dns$$ refused' );
eq( ( $alice->call( 'GET', 'meta' )[1]['types']['tag']['actions']['color-set'][0]['choices'] ?? array() )[1] ?? null, 'red', 'meta: the choices of an argument (color-set)' );
// the rule window: a rule of a rule type, changed field by field (description with the aliases of pan-os-php)
$r = $bob->call( 'GET', $C . '/object?type=rule&ruletype=security&location=shared&name=' . urlencode( 'shared pre rule 1' ) );
eq( array( status( $r ), $r[1]['model']['rulebase'] ?? null, $r[1]['model']['action'] ?? null, $r[1]['model']['source'] ?? null ), array( 200, 'pre', 'allow', array( 'any' ) ), 'rule window: a security rule with its model' );
eq( status( $bob->call( 'GET', $C . '/object?type=rule&ruletype=nat&location=shared&name=' . urlencode( 'shared pre rule 1' ) ) ), 404, 'rule window: the rule type counts' );
foreach( array( 'description-append:a$$comma$$ b$$colon$$ c', 'src-add:shared-host2', 'action-set:deny', 'disabled-set:true' ) as $a )
    $bob->call( 'POST', $C . '/change', array( 'type' => 'rule', 'ruletype' => 'security', 'location' => 'shared', 'filter' => '(name eq shared pre rule 1)', 'actions' => $a, 'field' => 'x' ) );
$r = $bob->call( 'GET', $C . '/object?type=rule&ruletype=security&location=shared&name=' . urlencode( 'shared pre rule 1' ) );
eq( array( $r[1]['row']['description'] ?? null, $r[1]['model']['source'] ?? null, $r[1]['model']['action'] ?? null, $r[1]['row']['disabled'] ?? null ),
    array( 'a, b: c', array( 'shared-host2' ), 'deny', 'true' ), 'rule window: description (aliases), source, action, disabled changed' );
eq( count( glob( $data . '/projects/' . $pid . '/*.xml' ) ), 1, 'no new file before save' );
eq( status( $bob->call( 'DELETE', $P ) ), 403, 'bob (write) can not delete the project' );

// ---- 9. save = new version, old version unchanged
$r = $bob->call( 'POST', $C . '/save' );
eq( status( $r ) === 200 && $r[1]['saved'] === TRUE, TRUE, 'bob saves' );
$cid2 = $r[1]['cid'] ?? '';
$C2 = $P . '/configs/' . $cid2;
eq( $cid2 !== '' && $cid2 !== $cid, TRUE, 'save creates a new version' );
eq( strpos( (string)$alice->call( 'GET', $C2 . '/download' )[1], 'VIEWERTEST' ) !== FALSE, TRUE, 'new version contains the change' );
eq( strpos( (string)$alice->call( 'GET', $C . '/download' )[1], 'VIEWERTEST' ), FALSE, 'old version is unchanged' );
$list = $alice->call( 'GET', $P . '/configs' )[1]['configs'];
eq( count( $list ) === 2 && $list[0]['parent'] === $cid && strpos( $list[0]['note'], 'description-append:VIEWERTEST [bob]' ) !== FALSE, TRUE, 'version history: parent, action and user' );
eq( $bob->call( 'POST', $C2 . '/save' )[1]['saved'] ?? null, FALSE, 'save without changes writes nothing' );

// ---- 10. a stopped worker with unsaved changes: recovered as a version
$bob->call( 'POST', $C2 . '/change', array( 'type' => 'address', 'location' => 'shared', 'filter' => '(name eq shared-host2)', 'actions' => 'description-append:RECOVERME' ) );
foreach( glob( $data . '/projects/' . $pid . '/work/*.pid' ) as $f )
    posix_kill( (int)file_get_contents( $f ), SIGTERM );
for( $i = 0; $i < 50 && count( glob( $data . '/projects/' . $pid . '/work/*.pid' ) ) > 0; $i++ )
    usleep( 100000 );
eq( status( $alice->call( 'GET', $C2 . '/objects?type=tag' ) ), 200, 'the version loads again after its worker was stopped' );
$list = $alice->call( 'GET', $P . '/configs' )[1]['configs'];
eq( count( $list ) === 3 && strpos( $list[0]['note'], 'autosave (recovered' ) === 0, TRUE, 'unsaved changes of the stopped worker are a version "autosave (recovered …)"' );
eq( strpos( (string)$alice->call( 'GET', $P . '/configs/' . $list[0]['cid'] . '/download' )[1], 'RECOVERME' ) !== FALSE, TRUE, 'the recovered version contains the unsaved change' );

// ---- 11. discard, remove member, delete
$bob->call( 'POST', $C2 . '/change', array( 'type' => 'address', 'location' => 'shared', 'filter' => '(name eq shared-host2)', 'actions' => 'description-append:DISCARDME' ) );
eq( status( $bob->call( 'POST', $C2 . '/discard' ) ), 200, 'bob discards' );
$r = $alice->call( 'GET', $C2 . '/objects?type=address&location=shared&filter=' . urlencode( '(name eq shared-host2)' ) );
eq( strpos( (string)( $r[1]['rows'][0]['description'] ?? '' ), 'DISCARDME' ), FALSE, 'discarded change is gone' );
eq( status( $alice->call( 'DELETE', $P . '/members/bob' ) ), 200, 'alice removes bob' );
eq( status( $bob->call( 'GET', $C2 . '/objects?type=address' ) ), 404, 'bob has no access any more' );
eq( $bob->call( 'GET', 'projects' )[1], array( 'projects' => array() ), 'bob: project list is empty again' );
eq( status( $alice->call( 'DELETE', $P ) ), 200, 'alice deletes the project' );
eq( is_dir( $data . '/projects/' . $pid ), FALSE, 'project folder is removed' );
eq( status( $alice->call( 'GET', $P ) ), 404, 'deleted project is gone' );

// ---- 12. admin, logout, lockout
eq( status( $alice->call( 'POST', 'users', array( 'user' => 'dave', 'password' => 'short' ) ) ), 400, 'admin: password too short' );
eq( status( $alice->call( 'POST', 'users', array( 'user' => 'dave', 'password' => 'dave-secret-45' ) ) ), 201, 'admin creates a user' );
eq( strpos( file_get_contents( $data . '/viewer.sqlite' ), 'dave-secret-45' ), FALSE, 'the password is not stored in clear text' );
eq( status( $alice->call( 'POST', 'logout' ) ), 200, 'logout' );
eq( status( $alice->call( 'GET', 'projects' ) ), 401, 'the session is gone after logout' );
for( $i = 0; $i < 5; $i++ )
    $anon->login( 'carol', 'wrong-' . $i );
eq( status( $anon->login( 'carol', 'carol-secret-3' ) ), 429, 'too many failed logins block the login for a while' );

// ---- 12r. REST resources per type
$alice = new Client(); $alice->login( 'alice', 'alice-secret-1' );
$r = $alice->call( 'POST', 'projects', array( 'name' => 'REST' ) );
$R = 'projects/' . $r[1]['pid'];
$r = $alice->call( 'POST', $R . '/configs', null, array( 'r.xml', $xml ) );
$RC = $R . '/configs/' . $r[1]['cid'];
$meta = $alice->call( 'GET', 'meta' )[1]['types'];
eq( array( $meta['address']['resource'], $meta['securityprofile']['resource'], $meta['address']['readonly'], $meta['application']['readonly'] ?? null ),
    array( 'addresses', 'security-profiles', FALSE, TRUE ), 'REST: meta lists resource names; other display types are read only' );
eq( count( $meta ) > 25, TRUE, 'REST: all types with objects are offered (' . count( $meta ) . ')' );
// locations of a version (choice in the page) and the filters with operators (suggestions in the page)
$r = $alice->call( 'GET', $RC . '/locations' );
eq( array( status( $r ), $r[1]['config'] ?? null, $r[1]['any'] ?? null, array_column( $r[1]['locations'] ?? array(), 'name' ), array_values( array_unique( array_column( $r[1]['locations'] ?? array(), 'kind' ) ) ) ),
    array( 200, 'panorama', TRUE, array( 'shared', 'Perimeter-FWs', 'Datacenter-Firewalls', 'testDG', 'DE-Berlin Office', 'FR Datacenter' ), array( 'shared', 'device-group' ) ),
    'locations: Panorama - shared and every device group' );
$fw = '<?xml version="1.0"?><config version="10.1.0" urldb="paloaltonetworks"><mgt-config/><shared><address><entry name="h1"><ip-netmask>1.1.1.1</ip-netmask></entry></address></shared>'
    . '<devices><entry name="localhost.localdomain"><deviceconfig><system><hostname>fw1</hostname></system></deviceconfig><vsys><entry name="vsys1"/><entry name="vsys2"/></vsys></entry></devices></config>';
$fwc = $alice->call( 'POST', $R . '/configs', null, array( 'fw.xml', $fw ) )[1]['cid'] ?? '';
$r = $alice->call( 'GET', $R . '/configs/' . $fwc . '/locations' );
eq( array( $r[1]['config'] ?? null, array_column( $r[1]['locations'] ?? array(), 'name' ) ), array( 'firewall', array( 'shared', 'vsys1', 'vsys2' ) ), 'locations: firewall - shared and every vsys' );
$scmc = $alice->call( 'POST', $R . '/configs', null, array( 'scm.xml', file_get_contents( $here . '/input/SCM-import.xml' ) ) )[1]['cid'] ?? '';
$r = $alice->call( 'GET', $R . '/configs/' . $scmc . '/locations' );
if( ( $r[1]['config'] ?? '' ) !== 'scm' ) print "SCM locations: " . json_encode( $r ) . " cid " . json_encode( $scmc ) . "\n";
$kinds = array_values( array_unique( array_column( $r[1]['locations'] ?? array(), 'kind' ) ) );
sort( $kinds );
eq( array( $r[1]['config'] ?? null, $kinds, in_array( 'All', array_column( $r[1]['locations'] ?? array(), 'name' ), TRUE ) ), array( 'scm', array( 'container', 'snippet' ), TRUE ),
    'locations: SCM - containers (folders) and snippets' );
foreach( array( $fwc, $scmc ) as $x )
    $alice->call( 'DELETE', $R . '/configs/' . $x );
$nf = $meta['address']['filters'] ?? array();
eq( array( $nf['name']['eq'] ?? null, $nf['object']['is.unused']['arg'] ?? null, isset( $nf['name']['is.in.file'] ), isset( $nf['value']['ip4.match.exact.from.file'] ) ),
    array( array( 'arg' => TRUE, 'example' => '(name eq new test 1)', 'help' => 'returns TRUE if object name matches the one specified in argument' ), FALSE, FALSE, FALSE ),
    'meta: filters with operators - needs a value, example, help; no operators that read a file' );
// who uses an object (actions=displayreferences): the page shows it below the object and opens the user
eq( array( $meta['address']['references'] ?? null, $meta['service']['references'] ?? null, $meta['rule']['references'] ?? null ), array( TRUE, TRUE, FALSE ),
    'meta: which types have references' );
$r = $alice->call( 'GET', $RC . '/references?type=address&location=any&name=' . rawurlencode( 'new test 2' ) );
$byLoc = array_column( $r[1]['objects'] ?? array(), null, 'location' );
$refs = array_column( $byLoc['shared']['references'] ?? array(), null, 'name' );
eq( array( status( $r ), array_keys( $byLoc ), count( $refs ), $refs['shared post rule 1'] ?? null ),
    array( 200, array( 'shared', 'Datacenter-Firewalls' ), 6, array( 'type' => 'rule', 'ruletype' => 'security', 'securityprofiletype' => null, 'location' => 'shared',
        'name' => 'shared post rule 1', 'class' => 'SecurityRule', 'rulebase' => 'post', 'fields' => array( 'source' ), 'open' => TRUE ) ),
    'references: every object of the name, its users with type, rule type, location, pre / post, field' );
eq( array( $refs['test']['ruletype'] ?? null, $refs['test']['location'] ?? null, $refs['test']['fields'] ?? null, $refs['group-with-duplicate-child']['type'] ?? null ),
    array( 'nat', 'DE-Berlin Office', array( 'source', 'destination', 'snathosts' ), 'address' ), 'references: NAT rule in a device group with all its fields, an address group' );
$r = $alice->call( 'GET', $RC . '/references?type=address&location=shared&name=nothing-like-this' );
eq( array( status( $r ), $r[1]['objects'] ?? null ), array( 200, array() ), 'references: an unknown name - no object' );
eq( status( $alice->call( 'GET', $RC . '/references?type=rule&location=any&name=x' ) ), 400, 'references: a type without references' );
eq( status( $alice->call( 'GET', $RC . '/references?type=address&location=any' ) ), 400, 'references: the name is needed' );
// the list of the page counts the users of every object (refcount after name) - the same users References shows
$r = $alice->call( 'GET', $RC . '/objects?type=address&location=any' );
$rc = array();
foreach( $r[1]['rows'] ?? array() as $row )
    $rc[$row['location'] . '|' . $row['name']] = $row['refcount'] ?? 'missing';
$cols = $r[1]['columns'] ?? array();
eq( array( $rc['shared|new test 2'] ?? null, $rc['shared|another object'] ?? null, $rc['Datacenter-Firewalls|new test 2'] ?? null, array_search( 'refcount', $cols ) === array_search( 'name', $cols ) + 1 ),
    array( 6, 0, count( array_column( $byLoc['Datacenter-Firewalls']['references'] ?? array(), 'name' ) ), TRUE ), 'list: refcount per object, right after the name' );
eq( array_key_exists( 'refcount', $alice->call( 'GET', $RC . '/addresses?model=display-v0&limit=1' )[1]['items'][0] ?? array() ), FALSE, 'REST: no refcount in the items' );
eq( in_array( 'refcount', $alice->call( 'GET', $RC . '/objects?type=rule&location=any' )[1]['columns'] ?? array(), TRUE ), FALSE, 'list: no refcount for a type without references' );
$r = $alice->call( 'GET', $RC . '/addresses?model=display-v0' );
eq( array( status( $r ), $r[1]['type'] ?? null, $r[1]['total'] ?? null, count( $r[1]['items'] ?? array() ), $r[1]['model'] ?? null ), array( 200, 'address', 27, 27, 'display-v0' ), 'REST: GET addresses, display-v0 (objects and groups)' );
eq( isset( $r[1]['items'][0]['model'] ), FALSE, 'REST: display-v0 items carry no model field' );
$r = $alice->call( 'GET', $RC . '/addresses?model=display-v0&location=shared&limit=5&offset=10' );
eq( array( status( $r ), $r[1]['total'] ?? null, count( $r[1]['items'] ?? array() ), $r[1]['offset'] ?? null ), array( 200, 13, 3, 10 ), 'REST: paging (13 in shared, offset 10, limit 5)' );
// SCM object model (scm-v1): SCM resources and fields
$a = $alice->call( 'GET', $RC . '/addresses' );
$g = $alice->call( 'GET', $RC . '/address-groups' );
eq( array( $a[1]['model'] ?? null, $g[1]['model'] ?? null, ( $a[1]['total'] ?? 0 ) + ( $g[1]['total'] ?? 0 ) ), array( 'scm-v1', 'scm-v1', 27 ), 'scm-v1: addresses + address-groups = the 27 objects of type address' );
$one = $alice->call( 'GET', $RC . '/addresses/shared-host1' )[1]['items'][0] ?? null;
eq( $one, array( 'name' => 'shared-host1', 'ip_netmask' => '1.2.2.3/32', 'tag' => array( 'grp.shared-group1' ), 'device_group' => 'shared' ), 'scm-v1: address as the SCM API (ip_netmask, tag list) + device_group' );
$grp = null;
foreach( $g[1]['items'] ?? array() as $x ) if( isset( $x['static'] ) ) { $grp = $x; break; }
eq( array( is_array( $grp['static'] ?? null ), isset( $grp['device_group'] ) ), array( TRUE, TRUE ), 'scm-v1: static address group with member names' );
$dyn = null;
foreach( $g[1]['items'] ?? array() as $x ) if( isset( $x['dynamic'] ) ) { $dyn = $x; break; }
eq( isset( $dyn['dynamic']['filter'] ), TRUE, 'scm-v1: dynamic address group with filter' );
$sv = $alice->call( 'GET', $RC . '/services' );
$sg = $alice->call( 'GET', $RC . '/service-groups' );
eq( ( $sv[1]['total'] ?? 0 ) + ( $sg[1]['total'] ?? 0 ), 17, 'scm-v1: services + service-groups = the 17 objects of type service' );
eq( isset( $sv[1]['items'][0]['protocol'] ), TRUE, 'scm-v1: service with protocol' );
eq( is_array( $sg[1]['items'][0]['members'] ?? null ), TRUE, 'scm-v1: service group with members' );
$tg = $alice->call( 'GET', $RC . '/tags' );
eq( array( $tg[1]['model'] ?? null, $tg[1]['total'] ?? null ), array( 'scm-v1', 6 ), 'scm-v1: tags' );
$locs = array();
foreach( $a[1]['items'] ?? array() as $x ) $locs[ isset( $x['device_group'] ) ? 'device_group' : implode( ',', array_keys( $x ) ) ] = TRUE;
eq( array_keys( $locs ), array( 'device_group' ), 'scm-v1: every Panorama object has device_group' );
foreach( array( 'schedules', 'url-categories', 'external-dynamic-lists', 'log-forwarding-profiles' ) as $res )
{
    $r = $alice->call( 'GET', $RC . '/' . $res );
    eq( array( status( $r ), $r[1]['model'] ?? null, $r[1]['resource'] ?? null ), array( 200, 'scm-v1', $res ), 'scm-v1: ' . $res );
}
$r = $alice->call( 'GET', $RC . '/log-forwarding-profiles' );
eq( array( $r[1]['total'] ?? null, isset( $r[1]['items'][0]['name'] ), isset( $r[1]['items'][0]['device_group'] ) ), array( 1, TRUE, TRUE ), 'scm-v1: the log forwarding profile of the test configuration' );
foreach( array( 'anti-spyware-profiles' => 'rules', 'vulnerability-protection-profiles' => 'rules', 'url-access-profiles' => 'name', 'file-blocking-profiles' => 'rules',
             'antivirus-profiles' => 'decoder', 'wildfire-analysis-profiles' => 'rules' ) as $res => $field )
{
    $r = $alice->call( 'GET', $RC . '/' . $res );
    eq( array( status( $r ), $r[1]['model'] ?? null, ( $r[1]['total'] ?? 0 ) > 0, isset( $r[1]['items'][0][$field] ) ), array( 200, 'scm-v1', TRUE, TRUE ), 'scm-v1: ' . $res );
}
foreach( array( 'dns-security-profiles', 'wildfire-anti-virus-profiles', 'zone-protection-profiles' ) as $res )
    eq( status( $alice->call( 'GET', $RC . '/' . $res ) ), 200, 'scm-v1: ' . $res . ' (none in a Panorama configuration of this test)' );
$r = $alice->call( 'GET', $RC . '/profile-groups' );
eq( array( $r[1]['total'] ?? null, $r[1]['items'][0]['device_group'] ?? null ), array( 1, 'shared' ), 'scm-v1: profile-groups' );
$r = $alice->call( 'GET', $RC . '/zones' );
eq( array( $r[1]['total'] ?? null, isset( $r[1]['items'][0]['template'] ), isset( $r[1]['items'][0]['network'] ) ), array( 3, TRUE, TRUE ), 'scm-v1: zones with their template' );
$r = $alice->call( 'GET', $RC . '/security-rules' );
$rule = $r[1]['items'][0] ?? array();
eq( array( status( $r ), $r[1]['model'] ?? null, $r[1]['total'] ?? null ), array( 200, 'scm-v1', 9 ), 'scm-v1: security-rules' );
eq( array( is_array( $rule['from'] ?? null ), is_array( $rule['source'] ?? null ), isset( $rule['action'] ), (bool)preg_match( '/^[0-9a-f-]{36}$/', $rule['uuid'] ?? '' ),
    in_array( $rule['rulebase'] ?? '', array( 'pre', 'post' ), TRUE ), is_int( $rule['position'] ?? null ), isset( $rule['device_group'] ) ),
    array( TRUE, TRUE, TRUE, TRUE, TRUE, TRUE, TRUE ), 'scm-v1: security rule with SCM fields + uuid, rulebase, position, device_group' );
foreach( array( 'nat-rules', 'decryption-rules', 'authentication-rules', 'default-security-rules' ) as $res )
{
    $r = $alice->call( 'GET', $RC . '/' . $res );
    eq( array( status( $r ), ( $r[1]['total'] ?? 0 ) > 0, isset( $r[1]['items'][0]['name'] ) ), array( 200, TRUE, TRUE ), 'scm-v1: ' . $res );
}
foreach( array( 'app-override-rules', 'pbf-rules', 'qos-policy-rules', 'dos-rules', 'tunnel-inspection-rules', 'captive-portal-rules', 'sdwan-rules', 'network-packet-broker-rules' ) as $res )
    eq( status( $alice->call( 'GET', $RC . '/' . $res ) ), 200, 'scm-v1: ' . $res . ' (none in this test configuration)' );
eq( status( $alice->call( 'GET', $RC . '/security-rules?ruletype=nat' ) ) === 200 && ( $alice->call( 'GET', $RC . '/security-rules?ruletype=nat' )[1]['total'] ?? null ) === 9, TRUE, 'scm-v1: the rule type of a rule resource can not be changed by the request' );
// ?computed=1: the values pan-os-php calculates, as _panosphp
$one = $alice->call( 'GET', $RC . '/addresses/shared-host1?computed=1' )[1]['items'][0] ?? array();
eq( array( $one['_panosphp']['ip_count'] ?? null, ( $one['_panosphp']['references'] ?? 0 ) > 0 ), array( 1, TRUE ), 'computed=1: address with ip_count and references' );
eq( isset( $alice->call( 'GET', $RC . '/addresses/shared-host1' )[1]['items'][0]['_panosphp'] ), FALSE, 'without computed=1: plain SCM shape' );
$r = $alice->call( 'GET', $RC . '/anti-spyware-profiles?computed=1' );
$c = $r[1]['items'][0]['_panosphp'] ?? array();
eq( array( array_key_exists( 'visibility', $c ), array_key_exists( 'best_practice', $c ), isset( $c['checks']['rules'], $c['checks']['inline'] ) ), array( TRUE, TRUE, TRUE ),
    'computed=1: anti-spyware profile with visibility, best_practice and single checks' );
$c = $alice->call( 'GET', $RC . '/profile-groups?computed=1' )[1]['items'][0]['_panosphp'] ?? array();
eq( array_key_exists( 'visibility', $c ), TRUE, 'computed=1: profile group' );
$c = $alice->call( 'GET', $RC . '/security-rules?computed=1' )[1]['items'][0]['_panosphp'] ?? array();
eq( array_key_exists( 'profiles_visibility', $c ), TRUE, 'computed=1: security rule with the verdict of its profiles' );
eq( status( $alice->call( 'GET', $RC . '/addresses?model=display-v0&computed=1' ) ), 400, 'computed=1 only with scm-v1' );
eq( status( $alice->call( 'GET', $RC . '/rules?model=scm-v1' ) ), 400, 'scm-v1: the type resource rules has no scm-v1 model (use security-rules, …)' );

eq( status( $alice->call( 'GET', $RC . '/addresses?model=nosuch' ) ), 400, 'model checked' );
eq( isset( $alice->call( 'GET', 'meta' )[1]['resources']['address-groups'] ), TRUE, 'meta lists the SCM resources' );
eq( status( $alice->call( 'GET', $RC . '/addresses?limit=0' ) ), 400, 'REST: limit checked' );
eq( status( $alice->call( 'GET', $RC . '/addresses?limit=999999' ) ), 400, 'REST: limit maximum' );
$r = $alice->call( 'GET', $RC . '/addresses/shared-host1' );
eq( array( status( $r ), $r[1]['items'][0]['name'] ?? null, $r[1]['items'][0]['device_group'] ?? null ), array( 200, 'shared-host1', 'shared' ), 'REST: GET one address' );
eq( status( $alice->call( 'GET', $RC . '/addresses/no-such-object' ) ), 404, 'REST: unknown object' );
eq( status( $alice->call( 'GET', $RC . '/addresses/' . rawurlencode( 'x) or (name regex /./' ) ) ), 400, 'REST: a name can not change the filter' );
eq( status( $alice->call( 'GET', $RC . '/nosuchresource' ) ), 404, 'REST: unknown resource' );
eq( $alice->call( 'GET', $RC . '/rules?ruletype=security' )[1]['total'] ?? null, 9, 'REST: GET rules' );
eq( status( $alice->call( 'GET', $RC . '/security-profiles' ) ), 200, 'REST: GET security-profiles' );
foreach( array( 'applications', 'devices', 'interfaces', 'log-profiles', 'dns-rules', 'threat-rules' ) as $res )
{
    $r = $alice->call( 'GET', $RC . '/' . $res . '?limit=2' );
    eq( array( status( $r ), ( $r[1]['total'] ?? 0 ) > 0 ), array( 200, TRUE ), 'REST: read only type ' . $res );
}
foreach( array( 'schedules', 'edls', 'zone-protection-profiles', 'ike-gateways', 'static-routes' ) as $res )
    eq( status( $alice->call( 'GET', $RC . '/' . $res ) ), 200, 'REST: type without objects in this configuration: ' . $res );
eq( status( $alice->call( 'POST', $RC . '/applications/actions', array( 'location' => 'any', 'actions' => 'display' ) ) ), 400, 'REST: no actions on a read only type' );
$r = $alice->call( 'POST', $RC . '/addresses/actions', array( 'type' => 'service', 'location' => 'shared', 'filter' => '(name eq shared-host1)', 'actions' => 'description-append:-rest' ) );
eq( array( status( $r ), $r[1]['processed'] ?? null ), array( 200, 1 ), 'REST: POST addresses/actions (the type comes from the resource, not from the body)' );
eq( status( $alice->call( 'GET', $RC . '/addresses', null ) ), 200, 'REST: read after change' );
$anon2 = new Client();
eq( status( $anon2->call( 'GET', $RC . '/addresses' ) ), 401, 'REST: no login' );
eq( status( $bob->call( 'GET', $RC . '/addresses' ) ), 404, 'REST: no access' );
eq( status( $alice->call( 'PUT', $R . '/members', array( 'user' => 'bob', 'role' => 'read', 'types' => array( 'address', 'application' ), 'scope' => array( 'shared' ) ) ) ), 200, 'REST: bob limited' );
eq( status( $bob->call( 'GET', $RC . '/addresses?location=shared' ) ), 200, 'REST limited: granted' );
$r = $bob->call( 'GET', $RC . '/locations' );
eq( array( status( $r ), $r[1]['any'] ?? null, array_column( $r[1]['locations'] ?? array(), 'name' ) ), array( 200, FALSE, array( 'shared' ) ), 'locations limited: only the granted ones, no any' );
$r = $bob->call( 'GET', $RC . '/references?type=address&location=shared&name=' . rawurlencode( 'new test 2' ) );
$o = $r[1]['objects'][0] ?? array();
eq( array( status( $r ), array_column( $o['references'] ?? array(), 'name' ), $o['hidden'] ?? null ), array( 200, array( 'group-with-duplicate-child' ), 5 ),
    'references limited: only inside the types / locations of the member, the others counted' );
eq( status( $bob->call( 'GET', $RC . '/references?type=address&name=x' ) ), 403, 'references limited: a location is needed' );
eq( status( $bob->call( 'GET', $RC . '/addresses' ) ), 403, 'REST limited: location needed' );
eq( status( $bob->call( 'GET', $RC . '/addresses/shared-host1' ) ), 403, 'REST limited: one object without location' );
eq( status( $bob->call( 'GET', $RC . '/addresses/shared-host1?location=shared' ) ), 200, 'REST limited: one object in the scope' );
eq( status( $bob->call( 'GET', $RC . '/services?location=shared' ) ), 403, 'REST limited: other type' );
eq( status( $bob->call( 'GET', $RC . '/applications?location=shared' ) ), 403, 'REST limited: type without location objects refused with a scope' );
eq( status( $alice->call( 'DELETE', $R ) ), 200, 'REST project deleted' );

// ---- 12j. runs (jobs): stats
function waitRun( $client, $path )
{
    for( $i = 0; $i < 600; $i++ )
    {
        $r = $client->call( 'GET', $path );
        if( !in_array( $r[1]['state'] ?? '', array( 'queued', 'running' ), TRUE ) )
            return $r;
        usleep( 200000 );
    }
    return $r;
}
$r = $alice->call( 'POST', 'projects', array( 'name' => 'Runs' ) );
$J = 'projects/' . $r[1]['pid'];
$r = $alice->call( 'POST', $J . '/configs', null, array( 'j.xml', $xml ) );
$JC = $J . '/configs/' . $r[1]['cid'];
eq( status( $anon2->call( 'POST', $JC . '/stats/runs', array() ) ), 401, 'runs: no login' );
eq( status( $bob->call( 'POST', $JC . '/stats/runs', array() ) ), 404, 'runs: no access' );
eq( status( $alice->call( 'POST', $JC . '/diff/runs', array() ) ), 404, 'runs: type that is not offered' );
eq( status( $alice->call( 'POST', $JC . '/stats/runs', array( 'location' => '../x' ) ) ), 400, 'runs: location checked' );
$r = $alice->call( 'POST', $JC . '/stats/runs', array( 'location' => 'any', 'in' => '/etc/passwd', 'actions' => 'exportToExcel:/tmp/x', 'out' => '/tmp/y' ) );
eq( array( status( $r ), $r[1]['state'] ?? null, $r[1]['args'] ?? null ), array( 202, 'queued', array( 'location=any', 'actions=display-bpa', 'json-to-folder', 'debugapi' ) ), 'runs: stats queued; arguments of the request are not taken over' );
$run = $J . '/runs/' . $r[1]['jid'];
$r = waitRun( $alice, $run );
eq( $r[1]['state'] ?? null, 'done', 'runs: stats done' );
$names = array_column( $r[1]['files'] ?? array(), 'name' );
eq( array( in_array( 'run.log', $names, TRUE ), in_array( 'json/debugAPI_string.json', $names, TRUE ) ), array( TRUE, TRUE ), 'runs: result files listed (' . implode( ', ', $names ) . ')' );
$r = $alice->call( 'GET', $run . '/files/json/debugAPI_string.json' );
eq( array( status( $r ), is_string( $r[1] ) ? ( strpos( $r[1], 'adoption' ) !== FALSE ) : isset( $r[1] ) ), array( 200, TRUE ), 'runs: result file downloaded' );
$log = $alice->call( 'GET', $run . '/files/run.log' );
eq( array( status( $log ), strpos( is_string( $log[1] ) ? $log[1] : json_encode( $log[1] ), $data ) ), array( 200, FALSE ), 'runs: no server path in the log' );
eq( status( $alice->call( 'GET', $run . '/files/' . rawurlencode( '../../viewer.sqlite' ) ) ), 404, 'runs: no file outside the run (encoded ..)' );
eq( status( $alice->call( 'GET', $run . '/files/nosuchfile' ) ), 404, 'runs: unknown file' );
eq( count( $alice->call( 'GET', $J . '/runs' )[1]['runs'] ?? array() ), 1, 'runs: list' );
eq( status( $bob->call( 'GET', $run ) ), 404, 'runs: other user' );
eq( status( $alice->call( 'PUT', $J . '/members', array( 'user' => 'bob', 'role' => 'read' ) ) ), 200, 'runs: bob read' );
eq( status( $bob->call( 'GET', $run . '/files/run.log' ) ), 200, 'runs: read member reads a result' );
eq( status( $bob->call( 'DELETE', $run ) ), 403, 'runs: read member can not delete the run of another user' );
$r = $bob->call( 'POST', $JC . '/stats/runs', array() );
eq( status( $r ), 202, 'runs: read member starts a run' );
eq( status( $bob->call( 'DELETE', $J . '/runs/' . $r[1]['jid'] ) ), 200, 'runs: cancel the own run' );
eq( in_array( waitRun( $bob, $J . '/runs/' . $r[1]['jid'] )[1]['state'] ?? null, array( 'cancelled' ), TRUE ), TRUE, 'runs: cancelled' );
eq( status( $alice->call( 'PUT', $J . '/members', array( 'user' => 'bob', 'role' => 'read', 'scope' => array( 'shared' ) ) ) ), 200, 'runs: bob limited' );
eq( status( $bob->call( 'POST', $JC . '/stats/runs', array() ) ), 403, 'runs: limited member can not run on the whole configuration' );
eq( status( $bob->call( 'GET', $run ) ), 403, 'runs: limited member can not read results of the whole configuration' );
$r = $alice->call( 'POST', $J . '/tokens', array( 'label' => 'cdss', 'role' => 'read', 'days' => 1 ) );
$tk = new Client(); $tk->bearer = $r[1]['token'];
$r = $tk->call( 'POST', $JC . '/stats/runs', array() );
eq( status( $r ), 202, 'runs: started with an API token' );
eq( waitRun( $tk, $J . '/runs/' . $r[1]['jid'] )[1]['state'] ?? null, 'done', 'runs: done with an API token' );
eq( status( $alice->call( 'DELETE', $run ) ), 200, 'runs: finished run deleted' );
eq( status( $alice->call( 'GET', $run ) ), 404, 'runs: gone' );
eq( status( $alice->call( 'DELETE', $J ) ), 200, 'runs project deleted' );

// ---- 12p. project files (playbook JSON, BP JSON) and playbook runs
$r = $alice->call( 'POST', 'projects', array( 'name' => 'Playbook' ) );
$PB = 'projects/' . $r[1]['pid'];
$r = $alice->call( 'POST', $PB . '/configs', null, array( 'p.xml', $xml ) );
$PBC = $PB . '/configs/' . $r[1]['cid'];
$steps = array(
    array( 'type' => 'address', 'actions' => 'actions=exportToExcel:addresses.html', 'location' => 'location=any', 'comment' => 'export' ),
    array( 'type' => 'address', 'actions' => 'actions=description-Append:-pb', 'filter' => 'filter=(name eq shared-host1)', 'location' => 'location=shared', 'pie_slice' => 'x' ),
    array( 'type' => 'rule', 'actions' => 'actions=logend-Enable', 'location' => 'location=any', 'outputformatset' => 'outputformatset=rules-set.txt' ),
);
$good = json_encode( array( 'stagename' => 'whatever/x-', 'header-comment' => 'test', 'command' => $steps ) );
$up = function( $client, $path, $kind, $content ) { return $client->call( 'POST', $path . '/files?kind=' . $kind, null, array( 'pb.json', $content, 'file' ) ); };
$badPlaybooks = array(
    'not JSON' => '{',
    'no command list' => json_encode( array( 'x' => 1 ) ),
    'key in' => json_encode( array( 'in' => '/etc/passwd', 'command' => $steps ) ),
    'key projectfolder' => json_encode( array( 'projectfolder' => '/tmp', 'command' => $steps ) ),
    'type not offered' => json_encode( array( 'command' => array( array( 'type' => 'upload', 'actions' => 'actions=display' ) ) ) ),
    'type ssh-connector' => json_encode( array( 'command' => array( array( 'type' => 'ssh-connector' ) ) ) ),
    'argument in=' => json_encode( array( 'command' => array( array( 'type' => 'address', 'x' => 'in=/etc/passwd', 'actions' => 'actions=display' ) ) ) ),
    'argument out=' => json_encode( array( 'command' => array( array( 'type' => 'address', 'x' => 'out=/tmp/x.xml' ) ) ) ),
    'argument shadow-bpjsonfile=' => json_encode( array( 'command' => array( array( 'type' => 'securityprofile', 'x' => 'shadow-bpjsonfile=/etc/passwd' ) ) ) ),
    'export with a path' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=exportToExcel:../../x.html' ) ) ) ),
    'export with an absolute path' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=exportToExcel:/tmp/x.html' ) ) ) ),
    'second action with a path' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=display/exportToExcel:../x.html' ) ) ) ),
    'outputformatset with a path' => json_encode( array( 'command' => array( array( 'type' => 'rule', 'actions' => 'actions=display', 'o' => 'outputformatset=../x.txt' ) ) ) ),
    'exportCSV with a path' => json_encode( array( 'command' => array( array( 'type' => 'html-merger', 'e' => 'exportCSV=/tmp/x.xlsx' ) ) ) ),
    'file filter' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=display', 'filter' => 'filter=(name is.in.file /etc/passwd)' ) ) ) ),
    'action that reaches another system' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=upload-x' ) ) ) ),
    'file-writing action that is not an export, with a path' => json_encode( array( 'command' => array( array( 'type' => 'device', 'actions' => 'actions=display-shadowrule:../x.xlsx' ) ) ) ),
    'action that reads a file of the server' => json_encode( array( 'command' => array( array( 'type' => 'rule', 'actions' => 'actions=dst-add-from-file:/etc/passwd' ) ) ) ),
    'action that does a DNS lookup' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=value-set-reverse-dns' ) ) ) ),
    'action that is not in the allow list' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=no-such-action' ) ) ) ),
    'subquery that reads a file' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=display', 'filter' => 'filter=(name eq x)', 's' => 'subquery1=(name is.in.file /etc/passwd)' ) ) ) ),
    'argument that is no text' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => array( 'actions=display' ) ) ) ) ),
    'path in the scm variant of a step' => json_encode( array( 'command' => array( array( 'type' => 'address', 'actions' => 'actions=display', 'scm' => array( 'actions' => 'actions=exportToExcel:/tmp/x.html' ) ) ) ) ),
);
foreach( $badPlaybooks as $what => $content )
    eq( status( $up( $alice, $PB, 'playbook', $content ) ), 400, 'playbook refused: ' . $what );
foreach( array( 'the visibility playbook shipped with pan-os-php (with scm variants)' => $here . '/../utils/api/v1/playbook/visibility.json',
             'a shipped playbook with subquery and shadow-ignoreInvalidAddressObjects' => $here . '/../utils/api/v1/playbook/visibility_misconfiguration.json',
             'a shipped playbook with subquery' => $here . '/../utils/api/v1/playbook/best-practice_SP.json' ) as $what => $file )
{
    $r = $up( $alice, $PB, 'playbook', file_get_contents( $file ) );
    eq( status( $r ), 201, 'playbook accepted: ' . $what . ( status( $r ) !== 201 ? ' - ' . json_encode( $r[1] ) : '' ) );
    $alice->call( 'DELETE', $PB . '/files/' . ( $r[1]['fid'] ?? 'x' ) );
}
eq( status( $up( $alice, $PB, 'playbook', json_encode( array( 'command' => array( array( 'type' => 'address', 'scm' => 'x' ) ) ) ) ) ), 400, 'playbook refused: scm that is neither false nor an object' );
eq( status( $up( $alice, $PB, 'nosuchkind', $good ) ), 400, 'files: kind checked' );
eq( status( $up( $bob, $PB, 'playbook', $good ) ), 404, 'files: no access' );
$r = $up( $alice, $PB, 'playbook', $good );
eq( status( $r ), 201, 'files: playbook uploaded' );
$pbFid = $r[1]['fid'];
$bpJson = file_get_contents( $here . '/../utils/api/v1/bp/scm_bp_sp_panw.json' );
$r = $up( $alice, $PB, 'bp', $bpJson );
eq( status( $r ), 201, 'files: BP JSON uploaded' );
$bpFid = $r[1]['fid'];
eq( count( $alice->call( 'GET', $PB . '/files' )[1]['files'] ?? array() ), 2, 'files: list' );
eq( status( $alice->call( 'GET', $PB . '/files/' . $pbFid . '/download' ) ), 200, 'files: download' );
eq( status( $alice->call( 'POST', $PBC . '/playbook/runs', array() ) ), 400, 'playbook run: playbook file needed' );
eq( status( $alice->call( 'POST', $PBC . '/playbook/runs', array( 'playbook' => $bpFid ) ) ), 400, 'playbook run: a BP JSON is no playbook' );
eq( status( $alice->call( 'POST', $PBC . '/playbook/runs', array( 'playbook' => $pbFid, 'bp' => $pbFid ) ) ), 400, 'playbook run: a playbook is no BP JSON' );
eq( status( $alice->call( 'POST', $PBC . '/playbook/runs', array( 'playbook' => '../../x' ) ) ), 400, 'playbook run: file id checked' );
$r = $alice->call( 'POST', $PBC . '/playbook/runs', array( 'playbook' => $pbFid, 'bp' => $bpFid ) );
eq( status( $r ), 202, 'playbook run: queued' );
$prun = $PB . '/runs/' . $r[1]['jid'];
eq( strpos( json_encode( $r[1] ), $data ), FALSE, 'playbook run: no server path in the answer' );
$r = waitRun( $alice, $prun );
if( ( $r[1]['state'] ?? '' ) !== 'done' )
    print "run.log:\n" . substr( (string)$alice->call( 'GET', $prun . '/files/run.log' )[1], -1500 ) . "\n";
eq( $r[1]['state'] ?? null, 'done', 'playbook run: done' );
$names = array_column( $r[1]['files'] ?? array(), 'name' );
eq( array( in_array( 'out.xml', $names, TRUE ), in_array( 'addresses.html', $names, TRUE ), in_array( 'rules-set.txt', $names, TRUE ), in_array( 'run.log', $names, TRUE ) ),
    array( TRUE, TRUE, TRUE, TRUE ), 'playbook run: result configuration, export and set commands in the folder of the run (' . implode( ', ', $names ) . ')' );
$outside = FALSE;
foreach( $names as $nm ) if( strpos( $nm, '..' ) !== FALSE || $nm[0] === '/' ) $outside = TRUE;
eq( array( $outside, count( glob( $viewer . '/addresses.html' ) ?: array() ) ), array( FALSE, 0 ), 'playbook run: nothing written outside the folder of the run' );
$out = $alice->call( 'GET', $prun . '/files/out.xml' );
eq( array( status( $out ), strpos( (string)$out[1], '-pb' ) !== FALSE ), array( 200, TRUE ), 'playbook run: the result configuration has the change of step 2' );
eq( status( $bob->call( 'POST', $prun . '/save' ) ), 404, 'playbook run: stranger can not save the result' );
$r = $alice->call( 'POST', $prun . '/save' );
eq( array( status( $r ), strpos( $r[1]['note'] ?? '', 'playbook run' ) ), array( 201, 0 ), 'playbook run: result saved as a new version' );
$r2 = $alice->call( 'GET', $PB . '/configs/' . $r[1]['cid'] . '/addresses/shared-host1' );
eq( strpos( $r2[1]['items'][0]['description'] ?? '', '-pb' ) !== FALSE, TRUE, 'playbook run: the new version has the change' );
$r = $alice->call( 'POST', $PBC . '/stats/runs', array( 'bp' => $bpFid ) );
eq( array( status( $r ), in_array( 'shadow-bpjsonfile=%FILES%/' . $bpFid . '.json', $r[1]['args'] ?? array(), TRUE ) ), array( 202, TRUE ), 'stats run with the BP JSON of the project' );
eq( waitRun( $alice, $PB . '/runs/' . $r[1]['jid'] )[1]['state'] ?? null, 'done', 'stats run with the BP JSON: done' );
// BP JSON of the project for reads and changes (?bp=<file id> / body "bp")
$empty = $up( $alice, $PB, 'bp', '{}' )[1]['fid'];
$asName = null;
$def = $alice->call( 'GET', $PBC . '/anti-spyware-profiles?computed=1' );
$withBp = $alice->call( 'GET', $PBC . '/anti-spyware-profiles?computed=1&bp=' . $bpFid );
$withEmpty = $alice->call( 'GET', $PBC . '/anti-spyware-profiles?computed=1&bp=' . $empty );
eq( array( status( $withBp ), $withBp[1]['items'][0]['_panosphp'] ?? null ), array( 200, $def[1]['items'][0]['_panosphp'] ?? 'x' ), 'bp: the same BP JSON as the default gives the same verdicts' );
$pe = $withEmpty[1]['items'][0]['_panosphp'] ?? array();
eq( array( status( $withEmpty ), array_key_exists( 'visibility', $pe ) && $pe['visibility'] === null, array_key_exists( 'best_practice', $pe ) && $pe['best_practice'] === null,
    ( $def[1]['items'][0]['_panosphp']['visibility'] ?? null ) !== null ),
    array( 200, TRUE, TRUE, TRUE ), 'bp: an empty BP JSON of the project - no check, verdicts N/A (null), while the default BP JSON gives a verdict' );
$again = $alice->call( 'GET', $PBC . '/anti-spyware-profiles?computed=1' );
eq( $again[1]['items'][0]['_panosphp'] ?? null, $def[1]['items'][0]['_panosphp'] ?? 'x', 'bp: the next request without bp uses the default BP JSON again' );
eq( status( $alice->call( 'GET', $PBC . '/anti-spyware-profiles?computed=1&bp=' . $pbFid ) ), 400, 'bp: a playbook file is no BP JSON' );
eq( status( $alice->call( 'GET', $PBC . '/anti-spyware-profiles?bp=' . urlencode( '../../../etc/passwd' ) ) ), 400, 'bp: file id checked' );
$r = $alice->call( 'POST', $PBC . '/security-profiles/actions', array( 'location' => 'shared', 'securityprofiletype' => 'spyware', 'actions' => 'alert-only-set', 'bp' => $bpFid ) );
eq( status( $r ), 200, 'bp: change (alert-only-set) with the BP JSON of the project' );
$after = $alice->call( 'GET', $PBC . '/tags?computed=1' );
eq( status( $after ), 200, 'bp: after a change with a BP JSON the loaded configuration still answers (default BP JSON restored)' );
$alice->call( 'POST', $PBC . '/discard' );

// the visibility playbook shipped with pan-os-php, end to end through the API
$r = $up( $alice, $PB, 'playbook', file_get_contents( $here . '/../utils/api/v1/playbook/visibility.json' ) );
$r = $alice->call( 'POST', $PBC . '/playbook/runs', array( 'playbook' => $r[1]['fid'], 'bp' => $bpFid ) );
$vrun = $PB . '/runs/' . $r[1]['jid'];
$r = waitRun( $alice, $vrun );
if( ( $r[1]['state'] ?? '' ) !== 'done' )
    print "run.log:\n" . substr( (string)$alice->call( 'GET', $vrun . '/files/run.log' )[1], -1500 ) . "\n";
$names = array_column( $r[1]['files'] ?? array(), 'name' );
eq( array( $r[1]['state'] ?? null, in_array( 'out.xml', $names, TRUE ), in_array( 'set-commands.txt', $names, TRUE ) ), array( 'done', TRUE, TRUE ),
    'visibility playbook through the API: done, result configuration and set commands' );
$out = (string)$alice->call( 'GET', $vrun . '/files/out.xml' )[1];
eq( array( strpos( $out, 'Alert-Only-AS' ) !== FALSE, strpos( $out, 'Alert_Only_Zone_Protection' ) !== FALSE ), array( TRUE, TRUE ), 'visibility playbook: the result has the alert-only profiles' );

// predefined playbooks (shipped with pan-os-php): visibility.json offered by default, more only by an administrator
$names = function( $r ) { return array_column( $r[1]['playbooks'] ?? array(), 'name' ); };
eq( $names( $bob->call( 'GET', 'playbooks' ) ), array( 'visibility.json' ), 'predefined playbooks: visibility.json offered by default' );
eq( $names( $alice->call( 'GET', 'playbooks' ) ), array( 'visibility.json' ), 'predefined playbooks: also an administrator gets only the offered ones for runs' );
eq( status( $bob->call( 'GET', 'playbooks?all=1' ) ), 404, 'predefined playbooks: the whole list only for an administrator' );
$all = $alice->call( 'GET', 'playbooks?all=1' )[1]['playbooks'] ?? array();
$usable = array_column( array_filter( $all, function( $p ) { return $p['usable']; } ), 'name' );
$notUsable = array_column( array_filter( $all, function( $p ) { return !$p['usable']; } ), 'why', 'name' );
eq( array( count( $all ) === count( glob( $here . '/../utils/api/v1/playbook/*.json' ) ), in_array( 'visibility.json', $usable, TRUE ),
    in_array( 'panorama_rule-merger.json', array_keys( $notUsable ), TRUE ), strpos( $notUsable['panorama_rule-merger.json'] ?? '', 'rule-merger' ) !== FALSE,
    array_column( array_filter( $all, function( $p ) { return $p['on']; } ), 'name' ) ),
    array( TRUE, TRUE, TRUE, TRUE, array( 'visibility.json' ) ), 'predefined playbooks: the administrator sees all, which can run here and why not' );
eq( status( $bob->call( 'PUT', 'playbooks', array( 'enabled' => array( 'best-practice-set.json' ) ) ) ), 404, 'predefined playbooks: only an administrator turns them on' );
eq( status( $alice->call( 'PUT', 'playbooks', array( 'enabled' => array( 'panorama_rule-merger.json' ) ) ) ), 400, 'predefined playbooks: one that can not run here is refused' );
eq( status( $alice->call( 'PUT', 'playbooks', array( 'enabled' => array( '../../etc/passwd' ) ) ) ), 400, 'predefined playbooks: unknown name refused' );
eq( status( $alice->call( 'POST', $PBC . '/playbook/runs', array( 'predefined' => 'best-practice-set.json' ) ) ), 400, 'predefined run: a playbook that is not turned on is refused' );
eq( status( $alice->call( 'POST', $PBC . '/playbook/runs', array( 'predefined' => '../visibility.json' ) ) ), 400, 'predefined run: name checked' );
eq( status( $alice->call( 'POST', $PBC . '/playbook/runs', array( 'predefined' => 'visibility.json', 'playbook' => $pbFid ) ) ), 400, 'predefined run: not together with a playbook file' );
$r = $alice->call( 'PUT', 'playbooks', array( 'enabled' => array( 'best-practice-set.json', 'visibility.json' ) ) );
eq( array( status( $r ), array_column( array_filter( $r[1]['playbooks'] ?? array(), function( $p ) { return $p['on']; } ), 'name' ) ),
    array( 200, array( 'best-practice-set.json', 'visibility.json' ) ), 'predefined playbooks: the administrator turns one more on' );
eq( $names( $bob->call( 'GET', 'playbooks' ) ), array( 'best-practice-set.json', 'visibility.json' ), 'predefined playbooks: offered to every user' );
$r = $alice->call( 'POST', $PBC . '/playbook/runs', array( 'predefined' => 'visibility.json', 'bp' => $bpFid ) );
eq( array( status( $r ), $r[1]['args'][0] ?? null ), array( 202, 'json=$$playbook$$/visibility.json' ), 'predefined run: queued, json=$$playbook$$/<name> as on the command line' );
$prun2 = $PB . '/runs/' . $r[1]['jid'];
$r = waitRun( $alice, $prun2 );
if( ( $r[1]['state'] ?? '' ) !== 'done' )
    print "run.log:\n" . substr( (string)$alice->call( 'GET', $prun2 . '/files/run.log' )[1], -1500 ) . "\n";
$fn = array_column( $r[1]['files'] ?? array(), 'name' );
$out2 = (string)$alice->call( 'GET', $prun2 . '/files/out.xml' )[1];
eq( array( $r[1]['state'] ?? null, in_array( 'set-commands.txt', $fn, TRUE ), strpos( $out2, 'Alert-Only-AS' ) !== FALSE ), array( 'done', TRUE, TRUE ),
    'predefined run: done - same result as the uploaded visibility.json' );
eq( status( $alice->call( 'PUT', 'playbooks', array( 'enabled' => array() ) ) ), 200, 'predefined playbooks: all turned off' );
eq( array( $names( $bob->call( 'GET', 'playbooks' ) ), status( $alice->call( 'POST', $PBC . '/playbook/runs', array( 'predefined' => 'visibility.json' ) ) ) ),
    array( array(), 400 ), 'predefined playbooks: nothing offered, a run is refused (no fall back to the default)' );

// diff: two versions of the project (file1 = this version, file2 = 'other'), set commands file1 -> file2
$xml2 = str_replace( '<ip-netmask>1.2.2.3/32</ip-netmask>', '<ip-netmask>9.9.9.9/32</ip-netmask>', $xml );
$other = $alice->call( 'POST', $PB . '/configs', null, array( 'p-changed.xml', $xml2 ) )[1]['cid'] ?? '';
eq( status( $alice->call( 'POST', $PBC . '/diff/runs', array( 'other' => basename( $PBC ) ) ) ), 400, 'diff: the same version twice is refused' );
eq( status( $alice->call( 'POST', $PBC . '/diff/runs', array( 'other' => str_repeat( 'f', 32 ) ) ) ), 404, 'diff: an unknown version' );
foreach( array( '/etc/passwd', '/config/../../etc', 'files/x.json', "/config/shared\n" ) as $bad )
    eq( status( $alice->call( 'POST', $PBC . '/diff/runs', array( 'other' => $other, 'xpath' => $bad ) ) ), 400, 'diff: xpath that is no XPath of the configuration refused (' . json_encode( $bad ) . ')' );
eq( status( $bob->call( 'POST', $PBC . '/diff/runs', array( 'other' => $other ) ) ), 404, 'diff: no access' );
$r = $alice->call( 'POST', $PBC . '/diff/runs', array( 'other' => $other, 'setcommands' => TRUE ) );
$a = $r[1]['args'] ?? array();
eq( array( status( $r ), count( $a ), (bool)preg_match( '#^file1=%PROJECT%/[0-9a-f]{32}\.xml$#', $a[0] ?? '' ), (bool)preg_match( '#^file2=%PROJECT%/[0-9a-f]{32}\.xml$#', $a[1] ?? '' ),
    ( $a[0] ?? '' ) !== 'file1' . substr( $a[1] ?? '', 5 ), $a[2] ?? null ), array( 202, 3, TRUE, TRUE, TRUE, 'outputformatset=set-commands.txt' ),
    'diff: queued with file1 / file2 (two versions of the project) and the set commands' );
$drun = $PB . '/runs/' . ( $r[1]['jid'] ?? '' );
$r = waitRun( $alice, $drun );
$set = (string)$alice->call( 'GET', $drun . '/files/set-commands.txt' )[1];
$log = (string)$alice->call( 'GET', $drun . '/files/run.log' )[1];
eq( array( $r[1]['state'] ?? null, strpos( $set, 'set shared address "shared-host1" ip-netmask 9.9.9.9/32' ) !== FALSE, strpos( $log, 'in=' ) === FALSE, strpos( $log, $data ) ),
    array( 'done', TRUE, TRUE, FALSE ), 'diff: done - set commands from file1 to file2, no in=' );
$r = $alice->call( 'POST', $PBC . '/diff/runs', array( 'other' => $other, 'xpath' => "/config/devices/entry[@name='localhost.localdomain']/device-group", 'noruleordercheck' => TRUE ) );
eq( array( status( $r ), array_slice( $r[1]['args'] ?? array(), 2 ) ), array( 202, array( 'noruleordercheck', "filter=/config/devices/entry[@name='localhost.localdomain']/device-group" ) ),
    'diff: only a part (XPath), without the rule order check' );
waitRun( $alice, $PB . '/runs/' . ( $r[1]['jid'] ?? '' ) );
$alice->call( 'DELETE', $PB . '/configs/' . $other );

// App-ID database of the installation (administrator upload): the viewer (worker) uses it - here with one more application
$pre = new DOMDocument();
$pre->load( $here . '/../lib/object-classes/predefined.xml', LIBXML_PARSEHUGE );
$xp = new DOMXPath( $pre );
$app0 = $xp->query( '/predefined/application/entry' )->item( 0 );
$copy = $app0->cloneNode( TRUE );
$copy->setAttribute( 'name', 'zz-viewer-test-app' );
$app0->parentNode->appendChild( $copy );
$xp->query( '/predefined/application-version' )->item( 0 )->nodeValue = '9998-9998';
$preFile = $data . '-predefined.xml';
$pre->save( $preFile );
unset( $pre, $xp );
eq( status( $bob->call( 'POST', 'central/appid', null, array( 'predefined.xml', file_get_contents( $preFile ), 'file' ) ) ), 404, 'installation App-ID: not for a user' );
$r = $alice->call( 'POST', 'central/appid', null, array( 'predefined.xml', file_get_contents( $preFile ), 'file' ) );
eq( array( status( $r ), $r[1]['version'] ?? null, $alice->call( 'GET', 'central' )[1]['appid']['version'] ?? null ), array( 200, '9998-9998', '9998-9998' ), 'installation App-ID: upload (air gap), version shown' );
$r = $alice->call( 'POST', 'projects', array( 'name' => 'AppID' ) );
$AP = 'projects/' . $r[1]['pid'];
$APC = $AP . '/configs/' . ( $alice->call( 'POST', $AP . '/configs', null, array( 'a.xml', $xml ) )[1]['cid'] ?? '' );
$r = $alice->call( 'GET', $APC . '/objects?type=application&location=shared&filter=' . rawurlencode( '(name eq zz-viewer-test-app)' ) );
eq( array( status( $r ), $r[1]['total'] ?? null, $alice->call( 'GET', $AP . '/appid' )[1]['from'] ?? null ), array( 200, 1, 'installation' ), 'installation App-ID: the viewer uses it (an application only it has)' );
$alice->call( 'DELETE', 'central/appid' );
$alice->call( 'DELETE', $AP );
@unlink( $preFile );

// the editors of pan-os-php (playbook, BP JSON): served sandboxed, scripts inline, no network, only in the viewer
$raw = @file_get_contents( $base . 'editor.php?e=playbook', FALSE, stream_context_create( array( 'http' => array( 'ignore_errors' => TRUE ) ) ) );
$hdr = implode( "\n", $http_response_header ?? array() );
eq( array( strpos( $hdr, ' 200' ) !== FALSE, strpos( $hdr, "sandbox allow-scripts" ) !== FALSE, strpos( $hdr, "connect-src 'none'" ) !== FALSE, strpos( $hdr, "frame-ancestors 'self'" ) !== FALSE,
    strpos( (string)$raw, '<script src=' ), strpos( (string)$raw, 'var subjectObject = {' ) !== FALSE, strpos( (string)$raw, 'panosphp-editor-save' ) !== FALSE ),
    array( TRUE, TRUE, TRUE, TRUE, FALSE, TRUE, TRUE ), 'playbook editor: sandboxed, no network, actions / filters of util_action_filter.json inline, save goes to the viewer' );
$raw = @file_get_contents( $base . 'editor.php?e=bp', FALSE, stream_context_create( array( 'http' => array( 'ignore_errors' => TRUE ) ) ) );
eq( array( strpos( (string)$raw, '<script src=' ), strpos( (string)$raw, 'BP_VALIDATION' ) !== FALSE, strpos( (string)$raw, 'panosphp-editor-load' ) !== FALSE ), array( FALSE, TRUE, TRUE ), 'BP JSON editor: d3 and validation inline, load / save through the viewer' );
@file_get_contents( $base . 'editor.php?e=../../etc', FALSE, stream_context_create( array( 'http' => array( 'ignore_errors' => TRUE ) ) ) );
eq( strpos( implode( "\n", $http_response_header ?? array() ), ' 404' ) !== FALSE, TRUE, 'editor: only the two editors' );
$r = $alice->call( 'GET', 'bp-default' );
eq( array( status( $r ), is_array( $r[1] ) && count( $r[1] ) > 3, status( $anon->call( 'GET', 'bp-default' ) ) ), array( 200, TRUE, 401 ), 'BP JSON shipped with pan-os-php: the start of a new one (login)' );
eq( status( $alice->call( 'DELETE', $PB . '/files/' . $pbFid ) ), 200, 'files: deleted' );
eq( status( $alice->call( 'POST', $PBC . '/playbook/runs', array( 'playbook' => $pbFid ) ) ), 400, 'playbook run: deleted file' );
eq( status( $alice->call( 'DELETE', $PB ) ), 200, 'playbook project deleted' );

// ---- 12c. allow list per action (action-classes.json)
$chk = proc_open( array( PHP_BINARY, $viewer . '/bin/action-classes.php', 'check' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes );
stream_get_contents( $pipes[1] );
eq( proc_close( $chk ), 0, 'action-classes.json is up to date with util_action_filter.json and the action sources' );
$meta = $alice->call( 'GET', 'meta' )[1]['types'];
eq( array( isset( $meta['address']['actions']['description-append'] ), isset( $meta['address']['actions']['value-set-reverse-dns'] ), isset( $meta['address']['actions']['exporttoexcel'] ),
    isset( $meta['address']['actions']['create-address-from-file'] ), isset( $meta['rule']['actions']['logend-enable'] ), isset( $meta['rule']['actions']['logend-enable-fastapi'] ) ),
    array( TRUE, FALSE, FALSE, FALSE, TRUE, FALSE ), 'allow list: change actions offered; network / file actions not' );
eq( array( $meta['edl']['readonly'] ?? null, count( $meta['edl']['actions'] ?? array( 1 ) ) ), array( TRUE, 0 ), 'allow list: a type that is not reviewed stays read only' );

// ---- 12l. audit log
$r = $alice->call( 'POST', 'projects', array( 'name' => 'Audit' ) );
$AU = 'projects/' . $r[1]['pid'];
$r = $alice->call( 'POST', $AU . '/configs', null, array( 'a.xml', $xml ) );
$AUC = $AU . '/configs/' . $r[1]['cid'];
$alice->call( 'PUT', $AU . '/members', array( 'user' => 'bob', 'role' => 'read' ) );
$alice->call( 'POST', $AUC . '/addresses/actions', array( 'location' => 'shared', 'filter' => '(name eq shared-host1)', 'actions' => 'description-append:-audit' ) );
$alice->call( 'GET', $AUC . '/addresses' );
$bob->call( 'GET', $AUC . '/download' );
$bob->call( 'POST', $AUC . '/addresses/actions', array( 'location' => 'shared', 'actions' => 'description-append:x' ) );
$r = $alice->call( 'POST', $AU . '/tokens', array( 'label' => 'audit token', 'role' => 'read', 'days' => 1 ) );
$atk = new Client(); $atk->bearer = $r[1]['token'];
$atk->call( 'GET', $AUC . '/download' );
$wrong = new Client(); $wrong->login( 'alice', 'this-is-wrong' );
$log = $alice->call( 'GET', $AU . '/audit' );
$lines = $log[1]['audit'] ?? array();
$find = function( $method, $suffix, $status ) use ( &$lines )
{
    foreach( $lines as $l )
        if( $l['method'] === $method && substr( $l['route'], -strlen( $suffix ) ) === $suffix && (int)$l['status'] === $status )
            return $l;
    return null;
};
eq( status( $log ), 200, 'audit: the owner reads the log of the project' );
$l = $find( 'POST', '/addresses/actions', 200 );
eq( array( $l['user'] ?? null, $l['detail']['actions'] ?? null, $l['detail']['filter'] ?? null ), array( 'alice', 'description-append:-audit', '(name eq shared-host1)' ), 'audit: change with user, actions and filter' );
$l = $find( 'PUT', '/members', 200 );
eq( array( $l['detail']['user'] ?? null, $l['detail']['role'] ?? null ), array( 'bob', 'read' ), 'audit: member change' );
eq( $find( 'GET', '/addresses', 200 ), null, 'audit: a plain read is not logged' );
$l = $find( 'GET', '/download', 200 );
eq( in_array( $l['user'] ?? null, array( 'bob', 'alice' ), TRUE ), TRUE, 'audit: download logged' );
eq( ( $find( 'POST', '/addresses/actions', 403 )['user'] ?? null ), 'bob', 'audit: refused change logged with its status' );
$tokenLine = null;
foreach( $lines as $l ) if( $l['token'] !== null && substr( $l['route'], -9 ) === '/download' ) $tokenLine = $l;
eq( array( $tokenLine['user'] ?? null, strlen( (string)( $tokenLine['token'] ?? '' ) ) ), array( 'alice', 16 ), 'audit: a request with an API token names the token id' );
eq( strpos( json_encode( $lines ), 'pvt_' ), FALSE, 'audit: no token secret in the log' );
eq( status( $bob->call( 'GET', $AU . '/audit' ) ), 403, 'audit: a member that is not the owner can not read it' );
eq( status( $atk->call( 'GET', $AU . '/audit' ) ), 404, 'audit: not with an API token' );
eq( status( $bob->call( 'GET', 'audit' ) ), 404, 'audit: the whole log only for an admin' );
$all = $alice->call( 'GET', 'audit?limit=1000' );
$failedLogin = null; $hasPassword = FALSE;
foreach( $all[1]['audit'] ?? array() as $l )
{
    if( $l['route'] === '/login' && (int)$l['status'] === 401 && $l['user'] === 'alice' ) $failedLogin = $l;
    if( strpos( json_encode( $l ), 'this-is-wrong' ) !== FALSE || strpos( json_encode( $l ), 'alice-secret-1' ) !== FALSE ) $hasPassword = TRUE;
}
eq( array( status( $all ), $failedLogin !== null, $hasPassword ), array( 200, TRUE, FALSE ), 'audit: admin reads everything; failed login logged; no password in the log' );
eq( count( $alice->call( 'GET', 'audit?user=bob&limit=5' )[1]['audit'] ?? array() ) <= 5, TRUE, 'audit: filter and limit' );
eq( status( $alice->call( 'DELETE', $AU ) ), 200, 'audit project deleted' );

// ---- 12a. grants per member: types and scope (locations)
$alice = new Client(); $alice->login( 'alice', 'alice-secret-1' );
$dave = new Client(); eq( status( $dave->login( 'dave', 'dave-secret-45' ) ), 200, 'dave logs in' );
$r = $alice->call( 'POST', 'projects', array( 'name' => 'Grants' ) );
$G = 'projects/' . $r[1]['pid'];
$r = $alice->call( 'POST', $G . '/configs', null, array( 'g.xml', $xml ) );
$GC = $G . '/configs/' . $r[1]['cid'];
eq( status( $alice->call( 'PUT', $G . '/members', array( 'user' => 'dave', 'role' => 'write', 'types' => array( 'nosuchtype' ) ) ) ), 400, 'grant: unknown type refused' );
eq( status( $alice->call( 'PUT', $G . '/members', array( 'user' => 'dave', 'role' => 'write', 'scope' => array( 'any' ) ) ) ), 400, 'grant: scope "any" refused' );
eq( status( $alice->call( 'PUT', $G . '/members', array( 'user' => 'dave', 'role' => 'write', 'scope' => array( '../x' ) ) ) ), 400, 'grant: scope with path characters refused' );
$r = $alice->call( 'PUT', $G . '/members', array( 'user' => 'dave', 'role' => 'write', 'types' => array( 'address', 'tag' ), 'scope' => array( 'shared' ) ) );
eq( status( $r ), 200, 'grant: dave write, types address + tag, scope shared' );
$m = null;
foreach( $r[1]['members'] as $x ) if( $x['user'] === 'dave' ) $m = $x;
eq( array( $m['types'] ?? null, $m['scope'] ?? null ), array( array( 'address', 'tag' ), array( 'shared' ) ), 'grant: shown in the member list' );
eq( $dave->call( 'GET', $G )[1]['scope'] ?? null, array( 'shared' ), 'grant: dave sees her own scope' );
eq( status( $dave->call( 'GET', $GC . '/objects?type=address&location=shared' ) ), 200, 'limited: granted type in granted location' );
eq( status( $dave->call( 'GET', $GC . '/objects?type=service&location=shared' ) ), 403, 'limited: other type refused' );
eq( status( $dave->call( 'GET', $GC . '/objects?type=address&location=any' ) ), 403, 'limited: location any refused' );
eq( status( $dave->call( 'GET', $GC . '/objects?type=address' ) ), 403, 'limited: no location (= any) refused' );
eq( status( $dave->call( 'GET', $GC . '/objects?type=address&location=' . urlencode( 'shared,any' ) ) ), 403, 'limited: location list refused' );
eq( status( $dave->call( 'GET', $GC . '/objects?type=address&location=nosuchlocation' ) ), 403, 'limited: other location refused' );
eq( status( $dave->call( 'GET', $GC . '/download' ) ), 403, 'limited: no download of the whole configuration' );
eq( status( $dave->call( 'POST', $G . '/configs', null, array( 'c.xml', $xml ) ) ), 403, 'limited: no upload' );
eq( status( $dave->call( 'DELETE', $GC ) ), 403, 'limited: no delete of a version' );
eq( status( $dave->call( 'POST', $GC . '/change', array( 'type' => 'address', 'location' => 'shared', 'filter' => '(name eq shared-host1)', 'actions' => 'move:shared' ) ) ), 403, 'limited: action that can act outside the scope refused' );
eq( status( $dave->call( 'POST', $GC . '/change', array( 'type' => 'service', 'location' => 'shared', 'actions' => 'description-append:x' ) ) ), 403, 'limited: change of another type refused' );
$r = $dave->call( 'POST', $GC . '/change', array( 'type' => 'address', 'location' => 'shared', 'filter' => '(name eq shared-host1)', 'actions' => 'description-append:-grant' ) );
eq( array( status( $r ), $r[1]['processed'] ?? null ), array( 200, 1 ), 'limited: change of a granted type in the scope' );
eq( status( $alice->call( 'PUT', $G . '/members', array( 'user' => 'dave', 'role' => 'read' ) ) ), 200, 'grant: back to read without limits' );
eq( status( $dave->call( 'GET', $GC . '/objects?type=service&location=any' ) ), 200, 'unlimited again: every type, location any' );
eq( status( $dave->call( 'GET', $GC . '/download' ) ), 200, 'unlimited again: download' );

// ---- 12b. API tokens (scripts): Authorization: Bearer, no cookie, no CSRF token
eq( status( $dave->call( 'POST', $G . '/tokens', array( 'label' => 'x', 'role' => 'write', 'days' => 1 ) ) ), 403, 'token: a read member gets no write token' );
eq( status( $dave->call( 'POST', $G . '/tokens', array( 'label' => 'x', 'role' => 'read', 'days' => 0 ) ) ), 400, 'token: days checked' );
$r = $dave->call( 'POST', $G . '/tokens', array( 'label' => 'dave script', 'role' => 'read', 'days' => 1 ) );
eq( array( status( $r ), (bool)preg_match( '/^pvt_[0-9a-f]{16}_[0-9a-f]{64}$/', $r[1]['token'] ?? '' ) ), array( 201, TRUE ), 'token: created' );
$daveTid = $r[1]["tid"];
$ct = new Client(); $ct->bearer = $r[1]['token'];
$r = $alice->call( 'POST', $G . '/tokens', array( 'label' => 'alice script', 'role' => 'write', 'days' => 1 ) );
$at = new Client(); $at->bearer = $r[1]['token'];
$aliceTid = $r[1]['tid'];
$db = new PDO( 'sqlite:' . $data . '/viewer.sqlite' );
eq( strpos( json_encode( $db->query( 'SELECT * FROM tokens' )->fetchAll( PDO::FETCH_ASSOC ) ), substr( $at->bearer, 21 ) ), FALSE, 'token: the secret is not stored' );
eq( strpos( json_encode( $alice->call( 'GET', $G . '/tokens' )[1] ), 'pvt_' ), FALSE, 'token: the list never shows a secret' );
eq( count( $alice->call( 'GET', $G . '/tokens' )[1]['tokens'] ), 2, 'token: the owner sees all tokens of the project' );
eq( count( $dave->call( 'GET', $G . '/tokens' )[1]['tokens'] ), 1, 'token: a member sees only its own' );
eq( status( $ct->call( 'GET', $GC . '/objects?type=address&location=shared' ) ), 200, 'token: read without cookie' );
eq( status( $ct->call( 'POST', $GC . '/change', array( 'type' => 'address', 'location' => 'shared', 'actions' => 'description-append:x' ) ) ), 403, 'token (read): no change' );
$r = $at->call( 'POST', $GC . '/change', array( 'type' => 'address', 'location' => 'shared', 'filter' => '(name eq shared-host1)', 'actions' => 'description-append:-token' ) );
eq( array( status( $r ), $r[1]['processed'] ?? null ), array( 200, 1 ), 'token (write): change without CSRF token' );
eq( status( $at->call( 'PUT', $G . '/members', array( 'user' => 'bob', 'role' => 'read' ) ) ), 403, 'token of the owner: no member management' );
eq( status( $at->call( 'DELETE', $G ) ), 403, 'token of the owner: no project delete' );
eq( status( $at->call( 'POST', $G . '/tokens', array( 'label' => 'y', 'role' => 'read', 'days' => 1 ) ) ), 403, 'token: can not create tokens' );
eq( status( $at->call( 'POST', 'projects', array( 'name' => 'by token' ) ) ), 403, 'token: can not create projects' );
eq( status( $at->call( 'GET', 'users' ) ), 404, 'token of an admin: no admin routes' );
eq( status( $at->call( 'GET', $C . '/objects?type=address' ) ), 404, 'token: other project of the same user is not reachable' );
eq( count( $at->call( 'GET', 'projects' )[1]['projects'] ?? array() ), 1, 'token: project list shows only its project' );
$bad = new Client(); $bad->bearer = substr( $at->bearer, 0, -1 ) . ( substr( $at->bearer, -1 ) === '0' ? '1' : '0' );
eq( status( $bad->call( 'GET', $GC . '/objects?type=address' ) ), 401, 'token: wrong secret' );
$db->exec( 'UPDATE tokens SET expires = ' . ( time() - 10 ) . " WHERE tid = '" . $aliceTid . "'" );
eq( status( $at->call( 'GET', $GC . '/objects?type=address' ) ), 401, 'token: expired' );
eq( status( $alice->call( 'PUT', $G . '/members', array( 'user' => 'dave', 'role' => 'read', 'types' => array( 'tag' ) ) ) ), 200, 'grant changed while a token exists' );
eq( status( $ct->call( 'GET', $GC . '/objects?type=address&location=shared' ) ), 403, 'token: follows the grant of its user (type removed)' );
eq( status( $ct->call( 'GET', $GC . '/objects?type=tag&location=shared' ) ), 200, 'token: granted type' );
eq( status( $bob->call( 'DELETE', $G . '/tokens/' . $daveTid ) ), 404, 'token: a stranger can not delete it' );
eq( status( $alice->call( 'DELETE', $G . '/members/dave' ) ), 200, 'member removed' );
eq( status( $ct->call( 'GET', $GC . '/objects?type=tag&location=shared' ) ), 401, 'token: gone with the membership' );
eq( status( $alice->call( 'DELETE', $G . '/tokens/' . $aliceTid ) ), 200, 'token: deleted by its user' );
eq( status( $alice->call( 'DELETE', $G ) ), 200, 'grants project deleted' );

// ---- 12p. plug-ins: run types, file kinds
$m = $alice->call( 'GET', 'meta' )[1]['plugins'] ?? array();
eq( array_keys( $m['runs'] ?? array() ), array( 'badargs-in', 'badargs-out', 'example-export', 'example-tag-rules', 'mig-import' ), 'plug-ins: run types in meta' );
eq( array( $m['kinds'] ?? null, $m['runs']['example-tag-rules']['fields'][0]['kind'] ?? null, $m['runs']['example-tag-rules']['result'] ?? null ),
    array( array( 'example-taglist' => 'tag list (JSON)', 'mig-source' => 'source' ), 'file:example-taglist', TRUE ), 'plug-ins: file kind and fields in meta' );
eq( array( $m['rawKinds'] ?? null, $m['runs']['mig-import']['input'] ?? null, $m['runs']['mig-import']['fields'][0]['options'] ?? null ), array( array( 'mig-source' ), 'none', array( 'ciscoswitch' => 'Cisco switch', 'ciscoisr' => 'Cisco router' ) ), 'plug-ins: raw kind, run without a version, options in meta' );
eq( array( array_keys( $m['errors'] ?? array() ), strpos( $m['errors']['wrongapi'] ?? '', '"api"' ) !== FALSE ), array( array( 'badenv', 'badenv2', 'othername', 'wrongapi' ), TRUE ), 'plug-ins: refused ones are named to the admin with the reason (also: env of the viewer, path with ..)' );
eq( array_key_exists( 'errors', $bob->call( 'GET', 'meta' )[1]['plugins'] ?? array( 'errors' => 1 ) ), FALSE, 'plug-ins: no reasons for other users' );
$r = $alice->call( 'POST', 'projects', array( 'name' => 'Plug-ins' ) );
$PL = 'projects/' . $r[1]['pid'];
$r = $alice->call( 'POST', $PL . '/configs', null, array( 'p.xml', $xml ) );
$PLC = $PL . '/configs/' . $r[1]['cid'];
$r = $up( $alice, $PL, 'example-taglist', '["bad tag!"]' );
eq( array( status( $r ), $r[1]['error'] ?? null ), array( 400, 'tag list: tag names with letters, digits and . _ - only' ), 'plug-ins: file kind - the check of the plug-in refuses a file' );
eq( status( $up( $alice, $PL, 'nosuch-kind', '[]' ) ), 400, 'plug-ins: unknown file kind' );
$r = $up( $alice, $PL, 'example-taglist', '["plugin-tag-1","plugin-tag-2"]' );
eq( status( $r ), 201, 'plug-ins: file of a plug-in kind uploaded' );
$tagFid = $r[1]['fid'];
$plBp = $up( $alice, $PL, 'bp', '{}' )[1]['fid'];
$r = $alice->call( 'POST', $PLC . '/example-export/runs', array( 'location' => 'shared', 'actions' => 'actions=delete', 'in' => '/etc/passwd' ) );
eq( array( status( $r ), $r[1]['args'] ?? null ), array( 202, array( 'location=shared', 'actions=exportToExcel:addresses.html' ) ), 'plug-ins: run queued with the arguments of the plug-in only' );
$r = waitRun( $alice, $PL . '/runs/' . $r[1]['jid'] );
eq( array( $r[1]['state'] ?? null, in_array( 'addresses.html', array_column( $r[1]['files'] ?? array(), 'name' ), TRUE ) ), array( 'done', TRUE ), 'plug-ins: run done, result file' );
eq( status( $alice->call( 'POST', $PL . '/runs/' . $r[1]['jid'] . '/save' ) ), 409, 'plug-ins: a run type without a result configuration can not become a version' );
eq( status( $alice->call( 'POST', $PLC . '/example-export/runs', array( 'location' => 'a;b' ) ) ), 400, 'plug-ins: field checked' );
eq( status( $alice->call( 'POST', $PLC . '/example-tag-rules/runs', array() ) ), 400, 'plug-ins: needed field missing' );
eq( status( $alice->call( 'POST', $PLC . '/example-tag-rules/runs', array( 'tags' => $plBp ) ) ), 400, 'plug-ins: a file of another kind is refused' );
eq( status( $alice->call( 'POST', $PLC . '/example-tag-rules/runs', array( 'tags' => $bpFid ) ) ), 400, 'plug-ins: a file of another project is refused' );
$r = $alice->call( 'POST', $PLC . '/example-tag-rules/runs', array( 'tags' => $tagFid, 'bp' => $plBp ) );
eq( array( status( $r ), $r[1]['args'] ?? null ), array( 202, array( 'location=any', 'actions=tag-Add-Force:plugin-tag-1/tag-Add-Force:plugin-tag-2', 'out=%JOB%/out.xml' ) ), 'plug-ins: changing run queued; bp ignored for a run type that takes none' );
$tagRun = $PL . '/runs/' . $r[1]['jid'];
eq( waitRun( $alice, $tagRun )[1]['state'] ?? null, 'done', 'plug-ins: changing run done' );
$r = $alice->call( 'POST', $tagRun . '/save' );
eq( status( $r ), 201, 'plug-ins: result configuration taken as a new version' );
$r = $alice->call( 'GET', $PL . '/configs/' . ( $r[1]['cid'] ?? 'x' ) . '/objects?type=tag&filter=' . rawurlencode( '(name eq plugin-tag-2)' ) );
eq( array( status( $r ), $r[1]['total'] ?? null ), array( 200, 1 ), 'plug-ins: the new version holds the change of the run' );
eq( status( $alice->call( 'POST', $PLC . '/badargs-in/runs', array() ) ), 500, 'plug-ins: a plug-in can not set in=' );
eq( status( $alice->call( 'POST', $PLC . '/badargs-out/runs', array() ) ), 500, 'plug-ins: a plug-in can not write outside the folder of the run' );
eq( status( $alice->call( 'POST', $PLC . '/wrongapi-x/runs', array() ) ), 404, 'plug-ins: no run type of a refused plug-in' );
eq( status( $alice->call( 'PUT', $PL . '/members', array( 'user' => 'bob', 'role' => 'write', 'scope' => array( 'shared' ) ) ) ), 200, 'plug-ins: bob limited' );
eq( status( $bob->call( 'POST', $PLC . '/example-export/runs', array() ) ), 403, 'plug-ins: no run for a limited member' );
// a raw file kind, a run without a version, the result into this and into another project
$sw = "hostname SW1\nip access-list extended ACL-IN\n permit tcp any host 10.1.1.10 eq 443\n deny ip any any\n";
eq( status( $up( $alice, $PL, 'mig-source', "hostname only\n" ) ), 400, 'plug-ins: raw file - the check of the plug-in refuses it' );
eq( status( $up( $alice, $PL, 'mig-source', $sw . str_repeat( "! filler\n", 300 ) ) ), 413, 'plug-ins: raw file - the size limit of the kind' );
$r = $up( $alice, $PL, 'mig-source', $sw );
eq( status( $r ), 201, 'plug-ins: raw file (not JSON) uploaded' );
$srcFid = $r[1]['fid'];
$r = $alice->call( 'GET', $PL . '/files/' . $srcFid . '/download' );
eq( array( status( $r ), $r[1] ), array( 200, $sw ), 'plug-ins: raw file comes back unchanged' );
eq( status( $bob->call( 'GET', $PL . '/files/' . $srcFid . '/download' ) ), 403, 'plug-ins: no raw file for a limited member' );
eq( status( $alice->call( 'POST', $PLC . '/mig-import/runs', array( 'vendor' => 'ciscoswitch', 'source' => $srcFid ) ) ), 404, 'plug-ins: a run without a version is not started on a version' );
eq( status( $alice->call( 'POST', $PL . '/example-export/runs', array() ) ), 404, 'plug-ins: a run that needs a version is not started without one' );
eq( status( $alice->call( 'POST', $PL . '/mig-import/runs', array( 'vendor' => 'paloalto', 'source' => $srcFid ) ) ), 400, 'plug-ins: select field - only its options' );
eq( status( $alice->call( 'POST', $PL . '/mig-import/runs', array( 'vendor' => 'ciscoswitch', 'source' => $srcFid, 'kinds' => array( 'address', 'x' ) ) ) ), 400, 'plug-ins: multi field - only its options' );
eq( status( $alice->call( 'POST', $PL . '/mig-import/runs', array( 'vendor' => 'ciscoswitch', 'source' => $tagFid ) ) ), 400, 'plug-ins: a JSON file is not a raw source' );
$r = $alice->call( 'POST', $PL . '/mig-import/runs', array( 'vendor' => 'ciscoswitch', 'source' => $srcFid, 'kinds' => array( 'address', 'rule' ) ) );
eq( array( status( $r ), array_key_exists( 'cid', (array)$r[1] ) ? $r[1]['cid'] : 'x', $r[1]['args'][0] ?? null, preg_match( '#^file=%FILES%/[0-9a-f]{32}\.dat$#', $r[1]['args'][1] ?? '' ), $r[1]['args'][4] ?? null ),
    array( 202, null, 'vendor=ciscoswitch', 1, '#kinds=address+rule' ), 'plug-ins: run without a version queued' );
$migRun = $PL . '/runs/' . ( $r[1]['jid'] ?? 'x' );
$r = waitRun( $alice, $migRun );
eq( array( $r[1]['state'] ?? null, in_array( 'out.xml', array_column( $r[1]['files'] ?? array(), 'name' ), TRUE ) ), array( 'done', TRUE ), 'plug-ins: run without a version done, result configuration written' );
$r = $alice->call( 'POST', $migRun . '/save' );
eq( array( status( $r ), $r[1]['pid'] ?? null, $r[1]['note'] ?? null ), array( 201, substr( $PL, 9 ), 'mig-import run ' . substr( $migRun, -32, 8 ) ), 'plug-ins: result as the version of this project' );
$r = $alice->call( 'GET', $PL . '/configs/' . ( $r[1]['cid'] ?? 'x' ) . '/objects?type=rule&location=any' );
eq( array( status( $r ), ( $r[1]['total'] ?? 0 ) >= 2 ), array( 200, TRUE ), 'plug-ins: the migrated version opens in the viewer and holds the rules' );
$r = $alice->call( 'POST', 'projects', array( 'name' => 'Optimise' ) );
$OPT = $r[1]['pid'];
$r = $alice->call( 'POST', $migRun . '/save', array( 'project' => $OPT ) );
eq( array( status( $r ), $r[1]['pid'] ?? null, $r[1]['note'] ?? null ), array( 201, $OPT, 'mig-import run ' . substr( $migRun, -32, 8 ) . ' of project "Plug-ins"' ), 'plug-ins: result as a version of another project, with where it comes from' );
eq( count( $alice->call( 'GET', 'projects/' . $OPT . '/configs' )[1]['configs'] ?? array() ), 1, 'plug-ins: the other project holds the version' );
eq( status( $alice->call( 'POST', $migRun . '/save', array( 'project' => substr( $P, 9 ) === $OPT ? 'x' : str_repeat( '0', 32 ) ) ) ), 404, 'plug-ins: no result into an unknown project' );
eq( status( $alice->call( 'DELETE', 'projects/' . $OPT ) ), 200, 'plug-ins: other project deleted' );
eq( status( $alice->call( 'DELETE', $PL ) ), 200, 'plug-ins: project deleted' );

// ---- 12l. licence and an encrypted plug-in package
$m = $alice->call( 'GET', 'meta' )[1]['plugins'] ?? array();
$pk = array_values( array_filter( $m['plugins'] ?? array(), function( $x ) { return $x['name'] === 'pack'; } ) )[0] ?? array();
eq( array( $pk['on'] ?? null, $pk['form'] ?? null, $pk['why'] ?? null, isset( $m['runs']['pack-import'] ) ), array( FALSE, 'package', 'not licensed: no licence installed', FALSE ),
    'licence: without a licence the package is locked, the admin sees why, no run type' );
eq( status( $bob->call( 'GET', 'license' ) ), 404, 'licence: not for users who are no admin' );
$r = $alice->call( 'GET', 'license' );
eq( array( status( $r ), array_key_exists( 'licence', (array)$r[1] ) ? $r[1]['licence'] : 'x' ), array( 200, null ), 'licence: none installed' );
$licText = testLicence( $licKeys, array( 'id' => 'L-VIEWER', 'customer' => 'Viewer test', 'features' => array( 'test-pack' ), 'keys' => array( $pkRel['kid'] => $pkRel['key'] ) ) );
$r = $alice->call( 'PUT', 'license', array( 'license' => str_replace( 'Viewer test', 'Viewer tesT', $licText ) ) );
eq( status( $r ), 200, 'licence: the text around the block is not part of the licence' );
$forged = testLicence( testLicenceKeys(), array( 'features' => array( 'test-pack' ) ) );
eq( array( status( $r = $alice->call( 'PUT', 'license', array( 'license' => $forged ) ) ), strpos( $r[1]['error'] ?? '', 'licence: signed with an unknown key' ) ), array( 400, 0 ), 'licence: a licence of an unknown key is refused' );
$r = $alice->call( 'PUT', 'license', array( 'license' => $licText ) );
eq( array( status( $r ), $r[1]['licence']['customer'] ?? null, $r[1]['licence']['state'] ?? null, array_key_exists( 'keys', $r[1]['licence'] ?? array( 'keys' => 1 ) ) ),
    array( 200, 'Viewer test', 'valid', FALSE ), 'licence: installed, shown without keys' );
$m = $alice->call( 'GET', 'meta' )[1]['plugins'] ?? array();
eq( array( isset( $m['runs']['pack-import'] ), $m['kinds']['pack-cfg'] ?? null ), array( TRUE, 'router configuration' ), 'licence: the package is loaded, its run type is offered' );
$r = $alice->call( 'POST', 'projects', array( 'name' => 'Licensed' ) );
$LP = 'projects/' . $r[1]['pid'];
$cfgFid = $up( $alice, $LP, 'pack-cfg', "hostname R1\nip access-list extended T1\n permit tcp host 10.1.1.1 host 10.2.0.9 eq 443\n deny ip any any\n" )[1]['fid'] ?? '';
$r = $alice->call( 'POST', $LP . '/pack-import/runs', array( 'source' => $cfgFid ) );
eq( status( $r ), 202, 'licence: run of the package queued' );
$lrun = $LP . '/runs/' . ( $r[1]['jid'] ?? 'x' );
$r = waitRun( $alice, $lrun );
eq( array( $r[1]['state'] ?? null, $r[1]['error'] ?? null ), array( 'done', null ), 'licence: run of the package done' );
$log = (string)( $alice->call( 'GET', $lrun . '/files/run.log' )[1] ?? '' );
eq( strpos( $log, 'vendor parser from PANOSPHP_MIGRATION_PARSERS: CISCOISR/CISCOISR.php' ) !== FALSE, TRUE, 'licence: the run used the parser from the package (decrypted in memory)' );
eq( preg_grep( '/BEGIN PAN-OS-PHP LICENSE|LICENSE-----/', array_column( $r[1]['files'] ?? array(), 'name' ) ), array(), 'licence: no licence among the result files' );
$au = json_encode( $alice->call( 'GET', 'audit?limit=50' )[1] ?? array() );
eq( array( strpos( $au, 'PUT' ) !== FALSE, strpos( $au, 'BEGIN PAN-OS-PHP' ) ), array( TRUE, FALSE ), 'licence: installing is in the audit log, the licence text is not' );
// a clock that is set back locks licensed plug-ins
file_put_contents( $data . '/license-clock', (string)( time() + 86400 * 400 ) );
$m = $alice->call( 'GET', 'meta' )[1]['plugins'] ?? array();
eq( array( isset( $m['runs']['pack-import'] ), $alice->call( 'GET', 'license' )[1]['clock'] ?? null ), array( FALSE, 'set back' ), 'licence: clock set back - package locked' );
unlink( $data . '/license-clock' );
eq( status( $alice->call( 'DELETE', 'license' ) ), 200, 'licence: removed' );
eq( isset( ( $alice->call( 'GET', 'meta' )[1]['plugins']['runs'] ?? array() )['pack-import'] ), FALSE, 'licence: removed - package locked again' );
eq( status( $alice->call( 'DELETE', $LP ) ), 200, 'licence: project deleted' );

// ---- 13. stopping the service stops its workers
$bob->login( 'bob', 'bob-secret-12' );
$r = $bob->call( 'POST', 'projects', array( 'name' => 'Bob project' ) );
$P = 'projects/' . $r[1]['pid'];
$r = $bob->call( 'POST', $P . '/configs', null, array( 'b.xml', $xml ) );
eq( status( $bob->call( 'GET', $P . '/configs/' . $r[1]['cid'] . '/objects?type=tag' ) ), 200, 'bob reads in his own project' );
$pids = array_map( function( $f ) { return (int)file_get_contents( $f ); }, glob( $data . '/projects/*/work/*.pid' ) );
eq( count( $pids ) === 1 && posix_kill( $pids[0], 0 ), TRUE, 'one worker is running' );
// a worker that dies (here: killed) - the service removes its files, the next request starts a new one; the web part
// never looks at process ids (web and service may be separate containers)
$pidFiles = glob( $data . '/projects/*/work/*.pid' );
posix_kill( $pids[0], SIGKILL );
for( $i = 0; $i < 50 && file_exists( $pidFiles[0] ); $i++ )
    usleep( 100000 );
eq( array( file_exists( $pidFiles[0] ), glob( $data . '/run/*.sock' ) ), array( FALSE, array() ), 'killed worker: the service removed its pid file and socket' );
eq( status( $bob->call( 'GET', $P . '/configs/' . $r[1]['cid'] . '/objects?type=tag' ) ), 200, 'killed worker: the next request loads the version again' );
for( $i = 0; $i < 50 && count( glob( $data . '/projects/*/work/*.pid' ) ) === 0; $i++ )
    usleep( 100000 );
$pids = array_map( function( $f ) { return (int)trim( (string)file_get_contents( $f ) ); }, glob( $data . '/projects/*/work/*.pid' ) );
eq( count( $pids ) === 1 && $pids[0] > 1 && posix_kill( $pids[0], 0 ), TRUE, 'a new worker is running' );
// a worker that does not end when it is closed: the web part asks the service to stop it (discard closes the worker)
if( count( $pids ) !== 1 || $pids[0] <= 1 )
{
    fwrite( STDERR, "no worker process id - stop\n" . json_encode( $pids ) . "\n" . implode( "\n", $failed ) . "\n" . json_encode( glob( $data . "/projects/*/work/*" ) ) . "\n" );
    proc_terminate( $service );
    exit( 1 );
}
posix_kill( $pids[0], SIGSTOP );
$t0 = microtime( TRUE );
$bob->call( 'POST', $P . '/configs/' . $r[1]['cid'] . '/discard' );
for( $i = 0; $i < 50 && posix_kill( $pids[0], 0 ); $i++ )
    usleep( 100000 );
eq( posix_kill( $pids[0], 0 ), FALSE, 'a worker that does not answer is stopped by the service' );
eq( status( $bob->call( 'GET', $P . '/configs/' . $r[1]['cid'] . '/objects?type=tag' ) ), 200, 'and the version can be loaded again' );
$pids = array_map( function( $f ) { return (int)file_get_contents( $f ); }, glob( $data . '/projects/*/work/*.pid' ) );
proc_terminate( $service );
for( $i = 0; $i < 50 && posix_kill( $pids[0], 0 ); $i++ )
    usleep( 100000 );
eq( posix_kill( $pids[0], 0 ), FALSE, 'the worker stops with the service' );
eq( status( $bob->call( 'GET', $P . '/configs/' . $r[1]['cid'] . '/objects?type=tag' ) ), 503, 'without the service a version can not be loaded (503)' );

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $m ) print " - " . $m . "\n";
    exit( 1 );
}
exit( 0 );
