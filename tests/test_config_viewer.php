<?php
/**
 * Tests of the config-viewer prototype (utils/develop/config-viewer): login, separation between users, project
 * permissions (read / write / owner), CSRF, input checks, load-once worker, change in memory, save, autosave recovery.
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

// ---- users, server
$env = array( 'PANOSPHP_VIEWER_DATA' => $data, 'PATH' => getenv('PATH'), 'PANOSPHP_VIEWER_AUTOSAVE_MIN' => '1' );
foreach( array( 'alice' => 'alice-secret-1 admin', 'bob' => 'bob-secret-12', 'carol' => 'carol-secret-3' ) as $name => $spec )
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
$sock = stream_socket_server( 'tcp://127.0.0.1:0' );
$port = (int)substr( strrchr( stream_socket_get_name( $sock, FALSE ), ':' ), 1 );
fclose( $sock );
$server = proc_open( array( PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $viewer ), array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'file', '/dev/null', 'w' ),
    2 => array( 'file', '/dev/null', 'w' ) ), $pipes, $viewer, $env + array( 'PHP_CLI_SERVER_WORKERS' => '4' ) );
$base = 'http://127.0.0.1:' . $port . '/';
for( $i = 0; $i < 50 && @file_get_contents( $base . 'index.html' ) === FALSE; $i++ )
    usleep( 100000 );

function cleanup()
{
    global $server, $data;
    foreach( glob( $data . '/projects/*/work/*.pid' ) ?: array() as $f )
        @posix_kill( (int)file_get_contents( $f ), SIGKILL );
    foreach( array( $server, $GLOBALS['service'] ) as $proc )
        if( is_resource( $proc ) )
        {
            proc_terminate( $proc );
            proc_close( $proc );
        }
    exec( 'rm -rf ' . escapeshellarg( $data ) );
}
register_shutdown_function( 'cleanup' );

/** a browser: keeps the session cookie and the CSRF token of one user */
class Client
{
    public $cookie = '';
    public $csrf = null;
    public $sendCsrf = TRUE;

    /** @return array [ status, decoded JSON or raw body ] */
    function call( $method, $path, $body = null, $upload = null )
    {
        global $base;
        $headers = array();
        if( $this->cookie !== '' ) $headers[] = 'Cookie: ' . $this->cookie;
        if( $method !== 'GET' && $this->csrf !== null && $this->sendCsrf ) $headers[] = 'X-CSRF-Token: ' . $this->csrf;
        $content = null;
        if( $upload !== null )
        {
            $b = '----viewertest' . bin2hex( random_bytes( 6 ) );
            $headers[] = 'Content-Type: multipart/form-data; boundary=' . $b;
            $content = "--" . $b . "\r\nContent-Disposition: form-data; name=\"config\"; filename=\"" . $upload[0] . "\"\r\nContent-Type: text/xml\r\n\r\n" . $upload[1] . "\r\n--" . $b . "--\r\n";
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
foreach( array( 'bin/worker.php', 'bin/user.php' ) as $f )
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

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $m ) print " - " . $m . "\n";
    exit( 1 );
}
exit( 0 );
