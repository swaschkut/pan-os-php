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

/**
 * config-viewer: one container per run (utils/develop/config-viewer/lib/ViewerContainer.php, bin/jobs.php).
 * No container runtime is needed: a stand-in program "docker" records how it is called and runs pan-os-php with the
 * folders that the call mounts. This checks the call (isolation options, mounts, nothing free from the job) and the
 * flow start / result / cancel - NOT that a real docker / podman accepts the call.
 *   php tests/test_config_viewer_container.php
 */
$repo = dirname( __FILE__, 2 );
$viewer = $repo . '/utils/develop/config-viewer';
require_once $viewer . '/lib/ViewerContainer.php';
require_once $viewer . '/lib/ViewerApp.php';
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
function withEnv( array $env, callable $fn )
{
    $all = array( 'PANOSPHP_VIEWER_CONTAINER', 'PANOSPHP_VIEWER_CONTAINER_IMAGE', 'PANOSPHP_VIEWER_CONTAINER_DATA', 'PANOSPHP_VIEWER_CONTAINER_TOOL',
        'PANOSPHP_VIEWER_CONTAINER_MEMORY', 'PANOSPHP_VIEWER_CONTAINER_CPUS', 'PANOSPHP_VIEWER_CONTAINER_USER', 'PANOSPHP_VIEWER_CONTAINER_PLUGINS' );
    foreach( $all as $k )
        putenv( isset( $env[$k] ) ? $k . '=' . $env[$k] : $k );
    try { return $fn(); }
    catch( Exception $e ) { return 'error: ' . $e->getMessage(); }
    finally { foreach( $all as $k ) putenv( $k ); }
}

// ---- 1. the call
$pid = str_repeat( 'a', 32 ); $jid = str_repeat( 'b', 32 ); $file = str_repeat( 'c', 32 ) . '.xml';
$job = array( 'pid' => $pid, 'jid' => $jid, 'file' => $file, 'type' => 'playbook',
    'rawArgs' => array( 'json=%FILES%/' . str_repeat( 'd', 32 ) . '.json', 'out=%JOB%/result.xml', '--network=host', '-v', '/:/host' ) );
eq( withEnv( array(), function() { return ViewerContainer::fromEnv( '/data' ); } ), null, 'not configured: no container' );
$base = array( 'PANOSPHP_VIEWER_CONTAINER' => 'docker', 'PANOSPHP_VIEWER_CONTAINER_IMAGE' => 'swaschkut/pan-os-php:develop', 'PANOSPHP_VIEWER_CONTAINER_USER' => '1000:1000' );
$cmd = withEnv( $base, function() use ( $job ) { return ViewerContainer::fromEnv( '/srv/viewer-data' )->runCommand( $job ); } );
// type=diff: two versions of the project as file1 / file2 under /project, no in=
$dcmd = withEnv( $base, function() use ( $job ) { return ViewerContainer::fromEnv( '/srv/viewer-data' )->runCommand( array( 'type' => 'diff', 'file' => null,
    'rawArgs' => array( 'file1=%PROJECT%/' . str_repeat( 'c', 32 ) . '.xml', 'file2=%PROJECT%/' . str_repeat( 'e', 32 ) . '.xml', 'outputformatset=set-commands.txt' ) ) + $job ); } );
eq( array( array_slice( $dcmd, -3 ), count( preg_grep( '/^in=/', $dcmd ) ), in_array( 'type=diff', $dcmd, TRUE ) ),
    array( array( 'file1=/project/' . str_repeat( 'c', 32 ) . '.xml', 'file2=/project/' . str_repeat( 'e', 32 ) . '.xml', 'outputformatset=set-commands.txt' ), 0, TRUE ),
    'diff in a container: both versions from /project (read-only), no in=' );
$image = array_search( 'swaschkut/pan-os-php:develop', $cmd, TRUE );
$opts = array_slice( $cmd, 0, $image );
eq( array_slice( $cmd, 0, 5 ), array( 'docker', 'run', '--rm', '--name', 'panosphp-run-' . $jid ), 'docker run --rm with the name of the run' );
foreach( array( array( '--network', 'none' ), array( '--cap-drop', 'ALL' ), array( '--security-opt', 'no-new-privileges' ), array( '--pids-limit', '256' ), array( '--memory', '2g' ),
    array( '--cpus', '2' ), array( '--user', '1000:1000' ), array( '--workdir', '/job' ), array( '--entrypoint', 'php' ) ) as $o )
{
    $i = array_search( $o[0], $opts, TRUE );
    eq( $i !== FALSE ? $opts[$i + 1] : null, $o[1], 'option ' . implode( ' ', $o ) );
}
eq( in_array( '--read-only', $opts, TRUE ), TRUE, 'option --read-only' );
$mounts = array();
foreach( $opts as $i => $o )
    if( $o === '--mount' )
        $mounts[] = $opts[$i + 1];
eq( $mounts, array( 'type=bind,src=/srv/viewer-data/projects/' . $pid . ',dst=/project,readonly', 'type=bind,src=/srv/viewer-data/projects/' . $pid . '/jobs/' . $jid . ',dst=/job' ),
    'host path: only the project (read-only) and the folder of the run are mounted' );
eq( array_slice( $cmd, $image + 1 ), array( '/tools/pan-os-php/utils/pan-os-php.php', 'type=playbook', 'in=/project/' . $file, 'json=/project/files/' . str_repeat( 'd', 32 ) . '.json',
    'out=/job/result.xml', '--network=host', '-v', '/:/host' ), 'arguments of the job come after the image (arguments of pan-os-php, never options of the runtime), paths as in the container' );
eq( count( array_filter( $opts, function( $o ) { return in_array( $o, array( '--privileged', '-v', '--volume', '--network=host', '--pid', '--device' ), TRUE ); } ) ), 0, 'no option from the job before the image' );
$cmd = withEnv( $base + array( 'PANOSPHP_VIEWER_CONTAINER_DATA' => 'viewer-data', 'PANOSPHP_VIEWER_CONTAINER_MEMORY' => '512m' ), function() use ( $job ) { return ViewerContainer::fromEnv( '/data' )->runCommand( $job ); } );
eq( array( in_array( 'type=volume,src=viewer-data,dst=/project,volume-subpath=projects/' . $pid . ',readonly', $cmd, TRUE ),
    in_array( 'type=volume,src=viewer-data,dst=/job,volume-subpath=projects/' . $pid . '/jobs/' . $jid, $cmd, TRUE ), in_array( '512m', $cmd, TRUE ) ), array( TRUE, TRUE, TRUE ), 'volume name: sub paths of the volume' );
$cmd = withEnv( $base, function() use ( $job ) { return ViewerContainer::fromEnv( '/data' )->runCommand( array( 'file' => null, 'tool' => 'vendor-migration' ) + $job ); } );
eq( array( in_array( 'type=vendor-migration', $cmd, TRUE ), count( preg_grep( '/^in=/', $cmd ) ) ), array( TRUE, 0 ), 'a run without a version: the type the plug-in names, no in=' );
// a run type of a plug-in with files of its own: the folder of the plug-in read-only, the environment with its path there
$pj = array( 'file' => null, 'tool' => 'vendor-migration', 'plugin' => 'migration', 'pluginBuiltin' => FALSE, 'rawEnv' => array( 'PANOSPHP_MIGRATION_PARSERS' => '%PLUGIN%/parser' ) ) + $job;
eq( substr( (string)withEnv( $base, function() use ( $pj ) { return ViewerContainer::fromEnv( '/data' )->runCommand( $pj ); } ), 0, 6 ), 'error:', 'plug-in with files, PANOSPHP_VIEWER_CONTAINER_PLUGINS not set: refused' );
$cmd = withEnv( $base + array( 'PANOSPHP_VIEWER_CONTAINER_PLUGINS' => '/srv/plugins' ), function() use ( $pj ) { return ViewerContainer::fromEnv( '/data' )->runCommand( $pj ); } );
eq( array( in_array( 'type=bind,src=/srv/plugins/migration,dst=/plugin,readonly', $cmd, TRUE ), in_array( 'PANOSPHP_MIGRATION_PARSERS=/plugin/parser', $cmd, TRUE ),
    array_search( 'PANOSPHP_MIGRATION_PARSERS=/plugin/parser', $cmd, TRUE ) < array_search( 'swaschkut/pan-os-php:develop', $cmd, TRUE ) ), array( TRUE, TRUE, TRUE ),
    'plug-in with files: its folder read-only at /plugin, environment before the image' );
// an encrypted plug-in: the package file read-only, the licence (one line) and %PLUGIN% = ppp://<name>
$pp = array( 'pluginPackage' => '/plugins/migration.ppp', 'licence' => '-----BEGIN PAN-OS-PHP LICENSE-----' . str_repeat( 'QUJD', 20 ) . '-----END PAN-OS-PHP LICENSE-----' ) + $pj;
$cmd = withEnv( $base + array( 'PANOSPHP_VIEWER_CONTAINER_PLUGINS' => '/srv/plugins' ), function() use ( $pp ) { return ViewerContainer::fromEnv( '/data' )->runCommand( $pp ); } );
eq( array( in_array( 'type=bind,src=/srv/plugins/migration.ppp,dst=/plugins/migration.ppp,readonly', $cmd, TRUE ), in_array( 'PANOSPHP_PLUGIN_PACKAGES=/plugins/migration.ppp', $cmd, TRUE ),
    in_array( $pp['licence'], array_map( function( $a ) { return substr( $a, strlen( 'PANOSPHP_LICENSE=' ) ); }, preg_grep( '/^PANOSPHP_LICENSE=/', $cmd ) ), TRUE ),
    in_array( 'PANOSPHP_MIGRATION_PARSERS=ppp://migration/parser', $cmd, TRUE ), in_array( 'type=bind,src=/srv/plugins/migration,dst=/plugin,readonly', $cmd, TRUE ) ),
    array( TRUE, TRUE, TRUE, TRUE, FALSE ), 'encrypted plug-in: package file, licence, files of the plug-in from ppp:// - no folder of clear text' );
eq( substr( (string)withEnv( $base + array( 'PANOSPHP_VIEWER_CONTAINER_PLUGINS' => '/srv/plugins' ), function() use ( $pp ) { return ViewerContainer::fromEnv( '/data' )->runCommand( array( 'licence' => "x\n--privileged" ) + $pp ); } ), 0, 6 ),
    'error:', 'encrypted plug-in: a licence value that is no licence block is refused' );
eq( substr( (string)withEnv( $base + array( 'PANOSPHP_VIEWER_CONTAINER_PLUGINS' => '/srv/../etc' ), function() { ViewerContainer::fromEnv( '/data' ); return 'x'; } ), 0, 6 ), 'error:', 'refused setting: plug-in folder with ..' );
$cmd = withEnv( array( 'PANOSPHP_VIEWER_CONTAINER' => 'podman' ) + $base, function() use ( $job ) { return ViewerContainer::fromEnv( '/data' )->runCommand( $job ); } );
eq( $cmd[0], 'podman', 'podman: same call' );
foreach( array( 'pid' => '../../etc', 'jid' => 'x', 'file' => '../viewer.sqlite', 'type' => 'stats --privileged' ) as $k => $v )
    eq( substr( (string)withEnv( $base, function() use ( $job, $k, $v ) { return ViewerContainer::fromEnv( '/data' )->runCommand( array( $k => $v ) + $job ); } ), 0, 6 ), 'error:', 'refused: ' . $k . ' = ' . $v );
foreach( array( array( 'PANOSPHP_VIEWER_CONTAINER' => 'sh' ), array( 'PANOSPHP_VIEWER_CONTAINER_IMAGE' => '' ), array( 'PANOSPHP_VIEWER_CONTAINER_IMAGE' => '--privileged' ),
    array( 'PANOSPHP_VIEWER_CONTAINER_DATA' => '/data/../etc' ), array( 'PANOSPHP_VIEWER_CONTAINER_DATA' => 'vol,readonly=false' ), array( 'PANOSPHP_VIEWER_CONTAINER_MEMORY' => 'all' ),
    array( 'PANOSPHP_VIEWER_CONTAINER_USER' => 'root' ) ) as $bad )
    eq( substr( (string)withEnv( $bad + $base, function() { ViewerContainer::fromEnv( '/data' ); return 'accepted'; } ), 0, 6 ), 'error:', 'refused setting: ' . json_encode( $bad ) );

// ---- 2. the flow with a stand-in "docker"
$data = sys_get_temp_dir() . '/viewer-container-test-' . getmypid();
$bin = $data . '-bin';
mkdir( $bin );
file_put_contents( $bin . '/docker', '#!' . PHP_BINARY . "\n" . <<<'FAKE'
<?php
// stand-in for docker: records the call; "run" starts pan-os-php with the mounted folders instead of a container
$a = array_slice( $argv, 1 );
file_put_contents( __DIR__ . '/calls.log', json_encode( $a ) . "\n", FILE_APPEND | LOCK_EX );
if( $a[0] === 'version' || $a[0] === 'ps' )
    exit( 0 );
if( $a[0] === 'rm' )
{
    $f = __DIR__ . '/' . end( $a ) . '.pid';
    if( is_file( $f ) )
        posix_kill( (int)file_get_contents( $f ), SIGKILL );
    exit( 0 );
}
$map = array(); $name = null;
foreach( $a as $i => $o )
{
    if( $o === '--mount' && preg_match( '#src=([^,]+),dst=([^,]+)#', $a[$i + 1], $m ) )
        $map[$m[2]] = $m[1];
    if( $o === '--name' )
        $name = $a[$i + 1];
    if( $o === '--entrypoint' )
        $rest = array_slice( $a, $i + 4 );
}
// longest target first: /project/files before /project
foreach( $rest as $i => $r )
    $rest[$i] = preg_replace_callback( '#(?<==|^)/(project|job)(?=/|$)#', function( $m ) use ( $map ) { return $map['/' . $m[1]]; }, $r );
file_put_contents( __DIR__ . '/' . $name . '.pid', getmypid() );
// a container the kernel stops for its memory limit ends with 137 (SIGKILL); a run with this marker plays that
if( in_array( 'memorythreshold=999936', $a, TRUE ) )
{
    print "Killed\n";
    exit( 137 );
}
if( in_array( 'memorythreshold=999872', $a, TRUE ) )
{
    print "some other error\n";
    exit( 1 );
}
chdir( $map['/job'] );
pcntl_exec( PHP_BINARY, array_merge( array( trim( file_get_contents( __DIR__ . '/tool' ) ) ), $rest ) );
FAKE
);
chmod( $bin . '/docker', 0755 );
file_put_contents( $bin . '/tool', $repo . '/utils/pan-os-php.php' );

$env = array( 'PANOSPHP_VIEWER_DATA' => $data, 'PATH' => $bin . ':' . getenv('PATH') );
$p = proc_open( array( PHP_BINARY, $viewer . '/bin/user.php', 'add', 'alice' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null, $env + array( 'VIEWER_PASSWORD' => 'alice-secret-1' ) );
stream_get_contents( $pipes[1] );
proc_close( $p );
$null = array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'file', '/dev/null', 'w' ), 2 => array( 'file', '/dev/null', 'w' ) );
$cenv = $env + array( 'PANOSPHP_VIEWER_JOBS' => '1', 'PANOSPHP_VIEWER_CONTAINER' => 'docker', 'PANOSPHP_VIEWER_CONTAINER_IMAGE' => 'pan-os-php:test' );

// a wrong setting stops the job runner - no silent fall back to runs without a container
$p = proc_open( array( PHP_BINARY, $viewer . '/bin/jobs.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, $viewer, array( 'PANOSPHP_VIEWER_CONTAINER_IMAGE' => '' ) + $cenv );
$err = stream_get_contents( $pipes[2] );
eq( array( proc_close( $p ), strpos( $err, 'PANOSPHP_VIEWER_CONTAINER_IMAGE' ) !== FALSE ), array( 1, TRUE ), 'job runner: stops without the image setting' );
$p = proc_open( array( PHP_BINARY, $viewer . '/bin/jobs.php' ), array( 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, $viewer, array( 'PANOSPHP_VIEWER_CONTAINER' => 'podman' ) + $cenv );
$err = stream_get_contents( $pipes[2] );
eq( proc_close( $p ), 1, 'job runner: stops when the runtime is not there (podman is not installed here: ' . trim( $err ) . ')' );

$jobs = proc_open( array( PHP_BINARY, $viewer . '/bin/jobs.php' ), $null, $pipes, $viewer, $cenv );
$sock = stream_socket_server( 'tcp://127.0.0.1:0' );
$port = (int)substr( strrchr( stream_socket_get_name( $sock, FALSE ), ':' ), 1 );
fclose( $sock );
$server = proc_open( array( PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $viewer ), $null, $pipes, $viewer, $env + array( 'PHP_CLI_SERVER_WORKERS' => '2' ) );
$base = 'http://127.0.0.1:' . $port . '/';
for( $i = 0; $i < 50 && @file_get_contents( $base . 'index.html' ) === FALSE; $i++ )
    usleep( 100000 );
register_shutdown_function( function() use ( $server, $jobs, $data, $bin ) {
    foreach( array( $server, $jobs ) as $proc )
        if( is_resource( $proc ) ) { proc_terminate( $proc ); proc_close( $proc ); }
    exec( 'rm -rf ' . escapeshellarg( $data ) . ' ' . escapeshellarg( $bin ) );
} );

$cookie = ''; $csrf = null;
function call( $method, $path, $body = null, $upload = null )
{
    global $base, $cookie, $csrf;
    $headers = array();
    if( $cookie !== '' ) $headers[] = 'Cookie: ' . $cookie;
    if( $method !== 'GET' && $csrf !== null ) $headers[] = 'X-CSRF-Token: ' . $csrf;
    $content = null;
    if( $upload !== null )
    {
        $b = '----viewertest' . bin2hex( random_bytes( 6 ) );
        $headers[] = 'Content-Type: multipart/form-data; boundary=' . $b;
        $content = "--" . $b . "\r\nContent-Disposition: form-data; name=\"" . $upload[2] . "\"; filename=\"" . $upload[0] . "\"\r\nContent-Type: text/plain\r\n\r\n" . $upload[1] . "\r\n--" . $b . "--\r\n";
    }
    elseif( $body !== null )
    {
        $headers[] = 'Content-Type: application/json';
        $content = json_encode( $body );
    }
    $raw = file_get_contents( $base . 'api.php/' . $path, FALSE, stream_context_create( array( 'http' => array( 'method' => $method, 'header' => implode( "\r\n", $headers ),
        'content' => $content, 'ignore_errors' => TRUE, 'timeout' => 120 ) ) ) );
    $status = 0;
    foreach( $http_response_header ?? array() as $h )
    {
        if( preg_match( '#^HTTP/\S+ (\d+)#', $h, $m ) ) $status = (int)$m[1];
        if( preg_match( '#^Set-Cookie: (PANOSPHPVIEWER=[^;]*)#i', $h, $m ) ) $cookie = $m[1];
    }
    $json = json_decode( (string)$raw, TRUE );
    return array( $status, is_array( $json ) ? $json : $raw );
}
function waitRun( $path, $until = array( 'queued', 'running' ) )
{
    for( $i = 0; $i < 900; $i++ )
    {
        $r = call( 'GET', $path );
        if( !in_array( $r[1]['state'] ?? '', $until, TRUE ) )
            return $r;
        usleep( 200000 );
    }
    return $r;
}
function calls()
{
    global $bin;
    return array_map( function( $l ) { return json_decode( $l, TRUE ); }, file( $bin . '/calls.log', FILE_IGNORE_NEW_LINES ) ?: array() );
}

$r = call( 'POST', 'login', array( 'user' => 'alice', 'password' => 'alice-secret-1' ) );
$csrf = $r[1]['csrf'] ?? null;
$r = call( 'POST', 'projects', array( 'name' => 'Container runs' ) );
$pid = $r[1]['pid'];
$P = 'projects/' . $pid;
$r = call( 'POST', $P . '/configs', null, array( 'c.xml', file_get_contents( $repo . '/tests/input/panorama-10.0-merger.xml' ), 'config' ) );
$cid = $r[1]['cid'];
eq( strlen( (string)$cid ), 32, 'configuration uploaded' );

// stats
$r = call( 'POST', $P . '/configs/' . $cid . '/stats/runs', array() );
$jid = $r[1]['jid'] ?? '';
$r = waitRun( $P . '/runs/' . $jid );
eq( $r[1]['state'] ?? null, 'done', 'stats run in the "container": done' );
eq( in_array( 'json/debugAPI_string.json', array_column( $r[1]['files'] ?? array(), 'name' ), TRUE ), TRUE, 'stats run: result file in the folder of the run' );
$run = array_values( array_filter( calls(), function( $c ) use ( $jid ) { return $c[0] === 'run' && in_array( 'panosphp-run-' . $jid, $c, TRUE ); } ) );
eq( count( $run ), 1, 'stats run: one container was started for it' );
$c = $run[0] ?? array();
$i = array_search( 'pan-os-php:test', $c, TRUE );
eq( array( in_array( 'none', $c, TRUE ), in_array( '--read-only', $c, TRUE ), in_array( 'type=bind,src=' . $data . '/projects/' . $pid . ',dst=/project,readonly', $c, TRUE ),
    in_array( 'type=bind,src=' . $data . '/projects/' . $pid . '/jobs/' . $jid . ',dst=/job', $c, TRUE ) ), array( TRUE, TRUE, TRUE, TRUE ), 'stats run: no network, read-only, the two mounts' );
eq( count( array_filter( array_slice( $c, (int)$i + 1 ), function( $a ) use ( $data ) { return strpos( $a, $data ) !== FALSE; } ) ), 0, 'stats run: no path of the server in the arguments of pan-os-php' );
eq( preg_match( '#^in=/project/[0-9a-f]{32}\.xml$#', $c[(int)$i + 3] ?? '' ), 1, 'stats run: in= is the version file in the container' );

// playbook with a BP JSON, result as version
$r = call( 'POST', $P . '/files?kind=playbook', null, array( 'pb.json', json_encode( array( 'command' => array(
    array( 'type' => 'address', 'actions' => 'actions=exportToExcel:addresses.html', 'location' => 'location=any' ),
    array( 'type' => 'rule', 'actions' => 'actions=logend-Enable', 'location' => 'location=any' ) ) ) ), 'file' ) );
$pb = $r[1]['fid'] ?? '';
$r = call( 'POST', $P . '/files?kind=bp', null, array( 'bp.json', file_get_contents( $repo . '/utils/api/v1/bp/scm_bp_sp_panw.json' ), 'file' ) );
$bp = $r[1]['fid'] ?? '';
$r = call( 'POST', $P . '/configs/' . $cid . '/playbook/runs', array( 'playbook' => $pb, 'bp' => $bp ) );
$jid2 = $r[1]['jid'] ?? '';
$r = waitRun( $P . '/runs/' . $jid2 );
eq( $r[1]['state'] ?? null, 'done', 'playbook run in the "container": done' );
$names = array_column( $r[1]['files'] ?? array(), 'name' );
eq( array( in_array( 'addresses.html', $names, TRUE ), in_array( 'out.xml', $names, TRUE ) ), array( TRUE, TRUE ), 'playbook run: export and result configuration in the folder of the run (' . implode( ', ', $names ) . ')' );
$c = array_values( array_filter( calls(), function( $c ) use ( $jid2 ) { return $c[0] === 'run' && in_array( 'panosphp-run-' . $jid2, $c, TRUE ); } ) )[0] ?? array();
$tail = array_slice( $c, (int)array_search( 'pan-os-php:test', $c, TRUE ) + 1 );
eq( count( preg_grep( '#=/project/files/[0-9a-f]{32}\.json$#', $tail ) ), 2, 'playbook run: playbook and BP JSON from /project/files (' . implode( ' ', $tail ) . ')' );
eq( count( preg_grep( '#=/job/#', $tail ) ) >= 1, TRUE, 'playbook run: result goes to /job' );
eq( call( 'POST', $P . '/runs/' . $jid2 . '/save' )[0], 201, 'playbook run: result taken as a new version' );

// playbook options for large configurations go to type=playbook; a run killed for memory is told apart
$r = call( 'POST', $P . '/configs/' . $cid . '/playbook/runs', array( 'playbook' => $pb, 'subprocess' => TRUE, 'memorythreshold' => '512', 'debugmemory' => TRUE, 'removestagefiles' => TRUE ) );
$r = waitRun( $P . '/runs/' . ( $r[1]['jid'] ?? '' ) );
eq( array( $r[1]['state'] ?? null, array_slice( $r[1]['args'] ?? array(), 4 ) ), array( 'done', array( 'subprocess', 'debugmemory', 'removestagefiles', 'memorythreshold=512' ) ),
    'playbook options: subprocess, memorythreshold, debugmemory, removestagefiles - the run works with them' );
$log = (string)call( 'GET', $P . '/runs/' . $r[1]['jid'] . '/files/run.log' )[1];
eq( strpos( $log, 'Running step as subprocess' ) !== FALSE, TRUE, 'playbook options: the steps ran as subprocesses (debugmemory in run.log)' );
foreach( array( array( 'memorythreshold' => '10' ), array( 'memorythreshold' => 'x' ), array( 'subprocess' => 'yes' ) ) as $bad )
    eq( call( 'POST', $P . '/configs/' . $cid . '/playbook/runs', array( 'playbook' => $pb ) + $bad )[0], 400, 'playbook options checked: ' . json_encode( $bad ) );
$r = call( 'POST', $P . '/configs/' . $cid . '/playbook/runs', array( 'playbook' => $pb, 'memorythreshold' => 999936 ) );
$r = waitRun( $P . '/runs/' . ( $r[1]['jid'] ?? '' ) );
eq( array( $r[1]['state'] ?? null, $r[1]['reason'] ?? null, strpos( $r[1]['error'] ?? '', 'out of memory' ) === 0, strpos( $r[1]['error'] ?? '', 'limit per run: 2g' ) !== FALSE ),
    array( 'failed', 'memory', TRUE, TRUE ), 'container killed (137): failed, reason memory, with the limit per run' );
$r = call( 'POST', $P . '/configs/' . $cid . '/playbook/runs', array( 'playbook' => $pb, 'memorythreshold' => 999872 ) );
$r = waitRun( $P . '/runs/' . ( $r[1]['jid'] ?? '' ) );
eq( array( $r[1]['state'] ?? null, $r[1]['reason'] ?? null, $r[1]['error'] ?? null ), array( 'failed', 'error', 'pan-os-php ended with an error (see run.log)' ),
    'other error: reason error' );
eq( array( ViewerApp::runFailure( 1, null, "x\n ** step type=rule ended with exit code 137 - the process was killed, most likely out of memory - the playbook stops here", null )[0],
    ViewerApp::runFailure( 255, null, "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 20480 bytes)", null )[0],
    ViewerApp::runFailure( -1, 9, '', null )[0], ViewerApp::runFailure( 1, null, 'derr: no such object', '4g' )[0] ),
    array( 'memory', 'memory', 'memory', 'error' ), 'out of memory also from the log (killed subprocess step, PHP memory_limit) and from signal 9' );

// cancel: the container is removed
$r = call( 'POST', $P . '/configs/' . $cid . '/stats/runs', array() );
$jid3 = $r[1]['jid'] ?? '';
waitRun( $P . '/runs/' . $jid3, array( 'queued' ) );
eq( call( 'DELETE', $P . '/runs/' . $jid3 )[0], 200, 'cancel a running run' );
for( $i = 0; $i < 50; $i++ )
{
    $rm = array_filter( calls(), function( $c ) use ( $jid3 ) { return $c === array( 'rm', '--force', 'panosphp-run-' . $jid3 ); } );
    if( count( $rm ) )
        break;
    usleep( 100000 );
}
eq( count( $rm ) >= 1, TRUE, 'cancel: the container of the run is removed (rm --force)' );
$fpid = (int)@file_get_contents( $bin . '/panosphp-run-' . $jid3 . '.pid' );
usleep( 300000 );
eq( $fpid > 0 && !posix_kill( $fpid, 0 ), TRUE, 'cancel: the run does not go on' );
eq( in_array( array( 'ps', '--all', '--quiet', '--filter', 'label=panosphp-viewer=' . substr( hash( 'sha256', $data ), 0, 16 ) ), calls(), TRUE ), TRUE, 'start of the job runner: looks for containers left over' );

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $m ) print " - " . $m . "\n";
    exit( 1 );
}
exit( 0 );
