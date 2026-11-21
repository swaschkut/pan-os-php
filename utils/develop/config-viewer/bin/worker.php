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
 * config-viewer worker: loads ONE configuration once and keeps it in memory (UTIL::$sharedConfig). Started by
 * bin/service.php on request of ViewerApp::session(), never by a user. Requests arrive on a unix socket inside the project folder, one JSON line
 * per connection:
 *   references type, args, name -> who uses the objects of that name (in a forked child)
 *   locations                 -> the locations of the loaded configuration (device groups / vsys / containers, snippets)
 *   read    type, args        -> runs in a forked child (a failing run / exit() can not hurt the loaded configuration)
 *   change  type, args, note  -> tried in a forked child first; only when that worked it runs on the real memory
 *   save    file              -> writes the memory to a new file (only when there are unsaved changes)
 *   status / close
 * Unsaved changes are written to the autosave file every <autosave> minutes and when the worker stops.
 *
 * Not started on its own: bin/service.php forks and includes this file.
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
// included by bin/service.php in a forked child, with the (validated) parameters in $viewerWorker
if( !isset( $viewerWorker ) || !is_array( $viewerWorker ) )
{
    fwrite( STDERR, "config-viewer worker: started by bin/service.php only\n" );
    exit( 2 );
}
$configFile = $viewerWorker['config'];
$sockFile = $viewerWorker['sock'];
$pidFile = $viewerWorker['pid'];
$logFile = $viewerWorker['log'];
$autosaveFile = $viewerWorker['autosave'];
$autosaveSec = max( 60, (int)$viewerWorker['autosaveMin'] * 60 );
$idleSec = max( 60, (int)$viewerWorker['idleMin'] * 60 );

posix_setsid();
ini_set( 'error_log', $logFile );
ini_set( 'log_errors', '1' );
ini_set( 'display_errors', '0' );
// whatever pan-os-php prints outside of a captured run is dropped
ob_start( function( $buffer ) { return ''; }, 4096 );
// written apart and renamed: the web part must never see the file without the process id in it
file_put_contents( $pidFile . '.tmp', (string)getmypid(), LOCK_EX );
chmod( $pidFile . '.tmp', 0600 );
rename( $pidFile . '.tmp', $pidFile );

$GLOBALS['viewerIsChild'] = FALSE;
$GLOBALS['viewerState'] = array( 'dirty' => FALSE, 'changes' => array(), 'saved' => null, 'autosaved' => null, 'loaded' => time() );

/**
 * The pan-os-php framework turns every PHP warning into a fatal error (also with @). The worker's own file and
 * socket calls must not stop it, e.g. a select() interrupted by a finished child.
 */
function viewerQuiet( callable $fn )
{
    set_error_handler( function() { return TRUE; } );
    try
    {
        return $fn();
    }
    finally
    {
        restore_error_handler();
    }
}

function viewerUnlink( $file )
{
    viewerQuiet( function() use ( $file ) { if( file_exists( $file ) ) unlink( $file ); } );
}

function viewerLog( $text )
{
    global $logFile;
    viewerQuiet( function() use ( $logFile, $text ) { file_put_contents( $logFile, date( 'c' ) . ' ' . $text . "\n", FILE_APPEND ); } );
}

function viewerStatus()
{
    $s = $GLOBALS['viewerState'];
    return array( 'dirty' => $s['dirty'], 'changes' => $s['changes'], 'saved' => $s['saved'], 'autosaved' => $s['autosaved'], 'loaded' => $s['loaded'] );
}

/**
 * the locations of the loaded configuration, for the location choice of the page: Panorama - shared and every device
 * group; firewall - shared and every vsys (and shared gateway); SCM - every container (folder) and snippet
 */
function viewerLocations()
{
    $pan = UTIL::$sharedConfig['pan'] ?? null;
    $out = array();
    $add = function( $kind, $list ) use ( &$out ) {
        foreach( is_array( $list ) ? $list : array() as $o )
            if( is_object( $o ) && method_exists( $o, 'name' ) && is_string( $o->name() ) && $o->name() !== '' )
                $out[] = array( 'name' => $o->name(), 'kind' => $kind );
    };
    if( $pan instanceof PanoramaConf )
    {
        $out[] = array( 'name' => 'shared', 'kind' => 'shared' );
        $add( 'device-group', $pan->getDeviceGroups() );
        return array( 'config' => 'panorama', 'locations' => $out );
    }
    if( $pan instanceof PANConf )
    {
        $out[] = array( 'name' => 'shared', 'kind' => 'shared' );
        $add( 'vsys', $pan->getVirtualSystems() );
        $add( 'shared-gateway', $pan->getSharedGateways() );
        return array( 'config' => 'firewall', 'locations' => $out );
    }
    if( $pan instanceof BuckbeakConf || $pan instanceof FawkesConf )
    {
        $add( 'container', $pan->getContainers() );
        $add( 'snippet', $pan->getSnippets() );
        return array( 'config' => 'scm', 'locations' => $out );
    }
    return array( 'config' => 'unknown', 'locations' => $out );
}

/** the viewer type (and rule type / profile type) of a pan-os-php object, null for others (interface, vsys, …) */
function viewerTypeOf( $o )
{
    static $rules = array( 'SecurityRule' => 'security', 'NatRule' => 'nat', 'DecryptionRule' => 'decryption', 'AppOverrideRule' => 'appoverride',
        'CaptivePortalRule' => 'captiveportal', 'AuthenticationRule' => 'authentication', 'PbfRule' => 'pbf', 'QoSRule' => 'qos', 'DoSRule' => 'dos',
        'TunnelInspectionRule' => 'tunnelinspection', 'DefaultSecurityRule' => 'defaultsecurity', 'NetworkPacketBrokerRule' => 'networkpacketbroker',
        'SDWanRule' => 'sdwan' );
    static $profiles = array( 'URLProfile' => 'url-filtering', 'AntiVirusProfile' => 'virus', 'VirusAndWildfireProfile' => 'virus',
        'VulnerabilityProfile' => 'vulnerability', 'AntiSpywareProfile' => 'spyware', 'FileBlockingProfile' => 'file-blocking',
        'DataFilteringProfile' => 'data-filtering', 'WildfireProfile' => 'wildfire-analysis', 'customURLProfile' => 'custom-url-category',
        'DNSSecurityProfile' => 'dns-security', 'SaasSecurityProfile' => 'saas-security' );
    static $plain = array( 'Address' => 'address', 'AddressGroup' => 'address', 'Region' => 'address', 'Service' => 'service', 'ServiceGroup' => 'service',
        'Tag' => 'tag', 'Zone' => 'zone', 'Schedule' => 'schedule', 'SecurityProfileGroup' => 'securityprofilegroup', 'App' => 'application',
        'AppGroup' => 'application', 'AppFilter' => 'application', 'AppCustom' => 'application', 'EDL' => 'edl', 'LogProfile' => 'log-profile' );
    $c = get_class( $o );
    if( isset( $rules[$c] ) )
        return array( 'type' => 'rule', 'ruletype' => $rules[$c] );
    if( isset( $profiles[$c] ) )
        return array( 'type' => 'securityprofile', 'securityprofiletype' => $profiles[$c] );
    if( isset( $plain[$c] ) )
        return array( 'type' => $plain[$c] );
    return null;
}

/** the objects that use $o (a rule, group, profile group, …), each once, with the fields it uses $o in */
function viewerUsers( $o )
{
    $refs = array();
    foreach( isset( $o->refrules ) && is_array( $o->refrules ) ? $o->refrules : array() as $ref )
    {
        // from the reference up to the object that uses it: a rule / group / profile group …; a "…Container" on
        // the way is the field (AddressRuleContainer:source)
        $field = null;
        $user = null;
        $first = null;
        for( $x = $ref, $i = 0; is_object( $x ) && $i < 8; $x = $x->owner ?? null, $i++ )
        {
            if( $first === null && method_exists( $x, 'name' ) && !preg_match( '/Store$/', get_class( $x ) ) )
                $first = $x;
            if( $field === null && preg_match( '/Container$/', get_class( $x ) ) && method_exists( $x, 'name' ) && is_string( $x->name() ) && $x->name() !== '' )
                $field = $x->name();
            if( viewerTypeOf( $x ) !== null )
            {
                $user = $x;
                break;
            }
        }
        $user = $user ?? $first;
        if( !is_object( $user ) )
            continue;
        $t = viewerTypeOf( $user );
        $loc = PH::getLocationString( $user );
        $row = array( 'type' => $t['type'] ?? null, 'ruletype' => $t['ruletype'] ?? null, 'securityprofiletype' => $t['securityprofiletype'] ?? null,
            'location' => is_string( $loc ) ? $loc : null, 'name' => method_exists( $user, 'name' ) ? (string)$user->name() : '', 'class' => get_class( $user ),
            'rulebase' => method_exists( $user, 'isPostRule' ) && $t !== null && $t['type'] === 'rule' ? ( $user->isPostRule() ? 'post' : 'pre' ) : null );
        $key = $row['class'] . '|' . $row['location'] . '|' . $row['name'];
        if( !isset( $refs[$key] ) )
            $refs[$key] = $row + array( 'fields' => array() );
        if( $field !== null && !in_array( $field, $refs[$key]['fields'], TRUE ) )
            $refs[$key]['fields'][] = $field;
    }
    return array_values( $refs );
}

/**
 * who uses the objects named $name of a type (in the location of $args): every object found, with its references -
 * the referencing object (type, rule type, location, name, pre / post) and the field (source, destination, member, …)
 */
function viewerReferences( $type, array $args, $name )
{
    global $configFile;
    // the run only selects the objects of the location (no object has this name, so nothing is shown)
    $argv = array_merge( array( 'config-viewer', 'in=' . $configFile, 'shadow-json' ), $args, array( 'actions=display', 'filter=(name eq config-viewer-load)' ) );
    PH::resetCliArgs( $argv );
    PH::$JSON_OUT = array();
    PH::$JSON_TMP = array();
    PH::$JSON_OUTlog = '';
    ob_start();
    $util = PH::callPANOSPHP( $type, $argv, count( $argv ), 'config-viewer' );
    ob_end_clean();
    $out = array();
    foreach( is_array( $util->objectsToProcess ?? null ) ? $util->objectsToProcess : array() as $set )
        foreach( is_array( $set['objects'] ?? null ) ? $set['objects'] : array() as $o )
        {
            if( !is_object( $o ) || !method_exists( $o, 'name' ) || $o->name() !== $name )
                continue;
            $refs = viewerUsers( $o );
            $loc = PH::getLocationString( $o );
            $out[] = array( 'location' => is_string( $loc ) ? $loc : null, 'class' => get_class( $o ), 'references' => $refs );
        }
    return $out;
}

function viewerWrite( $path )
{
    $tmp = $path . '.tmp';
    UTIL::$sharedConfig['pan']->save_to_file( $tmp, FALSE );
    if( !is_file( $tmp ) || filesize( $tmp ) < 10 )
        return FALSE;
    return viewerQuiet( function() use ( $tmp, $path ) { chmod( $tmp, 0600 ); return rename( $tmp, $path ); } );
}

/** one pan-os-php run on the configuration in memory; returns the JSON output as text */
function viewerRun( $type, array $args )
{
    global $configFile;
    // 'x-computed' is no pan-os-php argument: the API object model also gets its computed values (_panosphp)
    ApiObjectModel::$withComputed = in_array( 'x-computed', $args, TRUE );
    // 'x-refcount': count the users of every object of the read ("location|name" => number, $GLOBALS['viewerRefcounts'])
    $refcount = in_array( 'x-refcount', $args, TRUE );
    $args = array_values( array_diff( $args, array( 'x-computed', 'x-refcount' ) ) );
    // 'x-bp=<file>' is no pan-os-php argument either: the BP JSON of the project for this one run (checks, computed
    // verdicts, alert-only-set / best-practice-set). Only a file of the folder "files" of this project; afterwards the
    // BP JSON the configuration was loaded with is used again.
    $bp = null;
    foreach( $args as $i => $a )
        if( strpos( $a, 'x-bp=' ) === 0 )
        {
            $bp = substr( $a, 5 );
            unset( $args[$i] );
        }
    $args = array_values( $args );
    // the BP JSON the configuration was loaded with: taken when it is first replaced (the load has set it by then)
    static $defaultBp = null;
    if( $bp !== null )
    {
        if( $defaultBp === null )
            $defaultBp = array( PH::$shadow_bp_jsonfilename );
        if( !preg_match( '#^' . preg_quote( dirname( $configFile ) . '/files/', '#' ) . '[0-9a-f]{32}\.json$#', $bp ) || !is_file( $bp ) )
            return json_encode( array( 'error' => 'BP JSON file of the project not found' ) );
        PH::$shadow_bp_jsonfilename = $bp;
        PH::$shadow_bp_jsonfile = null;
    }
    $argv = array_merge( array( 'config-viewer', 'in=' . $configFile, 'shadow-json' ), $args );
    $argc = count( $argv );
    PH::resetCliArgs( $argv );
    PH::$JSON_OUT = array();
    PH::$JSON_TMP = array();
    PH::$JSON_OUTlog = '';
    ob_start();
    $util = PH::callPANOSPHP( $type, $argv, $argc, 'config-viewer' );
    if( $refcount )
    {
        $GLOBALS['viewerRefcounts'] = array();
        foreach( is_array( $util->objectsToProcess ?? null ) ? $util->objectsToProcess : array() as $set )
            foreach( is_array( $set['objects'] ?? null ) ? $set['objects'] : array() as $o )
                if( is_object( $o ) && isset( $o->refrules ) && method_exists( $o, 'name' ) )
                {
                    $loc = PH::getLocationString( $o );
                    $GLOBALS['viewerRefcounts'][( is_string( $loc ) ? $loc : '' ) . '|' . $o->name()] = count( viewerUsers( $o ) );
                }
    }
    unset( $util );
    $out = (string)ob_get_clean();
    if( $bp !== null )
    {
        PH::$shadow_bp_jsonfilename = $defaultBp[0];
        PH::$shadow_bp_jsonfile = null;
    }
    return $out;
}

function viewerDecode( $out )
{
    $start = strpos( $out, '{' );
    $json = $start === FALSE ? null : json_decode( substr( $out, $start ), TRUE );
    if( is_array( $json ) && !isset( $json['error'] ) )
        return array( 'ok' => TRUE, 'json' => $json );
    $msg = '';
    if( is_array( $json ) )
        $msg = is_string( $json['error'] ) ? $json['error'] : json_encode( $json['error'] );
    elseif( preg_match( '/\*\*ERROR\*\*\s*(.+)/', $out, $m ) )
        $msg = $m[1];
    return array( 'ok' => FALSE, 'error' => trim( $msg ) !== '' ? trim( $msg ) : 'pan-os-php stopped with an error - check the syntax of filter / actions' );
}

function viewerSend( $conn, array $answer )
{
    viewerQuiet( function() use ( $conn, $answer ) {
        if( is_resource( $conn ) )
        {
            fwrite( $conn, json_encode( $answer, JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE ) );
            fclose( $conn );
        }
    } );
}

/**
 * Runs in a forked child and never returns. The answer is sent from a shutdown function, so an exit() inside
 * pan-os-php still gives an answer. $send = FALSE: only the exit code tells whether the run worked (trial of a change).
 */
function viewerChild( $conn, $type, array $args, $send )
{
    $GLOBALS['viewerIsChild'] = TRUE;
    pcntl_alarm( 600 );
    $done = FALSE;
    register_shutdown_function( function() use ( $conn, $send, &$done ) {
        $out = '';
        while( ob_get_level() > 0 )
            $out = (string)ob_get_clean() . $out;
        $r = viewerDecode( $out );
        if( isset( $GLOBALS['viewerRefcounts'] ) && $r['ok'] )
            $r['refcounts'] = $GLOBALS['viewerRefcounts'];
        if( !$done && $r['ok'] )
            $r = array( 'ok' => FALSE, 'error' => 'the run stopped' );
        if( $send || !$r['ok'] )
            viewerSend( $conn, $r + array( 'status' => viewerStatus() ) );
        posix_kill( getmypid(), $r['ok'] ? SIGUSR1 : SIGKILL );
    } );
    try
    {
        ob_start();
        print viewerRun( $type, $args );
        $done = TRUE;
    }
    catch( Throwable $e )
    {
        while( ob_get_level() > 0 )
            ob_end_clean();
        ob_start();
        print json_encode( array( 'error' => $e->getMessage() ) );
    }
    exit( 0 );
}

register_shutdown_function( function() use ( $sockFile, $pidFile, $autosaveFile ) {
    if( $GLOBALS['viewerIsChild'] )
        return;
    // the worker stops: unsaved changes go to the autosave file, the viewer turns it into a version
    if( $GLOBALS['viewerState']['dirty'] && isset( UTIL::$sharedConfig['pan'] ) && UTIL::$sharedConfig['pan'] !== null )
    {
        try { viewerWrite( $autosaveFile ); } catch( Throwable $e ) { }
    }
    viewerUnlink( $sockFile );
    viewerUnlink( $pidFile );
} );

$repo = dirname( __FILE__ ) . '/../../../..';
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/lib/UTIL.php';

// ---- load once
$doc = new DOMDocument();
if( !$doc->load( $configFile, XML_PARSE_BIG_LINES | LIBXML_NONET ) )
{
    viewerLog( 'configuration can not be read' );
    exit( 5 );
}
UTIL::$sharedConfig = array( 'xmlDoc' => $doc, 'pan' => null );
// location=any: an SCM configuration has no 'shared' (its containers are 'All', folders, snippets)
$first = viewerDecode( viewerRun( 'tag', array( 'location=any', 'actions=display', 'filter=(name eq config-viewer-load)' ) ) );
if( !$first['ok'] || UTIL::$sharedConfig['pan'] === null )
{
    viewerLog( 'configuration can not be loaded: ' . ( $first['error'] ?? '' ) );
    exit( 6 );
}

viewerUnlink( $sockFile );
$old = umask( 0177 );
$server = viewerQuiet( function() use ( $sockFile, &$errstr ) { return stream_socket_server( 'unix://' . $sockFile, $errno, $errstr ); } );
umask( $old );
if( !$server )
{
    viewerLog( 'socket: ' . $errstr );
    exit( 7 );
}
pcntl_signal( SIGUSR1, SIG_DFL );
// a stopped worker (kill, shutdown of the server) still writes its unsaved changes to the autosave file
pcntl_async_signals( TRUE );
foreach( array( SIGTERM, SIGINT, SIGHUP ) as $sig )
    pcntl_signal( $sig, function() { if( !$GLOBALS['viewerIsChild'] ) exit( 0 ); posix_kill( getmypid(), SIGKILL ); } );
$lastUsed = time();
$lastAutosave = time();
$trials = array();

while( TRUE )
{
    // reap finished children
    while( ( $done = pcntl_waitpid( -1, $st, WNOHANG ) ) > 0 )
        unset( $trials[$done] );

    $read = array( $server );
    $write = null;
    $except = null;
    $n = viewerQuiet( function() use ( &$read, &$write, &$except ) { return stream_select( $read, $write, $except, 15 ); } );

    if( $GLOBALS['viewerState']['dirty'] && time() - $lastAutosave >= $autosaveSec )
    {
        try
        {
            if( viewerWrite( $autosaveFile ) )
                $GLOBALS['viewerState']['autosaved'] = time();
        }
        catch( Throwable $e ) { viewerLog( 'autosave failed: ' . $e->getMessage() ); }
        $lastAutosave = time();
    }
    if( time() - $lastUsed > $idleSec )
        exit( 0 );
    if( $n === FALSE || $n === 0 )
        continue;

    $conn = viewerQuiet( function() use ( $server ) { return stream_socket_accept( $server, 5 ); } );
    if( !$conn )
        continue;
    stream_set_timeout( $conn, 10 );
    $cmd = json_decode( (string)viewerQuiet( function() use ( $conn ) { return fgets( $conn, 1048576 ); } ), TRUE );
    if( !is_array( $cmd ) || !isset( $cmd['cmd'] ) )
    {
        viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad request' ) );
        continue;
    }
    $lastUsed = time();
    $type = isset( $cmd['type'] ) && is_string( $cmd['type'] ) ? $cmd['type'] : '';
    $args = isset( $cmd['args'] ) && is_array( $cmd['args'] ) ? array_values( array_filter( $cmd['args'], 'is_string' ) ) : array();

    if( $cmd['cmd'] === 'status' )
        viewerSend( $conn, array( 'ok' => TRUE, 'status' => viewerStatus() ) );
    elseif( $cmd['cmd'] === 'references' )
    {
        // in a child, like a read: whatever pan-os-php does on the way can not hurt the loaded configuration
        $name = isset( $cmd['name'] ) && is_string( $cmd['name'] ) ? $cmd['name'] : '';
        $child = pcntl_fork();
        if( $child === 0 )
        {
            fclose( $server );
            $GLOBALS['viewerIsChild'] = TRUE;
            pcntl_alarm( 300 );
            $sent = FALSE;
            register_shutdown_function( function() use ( $conn, &$sent ) {
                while( ob_get_level() > 0 )
                    ob_end_clean();
                if( !$sent )
                    viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'the references could not be read' ) );
                posix_kill( getmypid(), SIGKILL );
            } );
            try { $r = array( 'ok' => TRUE, 'objects' => viewerReferences( $type, $args, $name ) ); }
            catch( Throwable $e ) { $r = array( 'ok' => FALSE, 'error' => 'references: ' . $e->getMessage() ); }
            while( ob_get_level() > 0 )
                ob_end_clean();
            viewerSend( $conn, $r );
            $sent = TRUE;
            exit( 0 );
        }
        viewerQuiet( function() use ( $conn ) { fclose( $conn ); } );
        if( $child < 0 )
            viewerLog( 'fork failed' );
    }
    elseif( $cmd['cmd'] === 'locations' )
    {
        try { $r = array( 'ok' => TRUE ) + viewerLocations(); } catch( Throwable $e ) { $r = array( 'ok' => FALSE, 'error' => 'locations: ' . $e->getMessage() ); }
        viewerSend( $conn, $r );
    }
    elseif( $cmd['cmd'] === 'close' )
    {
        $GLOBALS['viewerState']['dirty'] = FALSE; // discard
        viewerUnlink( $autosaveFile );
        viewerSend( $conn, array( 'ok' => TRUE ) );
        exit( 0 );
    }
    elseif( $cmd['cmd'] === 'read' )
    {
        $child = pcntl_fork();
        if( $child === 0 )
        {
            fclose( $server );
            viewerChild( $conn, $type, $args, TRUE );
        }
        viewerQuiet( function() use ( $conn ) { fclose( $conn ); } );
        if( $child < 0 )
            viewerLog( 'fork failed' );
    }
    elseif( $cmd['cmd'] === 'change' )
    {
        // 1. trial in a child: a failing action must not stop or half-change the loaded configuration
        $child = pcntl_fork();
        if( $child === 0 )
        {
            fclose( $server );
            viewerChild( $conn, $type, $args, FALSE );
        }
        if( $child < 0 )
        {
            viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'fork failed' ) );
            continue;
        }
        pcntl_waitpid( $child, $st );
        if( !( pcntl_wifsignaled( $st ) && pcntl_wtermsig( $st ) === SIGUSR1 ) )
        {
            viewerQuiet( function() use ( $conn ) { fclose( $conn ); } ); // the child sent the error already
            continue;
        }
        // 2. the real run on the memory
        try
        {
            $r = viewerDecode( viewerRun( $type, $args ) );
        }
        catch( Throwable $e )
        {
            $r = array( 'ok' => FALSE, 'error' => $e->getMessage() );
        }
        if( $r['ok'] )
        {
            if( !$GLOBALS['viewerState']['dirty'] )
                $lastAutosave = time();
            $GLOBALS['viewerState']['dirty'] = TRUE;
            // the change as data (ViewerApp::change): time, user, type, location, filter, actions, field; text from older viewers
            $note = $cmd['note'] ?? $type;
            if( is_array( $note ) )
            {
                $clean = array();
                foreach( array( 'time', 'user', 'type', 'location', 'template', 'filter', 'actions', 'ruletype', 'securityprofiletype', 'field' ) as $k )
                    if( isset( $note[$k] ) && is_scalar( $note[$k] ) )
                        $clean[$k] = is_string( $note[$k] ) ? substr( $note[$k], 0, 2000 ) : $note[$k];
                $clean['args'] = array_slice( array_map( function( $a ) { return substr( (string)$a, 0, 2000 ); }, array_filter( (array)( $note['args'] ?? array() ), 'is_scalar' ) ), 0, 10 );
                $note = $clean;
            }
            else
                $note = substr( (string)$note, 0, 500 );
            $GLOBALS['viewerState']['changes'][] = $note;
        }
        viewerSend( $conn, $r + array( 'status' => viewerStatus() ) );
    }
    elseif( $cmd['cmd'] === 'save' )
    {
        $file = isset( $cmd['file'] ) && is_string( $cmd['file'] ) ? $cmd['file'] : '';
        // only into the folder of this project, only a new *.xml file
        if( !$GLOBALS['viewerState']['dirty'] )
            viewerSend( $conn, array( 'ok' => TRUE, 'saved' => FALSE, 'status' => viewerStatus() ) );
        elseif( dirname( $file ) !== dirname( $configFile ) || !preg_match( '/^[0-9a-f]{32}\.xml$/', basename( $file ) ) || file_exists( $file ) )
            viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad target' ) );
        else
        {
            try { $ok = viewerWrite( $file ); } catch( Throwable $e ) { $ok = FALSE; viewerLog( 'save failed: ' . $e->getMessage() ); }
            if( !$ok )
                viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'the configuration could not be written' ) );
            else
            {
                $changes = $GLOBALS['viewerState']['changes'];
                $GLOBALS['viewerState']['dirty'] = FALSE;
                $GLOBALS['viewerState']['changes'] = array();
                $GLOBALS['viewerState']['saved'] = time();
                viewerUnlink( $autosaveFile );
                $configFile = $file;
                viewerSend( $conn, array( 'ok' => TRUE, 'saved' => TRUE, 'changes' => $changes, 'status' => viewerStatus() ) );
            }
        }
    }
    else
        viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad request' ) );
}
