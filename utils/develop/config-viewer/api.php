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
 * config-viewer API (prototype). JSON only. Routes (api.php/<route>):
 *   POST login, POST logout, GET me, POST password, GET meta, GET playbooks, GET playbooks?all=1 + PUT playbooks (admin)
 *   GET|POST keys, POST keys/generate (API key from user + password), PUT|DELETE keys/<kid> (own API keys), GET|POST ldap, PUT|DELETE ldap/<qid> (own LDAP queries), GET|PUT network (admin), PUT projects/<pid>/network (owner), POST projects/<pid>/import/runs
 *   GET central, POST central/appid|geoip[/runs], DELETE central/appid|geoip (admin); GET|POST|DELETE projects/<pid>/appid, POST projects/<pid>/appid/runs
 *   GET|POST users, PUT|DELETE users/<name> (network, conntest, hosts), POST users/<name>/password, GET audit   (admin)
 *   POST conntest (connection test), GET|POST requests, DELETE requests/<rid> (own requests: network to hosts, connection test),
 *   GET requests?all=1, PUT requests/<rid> (admin: approve / reject)
 *   GET projects/<pid>/audit                                              (owner)
 *   GET|POST projects, GET|DELETE projects/<pid>
 *   GET|PUT projects/<pid>/members, DELETE projects/<pid>/members/<name>
 *   GET|POST projects/<pid>/tokens, DELETE projects/<pid>/tokens/<tid>                (API tokens for scripts)
 *   GET|POST projects/<pid>/configs, DELETE projects/<pid>/configs/<cid>, GET …/<cid>/download
 *   GET …/<cid>/<resource>[/<name>], POST …/<cid>/<resource>/actions            (REST per type, e.g. addresses, rules)
 *   POST …/<cid>/stats/runs; GET projects/<pid>/runs[/<jid>[/files/<name>]], DELETE projects/<pid>/runs/<jid>   (jobs)
 *   GET …/<cid>/objects, GET …/<cid>/status, POST …/<cid>/change, POST …/<cid>/undo, POST …/<cid>/save, POST …/<cid>/discard
 * Every route except login needs a session (browser) or "Authorization: Bearer <API token>" (scripts);
 * with a session every route that is not GET needs the header X-CSRF-Token.
 */
require_once dirname(__FILE__) . '/lib/ViewerApp.php';

header( 'Content-Type: application/json; charset=utf-8' );
header( 'Cache-Control: no-store' );
header( 'X-Content-Type-Options: nosniff' );
header( 'X-Frame-Options: DENY' );
header( 'Referrer-Policy: no-referrer' );
header( "Content-Security-Policy: default-src 'none'; frame-ancestors 'none'" );

/**
 * Audit log: one line for every login (also a failed one), every request that is not a plain read, and every
 * download (configuration, project file, result file of a run). Filled while the request is handled.
 */
$viewerAudit = array( 'app' => null, 'user' => null, 'token' => null, 'pid' => null, 'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'route' => (string)( $_SERVER['PATH_INFO'] ?? '' ), 'body' => array(), 'download' => FALSE );

/**
 * address of the client for the audit log and the login lock. Behind the reverse proxy (PANOSPHP_VIEWER_TLS_PROXY=1)
 * every request comes from the proxy: then the last entry of X-Forwarded-For, which is the one the proxy itself added
 * (entries before it come from the client and are not trusted).
 */
function viewerClientAddr(): string
{
    $peer = (string)( $_SERVER['REMOTE_ADDR'] ?? '' );
    if( getenv( 'PANOSPHP_VIEWER_TLS_PROXY' ) !== '1' || empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) )
        return $peer;
    $parts = explode( ',', (string)$_SERVER['HTTP_X_FORWARDED_FOR'] );
    $last = trim( (string)end( $parts ) );
    return filter_var( $last, FILTER_VALIDATE_IP ) !== FALSE ? $last : $peer;
}

function viewerAudit( int $code ): void
{
    global $viewerAudit;
    $a = $viewerAudit;
    if( $a['app'] === null || ( $a['method'] === 'GET' && !$a['download'] ) )
        return;
    $a['app']->auditWrite( $a['user'], $a['token'], viewerClientAddr(), $a['pid'], $a['method'], $a['route'], $code, $a['body'] + $_GET );
}

function viewerOut( $data, int $code = 200 ): void
{
    viewerAudit( $code );
    http_response_code( $code );
    print json_encode( $data, JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE );
    exit;
}

function viewerBody(): array
{
    $raw = file_get_contents( 'php://input', FALSE, null, 0, 1048576 );
    if( $raw === '' || $raw === FALSE )
        return array();
    $j = json_decode( $raw, TRUE );
    if( !is_array( $j ) )
        throw new ViewerException( 'JSON body expected', 400 );
    $GLOBALS['viewerAudit']['body'] = $j;
    return $j;
}

try
{
    $app = new ViewerApp();
    $viewerAudit['app'] = $app;
    // HTTPS directly, or TLS ends at a reverse proxy in front (then the proxy must be the only way in)
    $secure = ( !empty( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] !== 'off' ) || getenv( 'PANOSPHP_VIEWER_TLS_PROXY' ) === '1';
    // without HTTPS the session cookie would travel in clear text: only from this machine itself, or when
    // explicitly switched on (lab). The decision uses the client address, not the Host header.
    if( !$secure && getenv( 'PANOSPHP_VIEWER_ALLOW_HTTP' ) !== '1'
        && !in_array( (string)( $_SERVER['REMOTE_ADDR'] ?? '' ), array( '127.0.0.1', '::1' ), TRUE ) )
        throw new ViewerException( 'HTTPS required (PANOSPHP_VIEWER_ALLOW_HTTP=1 allows HTTP in a lab)', 403 );

    session_name( 'PANOSPHPVIEWER' );
    session_set_cookie_params( array( 'lifetime' => 0, 'path' => '/', 'secure' => $secure, 'httponly' => TRUE, 'samesite' => 'Strict' ) );
    ini_set( 'session.use_strict_mode', '1' );
    ini_set( 'session.use_only_cookies', '1' );
    session_start();

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $route = array_values( array_filter( explode( '/', (string)( $_SERVER['PATH_INFO'] ?? '' ) ), 'strlen' ) );
    $r0 = $route[0] ?? '';

    // ---- without a session: help pages, the first administrator of a new installation, login
    if( $r0 === 'docs' && $method === 'GET' && count( $route ) <= 2 )
        viewerOut( count( $route ) === 1 ? array( 'docs' => ViewerApp::docsList() ) : ViewerApp::docsGet( $route[1] ) );
    if( $r0 === 'setup' && count( $route ) === 1 )
    {
        if( $method === 'GET' )
            viewerOut( array( 'first_admin' => $app->firstAdminNeeded() ) );
        if( $method === 'POST' )
        {
            $b = viewerBody();
            $viewerAudit['user'] = is_string( $b['user'] ?? null ) ? $b['user'] : null;
            $viewerAudit['body'] = array();
            $u = $app->firstAdminCreate( $b['code'] ?? null, $b['user'] ?? null, $b['password'] ?? null, viewerClientAddr() );
            session_regenerate_id( TRUE );
            $_SESSION = array( 'uid' => (int)$u['id'], 'csrf' => bin2hex( random_bytes( 32 ) ), 'since' => time(), 'seen' => time() );
            viewerOut( array( 'user' => $u['name'], 'admin' => TRUE, 'csrf' => $_SESSION['csrf'] ), 201 );
        }
    }
    if( $r0 === 'login' && $method === 'POST' )
    {
        $b = viewerBody();
        $viewerAudit['user'] = is_string( $b['user'] ?? null ) ? $b['user'] : null;
        $viewerAudit['body'] = array();
        $u = $app->login( $b['user'] ?? null, $b['password'] ?? null, viewerClientAddr() );
        session_regenerate_id( TRUE );
        $_SESSION = array( 'uid' => (int)$u['id'], 'csrf' => bin2hex( random_bytes( 32 ) ), 'since' => time(), 'seen' => time() );
        // administrators: what was done or tried on the command line since they last logged in
        viewerOut( array( 'user' => $u['name'], 'admin' => (bool)$u['is_admin'], 'csrf' => $_SESSION['csrf'], 'notices' => $app->cliNotices( $u ) ) );
    }

    // ---- everything else: logged in user, taken from the DB on every request
    // scripts: "Authorization: Bearer <API token>" instead of the session cookie. A token is never sent by a browser
    // on its own, so no CSRF token is needed; it is limited to its project and never has admin rights.
    $auth = (string)( $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '' );
    $byToken = stripos( $auth, 'Bearer ' ) === 0;
    if( $byToken )
    {
        $user = $app->userByToken( trim( substr( $auth, 7 ) ) );
        if( $user === null )
            throw new ViewerException( 'API token unknown or expired', 401 );
        $user['is_admin'] = 0;
        $csrf = null;
        $viewerAudit['token'] = $user['token']['tid'];
        if( in_array( $r0, array( 'logout', 'password', 'users', 'license', 'keys', 'network', 'ldap', 'conntest', 'requests' ), TRUE ) )
            throw new ViewerException( 'not found', 404 );
    }
    else
    {
    $idle = max( 5, (int)( getenv( 'PANOSPHP_VIEWER_SESSION_IDLE_MIN' ) ?: 120 ) ) * 60;
    $user = isset( $_SESSION['uid'], $_SESSION['csrf'], $_SESSION['seen'] ) && time() - $_SESSION['seen'] <= $idle ? $app->userById( (int)$_SESSION['uid'] ) : null;
    if( $user === null )
    {
        $_SESSION = array();
        throw new ViewerException( 'login required', 401 );
    }
    $_SESSION['seen'] = time();
    if( $method !== 'GET' && !hash_equals( (string)$_SESSION['csrf'], (string)( $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '' ) ) )
        throw new ViewerException( 'CSRF token missing or wrong', 403 );
    $csrf = $_SESSION['csrf'];
    }
    // the session file is not needed any more: do not block parallel requests of the same user
    if( !( $r0 === 'logout' || $r0 === 'password' ) )
        session_write_close();

    $viewerAudit['user'] = $user['name'];
    $admin = (bool)$user['is_admin'];
    $key = $method . ' ' . $r0;

    if( $key === 'POST logout' )
    {
        $_SESSION = array();
        session_destroy();
        setcookie( session_name(), '', array( 'expires' => 1, 'path' => '/', 'secure' => $secure, 'httponly' => TRUE, 'samesite' => 'Strict' ) );
        viewerOut( array( 'ok' => TRUE ) );
    }
    if( $key === 'GET me' )
        viewerOut( array( 'user' => $user['name'], 'admin' => $admin, 'csrf' => $csrf ) );
    if( $key === 'POST password' )
    {
        $b = viewerBody();
        if( !is_string( $b['old'] ?? null ) || !password_verify( $b['old'], $user['pass'] ) )
            throw new ViewerException( 'current password wrong', 403 );
        $app->userSetPassword( (int)$user['id'], $b['new'] ?? null );
        session_regenerate_id( TRUE );
        viewerOut( array( 'ok' => TRUE ) );
    }
    // predefined playbooks (shipped with pan-os-php): everybody gets the offered ones; an administrator all of them
    // (?all=1: on / usable / why not) and turns them on
    if( $r0 === 'playbooks' && count( $route ) === 1 )
    {
        if( $method === 'GET' )
        {
            if( !empty( $_GET['all'] ) && !$admin )
                throw new ViewerException( 'not found', 404 );
            viewerOut( array( 'playbooks' => $app->playbooksPredefined( !empty( $_GET['all'] ) ) ) );
        }
        if( $method === 'PUT' )
        {
            if( !$admin )
                throw new ViewerException( 'not found', 404 );
            viewerOut( array( 'playbooks' => $app->playbooksSet( viewerBody()['enabled'] ?? null ) ) );
        }
    }
    // the BP JSON shipped with pan-os-php (the template of a new BP JSON in the editor)
    if( $key === 'GET bp-default' && count( $route ) === 1 )
    {
        viewerAudit( 200 );
        header( 'Content-Type: application/json' );
        readfile( $app->repoDir . '/utils/api/v1/bp/scm_bp_sp_panw.json' );
        exit;
    }
    if( $key === 'GET meta' )
        viewerOut( $app->meta() + array( 'plugins' => $app->pluginMeta( $admin ) ) );

    if( $r0 === 'audit' && $method === 'GET' && count( $route ) == 1 )
        viewerOut( array( 'audit' => $app->auditList( $user, null, $_GET ) ) );

    // licence (admins): GET state, PUT install {"license": "<text>"}, DELETE remove
    if( $r0 === 'license' && count( $route ) == 1 )
    {
        if( !$admin )
            throw new ViewerException( 'not found', 404 );
        if( $method === 'GET' )
            viewerOut( $app->licenceInfo() );
        if( $method === 'PUT' )
            viewerOut( $app->licenceSet( viewerBody()['license'] ?? null ) );
        if( $method === 'DELETE' )
        {
            $app->licenceDelete();
            viewerOut( array( 'ok' => TRUE ) );
        }
    }

    if( $r0 === 'users' )
    {
        if( !$admin )
            throw new ViewerException( 'not found', 404 );
        if( $method === 'GET' && count( $route ) == 1 )
            viewerOut( array( 'users' => $app->userList() ) );
        if( $method === 'POST' && count( $route ) == 1 )
        {
            $b = viewerBody();
            viewerOut( $app->userCreate( $b['user'] ?? null, $b['password'] ?? null, !empty( $b['admin'] ) ), 201 );
        }
        // what the user may beyond projects: network, connection test, own hosts
        if( $method === 'PUT' && count( $route ) == 2 )
            viewerOut( $app->userPermissions( $route[1], viewerBody() ) );
        // a new password for a user (made by the viewer, shown once to the administrator)
        if( $method === 'POST' && count( $route ) == 3 && $route[2] === 'password' )
            viewerOut( array( 'user' => $route[1], 'password' => $app->userNewPassword( $route[1] ) ) );
        if( $method === 'DELETE' && count( $route ) == 2 )
        {
            if( strcasecmp( $route[1], $user['name'] ) === 0 )
                throw new ViewerException( 'you can not delete yourself', 400 );
            $app->userDelete( $route[1] );
            viewerOut( array( 'ok' => TRUE ) );
        }
    }

    // the connection test (who may: administrator, Account, Network): one call to a device with its trace
    if( $r0 === 'conntest' && count( $route ) === 1 && $method === 'POST' )
        viewerOut( $app->connTest( $user, viewerBody() ) );
    // requests to the administrators: network to hosts, the connection test
    if( $r0 === 'requests' )
    {
        $n = count( $route );
        if( $method === 'GET' && $n === 1 )
        {
            $all = $admin && ( $_GET['all'] ?? '' ) === '1';
            viewerOut( array( 'requests' => $app->requestList( $user, $all ) ) );
        }
        if( $method === 'POST' && $n === 1 )
            viewerOut( $app->requestCreate( $user, viewerBody() ), 201 );
        if( $method === 'DELETE' && $n === 2 )
        {
            $app->requestWithdraw( $user, $route[1] );
            viewerOut( array( 'ok' => TRUE ) );
        }
        if( $method === 'PUT' && $n === 2 )
        {
            if( !$admin )
                throw new ViewerException( 'not found', 404 );
            viewerOut( $app->requestDecide( $user, $route[1], viewerBody() ) );
        }
    }
    // network for runs (administrator): on / off, allow list, deny list
    if( $r0 === 'network' && count( $route ) === 1 )
    {
        if( !$admin )
            throw new ViewerException( 'not found', 404 );
        if( $method === 'GET' )
            viewerOut( $app->networkGet() );
        if( $method === 'PUT' )
            viewerOut( $app->networkSet( viewerBody() ) );
    }
    // App-ID database and MaxMind data of the installation (administrator): state, download runs, upload (air gap), reset
    if( $r0 === 'central' )
    {
        $n = count( $route );
        $what = $route[1] ?? '';
        if( $method === 'GET' && $n === 1 )
            viewerOut( $app->centralInfo( $user ) );
        if( in_array( $what, array( 'appid', 'geoip' ), TRUE ) )
        {
            if( $n === 3 && $route[2] === 'runs' && $method === 'POST' )
            {
                $app->systemProject( $user );
                viewerOut( $app->jobCreate( $user, ViewerApp::SYSTEM_PID, null, $what, viewerBody() ), 202 );
            }
            if( $n === 2 && $method === 'POST' )
                viewerOut( $what === 'appid' ? $app->appidUpload( $user, null, $_FILES['file'] ?? null ) : $app->geoipUpload( $user, $_FILES['file'] ?? null ), $what === 'appid' ? 200 : 202 );
            if( $n === 2 && $method === 'DELETE' )
            {
                if( $what === 'appid' )
                    $app->appidReset( $user, null );
                else
                    $app->geoipReset( $user );
                viewerOut( array( 'ok' => TRUE ) );
            }
        }
        throw new ViewerException( 'not found', 404 );
    }
    // the API keys of the user (personal; the secret is never sent back)
    if( $r0 === 'keys' )
    {
        if( $method === 'GET' && count( $route ) === 1 )
            viewerOut( array( 'keys' => $app->keyList( $user ), 'kinds' => ViewerApp::KEY_KINDS, 'named' => ViewerApp::KEY_NAMED, 'network' => $app->networkGet()['enabled'] )
                + $app->accessInfo( $user ) );
        // an existing .panconfkeystore: the file (multipart field "keystore") or its text (JSON "keystore")
        if( $method === 'POST' && count( $route ) === 2 && $route[1] === 'import' )
        {
            $f = $_FILES['keystore'] ?? null;
            $text = is_array( $f ) && ( $f['error'] ?? 1 ) === UPLOAD_ERR_OK && is_uploaded_file( $f['tmp_name'] ) ? (string)file_get_contents( $f['tmp_name'] ) : ( viewerBody()['keystore'] ?? null );
            viewerOut( $app->keyImport( $user, $text ) );
        }
        if( $method === 'POST' && count( $route ) === 1 )
            viewerOut( $app->keyAdd( $user, viewerBody() ), 201 );
        // the API key of a firewall / Panorama from user name + password (XML API keygen; the password is not kept)
        if( $method === 'POST' && count( $route ) === 2 && $route[1] === 'generate' )
            viewerOut( $app->keyGenerate( $user, viewerBody() ), 201 );
        // change: the label (port), optionally a new secret
        if( $method === 'PUT' && count( $route ) === 2 )
            viewerOut( $app->keyUpdate( $user, $route[1], viewerBody() ) );
        if( $method === 'DELETE' && count( $route ) === 2 )
        {
            $app->keyDelete( $user, $route[1] );
            viewerOut( array( 'ok' => TRUE ) );
        }
    }

    // the saved LDAP queries of the user (personal)
    if( $r0 === 'ldap' )
    {
        if( $method === 'GET' && count( $route ) === 1 )
            viewerOut( $app->ldapQueries( $user ) );
        if( $method === 'POST' && count( $route ) === 1 )
            viewerOut( $app->ldapQuerySave( $user, null, viewerBody() ), 201 );
        if( $method === 'PUT' && count( $route ) === 2 )
            viewerOut( $app->ldapQuerySave( $user, (string)$route[1], viewerBody() ) );
        if( $method === 'DELETE' && count( $route ) === 2 )
        {
            $app->ldapQueryDelete( $user, $route[1] );
            viewerOut( array( 'ok' => TRUE ) );
        }
    }

    if( $r0 === 'projects' )
    {
        $n = count( $route );
        $pid = $route[1] ?? null;
        $sub = $route[2] ?? null;
        $cid = $route[3] ?? null;
        $op = $route[4] ?? null;
        $viewerAudit['pid'] = is_string( $pid ) ? $pid : null;
        // the project of the installation-wide runs: only its runs (administrators; Account, App-ID and MaxMind)
        if( $pid === ViewerApp::SYSTEM_PID && $sub !== 'runs' )
            throw new ViewerException( 'not found', 404 );
        // the App-ID database of the project: which one it uses, upload, back to the one of the installation
        if( $sub === 'appid' && $n === 3 )
        {
            if( $method === 'GET' )
                viewerOut( $app->appidInfo( $user, $pid ) );
            if( $method === 'POST' )
                viewerOut( $app->appidUpload( $user, $pid, $_FILES['file'] ?? null ) );
            if( $method === 'DELETE' )
            {
                $app->appidReset( $user, $pid );
                viewerOut( array( 'ok' => TRUE ) );
            }
        }
        if( $sub === 'audit' && $n == 3 && $method === 'GET' )
            viewerOut( array( 'audit' => $app->auditList( $user, $pid, $_GET ) ) );

        if( $n == 1 && $method === 'GET' )
            viewerOut( array( 'projects' => $app->projectList( $user ) ) );
        if( $n == 1 && $method === 'POST' )
            viewerOut( ViewerApp::projectPublic( $app->projectCreate( $user, viewerBody()['name'] ?? null ) ), 201 );
        if( $n == 2 && $method === 'GET' )
            viewerOut( ViewerApp::projectPublic( $app->projectGet( $user, $pid ) ) + array( 'network_global' => $app->networkGet()['enabled'] ) );
        // network for the runs of this project (owner; works only while the administrator allows network)
        if( $n == 3 && $sub === 'network' && $method === 'PUT' )
            viewerOut( $app->projectNetworkSet( $user, $pid, viewerBody()['enabled'] ?? FALSE ) );
        if( $n == 2 && $method === 'DELETE' )
        {
            $app->projectDelete( $user, $pid );
            viewerOut( array( 'ok' => TRUE ) );
        }

        if( $sub === 'members' )
        {
            if( $n == 3 && $method === 'GET' )
                viewerOut( array( 'members' => $app->memberList( $user, $pid ) ) );
            if( $n == 3 && $method === 'PUT' )
            {
                $b = viewerBody();
                $app->memberSet( $user, $pid, $b['user'] ?? null, $b['role'] ?? null, $b['types'] ?? null, $b['scope'] ?? null );
                viewerOut( array( 'members' => $app->memberList( $user, $pid ) ) );
            }
            if( $n == 4 && $method === 'DELETE' )
            {
                $app->memberRemove( $user, $pid, $route[3] );
                viewerOut( array( 'ok' => TRUE ) );
            }
        }

        if( $sub === 'tokens' )
        {
            if( $n == 3 && $method === 'GET' )
                viewerOut( array( 'tokens' => $app->tokenList( $user, $pid ) ) );
            if( $n == 3 && $method === 'POST' )
            {
                $b = viewerBody();
                viewerOut( $app->tokenCreate( $user, $pid, $b['label'] ?? null, $b['role'] ?? 'read', $b['days'] ?? 30 ), 201 );
            }
            if( $n == 4 && $method === 'DELETE' )
            {
                $app->tokenDelete( $user, $pid, $route[3] );
                viewerOut( array( 'ok' => TRUE ) );
            }
        }

        // project files: …/projects/<pid>/files?kind=playbook|bp   GET list, POST upload (multipart field "file")
        //                …/projects/<pid>/files/<fid>[/download]  DELETE, GET download
        if( $sub === 'files' )
        {
            if( $n == 3 && $method === 'GET' )
                viewerOut( array( 'files' => $app->fileList( $user, $pid ) ) );
            if( $n == 3 && $method === 'POST' )
                viewerOut( $app->fileUpload( $user, $pid, $_GET['kind'] ?? null, $_FILES['file'] ?? null ), 201 );
            if( $n == 4 && $method === 'DELETE' )
            {
                $app->fileDelete( $user, $pid, $route[3] );
                viewerOut( array( 'ok' => TRUE ) );
            }
            if( $n == 5 && $method === 'GET' && $route[4] === 'download' )
            {
                $f = $app->fileDownload( $user, $pid, $route[3] );
                $viewerAudit['download'] = TRUE;
                viewerAudit( 200 );
                header( 'Content-Type: ' . ( $f['raw'] ? 'application/octet-stream' : 'application/json' ) );
                header( 'Content-Disposition: attachment; filename="' . $f['name'] . '"' );
                print $f['content'];
                exit;
            }
        }

        // runs (jobs): …/projects/<pid>/runs                      GET  list
        //              …/projects/<pid>/runs/<jid>                GET  state + result files, DELETE cancel / delete
        //              …/projects/<pid>/runs/<jid>/files/<name…>  GET  one result file
        // a run without a version (run type of a plug-in with 'input' => 'none'): …/projects/<pid>/<type>/runs  POST
        if( $n == 4 && $method === 'POST' && $route[3] === 'runs' && in_array( $sub, $app->jobTypes(), TRUE ) )
            viewerOut( $app->jobCreate( $user, $pid, null, $sub, viewerBody() ), 202 );
        if( $sub === 'runs' )
        {
            if( $n == 3 && $method === 'GET' )
                viewerOut( array( 'runs' => $app->jobList( $user, $pid ) ) );
            if( $n == 4 && $method === 'GET' )
                viewerOut( $app->jobGet( $user, $pid, $route[3] ) );
            if( $n == 4 && $method === 'DELETE' )
            {
                $app->jobDelete( $user, $pid, $route[3] );
                viewerOut( array( 'ok' => TRUE ) );
            }
            // the result configuration of a playbook run as a new version of the project
            if( $n == 5 && $method === 'POST' && $route[4] === 'save' )
                viewerOut( $app->jobSaveConfig( $user, $pid, $route[3], viewerBody()['project'] ?? null ), 201 );
            // the servers an LDAP search found, with what the network rules allow, and a suggestion for a query
            if( $n == 5 && $method === 'GET' && $route[4] === 'ldap-servers' )
                viewerOut( $app->ldapDiscoverResult( $user, $pid, $route[3] ) );
            // a failed SCM import: only the conversion again, from the export the run has downloaded
            if( $n == 5 && $method === 'POST' && $route[4] === 'convert' )
                viewerOut( $app->jobConvert( $user, $pid, $route[3] ), 202 );
            if( $n >= 6 && $method === 'GET' && $route[4] === 'files' )
            {
                $f = $app->jobFile( $user, $pid, $route[3], implode( '/', array_map( 'rawurldecode', array_slice( $route, 5 ) ) ) );
                $viewerAudit['download'] = TRUE;
                viewerAudit( 200 );
                header( 'Content-Type: application/octet-stream' );
                header( 'Content-Disposition: attachment; filename="' . preg_replace( '/[^A-Za-z0-9._-]/', '_', $f['name'] ) . '"' );
                header( 'Content-Length: ' . strlen( $f['content'] ) );
                print $f['content'];
                exit;
            }
        }

        if( $sub === 'configs' )
        {
            if( $n == 3 && $method === 'GET' )
                viewerOut( array( 'configs' => $app->configList( $user, $pid ) ) );
            if( $n == 3 && $method === 'POST' )
                viewerOut( $app->configUpload( $user, $pid, $_FILES['config'] ?? null ), 201 );
            if( $n == 4 && $method === 'DELETE' )
            {
                $app->configDelete( $user, $pid, $cid );
                viewerOut( array( 'ok' => TRUE ) );
            }
            if( $n == 5 && $method === 'GET' && $op === 'download' )
            {
                $d = $app->configDownload( $user, $pid, $cid );
                $viewerAudit['download'] = TRUE;
                viewerAudit( 200 );
                header( 'Content-Type: application/xml' );
                header( 'Content-Disposition: attachment; filename="' . $d['name'] . '"' );
                header( 'Content-Length: ' . filesize( $d['path'] ) );
                readfile( $d['path'] );
                exit;
            }
            if( $n == 5 && $method === 'GET' && $op === 'objects' )
                viewerOut( $app->objects( $user, $pid, $cid, $_GET ) );
            if( $n == 5 && $method === 'GET' && $op === 'references' )
                viewerOut( $app->references( $user, $pid, $cid, $_GET ) );
            // the change list as a pan-os-php playbook (?source=unsaved / version)
            if( $n == 5 && $method === 'GET' && $op === 'playbook' )
                viewerOut( $app->playbook( $user, $pid, $cid, (string)( $_GET['source'] ?? 'unsaved' ) ) );
            // one object for the object window (fields + structured model)
            if( $n == 5 && $method === 'GET' && $op === 'object' )
                viewerOut( $app->objectGet( $user, $pid, $cid, $_GET ) );
            if( $n == 5 && $method === 'GET' && $op === 'locations' )
                viewerOut( $app->locations( $user, $pid, $cid ) );
            // System: settings of the firewall / Panorama / SCM folder (config sections)
            if( $n == 5 && $method === 'GET' && $op === 'system' )
                viewerOut( $app->system( $user, $pid, $cid, $_GET ) );
            if( $n == 6 && $method === 'POST' && $op === 'system' && $route[5] === 'change' )
                viewerOut( $app->systemChange( $user, $pid, $cid, viewerBody() ) );
            if( $n == 5 && $method === 'GET' && $op === 'status' )
                viewerOut( $app->status( $user, $pid, $cid ) );
            if( $n == 5 && $method === 'POST' && $op === 'change' )
                viewerOut( $app->change( $user, $pid, $cid, viewerBody() ) );
            // undo of one unsaved change (body: index in the change list) - git history of the version
            if( $n == 5 && $method === 'POST' && $op === 'undo' )
                viewerOut( $app->undo( $user, $pid, $cid, viewerBody() ) );
            if( $n == 5 && $method === 'POST' && $op === 'save' )
                viewerOut( $app->save( $user, $pid, $cid ) );
            if( $n == 5 && $method === 'POST' && $op === 'discard' )
            {
                $app->discard( $user, $pid, $cid );
                viewerOut( array( 'ok' => TRUE ) );
            }

            // REST resources per type: …/configs/<cid>/<resource>            GET  list (location, filter, limit, offset, ruletype, securityprofiletype)
            //                          …/configs/<cid>/<resource>/<name>     GET  one object (all locations, or ?location=)
            //                          …/configs/<cid>/<resource>/actions    POST change: body location, filter, actions
            // …/configs/<cid>/<job type>/runs   POST  queue a run (stats, …) -> 202 with the run
            if( $n == 6 && $method === 'POST' && $route[5] === 'runs' && in_array( $op, $app->jobTypes(), TRUE ) )
                viewerOut( $app->jobCreate( $user, $pid, $cid, $op, viewerBody() ), 202 );
            $type = $n >= 5 ? $app->resourceType( $op ) : null;
            if( $type !== null )
            {
                if( $n == 5 && $method === 'GET' )
                    viewerOut( $app->resourceList( $user, $pid, $cid, $type, $_GET, null, $op ) );
                if( $n == 6 && $method === 'GET' )
                    viewerOut( $app->resourceList( $user, $pid, $cid, $type, $_GET, rawurldecode( $route[5] ), $op ) );
                if( $n == 6 && $method === 'POST' && $route[5] === 'actions' )
                    viewerOut( $app->change( $user, $pid, $cid, array( 'type' => $type ) + viewerBody() ) );
            }
        }
    }

    throw new ViewerException( 'not found', 404 );
}
catch( ViewerException $e )
{
    $code = $e->getCode();
    // a refused download is logged as well
    if( $viewerAudit['method'] === 'GET' && preg_match( '#/download$|/runs/[0-9a-f]+/files/#', $viewerAudit['route'] ) )
        $viewerAudit['download'] = TRUE;
    viewerOut( array( 'error' => $e->getMessage() ) + ( $e instanceof ViewerDetailException ? array( 'details' => $e->details ) : array() ), $code >= 400 && $code < 600 ? $code : 400 );
}
catch( Throwable $e )
{
    // no internals (paths, SQL) to the client
    error_log( 'config-viewer: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() );
    viewerOut( array( 'error' => 'internal error' ), 500 );
}
