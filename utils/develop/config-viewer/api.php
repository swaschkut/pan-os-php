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
 *   POST login, POST logout, GET me, POST password, GET meta
 *   GET|POST users, DELETE users/<name>                                   (admin)
 *   GET|POST projects, GET|DELETE projects/<pid>
 *   GET|PUT projects/<pid>/members, DELETE projects/<pid>/members/<name>
 *   GET|POST projects/<pid>/tokens, DELETE projects/<pid>/tokens/<tid>                (API tokens for scripts)
 *   GET|POST projects/<pid>/configs, DELETE projects/<pid>/configs/<cid>, GET …/<cid>/download
 *   GET …/<cid>/<resource>[/<name>], POST …/<cid>/<resource>/actions            (REST per type, e.g. addresses, rules)
 *   POST …/<cid>/stats/runs; GET projects/<pid>/runs[/<jid>[/files/<name>]], DELETE projects/<pid>/runs/<jid>   (jobs)
 *   GET …/<cid>/objects, GET …/<cid>/status, POST …/<cid>/change, POST …/<cid>/save, POST …/<cid>/discard
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

function viewerOut( $data, int $code = 200 ): void
{
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
    return $j;
}

try
{
    $app = new ViewerApp();
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

    // ---- login: the only route without a session
    if( $r0 === 'login' && $method === 'POST' )
    {
        $b = viewerBody();
        $u = $app->login( $b['user'] ?? null, $b['password'] ?? null, (string)( $_SERVER['REMOTE_ADDR'] ?? '' ) );
        session_regenerate_id( TRUE );
        $_SESSION = array( 'uid' => (int)$u['id'], 'csrf' => bin2hex( random_bytes( 32 ) ), 'since' => time(), 'seen' => time() );
        viewerOut( array( 'user' => $u['name'], 'admin' => (bool)$u['is_admin'], 'csrf' => $_SESSION['csrf'] ) );
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
        if( in_array( $r0, array( 'logout', 'password', 'users' ), TRUE ) )
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
    if( $key === 'GET meta' )
        viewerOut( $app->meta() );

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
        if( $method === 'DELETE' && count( $route ) == 2 )
        {
            if( strcasecmp( $route[1], $user['name'] ) === 0 )
                throw new ViewerException( 'you can not delete yourself', 400 );
            $app->userDelete( $route[1] );
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

        if( $n == 1 && $method === 'GET' )
            viewerOut( array( 'projects' => $app->projectList( $user ) ) );
        if( $n == 1 && $method === 'POST' )
            viewerOut( ViewerApp::projectPublic( $app->projectCreate( $user, viewerBody()['name'] ?? null ) ), 201 );
        if( $n == 2 && $method === 'GET' )
            viewerOut( ViewerApp::projectPublic( $app->projectGet( $user, $pid ) ) );
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

        // runs (jobs): …/projects/<pid>/runs                      GET  list
        //              …/projects/<pid>/runs/<jid>                GET  state + result files, DELETE cancel / delete
        //              …/projects/<pid>/runs/<jid>/files/<name…>  GET  one result file
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
            if( $n >= 6 && $method === 'GET' && $route[4] === 'files' )
            {
                $f = $app->jobFile( $user, $pid, $route[3], implode( '/', array_map( 'rawurldecode', array_slice( $route, 5 ) ) ) );
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
                header( 'Content-Type: application/xml' );
                header( 'Content-Disposition: attachment; filename="' . $d['name'] . '"' );
                header( 'Content-Length: ' . filesize( $d['path'] ) );
                readfile( $d['path'] );
                exit;
            }
            if( $n == 5 && $method === 'GET' && $op === 'objects' )
                viewerOut( $app->objects( $user, $pid, $cid, $_GET ) );
            if( $n == 5 && $method === 'GET' && $op === 'status' )
                viewerOut( $app->status( $user, $pid, $cid ) );
            if( $n == 5 && $method === 'POST' && $op === 'change' )
                viewerOut( $app->change( $user, $pid, $cid, viewerBody() ) );
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
            if( $n == 6 && $method === 'POST' && $route[5] === 'runs' && in_array( $op, ViewerApp::JOB_TYPES, TRUE ) )
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
    viewerOut( array( 'error' => $e->getMessage() ), $code >= 400 && $code < 600 ? $code : 400 );
}
catch( Throwable $e )
{
    // no internals (paths, SQL) to the client
    error_log( 'config-viewer: ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine() );
    viewerOut( array( 'error' => 'internal error' ), 500 );
}
