<?php
/**
 * config-viewer: user management on the command line (the first user must be created here).
 *
 *   php bin/user.php add <name> [admin]     password is asked (or taken from the environment variable VIEWER_PASSWORD)
 *   php bin/user.php password <name>
 *   php bin/user.php delete <name>          also deletes the projects the user owns
 *   php bin/user.php list
 *   php bin/user.php first-code             a new installation (no user yet): the one-time code for the first administrator
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
require_once dirname(__FILE__) . '/../lib/ViewerApp.php';

function askPassword(): string
{
    $env = getenv( 'VIEWER_PASSWORD' );
    if( is_string( $env ) && $env !== '' )
        return $env;
    fwrite( STDERR, 'password (at least ' . ViewerApp::PASSWORD_MIN . ' characters): ' );
    $tty = function_exists( 'posix_isatty' ) && posix_isatty( STDIN );
    if( $tty ) system( 'stty -echo' );
    $pw = rtrim( (string)fgets( STDIN ), "\r\n" );
    if( $tty ) { system( 'stty echo' ); fwrite( STDERR, "\n" ); }
    return $pw;
}

try
{
    $app = new ViewerApp();
    $cmd = $argv[1] ?? '';
    $name = $argv[2] ?? '';
    if( $cmd === 'add' && $name !== '' )
    {
        $app->userCreate( $name, askPassword(), ( $argv[3] ?? '' ) === 'admin' );
        print "user '" . $name . "' created\n";
    }
    elseif( $cmd === 'password' && $name !== '' )
    {
        $u = $app->userByName( $name );
        if( $u === null ) throw new ViewerException( 'unknown user' );
        $app->userSetPassword( (int)$u['id'], askPassword() );
        print "password changed\n";
    }
    elseif( $cmd === 'delete' && $name !== '' )
    {
        $app->userDelete( $name );
        print "user '" . $name . "' and the projects of this user deleted\n";
    }
    elseif( $cmd === 'first-code' )
    {
        // nothing when there are users already
        $code = $app->firstAdminCode();
        if( $code !== null )
            print $code . "\n";
    }
    elseif( $cmd === 'list' )
    {
        foreach( $app->userList() as $u )
            print $u['name'] . ( $u['admin'] ? ' (admin)' : '' ) . "\n";
    }
    else
    {
        fwrite( STDERR, "usage: php user.php add <name> [admin] | password <name> | delete <name> | list | first-code\n  data directory: " . $app->dataDir . "\n" );
        exit( 2 );
    }
}
catch( Exception $e )
{
    fwrite( STDERR, 'error: ' . $e->getMessage() . "\n" );
    exit( 1 );
}
