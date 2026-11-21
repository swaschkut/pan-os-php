<?php
/**
 * config-viewer: users on the command line.
 *
 * add / password / delete work only while there is no administrator (the first setup). Afterwards an administrator
 * does this in the browser (Account); a try here is refused, logged and shown to the administrators.
 *
 *   php bin/user.php add <name> [admin]     password is asked (or taken from the environment variable VIEWER_PASSWORD)
 *   php bin/user.php password <name>
 *   php bin/user.php delete <name>          also deletes the projects the user owns
 *   php bin/user.php list
 *   php bin/user.php first-code             a new installation (no administrator yet): the one-time code for the first one
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
        $admin = ( $argv[3] ?? '' ) === 'admin';
        $app->cliChange( 'user add', array( 'user' => $name, 'admin' => $admin ) );
        $app->userCreate( $name, askPassword(), $admin );
        $app->cliDone( 'user add', array( 'user' => $name, 'admin' => $admin ) );
        print "user '" . $name . "' created\n";
    }
    elseif( $cmd === 'password' && $name !== '' )
    {
        $app->cliChange( 'password', array( 'user' => $name ) );
        $u = $app->userByName( $name );
        if( $u === null ) throw new ViewerException( 'unknown user' );
        $app->userSetPassword( (int)$u['id'], askPassword() );
        $app->cliDone( 'password', array( 'user' => $name ) );
        print "password changed\n";
    }
    elseif( $cmd === 'delete' && $name !== '' )
    {
        $app->cliChange( 'user delete', array( 'user' => $name ) );
        $app->userDelete( $name );
        $app->cliDone( 'user delete', array( 'user' => $name ) );
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
