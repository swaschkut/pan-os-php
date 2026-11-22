<?php
/**
 * config-viewer: projects and API tokens on the command line. Runs as the given user - with that user's permissions.
 * Listing works always; project-add / create / delete only while there is no administrator (the first setup) -
 * afterwards API tokens are made in the browser (project, API tokens), a try here is refused, logged and shown to
 * the administrators.
 *
 *   php bin/token.php projects <user>                                     projects of the user (id, permission, name)
 *   php bin/token.php project-add <user> <name>                           new project of the user; prints its id
 *   php bin/token.php create <user> <project> [read|write] [days] [label] new API token (shown once)
 *   php bin/token.php list <user> <project>                               tokens of the project (never the secret)
 *   php bin/token.php delete <user> <project> <token id>
 *
 * <project>: the id, or the name when it is unique for the user. A token works for its project only and never with
 * admin rights: scripts send "Authorization: Bearer <token>".
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
require_once dirname(__FILE__) . '/../lib/ViewerApp.php';

function needUser( ViewerApp $app, ?string $name ): array
{
    $u = $app->userByName( (string)$name );
    if( $u === null )
        throw new ViewerException( 'unknown user: ' . (string)$name );
    return $u;
}

function projectId( ViewerApp $app, array $user, ?string $p ): string
{
    $p = (string)$p;
    $hits = array();
    foreach( $app->projectList( $user ) as $row )
        if( $row['pid'] === $p || strcasecmp( $row['name'], $p ) === 0 )
            $hits[$row['pid']] = $row;
    if( count( $hits ) === 1 )
        return array_keys( $hits )[0];
    throw new ViewerException( count( $hits ) === 0 ? 'no project "' . $p . '" of this user' : 'several projects are called "' . $p . '" - use the id' );
}

try
{
    $app = new ViewerApp();
    $cmd = $argv[1] ?? '';
    if( $cmd === 'projects' && isset( $argv[2] ) )
    {
        foreach( $app->projectList( needUser( $app, $argv[2] ) ) as $p )
            printf( "%s  %-6s %s\n", $p['pid'], $p['role'], $p['name'] );
    }
    elseif( $cmd === 'project-add' && isset( $argv[3] ) )
    {
        $app->cliChange( 'project add', array( 'user' => $argv[2], 'name' => $argv[3] ) );
        $p = $app->projectCreate( needUser( $app, $argv[2] ), $argv[3] );
        $app->cliDone( 'project add', array( 'user' => $argv[2], 'name' => $argv[3] ) );
        print $p['pid'] . "\n";
    }
    elseif( $cmd === 'create' && isset( $argv[3] ) )
    {
        $app->cliChange( 'token create', array( 'user' => $argv[2], 'name' => $argv[3] ) );
        $u = needUser( $app, $argv[2] );
        $days = isset( $argv[5] ) ? (int)$argv[5] : 30;
        $t = $app->tokenCreate( $u, projectId( $app, $u, $argv[3] ), $argv[6] ?? 'command line ' . gmdate( 'Y-m-d' ), $argv[4] ?? 'read', $days );
        $app->cliDone( 'token create', array( 'user' => $argv[2], 'name' => $argv[3], 'role' => $t['role'], 'days' => $days ) );
        printf( "token (shown only now): %s\n  id %s, permission %s, valid until %s\n", $t['token'], $t['tid'], $t['role'], gmdate( 'Y-m-d', $t['expires'] ) );
    }
    elseif( $cmd === 'list' && isset( $argv[3] ) )
    {
        $u = needUser( $app, $argv[2] );
        foreach( $app->tokenList( $u, projectId( $app, $u, $argv[3] ) ) as $t )
            printf( "%s  %-5s %-8s until %s  last used %s  %s\n", $t['tid'], $t['role'], $t['user'], gmdate( 'Y-m-d', (int)$t['expires'] ),
                $t['last_used'] ? gmdate( 'Y-m-d H:i', (int)$t['last_used'] ) : '-', $t['label'] );
    }
    elseif( $cmd === 'delete' && isset( $argv[4] ) )
    {
        $app->cliChange( 'token delete', array( 'user' => $argv[2], 'name' => $argv[3] ) );
        $u = needUser( $app, $argv[2] );
        $app->tokenDelete( $u, projectId( $app, $u, $argv[3] ), $argv[4] );
        $app->cliDone( 'token delete', array( 'user' => $argv[2], 'name' => $argv[3] ) );
        print "token deleted\n";
    }
    else
    {
        fwrite( STDERR, "usage: php token.php projects <user> | project-add <user> <name> | create <user> <project> [read|write] [days] [label]"
            . " | list <user> <project> | delete <user> <project> <token id>\n" );
        exit( 2 );
    }
}
catch( ViewerException $e )
{
    fwrite( STDERR, "error: " . $e->getMessage() . "\n" );
    exit( 1 );
}
