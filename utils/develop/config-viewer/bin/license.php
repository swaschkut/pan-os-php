<?php
/**
 * config-viewer: licence on the command line (same as Account -> Licence in the page).
 *
 *   php bin/license.php install <file>     install a licence (file, or - for standard input)
 *   php bin/license.php show               the installed licence (without keys), its state, the plug-ins
 *   php bin/license.php remove
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
require_once dirname(__FILE__) . '/../lib/ViewerApp.php';

function showInfo( ViewerApp $app ): void
{
    $i = $app->licenceInfo();
    $l = $i['licence'];
    if( $l === null )
        print "no licence installed - basic features only\n";
    else
        printf( "licence %s for %s\n  valid until %s (+%d days grace), state %s, %d days left\n  features: %s\n",
            $l['id'], $l['customer'], $l['valid_until'], $l['grace_days'], $l['state'], $l['days_left'], implode( ', ', $l['features'] ) );
    if( $i['error'] !== null )
        print "the installed licence is not valid: " . $i['error'] . "\n";
    if( $i['clock'] !== 'ok' )
        print "the clock of this computer was set back - licensed plug-ins are locked\n";
    $m = $app->pluginMeta( TRUE );
    foreach( $m['plugins'] as $p )
        printf( "  plug-in %-14s %-8s %-18s %s%s\n", $p['name'], $p['version'], $p['feature'] ?? 'basic', $p['on'] ? 'on' : 'locked', !empty( $p['why'] ) ? ' - ' . $p['why'] : '' );
    foreach( $m['errors'] ?? array() as $what => $why )
        printf( "  plug-in %-14s not loaded - %s\n", $what, $why );
}

try
{
    $app = new ViewerApp();
    $cmd = $argv[1] ?? '';
    if( $cmd === 'install' && isset( $argv[2] ) )
    {
        $text = $argv[2] === '-' ? stream_get_contents( STDIN ) : @file_get_contents( $argv[2] );
        if( !is_string( $text ) || $text === '' )
            throw new ViewerException( 'licence file can not be read' );
        $app->licenceSet( $text );
        print "licence installed\n";
        $app = new ViewerApp();
        showInfo( $app );
    }
    elseif( $cmd === 'show' )
        showInfo( $app );
    elseif( $cmd === 'remove' )
    {
        $app->licenceDelete();
        print "licence removed - licensed plug-ins are locked\n";
    }
    else
    {
        fwrite( STDERR, "usage: php license.php install <file|-> | show | remove\n" );
        exit( 2 );
    }
}
catch( ViewerException $e )
{
    fwrite( STDERR, "error: " . $e->getMessage() . "\n" );
    exit( 1 );
}
