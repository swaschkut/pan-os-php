<?php
/**
 * Scans every Panorama XML config in a folder and lists the config files in which
 * the type=device filter matches at least one Template or Template-Stack.
 *
 * Default filter: (template manageddevice.all.with-no-dg)
 *   -> Templates / Template-Stacks that reach at least one firewall and none of
 *      these firewalls is assigned to a device group.
 *
 * Usage:
 *   php tests/test_template_manageddevice_with_no_dg.php folder=/path/to/configs
 *   php tests/test_template_manageddevice_with_no_dg.php folder=/path/to/configs recursive
 *   php tests/test_template_manageddevice_with_no_dg.php folder=/path/to/configs 'filter=(template manageddevice.all.in.file chosen.txt)'
 *   php tests/test_template_manageddevice_with_no_dg.php folder=/path/to/configs verbose
 *
 * Every config file is evaluated in its own PHP process, so a config that the library
 * cannot load (derr/exit, memory) is reported as ERROR and does not stop the scan.
 *
 * Exit code: 0 = at least one matching config, 1 = no match, 2 = usage / filter error
 */

$defaultFilter = '(template manageddevice.all.with-no-dg)';

// ---------------------------------------------------------------------------------
// argument parsing (key=value or flag)
// ---------------------------------------------------------------------------------
$args = array();
foreach( array_slice( $argv, 1 ) as $arg )
{
    $pos = strpos( $arg, '=' );
    if( $pos === FALSE )
        $args[strtolower( $arg )] = TRUE;
    else
        $args[strtolower( substr( $arg, 0, $pos ) )] = substr( $arg, $pos + 1 );
}

$filter = isset( $args['filter'] ) ? $args['filter'] : $defaultFilter;

// ---------------------------------------------------------------------------------
// CHECK mode: only validate the filter syntax
// ---------------------------------------------------------------------------------
if( isset( $args['child-checkfilter'] ) )
{
    ob_start();
    require_once dirname( __FILE__ ) . "/../lib/pan_php_framework.php";
    $rQuery = new RQuery( 'device' );
    $errorMessage = '';
    $ok = $rQuery->parseFromString( $filter, $errorMessage ) !== FALSE;
    ob_end_clean();
    echo json_encode( array( 'status' => $ok ? 'ok' : 'filter-error', 'message' => $errorMessage ) ) . "\n";
    exit( 0 );
}

// ---------------------------------------------------------------------------------
// CHILD mode: evaluate one config file, print one JSON line
// ---------------------------------------------------------------------------------
if( isset( $args['child-file'] ) )
{
    $file = $args['child-file'];
    $result = array( 'file' => $file, 'status' => 'ok', 'templates' => array(), 'templatestacks' => array(), 'checked' => 0 );

    // load the XML before the library installs its error handler
    libxml_use_internal_errors( TRUE );
    $doc = new DOMDocument();
    if( !$doc->load( $file, defined( "LIBXML_BIGLINES" ) ? LIBXML_BIGLINES : 0 ) )
    {
        $xmlError = libxml_get_last_error();
        $result['status'] = 'error';
        $result['message'] = 'not a valid XML file' . ( $xmlError ? ': ' . trim( $xmlError->message ) . ' (line ' . $xmlError->line . ')' : '' );
        echo json_encode( $result ) . "\n";
        exit( 0 );
    }
    libxml_clear_errors();
    libxml_use_internal_errors( FALSE );

    ob_start();   // the library prints load information, keep the child output clean
    require_once dirname( __FILE__ ) . "/../lib/pan_php_framework.php";

    // same platform detection as UTIL: panorama has no /config/devices/entry/vsys
    $xpath = new DOMXPath( $doc );
    $configRoot = $xpath->query( '/config' )->item( 0 );
    $isPanorama = $configRoot !== null
        && $xpath->query( '/config/devices/entry/vsys' )->length == 0
        && !$configRoot->hasAttribute( 'buckbeak' )
        && !$configRoot->hasAttribute( 'fawkes-config-version' )
        && !$configRoot->hasAttribute( 'fawkes-config' );
    if( !$isPanorama )
    {
        ob_end_clean();
        $result['status'] = 'skipped';
        $result['message'] = 'not a Panorama config';
        echo json_encode( $result ) . "\n";
        exit( 0 );
    }

    $rQuery = new RQuery( 'device' );
    $errorMessage = '';
    if( $rQuery->parseFromString( $filter, $errorMessage ) === FALSE )
    {
        ob_end_clean();
        $result['status'] = 'filter-error';
        $result['message'] = $errorMessage;
        echo json_encode( $result ) . "\n";
        exit( 0 );
    }

    $pan = new PanoramaConf();
    $pan->load_from_domxml( $doc );

    $nestedQueries = array();
    foreach( array( 'templates' => $pan->getTemplates(), 'templatestacks' => $pan->getTemplatesStacks() ) as $kind => $objects )
    {
        foreach( $objects as $object )
        {
            $result['checked']++;
            if( $rQuery->matchSingleObject( array( 'object' => $object, 'nestedQueries' => &$nestedQueries ) ) )
            {
                $serials = array();
                foreach( $object->managedDevices() as $serial => $device )
                    $serials[] = $serial;
                $result[$kind][$object->name()] = $serials;
            }
        }
    }

    ob_end_clean();
    echo json_encode( $result ) . "\n";
    exit( 0 );
}

// ---------------------------------------------------------------------------------
// MAIN mode: walk the folder, run one child per XML file
// ---------------------------------------------------------------------------------
if( !isset( $args['folder'] ) || !is_dir( $args['folder'] ) )
{
    fwrite( STDERR, "usage: php " . basename( __FILE__ ) . " folder=/path/to/configs [recursive] [verbose] ['filter=(...)']\n" );
    exit( 2 );
}

$folder = rtrim( $args['folder'], '/' );
$recursive = isset( $args['recursive'] );
$verbose = isset( $args['verbose'] );

$files = array();
if( $recursive )
{
    $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $folder, FilesystemIterator::SKIP_DOTS ) );
    foreach( $it as $f )
        if( $f->isFile() && strtolower( $f->getExtension() ) == 'xml' )
            $files[] = $f->getPathname();
}
else
{
    foreach( glob( $folder . '/*' ) as $f )
        if( is_file( $f ) && strtolower( pathinfo( $f, PATHINFO_EXTENSION ) ) == 'xml' )
            $files[] = $f;
}
sort( $files );

echo "folder : $folder" . ( $recursive ? " (recursive)" : "" ) . "\n";
echo "filter : type=device $filter\n";
echo "files  : " . count( $files ) . " XML file(s)\n\n";

$php = PHP_BINARY;

// validate the filter once before scanning
$output = array();
exec( escapeshellarg( $php ) . ' ' . escapeshellarg( __FILE__ ) . ' child-checkfilter ' . escapeshellarg( 'filter=' . $filter ) . ' 2>&1', $output );
$check = json_decode( (string)end( $output ), TRUE );
if( !is_array( $check ) || $check['status'] != 'ok' )
{
    fwrite( STDERR, "**ERROR** filter '$filter' cannot be parsed: " . ( is_array( $check ) ? $check['message'] : implode( ' ', $output ) ) . "\n" );
    fwrite( STDERR, "Is the filter available in this pan-os-php version (lib/misc-classes/filters/filters-Device.php)?\n" );
    exit( 2 );
}

$matching = array();
$counts = array( 'match' => 0, 'nomatch' => 0, 'skipped' => 0, 'error' => 0 );

foreach( $files as $file )
{
    $cmd = escapeshellarg( $php ) . ' ' . escapeshellarg( __FILE__ )
        . ' ' . escapeshellarg( 'child-file=' . $file )
        . ' ' . escapeshellarg( 'filter=' . $filter ) . ' 2>&1';
    $output = array();
    exec( $cmd, $output );

    // the result is the last JSON line of the child output
    $result = null;
    for( $i = count( $output ) - 1; $i >= 0; $i-- )
    {
        $decoded = json_decode( $output[$i], TRUE );
        if( is_array( $decoded ) && isset( $decoded['status'] ) )
        {
            $result = $decoded;
            break;
        }
    }

    if( $result === null )
    {
        $counts['error']++;
        $msg = trim( implode( ' ', array_slice( $output, -3 ) ) );
        echo "ERROR    $file  (" . substr( $msg, 0, 200 ) . ")\n";
        continue;
    }

    if( $result['status'] == 'filter-error' )
    {
        fwrite( STDERR, "\n**ERROR** filter '$filter' cannot be parsed: " . $result['message'] . "\n" );
        fwrite( STDERR, "Is the filter available in this pan-os-php version (lib/misc-classes/filters/filters-Device.php)?\n" );
        exit( 2 );
    }

    if( $result['status'] == 'skipped' )
    {
        $counts['skipped']++;
        if( $verbose )
            echo "SKIPPED  $file  (" . $result['message'] . ")\n";
        continue;
    }

    if( $result['status'] == 'error' )
    {
        $counts['error']++;
        echo "ERROR    $file  (" . $result['message'] . ")\n";
        continue;
    }

    $hits = count( $result['templates'] ) + count( $result['templatestacks'] );
    if( $hits > 0 )
    {
        $counts['match']++;
        $matching[] = $file;
        echo "MATCH    $file\n";
        foreach( array( 'templates' => 'template     ', 'templatestacks' => 'templatestack' ) as $kind => $label )
            foreach( $result[$kind] as $name => $serials )
                echo "           $label '$name'  firewalls: " . implode( ',', $serials ) . "\n";
    }
    else
    {
        $counts['nomatch']++;
        if( $verbose )
            echo "no match $file  (" . $result['checked'] . " templates / stacks checked)\n";
    }
}

echo "\n----- summary -----\n";
echo "matching configs : " . $counts['match'] . "\n";
echo "no match         : " . $counts['nomatch'] . "\n";
echo "skipped (no Panorama config) : " . $counts['skipped'] . "\n";
echo "errors           : " . $counts['error'] . "\n";

if( count( $matching ) > 0 )
{
    echo "\nconfig files with matches:\n";
    foreach( $matching as $file )
        echo "  $file\n";
}

exit( count( $matching ) > 0 ? 0 : 1 );
