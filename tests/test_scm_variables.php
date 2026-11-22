<?php
/**
 * SCM variables (/config/setup/v1/variables): loaded with the real import code of PanSCMAPIConnector from a
 * synthetic answer of the API (no tenant), written into the XML of their folder / snippet / device and shown by
 * type=device actions=display (shadow-json "variables"). Also offline: in=scm-export:// with NN_variables.json.
 *
 *   php tests/test_scm_variables.php
 */
$repo = dirname( __DIR__ );
require_once $repo . "/lib/pan_php_framework.php";
require_once $repo . "/utils/lib/UTIL.php";

$checks = 0;
$failed = array();
function eq( $got, $want, $what )
{
    global $checks, $failed;
    $checks++;
    if( $got === $want )
        echo "ok  " . $what . "\n";
    else
    {
        echo "FAIL " . $what . "\n";
        $failed[] = " - " . $what . "\n      expected " . json_encode( $want ) . "\n      got      " . json_encode( $got );
    }
}

// a synthetic tenant: folders All > ngfw-shared > Branches > firewall 001122334455 (on-prem), a snippet at Branches
$setup = array(
    'folders' => array(
        array( 'id' => 'f-all', 'name' => 'All', 'parent' => '', 'type' => 'container' ),
        array( 'id' => 'f-ngfw', 'name' => 'ngfw-shared', 'parent' => 'All', 'type' => 'container' ),
        array( 'id' => 'f-br', 'name' => 'Branches', 'parent' => 'ngfw-shared', 'type' => 'container', 'snippets' => array( 'branch-snippet' ) ),
        array( 'id' => 'd-1', 'name' => '001122334455', 'parent' => 'Branches', 'type' => 'on-prem', 'serial_number' => '001122334455' ),
    ),
    'snippets' => array( array( 'id' => 's-1', 'name' => 'branch-snippet' ) ),
    // the answer of /config/setup/v1/variables (for any folder / snippet / device: the import takes only its own)
    'variables' => array(
        array( 'id' => 'v1', 'name' => '$ethernet1_1', 'type' => 'ip-netmask', 'value' => '10.0.0.1/24', 'folder' => 'Branches', 'description' => 'LAN default' ),
        array( 'id' => 'v2', 'name' => '$ethernet1_1', 'type' => 'ip-netmask', 'value' => '10.1.1.1/24', 'device' => '001122334455', 'overridden' => TRUE ),
        array( 'id' => 'v3', 'name' => '$dns-server', 'type' => 'fqdn', 'value' => 'dns.example.com', 'snippet' => 'branch-snippet' ),
        array( 'id' => 'v4', 'name' => '$egress', 'type' => 'egress-max', 'value' => '1000', 'folder' => 'ngfw-shared' ),
        array( 'id' => 'v5', 'name' => '$pred', 'type' => 'ip-netmask', 'value' => '1.1.1.1', 'folder' => 'predefined' ),
    ),
);

class MockVariablesConnector extends PanSCMAPIConnector
{
    public $setup;
    public $calls = array();
    public function getAccessToken() { $this->access_token = "mock"; }
    function curl_request_SCM( $url )
    {
        $this->calls[] = $url;
        $p = parse_url( $url );
        $type = basename( $p['path'] );
        $data = strpos( $p['path'], '/config/setup/' ) !== FALSE ? ( $this->setup[$type] ?? array() ) : array();
        return array( 'data' => $data, 'total' => count( $data ), 'limit' => 10000, 'offset' => 0 );
    }
}

$doc = new DOMDocument();
$doc->load( $repo . "/utils/develop/buckbeak_baseconfig.xml", XML_PARSE_BIG_LINES );
$pan = new BuckbeakConf();
$pan->load_from_domxml( $doc );
$c = new MockVariablesConnector( "1234567890" );
$c->setup = $setup;
$folders = array_values( array_unique( array_merge( PanSCMAPIConnector::$folderArray, $c->getSnippetsavailable( $pan ), $c->getFolderavailable( $pan ) ) ) );
foreach( $folders as $folder )
{
    $sub = $pan->findContainer( $folder ) ?? $pan->findSnippet( $folder ) ?? $pan->findDeviceCloud( $folder ) ?? $pan->findDeviceOnPrem( $folder );
    if( $sub !== null )
        $c->loadSCMConfig( $folder, $sub, 'device' );
}
$urls = array_values( array_filter( $c->calls, function( $u ) { return strpos( $u, '/variables' ) !== FALSE; } ) );
eq( array( count( preg_grep( '#/config/setup/v1/variables\?folder=Branches&#', $urls ) ), count( preg_grep( '#/config/setup/v1/variables\?device=001122334455&#', $urls ) ),
    count( preg_grep( '#/config/setup/v1/variables\?snippet=branch-snippet&#', $urls ) ) ), array( 1, 1, 1 ),
    'variables: read per folder, device and snippet (/config/setup/v1/variables?folder= / device= / snippet=)' );

$out = tempnam( sys_get_temp_dir(), 'scmvar' ) . '.xml';
$pan->save_to_file( $out );

// type=device actions=display: the variables of each folder / snippet / device (shadow-json)
$vars = array();
foreach( array( 'container', 'deviceonprem', 'snippet' ) as $dt )
{
    $o = shell_exec( 'php ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=device devicetype=' . $dt . ' in=' . escapeshellarg( $out ) . ' actions=display shadow-json 2>/dev/null' );
    $j = json_decode( substr( (string)$o, (int)strpos( (string)$o, '{' ) ), TRUE );
    foreach( (array)$j as $k => $stores )
        if( is_array( $stores ) )
            foreach( $stores as $st )
                foreach( (array)( $st['sub']['object'] ?? array() ) as $name => $obj )
                    if( !empty( $obj['variables'] ) )
                        $vars[$name] = $obj['variables'];
}
ksort( $vars );
eq( $vars, array(
    '001122334455' => array( '$ethernet1_1' => array( 'type' => 'ip-netmask', 'value' => '10.1.1.1/24', 'description' => '' ) ),
    'Branches' => array( '$ethernet1_1' => array( 'type' => 'ip-netmask', 'value' => '10.0.0.1/24', 'description' => 'LAN default' ) ),
    'branch-snippet' => array( '$dns-server' => array( 'type' => 'fqdn', 'value' => 'dns.example.com', 'description' => '' ) ),
    'ngfw-shared' => array( '$egress' => array( 'type' => 'egress-max', 'value' => '1000', 'description' => '' ) ),
), 'variables: each in its own folder / snippet / device (the device value overrides the folder value), predefined left out' );

$x = file_get_contents( $out );
eq( strpos( preg_replace( '/>\s+</', '><', $x ), '<variable><entry name="$ethernet1_1"><type><ip-netmask>10.1.1.1/24</ip-netmask></type></entry></variable>' ) !== FALSE, TRUE,
    'variables: XML as PAN-OS keeps variables of a template' );

// offline: in=scm-export:// - NN_variables.json of the export is read the same way
$exp = sys_get_temp_dir() . '/scmvar-export-' . getmypid();
@mkdir( $exp . '/config/folders/Branches', 0700, TRUE );
@mkdir( $exp . '/config/devices/001122334455', 0700, TRUE );
file_put_contents( $exp . '/manifest.json', json_encode( array( 'tsg_id' => '1234567890' ) ) );
file_put_contents( $exp . '/config/01_folders.json', json_encode( array( 'data' => $setup['folders'] ) ) );
file_put_contents( $exp . '/config/02_snippets.json', json_encode( array( 'data' => $setup['snippets'] ) ) );
file_put_contents( $exp . '/config/folders/Branches/01_variables.json', json_encode( array( 'data' => array( $setup['variables'][0] ) ) ) );
file_put_contents( $exp . '/config/devices/001122334455/01_variables.json', json_encode( array( 'data' => array( $setup['variables'][1] ) ) ) );
$out2 = $exp . '/out.xml';
shell_exec( 'php ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=device in=scm-export://' . escapeshellarg( $exp ) . ' location=any actions=display out=' . escapeshellarg( $out2 ) . ' 2>&1' );
$x2 = (string)@file_get_contents( $out2 );
eq( array( substr_count( $x2, '<entry name="$ethernet1_1">' ), strpos( $x2, '<ip-netmask>10.1.1.1/24</ip-netmask>' ) !== FALSE ), array( 2, TRUE ),
    'variables: also from an export (in=scm-export://, NN_variables.json)' );

@unlink( $out );
array_map( 'unlink', array_filter( glob( $exp . '/{,config/,config/*/,config/*/*/}*', GLOB_BRACE ), 'is_file' ) );

echo "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
foreach( $failed as $f )
    echo $f . "\n";
exit( count( $failed ) ? 1 : 0 );
