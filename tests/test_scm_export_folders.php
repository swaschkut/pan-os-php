<?php
/**
 * type=scm-export-xml with folders as scm_pa_export.php writes them (synthetic export, no customer data):
 * - the folder directories are slugs ("Prisma Access" -> config/folders/Prisma_Access/), the cloud folders (Mobile
 *   Users, Remote Networks, Service Connections - loaded as DeviceCloud) are below config/folders/ as well: before,
 *   nothing of these folders was loaded (only All, ngfw-shared and the snippets)
 * - objects of "Prisma Access" carry the former owner name "Shared"
 *
 *   php tests/test_scm_export_folders.php
 */
$repo = dirname( __DIR__ );
$dir = sys_get_temp_dir() . '/scmfold-' . getmypid();
$exp = $dir . '/1234567890/20261123-010000';
@mkdir( $exp . '/config', 0700, TRUE );
file_put_contents( $exp . '/manifest.json', json_encode( array( 'tsg_id' => '1234567890', 'areas' => array( 'config' ) ) ) );
$folders = array(
    array( 'id' => 'f1', 'name' => 'All', 'parent' => '', 'type' => 'container', 'display_name' => 'Global' ),
    array( 'id' => 'f2', 'name' => 'Prisma Access', 'parent' => 'All', 'type' => 'container' ),
    array( 'id' => 'f3', 'name' => 'Mobile Users Container', 'parent' => 'Prisma Access', 'type' => 'container' ),
    array( 'id' => 'f4', 'name' => 'Mobile Users', 'parent' => 'Mobile Users Container', 'type' => 'cloud' ),
    array( 'id' => 'f5', 'name' => 'Mobile Users Explicit Proxy', 'parent' => 'Mobile Users Container', 'type' => 'cloud' ),
    array( 'id' => 'f6', 'name' => 'Remote Networks', 'parent' => 'Prisma Access', 'type' => 'cloud' ),
    array( 'id' => 'f7', 'name' => 'Service Connections', 'parent' => 'Prisma Access', 'type' => 'cloud' ) );
file_put_contents( $exp . '/config/01_folders.json', json_encode( array( 'data' => $folders ) ) );
file_put_contents( $exp . '/config/02_snippets.json', json_encode( array( 'data' => array() ) ) );
file_put_contents( $exp . '/config/03_devices.json', json_encode( array( 'data' => array() ) ) );
$put = function( $container, $file, $data ) use ( $exp ) {
    $d = $exp . '/config/folders/' . preg_replace( '/[^A-Za-z0-9._-]+/', '_', $container );
    @mkdir( $d, 0700, TRUE );
    file_put_contents( $d . '/' . $file, json_encode( array( 'container' => $container, 'data' => $data ) ) );
};
$put( 'All', '20_addresses.json', array( array( 'id' => 'a1', 'name' => 'all-net', 'folder' => 'All', 'ip_netmask' => '10.9.0.0/16' ) ) );
$put( 'Prisma Access', '20_addresses.json', array( array( 'id' => 'a2', 'name' => 'pa-fqdn', 'folder' => 'Shared', 'fqdn' => 'pa.example.com' ),
    array( 'id' => 'a3', 'name' => 'pa-net', 'folder' => 'Shared', 'ip_netmask' => '10.1.0.0/16' ) ) );
$put( 'Mobile Users', '20_addresses.json', array( array( 'id' => 'a4', 'name' => 'mu-fqdn', 'folder' => 'Mobile Users', 'fqdn' => 'mu.example.com' ) ) );
$put( 'Mobile Users Explicit Proxy', '20_addresses.json', array( array( 'id' => 'a5', 'name' => 'ep-fqdn', 'folder' => 'Mobile Users Explicit Proxy', 'fqdn' => 'ep.example.com' ) ) );
$put( 'Remote Networks', '20_addresses.json', array( array( 'id' => 'a6', 'name' => 'rn-net', 'folder' => 'Remote Networks', 'ip_netmask' => '10.6.0.0/16' ) ) );
$put( 'Prisma Access', '84_security-rules-pre.json', array( array( 'id' => 'r1', 'name' => 'pa-rule', 'folder' => 'Shared', 'from' => array( 'any' ), 'to' => array( 'any' ),
    'source' => array( 'pa-net' ), 'destination' => array( 'pa-fqdn' ), 'service' => array( 'any' ), 'application' => array( 'any' ), 'action' => 'allow' ) ) );
$out = $dir . '/out.xml';
$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=scm-export-xml ' . escapeshellarg( 'in=scm-export://' . $dir . '/1234567890' ) . ' ' . escapeshellarg( 'out=' . $out ) . ' 2>&1';
exec( $cmd, $lines, $rc );
$checks = 0; $failed = array();
$ok = function( $cond, $msg ) use ( &$checks, &$failed ) { $checks++; print ( $cond ? "ok   " : "FAIL " ) . $msg . "\n"; if( !$cond ) $failed[] = $msg; };
$doc = new DOMDocument();
$loaded = is_file( $out ) && @$doc->loadXML( (string)file_get_contents( $out ) );
$where = array();
if( $loaded )
    foreach( ( new DOMXPath( $doc ) )->query( '//address/entry' ) as $e )
    {
        $c = $e->parentNode->parentNode;
        $where[$e->getAttribute( 'name' )] = $c->getAttribute( 'name' ) . ( $e->getElementsByTagName( 'fqdn' )->length ? ' fqdn' : '' );
    }
$rules = array();
if( $loaded )
    foreach( ( new DOMXPath( $doc ) )->query( '//security/rules/entry' ) as $e )
        $rules[] = $e->getAttribute( 'name' );
$ok( $rc === 0 && $loaded, 'the conversion runs through' );
$ok( ( $where['all-net'] ?? '' ) === 'All', 'folder All' );
$ok( ( $where['pa-fqdn'] ?? '' ) === 'Prisma Access fqdn' && ( $where['pa-net'] ?? '' ) === 'Prisma Access', 'folder Prisma Access (directory Prisma_Access, owner "Shared"): FQDN and netmask objects' );
$ok( ( $where['mu-fqdn'] ?? '' ) === 'Mobile Users fqdn' && ( $where['ep-fqdn'] ?? '' ) === 'Mobile Users Explicit Proxy fqdn' && ( $where['rn-net'] ?? '' ) === 'Remote Networks',
    'cloud folders Mobile Users / Explicit Proxy / Remote Networks (directories with "_")' );
$ok( in_array( 'pa-rule', $rules, TRUE ), 'a security rule of Prisma Access (owner "Shared")' );
exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
if( count( $failed ) ) { print_r( $where ); print implode( "\n", array_slice( $lines, -15 ) ) . "\n"; exit( 1 ); }
exit( 0 );
