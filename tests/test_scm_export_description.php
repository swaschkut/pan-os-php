<?php
/**
 * type=scm-export-xml with a security rule whose description SCM sends as a list (synthetic export, no customer data):
 * before, Rule->setDescription() got the array (TypeError in strlen) and the conversion stopped.
 *
 *   php tests/test_scm_export_description.php
 */
$repo = dirname( __DIR__ );
$dir = sys_get_temp_dir() . '/scmdesc-' . getmypid();
$exp = $dir . '/1234567890/20261121-120000';
@mkdir( $exp . '/config/folders/All', 0700, TRUE );
file_put_contents( $exp . '/manifest.json', json_encode( array( 'tsg_id' => '1234567890', 'areas' => array( 'config' ) ) ) );
foreach( array( '01_folders.json', '02_snippets.json', '03_devices.json' ) as $f )
    file_put_contents( $exp . '/config/' . $f, json_encode( array( 'data' => array() ) ) );
$rule = function( $name, $desc ) {
    return array( 'id' => md5( $name ), 'name' => $name, 'folder' => 'All', 'from' => array( 'any' ), 'to' => array( 'any' ), 'source' => array( 'any' ),
        'destination' => array( 'any' ), 'service' => array( 'any' ), 'application' => array( 'any' ), 'action' => 'allow', 'description' => $desc );
};
file_put_contents( $exp . '/config/folders/All/030_security-rules-pre.json', json_encode( array( 'data' => array(
    $rule( 'r-text', 'one line' ), $rule( 'r-list', array( 'line a', 'line b' ) ), $rule( 'r-empty', array() ), $rule( 'r-odd', array( array( 'x' ) ) ) ) ) ) );
$out = $dir . '/out.xml';
$cmd = escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=scm-export-xml ' . escapeshellarg( 'in=scm-export://' . $dir . '/1234567890' ) . ' ' . escapeshellarg( 'out=' . $out ) . ' 2>&1';
exec( $cmd, $lines, $rc );
$xml = is_file( $out ) ? (string)file_get_contents( $out ) : '';
$checks = 0; $failed = array();
$ok = function( $cond, $msg ) use ( &$checks, &$failed ) { $checks++; print ( $cond ? "ok   " : "FAIL " ) . $msg . "\n"; if( !$cond ) $failed[] = $msg; };
$doc = new DOMDocument();
$loaded = $xml !== '' && @$doc->loadXML( $xml );
$desc = array();
if( $loaded )
    foreach( ( new DOMXPath( $doc ) )->query( '//security/rules/entry' ) as $e )
        $desc[$e->getAttribute( 'name' )] = ( $d = $e->getElementsByTagName( 'description' )->item( 0 ) ) ? $d->textContent : null;
$ok( $rc === 0 && $loaded && strpos( implode( "\n", $lines ), 'TypeError' ) === FALSE, 'the conversion runs through (no TypeError)' );
$ok( ( $desc['r-text'] ?? '-' ) === 'one line', 'a text description stays' );
$ok( ( $desc['r-list'] ?? '-' ) === "line a\nline b", 'a description as a list: its lines' );
$ok( array_key_exists( 'r-empty', $desc ) && (string)$desc['r-empty'] === '' && array_key_exists( 'r-odd', $desc ) && (string)$desc['r-odd'] === '', 'an empty list / not text: no description text, the rule is there' );
exec( 'rm -rf ' . escapeshellarg( $dir ) );
print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
if( count( $failed ) ) { print implode( "\n", array_slice( $lines, -15 ) ) . "\n"; exit( 1 ); }
exit( 0 );
