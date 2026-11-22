<?php
/**
 * Support files: pan-os-php type=support-file / support-file-read, SupportFile (encryption), ConfigExcerpt.
 * Synthetic configurations only (tests/input/merger/*.xml and the one written here).
 *   php tests/test_support_file.php
 */
$repo = realpath( dirname( __FILE__ ) . '/..' );
require_once $repo . '/lib/misc-classes/SupportFile.php';
require_once $repo . '/utils/common/ConfigExcerpt.php';

$fail = 0;
$count = 0;
$ok = function( $cond, string $msg ) use ( &$fail, &$count ) {
    $count++;
    if( !$cond )
    {
        $fail++;
        echo " - FAILED: " . $msg . "\n";
    }
};
$dir = sys_get_temp_dir() . '/support-file-test-' . bin2hex( random_bytes( 4 ) );
mkdir( $dir, 0700 );
$key = SupportFile::keygen( 'test-support' );
file_put_contents( $dir . '/support.key', $key['secret'] );
putenv( 'PANOSPHP_SUPPORT_TEST_KEYS=' . json_encode( array( 'keys' => array( $key['public'] ) ) ) );
$run = function( string $args ) use ( $repo, $dir ) {
    exec( 'cd ' . escapeshellarg( $dir ) . ' && ' . escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . $args . ' 2>&1', $out, $rc );
    return array( $rc, implode( "\n", $out ) );
};
$unzip = function( string $bytes ) {
    $f = tempnam( sys_get_temp_dir(), 'tz' );
    file_put_contents( $f, $bytes );
    $z = new ZipArchive();
    $out = array();
    if( $z->open( $f ) === TRUE )
    {
        for( $i = 0; $i < $z->numFiles; $i++ )
            $out[$z->getNameIndex( $i )] = $z->getFromIndex( $i );
        $z->close();
    }
    @unlink( $f );
    return $out;
};

// ---- SupportFile: encrypt / decrypt, a changed byte, another key
$e = SupportFile::encrypt( 'zip-bytes' );
$other = SupportFile::keygen( 'other' );
$bad = $e;
$bad[strlen( $bad ) - 3] = chr( ord( $bad[strlen( $bad ) - 3] ) ^ 1 );
$msg = function( callable $f ) { try { $f(); return 'ok'; } catch( Exception $x ) { return $x->getMessage(); } };
$ok( SupportFile::decrypt( $e, $key['secret'] ) === 'zip-bytes' && SupportFile::header( $e )['kid'] === 'test-support'
    && strpos( $msg( function() use ( $bad, $key ) { SupportFile::decrypt( $bad, $key['secret'] ); } ), 'damaged or changed' ) !== FALSE
    && strpos( $msg( function() use ( $e, $other ) { SupportFile::decrypt( $e, $other['secret'] ); } ), 'made for the support key test-support' ) !== FALSE,
    'SupportFile: encrypt / decrypt; a changed byte and another key are refused' );

// ---- ConfigExcerpt: every copy, the groups up, the members down, the rules, the hierarchy (loadable)
$d = new DOMDocument();
$d->load( $repo . '/tests/input/merger/safety-shadowed-panorama.xml' );
$ex = new ConfigExcerpt( $d );
$sel = $ex->select( array( 'web' ), TRUE );
$small = $ex->build( $sel );
$x = new DOMXPath( $small );
$ok( $sel['up'] === array( 'web', 'G' ) && count( $sel['rules'] ) === 1 && $x->query( '//device-group/entry[@name="DG-C"]/address/entry[@name="web"]' )->length === 1
    && $x->query( '//device-group/entry[@name="DG-P"]/address/entry[@name="web2"]' )->length === 0
    && $x->query( '//readonly//device-group/entry[@name="DG-C"]/parent-dg' )->item( 0 )->textContent === 'DG-P'
    && $ex->hierarchy()['deviceGroups']['DG-C']['parent'] === 'DG-P',
    'ConfigExcerpt: web in DG-P and DG-C, group G up, the rule of DG-C, not web2; the hierarchy' );

// ---- type=support-file: merger case (report, result), secrets replaced, read back
$cfg = $repo . '/tests/input/merger/safety-shadowed-panorama.xml';
$withSecrets = str_replace( '<mgt-config/>', '<mgt-config><users><entry name="admin"><phash>$5$abcdefgh$verysecrethash</phash></entry></users></mgt-config>', file_get_contents( $cfg ) );
$withSecrets = str_replace( '<shared/>', '<shared><log-settings><snmptrap><entry name="t"><version><v2c><server><entry name="s"><community>snmp-community-secret</community></entry></server></v2c></version></entry></snmptrap></log-settings></shared>', $withSecrets );
file_put_contents( $dir . '/in.xml', $withSecrets );
$run( 'type=object-merger in=in.xml out=after.xml objecttype=address location=DG-P exportjson=m.json' );
list( $rc, $o ) = $run( 'type=support-file in=in.xml result=after.xml report=m.json full out=s.tsf ' . escapeshellarg( 'note=web blocked' ) );
$z = $unzip( SupportFile::decrypt( (string)file_get_contents( $dir . '/s.tsf' ), $key['secret'] ) );
$man = json_decode( $z['manifest.json'] ?? '', TRUE );
$objs = json_decode( $z['config/objects.json'] ?? '', TRUE );
$all = implode( "\n", $z );
$ok( $rc === 0 && $man['note'] === 'web blocked' && $man['anonymized'] === FALSE && in_array( 'web', $man['names'], TRUE )
    && array_column( $objs['web']['before'] ?? array(), 'location' ) === array( 'DG-P', 'DG-C' ) && isset( $z['config/full-before.xml'], $z['case/report.json'], $z['environment.json'] )
    && strpos( $all, 'verysecrethash' ) === FALSE && strpos( $all, 'snmp-community-secret' ) === FALSE && strpos( $all, '-removed-' ) !== FALSE,
    'support-file: case of the merger, every copy of web, whole configuration - secrets (phash, community) replaced' );
list( $rc, $o ) = $run( 'type=support-file-read in=s.tsf key=support.key out=open' );
$ok( $rc === 0 && strpos( $o, 'every file matches the manifest' ) !== FALSE && is_file( $dir . '/open/report.html' ) && is_file( $dir . '/open/config/excerpt-before.xml' )
    && strpos( (string)file_get_contents( $dir . '/open/report.html' ), 'DG-C' ) !== FALSE,
    'support-file-read: opened, checked against the manifest, report.html, the excerpt' );
list( $rc, $o ) = $run( 'type=address in=open/config/excerpt-before.xml location=any' );
$ok( $rc === 0 && strpos( $o, "Address 'web'" ) !== FALSE, 'the excerpt is a configuration pan-os-php loads' );

// ---- anonymised: mapping only outside, no original name / address left
list( $rc, $o ) = $run( 'type=support-file in=in.xml result=after.xml report=m.json anonymize mapping=map.json out=a.tsf' );
$z = $unzip( SupportFile::decrypt( (string)file_get_contents( $dir . '/a.tsf' ), $key['secret'] ) );
$map = json_decode( (string)@file_get_contents( $dir . '/map.json' ), TRUE );
$all = implode( "\n", $z );
$left = array();
foreach( array( 'web2', 'DG-P', 'DG-C', '10.9.9.9', '10.1.1.1' ) as $orig )
    if( preg_match( '/[>"\s]' . preg_quote( $orig, '/' ) . '[<"\s,]/', $all ) )
        $left[] = $orig;
$ok( $rc === 0 && isset( $map['names']['web2'] ) && $left === array() && count( preg_grep( '/map/', array_keys( $z ) ) ) === 0
    && json_decode( $z['manifest.json'], TRUE )['anonymized'] === TRUE && isset( json_decode( $z['config/objects.json'], TRUE )[$map['names']['web2']] ),
    'support-file anonymize: mapping only in mapping=, no original name / address in the support file, objects under their pseudonyms' );

// ---- the shipped support key is valid; a support file is made for the last key of the list
putenv( 'PANOSPHP_SUPPORT_TEST_KEYS' );
$shipped = SupportFile::trustedKeys();
list( $rc, $o ) = $run( 'type=support-file in=in.xml out=n.tsf' );
$ok( count( $shipped ) >= 1 && $rc === 0 && SupportFile::header( (string)file_get_contents( $dir . '/n.tsf' ) )['kid'] === array_key_last( $shipped ),
    'support-file: the shipped support key (lib/resources/support/keys.json) is valid, the file is made for the last one' );

exec( 'rm -rf ' . escapeshellarg( $dir ) );
echo $count . " checks, " . $fail . " failed\n";
exit( $fail ? 1 : 0 );
