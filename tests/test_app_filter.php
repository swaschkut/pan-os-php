<?php
/**
 * application filter: the apps it matches come from its store and every store above it (parentCentralStore: parent
 * device groups / folders, shared / All, the predefined apps) - Panorama device group and SCM folder (Buckbeak: before
 * "Attempt to read property appStore on null"). Synthetic configurations (test inputs + an application filter).
 *
 *   php tests/test_app_filter.php
 */
$repo = dirname( __DIR__ );
$checks = 0;
$failed = array();
function eq( $got, $want, $what )
{
    global $checks, $failed;
    $checks++;
    echo ( $got === $want ? "ok  " : "FAIL " ) . $what . "\n";
    if( $got !== $want )
        $failed[] = " - " . $what . "\n      expected " . json_encode( $want ) . "\n      got      " . json_encode( $got );
}
$af = '<application-filter><entry name="AF-net"><category><member>networking</member></category><risk><member>5</member></risk></entry></application-filter>';
$count = function( $xml ) use ( $repo ) {
    $f = tempnam( sys_get_temp_dir(), 'af' ) . '.xml';
    file_put_contents( $f, $xml );
    $o = (string)shell_exec( 'php ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=application in=' . escapeshellarg( $f )
        . ' location=any ' . escapeshellarg( 'filter=(name eq AF-net)' ) . ' actions=display 2>&1' );
    @unlink( $f );
    if( strpos( $o, 'Died' ) !== FALSE )
        return 'error';
    return preg_match( "/AppFilter 'AF-net' app_counter: (\\d+)/", $o, $m ) ? (int)$m[1] : null;
};
$scm = file_get_contents( $repo . '/tests/input/SCM-import.xml' );
$i = strpos( $scm, '<entry name="ngfw-shared"' );
$j = strpos( $scm, '>', $i ) + 1;
$n1 = $count( substr( $scm, 0, $j ) . $af . substr( $scm, $j ) );
$pano = str_replace( '<entry name="DG2"><address>', '<entry name="DG2">' . $af . '<address>', file_get_contents( $repo . '/tests/input/effective-panorama.xml' ) );
$n2 = $count( $pano );
eq( array( is_int( $n1 ) && $n1 > 0, $n1 === $n2 ), array( TRUE, TRUE ), 'application filter in an SCM folder and in a device group: the predefined apps of the category (' . json_encode( $n1 ) . ' / ' . json_encode( $n2 ) . ')' );
echo "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
foreach( $failed as $f )
    echo $f . "\n";
exit( count( $failed ) ? 1 : 0 );
