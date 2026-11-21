<?php
/**
 * ConfigObjectMerge (merge per field, git step 4) and the merge driver in the history of the config viewer (undo).
 * Synthetic entries only.
 *
 *   php tests/test_config_merge.php
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/misc-classes/ConfigObjectMerge.php';
require_once $repo . '/lib/misc-classes/ConfigObjectSplit.php';
require_once $repo . '/utils/develop/config-viewer/lib/ViewerGit.php';
$checks = 0; $failed = array();
$ok = function( $cond, $msg ) use ( &$checks, &$failed ) { $checks++; print ( $cond ? "ok   " : "FAIL " ) . $msg . "\n"; if( !$cond ) $failed[] = $msg; };
$c = function( $xml ) { $d = new DOMDocument(); $d->loadXML( $xml ); return ConfigObjectSplit::canonical( $d->documentElement ); };
$M = function( $o, $a, $b, $p = 'shared/address/x.xml' ) { return ConfigObjectMerge::merge( $o, $a, $b, $p ); };

$o = $c( '<entry name="web"><ip-netmask>10.0.0.1</ip-netmask><description>a</description><tag><member>t1</member></tag></entry>' );
$a = $c( '<entry name="web"><ip-netmask>10.0.0.1</ip-netmask><description>b</description><tag><member>t1</member></tag></entry>' );
$b = $c( '<entry name="web"><ip-netmask>10.0.0.1</ip-netmask><description>a</description><tag><member>t1</member><member>t2</member></tag></entry>' );
$ok( $M( $o, $a, $b ) === $c( '<entry name="web"><ip-netmask>10.0.0.1</ip-netmask><description>b</description><tag><member>t1</member><member>t2</member></tag></entry>' ),
    'different fields of one object: both taken (neighbouring lines)' );
$b2 = $c( '<entry name="web"><ip-netmask>10.0.0.1</ip-netmask><description>c</description><tag><member>t1</member></tag></entry>' );
$ok( $M( $o, $a, $b2 ) === null, 'the same field changed on both sides to different values: conflict' );
$ok( $M( $o, $a, $a ) === $a && $M( $o, $o, $b ) === $b && $M( $o, $a, $o ) === $a, 'one side only / both the same' );

$o = $c( '<entry name="g"><static><member>m0</member><member>m1</member></static></entry>' );
$a = $c( '<entry name="g"><static><member>m0</member><member>m1</member><member>a1</member></static></entry>' );
$b = $c( '<entry name="g"><static><member>m1</member><member>b1</member></static></entry>' );
$ok( $M( $o, $a, $b ) === $c( '<entry name="g"><static><member>m1</member><member>b1</member><member>a1</member></static></entry>' ),
    'members are a set: additions of both sides, the removal of one side' );
$a = $c( '<entry name="g"><static><member>m0</member><member>m1</member><member>x</member></static></entry>' );
$b = $c( '<entry name="g"><static><member>m0</member><member>m1</member><member>x</member></static></entry>' );
$ok( $M( $o, $a, $b ) === $a, 'the same member added on both sides: once' );

$o = $c( '<entry name="w"><ip-netmask>1.1.1.1</ip-netmask><description>a</description></entry>' );
$a = $c( '<entry name="w"><ip-netmask>1.1.1.1</ip-netmask></entry>' );
$b = $c( '<entry name="w"><ip-netmask>1.1.1.1</ip-netmask><description>b</description></entry>' );
$ok( $M( $o, $a, $b ) === null, 'a field removed on one side and changed on the other: conflict' );
$b = $c( '<entry name="w"><ip-netmask>1.1.1.2</ip-netmask><description>a</description></entry>' );
$ok( $M( $o, $a, $b ) === $c( '<entry name="w"><ip-netmask>1.1.1.2</ip-netmask></entry>' ), 'a field removed on one side, another changed on the other' );

$o = $c( '<entry name="r1" uuid="u1"><action>allow</action><disabled>no</disabled></entry>' );
$a = $c( '<entry name="r1-new" uuid="u1"><action>allow</action><disabled>no</disabled></entry>' );
$b = $c( '<entry name="r1" uuid="u1"><action>deny</action><disabled>no</disabled></entry>' );
$ok( $M( $o, $a, $b ) === $c( '<entry name="r1-new" uuid="u1"><action>deny</action><disabled>no</disabled></entry>' ), 'a rule renamed (attribute) and its action changed' );

$ok( $M( "a\nb\nc\n", "a\nb\nc\nx\n", "a\nc\n", 'shared/address/_order' ) === "a\nc\nx\n", '_order: an addition and a removal' );
$ok( $M( "a\nb\nc\n", "a\nb\nc\n", "c\na\nb\n", 'pre-rulebase/security/rules/_order' ) === "c\na\nb\n", '_order: moved on one side only' );
$ok( $M( "a\nb\n", "a\nx\nb\n", "a\nb\ny\n", 'x/_order' ) === "a\nx\nb\ny\n", '_order: additions of both sides at their places' );

$rest = function( $x, $y ) use ( $c ) { $d = new DOMDocument(); $d->loadXML( '<config><mgt-config><users>' . $x . '</users></mgt-config><devices><entry name="localhost.localdomain"><deviceconfig>' . $y . '</deviceconfig></entry></devices></config>' ); return ConfigObjectSplit::canonical( $d ); };
$ok( $M( $rest( '<entry name="admin"/>', '<system/>' ), $rest( '<entry name="admin"/><entry name="bob"/>', '<system/>' ), $rest( '<entry name="admin"/>', '<system><hostname>fw1</hostname></system>' ), '_rest.xml' )
    === $rest( '<entry name="admin"/><entry name="bob"/>', '<system><hostname>fw1</hostname></system>' ), '_rest.xml: changes in two places of the rest' );
$ok( $M( 'x', '<entry name="a"/>', '<entry name="b"/>' ) === null, 'no XML: conflict' );

// ---- in git: the undo (merge-tree) with the driver, in a bare repository of ViewerGit
$dir = sys_get_temp_dir() . '/cfgmerge-' . getmypid();
$g = new ViewerGit( $dir . '/history.git' );
$ok( $g->ready() && strpos( (string)@file_get_contents( $dir . '/history.git/info/attributes' ), '*.xml merge=panos' ) !== FALSE, 'git: the repository gets the merge driver' );
$P = 'shared/address/web.xml';
$e = function( $desc, $tags ) use ( $c ) { return $c( '<entry name="web"><ip-netmask>10.0.0.1</ip-netmask><description>' . $desc . '</description><tag>' . $tags . '</tag></entry>' ); };
$v = $g->commit( 'refs/viewer/versions/t', null, array( $P => $e( 'a', '<member>t1</member>' ), '_rest.xml' => "<?xml version=\"1.0\"?>\n<config/>\n" ), array(), "v\n", 't', time(), TRUE );
$c1 = $g->commit( 'refs/viewer/work/t', $v, array( $P => $e( 'b', '<member>t1</member>' ) ), array(), "c1\n", 't', time() );
$c2 = $g->commit( 'refs/viewer/work/t', $c1, array( $P => $e( 'b', '<member>t1</member><member>t2</member>' ) ), array(), "c2\n", 't', time() );
$r = $g->revertTree( $c1, $c2 );
$ok( $r['tree'] !== null && $g->show( $r['tree'], $P ) === $e( 'a', '<member>t1</member><member>t2</member>' ),
    'git: undo of the description while a later change added a tag in the next lines - merged per field' );
$c3 = $g->commit( 'refs/viewer/work/t', $c2, array( $P => $e( 'c', '<member>t1</member><member>t2</member>' ) ), array(), "c3\n", 't', time() );
$r = $g->revertTree( $c1, $c3 );
$ok( $r['tree'] === null && $r['conflicts'] === array( $P ), 'git: undo of the description after a later change of the description - conflict' );
exec( 'rm -rf ' . escapeshellarg( $dir ) );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
