<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DiffLog (lib/misc-classes/DiffLog.php): the output of type=diff read back as entries - with a real type=diff of two
 * synthetic configurations (tests/input) and the XPaths of the locations of a Panorama / firewall.
 *
 *   php tests/test_difflog.php
 */
$repo = dirname( __DIR__ );
require_once $repo . '/lib/misc-classes/DiffLog.php';
$checks = 0; $failed = 0;
function eq( $got, $want, $msg )
{
    global $checks, $failed;
    $checks++;
    if( $got === $want ) { print "ok   " . $msg . "\n"; return; }
    $failed++;
    print "FAIL " . $msg . "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) . "\n";
}

// where / what / which of an XPath
$loc = function( $x ) { $e = DiffLog::entry( $x ); return array( $e['location'], $e['kind'], $e['name'] ); };
$d = "/config/devices/entry[@name='localhost.localdomain']";
eq( $loc( "/config/shared/address/entry[@name='h1']" ), array( 'shared', 'address', 'h1' ), 'shared object' );
eq( $loc( $d . "/device-group/entry[@name='DG 1']/pre-rulebase/security/rules/entry[@name='r1']" ), array( 'device-group DG 1', 'pre-rulebase/security/rules', 'r1' ), 'rule of a device group' );
eq( $loc( $d . "/template/entry[@name='T1']/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/zone/entry[@name='trust']" ),
    array( 'template T1 / vsys vsys1', 'zone', 'trust' ), 'zone of a vsys of a template' );
eq( $loc( $d . "/template/entry[@name='T1']/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet/entry[@name='ethernet1/1']" ),
    array( 'template T1', 'network/interface/ethernet', 'ethernet1/1' ), 'interface of a template' );
eq( $loc( $d . "/vsys/entry[@name='vsys1']/address" ), array( 'vsys vsys1', 'address', '' ), 'a container of a firewall vsys (no entry at the end)' );
eq( $loc( $d . "/deviceconfig/system" ), array( 'device', 'deviceconfig/system', '' ), 'settings of the device' );
eq( $loc( "/config/mgt-config/users/entry[@name='admin']" ), array( 'other', 'mgt-config/users', 'admin' ), 'anything else' );

// a real type=diff: a description added to some addresses, the same diff the other way round
$tmp = sys_get_temp_dir() . '/difflog-test-' . getmypid();
mkdir( $tmp );
copy( $repo . '/tests/input/panorama-10.0-merger.xml', $tmp . '/a.xml' );
$php = escapeshellarg( PHP_BINARY ); $tool = escapeshellarg( $repo . '/utils/pan-os-php.php' );
exec( 'cd ' . escapeshellarg( $tmp ) . " && $php $tool type=address in=a.xml out=b.xml location=any actions=description-Append:changed 'filter=(name contains 1)' >/dev/null 2>&1"
    . " && $php $tool type=diff file1=a.xml file2=b.xml > ab.log 2>&1; $php $tool type=diff file1=b.xml file2=a.xml > ba.log 2>&1; $php $tool type=diff file1=a.xml file2=a.xml > aa.log 2>&1" );
$ab = DiffLog::read( $tmp . '/ab.log' );
$ba = DiffLog::read( $tmp . '/ba.log' );
$aa = DiffLog::read( $tmp . '/aa.log' );
$n = substr_count( (string)file_get_contents( $tmp . '/ab.log' ), "\nXPATH: " );
eq( array( $ab['final'], $ab['count'], count( $ab['entries'] ), $n > 3 ), array( 'FAIL', $n, $n, TRUE ), 'type=diff: one entry per XPath, FinalResult FAIL' );
$e = $ab['entries'][0];
eq( array( $e['location'], $e['kind'], $e['added'], $e['removed'], $e['lines'] ), array( 'shared', 'address', 1, 0, array( '+<description>changed</description>' ) ), 'an entry: + lines of file2' );
eq( array( $ba['count'], $ba['entries'][0]['added'], $ba['entries'][0]['removed'], DiffLog::finalResult( $tmp . '/ba.log' ) ), array( $n, 0, 1, 'FAIL' ), 'the other way round: - lines' );
eq( array( $aa['final'], $aa['count'], DiffLog::finalResult( $tmp . '/aa.log' ) ), array( 'PASS', 0, 'PASS' ), 'the same file twice: PASS, no entry' );
$cut = DiffLog::read( $tmp . '/ab.log', 2, 0 );
eq( array( count( $cut['entries'] ), $cut['count'], $cut['truncated'], $cut['entries'][0]['lines'], $cut['entries'][0]['lines_cut'] ), array( 2, $n, TRUE, array(), 1 ),
    'limits: entries / lines kept, the rest counted' );
eq( array( DiffLog::read( $tmp . '/none.log' )['count'], DiffLog::finalResult( $tmp . '/none.log' ) ), array( 0, null ), 'no file: nothing' );
exec( 'rm -rf ' . escapeshellarg( $tmp ) );

print "\n" . $checks . " checks, " . $failed . " failed\n";
exit( $failed ? 1 : 0 );
