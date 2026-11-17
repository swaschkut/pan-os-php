<?php
/**
 * Tests of the IP maps (lib/helper-classes/IPMap.php, IP4Map.php, IP6Map.php, cidr.php): exact 128 bit IPv6 values.
 *
 * IPv6 values are 128 bit integers as decimal strings. PHP compares such strings - and calculates '+ 1' / '- 1' -
 * as float, which made neighbouring IPv6 addresses equal (wrong merges, float values in the map, dumpToString() dying
 * after substract()). IPv4 (int) has to behave as before.
 *
 *   cd tests && php test_ipmap.php          exit code 0 = passed
 */

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__) . "/../lib/pan_php_framework.php";

$failed = array();
$checks = 0;
function eq( $actual, $expected, $msg )
{
    global $failed, $checks;
    $checks++;
    if( $actual !== $expected )
    {
        $failed[] = $msg . ' - expected ' . json_encode($expected) . ', got ' . json_encode($actual);
        print "    FAIL " . end($failed) . "\n";
    }
}

/** merged map of the texts, in the given order */
function merged( $class, array $texts )
{
    $m = new $class();
    foreach( $texts as $t )
        $m->addMap( $class::mapFromText($t), TRUE );
    $m->sortAndRecalculate();
    return $m;
}

function minus( $class, $text, array $sub )
{
    $m = $class::mapFromText( $text );
    foreach( $sub as $s )
        $m->substract( $class::mapFromText($s) );
    return $m;
}

/** TRUE when no start / end is a float */
function noFloat( IPMap $m )
{
    foreach( $m->getMapArray() as $e )
        if( is_float($e['start']) || is_float($e['end']) )
            return FALSE;
    return TRUE;
}

$big = cidr::inet_ptoi( '2001:db8::' );          // 42540766411282592856903984951653826560

print "  cidr::ipCmp / ipInc / ipDec\n";
if( !method_exists('cidr', 'ipCmp') )
    print "    (not available - older library)\n";
else
{
eq( cidr::ipCmp( 1, 2 ), -1, 'int' );
eq( cidr::ipCmp( 167772160, 167772160 ), 0, 'int equal' );
eq( cidr::ipCmp( $big, cidr::inet_ptoi('2001:db8::1') ), -1, 'neighbouring IPv6 values' );
eq( cidr::ipCmp( cidr::inet_ptoi('2001:db8::1'), $big ), 1, 'neighbouring IPv6 values reversed' );
eq( cidr::ipCmp( '5', $big ), -1, 'different length (string comparison would say "5" > "4...")' );
eq( cidr::ipCmp( '007', '7' ), 0, 'leading zeros' );
eq( cidr::ipCmp( 5, '5' ), 0, 'int vs string' );
eq( cidr::ipInc( 41 ), 42, 'ipInc int stays int' );
eq( cidr::ipInc( '1999' ), '2000', 'ipInc carry' );
eq( cidr::ipInc( '999' ), '1000', 'ipInc new digit' );
eq( cidr::ipInc( $big ), cidr::inet_ptoi('2001:db8::1'), 'ipInc IPv6' );
eq( cidr::ipDec( 42 ), 41, 'ipDec int' );
eq( cidr::ipDec( '2000' ), '1999', 'ipDec borrow' );
eq( cidr::ipDec( '1000' ), '999', 'ipDec shorter' );
eq( cidr::ipDec( cidr::inet_ptoi('2001:db8::1') ), $big, 'ipDec IPv6' );
eq( cidr::ipDec( '0' ), '0', 'ipDec 0' );
}

print "  IPv6 merge (sortAndRecalculate / sortArrayByStartValue)\n";
$r = merged( 'IP6Map', array( '2001:db8::1', '2001:db8::/64' ) )->dumpToString();
eq( $r, '2001:db8::-2001:db8::ffff:ffff:ffff:ffff', 'host inside network - host first' );
eq( merged( 'IP6Map', array( '2001:db8::/64', '2001:db8::1' ) )->dumpToString(), $r, 'host inside network - network first' );
eq( merged( 'IP6Map', array( '2001:db8::', '2001:db8::2' ) )->dumpToString(), '2001:db8::,2001:db8::2', 'not adjacent: not merged (::1 is not included)' );
eq( merged( 'IP6Map', array( '2001:db8::', '2001:db8::1' ) )->dumpToString(), '2001:db8::-2001:db8::1', 'adjacent: merged' );
eq( merged( 'IP6Map', array( '2001:db8::2-2001:db8::5', '2001:db8::4-2001:db8::9', '2001:db8::a' ) )->dumpToString(), '2001:db8::2-2001:db8::a', 'overlapping + adjacent ranges' );
eq( merged( 'IP6Map', array( '2001:db8::5', '::5', '2001:db8::/126' ) )->dumpToString(), '::5,2001:db8::-2001:db8::3,2001:db8::5', 'small and large values sorted by value' );
eq( noFloat( merged( 'IP6Map', array( '2001:db8::1', '2001:db8::/64', '2001:db8::2' ) ) ), TRUE, 'no float in the merged map' );
$arr = array( array('start' => '42540766411282592856903984951653826561', 'end' => '1'), array('start' => $big, 'end' => '1'), array('start' => '5', 'end' => '5') );
eq( array_column( sortArrayByStartValue($arr), 'start' ), array( '5', $big, '42540766411282592856903984951653826561' ), 'sortArrayByStartValue: decimal strings by value' );
$arr = array( array('start' => 443, 'end' => 443), array('start' => 80, 'end' => 80), array('start' => 8080, 'end' => 8080) );
eq( array_column( sortArrayByStartValue($arr), 'start' ), array( 80, 443, 8080 ), 'sortArrayByStartValue: int (ports, IPv4) as before' );

print "  IPv6 substract / dump\n";
$m = minus( 'IP6Map', '2001:db8::/126', array( '2001:db8::1' ) );
eq( $m->dumpToString(), '2001:db8::,2001:db8::2-2001:db8::3', 'split in the middle' );
eq( noFloat($m), TRUE, 'no float after substract' );
eq( minus( 'IP6Map', '2001:db8::/126', array( '2001:db8::' ) )->dumpToString(), '2001:db8::1-2001:db8::3', 'cut the start' );
eq( minus( 'IP6Map', '2001:db8::/126', array( '2001:db8::3' ) )->dumpToString(), '2001:db8::-2001:db8::2', 'cut the end' );
eq( minus( 'IP6Map', '2001:db8::/126', array( '2001:db8::/64' ) )->count(), 0, 'fully removed' );
eq( minus( 'IP6Map', '2001:db8::/126', array( '2001:db8::4' ) )->dumpToString(), '2001:db8::-2001:db8::3', 'no overlap (neighbour)' );
eq( minus( 'IP6Map', '2001:db8::/126', array( '2001:db8::1', '2001:db8::2' ) )->dumpToString(), '2001:db8::,2001:db8::3', 'two neighbouring holes' );

print "  IPv6 includes / included / equals / netMatch\n";
eq( IP6Map::mapFromText('2001:db8::1')->includedInOtherMap( IP6Map::mapFromText('2001:db8::/127') ), 1, '::1 included in ::/127' );
eq( IP6Map::mapFromText('2001:db8::2')->includedInOtherMap( IP6Map::mapFromText('2001:db8::/127') ), 0, '::2 not included in ::/127' );
eq( IP6Map::mapFromText('2001:db8::1-2001:db8::2')->includedInOtherMap( IP6Map::mapFromText('2001:db8::/127') ), 2, '::1-::2 partially included' );
eq( IP6Map::mapFromText('2001:db8::/127')->includesOtherMap( IP6Map::mapFromText('2001:db8::2') ), 0, '::/127 does not include ::2' );
eq( IP6Map::mapFromText('2001:db8::')->equals( IP6Map::mapFromText('2001:db8::1') ), FALSE, 'equals: neighbours differ' );
eq( merged( 'IP6Map', array( '2001:db8::1', '2001:db8::' ) )->equals( IP6Map::mapFromText('2001:db8::/127') ), TRUE, 'equals: same range' );
eq( cidr::netMatch( '2001:db8::1', '2001:db8::/127' ), 1, 'netMatch included' );
eq( cidr::netMatch( '2001:db8::2', '2001:db8::/127' ), 0, 'netMatch neighbour not included' );
eq( cidr::netMatch( '2001:db8::1-2001:db8::2', '2001:db8::/127' ), 2, 'netMatch partial' );

print "  IPv4 unchanged\n";
eq( merged( 'IP4Map', array( '10.0.0.0/24', '10.0.1.0/24', '10.0.3.1' ) )->dumpToString(), '10.0.0.0-10.0.1.255,10.0.3.1', 'IPv4 merge' );
eq( merged( 'IP4Map', array( '10.0.0.0', '10.0.0.2' ) )->dumpToString(), '10.0.0.0,10.0.0.2', 'IPv4 not adjacent' );
eq( merged( 'IP4Map', array( '10.0.0.0', '10.0.0.1' ) )->dumpToString(), '10.0.0.0-10.0.0.1', 'IPv4 adjacent' );
$m = minus( 'IP4Map', '10.0.0.0/30', array( '10.0.0.1' ) );
eq( $m->dumpToString(), '10.0.0.0,10.0.0.2-10.0.0.3', 'IPv4 split - dumpToString after substract (no network key)' );
eq( array_map( function($e){ return array( is_int($e['start']), is_int($e['end']) ); }, $m->getMapArray() ), array( array(TRUE, TRUE), array(TRUE, TRUE) ), 'IPv4 values stay int' );
eq( cidr::netMatch( '10.0.0.1', '10.0.0.0/31' ), 1, 'IPv4 netMatch' );
eq( cidr::netMatch( '10.0.0.2', '10.0.0.0/31' ), 0, 'IPv4 netMatch outside' );
eq( IP4Map::mapFromText('10.0.0.0/24')->includesOtherMap( IP4Map::mapFromText('10.0.0.128/25') ), 1, 'IPv4 includes' );
eq( merged( 'IP4Map', array( '0.0.0.0-255.255.255.255', '10.0.0.1' ) )->dumpToString(), '0.0.0.0-255.255.255.255', 'IPv4 full range' );

print "\n" . $checks . " checks, " . count($failed) . " failed\n";
exit( count($failed) ? 1 : 0 );
