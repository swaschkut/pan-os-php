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
 * Regions: predefined regions (country codes of predefined.xml) are found instead of temporary addresses, custom
 * regions (also geo-location only, also shared of a firewall), type=region and its actions (offline).
 * Synthetic input tests/input/regions.xml.
 *
 *   php tests/test_regions.php
 */
$repo = dirname( __DIR__ );
$in = $repo . '/tests/input/regions.xml';
$tmp = sys_get_temp_dir() . '/regions-' . getmypid();
@mkdir( $tmp, 0700 );

$checks = 0; $failed = array();
$eq = function( $got, $want, $msg ) use ( &$checks, &$failed ) {
    $checks++; $ok = $got === $want;
    print ( $ok ? "ok   " : "FAIL " ) . $msg . ( $ok ? "" : "\n     got:  " . json_encode( $got ) . "\n     want: " . json_encode( $want ) ) . "\n";
    if( !$ok ) $failed[] = $msg;
};

// pan-os-php type=… in=$from out=$to; returns all lines and the lines '* …' / '*** SKIPPED …'
$step = 0;
$run = function( string $type, string $from, string $location, string $filter, string $actions ) use ( $repo, $tmp, &$step ) {
    $to = $tmp . '/' . ( ++$step ) . '.xml';
    $args = array( 'type=' . $type, 'in=' . $from, 'out=' . $to, 'location=' . $location, 'actions=' . $actions );
    if( $filter !== '' )
        $args[] = 'filter=' . $filter;
    exec( escapeshellarg( PHP_BINARY ) . ' ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>&1', $o );
    return array( $to, array_values( array_map( 'trim', preg_grep( '/^\s+\*+ (SKIPPED|[a-z])/', $o ) ) ), $o );
};
$xp = function( string $file, string $q ) {
    $d = new DOMDocument();
    $d->load( $file );
    $out = array();
    foreach( ( new DOMXPath( $d ) )->query( $q ) as $n )
        $out[] = trim( $n->textContent );
    return $out;
};
$objects = function( array $lines ) {
    $out = array();
    foreach( $lines as $l )
        if( preg_match( "/^\s+- object '(?:\e\[1m)?([^'\e]+)/", $l, $m ) )
            $out[] = $m[1];
    return $out;
};
$v = "//devices/entry/vsys/entry[@name='vsys1']";

// ---- library: predefined region instead of a temporary address
require_once $repo . '/lib/pan_php_framework.php';
PH::$shadow_json = FALSE;
$pan = new PANConf();
$pan->load_from_file( $in );
$vsys = $pan->findVirtualSystem( 'vsys1' );
$de = $vsys->addressStore->find( 'DE' );
$eq( array( get_class( $de ), $de->isPredefined(), $de->description(), $de->isTmpAddr() ), array( 'Region', TRUE, 'Germany', FALSE ),
    'predefined region: DE of an address group is the predefined region (country name), not a temporary address' );
$fr = $vsys->addressStore->find( 'FR' );
$eq( array( get_class( $fr ), $fr->countReferences() ), array( 'Region', 1 ), 'predefined region: FR of a rule - one reference' );
$eq( array_keys( $vsys->addressStore->find( 'g-geo' )->getIP4Mapping()->unresolved ), array( 'DE' ),
    'IP map of a group with a country: the country is unresolved (its addresses are only known on the firewall)' );
$res = $vsys->addressStore->find( '10.0.0.0-10.255.255.255' );
$eq( array( $res->isTmpAddr(), $res->getIP4Mapping()->count() ), array( TRUE, 1 ), 'a reserved range of predefined.xml stays an IP value (ip-range)' );
$eq( array( AddressStore::isPredefinedRegionName( 'DE' ), AddressStore::isPredefinedRegionName( '10.0.0.0-10.255.255.255' ), AddressStore::isPredefinedRegionName( 'XX-none' ) ),
    array( TRUE, FALSE, FALSE ), 'predefined region names: country codes only' );
$eq( array( get_class( $vsys->addressStore->find( 'geo-only' ) ), get_class( $pan->addressStore->find( 'shared-region' ) ) ), array( 'Region', 'Region' ),
    'custom regions: a region with only a geo-location, a shared region of a firewall (/config/shared/region)' );
$hq = $vsys->addressStore->find( 'hq-region' );
$eq( array( $hq->getIP4Mapping()->count(), count( $hq->getIP4Mapping()->unresolved ) ), array( 2, 0 ), 'custom region: IPv4 map of its addresses' );

// ---- type=region: lists
list( , , $o ) = $run( 'region', $in, 'any', '(object is.custom) or (refcount > 0)', 'display' );
$eq( $objects( $o ), array( 'DE', 'FR', 'shared-region', 'hq-region', 'geo-only' ), 'type=region location=any: used predefined regions, shared and vsys regions' );
list( , , $o ) = $run( 'region', $in, 'predefined', '', 'display' );
$eq( count( $objects( $o ) ), count( AddressStore::predefinedRegionNames() ), 'type=region location=predefined: every predefined region' );
list( , , $o ) = $run( 'address', $in, 'vsys1', '!(object is.region)', 'display' );
$eq( $objects( $o ), array( '10.0.0.0-10.255.255.255', 'h-1', 'g-geo' ), 'type=address: DE / FR are no temporary addresses any more' );

// ---- actions
list( $f, $l ) = $run( 'region', $in, 'vsys1', '(name eq hq-region)',
    'address-add:2001$$colon$$db8$$colon$$$$colon$$$$forwardslash$$32/address-remove:192.0.2.0$$forwardslash$$24/geo-location-set:52.52,13.40/name-rename:main-region' );
$eq( array( $xp( $f, "$v/region/entry[@name='main-region']/address/member" ), $xp( $f, "$v/region/entry[@name='main-region']/geo-location/latitude" ),
    $xp( $f, "$v/region/entry[@name='main-region']/geo-location/longitude" ), $xp( $f, "$v/rulebase/security/rules/entry[@name='r-country']/destination/member" ),
    $xp( $f, "$v/address-group/entry[@name='g-geo']/static/member" ) ),
    array( array( '198.51.100.1-198.51.100.20', '2001:db8::/32' ), array( '52.52' ), array( '13.40' ), array( 'main-region' ), array( 'DE', 'main-region', 'h-1' ) ),
    'custom region: address-add (IPv6, aliases), address-remove, geo-location-set, name-rename (rule and group updated)' );
list( , $l ) = $run( 'region', $f, 'vsys1', '(name eq main-region)', 'address-add:300.1.1.1/address-add:2001$$colon$$db8$$colon$$$$colon$$$$forwardslash$$32/address-remove:192.0.2.99' .
    '/geo-location-set:95,1/name-rename:DE/name-rename:10.1.1.1/name-rename:geo-only/delete' );
$eq( array_values( preg_grep( '/SKIPPED/', $l ) ), array(
    "*** SKIPPED : '300.1.1.1' is no ip-netmask / ip-range (IPv4 or IPv6)",
    "*** SKIPPED : '2001:db8::/32' is a member already",
    "*** SKIPPED : '192.0.2.99' is no member",
    "*** SKIPPED : latitude '95' is outside -90 .. 90",
    "*** SKIPPED : 'DE' is a predefined region (country code)",
    "*** SKIPPED : '10.1.1.1' is an IP value",
    "*** SKIPPED : 'geo-only' exists already",
    "*** SKIPPED : this region is used by other objects and cannot be deleted (remove it from the rules / groups first)" ),
    'custom region: invalid values refused, a used region is not deleted' );
list( $f, $l ) = $run( 'region', $in, 'vsys1', '(name eq geo-only)', 'geo-location-remove/delete' );
$eq( $xp( $f, "$v/region/entry/@name" ), array( 'hq-region' ), 'custom region: geo-location-remove, delete of an unused region' );
list( , $l ) = $run( 'region', $in, 'predefined', '(name eq DE)', 'address-add:192.0.2.1/name-rename:XX/delete' );
$eq( array_values( preg_grep( '/SKIPPED/', $l ) ), array_fill( 0, 3, "*** SKIPPED : read-only object: predefined" ), 'predefined region: read only' );
list( $f, ) = $run( 'region', $in, 'shared', '(name eq shared-region)', 'address-add:203.0.114.1' );
$eq( $xp( $f, "/config/shared/region/entry[@name='shared-region']/address/member" ), array( '203.0.113.0/24', '203.0.114.1' ), 'shared region of a firewall: changed in /config/shared' );

// ---- a region in a rule: added / removed like an address (the rule container takes Address, AddressGroup, EDL and Region)
$r = "$v/rulebase/security/rules/entry[@name='r-country']";
list( $f, $l ) = $run( 'rule', $in, 'vsys1', '(name eq r-country)', 'src-add:DE/dst-add:geo-only' );
$eq( array( $xp( $f, "$r/source/member" ), $xp( $f, "$r/destination/member" ) ), array( array( 'FR', 'DE' ), array( 'hq-region', 'geo-only' ) ),
    'rule: src-add of a predefined region (country code), dst-add of a custom region' );
list( $f, $l ) = $run( 'rule', $in, 'vsys1', '(name eq r-country)', 'src-remove-force-any:FR/dst-remove-force-any:hq-region' );
$eq( array( $xp( $f, "$r/source/member" ), $xp( $f, "$r/destination/member" ) ), array( array( 'any' ), array( 'any' ) ), 'rule: region removed from source / destination' );

// the way the SCM import fills a rule: findOrCreate() of the name, then addObject()
require_once $repo . '/lib/pan_php_framework.php';
$pan = new PANConf();
$pan->load_from_domxml( $doc = ( function() use ( $in ) { $d = new DOMDocument(); $d->load( $in ); return $d; } )() );
$vsys = $pan->findVirtualSystem( 'vsys1' );
$rule = $vsys->securityRules->find( 'r-country' );
$found = array();
foreach( array( 'DE', 'geo-only', 'h-1' ) as $name )
{
    $object = $vsys->addressStore->findOrCreate( $name, null, TRUE );
    $found[] = get_class( $object );
    $rule->source->addObject( $object );
}
$names = array();
foreach( $rule->source->members() as $member )
    $names[] = $member->name();
$eq( array( $found, $names, $rule->source->hasObjectRecursive( $vsys->addressStore->find( 'DE' ) ) ),
    array( array( 'Region', 'Region', 'Address' ), array( 'FR', 'DE', 'geo-only', 'h-1' ), TRUE ),
    'findOrCreate + addObject: regions and an address in the source of a rule' );

// ---- filters
list( , , $o ) = $run( 'region', $in, 'any', '(geo-location is.set)', 'display' );
$eq( $objects( $o ), array( 'hq-region', 'geo-only' ), 'filter geo-location is.set' );
list( , , $o ) = $run( 'region', $in, 'any', '(address has 192.0.2.0/24) or (address is.empty)', 'display' );
$eq( $objects( $o ), array( 'hq-region', 'geo-only' ), 'filter address has / address is.empty' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
