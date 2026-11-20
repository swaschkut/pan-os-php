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
 * ApiObjectModel (todo/json-object-model.md): objects in the shape of the SCM API, with the location fields of
 * Panorama / firewall (device_group, vsys). Tags, addresses, address groups, services, service groups.
 *
 *   php tests/test_api_object_model.php
 */
$here = dirname(__FILE__);
require_once $here . '/../lib/pan_php_framework.php';
PH::processCliArgs();

$failed = array();
$checks = 0;
function eq( $actual, $expected, $msg )
{
    global $failed, $checks;
    $checks++;
    if( $actual !== $expected )
    {
        $failed[] = $msg;
        print "  FAIL " . $msg . "\n      expected " . json_encode( $expected ) . "\n      got      " . json_encode( $actual ) . "\n";
    }
}

$objects = '<tag><entry name="t1"><color>color1</color><comments>c</comments></entry></tag>'
    . '<address><entry name="h1"><ip-netmask>10.0.0.1/32</ip-netmask><description>d</description><tag><member>t1</member></tag></entry>'
    . '<entry name="r1"><ip-range>10.0.0.1-10.0.0.9</ip-range></entry><entry name="f1"><fqdn>a.example.com</fqdn></entry></address>'
    . '<address-group><entry name="g1"><static><member>h1</member><member>r1</member></static></entry>'
    . '<entry name="g2"><dynamic><filter>\'t1\'</filter></dynamic></entry></address-group>'
    . '<service><entry name="s1"><protocol><tcp><port>443</port><source-port>1024-65535</source-port></tcp></protocol></entry></service>'
    . '<service-group><entry name="sg1"><members><member>s1</member></members></entry></service-group>';

// ---- firewall: vsys
$fw = new PANConf();
ob_start();
$fwXml = '<config version="11.1.0"><mgt-config><users/></mgt-config><shared/><devices><entry name="localhost.localdomain"><vsys><entry name="vsys1">'
    . $objects . '</entry></vsys></entry></devices></config>';
$fw->load_from_xmlstring( $fwXml );
ob_end_clean();
$v = $fw->findVirtualSystem( 'vsys1' );
eq( ApiObjectModel::item( $v->tagStore->find( 't1' ) ), array( 'resource' => 'tags', 'item' => array( 'name' => 't1', 'color' => 'Red', 'comments' => 'c', 'vsys' => 'vsys1' ) ), 'tag: SCM color name, vsys' );
eq( ApiObjectModel::item( $v->addressStore->find( 'h1' ) ), array( 'resource' => 'addresses',
    'item' => array( 'name' => 'h1', 'ip_netmask' => '10.0.0.1/32', 'description' => 'd', 'tag' => array( 't1' ), 'vsys' => 'vsys1' ) ), 'address ip_netmask' );
eq( ApiObjectModel::item( $v->addressStore->find( 'r1' ) )['item'], array( 'name' => 'r1', 'ip_range' => '10.0.0.1-10.0.0.9', 'vsys' => 'vsys1' ), 'address ip_range' );
eq( ApiObjectModel::item( $v->addressStore->find( 'f1' ) )['item'], array( 'name' => 'f1', 'fqdn' => 'a.example.com', 'vsys' => 'vsys1' ), 'address fqdn' );
eq( ApiObjectModel::item( $v->addressStore->find( 'g1' ) ), array( 'resource' => 'address-groups', 'item' => array( 'name' => 'g1', 'static' => array( 'h1', 'r1' ), 'vsys' => 'vsys1' ) ), 'static address group' );
eq( ApiObjectModel::item( $v->addressStore->find( 'g2' ) )['item'], array( 'name' => 'g2', 'dynamic' => array( 'filter' => "'t1'" ), 'vsys' => 'vsys1' ), 'dynamic address group' );
eq( ApiObjectModel::item( $v->serviceStore->find( 's1' ) ), array( 'resource' => 'services',
    'item' => array( 'name' => 's1', 'protocol' => array( 'tcp' => array( 'port' => '443', 'source_port' => '1024-65535' ) ), 'vsys' => 'vsys1' ) ), 'service' );
eq( ApiObjectModel::item( $v->serviceStore->find( 'sg1' ) ), array( 'resource' => 'service-groups', 'item' => array( 'name' => 'sg1', 'members' => array( 's1' ), 'vsys' => 'vsys1' ) ), 'service group' );

// ---- Panorama: shared and device group
$pano = new PanoramaConf();
ob_start();
$panoXml = '<config version="11.1.0"><mgt-config><users/></mgt-config><shared>' . $objects . '</shared><devices><entry name="localhost.localdomain">'
    . '<device-group><entry name="DG1"><address><entry name="dg-h"><ip-netmask>10.1.1.1/32</ip-netmask></entry></address></entry></device-group></entry></devices>'
    . '<readonly><devices><entry name="localhost.localdomain"><device-group><entry name="DG1"><id>11</id></entry></device-group></entry></devices></readonly></config>';
$pano->load_from_xmlstring( $panoXml );
ob_end_clean();
eq( ApiObjectModel::item( $pano->addressStore->find( 'h1' ) )['item']['device_group'] ?? null, 'shared', 'Panorama shared: device_group "shared"' );
eq( ApiObjectModel::item( $pano->findDeviceGroup( 'DG1' )->addressStore->find( 'dg-h' ) )['item'], array( 'name' => 'dg-h', 'ip_netmask' => '10.1.1.1/32', 'device_group' => 'DG1' ), 'Panorama device group' );

// ---- no model: other classes, objects without XML
eq( ApiObjectModel::item( $v ), null, 'no model for a class that is not listed' );
eq( ApiObjectModel::item( $v->addressStore->findOrCreate( '192.0.2.99' ) ), null, 'tmp object without XML: no item' );
eq( ApiObjectModel::generic( DH::importXmlStringOrDie( new DOMDocument(), '<x><a-b>1</a-b><l><member>m1</member><member>m2</member></l><e><entry name="n"><v>2</v></entry></e></x>' ) ),
    array( 'a_b' => '1', 'l' => array( 'm1', 'm2' ), 'e' => array( array( 'name' => 'n', 'v' => '2' ) ) ), 'generic conversion of an element without SCM schema' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
