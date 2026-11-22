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
 * Panorama / firewall (device_group, vsys). Tags, addresses, address groups, services, service groups, schedules,
 * custom URL categories, external dynamic lists, log forwarding profiles.
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
    . '<service-group><entry name="sg1"><members><member>s1</member></members></entry></service-group>'
    . '<schedule><entry name="sch1"><schedule-type><recurring><daily><member>08:00-18:00</member></daily></recurring></schedule-type></entry>'
    . '<entry name="sch2"><schedule-type><non-recurring><member>2026/01/01@00:00-2026/01/02@00:00</member></non-recurring></schedule-type></entry></schedule>'
    . '<external-list><entry name="edl1"><type><ip><recurring><hourly/></recurring><url>https://example.com/l.txt</url><certificate-profile>cp</certificate-profile></ip></type></entry></external-list>'
    . '<log-settings><profiles><entry name="lfp1"><match-list><entry name="traffic"><log-type>traffic</log-type><filter>All Logs</filter>'
    . '<send-to-panorama>yes</send-to-panorama><send-syslog><member>sys1</member></send-syslog></entry></match-list></entry></profiles></log-settings>'
    . '<profiles><custom-url-category><entry name="cat1"><list><member>example.com/</member></list><type>URL List</type><description>x</description></entry>'
    . '<entry name="cat2"><list><member>a.com</member></list></entry></custom-url-category>'
    . '<spyware><entry name="as1"><rules><entry name="r1"><action><default/></action><severity><member>any</member></severity><threat-name>any</threat-name>'
    . '<category>any</category><packet-capture>disable</packet-capture></entry><entry name="r2"><action><reset-both/></action><severity><member>high</member></severity>'
    . '<threat-name>any</threat-name><category>any</category><packet-capture>single-packet</packet-capture></entry></rules></entry></spyware>'
    . '<virus><entry name="av1"><decoder><entry name="http"><action>default</action><wildfire-action>reset-both</wildfire-action></entry></decoder></entry></virus>'
    . '<wildfire-analysis><entry name="wf1"><rules><entry name="all"><application><member>any</member></application><file-type><member>any</member></file-type>'
    . '<direction>both</direction><analysis>public-cloud</analysis></entry></rules></entry></wildfire-analysis></profiles>'
    . '<profile-group><entry name="pg1"><spyware><member>as1</member></spyware><virus><member>av1</member></virus><wildfire-analysis><member>wf1</member></wildfire-analysis></entry></profile-group>'
    . '<zone><entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>'
    . '<rulebase><security><rules>'
    . '<entry name="r-first" uuid="11111111-1111-1111-1111-111111111111"><from><member>trust</member></from><to><member>any</member></to><source><member>h1</member></source>'
    . '<destination><member>any</member></destination><source-user><member>any</member></source-user><category><member>any</member></category>'
    . '<application><member>any</member></application><service><member>s1</member></service><action>allow</action><rule-type>intrazone</rule-type>'
    . '<profile-setting><group><member>pg1</member></group></profile-setting><log-end>yes</log-end><disabled>yes</disabled><negate-source>yes</negate-source></entry>'
    . '<entry name="r-second" uuid="22222222-2222-2222-2222-222222222222"><from><member>any</member></from><to><member>any</member></to><source><member>any</member></source>'
    . '<destination><member>any</member></destination><application><member>any</member></application><service><member>any</member></service><action>deny</action></entry>'
    . '</rules></security><nat><rules><entry name="n1"><from><member>trust</member></from><to><member>trust</member></to><source><member>any</member></source>'
    . '<destination><member>any</member></destination><service>any</service></entry></rules></nat></rulebase>';

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

// ---- schedules, url-categories, external-dynamic-lists, log-forwarding-profiles
eq( ApiObjectModel::item( $v->scheduleStore->find( 'sch1' ) ), array( 'resource' => 'schedules',
    'item' => array( 'name' => 'sch1', 'schedule_type' => array( 'recurring' => array( 'daily' => array( '08:00-18:00' ) ) ), 'vsys' => 'vsys1' ) ), 'schedule recurring' );
eq( ApiObjectModel::item( $v->scheduleStore->find( 'sch2' ) )['item']['schedule_type'], array( 'non_recurring' => array( '2026/01/01@00:00-2026/01/02@00:00' ) ), 'schedule non-recurring' );
eq( ApiObjectModel::item( $v->EDLStore->find( 'edl1' ) )['item']['type']['ip']['url'] ?? null, 'https://example.com/l.txt', 'external dynamic list' );
eq( ApiObjectModel::item( $v->EDLStore->find( 'edl1' ) )['resource'], 'external-dynamic-lists', 'external dynamic list resource' );
eq( ApiObjectModel::item( $v->customURLProfileStore->find( 'cat1' ) ), array( 'resource' => 'url-categories',
    'item' => array( 'name' => 'cat1', 'list' => array( 'example.com/' ), 'type' => 'URL List', 'description' => 'x', 'vsys' => 'vsys1' ) ), 'custom URL category' );
eq( ApiObjectModel::item( $v->customURLProfileStore->find( 'cat2' ) )['item']['type'] ?? null, 'URL List', 'custom URL category without type: URL List as in SCM' );
$lfp = ApiObjectModel::item( $v->LogProfileStore->find( 'lfp1' ) );
eq( array( $lfp['resource'], $lfp['item']['match_list'][0]['log_type'] ?? null, $lfp['item']['match_list'][0]['send_syslog'] ?? null ),
    array( 'log-forwarding-profiles', 'traffic', array( 'sys1' ) ), 'log forwarding profile' );
eq( array( $lfp['item']['match_list'][0]['send_to_panorama'] ?? null, isset( $lfp['item']['_panosphp'] ) ), array( 'yes', FALSE ),
    'a PAN-OS field the SCM schema does not know (send-to-panorama) stays at its place, nothing in not_converted' );

// ---- security profiles, profile groups, zones
$as = ApiObjectModel::item( $v->AntiSpywareProfileStore->find( 'as1' ) );
eq( array( $as['resource'], json_encode( $as['item']['rules'][0]['action'] ), json_encode( $as['item']['rules'][1]['action'] ), $as['item']['rules'][1]['packet_capture'] ),
    array( 'anti-spyware-profiles', '{"default":{}}', '{"reset_both":{}}', 'single-packet' ), 'anti-spyware profile: rule actions, also the one the SCM schema does not know (default)' );
// DNS security: Panorama / firewall have it inside the anti-spyware profile (botnet-domains), SCM in its own dns-security-profiles
eq( array( isset( $as['item']['botnet_domains']['dns_security_categories'] ), isset( $as['item']['botnet_domains']['lists'] ), isset( $as['item']['_panosphp'] ) ),
    array( TRUE, TRUE, FALSE ), 'anti-spyware profile of a firewall: DNS security stays inside (botnet_domains), nothing dropped' );
$av = ApiObjectModel::item( $v->AntiVirusProfileStore->find( 'av1' ) );
eq( array( $av['resource'], $av['item']['decoder'][0]['name'] ?? null, $av['item']['decoder'][0]['wildfire_action'] ?? null, $av['item']['vsys'] ?? null ),
    array( 'antivirus-profiles', 'http', 'reset-both', 'vsys1' ), 'antivirus profile: own resource (Panorama / firewall)' );
$wf = ApiObjectModel::item( $v->WildfireProfileStore->find( 'wf1' ) );
eq( array( $wf['resource'], $wf['item']['rules'][0]['analysis'] ?? null ), array( 'wildfire-analysis-profiles', 'public-cloud' ), 'WildFire analysis profile: own resource' );
eq( ApiObjectModel::item( $v->securityProfileGroupStore->find( 'pg1' ) ), array( 'resource' => 'profile-groups',
    'item' => array( 'name' => 'pg1', 'spyware' => array( 'as1' ), 'virus' => array( 'av1' ), 'wildfire_analysis' => array( 'wf1' ), 'vsys' => 'vsys1' ) ),
    'profile group: SCM fields + own fields virus / wildfire_analysis' );
eq( ApiObjectModel::item( $v->zoneStore->find( 'trust' ) ), array( 'resource' => 'zones',
    'item' => array( 'name' => 'trust', 'network' => array( 'layer3' => array( 'ethernet1/1' ) ), 'vsys' => 'vsys1' ) ), 'zone' );

// ---- rules
$r1 = ApiObjectModel::item( $v->securityRules->find( 'r-first' ) );
eq( $r1['resource'], 'security-rules', 'security rule resource' );
eq( array( $r1['item']['from'], $r1['item']['source'], $r1['item']['service'], $r1['item']['action'], $r1['item']['profile_setting'] ?? null ),
    array( array( 'trust' ), array( 'h1' ), array( 's1' ), 'allow', array( 'group' => array( 'pg1' ) ) ), 'security rule: SCM fields' );
eq( array( $r1['item']['disabled'] ?? null, $r1['item']['negate_source'] ?? null, $r1['item']['log_end'] ?? null ), array( TRUE, TRUE, TRUE ), 'security rule: booleans' );
eq( array( $r1['item']['uuid'] ?? null, $r1['item']['rulebase'] ?? null, $r1['item']['position'] ?? null, $r1['item']['rule_type'] ?? null, $r1['item']['vsys'] ?? null ),
    array( '11111111-1111-1111-1111-111111111111', 'local', 1, 'intrazone', 'vsys1' ), 'security rule: own fields uuid, rulebase, position, rule_type; location' );
eq( ApiObjectModel::item( $v->securityRules->find( 'r-second' ) )['item']['position'] ?? null, 2, 'second rule: position 2' );
$n1 = ApiObjectModel::item( $v->natRules->find( 'n1' ) );
eq( array( $n1['resource'], $n1['item']['rulebase'] ?? null, $n1['item']['position'] ?? null ), array( 'nat-rules', 'local', 1 ), 'NAT rule' );

// ---- computed values (_panosphp): only when asked
ApiObjectModel::$withComputed = TRUE;
$c = ApiObjectModel::item( $v->addressStore->find( 'h1' ) )['item']['_panosphp'] ?? null;
eq( array( $c['ip_count'] ?? null, ( $c['references'] ?? 0 ) >= 2 ), array( 1, TRUE ), 'computed: address ip_count, references (group g1, rule r-first)' );
$c = ApiObjectModel::item( $v->AntiSpywareProfileStore->find( 'as1' ) )['item']['_panosphp'] ?? array();
eq( array( array_key_exists( 'visibility', $c ), array_key_exists( 'best_practice', $c ), array_keys( $c['checks'] ?? array() ) ),
    array( TRUE, TRUE, array( 'rules', 'inline', 'dns_lists', 'dns_security', 'advanced_dns_security' ) ), 'computed: anti-spyware profile verdicts and single checks' );
eq( array( is_bool( $c['checks']['rules']['visibility'] ) || $c['checks']['rules']['visibility'] === null, $c['best_practice'] ), array( TRUE, FALSE ),
    'computed: verdicts are true / false / null; this profile is not best practice' );
$c = ApiObjectModel::item( $v->securityProfileGroupStore->find( 'pg1' ) )['item']['_panosphp'] ?? array();
eq( array( array_key_exists( 'visibility', $c ), $c['references'] ?? null ), array( TRUE, 1 ), 'computed: profile group verdict, referenced by one rule' );
$c = ApiObjectModel::item( $v->securityRules->find( 'r-first' ) )['item']['_panosphp'] ?? array();
eq( array( array_key_exists( 'profiles_visibility', $c ), array_key_exists( 'profiles_best_practice', $c ) ), array( TRUE, TRUE ), 'computed: security rule - verdict of its profiles' );
ApiObjectModel::$withComputed = FALSE;
eq( isset( ApiObjectModel::item( $v->addressStore->find( 'h1' ) )['item']['_panosphp'] ), FALSE, 'computed: off by default - plain SCM shape' );

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
eq( json_encode( ApiObjectModel::generic( DH::importXmlStringOrDie( new DOMDocument(), '<x><a-b>1</a-b><l><member>m1</member><member>m2</member></l><e><entry name="n"><v>2</v></entry></e><c><yes/></c></x>' ) ) ),
    '{"a_b":"1","l":["m1","m2"],"e":[{"name":"n","v":"2"}],"c":{"yes":{}}}', 'generic conversion of an element without SCM schema' );

print "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
exit( count( $failed ) ? 1 : 0 );
