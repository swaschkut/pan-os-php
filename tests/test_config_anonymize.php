<?php
/**
 * ISC License
 *
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
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

/*
 * type=config-anonymize: php tests/test_config_anonymize.php
 */

$here = dirname(__FILE__);
require_once $here . '/../lib/pan_php_framework.php';
require_once $here . '/../utils/common/ConfigSecrets.php';
require_once $here . '/../utils/common/ConfigAnonymizer.php';

$cli = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($here . '/../utils/pan-os-php.php');
$work = sys_get_temp_dir() . '/pan-os-php-test-config-anonymize-' . getmypid();
@mkdir( $work, 0700, TRUE );

$failed = array();
$checks = 0;
function check( $cond, $msg )
{
    global $failed, $checks;
    $checks++;
    if( !$cond )
        $failed[] = $msg;
}
function run( $args )
{
    global $cli;
    exec( $cli . ' ' . $args . ' 2>&1', $out, $rc );
    return array( $rc, implode( "\n", $out ) );
}

$crypto = new PanosCrypto();
$enc = $crypto->encrypt( 'TopSecretPsk', null );
$xml = <<<XML
<config version="11.2.0" urldb="paloaltonetworks">
  <mgt-config><users><entry name="jdoe"><phash>\$5\$abcdefgh\$Kq0p1rT8fN3oPzW2mRx7c4Y6vB9sD1eF5gH8jL0kM2n</phash></entry></users></mgt-config>
  <shared>
    <address>
      <entry name="AcmeWebServer"><ip-netmask>203.0.113.10/32</ip-netmask><description>Web server of ACME Corp, room 4711</description><tag><member>AcmeTag</member></tag></entry>
      <entry name="AcmeNet"><ip-netmask>203.0.113.0/24</ip-netmask></entry>
      <entry name="AcmeLan"><ip-netmask>10.20.30.0/24</ip-netmask></entry>
      <entry name="AcmePortal"><fqdn>portal.acme-corp.de</fqdn></entry>
    </address>
    <address-group><entry name="AcmeServers"><static><member>AcmeWebServer</member><member>AcmePortal</member></static></entry></address-group>
    <tag><entry name="AcmeTag"><color>color1</color></entry></tag>
    <external-list><entry name="AcmeEDL"><type><ip><url>https://lists.acme-corp.de/block.txt</url></ip></type></entry></external-list>
  </shared>
  <devices><entry name="localhost.localdomain">
    <deviceconfig><system><hostname>fw-acme-berlin-01</hostname><domain>acme-corp.de</domain><timezone>Europe/Berlin</timezone>
      <login-banner>Property of ACME Corp - unauthorized access prohibited</login-banner></system></deviceconfig>
    <network><ike><gateway><entry name="AcmeVPN"><authentication><pre-shared-key><key>$enc</key></pre-shared-key></authentication></entry></gateway></ike></network>
    <vsys><entry name="vsys1"><display-name>ACME Main</display-name>
      <zone><entry name="AcmeDMZ"><network><layer3><member>ethernet1/1</member></layer3></network></entry></zone>
      <rulebase><security><rules>
        <entry name="Allow Acme Web"><from><member>any</member></from><to><member>AcmeDMZ</member></to>
          <source><member>AcmeLan</member></source><destination><member>AcmeServers</member></destination>
          <source-user><member>acme\\jdoe</member></source-user>
          <application><member>web-browsing</member></application><service><member>application-default</member></service>
          <action>allow</action><description>requested by john.doe@acme-corp.de</description></entry>
      </rules></security></rulebase>
    </entry></vsys>
  </entry></devices>
</config>
XML;
$in = $work . '/in.xml';
file_put_contents( $in, $xml );
$md5in = md5_file( $in );

// ---- run
list( $rc, $t ) = run( 'type=config-anonymize in=' . escapeshellarg($in) . ' out=' . escapeshellarg($work . '/out.xml') . ' salt=test' );
check( $rc == 0, 'run ok: ' . $t );
check( is_file($work . '/out.xml'), 'output written' );
$out = (string)@file_get_contents( $work . '/out.xml' );

// ---- nothing customer specific left
foreach( array( 'Acme', 'acme', 'ACME', '203.0.113.10', '10.20.30.0', 'portal', 'room 4711', 'jdoe', 'john.doe',
             'Berlin', 'TopSecretPsk', 'Kq0p1rT8', $enc, 'unauthorized' ) as $leak )
    check( stripos( $out, $leak ) === FALSE, 'no "' . $leak . '" in the output' );

// ---- logic kept
$d = new DOMDocument();
check( @$d->loadXML( $out ), 'output is valid XML' );
$x = new DOMXPath( $d );
$addr = array();
foreach( $x->query('/config/shared/address/entry') as $e )
    $addr[] = $e->getAttribute('name');
check( count($addr) == 4, 'four address objects' );
$members = array();
foreach( $x->query('/config/shared/address-group/entry/static/member') as $m )
    $members[] = $m->textContent;
check( count( array_intersect( $members, $addr ) ) == 2, 'group members still reference the renamed addresses' );
$tagRef = $x->query('/config/shared/address/entry/tag/member')->item(0)->textContent;
check( $x->query('/config/shared/tag/entry[@name="' . $tagRef . '"]')->length == 1, 'tag reference kept' );
$zoneRef = $x->query('//rules/entry/to/member')->item(0)->textContent;
check( $x->query('//zone/entry[@name="' . $zoneRef . '"]')->length == 1, 'zone reference kept' );
check( $x->query('//rules/entry/application/member')->item(0)->textContent === 'web-browsing', 'predefined application kept' );
check( $x->query('//rules/entry/service/member')->item(0)->textContent === 'application-default', 'application-default kept' );
check( $x->query('//zone/entry/network/layer3/member')->item(0)->textContent === 'ethernet1/1', 'interface name kept' );
check( $x->query('//vsys/entry')->item(0)->getAttribute('name') === 'vsys1', 'vsys1 kept' );

// IP: prefix kept (host in network), netmask kept, private stays private
$ips = array();
foreach( $x->query('/config/shared/address/entry/ip-netmask') as $e )
    $ips[] = $e->textContent;
list( $hostIp, $hostMask ) = explode( '/', $ips[0] );
list( $netIp, $netMask ) = explode( '/', $ips[1] );
check( $hostMask === '32' && $netMask === '24', 'netmasks kept' );
check( substr( $netIp, -2 ) === '.0', 'network address stays a network address' );
check( implode( '.', array_slice( explode( '.', $hostIp ), 0, 3 ) ) === implode( '.', array_slice( explode( '.', $netIp ), 0, 3 ) ), 'host stays inside its /24' );
check( strpos( $ips[2], '10.' ) === 0, 'private address stays in 10/8' );

// secrets / hashes replaced, still in PAN-OS format
$psk = $x->query('//pre-shared-key/key')->item(0)->textContent;
check( $crypto->decrypt( $psk, null ) === ConfigAnonymizer::PLACEHOLDER_SECRET, 'PSK replaced by the encrypted placeholder' );
check( strpos( $x->query('//phash')->item(0)->textContent, '$5$' ) === 0, 'phash replaced by a hash' );
check( substr( $x->query('//fqdn')->item(0)->textContent, -8 ) === '.example', 'FQDN under .example' );
check( $x->query('//timezone')->item(0)->textContent === 'UTC', 'timezone UTC' );

// ---- same salt -> same pseudonyms, other salt -> other pseudonyms
run( 'type=config-anonymize in=' . escapeshellarg($in) . ' out=' . escapeshellarg($work . '/out2.xml') . ' salt=test' );
check( md5_file($work . '/out.xml') === md5_file($work . '/out2.xml'), 'same salt: same output' );
run( 'type=config-anonymize in=' . escapeshellarg($in) . ' out=' . escapeshellarg($work . '/out3.xml') . ' salt=other' );
check( md5_file($work . '/out.xml') !== md5_file($work . '/out3.xml'), 'other salt: other output' );

// ---- leak scan
$a = new ConfigAnonymizer( 'x' );
$a->name( 'SecretCorp-Net', 'address' );
check( $a->leakScan( '<a><member>SecretCorp-Net</member></a>' ) === array( 'SecretCorp-Net' ), 'leak scan finds an original name' );
check( $a->leakScan( '<a><member>addr-000000</member></a>' ) === array(), 'leak scan: pseudonyms are no leak' );

check( md5_file($in) === $md5in, 'input file unchanged' );

exec( 'rm -rf ' . escapeshellarg($work) );
print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
