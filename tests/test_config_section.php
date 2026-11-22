<?php
/**
 * Tests of pan-os-php type=config-section (utils/lib/CONFIG_SECTION__.php, utils/common/ConfigSection.php).
 *
 *   cd tests && php test_config_section.php
 *
 * Input: input/panorama-move/panorama-move-A.xml, extended at runtime with Panorama settings: deployment-update-schedule
 * in the structure of a real Panorama configuration (Device Deployment > Dynamic Updates > Schedules, serials replaced by
 * the fixture serials), config-bundle-export-schedule with example elements (the type works on any structure).
 * Exit code 0 = all passed.
 */

$here = dirname(__FILE__);
$cli = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($here . '/../utils/pan-os-php.php') . ' type=config-section';
$work = sys_get_temp_dir() . '/pan-os-php-test-config-section-' . getmypid();
@mkdir( $work, 0700, TRUE );

$failed = array();
$checks = 0;
$current = '';

function check( $cond, $msg )
{
    global $failed, $checks, $current;
    $checks++;
    if( !$cond )
        $failed[] = $current . ': ' . $msg;
}

function eq( $actual, $expected, $msg )
{
    check( $actual === $expected, $msg . ' (expected ' . json_encode($expected) . ', got ' . json_encode($actual) . ')' );
}

/** runs the type, returns array( exit code, output, JSON (shadow-json) or null ) */
function cs( array $args, $json = FALSE )
{
    global $cli;
    $cmd = $cli;
    foreach( $args as $a ) $cmd .= ' ' . escapeshellarg($a);
    if( $json ) $cmd .= ' shadow-json';
    exec( $cmd . ' 2>&1', $out, $rc );
    $text = implode( "\n", $out );
    $j = null;
    if( $json )
    {
        $p = strpos( $text, '{' );
        $j = $p === FALSE ? null : json_decode( substr($text, $p), TRUE );
    }
    return array( $rc, $text, $j );
}

function xp( $file )
{
    $d = new DOMDocument();
    if( !@$d->load($file) ) return null;
    return new DOMXPath( $d );
}

// input: panorama-move-A.xml + Panorama settings
$d = new DOMDocument();
$d->load( $here . '/input/panorama-move/panorama-move-A.xml' );
$x = new DOMXPath( $d );
$system = $x->query("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system")->item(0);
$f = new DOMDocument();
$f->loadXML( '<root>'
    . '<deployment-update-schedule>'
    . '<entry name="AppAndThreats"><app-and-threat><recurring><threshold>24</threshold><daily><action><download-and-install>'
    . '<devices><member>007100000290</member><member>000000000101</member></devices>'
    . '</download-and-install></action><at>03:00</at></daily></recurring></app-and-threat>'
    . '<download-source><update-server/></download-source><disabled>no</disabled></entry>'
    . '<entry name="WF"><wildfire><recurring><every-min><action><download-and-install>'
    . '<devices><member>000000000555</member></devices>'
    . '</download-and-install></action></every-min></recurring></wildfire>'
    . '<download-source><update-server/></download-source><disabled>no</disabled></entry>'
    . '</deployment-update-schedule>'
    . '<config-bundle-export-schedule><entry name="export1"><protocol><scp><hostname>192.0.2.3</hostname><username>backup</username>'
    . '<password>-AQ==FIXTUREbundleCCCCCCCCCCCCCCCCCCCCCCCC=</password></scp></protocol><start-time>02:00</start-time><enable>yes</enable></entry>'
    . '</config-bundle-export-schedule></root>' );
foreach( $f->documentElement->childNodes as $c )
    $system->appendChild( $d->importNode($c, TRUE) );
$in = $work . '/panorama.xml';
$d->save( $in );

$fw = $work . '/firewall.xml';
file_put_contents( $fw, '<?xml version="1.0"?><config version="11.0.0"><mgt-config/><shared/><devices><entry name="localhost.localdomain">'
    . '<deviceconfig><system><hostname>fw1</hostname><permitted-ip><entry name="192.0.2.0/24"/></permitted-ip></system></deviceconfig>'
    . '<vsys><entry name="vsys1"/></vsys></entry></devices></config>' );

$scenarios = array();

$scenarios['list-and-display'] = function() use ( $in ) {
    list( $rc, $t ) = cs( array( 'section=list' ) );
    eq( $rc, 0, 'section=list exit code' );
    check( strpos($t, 'deployment-update-schedule') !== FALSE && strpos($t, 'permitted-ip') !== FALSE, 'section=list shows the registry' );

    list( $rc, $t, $j ) = cs( array( 'in=' . $in, 'section=deployment-update-schedule' ), TRUE );
    eq( $rc, 0, 'display exit code' );
    $e = $j !== null && isset($j['deployment-update-schedule']) ? $j['deployment-update-schedule'] : array();
    eq( count($e), 2, 'two entries' );
    eq( $e[0]['name'], 'AppAndThreats', 'first entry' );
    eq( $e[0]['fields']['app-and-threat.recurring.daily.action.download-and-install.devices'], '007100000290, 000000000101', 'member list flattened' );
    eq( $e[0]['fields']['app-and-threat.recurring.daily.at'], '03:00', 'nested field' );
    eq( $e[0]['fields']['download-source.update-server'], '(set)', 'empty element' );
    $refs = array_map( function( $r ) { return $r['kind'] . ' ' . $r['name']; }, $e[0]['references'] );
    sort( $refs );
    eq( $refs, array( 'firewall 000000000101', 'firewall 007100000290' ), 'references (managed firewalls)' );

    list( $rc, $t ) = cs( array( 'in=' . $in, 'section=config-bundle-export-schedule' ) );
    check( strpos($t, 'FIXTUREbundle') === FALSE, 'encrypted value never displayed' );
    check( strpos($t, '*** encrypted ***') !== FALSE, 'encrypted value masked' );
};

$scenarios['get'] = function() use ( $in ) {
    list( $rc, $t ) = cs( array( 'in=' . $in, 'section=config-bundle-export-schedule', 'actions=get:set' ) );
    check( strpos($t, 'set deviceconfig system config-bundle-export-schedule export1 protocol scp hostname 192.0.2.3') !== FALSE, 'set command' );
    check( strpos($t, 'protocol scp password <encrypted>') !== FALSE && strpos($t, 'FIXTUREbundle') === FALSE, 'set command without secret' );
    list( $rc, $t ) = cs( array( 'in=' . $in, 'section=deployment-update-schedule', 'entry=AppAndThreats', 'actions=get:set' ) );
    $p = 'set deviceconfig system deployment-update-schedule AppAndThreats app-and-threat recurring ';
    check( strpos($t, $p . 'threshold 24') !== FALSE, 'set command value' );
    check( strpos($t, $p . 'daily action download-and-install devices [ 007100000290 000000000101 ]') !== FALSE, 'set command member list' );
    check( strpos($t, $p . 'daily at 03:00') !== FALSE, 'set command nested value' );
    check( strpos($t, 'set deviceconfig system deployment-update-schedule AppAndThreats download-source update-server') !== FALSE, 'set command empty element' );
    list( $rc, $t ) = cs( array( 'in=' . $in, 'section=deployment-update-schedule', 'entry=AppAndThreats', 'actions=get:xml' ) );
    check( strpos($t, '<entry name="AppAndThreats">') !== FALSE, 'get:xml' );
};

$scenarios['change-offline'] = function() use ( $in, $work ) {
    $out = $work . '/changed.xml';
    $dev = 'app-and-threat.recurring.daily.action.download-and-install.devices';
    list( $rc ) = cs( array( 'in=' . $in, 'out=' . $out, 'section=deployment-update-schedule', 'entry=AppAndThreats',
        'actions=remove-member:' . $dev . ',007100000290/set:app-and-threat.recurring.daily.at,04:00/add-member:' . $dev . ',000000000555/set:disabled,yes' ) );
    eq( $rc, 0, 'change exit code' );
    $x = xp( $out );
    $base = "/config/devices/entry/deviceconfig/system/deployment-update-schedule/entry[@name='AppAndThreats']";
    $devs = $base . '/app-and-threat/recurring/daily/action/download-and-install/devices';
    eq( $x->query($devs . "/member[.='007100000290']")->length, 0, 'member removed' );
    eq( $x->query($devs . "/member[.='000000000555']")->length, 1, 'member added' );
    eq( trim($x->query($base . '/app-and-threat/recurring/daily/at')->item(0)->textContent), '04:00', 'value set' );
    eq( trim($x->query($base . '/disabled')->item(0)->textContent), 'yes', 'disabled set' );

    $out2 = $work . '/changed2.xml';
    cs( array( 'in=' . $out, 'out=' . $out2, 'section=deployment-update-schedule', 'entry=WF', 'actions=delete' ) );
    $x = xp( $out2 );
    eq( $x->query("/config/devices/entry/deviceconfig/system/deployment-update-schedule/entry[@name='WF']")->length, 0, 'entry deleted' );
    eq( $x->query("/config/devices/entry/deviceconfig/system/deployment-update-schedule/entry[@name='AppAndThreats']")->length, 1, 'other entry kept' );

    $out3 = $work . '/changed3.xml';
    cs( array( 'in=' . $in, 'out=' . $out3, 'section=deployment-update-schedule', 'entry=AV', 'actions=set:anti-virus.recurring.threshold,48' ) );
    $x = xp( $out3 );
    eq( trim($x->query("//deployment-update-schedule/entry[@name='AV']/anti-virus/recurring/threshold")->item(0)->textContent), '48', 'set on a missing entry creates it' );

    list( $rc, $t ) = cs( array( 'in=' . $in, 'section=deployment-update-schedule', 'actions=delete' ) );
    check( $rc != 0 && strpos($t, 'out=') !== FALSE, 'change without out= refused' );
};

$scenarios['html'] = function() use ( $in, $work ) {
    $html = $work . '/dus.html';
    // a '/' inside an action argument is written as '//'
    cs( array( 'in=' . $in, 'section=deployment-update-schedule', 'actions=exportToHtml:' . str_replace('/', '//', $html) ) );
    $h = @file_get_contents( $html );
    check( $h !== FALSE && strpos($h, 'AppAndThreats') !== FALSE && strpos($h, 'app-and-threat.recurring.daily.at') !== FALSE, 'HTML export with field columns' );
    check( $h !== FALSE && strpos($h, 'firewall 007100000290') !== FALSE, 'HTML export with references' );
};

$scenarios['template-and-firewall'] = function() use ( $in, $fw, $work ) {
    $out = $work . '/tpl.xml';
    cs( array( 'in=' . $in, 'out=' . $out, 'section=permitted-ip', 'template=Paris Datacenter', 'entry=10.0.0.0/8', 'actions=set:description,mgmt' ) );
    $x = xp( $out );
    eq( $x->query("//template/entry[@name='Paris Datacenter']/config/devices/entry/deviceconfig/system/permitted-ip/entry[@name='10.0.0.0/8']/description")->length, 1, 'template section created' );
    list( $rc, $t ) = cs( array( 'in=' . $out, 'section=permitted-ip', 'template=Paris Datacenter', 'actions=get:set' ) );
    check( strpos($t, 'set template "Paris Datacenter" config deviceconfig system permitted-ip 10.0.0.0/8 description mgmt') !== FALSE, 'template set command' );

    list( $rc, $t, $j ) = cs( array( 'in=' . $fw, 'section=permitted-ip' ), TRUE );
    eq( $rc, 0, 'firewall permitted-ip exit code' );
    eq( $j !== null && isset($j['permitted-ip'][0]['name']) ? $j['permitted-ip'][0]['name'] : null, '192.0.2.0/24', 'firewall permitted-ip entry' );
    list( $rc, $t ) = cs( array( 'in=' . $fw, 'section=deployment-update-schedule' ) );
    check( $rc != 0 && strpos($t, 'not available for firewall') !== FALSE, 'Panorama section refused on a firewall' );
};

$scenarios['errors'] = function() use ( $in ) {
    list( $rc, $t ) = cs( array( 'in=' . $in, 'section=does-not-exist' ) );
    check( $rc != 0 && strpos($t, 'is not known') !== FALSE, 'unknown section' );
    list( $rc, $t ) = cs( array( 'in=' . $in, 'section=deployment-update-schedule', 'actions=foo' ) );
    check( $rc != 0 && strpos($t, 'not supported') !== FALSE, 'unknown action' );
    list( $rc, $t ) = cs( array( 'in=' . $in, 'section=deployment-update-schedule', 'actions=set:only-path' ) );
    check( $rc != 0, 'set without value' );
};

$only = array_slice( $argv, 1 );
foreach( $scenarios as $name => $fn )
{
    if( count($only) && !in_array($name, $only, TRUE) )
        continue;
    $current = $name;
    $before = count( $failed );
    print "  " . $name . "\n";
    $fn();
    print "    " . ( count($failed) == $before ? "ok" : "FAILED" ) . "\n";
}
exec( 'rm -rf ' . escapeshellarg($work) );
print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
