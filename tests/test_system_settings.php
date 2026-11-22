<?php
/**
 * System settings (type=config-section, utils/common/config_sections.json) of Panorama, a template, a firewall and
 * SCM - the settings sections and the SCM NGFW device settings (/config/device/v1/<type>, loaded by the real import
 * code of PanSCMAPIConnector from a synthetic answer). Secrets are never shown. Synthetic configurations only.
 *
 *   php tests/test_system_settings.php
 */
$repo = dirname( __DIR__ );
require_once $repo . "/lib/pan_php_framework.php";
require_once $repo . "/utils/lib/UTIL.php";

$checks = 0;
$failed = array();
function eq( $got, $want, $what )
{
    global $checks, $failed;
    $checks++;
    if( $got === $want )
        echo "ok  " . $what . "\n";
    else
    {
        echo "FAIL " . $what . "\n";
        $failed[] = " - " . $what . "\n      expected " . json_encode( $want ) . "\n      got      " . json_encode( $got );
    }
}

/** type=config-section with shadow-json: entry name => fields */
function section( $file, $section, array $extra = array() )
{
    global $repo;
    $cmd = 'php ' . escapeshellarg( $repo . '/utils/pan-os-php.php' ) . ' type=config-section in=' . escapeshellarg( $file ) . ' section=' . $section . ' shadow-json';
    foreach( $extra as $a )
        $cmd .= ' ' . escapeshellarg( $a );
    $o = (string)shell_exec( $cmd . ' 2>/dev/null' );
    $j = json_decode( substr( $o, (int)strpos( $o, '{' ) ), TRUE );
    $out = array();
    foreach( (array)( $j[$section] ?? array() ) as $e )
        if( isset( $e['name'] ) )
            $out[$e['name']] = $e['fields'];
    return $out;
}

$pano = $repo . '/tests/input/system-panorama.xml';
$fw = $repo . '/tests/input/system-firewall.xml';

eq( section( $pano, 'management-settings' ), array( 'management-settings' => array( 'ancestor-objects-take-precedence' => 'yes', 'rule-require-audit-comment' => 'yes', 'idle-timeout' => '30' ) ),
    'Panorama: management settings (ancestor precedence, audit comment) as one settings entry' );
$sys = section( $pano, 'system' )['system'] ?? array();
eq( array( $sys['hostname'] ?? null, $sys['timezone'] ?? null, isset( $sys['permitted-ip[10.0.0.0/8]'] ) ), array( 'pano-synthetic', 'Europe/Berlin', FALSE ),
    'Panorama: system - permitted-ip left out (a section of its own)' );
$adm = section( $pano, 'administrators' );
eq( array( array_keys( $adm ), $adm['admin']['phash'] ?? null, $adm['audit']['authentication-profile'] ?? null ), array( array( 'admin', 'audit' ), '*** hidden ***', 'AP-LDAP' ),
    'Panorama: administrators (mgt-config/users), the password hash hidden' );
eq( array( array_keys( section( $pano, 'admin-roles' ) ), array_keys( section( $pano, 'authentication-profiles' ) ), section( $pano, 'server-profile-ldap' )['LDAP1']['bind-password'] ?? null ),
    array( array( 'Readonly' ), array( 'AP-LDAP' ), '*** encrypted ***' ), 'Panorama: admin roles / authentication profiles below panorama/, the bind password masked' );
eq( array( section( $pano, 'management-settings', array( 'template=T1' ) ), array_keys( section( $pano, 'authentication-profiles', array( 'template=T1' ) ) ),
    section( $pano, 'update-schedule', array( 'template=T1' ) )['update-schedule']['threats.recurring.daily.at'] ?? null ),
    array( array( 'management-settings' => array( 'idle-timeout' => '15' ) ), array( 'AP-FW' ), '03:00' ), 'template: management, authentication profiles (template shared/), update schedule' );

eq( array( section( $fw, 'system' )['system']['panorama.local-panorama.panorama-server'] ?? null, section( $fw, 'high-availability' )['high-availability']['group.peer-ip'] ?? null,
    section( $fw, 'server-profile-snmptrap' )['SNMP1']['version.v2c.server[m1].community'] ?? null, section( $fw, 'server-profile-radius' )['RAD1']['server[r1].secret'] ?? null ),
    array( '192.0.2.10', '192.0.2.21', '*** hidden ***', '*** encrypted ***' ), 'firewall: Panorama server, HA, SNMP community / RADIUS secret never shown' );

// SCM: the NGFW device settings of a folder, loaded from the API (mock) into device-settings/<type>
class MockSettingsConnector extends PanSCMAPIConnector
{
    public $answers = array();
    public $calls = array();
    public function getAccessToken() { $this->access_token = "mock"; }
    function curl_request_SCM( $url )
    {
        $this->calls[] = $url;
        $p = parse_url( $url );
        parse_str( $p['query'] ?? '', $q );
        $type = basename( $p['path'] );
        if( strpos( $p['path'], '/config/setup/' ) !== FALSE )
            $data = $this->answers['setup'][$type] ?? array();
        else
            $data = $this->answers['device'][$type][$q['folder'] ?? $q['device'] ?? $q['snippet'] ?? ''] ?? array();
        return array( 'data' => $data, 'total' => count( $data ), 'limit' => 10000, 'offset' => 0 );
    }
}
$doc = new DOMDocument();
$doc->load( $repo . "/utils/develop/buckbeak_baseconfig.xml", XML_PARSE_BIG_LINES );
$pan = new BuckbeakConf();
$pan->load_from_domxml( $doc );
$c = new MockSettingsConnector( "1234567890" );
$c->answers = array(
    'setup' => array( 'folders' => array( array( 'id' => 'f-all', 'name' => 'All', 'parent' => '', 'type' => 'container' ),
        array( 'id' => 'f-ngfw', 'name' => 'ngfw-shared', 'parent' => 'All', 'type' => 'container' ) ) ),
    'device' => array(
        'general-settings' => array( 'ngfw-shared' => array( array( 'id' => 'g1', 'folder' => 'ngfw-shared',
            'general' => array( 'hostname' => 'fw-scm', 'timezone' => 'Europe/Berlin', 'login_banner' => 'synthetic banner' ) ) ) ),
        'service-settings' => array( 'ngfw-shared' => array( array( 'id' => 's1', 'folder' => 'ngfw-shared',
            'services' => array( 'dns_setting' => array( 'servers' => array( 'primary' => '192.0.2.53' ) ), 'ntp_servers' => array( 'primary_ntp_server' => array( 'ntp_server_address' => '0.pool.ntp.org',
                'authentication_type' => array( 'symmetric_key' => array( 'key_id' => 1, 'algorithm' => array( 'sha1' => array( 'authentication_key' => 'synthetic-key' ) ) ) ) ) ) ) ) ) ),
        'management-interface-settings' => array( 'ngfw-shared' => array( array( 'id' => 'm1', 'folder' => 'ngfw-shared',
            'permitted_ip' => array( array( 'name' => '10.0.0.0/8', 'description' => 'mgmt' ) ), 'service' => array( 'disable_telnet' => TRUE ) ) ) ),
    ),
);
$folders = array_values( array_unique( array_merge( PanSCMAPIConnector::$folderArray, $c->getSnippetsavailable( $pan ), $c->getFolderavailable( $pan ) ) ) );
foreach( $folders as $folder )
{
    $sub = $pan->findContainer( $folder ) ?? $pan->findSnippet( $folder ) ?? $pan->findDeviceCloud( $folder ) ?? $pan->findDeviceOnPrem( $folder );
    if( $sub !== null )
        $c->loadSCMConfig( $folder, $sub, 'device' );
}
eq( count( preg_grep( '#/config/device/v1/general-settings\?folder=ngfw-shared&#', $c->calls ) ), 1, 'SCM: device settings read per folder (/config/device/v1/<type>?folder=)' );
$out = tempnam( sys_get_temp_dir(), 'scmset' ) . '.xml';
$pan->save_to_file( $out );
$g = section( $out, 'scm-general-settings', array( 'location=ngfw-shared' ) );
$sv = section( $out, 'scm-service-settings', array( 'location=ngfw-shared' ) );
$m = section( $out, 'scm-management-interface-settings', array( 'location=ngfw-shared' ) );
eq( array( $g['scm-general-settings']['general.hostname'] ?? null, $g['scm-general-settings']['general.login-banner'] ?? null,
    $sv['scm-service-settings']['services.ntp-servers.primary-ntp-server.authentication-type.symmetric-key.algorithm.sha1.authentication-key'] ?? null,
    $m['scm-management-interface-settings']['permitted-ip[10.0.0.0/8].description'] ?? null, $m['scm-management-interface-settings']['service.disable-telnet'] ?? null,
    section( $out, 'scm-general-settings', array( 'location=All' ) ) ),
    array( 'fw-scm', 'synthetic banner', '*** hidden ***', 'mgmt', 'yes', array() ),
    'SCM: NGFW device settings of a folder (general, services - the NTP key hidden, management interface), not in another folder' );
@unlink( $out );

echo "\n" . $checks . " checks, " . count( $failed ) . " failed\n";
foreach( $failed as $f )
    echo $f . "\n";
exit( count( $failed ) ? 1 : 0 );
