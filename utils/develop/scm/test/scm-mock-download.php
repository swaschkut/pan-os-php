<?php
/**
 * Offline "download" of an SCM configuration: runs the real PanSCMAPIConnector import
 * (getSnippetsavailable, getFolderavailable, loadSCMConfig, importConfig) against fixture
 * responses instead of the SCM API and writes the XML that in=scm-api://... out=... would write.
 *
 *   php scm-mock-download.php <pan-os-php repo> <scm-fixtures.json> <out.xml>
 */
$repo = $argv[1];
require_once $repo . "/lib/pan_php_framework.php";
require_once $repo . "/utils/lib/UTIL.php";
PH::processCliArgs();

class MockSCMConnector extends PanSCMAPIConnector
{
    public $fx; public $calls = array();
    public function getAccessToken() { $this->access_token = "mock"; }
    function curl_request_SCM( $url )
    {
        $this->calls[] = $url;
        $p = parse_url($url); parse_str($p['query'] ?? '', $q);
        $type = basename($p['path']);
        if( strpos($p['path'], '/config/setup/') !== FALSE )
            return array('data' => $this->fx['setup'][$type] ?? array(), 'total' => count($this->fx['setup'][$type] ?? array()), 'limit' => 10000);
        foreach( array('folder','snippet','device') as $s )
            if( isset($q[$s]) ) { $scope = $s; $name = $q[$s]; }
        $pos = $q['position'] ?? '';
        $data = $this->fx['res']["$type|$scope|$name|$pos"] ?? array();
        return array('data' => $data, 'total' => count($data), 'limit' => 10000, 'offset' => 0);
    }
}

$fx = json_decode(file_get_contents($argv[2]), TRUE);
$xmlDoc = new DOMDocument();
$xmlDoc->load($repo . "/utils/develop/buckbeak_baseconfig.xml", XML_PARSE_BIG_LINES);
$pan = new BuckbeakConf();
$pan->load_from_domxml($xmlDoc);

$c = new MockSCMConnector("1234567890");
$c->fx = $fx;
$folders = array_merge(PanSCMAPIConnector::$folderArray, $c->getSnippetsavailable($pan), $c->getFolderavailable($pan));
$folders = array_values(array_unique($folders));
foreach( array('stats') as $utilType )
    foreach( $folders as $folder )
    {
        $sub = $pan->findContainer($folder) ?? $pan->findSnippet($folder) ?? $pan->findDeviceCloud($folder) ?? $pan->findDeviceOnPrem($folder);
        if( $sub === null ) continue;
        $c->loadSCMConfig($folder, $sub, $utilType);
    }
$pan->save_to_file($argv[3]);
fwrite(STDERR, "calls: " . count($c->calls) . "\n");
