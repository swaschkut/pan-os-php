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
 * scm_internal_api_get.php
 *
 * One read-only GET against the internal Strata Cloud Manager UI API with the service account token, answer
 * written to a JSON file - to compare the internal answer with the public API (e.g. security profiles).
 *
 * php scm_internal_api_get.php in=scm-api://<TSG> path=/api/config/v9.2/Objects/WildFireAndAntivirusSecurityProfiles
 *     folder="Mobile Users Explicit Proxy" [type=cloud|container] [name=<object>] [out=answer.json]
 *     [host=paas-3.prod.eu.panorama.paloaltonetworks.com]
 *
 * type: folder type - cloud for the Prisma Access deployment folders (Mobile Users, Mobile Users Explicit Proxy,
 * Remote Networks, Service Connections), container for all other folders (default).
 */

set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");

PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " **************");
PH::print_stdout();

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=scm-api://<TSG>', 'argDesc' => 'scm-api://[TSG]');
$supportedArguments['path'] = array('niceName' => 'path', 'shortHelp' => 'internal API path, e.g. /api/config/v9.2/Objects/VulnerabilityProtectionSecurityProfiles', 'argDesc' => '[path]');
$supportedArguments['folder'] = array('niceName' => 'folder', 'shortHelp' => 'folder name', 'argDesc' => '[folder]');
$supportedArguments['type'] = array('niceName' => 'type', 'shortHelp' => 'folder type: container (default) | cloud', 'argDesc' => '[type]');
$supportedArguments['name'] = array('niceName' => 'name', 'shortHelp' => 'only this object', 'argDesc' => '[name]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file (default internal-answer.json)', 'argDesc' => '[file]');
$supportedArguments['host'] = array('niceName' => 'host', 'shortHelp' => 'internal UI API host (default paas-3.prod.eu.panorama.paloaltonetworks.com)', 'argDesc' => '[host]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$usage = "php " . basename(__FILE__) . " in=scm-api://<TSG> path=/api/config/v9.2/... folder=<folder> [type=cloud|container] [name=<object>] [out=file.json] [host=<UI API host>]";

$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usage);
$util->utilInit();

/* @var PanSCMAPIConnector $connector */
$connector = $util->pan->connector;
if( !is_object($connector) || get_class($connector) !== "PanSCMAPIConnector" )
    derr("argument in=scm-api://<TSG> is required", null, FALSE);
if( isset(PH::$args['debugapi']) )
    $connector->setShowApiCalls(TRUE);
if( !isset(PH::$args['path']) || strpos(PH::$args['path'], "/api/") !== 0 )
    derr("argument path=/api/... is required", null, FALSE);
if( !isset(PH::$args['folder']) )
    derr("argument folder= is required", null, FALSE);

$host = isset(PH::$args['host']) ? PH::$args['host'] : "paas-3.prod.eu.panorama.paloaltonetworks.com";
$query = array( 'folder' => PH::$args['folder'], 'type' => isset(PH::$args['type']) ? PH::$args['type'] : 'container' );
if( isset(PH::$args['name']) )
    $query['name'] = PH::$args['name'];
$url = "https://" . $host . PH::$args['path'] . "?" . http_build_query($query, '', '&', PHP_QUERY_RFC3986);

$r = $connector->sendSCMAPIRequest("GET", $url, false, FALSE);
$out = isset(PH::$args['out']) ? PH::$args['out'] : "internal-answer.json";
$content = array( 'url' => $url, 'tsg_id' => $connector->apihost, 'fetched_at' => date('c'), 'http_code' => $r['http_code'],
    'errors' => $r['errors'], 'answer' => $r['json'] !== null ? $r['json'] : $r['response'] );
file_put_contents($out, json_encode($content, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
chmod($out, 0600);

$entries = isset($r['json']['result']['entry']) && is_array($r['json']['result']['entry']) ? $r['json']['result']['entry'] : array();
PH::print_stdout(" - HTTP " . $r['http_code'] . ", " . count($entries) . " entr" . ( count($entries) == 1 ? "y" : "ies" ) . " -> " . $out);
foreach( $entries as $e )
    PH::print_stdout("   * " . ( isset($e['@name']) ? $e['@name'] : '?' ) . "  [loc " . ( isset($e['@loc']) ? $e['@loc'] : '-' )
        . ( isset($e['@snippet-loc']) ? ", snippet " . $e['@snippet-loc'] : "" ) . "]  " . implode(", ", array_filter(array_keys($e), function($k){ return $k[0] !== '@'; })));

PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************");
PH::print_stdout();
