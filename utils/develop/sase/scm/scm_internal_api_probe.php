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
 * scm_internal_api_probe.php
 *
 * Checks whether the internal Strata Cloud Manager UI API (used by the web UI for pages without public API,
 * e.g. Mobile Users Explicit Proxy) accepts the service account token of pan-os-php.
 *
 * Read-only: GET requests only. Prints per request: auth variant, HTTP code, top-level keys / entry count -
 * never values, never the token.
 *
 * php scm_internal_api_probe.php in=scm-api://<TSG> [host=paas-3.prod.eu.panorama.paloaltonetworks.com] [debugapi]
 *
 * host: the UI API host of the tenant region - browser developer tools / HAR (requests to /api/config/v9.2/...)
 */

set_include_path(dirname(__FILE__) . '/../../../../' . PATH_SEPARATOR . get_include_path());
require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");

PH::print_stdout();
PH::print_stdout("*********** " . basename(__FILE__) . " **************");
PH::print_stdout();

$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'in=scm-api://<TSG>', 'argDesc' => 'scm-api://[TSG]');
$supportedArguments['host'] = array('niceName' => 'host', 'shortHelp' => 'internal UI API host (default paas-3.prod.eu.panorama.paloaltonetworks.com)', 'argDesc' => '[host]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$usage = "php " . basename(__FILE__) . " in=scm-api://<TSG> [host=<UI API host>]";

$util = new UTIL("custom", $argv, $argc, __FILE__, $supportedArguments, $usage);
$util->utilInit();

/* @var PanSCMAPIConnector $connector */
$connector = $util->pan->connector;
if( !is_object($connector) || get_class($connector) !== "PanSCMAPIConnector" )
    derr("argument in=scm-api://<TSG> is required", null, FALSE);

$host = isset(PH::$args['host']) ? PH::$args['host'] : "paas-3.prod.eu.panorama.paloaltonetworks.com";
$base = "https://" . $host;

$EP = rawurlencode("Mobile Users Explicit Proxy");
$MU = rawurlencode("Mobile Users");
$probes = array(
    "EP settings" => "/api/config/v9.2/Plugins/CloudServices/MobileUsersExplicitProxy?folder=" . $EP . "&type=cloud",
    "EP auth settings" => "/api/config/v9.2/Plugins/CloudServices/MobileUsersExplicitProxy/AuthSettings?folder=" . $EP . "&type=cloud",
    "EP forwarding profiles" => "/api/sase/config/v1/device-config/sase-forwarding-profiles/forwarding-profile?folder=" . $MU . "&pagination=false",
    "MU settings (plugin)" => "/api/config/v9.2/Plugins/CloudServices/MobileUsers?folder=" . $MU . "&type=cloud",
    "EP vulnerability profiles" => "/api/config/v9.2/Objects/VulnerabilityProtectionSecurityProfiles?folder=" . $EP . "&type=cloud",
);

$connector->getAccessToken();
$token = $connector->access_token;

$variants = array(
    'bearer' => array("Authorization: Bearer " . $token),
    'x-auth-jwt' => array("x-auth-jwt: " . $token),
);

$ok = 0;
foreach( $probes as $label => $path )
{
    foreach( $variants as $variant => $headers )
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $base . $path);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge($headers, array("Accept: application/json")));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);
        if( isset(PH::$args['debugapi']) )
            PH::print_stdout("GET " . $base . $path . " (" . $variant . ")");
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = $body === false ? curl_error($ch) : null;

        $info = "";
        $json = is_string($body) ? json_decode($body, TRUE) : null;
        if( $err !== null )
            $info = "curl: " . $err;
        elseif( is_array($json) )
        {
            $keys = array_slice(array_keys($json), 0, 6);
            $info = "keys: " . implode(", ", $keys);
            if( isset($json['result']['entry']) && is_array($json['result']['entry']) )
                $info .= " | entries: " . count($json['result']['entry']);
            elseif( array_keys($json) === range(0, count($json) - 1) )
                $info .= " | list: " . count($json);
            if( isset($json['@code']) )
                $info .= " | @code " . $json['@code'];
        }
        elseif( is_string($body) )
            $info = "non-JSON answer (" . strlen($body) . " bytes)";

        if( $code >= 200 && $code < 300 && is_array($json) )
            $ok++;
        PH::print_stdout(sprintf(" - %-26s %-11s HTTP %3d  %s", $label, $variant, $code, $info));
    }
}

PH::print_stdout();
PH::print_stdout($ok > 0
    ? "the internal UI API accepts the service account token (see which variant answered 200)"
    : "no answer with HTTP 2xx - the internal UI API does not accept the service account token (UI session only)");
PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************");
PH::print_stdout();
