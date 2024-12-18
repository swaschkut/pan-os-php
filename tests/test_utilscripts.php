<?php

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";


$supportedUTILTypes = array(
    "stats",
    "address", "service", "tag", "schedule", "application", "threat",
    "rule",
    "device", "securityprofile", "securityprofilegroup",
    "zone",  "interface", "virtualwire", "routing",
    "key-manager",
    "address-merger", "addressgroup-merger",
    "service-merger", "servicegroup-merger",
    "tag-merger",
    "rule-merger",
    ##"override-finder",
    ##"diff",
    ##"upload",
    "xml-issue",
    ##"appid-enabler",
    "config-size",
    ##"download-predefined",
    ##"register-ip-mgr",
    ##"userid-mgr",
    ##"xml-op-json",
    ##"bpa-generator"
);
/*
address                    config-commit              download-predefined        license                    routing                    service                    spiffy                     traffic-log                xml-op-json
address-merger             config-download-all        gratuitous-arp             maxmind-update             rule                       service-merger             stats                      upload                     zone
addressgroup-merger        config-size                html-merger                override-finder            rule-merger                servicegroup-merger        system-log                 userid-mgr
appid-enabler              device                     interface                  playbook                   schedule                   software-download          tag                        util_get-action-filter
application                dhcp                       ironskillet-update         protocoll-number-download  securityprofile            software-preparation       tag-merger                 virtualwire
bpa-generator              diff                       key-manager                register-ip-mgr            securityprofilegroup       software-remove            threat                     xml-issue
 */

foreach( $supportedUTILTypes as $util )
{
    $location = 'any';
    $output = '/dev/null';
    $input = 'input/panorama-10.0-merger.xml';

    $utilscript = '../utils/pan-os-php.php';

    $additional = "";

    if( $util == "config-size" || $util == "key-manager" )
    {
        $additional = "";
    }
    else
    {
        $additional .= " actions=display";
    }

    if( $util == "rule-merger" )
    {
        $additional .= " method=matchFromToSrcDstApp panoramaPreRules";
    }

    $path = dirname(__FILE__)."/";
    if( $util == "key-manager" )
        $cli = "php ".$path.$utilscript." type={$util}";
    else
        $cli = "php ".$path.$utilscript." type={$util} in=".$path.$input." out={$output} location={$location}";

    $cli .= $additional;

    $cli .= ' shadow-ignoreinvalidaddressobjects';
    $cli .= ' 2>&1';

    PH::print_stdout( " * Executing CLI: {$cli}" );

    $output = array();
    $retValue = 0;

    exec($cli, $output, $retValue);

    foreach( $output as $line )
    {
        $string = '   ##  ';
        $string .= $line;
        PH::print_stdout( $string );
    }

    if( $retValue != 0 && $util != "key-manager" )
        derr("CLI exit with error code '{$retValue}'");

    PH::print_stdout();
}