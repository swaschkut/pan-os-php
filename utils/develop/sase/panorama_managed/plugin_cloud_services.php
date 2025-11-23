<?php

/**
 * ISC License
 *
 * Copyright (c) 2019, Palo Alto Networks Inc.
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

//Todo: 20250102 - all these part are now separatly available as utility e.g. type=ike-gateway

set_include_path(dirname(__FILE__) . '/../../../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../../../lib/pan_php_framework.php";

PH::print_stdout();
PH::print_stdout("***********************************************");
PH::print_stdout("*********** " . basename(__FILE__) . " UTILITY **************");
PH::print_stdout();

function display_usage_and_exit($shortMessage = FALSE)
{
    global $argv;
    PH::print_stdout( PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=inputfile.xml location=vsys1 " .
        "actions=action1:arg1 ['filter=(type is.group) or (name contains datacenter-)']");
    PH::print_stdout( "php " . basename(__FILE__) . " help          : more help messages");


    if( !$shortMessage )
    {
        PH::print_stdout( PH::boldText("\nListing available arguments") );

        global $supportedArguments;

        ksort($supportedArguments);

        foreach( $supportedArguments as &$arg )
        {
            $text = "";
            $text .= " - " . PH::boldText($arg['niceName']);
            if( isset($arg['argDesc']) )
                $text .= '=' . $arg['argDesc'];
            //."=";
            if( isset($arg['shortHelp']) )
                $text .= "\n     " . $arg['shortHelp'];
            PH::print_stdout( $text."\n");
        }

        PH::print_stdout();
    }

    exit(1);
}

function display_error_usage_exit($msg)
{
    if( PH::$shadow_json )
        PH::$JSON_OUT['error'] = $msg;
    else
        fwrite(STDERR, PH::boldText("\n**ERROR** ") . $msg . "\n\n");
    display_usage_and_exit(TRUE);
}


PH::print_stdout();

$configType = null;
$configInput = null;
$configOutput = null;
$doActions = null;
$dryRun = FALSE;
$objectslocation = 'shared';
$objectsFilter = null;
$errorMessage = '';
$debugAPI = FALSE;


$supportedArguments = array();
$supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['location'] = array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['template'] = array('niceName' => 'template', 'shortHelp' => 'Panorama template');
$supportedArguments['loadpanoramapushedconfig'] = array('niceName' => 'loadPanoramaPushedConfig', 'shortHelp' => 'load Panorama pushed config from the firewall to take in account panorama objects and rules');
$supportedArguments['folder'] = array('niceName' => 'folder', 'shortHelp' => 'specify the folder where the offline files should be saved');


PH::processCliArgs();

foreach( PH::$args as $index => &$arg )
{
    if( !isset($supportedArguments[$index]) )
    {
        //var_dump($supportedArguments);
        display_error_usage_exit("unsupported argument provided: '$index'");
    }
}

if( isset(PH::$args['help']) )
{
    display_usage_and_exit();
}


if( !isset(PH::$args['in']) )
    display_error_usage_exit('"in" is missing from arguments');
$configInput = PH::$args['in'];
if( !is_string($configInput) || strlen($configInput) < 1 )
    display_error_usage_exit('"in" argument is not a valid string');

if( isset(PH::$args['out']) )
{
    $configOutput = PH::$args['out'];
    if( !is_string($configOutput) || strlen($configOutput) < 1 )
        display_error_usage_exit('"out" argument is not a valid string');
}

if( isset(PH::$args['debugapi']) )
{
    $debugAPI = TRUE;
}

if( isset(PH::$args['folder']) )
{
    $offline_folder = PH::$args['folder'];
}



################
//
// What kind of config input do we have.
//     File or API ?
//
// <editor-fold desc="  ****  input method validation and PANOS vs Panorama auto-detect  ****" defaultstate="collapsed" >
$configInput = PH::processIOMethod($configInput, TRUE);
$xmlDoc1 = null;

if( $configInput['status'] == 'fail' )
{
    fwrite(STDERR, "\n\n**ERROR** " . $configInput['msg'] . "\n\n");
    exit(1);
}

if( $configInput['type'] == 'file' )
{
    if( !file_exists($configInput['filename']) )
        derr("file '{$configInput['filename']}' not found");

    $xmlDoc1 = new DOMDocument();
    if( !$xmlDoc1->load($configInput['filename'], XML_PARSE_BIG_LINES) )
        derr("error while reading xml config file");

}
elseif( $configInput['type'] == 'api' )
{

    if( $debugAPI )
        $configInput['connector']->setShowApiCalls(TRUE);
    PH::print_stdout( " - Downloading config from API... ");

    if( isset(PH::$args['loadpanoramapushedconfig']) )
    {
        PH::print_stdout( " - 'loadPanoramaPushedConfig' was requested, downloading it through API...");
        $xmlDoc1 = $configInput['connector']->getPanoramaPushedConfig();
    }
    else
    {
        $xmlDoc1 = $configInput['connector']->getCandidateConfig();

    }
    $hostname = $configInput['connector']->info_hostname;

    #$xmlDoc1->save( $offline_folder."/orig/".$hostname."_prod_new.xml" );



}
else
    derr('not supported yet');

//
// Determine if PANOS or Panorama
//
$xpathResult1 = DH::findXPath('/config/devices/entry/vsys', $xmlDoc1);
if( $xpathResult1 === FALSE )
    derr('XPath error happened');
if( $xpathResult1->length < 1 )
{
    $xpathResult1 = DH::findXPath('/panorama', $xmlDoc1);
    if( $xpathResult1->length < 1 )
        $configType = 'panorama';
    else
        $configType = 'pushed_panorama';
}
else
    $configType = 'panos';
unset($xpathResult1);

PH::print_stdout( " - Detected platform type is '{$configType}'");

############## actual not used

if( $configType == 'panos' )
    $pan = new PANConf();
elseif( $configType == 'panorama' )
    $pan = new PanoramaConf();


if( $configInput['type'] == 'api' )
    $pan->connector = $configInput['connector'];


// </editor-fold>

################





##########################################
##########################################
$zone_array = array();


$pan->load_from_domxml($xmlDoc1);

if( $configType !== 'panorama' )
{
    derr('"plugins->cloud_services" is expecting Panorama Configuration - but not provided');
}



$cloud_seviceslist = DH::findXPath("/config/devices/entry[@name='localhost.localdomain']/plugins/cloud_services", $pan->xmlroot);
$cloud_sevicesXMLroot = $cloud_seviceslist->item(0);

PH::print_stdout();
PH::print_stdout("---------------------------------");
PH::print_stdout();

if( $cloud_sevicesXMLroot !== FALSE and $cloud_sevicesXMLroot !== null )
{
    $service_connectionXML = DH::findFirstElement("service-connection", $cloud_sevicesXMLroot);
    if( $service_connectionXML !== FALSE )
    {
        $internal_dns_listXML = DH::findFirstElement("internal-dns-list", $service_connectionXML);
        if( $internal_dns_listXML !== FALSE )
        {
            $service_connectionXML->removeChild($internal_dns_listXML);
            PH::print_stdout("internal-dns-list removed - for better display");
        }
        PH::print_stdout();
        DH::DEBUGprintDOMDocument($service_connectionXML);
        PH::print_stdout("---------------------------------");
        PH::print_stdout();
    }


    $remote_networksXML = DH::findFirstElement("remote-networks", $cloud_sevicesXMLroot);
    if( $remote_networksXML !== FALSE )
    {
        $onboardingXML = DH::findFirstElement("onboarding", $remote_networksXML);
        if( $onboardingXML !== FALSE )
        {
            $remote_networksXML->removeChild($onboardingXML);
            PH::print_stdout("onboarding removed");

            foreach( $onboardingXML->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                /*
                   <entry name="Chennai-ICF-Corp">
                       <protocol>
                        <bgp>
                         <enable>no</enable>
                        </bgp>
                       </protocol>
                       <subnets>
                        <member>10.126.0.0/17</member>
                       </subnets>
                       <bgp-peer>
                        <same-as-primary>yes</same-as-primary>
                       </bgp-peer>
                       <region>india-south</region>
                       <license-type>FWAAS-AGGREGATE</license-type>
                       <ipsec-tunnel>Chennai-ICF-Corp-IPSec-TATA</ipsec-tunnel>
                       <secondary-wan-enabled>yes</secondary-wan-enabled>
                       <secondary-ipsec-tunnel>Chennai-ICF-Corp-IPSec-TTSL</secondary-ipsec-tunnel>
                       <spn-name>asia-south-fig</spn-name>
                       <ecmp-load-balancing>disabled</ecmp-load-balancing>
                      </entry>
                 */
                $name = DH::findAttribute('name', $node);

                PH::print_stdout("----------");
                PH::print_stdout("NAME: ".$name);

                $bgp_enabled = "no";
                $protocolXML = DH::findFirstElement("protocol", $node);
                if( $protocolXML !== FALSE )
                {
                    $bgpXML = DH::findFirstElement("bgp", $protocolXML);
                    if( $bgpXML !== FALSE )
                    {
                        $bgpEnableXML = DH::findFirstElement("enable", $bgpXML);
                        if( $bgpEnableXML !== FALSE )
                            $bgp_enabled = $bgpEnableXML->textContent;
                    }
                }
                PH::print_stdout(" - BGP enabled: ".$bgp_enabled);


                $subnetsArray = array();
                $subnetsXML = DH::findFirstElement("subnets", $node);
                if( $subnetsXML !== FALSE )
                {
                    foreach( $subnetsXML->childNodes as $subnets_node )
                    {
                        if( $subnets_node->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $subnetsArray[] = $subnets_node->textContent;
                    }
                }
                PH::print_stdout(" - subnets: ".implode(",", $subnetsArray));

                $region = null;
                $regionXML = DH::findFirstElement("region", $node);
                if( $regionXML !== FALSE )
                    $region = $regionXML->textContent;
                PH::print_stdout(" - Region: ".$region);

                $licenseType = null;
                $licenseTypeXML = DH::findFirstElement("license-type", $node);
                if( $licenseTypeXML !== FALSE )
                    $licenseType = $licenseTypeXML->textContent;
                PH::print_stdout(" - License type: ".$licenseType);

                $ipsecTunnel = null;
                $ipsecTunnelXML = DH::findFirstElement("ipsec-tunnel", $node);
                if( $ipsecTunnelXML !== FALSE )
                    $ipsecTunnel = $ipsecTunnelXML->textContent;
                PH::print_stdout(" - IPsec Tunnel: ".$ipsecTunnel);

                $secondaryIpsecTunnel = null;
                $secondaryIpsecTunnelXML = DH::findFirstElement("secondary-ipsec-tunnel", $node);
                if( $secondaryIpsecTunnelXML !== FALSE )
                    $secondaryIpsecTunnel = $secondaryIpsecTunnelXML->textContent;
                PH::print_stdout(" - secondary IPsecTunnel: ".$secondaryIpsecTunnel);

                $spnName = null;
                $spnNameXML = DH::findFirstElement("spn-name", $node);
                if( $spnNameXML !== FALSE )
                    $spnName = $spnNameXML->textContent;
                PH::print_stdout(" - SPNName: ".$spnName);

                $ecmpLoadBalancing = null;
                $ecmpXML = DH::findFirstElement("ecmp-load-balancing", $node);
                if( $ecmpXML !== FALSE )
                    $ecmpLoadBalancing = $ecmpXML->textContent;
                PH::print_stdout(" - ECMP-LoadBalancing: ".$ecmpLoadBalancing);
                /*
                <region>india-south</region>
               <license-type>FWAAS-AGGREGATE</license-type>
               <ipsec-tunnel>Chennai-ICF-Corp-IPSec-TATA</ipsec-tunnel>
               <secondary-wan-enabled>yes</secondary-wan-enabled>
               <secondary-ipsec-tunnel>Chennai-ICF-Corp-IPSec-TTSL</secondary-ipsec-tunnel>
               <spn-name>asia-south-fig</spn-name>
               <ecmp-load-balancing>disabled</ecmp-load-balancing>
                */
            }
        }
        PH::print_stdout("----------");
        PH::print_stdout();
        DH::DEBUGprintDOMDocument($remote_networksXML);
        PH::print_stdout("---------------------------------");
        PH::print_stdout();
    }


    $routing_preferenceXML = DH::findFirstElement("routing-preference", $cloud_sevicesXMLroot);
    if( $routing_preferenceXML !== FALSE )
    {
        /*
         * <routing-preference __recordInfo="{&quot;permission&quot;:&quot;readwrite&quot;,&quot;xpathId&quot;:&quot;plugin&quot;}">
     <default/>
    </routing-preference>
         */
        $routingPreference = null;
        foreach($routing_preferenceXML->childNodes as $routing_preference_node)
        {
            if( $routing_preference_node->nodeType != XML_ELEMENT_NODE )
                continue;

            $routingPreference = $routing_preference_node->nodeName;
        }
        PH::print_stdout(" - Routing Preference: ".$routingPreference);
        #DH::DEBUGprintDOMDocument($routing_preferenceXML);
        PH::print_stdout("---------------------------------");
        PH::print_stdout();
    }


}


##############################################

PH::print_stdout();

// save our work !!!
if( $configOutput !== null )
{
    if( $configOutput != '/dev/null' )
    {
        $pan->save_to_file($configOutput);
    }
}


PH::print_stdout();
PH::print_stdout("************* END OF SCRIPT " . basename(__FILE__) . " ************" );
PH::print_stdout();
