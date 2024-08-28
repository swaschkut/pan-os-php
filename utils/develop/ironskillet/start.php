<?php

require_once "lib/pan_php_framework.php";


$array = array();

#$array['basic'] = array();
#$array['optional'] = array();

$tmp_array = array();

$tmp_array['value'] = "You have accessed a protected system. Log off immediately if you are not an authorized user.";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/login-banner";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Standard text";
$array["{{custom-LOGIN-BANNER}}"] = $tmp_array;


$tmp_array['value'] = "Europe/Berlin";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/timezone";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Time zone e.g. 'Europe/Berlin'";
$array["{{custom-TIMEZONE}}"] = $tmp_array;


$tmp_array['value'] = "no";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/management/auto-acquire-commit-lock";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "auto commit lock";
$array["{{custom-COMMIT-LOCK}}"] = $tmp_array;


$tmp_array['value'] = 10;
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/idle-timeout";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Session Idle-Timeout for Admins in minutes (Best Practice = 10 / Default = 60)";
$array["{{custom-IDLE-TIMEOUT}}"] = $tmp_array;


$tmp_array['value'] = 0;
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/api/key/lifetime";
$tmp_array['replace'] = "{{API_KEY_LIFETIME}}";
$tmp_array['comment'] = "API-Key Lifetime in minutes (Default = 0, never); SVA-default=0; IronSkillet=525600 (365days/1year)";
$array[] = $tmp_array;

/*
//create cert in termplate shared
$tmp_array['value'] = 1;
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/idle-timeout";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "API KEY Cert - needed with PAN-OS 11.1.x";
$array["{{custom-API-KEY-CERT}}"] = $tmp_array;
*/

$tmp_array['value'] = 5;
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/admin-lockout/failed-attempts";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "User failed login attempts";
$array["{{custom-USER-FAILED-ATTEMPTS}}"] = $tmp_array;

$tmp_array['value'] = 10;
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/admin-lockout/lockout-time";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "lockout time after User failed login attempts";
$array["{{custom-USER-FAILED-ATTEMPTS}}"] = $tmp_array;


$tmp_array['value'] = "no";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/rule-require-tag";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Require Tag on Policies";
$array["{{custom-POLICY-REQUIRE-TAG}}"] = $tmp_array;

$tmp_array['value'] = "no";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/rule-require-description";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Require description on Policies";
$array["{{custom-POLICY-REQUIRE-DESCRIPTION}}"] = $tmp_array;


$tmp_array['value'] = "no";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/rule-require-audit-comment";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Require audit comment on Policies";
$array["{{custom-POLICY-REQUIRE-AUDIT-COMMENT}}"] = $tmp_array;


$tmp_array['value'] = "yes";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/wildcard-topdown-match-mode";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Require audit comment on Policies";
$array["{{custom-POLICY-WILDCARD-MATCH-MODE}}"] = $tmp_array;


$tmp_array['value'] = "yes";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/rule-hit-count";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Require audit comment on Policies";
$array["{{custom-RULE-HIT-COUNT}}"] = $tmp_array;

$tmp_array['value'] = "yes";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/appusage-policy";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Require audit comment on Policies";
$array["{{custom-APPUSAGE-POLICY}}"] = $tmp_array;

$tmp_array['value'] = 1048576;
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/max-rows-in-csv-export";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Require audit comment on Policies";
$array["{{custom-MAX-ROWS-CSV-EXPORT}}"] = $tmp_array;

$tmp_array['value'] = "yes";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/log-revert-operations";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Enable Configuration Logs for Revert Operations";
$array["{{custom-LOG-REVERT-OPERATIONS}}"] = $tmp_array;


$tmp_array['value'] = "yes";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/enable-log-high-dp-load";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Enable Configuration Logs on high DP load";
$array["{{custom-LOG-HIGH-DP-LOAD}}"] = $tmp_array;

$tmp_array['value'] = "yes";
$tmp_array['enable'] = 0;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/audit-tracking/op-commands";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Enable audit log for op-commands, but only possible via syslog";
$array["{{custom-AUDIT-TRACKING-OP-COMMANDS}}"] = $tmp_array;

$tmp_array['value'] = "yes";
$tmp_array['enable'] = 0;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/audit-tracking/ui-actions";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Enable audit log for ui-actions, but only possible via syslog";
$array["{{custom-AUDIT-TRACKING-UI-ACTIONS}}"] = $tmp_array;


$tmp_array['value'] = "1.2.3.4";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/panorama/local-panroama/panorama-server";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Panorama Server IP 1";
$array["{{custom-PANORAMA-SERVER-1}}"] = $tmp_array;

$tmp_array['value'] = "5.6.7.8";
$tmp_array['enable'] = 0;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/panorama/local-panroama/panorama-server-2";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Panorama Server IP 2";
$array["{{custom-PANORAMA-SERVER-2}}"] = $tmp_array;



$tmp_array['value'] = "no";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/disable-commit-recovery";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "disable commit recocvery if Panorama is not reachable";
$array["{{custom-COMMIT-RECOVERY-DISABLE}}"] = $tmp_array;

$tmp_array['value'] = 3;
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/commit-recovery-retry";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "FW commit recovery retry if Panorama is not reachable";
$array["{{custom-COMMIT-RECOVERY-RETRY}}"] = $tmp_array;

$tmp_array['value'] = 5;
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/commit-recovery-timeout";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "FW commit recovery timeout if Panorama is not reachable";
$array["{{custom-COMMIT-RECOVERY-TIMEOUT}}"] = $tmp_array;

$tmp_array['value'] = "yes";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/management/device-monitoring/enable";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Send Device monitoring information to Panorama";
$array["{{custom-DEVICE-MONITORING}}"] = $tmp_array;



$tmp_array['value'] = "no";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/motd-and-banner/motd-enable";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Disable Banner";
$array["{{custom-MOTD-BANNER}}"] = $tmp_array;


$tmp_array['value'] = "no";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/mgt-config/password-complexity";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "set Password-Complexity";
$array["{{custom-PASSWORD-COMPLEXITY}}"] = $tmp_array;


$tmp_array['value'] = "no";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/deviceconfig/system/snmp-setting";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "set SNMPv3";
$array["{{custom-PASSWORD-COMPLEXITY}}"] = $tmp_array;




$tmp_array['value'] = "updates.paloaltonetworks.com";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/deviceconfig/system/update-server";
$tmp_array['replace'] = "{{UPDATE-SERVER}}";
$tmp_array['comment'] = "set Update Server";
$array["{{custom-UPDATE-SERVER}}"] = $tmp_array;



$tmp_array['value'] = "192.168.10.100";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/dns-setting/servers/primary";
$tmp_array['replace'] = "{{DNS_1}}";
$tmp_array['comment'] = "Primary DNS";
$array[] = $tmp_array;

$tmp_array['value'] = "192.168.10.200";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/dns-setting/servers/secondary";
$tmp_array['replace'] = "{{DNS_2}}";
$tmp_array['comment'] = "Secondary DNS";
$array[] = $tmp_array;

$tmp_array['value'] = "192.168.10.100";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ntp-servers/primary-ntp-server/ntp-server-address";
$tmp_array['replace'] = "{{NTP_1}}";
$tmp_array['comment'] = "Primary NTP";
$array[] = $tmp_array;

$tmp_array['value'] = "192.168.10.200";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address";
$tmp_array['replace'] = "{{NTP_2}}";
$tmp_array['comment'] = "Secondary NTP";
$array[] = $tmp_array;

$tmp_array['value'] = "yes";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/deviceconfig/system/device-telemetry";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "Telemetry settings";
$array[] = $tmp_array;


$tmp_array['value'] = "yes";
$tmp_array['enable'] = 1;
$tmp_array['xpath'] = "/config/deviceconfig/settings/ctd";
$tmp_array['replace'] = "FULL-XML-NODE";
$tmp_array['comment'] = "CTD settings";
$array[] = $tmp_array;


//set template BP-Device_v1.0 vsys vsys1 setting ssl-decrypt allow-forward-decrypted-content yes

#foreach( $array as $entry )
#{
#    print $entry['xpath']."\n";
#}

$variable_array = array();

$version = "10.2";
$type= "panorama";
#$type= "panos";
if( $type=="panorama" )
    $path_type = $type;
elseif( $type=="panos" )
    $path_type = $type;
$config_file = "../../../iron-skillet/panos_v".$version."/templates/".$path_type."/full/iron_skillet_".$path_type."_full.xml";



#load config
#find xpath
#get XMLnode and print

$newdoc = new DOMDocument;
#$newdoc->load($config_file, XML_PARSE_BIG_LINES);
$newdoc->load($config_file);

/*
$xmlString = DEBUGprintDOMDocument($newdoc->documentElement);
xmlStringVariableArray($xmlString);
print_r($variable_array);
print(count($variable_array)."\n");
$keepArray = $variable_array;
$variable_array = array();
*/

#remove specific xpath:
$xpath_to_be_removed = array();
$xpath_to_be_removed[] = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/management/initcfg";
foreach( $xpath_to_be_removed as $remove_xpath )
{
    $nodeList = DH::findXPath($remove_xpath, $newdoc->documentElement);
    foreach( $nodeList as $node )
        $node->parentNode->removeChild($node);
}


function printXMLnode( $newdoc, $xpath)
{
    print $xpath."\n";

    $nodeList = DH::findXPath($xpath, $newdoc->documentElement);
    if(count($nodeList)==0)
        derr("xpath: '".$xpath."' not found", null, false);
    foreach($nodeList as $node)
    {
        $xmlString = DEBUGprintDOMDocument($node);
        print $xmlString;

        xmlStringVariableArray($xmlString, $xpath);
    }

    print("######################################################\n");
}

function xmlStringVariableArray($xmlString, $xpath)
{
    global $variable_array;
    if(strpos( $xmlString, "{{" ) !== FALSE)
    {
        #print $xmlString;

        $delimiter = '#';
        $startTag = '{{';
        $endTag = '}}';
        $regex = $delimiter . preg_quote($startTag, $delimiter)
            . '(.*?)'
            . preg_quote($endTag, $delimiter)
            . $delimiter
            . 's';
        preg_match_all($regex,$xmlString,$matches);
        #print_r($matches[0]);
        foreach( $matches[0] as $data )
        {
            $variable_array[$data] = $xpath;
            print $data."\n";
            #$variable_array[] = $data;
        }
    }
}
function DEBUGprintDOMDocument( $node )
{
    if ($node != null) {
        $newdoc = new DOMDocument;
        $node = $newdoc->importNode($node, true);
        $newdoc->appendChild($node);

        $lineReturn = TRUE;
        $indentingXmlIncreament = 1;
        $indentingXml = 0;
        $xml = &DH::dom_to_xml($newdoc->documentElement, $indentingXml, $lineReturn, -1, $indentingXmlIncreament);
        return $xml;
        #print $newdoc->saveXML($newdoc->documentElement);
    }
    return null;
}

$xpath = "/config/mgt-config/password-complexity";
printXMLnode( $newdoc, $xpath );

if( $type=="panorama" )
    $xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{{DEVICE_GROUP}}']/external-list";
else
    $xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/external-list";
printXMLnode( $newdoc, $xpath );

$xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system";
printXMLnode( $newdoc, $xpath );

$xpath = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/management";
printXMLnode( $newdoc, $xpath );


if( $type=="panorama" )
{
    #template
    #$xpath = "/config/devices/entry[@name='localhost.localdomain']/template/entry[@name='iron-skillet']/config/shared/log-settings";

    #Log Collector:
    #$xpath = "/config/devices/entry[@name='localhost.localdomain']/log-collector-group/entry[@name='Default_Collector_Group']/log-settings";

    $xpath = "/config/panorama/log-settings";
    printXMLnode( $newdoc, $xpath );
}
else
{
    #$xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/log-settings";
    #printXMLnode( $newdoc, $xpath );

    #$xpath = "/config/shared/log-settings";
    #printXMLnode( $newdoc, $xpath );
}



$xpath = "/config/shared/log-settings";
printXMLnode( $newdoc, $xpath );


if( $type=="panorama" )
    $xpath = "/config/shared/profiles/decryption";
else
    $xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/decryption";
printXMLnode( $newdoc, $xpath );

if( $type=="panorama" )
    $xpath = "/config/shared/pre-rulebase";
else
    $xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase";
printXMLnode( $newdoc, $xpath );


if( $type=="panorama" )
    $xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{{DEVICE_GROUP}}']/reports";
else
    $xpath = "/config/shared/reports";
printXMLnode( $newdoc, $xpath );


if( $type=="panorama" )
    $xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{{DEVICE_GROUP}}']/report-group";
else
    $xpath = "/config/shared/report-group";
printXMLnode( $newdoc, $xpath );

if( $type=="panorama" )
    $xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{{DEVICE_GROUP}}']/email-scheduler";
else
    $xpath = "/config/shared/email-scheduler";
printXMLnode( $newdoc, $xpath );


print_r($variable_array);
print(count($variable_array)."\n");

/*
foreach( $keepArray as $key => $keepElement )
{
    if( isset($variable_array[$key]) )
        unset($keepArray[$key]);
}
print_R($keepArray);
*/


$finalJSON = array();
#preperation of JSON file creation:
foreach( $variable_array as $key => $entry )
{
    $tmp_array = array();
    $tmp_array['value'] = "DUMMY";
    $tmp_array['enable'] = 0;
    $tmp_array['xpath'] = "is this needed";
    $tmp_array['replace'] = $key;
    $tmp_array['comment'] = "DUMMY text";

    $finalJSON[$key] = $tmp_array;

}

foreach( $array as $key => $entry )
{
    $finalJSON[$key] = $entry;
}

print_r($finalJSON);

$json = json_encode($finalJSON, JSON_PRETTY_PRINT);
echo $json;


$json_Array = json_decode( $json, true );
print_r($json_Array);
print_r($json_Array['{{CONFIG_EXPORT_IP}}']);