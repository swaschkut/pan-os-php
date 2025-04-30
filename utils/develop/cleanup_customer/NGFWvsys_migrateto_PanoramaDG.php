<?php

$dirname = dirname(__FILE__);

// load PAN-OS-PHP library
require_once($dirname."/../../../lib/pan_php_framework.php");
require_once $dirname."/../../../utils/lib/UTIL.php";


$filename_input_firewall = "firewall.xml";
$filename_output_panorama = "panorama.xml";



$cli = "php ".$dirname."/../../../utils/pan-os-php.php type=upload in=".$filename_input_firewall." out=".$filename_output_panorama." 'fromXpath=/config/shared/*' 'toXpath=/config/shared'";

print $cli."\n";
exec($cli, $output, $retValue);
foreach($output as $line)
{
    $string =  '   ##  ';
    $string .= $line;
    PH::print_stdout( $string );
}

if( $retValue != 0 )
    derr("CLI exit with error code '{$retValue}'");


//Todo: to migrate all existing vsys, parse inputfile; get all virtualSystems in array, go to each array entry
for( $i = 1; $i < 29; $i++ )
{
    $location_name = "vsys".$i;


    $cli = "php ".$dirname."/../../../utils/pan-os-php.php type=upload in=".$filename_input_firewall." out=".$filename_output_panorama." 'fromXpath=/config/devices/entry[@name=\"localhost.localdomain\"]/vsys/entry[@name=\"".$location_name."\"]/*' 'toXpath=/config/devices/entry/device-group/entry[@name=\"".$location_name."\"]'";

    print $cli."\n";
    exec($cli, $output, $retValue);
    foreach($output as $line)
    {
        $string =  '   ##  ';
        $string .= $line;
        PH::print_stdout( $string );
    }

    if( $retValue != 0 )
        derr("CLI exit with error code '{$retValue}'");


}
