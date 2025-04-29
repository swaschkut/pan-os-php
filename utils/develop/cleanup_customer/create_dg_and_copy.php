<?php

$dirname = dirname(__FILE__);

// load PAN-OS-PHP library
require_once($dirname."/../../../lib/pan_php_framework.php");
require_once $dirname."/../../../utils/lib/UTIL.php";


$filename = "panorama.xml";



$cli = "php ".$dirname."/../../../utils/pan-os-php.php type=upload in=firewall.xml out=panorama.xml 'fromXpath=/config/shared/*' 'toXpath=/config/shared'";

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

/*
for( $i = 1; $i < 29; $i++ )
{
    $dirname = dirname(__FILE__);

    /*
    $cli = "php ".$dirname."/../../../utils/pan-os-php.php type=device in=".$filename." out=".$filename." actions=devicegroup-create:vsys".$i."";

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
    */

    //----------------

/*
    $cli = "php ".$dirname."/../../../utils/pan-os-php.php type=upload in=firewall.xml out=panorama.xml 'fromXpath=/config/devices/entry[@name=\"localhost.localdomain\"]/vsys/entry[@name=\"vsys".$i."\"]/*' 'toXpath=/config/devices/entry/device-group/entry[@name=\"vsys".$i."\"]'";

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
*/