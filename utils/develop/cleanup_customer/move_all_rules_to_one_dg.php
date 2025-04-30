<?php

$dirname = dirname(__FILE__);

// load PAN-OS-PHP library
require_once($dirname."/../../../lib/pan_php_framework.php");
require_once $dirname."/../../../utils/lib/UTIL.php";


$filename = "panorama_final.xml";



$cli = "php ".$dirname."/../../../utils/pan-os-php.php type=device in=".$filename." out=".$filename." actions=devicegroup-create:final";

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


for( $i = 1; $i < 29; $i++ )
{
    $dirname = dirname(__FILE__);





    //----------------


    $cli = "php ".$dirname."/../../../utils/pan-os-php.php type=rule in=".$filename." out=".$filename." location=vsys".$i." actions=move:final";

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
