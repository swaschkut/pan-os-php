<?php
/**
 * ISC License
 *
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

$dirname = dirname(__FILE__);

// load PAN-OS-PHP library
require_once($dirname."/../../../lib/pan_php_framework.php");
require_once $dirname."/../../../utils/lib/UTIL.php";


//---------------------------------------------

$filename = "panorama_final.xml";
$final_DG_name = "final";

//---------------------------------------------

//Task1 - create DG with $final_DG_name
$cli = "php ".$dirname."/../../../utils/pan-os-php.php type=device in=".$filename." out=".$filename." actions=devicegroup-create:".$final_DG_name;

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

//---------------------------------------------

//Task2 - move for DG name vsys{X}, to DG $final_DG_name

//Todo: parse input Panorama config -> get all Devicegroups, use these DeviceGroups as $locationname
for( $i = 1; $i <= 29; $i++ )
{
    $locationname = "vsys".$i;

    $cli = "php ".$dirname."/../../../utils/pan-os-php.php type=rule in=".$filename." out=".$filename." location=".$locationname." actions=move:".$final_DG_name;

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

//---------------------------------------------