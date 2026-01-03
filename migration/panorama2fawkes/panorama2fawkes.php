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

$version = "1.12";
$versionDate = "2022-09-30";

if( !in_array ( "testing", $argv ) && !in_array ( "shadow-json", $argv ) )
    $argv[] = "shadow-json";


require_once("lib/pan_php_framework.php");
require_once("utils/lib/UTIL.php");

require_once ("migration/panorama2fawkes/lib/Panorama2Fawkes.php");


PH::print_stdout( "***********************************************");
PH::print_stdout( "************ Panorama2Fawkes migration ****************");


$pan2faw = new Panorama2Fawkes();

if( in_array("version", $argv) )
{
    PH::$JSON_TMP["version"] = $version;
    PH::$JSON_TMP["versiondate"] = $versionDate;
    PH::print_stdout(PH::$JSON_TMP, true);
    PH::$JSON_TMP = array();

    print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
    exit();
}

if( !in_array("help", $argv) )
    $argv = $pan2faw->run_cleanup_script( $argv );

if( !in_array ( "shadow-ignoreInvalidAddressObjects", $argv ) )
    $argv[] = "shadow-ignoreInvalidAddressObjects";

#if( !in_array ( "versionmigration", $argv ) )
#    $argv[] = "versionmigration";

$pan2faw->main( $argv, $argc );


if( PH::$shadow_json )
{
    PH::$JSON_OUT['log'] = PH::$JSON_OUTlog;
    print json_encode( PH::$JSON_OUT, JSON_PRETTY_PRINT );
}
