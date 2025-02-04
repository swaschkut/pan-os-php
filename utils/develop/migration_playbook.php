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

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../lib/pan_php_framework.php";

require_once("utils/common/actions.php");
require_once dirname(__FILE__)."/../../utils/lib/UTIL.php";

require_once("parser/lib/CONVERTER.php");
require_once("parser/lib/PARSER.php");
require_once("parser/lib/SHAREDNEW.php");

###############################################################################
//migration playbook arguments
###############################################################################
//NEEDED??????     please input a JSON or something else which define all part for the playbook

PH::processCliArgs();

if( isset(PH::$args['vendor']) )
{
    $vendor = PH::$args['vendor'];
}

if( isset(PH::$args['file']) )
{
    $file = PH::$args['file'];
}

if( isset(PH::$args['in']) )
{
    $input = PH::$args['in'];
}

//define out to save the final file into this file
if( isset(PH::$args['out']) )
{
    $output = PH::$args['out'];
}
###############################################################################
###############################################################################
$pa_migration_parser = "parser";
$pa_address_edit = "address";
$pa_service_edit = "service";
$pa_tag_edit = "tag";
$pa_zone_edit = "zone";
$pa_rule_edit = "rule";
$pa_rule_stats = "stats";

$pa_address_merger = "address-merger";
$pa_addressgroup_merger = "addressgroup-merger";
$pa_service_merger = "service-merger";
$pa_servicegroup_merger = "servicegroup-merger";
$pa_tag_merger = "tag-merger";

###############################################################################
//MIGRATION PLAYBOOK
###############################################################################
//interactive script needed:
//1) ask for type of script
//2) ask for all supported arguments and continue there:


$command_array = array();
$command_array[] = array( $pa_migration_parser, "vendor=".$vendor, "file=".$file, "stats" );
$command_array[] = array( $pa_rule_stats );
$command_array[] = array( $pa_address_edit, "location=vsys1", "actions=display", "filter=(object is.unused.recursive)", "stats" );
#$command_array[] = array( $pa_address_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );
#$command_array[] = array( $pa_addressgroup_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );
#$command_array[] = array( $pa_service_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );
#$command_array[] = array( $pa_servicegroup_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );
#$command_array[] = array( $pa_tag_merger, "location=any", "allowmergingwithupperlevel", "shadow-ignoreInvalidAddressObjects", "stats" );

/*
pa_address-edit  in=fixed.xml out=improved.xml location=any actions=replace-IP-by-MT-like-Object  shadow-ignoreInvalidAddressObjects 'filter=(object is.tmp)' | tee log_transform_IP_to_Object.txt
pa_address-merger in=improved.xml out=improved.xml location=any allowmergingwithupperlevel shadow-ignoreInvalidAddressObjects | tee address-merger.txt
pa_addressgroup-merger in=improved.xml out=improved.xml location=any allowmergingwithupperlevel shadow-ignoreInvalidAddressObjects | tee addressgroup-merger.txt
pa_service-merger in=improved.xml out=improved.xml location=any allowmergingwithupperlevel shadow-ignoreInvalidAddressObjects | tee service-merger.txt
pa_servicegroup-merger in=improved.xml out=improved.xml location=any allowmergingwithupperlevel shadow-ignoreInvalidAddressObjects | tee servicegroup-merger.txt
 */


###############################################################################
//VARIABLE DECLARATION
###############################################################################
$stage_name = "stage";






###############################################################################
//EXECUTION
###############################################################################


$out = "";
$in = "";



foreach( $command_array as $key => $command )
{
    $arguments = array();
    $arguments[0] = "migration_playbook";

    $script = $command[0];
    unset( $command[0] );
    $arg_string = "";


    foreach( $command as $arg )
        $arguments[] = $arg;



    ###############################################################################
    //IN / OUT specification
    ###############################################################################
    if( $key == 0 && $script == $pa_migration_parser )
        $out_counter = 0;
    elseif( $key > 0 )
    {
        $in = $out;

        if( $script != $pa_rule_stats )
            $out_counter++;
    }


    if( $script != $pa_migration_parser )
        $arguments[] = "in=".$in;

    if( $script != $pa_rule_stats )
        $arguments[] = "out=".$stage_name.$out_counter.".xml";


    PH::resetCliArgs( $arguments);


    if( $script == $pa_rule_edit )
    {
        $tool = "pa_rule-edit";
        print_tool_usage( $tool, PH::$argv );
        $util = new RULEUTIL($script, $argv, $argc, $tool);
    }
    elseif( $script == $pa_migration_parser )
    {
        $tool = "pa_migration-parser";
        print_tool_usage( $tool, PH::$argv );
        $converter = new CONVERTER(  );
    }
    elseif( $script == $pa_rule_stats )
    {
        $tool = "pa_rule-stats";
        print_tool_usage( $tool, PH::$argv );
        $stats = new STATSUTIL( $script, $argv, $argc, $tool );
    }
    elseif( $script == $pa_rule_edit )
    {
        $tool = "pa_rule-edit";
        print_tool_usage( $tool, PH::$argv );
        $util = new RULEUTIL($script, $argv, $argc, $tool);
    }
    else
    {
        $tool = "pa_".$script."-edit";
        print_tool_usage( $tool, PH::$argv );
        $util = new UTIL($script, $argv, $argc, $tool );
    }

    PH::print_stdout();
    PH::print_stdout( "############################################################################");
    PH::print_stdout();

}

if( isset(PH::$args['out']) )
{
//now save the latest out= from the foreach loop "$out" into "$output" file;
    copy( $out, $output );
}




function print_tool_usage( $tool, $argv )
{
    PH::print_stdout();
    PH::print_stdout( PH::boldText( "[ ".$tool. " ".implode( " ", $argv )." ]" ) );
    PH::print_stdout();
}