<?php


/*
// this script is to prepare test XML file with log information,
// the information is normally generated in production with script report-generator.php against PAN-OS XML API
 */

require_once("lib/pan_php_framework.php");

$timezone_name = "GMT";
date_default_timezone_set( $timezone_name );

$unix_timestamp = time();
$date =  date('d-F-Y H:i');

$stats_filename = "0123456789-vsys1-stats_blank.xml";

$stats_file = file_get_contents($stats_filename);

$stats_file1 = str_replace( "{unix-timestamp}", $unix_timestamp, $stats_file );
$stats_file2 = str_replace( "{date}", $date, $stats_file1 );



$filename = "../0123456789-vsys1-stats.xml";
file_put_contents($filename, $stats_file2);


#pan-os-php type=tag loadplugin=plugin_tag_rename.php actions=name-rename-appid-toolbox 'filter=(name regex /appid#activated#/)' in=../compare/stage15.xml out=../compare/stage15.xml
#pan-os-php type=tag loadplugin=plugin_tag_rename.php actions=name-rename-appid-toolbox 'filter=(name regex /appid#activated#/)' in=../compare/stage20.xml out=../compare/stage20.xml
$dirname = dirname(__FILE__);

$cli_array[] = "php ".$dirname."/../../../utils/pan-os-php.php type=tag loadplugin=plugin_tag_rename.php actions=name-rename-appid-toolbox 'filter=(name regex /appid#activated#/)' in=../compare/stage15.xml out=../compare/stage15.xml";
$cli_array[] = "php ".$dirname."/../../../utils/pan-os-php.php type=tag loadplugin=plugin_tag_rename.php actions=name-rename-appid-toolbox 'filter=(name regex /appid#activated#/)' in=../compare/stage20.xml out=../compare/stage20.xml";

foreach( $cli_array as $cli )
{
    $cli .= ' 2>&1';

    PH::print_stdout( " * Executing CLI: {$cli}" );

    $output = Array();
    $retValue = 0;

    exec($cli, $output, $retValue);

    foreach($output as $line)
    {
        $string =  '   ##  ';
        $string .= $line;
        PH::print_stdout( $string );
    }

    if( $retValue != 0 )
        derr("CLI exit with error code '{$retValue}'");

    PH::print_stdout(  "");
}