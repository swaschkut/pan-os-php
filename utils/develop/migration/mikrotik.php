<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
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


###################################################################################
###################################################################################
//Todo: possible to bring this in via argument
//CUSTOM variables for the script


$print = false;

###################################################################################
###################################################################################

print "\n***********************************************\n";
print "************ Mikrotik UTILITY ****************\n\n";

set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";
#require_once("lib/pan_php_framework.php");
#require_once ( "utils/lib/UTIL.php");


$file = null;

$supportedArguments = Array();
$supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
$supportedArguments['out'] = Array('niceName' => 'out', 'shortHelp' => 'output file to save config after changes. Only required when input is a file. ie: out=save-config.xml', 'argDesc' => '[filename]');
$supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');
$supportedArguments['file'] = Array('niceName' => 'FILE', 'shortHelp' => 'BlueCoat config file, export via CLI: ""');
$supportedArguments['location'] = Array('niceName' => 'Location', 'shortHelp' => 'specify if you want to limit your query to a VSYS/DG. By default location=shared for Panorama, =vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
$supportedArguments['loadxmlfromfile'] = Array('niceName' => 'loadxmlfromfile', 'shortHelp' => 'do not load from memory, load from newly generated XML file during execution');


$usageMsg = PH::boldText('USAGE: ')."php ".basename(__FILE__)." in=[PAN-OS base config file] file=[PULSE xml config file] [out=]";


function strip_hidden_chars($str)
{
    $chars = array("\r\n", "\n", "\r", "\t", "\0", "\x0B");

    $str = str_replace($chars,"",$str);

    #return preg_replace('/\s+/',' ',$str);
    return $str;
}

if( !isset(PH::$args['in'])  )
    PH::$args['in'] = dirname(__FILE__)."/panos_baseconfig.xml";


$util = new UTIL( "custom", $argv, $argc, __FILE__, $supportedArguments, $usageMsg );
$util->utilInit();

##########################################
##########################################

if( isset(PH::$args['file'])  )
    $file = PH::$args['file'];
else
    derr( "argument file not set" );



$util->load_config();
#$util->location_filter();
#$location = $util->objectsLocation[0];


$location = $util->objectsLocation;

$pan = $util->pan;


print "location: ".$location."\n";

if( $util->configType == 'panos' )
{
    // Did we find VSYS1 ?
    $v = $pan->findVirtualSystem( $location );
    if( $v === null )
        derr( $util->$location." was not found ? Exit\n");
}
elseif( $util->configType == 'panorama' )
{
    $v = $pan->findDeviceGroup( $location );
    if( $v == null )
        $v = $pan->createDeviceGroup( $location );
}
elseif( $util->configType == 'fawkes' )
{
    $v = $pan->findContainer( $location );
    if( $v == null )
        $v = $pan->createContainer( $location );
}


##########################################

//read file to string
$filename = $file;




$addressObjectArray = array();
$addressMissingObjects = array();

$serviceObjectArray = array();
$serviceMissingObjects = array();

$userObjectArray = array();
$userMissingObjects = array();

$policyGroupObjectArray = array();
$policyGroupMissingObjects = array();

$missingURL = array();


#######################################################




// 2. Process the file
$data = parseMikroTikConfig($filename);

// 3. Output the result
print_r($data);

/**
 * Main Parsing Logic
 */





#######################################################

function parseMikroTikConfig($filePath) {
    $config = [];
    $currentSection = '';
    $lines = file($filePath, FILE_IGNORE_NEW_LINES);

    $buffer = "";
    $processedLines = [];

    // Step A: Join lines ending with "\"
    foreach ($lines as $line) {
        $trimmedLine = trim($line);
        if (str_ends_with($trimmedLine, '\\')) {
            $buffer .= substr($trimmedLine, 0, -1);
            continue;
        } else {
            $buffer .= $trimmedLine;
            if ($buffer !== "") {
                $processedLines[] = $buffer;
            }
            $buffer = "";
        }
    }

    // Step B: Build the Array
    foreach ($processedLines as $line) {
        if (str_starts_with($line, '#')) continue;

        // New Section (e.g., /ip address)
        if (str_starts_with($line, '/')) {
            $currentSection = trim(substr($line, 1));
            continue;
        }

        // Parse Action (add or set)
        if (preg_match('/^(add|set|edit)\s+(.*)$/', $line, $matches)) {
            $attributesRaw = $matches[2];
            $item = parseAttributes($attributesRaw);
            $config[$currentSection][] = $item;
        }
    }

    return $config;
}

/**
 * Regex Helper to split key=value pairs
 */
function parseAttributes($string) {
    $attributes = [];
    // This regex handles: key=value, key="value with spaces", and [ find ... ]
    $pattern = '/(\S+)=("[^"]*"|\[[^\]]*\]|\S+)|(\S+)/';
    preg_match_all($pattern, $string, $matches, PREG_SET_ORDER);

    foreach ($matches as $match) {
        if (isset($match[1]) && $match[1] !== "") {
            $key = $match[1];
            $val = trim($match[2], '"');
            $attributes[$key] = $val;
        } else {
            // Standalone flags (like 'disabled' or 'passive')
            $attributes[$match[0]] = true;
        }
    }
    return $attributes;
}

function print_xml_info( $appx3, $print = false )
{
    $appName3 = $appx3->nodeName;

    if( $print )
        print "|13:|" . $appName3 . "\n";

    $newdoc = new DOMDocument;
    $node = $newdoc->importNode($appx3, TRUE);
    $newdoc->appendChild($node);
    $html = $newdoc->saveHTML();

    if( $print )
        print "|" . $html . "|\n";
}


function truncate_names($longString) {
    global $source;
    $variable = strlen($longString);

    if ($variable < 63) {
        return $longString;
    } else {
        $separator = '';
        $separatorlength = strlen($separator);
        $maxlength = 63 - $separatorlength;
        $start = $maxlength;
        $trunc = strlen($longString) - $maxlength;
        $salida = substr_replace($longString, $separator, $start, $trunc);

        if ($salida != $longString) {
            //Todo: swaschkut - xml attribute adding needed
            #add_log('warning', 'Names Normalization', 'Object Name exceeded >63 chars Original:' . $longString . ' NewName:' . $salida, $source, 'No Action Required');
        }
        return $salida;
    }
}

function normalizeNames($nameToNormalize) {
    $nameToNormalize = trim($nameToNormalize);
    //$nameToNormalize = preg_replace('/(.*) (&#x2013;) (.*)/i', '$0 --> $1 - $3', $nameToNormalize);
    //$nameToNormalize = preg_replace("/&#x2013;/", "-", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\/]+/", "_", $nameToNormalize);
    $nameToNormalize = preg_replace("/[^a-zA-Z0-9-_. ]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/[\s]+/", " ", $nameToNormalize);

    $nameToNormalize = preg_replace("/^[-]+/", "", $nameToNormalize);
    $nameToNormalize = preg_replace("/^[_]+/", "", $nameToNormalize);

    $nameToNormalize = preg_replace('/\(|\)/','',$nameToNormalize);

    return $nameToNormalize;
}

function find_string_between($line, $needle1, $needle2 = "--END--")
{
    $needle_length = strlen($needle1);
    $pos1 = strpos($line, $needle1);

    if( $needle2 !== "--END--" )
        $pos2 = strpos($line, $needle2);
    else
        $pos2 = strlen($line);

    $finding = substr($line, $pos1 + $needle_length, $pos2 - ($pos1 + $needle_length));

    return $finding;
}

##################################################################

/*

$configInput = array();
$configInput['type'] = 'file';
$configInput['filename'] = $util->configInput;

CONVERTER::rule_merging( $v, $configInput, true, false, false, "tag", array( "1", "3" ) );
*/

print "\n\n\n";

$util->save_our_work();

print "\n\n************ END OF TMG UTILITY ************\n";
print     "**************************************************\n";
print "\n\n";

