<?php


#set_include_path(dirname(__FILE__) . '/../../../' . PATH_SEPARATOR . get_include_path());

set_include_path(get_include_path() . PATH_SEPARATOR . dirname(__FILE__) . '/../');

require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";

PH::processCliArgs();

require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_release_notes.php";




require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_known_issue.php";
require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_fixed_issue.php";
require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_version.php";



$releaseNotes = new panos_release_notes( "known" );

$filterVersion = false;
if( isset(PH::$args['version']) )
{
    $filterVersion = true;
    $filterVersionTxt = PH::$args['version'];

    #$filterVersionTxt = str_replace(".", "-", $filterVersionTxt);
}


$filterInfo = false;
if( isset(PH::$args['text']) )
{
    $filterInfo = true;
    $filterInfoTxt = PH::$args['text'];
    $filterInfoTxt = strtolower($filterInfoTxt);
}

$displayCounter = 0;
foreach($releaseNotes->knownIssues as $issue)
{
    if( $filterVersion && $filterInfo )
    {
        if( filterVersion($issue, $filterVersionTxt ) && filterInfo($issue, $filterInfoTxt ) )
        {
            display_Issue($issue);
            $displayCounter++;
        }
    }
    elseif( $filterVersion )
    {
        if( filterVersion($issue, $filterVersionTxt ) )
        {
            display_Issue($issue);
            $displayCounter++;
        }
    }
    elseif( $filterInfo )
    {
        if( filterInfo($issue, $filterInfoTxt ) )
        {
            display_Issue($issue);
            $displayCounter++;
        }
    }
    else
    {
        display_Issue($issue);
        $displayCounter++;
    }
}

PH::print_stdout("Counter: ".$displayCounter);

function display_Issue( $issue)
{
    $padding = "   ";
    print "--------------------\n";

    print "ISSUE: ".$issue->issueNumber."\n";
    print $padding."INFO: ".$issue->info."\n";


    print $padding."VERSION: ";
    print implode( ", ", $issue->version_listed)."\n";

    if( isset($issue->solved_issue) )
    {
        print $padding. "SOLVED ISSUE: ".$issue->solved_issue."\n";
    }
}

function filterVersion($issue, $subVersion )
{
    $versionArray = $issue->version_listed;
    $versionArrayKeys = array_keys($versionArray);
    foreach ($versionArrayKeys as $version)
    {
        //string contains is case sensitive
        #if( str_contains($version, $subVersion) )
        if( strpos($version, $subVersion) !== FALSE )
            return true;
    }
    return false;
}

function filterInfo($issue, $infoFilterTxt )
{
    #if( str_contains($issue->info, $infoFilterTxt) )
    if( strpos($issue->info, $infoFilterTxt) !== FALSE )
        return true;

    return false;
}