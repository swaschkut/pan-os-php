<?php


#set_include_path(dirname(__FILE__) . '/../../../' . PATH_SEPARATOR . get_include_path());

set_include_path(get_include_path() . PATH_SEPARATOR . dirname(__FILE__) . '/../');

require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";
require_once dirname(__FILE__)."/../../../utils/lib/UTIL.php";

PH::processCliArgs();

require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_release_notes.php";




require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_known_issue.php";
require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_addressed_issue.php";
require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_version.php";



$updateHtml = false;
$updateJson = false;
$updateMissing = true;

#$type= "known";
#$type= "addressed";


$filterVersion = false;
if( isset(PH::$args['version']) )
{
    $filterVersion = true;
    $filterVersionTxt = PH::$args['version'];

    #$filterVersionTxt = str_replace(".", "-", $filterVersionTxt);
}


$filterInfo = false;
if( isset(PH::$args['description']) )
{
    $filterInfo = true;
    $filterInfoTxt = PH::$args['description'];
    $filterInfoTxt = strtolower($filterInfoTxt);
}

$filterBugID = false;
if( isset(PH::$args['bugid']) )
{
    $filterBugID = true;
    $filterBugIDTxt = PH::$args['bugid'];
    $filterBugIDTxt = strtolower($filterBugIDTxt);
}


$releaseNotes = new panos_release_notes("known", $updateHtml, $updateJson);

$typeArray = array( "known", "addressed" );
foreach( $typeArray as $type )
{
    #$releaseNotes = new panos_release_notes($type, $updateHtml, $updateJson);
    $displayCounter = 0;
    PH::print_stdout("#################################################");
    PH::print_stdout($type." Issues:");
    if( $type == "known" )
        $releaseNotesObjects = $releaseNotes->knownIssues;
    elseif( $type == "addressed" )
        $releaseNotesObjects = $releaseNotes->addressedIssues;

    foreach ( $releaseNotesObjects as $issue)
    {
        $addressed_issue = null;
        if( $type == "known" )
        {
            if( isset($releaseNotes->addressedIssues[$issue->issueNumber]) )
            {
                $addressed_issue = $releaseNotes->addressedIssues[$issue->issueNumber];
            }
        }

        if ($filterVersion && $filterInfo && $filterBugID)
        {
            if (filterVersion($issue, $filterVersionTxt) && filterInfo($issue, $filterInfoTxt) && filterBugID($issue, $filterBugIDTxt))
            {
                display_Issue($issue, $addressed_issue);
                $displayCounter++;
            }
        }
        elseif ($filterVersion && $filterInfo)
        {
            if (filterVersion($issue, $filterVersionTxt) && filterInfo($issue, $filterInfoTxt))
            {
                display_Issue($issue, $addressed_issue);
                $displayCounter++;
            }
        }
        elseif ($filterVersion && $filterBugID)
        {
            if (filterVersion($issue, $filterVersionTxt) && filterBugID($issue, $filterBugIDTxt))
            {
                display_Issue($issue, $addressed_issue);
                $displayCounter++;
            }
        }
        elseif ($filterInfo && $filterBugID)
        {
            if (filterInfo($issue, $filterInfoTxt) && filterBugID($issue, $filterBugIDTxt))
            {
                display_Issue($issue, $addressed_issue);
                $displayCounter++;
            }
        }
        elseif ($filterVersion)
        {
            if (filterVersion($issue, $filterVersionTxt))
            {
                display_Issue($issue, $addressed_issue);
                $displayCounter++;
            }
        }
        elseif ($filterInfo)
        {
            if (filterInfo($issue, $filterInfoTxt))
            {
                display_Issue($issue, $addressed_issue);
                $displayCounter++;
            }
        }
        elseif ($filterBugID)
        {
            if (filterBugID($issue, $filterBugIDTxt))
            {
                display_Issue($issue, $addressed_issue);
                $displayCounter++;
            }
        }
        else
        {
            display_Issue($issue, $addressed_issue);
            $displayCounter++;
        }
    }

    PH::print_stdout("Counter: " . $displayCounter);

    PH::print_stdout("");
    PH::print_stdout("");
}

####################################


function display_Issue( $issue, $addressed_issue)
{
    $padding = "   ";
    print "--------------------\n";

    print "ISSUE: '".$issue->issueNumber."'\n";
    print $padding."INFO: ".$issue->info."\n";


    if( $issue->type == "known" )
        print $padding."Known in VERSION: ";
    elseif( $issue->type == "addressed" )
        print $padding."FIXED in VERSION: ";
    print implode( ", ", $issue->version_listed)."\n";

    if( isset($issue->solved_issue) )
    {
        print $padding. "SOLVED ISSUE: ".$issue->solved_issue."\n";
    }

    if( $addressed_issue !== null )
    {
        print $padding."FIXED in VERSION: ";
        print implode( ", ", $addressed_issue->version_listed)."\n";
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
    if( strpos(strtolower($issue->info), $infoFilterTxt) !== FALSE )
        return true;

    return false;
}

function filterBugID($issue, $bugIDFilter )
{
    #if( str_contains($issue->info, $infoFilterTxt) )
    if( strpos($issue->issueNumber, $bugIDFilter) !== FALSE )
        return true;

    return false;
}