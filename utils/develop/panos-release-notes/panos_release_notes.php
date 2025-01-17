<?php


set_include_path(dirname(__FILE__) . '/../../../' . PATH_SEPARATOR . get_include_path());


require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_release_notes.php";




require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_known_issue.php";
require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_fixed_issue.php";
require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_version.php";



$releaseNotes = new panos_release_notes( "known" );

$filterVersion = true;
$filterVersionTxt = "11-1";

$filterInfo = true;
$filterInfoTxt = "IPv6";

foreach($releaseNotes->knownIssues as $issue)
{
    if( $filterVersion && $filterInfo )
    {
        if( filterVersion($issue, $filterVersionTxt ) && filterInfo($issue, $filterInfoTxt ) )
            display_Issue($issue);
    }
    elseif( $filterVersion )
    {
        if( filterVersion($issue, $filterVersionTxt ) )
            display_Issue($issue);
    }
    elseif( $filterInfo )
    {
        if( filterInfo($issue, $filterInfoTxt ) )
            display_Issue($issue);
    }
}


function display_Issue( $issue)
{
    $padding = "   ";
    print "--------------------\n";

    print "ISSUE: ".$issue->issueNumber."\n";
    print $padding."INFO: ".$issue->info."\n";


    print $padding."VERSION: \n";
    print_r( $issue->version_listed );

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
        if( str_contains($version, $subVersion) )
            return true;
    }
    return false;
}

function filterInfo($issue, $infoFilterTxt )
{
    if( str_contains($issue->info, $infoFilterTxt) )
            return true;

    return false;
}