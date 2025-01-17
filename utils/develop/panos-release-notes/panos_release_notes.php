<?php


set_include_path(dirname(__FILE__) . '/../../../' . PATH_SEPARATOR . get_include_path());


require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_release_notes.php";




require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_known_issue.php";
require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_fixed_issue.php";
require_once dirname(__FILE__)."/../../../lib/resources/panos_release_notes/classes/panos_version.php";



$releaseNotes = new panos_release_notes( "known" );



foreach($releaseNotes->knownIssues as $issue)
{
    print "--------------------\n";

    print "ISSUE: ".$issue->issueNumber."\n";
    print "INFO: ".$issue->info."\n";


    print "VERSION: \n";
    print_r( $issue->version_listed );

    if( isset($issue->solved_issue) )
    {
        print "SOLVED ISSUE: ".$issue->solved_issue."\n";
    }

}


