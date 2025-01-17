<?php


$panOSversion_array = array();

//-------------------------------------
$panOSversion_array[10] = array();
$panOSversion_array[10][1] = array();
$panOS_version = &$panOSversion_array[10][1];
$panOS_version[0] = false;
$panOS_version[1] = false;
$panOS_version[2] = false;
$panOS_version[3] = false;
$panOS_version[4] = false;
$panOS_version[5] = false;
$panOS_version[6] = false;
$panOS_version[7] = false;
$panOS_version[8] = false;
$panOS_version[9] = false;
$panOS_version[10] = false;
$panOS_version[11] = false;
$panOS_version[12] = false;
$panOS_version[13] = false;
$panOS_version[14] = true;


$panOSversion_array[10][2] = array();
$panOS_version = &$panOSversion_array[10][2];
$panOS_version[0] = false;
$panOS_version[1] = false;
$panOS_version[2] = false;
$panOS_version[3] = false;
$panOS_version[4] = false;
$panOS_version[5] = false;
$panOS_version[6] = false;
$panOS_version[7] = false;
$panOS_version[8] = false;
$panOS_version[9] = false;
$panOS_version[10] = false;
$panOS_version[11] = false;
$panOS_version[12] = false;
$panOS_version[13] = true;

//-------------------------------------------------------
$panOSversion_array[11] = array();
$panOSversion_array[11][1] = array();
$panOS_version = &$panOSversion_array[11][1];
$panOS_version[0] = false;
$panOS_version[1] = false;
$panOS_version[2] = false;
$panOS_version[3] = false;
$panOS_version[4] = false;
$panOS_version[5] = false;
$panOS_version[6] = true;


$panOSversion_array[11][2] = array();
$panOS_version = &$panOSversion_array[11][2];
$panOS_version[0] = false;
$panOS_version[1] = false;
$panOS_version[2] = false;
$panOS_version[3] = false;
$panOS_version[4] = true;




$release_notes_links = array();
foreach( $panOSversion_array as $Version => $majorVersionArray )
{
    foreach( $majorVersionArray as $majorVersion => $minorVersionArray )
    {
        foreach( $minorVersionArray as $minorVersion => $enabled )
        {
            #if( $enabled ) {
                $mainVersion = $Version."-".$majorVersion;
                $subVersion = $mainVersion."-".$minorVersion;

                $string = "https://docs.paloaltonetworks.com/pan-os/".$mainVersion."/pan-os-release-notes/pan-os-".$subVersion."-known-and-addressed-issues/pan-os-".$subVersion."-known-issues";
                $release_notes_links[] = $string;
                requestKnownIssueHTML( $string );
            #}
        }
    }
}


function requestKnownIssueHTML( $url )
{
    #print $url."\n";

    // Use basename() function to return the base name of file
    $file_name = basename($url);
    $directory = dirname(__FILE__) . "/../../../lib/resources/panos_release_notes/known_issues/";
    // Use file_get_contents() function to get the file
    // from url and use file_put_contents() function to
    // save the file by using base name

    if (!file_exists($directory.'html')) {
        mkdir($directory.'html', 0777, true);
    }

    if (file_put_contents($directory."html/".$file_name, file_get_contents($url)))
    {
        #print "File downloaded successfully\n";
    }
    else
    {
        print "File downloading failed.\n";
    }
}