<?php

require_once dirname(__FILE__)."/../../../../lib/resources/panos_release_notes/classes/panos_release_misc.php";

class panos_release_notes
{
    public $version_store = array();
    public $type;

    public $knownIssues = array();
    public $fixedIssues = array();

    function __construct( $type = "known")
    {
        $directory = dirname(__FILE__);

        $this->type = $type;

        if( $this->type == "known" )
        {
            //list all files from known_issues/json
            if(!file_exists($directory."/../known_issues/json") )
            {
                //download HTML files
                panos_release_misc::request_html();

                //create JSON files
                panos_release_misc::displayJSON();
            }
            $scanned_directory = array_diff(scandir($directory."/../known_issues/json"), array('..', '.'));

            #print_r($scanned_directory);

            foreach( $scanned_directory as $file )
            {
                $fileName = str_replace( "pan-os-", "", $file );
                $version_string = str_replace( "-known-issues", "", $fileName );
                $tmp_version_string = str_replace("-", ".", $version_string);

                $tmpVersion = new panos_version( $this, "known", $version_string, $directory."/../known_issues/json/", $scanned_directory );

                $this->version_store[$tmp_version_string] = $tmp_version_string;
            }
        }
        elseif( $this->type == "fixed" )
        {
            //list all files from known_issues/json
            $scanned_directory = array_diff(scandir($directory."/../fixed_issues/json"), array('..', '.'));

            print_r($scanned_directory);
        }
    }


}