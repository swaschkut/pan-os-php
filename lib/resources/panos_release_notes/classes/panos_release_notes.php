<?php

require_once dirname(__FILE__)."/../../../../lib/resources/panos_release_notes/classes/panos_release_misc.php";

class panos_release_notes
{
    public $version_store = array();
    public $type;

    public $updatehtml = false;
    public $updatejson = false;

    public $knownIssues = array();
    public $addressedIssues = array();

    function __construct( $type = "known", $updatehtml = false, $updatejson = false )
    {
        $directory = dirname(__FILE__);


        $this->updatehtml = $updatehtml;
        $this->updatejson = $updatejson;


        ########################################
        $this->type = "known";
        //list all files from known_issues/json
        if(!file_exists($directory."/../".$this->type."_issues/html") || $this->updatehtml)
        {
            //download HTML files
            panos_release_misc::request_html( $this->type );
        }
        if(!file_exists($directory."/../".$this->type."_issues/json") || $this->updatejson)
        {
            //create JSON files
            panos_release_misc::displayJSON($this->type);
        }
        $scanned_directory = array_diff(scandir($directory."/../".$this->type."_issues/json"), array('..', '.'));

        #print_r($scanned_directory);

        foreach( $scanned_directory as $file )
        {
            $fileName = str_replace( "pan-os-", "", $file );
            $version_string = str_replace( "-".$this->type."-issues", "", $fileName );
            $tmp_version_string = str_replace("-h", "_h", $version_string);
            $tmp_version_string = str_replace("-", ".", $tmp_version_string);
            $tmp_version_string = str_replace("_h", "-h", $tmp_version_string);


            $tmpVersion = new panos_version( $this, $this->type, $version_string, $directory."/../".$this->type."_issues/json/", $scanned_directory );

            $this->version_store[$tmp_version_string] = $tmp_version_string;
        }


        ###########################################
        $this->type = "addressed";
        //list all files from known_issues/json
        if(!file_exists($directory."/../".$this->type."_issues/html") || $this->updatehtml)
        {
            //download HTML files
            panos_release_misc::request_html( $this->type );
        }
        if(!file_exists($directory."/../".$this->type."_issues/json") || $this->updatejson)
        {
            //create JSON files
            panos_release_misc::displayJSON($this->type);
        }
        $scanned_directory = array_diff(scandir($directory."/../".$this->type."_issues/json"), array('..', '.'));

        #print_r($scanned_directory);

        foreach( $scanned_directory as $file )
        {
            $fileName = str_replace( "pan-os-", "", $file );
            $version_string = str_replace( "-".$this->type."-issues", "", $fileName );
            $tmp_version_string = str_replace("-h", "_h", $version_string);
            $tmp_version_string = str_replace("-", ".", $tmp_version_string);
            $tmp_version_string = str_replace("_h", "-h", $tmp_version_string);


            $tmpVersion = new panos_version( $this, $this->type, $version_string, $directory."/../".$this->type."_issues/json/", $scanned_directory );

            $this->version_store[$tmp_version_string] = $tmp_version_string;
        }
    }
}