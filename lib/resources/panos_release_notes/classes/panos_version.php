<?php

class panos_version
{
    public $owner;

    public $type;
    public $version;
    public $directory;

    public $scanned_directory = array();

    #public $knownIssues = array();
    #public $fixedIssues = array();


    function __construct( $owner, $type, $version_string, $directory, $scanned_directory )
    {
        $this->owner = $owner;

        $this->type = $type;
        $this->version = $version_string;
        $this->directory = $directory;

        $this->scanned_directory = $scanned_directory;



        #print "VERSION: $version_string\n";

        if( $this->type == "known" )
        {
            $known_file = file_get_contents( $directory."pan-os-".$version_string."-known-issues" );

            $data = json_decode($known_file, TRUE);

            foreach( $data[$version_string] as $issue )
            {
                foreach( $issue as $issueNumber => $issue_details )
                {
                    if( isset($this->owner->knownIssues[$issueNumber]) )
                    {
                        //add Version
                        $this->owner->knownIssues[$issueNumber]->version_listed[$version_string] = $version_string;


                        if( isset($issueDetails['solved']) )
                            $this->owner->knownIssues[$issueNumber]->solved = $issueDetails['solved'];
                    }
                    else
                    {
                        $known_issue_obj = new panos_known_issue( $this, $issueNumber, $issue_details );
                        #$this->knownIssues[$issueNumber] = $known_issue_obj;

                        $this->owner->knownIssues[$issueNumber] = $known_issue_obj;
                    }
                }
            }


        }


    }


}