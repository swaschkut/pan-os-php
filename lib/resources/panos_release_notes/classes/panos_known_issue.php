<?php

class panos_known_issue
{
    public $owner;
    public $info;
    public $issueNumber;
    public $solved;

    public $version_listed;

    function __construct( $owner,  $issueNumber, $issueDetails )
    {
        $this->owner = $owner;

        $this->issueNumber = $issueNumber;
        $tmp_version_string = $owner->version;
        $tmp_version_string = str_replace("-", ".", $tmp_version_string);
        $this->version_listed[$tmp_version_string] = $tmp_version_string;

        $this->info = $issueDetails['info'][0];

        if( isset($issueDetails['solved']) )
            $this->solved = $issueDetails['solved'];
    }

}