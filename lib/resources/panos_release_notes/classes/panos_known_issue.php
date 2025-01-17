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
        $this->version_listed[$owner->version] = $owner->version;

        $this->info = $issueDetails['info'][0];

        if( isset($issueDetails['solved']) )
            $this->solved = $issueDetails['solved'];
    }

}