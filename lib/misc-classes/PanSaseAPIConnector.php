<?php

//Todo: swaschkut 20250117:
//check new Strata Cloud Manager adjusted part:
//https://pan.dev/scm/docs/release-notes/november2024/

//access policy:
//https://pan.dev/scm/api/iam/post-iam-v-1-access-policies/

class PanSaseAPIConnector
{
    public $name = 'connector';

    /** @var string */
    public $apikey;
    /** @var string */
    public $apihost;

    /** @var string */
    public $client_id;
    /** @var string */
    public $client_secret;
    /** @var string */
    public $scope;

    public $access_token;

    /** @var bool */
    public $showApiCalls = FALSE;

    public $global_limit = 200;


    private $_curl_handle = null;
    private $_curl_count = 0;


    /**
     * @var PanAPIConnector[]
     */
    static public $savedConnectors = array();
    static public $projectfolder = "";
    static private $keyStoreFileName = '.panconfkeystore';
    static private $keyStoreInitialized = FALSE;

    private $utilType = null;
    private $utilAction = "";

    public $url_token = "https://auth.apps.paloaltonetworks.com/oauth2/access_token";

    //FAWKES - Prisma Access Configuration
    #public $url_api = "https://api.sase.paloaltonetworks.com";
    //Strata Cloud Manager
    public $url_api = "https://api.strata.paloaltonetworks.com";


    static public $folderArray = array(
        "All",
        "Shared",
        "Mobile Users",
        "Remote Networks",
        "Service Connections",
        "Mobile Users Container",
        "Mobile Users Explicit Proxy"
    );

    private $typeArray = array();

    /**
     * @param string $host
     * @param string $key
     * @param string $type can be 'panos' 'panorama' or 'panos-via-panorama'
     * @param integer $port
     * @param string|null $serial
     */
    public function __construct($host, $key = null, $type = 'panos', $serial = null, $port = 443)
    {
        #$this->setType($type, $serial);

        $this->apikey = $key;
        $this->apihost = $host;

        $this->scope = "tsg_id:" . $host;
        if( $key != null )
        {
            $test = explode("%", $key);
            $this->client_id = $test[0];
            $this->client_secret = $test[1];
        }
        if( PH::$saseQAapi )
        {
            $this->url_token = "https://auth.qa.appsvc.paloaltonetworks.com/am/oauth2/access_token";
            $this->url_api = "https://qa.api.sase.paloaltonetworks.com";
        }
    }

    public function setUTILtype( $utilType)
    {
        $this->utilType = $utilType;
    }

    public function setUTILaction( $utilAction)
    {
        $this->utilAction = $utilAction;
    }

    public function setShowApiCalls($yes)
    {
        $this->showApiCalls = $yes;
    }

    public function isSaseAPI()
    {
        return TRUE;
    }

    public function isAPI()
    {
        return FALSE;
    }

    public function findOrCreateConnectorFromHost($TSGid)
    {
        //$host must be "tsg_id".TSG_ID
        $host = "tsg_id" . $TSGid;
        $connector = null;

        foreach(PanAPIConnector::$savedConnectors as $connector )
        {
            if( strpos($connector->apihost, $host) !== FALSE )
            {
                $key = $connector->apikey;
                $test = explode("%", $key);
                $this->client_id = $test[0];
                $this->client_secret = $test[1];
                break;
            }
            else
                $connector = null;
        }
        if( $connector === null )
        {
            PH::print_stdout(" ** Please enter client_id");
            $handle = fopen("php://stdin", "r");
            $line = fgets($handle);
            $this->client_id = trim($line);

            PH::print_stdout(" ** Please enter client_secret");
            $handle = fopen("php://stdin", "r");
            $line = fgets($handle);
            $this->client_secret = trim($line);

            $addHost = "tsg_id" . $TSGid;
            $key = $this->client_id . "%" . $this->client_secret;

            foreach(PanAPIConnector::$savedConnectors as $cIndex => $connector )
            {
                if( $connector->apihost == $addHost )
                    unset(PanAPIConnector::$savedConnectors[$cIndex]);
            }

            PanAPIConnector::$savedConnectors[] = new PanAPIConnector($addHost, $key);
            PanAPIConnector::saveConnectorsToUserHome();
        }
    }

    ///////CURL
    private function _createOrRenewCurl()
    {
        if( (PHP_MAJOR_VERSION <= 5 && PHP_MINOR_VERSION < 5) || $this->_curl_handle === null || $this->_curl_count > 100 )
        {
            if( $this->_curl_handle !== null )
                curl_close($this->_curl_handle);

            $this->_curl_handle = curl_init();
            $this->_curl_count = 0;
        }
        else
        {
            curl_reset($this->_curl_handle);
            $this->_curl_count++;
        }
    }


    public function getAccessToken( $debugAPI = false )
    {
        /*
        curl -d "grant_type=client_credentials&scope=tsg_id:<tsg_id>" \
        -u <client_id>:<client_secret> \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -X POST https://auth.apps.paloaltonetworks.com/oauth2/access_token
        */
        $content = "grant_type=client_credentials&scope=" . $this->scope . "&client_id=" . $this->client_id . "&client_secret=" . $this->client_secret;
        $header = array("Content-Type: application/x-www-form-urlencoded");


        $this->_createOrRenewCurl();

        curl_setopt($this->_curl_handle, CURLOPT_URL, $this->url_token);
        curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, $header);
        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($this->_curl_handle, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($this->_curl_handle, CURLOPT_POST, TRUE);
        curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS, $content);

        if( $this->showApiCalls )
        {
            if( PH::$displayCurlRequest )
            {
                print $this->url_token."?".$content."\n";
                print "content: '".$content."'\n";
                curl_setopt($this->_curl_handle, CURLOPT_FOLLOWLOCATION, TRUE);
                curl_setopt($this->_curl_handle, CURLOPT_VERBOSE, TRUE);
            }
        }



        $response = curl_exec($this->_curl_handle);

        if( empty($response) )
            derr("something went wrong - check internet connection", null, FALSE);

        $jsonArray = json_decode($response, TRUE);
        if( !isset($jsonArray['access_token']) )
        {
            if( isset($jsonArray['error']) )
            {
                PH::print_stdout( );
                PH::print_stdout( PH::boldText("ERROR: " .$jsonArray['error'] ) );
                PH::print_stdout( "if your tenant: ".$this->scope." is NOT running in production environment this is expected | for QA environment use additional argument 'shadow-saseapiqa'" );
            }

            derr( "problem with SASE API connection - not possible to get 'access_token'", null, FALSE );
        }
        elseif( $debugAPI )
            PH::print_stdout( "TOKEN: ".$jsonArray['access_token'] );

        $this->access_token = $jsonArray['access_token'];
    }

    function getTypeArray($utilType, $ruleType = "security")
    {
        $this->typeArray = array();
        if( $utilType == "address" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";
            $this->typeArray[] = "security-rules";
        }
        elseif( $utilType == "address-merger" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";
            $this->typeArray[] = "security-rules";
        }
        elseif( $utilType == "addressgroup-merger" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";
            $this->typeArray[] = "security-rules";
        }
        elseif( $utilType == "service" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";
            $this->typeArray[] = "security-rules";
        }
        elseif( $utilType == "service-merger" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";
            $this->typeArray[] = "security-rules";
        }
        elseif( $utilType == "servicegroup-merger" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";
            $this->typeArray[] = "security-rules";
        }
        elseif( $utilType == "rule" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";

            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";
            $this->typeArray[] = "security-rules";
            #$this->typeArray[] = "authentication-rules"; //problems reading config also in Shared
            #$this->typeArray[] = "qos-policy-rules"; // Access denied
            #$this->typeArray[] = "app-override-rules"; //problems reading config also in Shared
            #"$this->typeArray[] = decryption-rules";
        }
        elseif( $utilType == "tag" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";

            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";
            $this->typeArray[] = "security-rules";
        }
        elseif( $utilType == "tag-merger" )
        {
            $this->typeArray[] = "tags";
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";

            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";
            $this->typeArray[] = "security-rules";
        }
        elseif( $utilType == "schedule" )
        {
            $this->typeArray[] = "schedules";
        }
        elseif( $utilType == "application" )
        {
            $this->typeArray[] = "applications";
            $this->typeArray[] = "application-filters";
            $this->typeArray[] = "application-groups";
        }
        elseif( $utilType == "securityprofilegroup" || $utilType == "securityprofile" )
        {
            $this->typeArray[] = "profile-groups";
            $this->typeArray[] = "anti-spyware-profiles";
            //maybe needed later on:
            //url-filtering-categories
            $this->typeArray[] = "url-access-profiles";
            $this->typeArray[] = "file-blocking-profiles";
            $this->typeArray[] = "dns-security-profiles";
            $this->typeArray[] = "vulnerability-protection-profiles";
            //this is: customURLCategories
            $this->typeArray[] = "url-categories";
            $this->typeArray[] = "wildfire-anti-virus-profiles";
        }
        elseif( $utilType == "upload" )
        {
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";

            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";

            $this->typeArray[] = "security-rules";
            #$this->typeArray[] = "authentication-rules"; //problems reading config also in Shared
            #$this->typeArray[] = "qos-policy-rules"; // Access denied
            #$this->typeArray[] = "app-override-rules"; //problems reading config also in Shared
            #"$this->typeArray[] = decryption-rules";

            $this->typeArray[] = "tags";

            $this->typeArray[] = "schedules";

            #$this->typeArray[] = "applications";
            $this->typeArray[] = "application-filters";
            $this->typeArray[] = "application-groups";
        }
        elseif( $utilType == "device" )
        {
            mwarning("only local offline config validation", null, FALSE);
        }
        elseif( $utilType == "custom" )
        {
        }
        else
        {
            derr("PAN-OS-PHP connection method 'sase-api://' - do not yet support this UTIL type: '" . $utilType . "'", null, FALSE);
        }

        //Todo:
        #"hip-objects",
        #"hip-profiles",

        ######
        #"profile-groups",

        #"anti-spyware-profiles",
        #"wildfire-anti-virus-profiles",
        #"vulnerability-protection-profile",
        #"dns-security-profiles",
        #"file-blocking-profiles",
        //Todo:
        #"decryption-profiles",

        return $this->typeArray;
    }

    function getTypeURL($object)
    {
        if( get_class($object) == "Address" )
            return "addresses";
        elseif( get_class($object) == "AddressGroup" )
            return "address-groups";
        elseif( get_class($object) == "Service" )
            return "services";
        elseif( get_class($object) == "ServiceGroup" )
            return "service-groups";
        elseif( get_class($object) == "SecurityRule" )
            return "security-rules";
        elseif( get_class($object) == "AuthenticationRule" )
            return "authentication-rules";
        elseif( get_class($object) == "QoSRule" )
            return "qos-policy-rules";
        elseif( get_class($object) == "AppOverrideRule" )
            return "app-override-rules";
        elseif( get_class($object) == "DecryptionRule" )
            return "decryption-rules";
        elseif( get_class($object) == "Tag" )
            return "tags";
        elseif( get_class($object) == "Schedule" )
            return "schedules";
        elseif( get_class($object) == "App" || get_class($object) == "AppCustom" )
            return "applications";
        elseif( get_class($object) == "AppFilter" )
            return "application-filters";
        elseif( get_class($object) == "AppGroup" )
            return "application-groups";


        #"hip-objects",
        #"hip-profiles",

        ######
        #"profile-groups",

        #"anti-spyware-profiles",
        #"wildfire-anti-virus-profiles",
        #"vulnerability-protection-profile",
        #"dns-security-profiles",
        #"file-blocking-profiles",
        #"decryption-profiles",

        return $this->typeArray;
    }

    function getResource($access_token, $type = "address", $folder = "Shared", $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1)
    {
        $this->getAccessToken();

        $url = $this->url_api;
        //Fawkes
        $url .= "/sse/config/v1/" . $type . "?folder=" . $folder;
        //Buckbeak
        //$url .= "/config/objects/v1/" . $type . "?folder=" . $folder;

        $url .= "&limit=" . $this->global_limit;

        if( $offset !== "" )
            $url .= "&offset=" . $offset;

        if( strpos($type, "-rule") !== FALSE )
            $url .= "&position=" . $prePost;

        $url = str_replace(' ', '%20', $url);

        if( $this->showApiCalls )
        {
            PH::print_stdout($url);
        }


        $header = array("Authorization: Bearer {$this->access_token}");


        $this->_createOrRenewCurl();

        curl_setopt($this->_curl_handle, CURLOPT_URL, $url);
        curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, $header);
        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($this->_curl_handle, CURLOPT_RETURNTRANSFER, TRUE);

        if( $this->showApiCalls )
        {
            if( PH::$displayCurlRequest )
            {
                curl_setopt($this->_curl_handle, CURLOPT_FOLLOWLOCATION, TRUE);
                curl_setopt($this->_curl_handle, CURLOPT_VERBOSE, TRUE);
            }
        }


        $response = curl_exec($this->_curl_handle);

        $jsonArray = json_decode($response, TRUE);

        if( $this->showApiCalls )
        {
            #print json_encode($jsonArray, JSON_PRETTY_PRINT)."\n";
        }



        if( isset($jsonArray['_errors']) )
        {
            print_r($jsonArray['_errors']);
            derr($jsonArray['_errors'][0]['message'], null, FALSE);
        }


        if( $jsonArray !== null
            && isset($jsonArray['total'])
            && $jsonArray['total'] > ($this->global_limit - 1)
            && $jsonArray['total'] > ($runtime * $this->global_limit)
        )
        {
            $offset = $this->global_limit * $runtime;
            $runtime++;
            $resource = $this->getResource($access_token, $type, $folder, $this->global_limit, $prePost, $offset, $runtime);

            foreach( $resource['data'] as $data )
                $jsonArray['data'][] = $data;
        }


        return $jsonArray;
    }

    function loadSaseConfig($folder, $sub, $utilType, $ruleType = "security")
    {
        $this->getAccessToken();

        $typeArray = $this->getTypeArray($utilType);
        foreach( $typeArray as $type )
        {
            if( $folder == "Service Connections" )
            {
                if( strpos($type, "-rule") !== FALSE )
                    continue;
                elseif( strpos($type, "profile-groups") !== FALSE )
                    continue;
                elseif( strpos($type, "-profiles") !== FALSE )
                    continue;
            }



            $resource = $this->getResource($this->access_token, $type, $folder, $this->global_limit);

            if( $resource !== null )
            {
                if( $this->showApiCalls )
                {
                    #PH::print_stdout("|" . $folder . " - " . $type);
                    #print_r($resource);
                }

                $this->importConfig($sub, $folder, $type, $resource);

                if( $this->showApiCalls )
                {
                    #PH::print_stdout("------------------------------");
                }

            }
            else
            {
                if( $this->showApiCalls )
                {
                    #PH::print_stdout("|" . $folder . " - " . $type . "| empty");
                    #PH::print_stdout("------------------------------");
                }
            }

            $json_string = json_encode($resource, JSON_PRETTY_PRINT);
            #if( $this->showApiCalls )
                #print $json_string . "\n";

            if( strpos($type, '-rules') !== FALSE )
            {
                $resource = $this->getResource($this->access_token, $type, $folder, $this->global_limit, 'post');

                if( $resource !== null )
                {
                    if( $this->showApiCalls )
                    {
                        #PH::print_stdout("|" . $folder . " - " . $type);
                        #print_r($resource);
                    }

                    $this->importConfig($sub, $folder, $type, $resource);

                    #if( $this->showApiCalls )
                        #PH::print_stdout("------------------------------");
                }

                $json_string = json_encode($resource, JSON_PRETTY_PRINT);
            }
        }
    }

    function importConfig($sub, $folder, $type, $jsonArray)
    {
        if( !isset($jsonArray['data']) )
            return null;

        /** @var Container|DeviceCloud $sub */
        foreach( $jsonArray['data'] as $object )
        {
            if( $object['folder'] === "predefined" )
                continue;

            if( $object['folder'] !== $folder )
                continue;

            if( $type === "addresses" )
            {
                if( isset( $object['id'] ) )
                {
                    if( isset($object['ip_netmask']) )
                        $tmp_address = $sub->addressStore->newAddress($object['name'], 'ip-netmask', $object['ip_netmask']);
                    elseif( isset($object['fqdn']) )
                        $tmp_address = $sub->addressStore->newAddress($object['name'], 'fqdn', $object['fqdn']);
                    elseif( isset($object['ip_range']) )
                        $tmp_address = $sub->addressStore->newAddress($object['name'], 'ip-range', $object['ip_range']);
                    elseif( isset($object['ip_wildcard']) )
                        $tmp_address = $sub->addressStore->newAddress($object['name'], 'ip-wildcard', $object['ip_wildcard']);
                    else
                    {
                        print_r( $object );
                        mwarning( "type: not supported", null, FALSE );
                        continue;
                    }

                    if( isset($object['description']) and $tmp_address !== null)
                    {
                        if( is_string($object['description']) )
                            $tmp_address->setDescription($object['description']);
                    }


                    if( isset($object['tag']) )
                    {
                        foreach( $object['tag'] as $tag )
                        {
                            $tmp_tag = $sub->tagStore->findOrCreate($tag);
                            $tmp_address->tags->addTag($tmp_tag);
                        }
                    }

                    $tmp_address->setSaseID( $object['id'] );
                }
            }
            elseif( $type === "tags" )
            {
                if( isset( $object['id'] ) )
                {
                    #$tmp_tag = $sub->tagStore->createTag($object['name']);
                    $tmp_tag = $sub->tagStore->findOrCreate($object['name']);

                    if( isset($object['color']) )
                    {
                        $tmp_tag->setColor($object['color']);
                    }
                    if( isset($object['comments']) )
                        if( is_string($object['comments']) )
                            $tmp_tag->addComments($object['comments']);
                    $tmp_tag->setSaseID( $object['id'] );
                }
            }
            elseif( $type === "address-groups" )
            {
                if( isset( $object['id'] ) )
                {
                    if( isset($object['static']) )
                    {
                        $tmp_addressgroup = $sub->addressStore->newAddressGroup($object['name']);
                        foreach( $object['static'] as $member )
                        {
                            $tmp_address = $sub->addressStore->find($member);
                            if( $tmp_address !== null )
                                $tmp_addressgroup->addMember($tmp_address);
                        }

                        $tmp_addressgroup->setSaseID( $object['id'] );
                    }
                    //elseif( isset($object['dynamic']) )
                }
            }
            elseif( $type === "services" )
            {
                if( isset( $object['id'] ) )
                {
                    foreach( $object['protocol'] as $prot => $entry )
                    {
                        $tmp_service = $sub->serviceStore->newService($object['name'], $prot, $entry['port']);
                    }

                    if( isset($object['description']) )
                        if( is_string($object['description']) )
                            $tmp_service->setDescription($object['description']);
                    $tmp_service->setSaseID( $object['id'] );
                }
            }
            elseif( $type === "service-groups" )
            {
                if( isset( $object['id'] ) )
                {
                    $tmp_servicegroup = $sub->serviceStore->newServiceGroup($object['name']);
                    foreach( $object['members'] as $member )
                    {
                        $tmp_service = $sub->serviceStore->find($member);
                        if( $tmp_service !== null )
                            $tmp_servicegroup->addMember($tmp_service);
                    }

                    if( isset($object['tag']) )
                    {
                        foreach( $object['tag'] as $tag )
                        {
                            $tmp_tag = $sub->tagStore->findOrCreate($tag);
                            $tmp_servicegroup->tags->addTag($tmp_tag);
                        }
                    }

                    $tmp_servicegroup->setSaseID( $object['id'] );
                }
            }
            elseif( $type === "schedules" )
            {
                $tmp_schedule = $sub->scheduleStore->createSchedule($object['name']);

                if( isset($object['schedule_type']['non_recurring']) )
                {
                    foreach( $object['schedule_type']['non_recurring'] as $entry )
                        $tmp_schedule->setNonRecurring($entry);
                }
                elseif( isset($object['schedule_type']['recurring']) )
                {
                    if( isset($object['schedule_type']['recurring']['daily']) )
                    {
                        foreach( $object['schedule_type']['recurring']['daily'] as $entry )
                            $tmp_schedule->setRecurringDaily($entry);
                    }

                    if( isset($object['schedule_type']['recurring']['weekly']) )
                    {
                        foreach( $object['schedule_type']['recurring']['weekly'] as $day => $entry )
                        {
                            foreach( $entry as $entry2 )
                                $tmp_schedule->setRecurringWeekly($day, $entry2);
                        }
                    }
                }
                $tmp_schedule->setSaseID( $object['id'] );
            }
            elseif( $type === "application-groups" )
            {
                //pan-os-php has no newApplicationGroup method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "application-filters" )
            {
                //pan-os-php has no newApplicationFilters method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "regions" )
            {
                //pan-os-php has no newRegion method
                #PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "applications" )
            {
                //pan-os-php has no newApplication method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "hip-objects" )
            {
                //pan-os-php has no newhip-objects method
                PH::print_stdout($type . " - not implemented yet");
            }
            elseif( $type === "hip-profiles" )
            {
                //pan-os-php has no newhip-profiles method
                PH::print_stdout($type . " - not implemented yet");
            }
            //anti-spyware-profiles
            //dns-security-profiles
            //file-blocking-profiles
            //url-access-profiles
            elseif( $type === "vulnerability-protection-profiles" )
            {
                PH::print_stdout($type . " - not implemented yet");
                #print_r($object);
                /*
                 *Array
                (
                    [id] => d6f00677-3200-475f-a470-c07952802f24
                    [name] => best-practice
                    [folder] => All
                    [snippet] => predefined-snippet
                    [description] => Best practice vulnerability protection security profile
                    [rules] => Array
                        (
                            [0] => Array
                                (
                                    [name] => simple-client-critical
                                    [action] => Array
                                        (
                                            [reset_both] => Array
                                                (
                                                )

                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => critical
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => client
                                    [category] => any
                                    [packet_capture] => single-packet
                                )

                            [1] => Array
                                (
                                    [name] => simple-client-high
                                    [action] => Array
                                        (
                                            [reset_both] => Array
                                                (
                                                )

                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => high
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => client
                                    [category] => any
                                    [packet_capture] => single-packet
                                )

                            [2] => Array
                                (
                                    [name] => simple-client-medium
                                    [action] => Array
                                        (
                                            [reset_both] => Array
                                                (
                                                )

                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => medium
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => client
                                    [category] => any
                                    [packet_capture] => single-packet
                                )

                            [3] => Array
                                (
                                    [name] => simple-client-informational
                                    [action] => Array
                                        (
                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => informational
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => client
                                    [category] => any
                                    [packet_capture] => disable
                                )

                            [4] => Array
                                (
                                    [name] => simple-client-low
                                    [action] => Array
                                        (
                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => low
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => client
                                    [category] => any
                                    [packet_capture] => single-packet
                                )

                            [5] => Array
                                (
                                    [name] => simple-server-critical
                                    [action] => Array
                                        (
                                            [reset_both] => Array
                                                (
                                                )

                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => critical
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => server
                                    [category] => any
                                    [packet_capture] => single-packet
                                )

                            [6] => Array
                                (
                                    [name] => simple-server-high
                                    [action] => Array
                                        (
                                            [reset_both] => Array
                                                (
                                                )

                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => high
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => server
                                    [category] => any
                                    [packet_capture] => single-packet
                                )

                            [7] => Array
                                (
                                    [name] => simple-server-medium
                                    [action] => Array
                                        (
                                            [reset_both] => Array
                                                (
                                                )

                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => medium
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => server
                                    [category] => any
                                    [packet_capture] => single-packet
                                )

                            [8] => Array
                                (
                                    [name] => simple-server-informational
                                    [action] => Array
                                        (
                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => informational
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => server
                                    [category] => any
                                    [packet_capture] => disable
                                )

                            [9] => Array
                                (
                                    [name] => simple-server-low
                                    [action] => Array
                                        (
                                        )

                                    [vendor_id] => Array
                                        (
                                            [0] => any
                                        )

                                    [severity] => Array
                                        (
                                            [0] => low
                                        )

                                    [cve] => Array
                                        (
                                            [0] => any
                                        )

                                    [threat_name] => any
                                    [host] => server
                                    [category] => any
                                    [packet_capture] => single-packet
                                )

                        )

                )

                 */
            }
            elseif( $type === "wildfire-anti-virus-profiles" )
            {
                PH::print_stdout($type . " - not implemented yet");
                #print_r($object);
                /*
                 * Array
            (
                [id] => 2b70caff-c6af-4c08-9ee1-7915ea76fb88
                [name] => best-practice
                [folder] => All
                [snippet] => predefined-snippet
                [rules] => Array
                    (
                        [0] => Array
                            (
                                [name] => default
                                [application] => Array
                                    (
                                        [0] => any
                                    )

                                [file_type] => Array
                                    (
                                        [0] => any
                                    )

                                [direction] => both
                                [analysis] => public-cloud
                            )

                    )

                [description] => Best practice antivirus and wildfire analysis security profile
            )

                 */
            }
            elseif( $type === "profile-groups" )
            {
                PH::print_stdout($type . " - not implemented yet");
                #print_r($object);
                /*
                 * Array
(
    [id] => c0b6257c-ea66-4c19-ae87-3094150b37f3
    [name] => Explicit Proxy - Unknown Users
    [folder] => All
    [snippet] => predefined-snippet
    [spyware] => Array
        (
            [0] => best-practice
        )

    [vulnerability] => Array
        (
            [0] => best-practice
        )

    [url_filtering] => Array
        (
            [0] => Explicit Proxy - Unknown Users
        )

    [file_blocking] => Array
        (
            [0] => best-practice
        )

    [virus_and_wildfire_analysis] => Array
        (
            [0] => best-practice
        )

)

                 */
            }
            elseif( $type === "security-rules" )
            {
                $tmp_rule = null;


                $tmp_rule = $sub->securityRules->find($object['name']);
                if( $tmp_rule !== null )
                {
                    //already added
                    return;
                }

                if( isset($object['position']) && $object['position'] === "post" )
                    $tmp_rule = $sub->securityRules->newSecurityRule($object['name'], TRUE);
                else
                    $tmp_rule = $sub->securityRules->newSecurityRule($object['name']);

                if( isset($object['id']) )
                    $tmp_rule->setUUID($object['id']);

                if( isset($object['action']) )
                    $tmp_rule->setAction($object['action']);
                if( isset($object['from']) )
                    foreach( $object['from'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_zone = $sub->zoneStore->findOrCreate($obj);
                        $tmp_rule->from->addZone($tmp_zone);
                    }
                if( isset($object['to']) )
                    foreach( $object['to'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_zone = $sub->zoneStore->findOrCreate($obj);
                        $tmp_rule->to->addZone($tmp_zone);
                    }

                if( isset($object['source']) )
                    foreach( $object['source'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_addr = $sub->addressStore->findOrCreate($obj, null, TRUE);
                        $tmp_rule->source->addObject($tmp_addr);
                    }

                if( isset($object['destination']) )
                    foreach( $object['destination'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_addr = $sub->addressStore->findOrCreate($obj, null, TRUE);
                        $tmp_rule->destination->addObject($tmp_addr);
                    }
                if( isset($object['service']) )
                    foreach( $object['service'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_addr = $sub->serviceStore->findOrCreate($obj, null, TRUE);
                        $tmp_rule->services->add($tmp_addr);
                    }
                if( isset($object['source_user']) )
                {
                    foreach( $object['source_user'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_rule->userID_addUser($obj);
                    }
                }
                if( isset($object['application']) )
                    foreach( $object['application'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_obj = $sub->appStore->findorCreate($obj);
                        $tmp_rule->apps->addApp($tmp_obj);
                    }
                if( isset($object['log_setting']) )
                    $tmp_rule->setLogSetting($object['log_setting']);
                if( isset($object['log_start']) )
                {
                    if( $object['log_start'] == "true" )
                        $tmp_rule->setLogStart( true );
                    else
                        $tmp_rule->setLogStart( false );
                }
                if( isset($object['log_end']) )
                {
                    if( $object['log_end'] == "true" )
                        $tmp_rule->setLogEnd( true );
                    else
                        $tmp_rule->setLogEnd( false );
                }

                if( isset($object['tag']) )
                    foreach( $object['tag'] as $obj )
                    {
                        $tmp_obj = $sub->tagStore->findOrCreate($obj);
                        $tmp_rule->tags->addTag($tmp_obj);
                    }
                if( isset($object['description']) )
                    $tmp_rule->setDescription($object['description']);
                if( isset($object['category']) )
                    foreach( $object['category'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_rule->setUrlCategories($obj);
                    }
                if( isset($object['disabled']) )
                    if( $object['disabled'] == "true" )
                        $tmp_rule->setDisabled(TRUE);
                if( isset($object['source_hip']) )
                    foreach( $object['source_hip'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        #$tmp_rule->setHipProfile($obj);
                    }
                if( isset($object['destination_hip']) )
                    foreach( $object['destination_hip'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        //destination-hip not implemented in pan-os-php
                        #$tmp_rule->setHipProfile($obj);
                    }
                if( isset($object['profile_setting']['group']) )
                {
                    foreach( $object['profile_setting']['group'] as $entry )
                        $tmp_rule->setSecurityProfileGroup($entry);
                }
                /*
                "profile_setting": {
                    "group": [
                        "best-practice"
                    ]
                },
                 */

                if( isset($object['id']) )
                    $tmp_rule->setSaseID( $object['id'] );
            }
            else
            {
                PH::print_stdout($type . " - 2 not implemented yet");
            }
        }
    }

    public function testConnectivity($checkHost = "")
    {
        PH::print_stdout(" - Testing API connectivity... ");

        $this->getAccessToken();

        /*
        PH::print_stdout(" - PAN-OS version: " . $this->info_PANOS_version);
        PH::$JSON_TMP[$checkHost]['panos']['version'] = $this->info_PANOS_version;
        PH::$JSON_TMP[$checkHost]['panos']['type'] = $this->info_deviceType;
        PH::$JSON_TMP[$checkHost]['status'] = "success";
        */
    }

    public function getDataFromObject( $object )
    {
        #print get_class($object);
        $bodyArray = array();
        if( get_class( $object ) == "Address" )
        {
            //Sase-API

            $bodyArray['description'] = $object->description();
            $bodyArray['name'] = $object->name();
            $tagArray = $object->tags->getAll();
            foreach($tagArray as $tag)
                $bodyArray['tag'][] = $tag->name();
            if( $object->isType_ipNetmask() )
                $bodyArray['ip_netmask'] = $object->value();
            elseif( $object->isType_FQDN() )
                $bodyArray['fqdn'] = $object->value();

            $bodyArray['folder'] = $object->owner->owner->name();

            return $bodyArray;
        }
        if( get_class( $object ) == "AddressGroup" )
        {
            //Sase-API

            $bodyArray['description'] = $object->description();
            $bodyArray['name'] = $object->name();
            $bodyArray['folder'] = $object->owner->owner->name();
            $memberArray = $object->members();
            if( !$object->isDynamic() )
            {
                $bodyArray['static'] = array();
                foreach($memberArray as $member)
                    $bodyArray['static'][] = $member->name();
            }
            else
                $bodyArray['dynamic']['filter'] = $object->filter;


            return $bodyArray;
        }
        elseif( get_class( $object ) == "Service" )
        {
            //Sase-API

            $bodyArray['description'] = $object->description();
            $bodyArray['name'] = $object->name();
            $tagArray = $object->tags->getAll();
            foreach($tagArray as $tag)
                $bodyArray['tag'][] = $tag->name();
            if( $object->isTcp() )
                $bodyArray['protocol']['tcp']['port'] = $object->getDestPort();
            elseif( $object->isUdp() )
                $bodyArray['protocol']['udp']['port'] = $object->getDestPort();

            $bodyArray['folder'] = $object->owner->owner->name();

            return $bodyArray;
        }
        elseif( get_class( $object ) == "Tag" )
        {
            //Sase-API

            $bodyArray['comments'] = $object->getComments();
            $bodyArray['name'] = $object->name();
            $bodyArray['folder'] = $object->owner->owner->name();

            $color = $object->getColor();
            $color = ucwords($color);
            if( $color === "dark green" )
               $color = "Olive";
            $bodyArray['color'] = $color;

            return $bodyArray;
        }
        else
            return $bodyArray;
    }

    private function curlRequest($url, $header = null)
    {
        $this->_createOrRenewCurl();

        curl_setopt($this->_curl_handle, CURLOPT_URL, $url);

        if( $header !== null)
            curl_setopt($this->_curl_handle, CURLOPT_HTTPHEADER, $header);

        curl_setopt($this->_curl_handle, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($this->_curl_handle, CURLOPT_RETURNTRANSFER, TRUE);


        if( $this->showApiCalls )
        {
            if( PH::$displayCurlRequest )
            {
                curl_setopt($this->_curl_handle, CURLOPT_FOLLOWLOCATION, TRUE);
                curl_setopt($this->_curl_handle, CURLOPT_VERBOSE, TRUE);

                curl_setopt($this->_curl_handle, CURLOPT_HEADER, 1);
                curl_setopt($this->_curl_handle, CURLINFO_HEADER_OUT, true);
            }
        }
    }

    public function sendCreateRequest( $element )
    {
        $this->getAccessToken();

        $header = array( "Content-Type: application/json", "Authorization: Bearer {$this->access_token}");

        $bodyArray = $this->getDataFromObject( $element );
        if( empty($bodyArray) )
            derr( "empty object - check", $element, false );


        $folder = $bodyArray['folder'];
        if($folder == "Prisma Access")
            $folder = "Shared";
        unset( $bodyArray['folder'] );
        $url = $this->url_api;

        $type = $this->getTypeURL($element);

        //Fawkes
        $url .= "/sse/config/v1/" . $type . "?folder=" . $folder;
        //Buckbeak
        //$url .= "/config/objects/v1/" . $type . "?folder=" . $folder;

        $body = json_encode($bodyArray);

        if( $this->showApiCalls )
        {
            PH::print_stdout( "URL: ".$url);
            PH::print_stdout( "BODY: ".$body );
        }

        $this->curlRequest( $url, $header );

        curl_setopt($this->_curl_handle, CURLOPT_POST,           1 );
        curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS,     $body );


        $response = curl_exec($this->_curl_handle);

        $this->displayCurlResponse( $response );
    }

    public function sendPUTRequest( $element )
    {
        $this->getAccessToken();

        $header = array( "Content-Type: application/json", "Authorization: Bearer {$this->access_token}");

        $bodyArray = $this->getDataFromObject( $element );
        if( empty($bodyArray) )
            derr( "empty object - check", $element, false );


        $folder = $bodyArray['folder'];
        if($folder == "Prisma Access")
            $folder = "Shared";
        unset( $bodyArray['folder'] );
        $url = $this->url_api;

        $type = $this->getTypeURL($element);

        //Fawkes
        $url .= "/sse/config/v1/" . $type . "/" . $element->getSaseID();
        //Buckbeak
        //$url .= "/config/objects/v1/" . $type . "/" . $element->getSaseID();

        $body = json_encode($bodyArray);

        if( $this->showApiCalls )
        {
            PH::print_stdout( "URL: ".$url);
            PH::print_stdout( "BODY: ".$body );
        }

        $this->curlRequest( $url, $header );

        curl_setopt($this->_curl_handle, CURLOPT_CUSTOMREQUEST, 'PUT');

        curl_setopt($this->_curl_handle, CURLOPT_POST,           1 );
        curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS,     $body );


        $response = curl_exec($this->_curl_handle);

        $this->displayCurlResponse( $response );
    }

    public function sendDELETERequest( $element )
    {
        $this->getAccessToken();

        $header = array( "Authorization: Bearer {$this->access_token}");

        $url = $this->url_api;

        $type = $this->getTypeURL($element);

        $saseID = $element->getSaseID();
        if( empty($saseID) )
            derr( "for DELETE request SaseID must be present", null, FALSE );

        $url .= "/sse/config/v1/" . $type . "/" . $saseID;
        //Buckbeak
        //$url .= "/config/objects/v1/" . $type . "/" . $saseID;

        if( $this->showApiCalls )
            PH::print_stdout( "URL: ".$url);

        $this->curlRequest( $url, $header );
        curl_setopt($this->_curl_handle, CURLOPT_CUSTOMREQUEST, 'DELETE');

        $response = curl_exec($this->_curl_handle);

        $this->displayCurlResponse( $response );
    }

    private function displayCurlResponse( $response )
    {
        $jsonArray = json_decode($response, TRUE);

        if( isset($jsonArray['_errors']) )
        {
            print_r($jsonArray['_errors']);
            derr($jsonArray['_errors'][0]['message'], null, FALSE);
        }


        if( $this->showApiCalls )
        {
            print "RESPONSE: '".$response . "'\n";
            //check ID from response and add it to config file
            //{"id":"8b9fd854-ad26-4d38-909a-ca24bf9ff7f0","name":"sven3","folder":"All","description":{},"ip_netmask":"4.5.6.7"}

            print_r( $jsonArray );
            if( $jsonArray !== null && isset($jsonArray['id']) )
            {
                $saseID = $jsonArray['id'];
                PH::print_stdout( "ID: ".$saseID);
            }

        }

    }
}
