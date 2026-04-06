<?php

//Todo: swaschkut 20250117:
//check new Strata Cloud Manager adjusted part:
//https://pan.dev/scm/docs/release-notes/november2024/

//access policy:
//https://pan.dev/scm/api/iam/post-iam-v-1-access-policies/

class PanSCMAPIConnector
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

    public $access_token = null;
    public $access_token_timeout = 600; //seconds
    public $access_token_refreshed_time = null;

    /** @var bool */
    public $showApiCalls = FALSE;

    public $global_limit = 10000; // default 200


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
        "Prisma Access",
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

    public function getFolderavailable( BuckbeakConf $pan)
    {
        $url_config = "/config/setup/v1/folders";

        //$limit and $offset are running into 'Access denied
        #$responseArray = $this->getResourceURL( $url_config);
        $responseArray = $this->getResourceSetup( "folders" );


        $folderNameArray = array();
        $deviceCloudArray = array();
        $deviceOnPremArray = array();

        $parentContainerNotFound = array();
        $parentContainerNotFound_2 = array();
        $parentContainerNotFound_3 = array();
        $parentContainerNotFound_4 = array();

        foreach( $responseArray['data'] as $folder )
        {
            $folderNameArray[] = $folder['name'];

            $display_more = false;
            if( $this->showApiCalls && $display_more )
            {
                print "name: " . $folder['name'] . "\n";
                print "parent: " . $folder['parent'] . "\n";
                print "id: " . $folder['id'] . "\n";
                if( isset( $folder['display_name'] ) )
                    print "display_name: " . $folder['display_name'] . "\n";
                print "type: " . $folder['type'] . "\n";
                print_r($folder);
                PH::print_stdout("-----------");
            }


            if( !empty($folder['parent']) )
            {
                $parent = $folder['parent'];

                if( $parent == "ngfw-shared" )
                {
                    $sub = $pan->findContainer( "ngfw-shared" );
                    if( $sub == null )
                    {
                        $sub = $pan->createContainer( "ngfw-shared", "All" );
                    }
                }
            }

            else
                $parent = null;

            if( $folder['type'] == "container" )
            {
                $parentContainer = $pan->findContainer( $parent );
                if( $parentContainer !== null )
                {
                    $sub = $pan->findContainer( $folder['name'] );
                    if( $sub == null )
                        $sub = $pan->createContainer( $folder['name'], $parent );
                    $sub->setSaseID($folder['id']);
                }
                else
                {
                    $tmpArray = array();
                    $tmpArray['folder'] = $folder;
                    $tmpArray['parent'] = $parent;
                    $parentContainerNotFound[] = $tmpArray;
                }
            }
            elseif( $folder['type'] == "cloud" )
            {
                $tmpArray = array();
                $tmpArray['folder'] = $folder;
                $tmpArray['parent'] = $parent;
                $deviceCloudArray[] = $tmpArray;
            }
            elseif( $folder['type'] == "on-prem" )
            {
                /*
                Array
                (
                    [display_name] => RSNISFIRE01
                    [id] => b6a795ac-9ad2-4b9a-96b8-449b58b85afa
                    [model] => PA-440
                    [name] => 021209061525
                    [parent] => ZTP_LandingFolder
                    [serial_number] => 021209061525
                    [type] => on-prem
                )
                 */

                $tmpArray = array();
                $tmpArray['folder'] = $folder;
                $tmpArray['parent'] = $parent;
                $deviceOnPremArray[] = $tmpArray;
            }
            //todo: swaschkut 20260125 - any other type???? what about on-prem???

            if( isset($folder['snippets']) )
            {
                foreach( $folder['snippets'] as $snippet )
                {
                    $snippet = $pan->findSnippet( $snippet );
                    $sub->addSnippet( $snippet );
                }
            }
        }

        foreach( $parentContainerNotFound as $parentNotFound )
        {
            $folder = $parentNotFound['folder'];
            $parent = $parentNotFound['parent'];

            if( $pan->findContainer( $parent ) !== null )
            {
                $sub = $pan->findContainer( $folder['name'] );
                if( $sub == null )
                    $sub = $pan->createContainer( $folder['name'], $parent );
                $sub->setSaseID($folder['id']);
            }
            else
            {
                $tmpArray = array();
                $tmpArray['folder'] = $folder;
                $tmpArray['parent'] = $parent;
                $parentContainerNotFound_2[] = $tmpArray;
            }
        }

        foreach( $parentContainerNotFound_2 as $parentNotFound_2 )
        {
            $folder = $parentNotFound_2['folder'];
            $parent = $parentNotFound_2['parent'];

            if( $pan->findContainer( $parent ) !== null )
            {
                $sub = $pan->findContainer( $folder['name'] );
                if( $sub == null )
                    $sub = $pan->createContainer( $folder['name'], $parent );
                $sub->setSaseID($folder['id']);
            }
            else
            {
                $tmpArray = array();
                $tmpArray['folder'] = $folder;
                $tmpArray['parent'] = $parent;
                $parentContainerNotFound_3[] = $tmpArray;
            }
        }

        foreach( $parentContainerNotFound_3 as $parentNotFound_3 )
        {
            $folder = $parentNotFound_3['folder'];
            $parent = $parentNotFound_3['parent'];

            if( $pan->findContainer( $parent ) !== null )
            {
                $sub = $pan->findContainer( $folder['name'] );
                if( $sub == null )
                    $sub = $pan->createContainer( $folder['name'], $parent );
                $sub->setSaseID($folder['id']);
            }
            else
            {
                $tmpArray = array();
                $tmpArray['folder'] = $folder;
                $tmpArray['parent'] = $parent;
                $parentContainerNotFound_4[] = $tmpArray;
            }
        }

        foreach( $parentContainerNotFound_4 as $parentNotFound_4 )
        {
            $folder = $parentNotFound_4['folder'];
            $parent = $parentNotFound_4['parent'];

            $sub = $pan->findContainer( $folder['name'] );
            if( $sub == null )
                $sub = $pan->createContainer( $folder['name'], $parent );
            $sub->setSaseID($folder['id']);
        }

        foreach( $deviceOnPremArray as $deviceOnPrem )
        {
            $folder = $deviceOnPrem['folder'];
            $parent = $deviceOnPrem['parent'];

            $sub = $pan->findDeviceCloud( $folder['name'] );
            if( $sub == null )
                $sub = $pan->createDeviceCloud( $folder['name'], $parent );
            $sub->setSaseID($folder['id']);
        }

        foreach( $deviceCloudArray as $deviceCloud )
        {
            $folder = $deviceCloud['folder'];
            $parent = $deviceCloud['parent'];

            $sub = $pan->findDeviceCloud( $folder['name'] );
            if( $sub == null )
                $sub = $pan->createDeviceCloud( $folder['name'], $parent );
            $sub->setSaseID($folder['id']);
        }


        return $folderNameArray;
    }

    public function getSnippetsavailable( BuckbeakConf $pan)
    {
        $url_config = "/config/setup/v1/snippets";

        //$limit and $offset are running into 'Access denied
        #$responseArray = $this->getResourceURL( $url_config);
        $responseArray = $this->getResourceSetup( "snippets" );

        $folderNameArray = array();
        foreach( $responseArray['data'] as $folder )
        {
            $folderNameArray[] = $folder['name'];

            #print "name: " . $folder['name'] . "\n";
            #print "parent: " . $folder['parent'] . "\n";
            #print "id: " . $folder['id'] . "\n";
            #if( isset( $folder['display_name'] ) )
            #    print "display_name: " . $folder['display_name'] . "\n";
            #print "type: " . $folder['type'] . "\n";
            #print_r($folder);
            #PH::print_stdout("-----------");

            $sub = $pan->findSnippet( $folder['name'] );
            if( $sub == null )
                $sub = $pan->createSnippet( $folder['name'] );
            $sub->setSaseID($folder['id']);
        }

        return $folderNameArray;
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

    public function isSCMAPI()
    {
        return TRUE;
    }
    public function isSaseAPI()
    {
        return FALSE;
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
            #if( $this->_curl_handle !== null )
            #    curl_close($this->_curl_handle);

            $this->_curl_handle = curl_init();
            $this->_curl_count = 0;
        }
        else
        {
            curl_reset($this->_curl_handle);
            $this->_curl_count++;
        }
    }


    public function getAccessToken()
    {
        if( $this->access_token === null || $this->access_token_refreshed_time = time() + $this->access_token_timeout )
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

                derr( "problem with SCM API connection - not possible to get 'access_token'", null, FALSE );
            }
            elseif( $this->showApiCalls )
                PH::print_stdout( "TOKEN: ".$jsonArray['access_token'] );

            $this->access_token = $jsonArray['access_token'];
            $this->access_token_refreshed_time = time();
        }
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


            $this->typeArray[] = "anti-spyware-profiles";
            $this->typeArray[] = "dns-security-profiles";
            $this->typeArray[] = "file-blocking-profiles";
            $this->typeArray[] = "saas-security-profiles";
            $this->typeArray[] = "url-access-profiles";
            $this->typeArray[] = "wildfire-anti-virus-profiles";
            $this->typeArray[] = "vulnerability-protection-profiles";

            $this->typeArray[] = "profile-groups";


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
        elseif( $utilType == "upload" )
        {
            $this->typeArray[] = "addresses";
            $this->typeArray[] = "address-groups";
            $this->typeArray[] = "regions";

            $this->typeArray[] = "services";
            $this->typeArray[] = "service-groups";

            $this->typeArray[] = "anti-spyware-profiles";
            $this->typeArray[] = "dns-security-profiles";
            $this->typeArray[] = "file-blocking-profiles";
            $this->typeArray[] = "saas-security-profiles";
            $this->typeArray[] = "url-access-profiles";
            $this->typeArray[] = "wildfire-anti-virus-profiles";
            $this->typeArray[] = "vulnerability-protection-profiles";

            $this->typeArray[] = "profile-groups";


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
            #mwarning("only local offline config validation", null, FALSE);
        }
        elseif( $utilType == "custom" )
        {
        }
        elseif( $utilType == "securityprofile" )
        {
            $this->typeArray[] = "anti-spyware-profiles";
            $this->typeArray[] = "dns-security-profiles";
            $this->typeArray[] = "file-blocking-profiles";
            $this->typeArray[] = "saas-security-profiles";
            $this->typeArray[] = "url-access-profiles";
            $this->typeArray[] = "wildfire-anti-virus-profiles";
            $this->typeArray[] = "vulnerability-protection-profiles";

            //Todo: missing:
            //ai-security-profiles
            //header-insertion-profiles
        }
        elseif( $utilType == "securityprofilegroup" )
        {
            $this->typeArray[] = "profile-groups";
        }
        elseif( $utilType == "log-profile" )
        {
            $this->typeArray[] = "log-forwarding-profiles";
        }
        elseif( $utilType == "stats" )
        {
            //Todo: out for faster validation of BPA
            #$this->typeArray[] = "tags";

            #$this->typeArray[] = "addresses";
            #$this->typeArray[] = "address-groups";
            #$this->typeArray[] = "regions";

            #$this->typeArray[] = "services";
            #$this->typeArray[] = "service-groups";

            $this->typeArray[] = "anti-spyware-profiles";
            $this->typeArray[] = "dns-security-profiles";
            $this->typeArray[] = "file-blocking-profiles";
            $this->typeArray[] = "saas-security-profiles";
            $this->typeArray[] = "url-access-profiles";
            $this->typeArray[] = "wildfire-anti-virus-profiles";
            $this->typeArray[] = "vulnerability-protection-profiles";

            $this->typeArray[] = "profile-groups";

            $this->typeArray[] = "zones";
            $this->typeArray[] = "zone-protection-profiles";

            $this->typeArray[] = "security-rules";

            $this->typeArray[] = "log-forwarding-profiles";
        }
        elseif( $utilType == "zone" )
        {
            $this->typeArray[] = "zones";
        }
        elseif( $utilType == "zone-protection-profile" )
        {
            $this->typeArray[] = "zone-protection-profiles";
        }
        else
        {
            derr("PAN-OS-PHP connection method 'scm-api://' - do not yet support this UTIL type: '" . $utilType . "'", null, FALSE);
        }

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


        elseif( get_class($object) == "AntiSpywareProfile" )
            return "anti-spyware-profiles";
        elseif( get_class($object) == "DNSSecurityProfile" )
            return "dns-security-profiles";
        elseif( get_class($object) == "FileBlockingProfile" )
            return "file-blocking-profiles";
        elseif( get_class($object) == "SaasSecurityProfile" )
            return "saas-security-profiles";
        elseif( get_class($object) == "URLProfile" )
            return "url-access-profiles";
        elseif( get_class($object) == "VirusAndWildfireProfile" )
            return "wildfire-anti-virus-profiles";
        elseif( get_class($object) == "VulnerabilityProfile" )
            return "vulnerability-protection-profiles";
        //Todo: implementation needed
        elseif( get_class($object) == "AISecurityProfile" )
            return "ai-security-profiles";
        //Todo: Header insertion profile - implementation needed

        elseif( get_class($object) == "SecurityProfileGroup" )
            return "profile-groups";


        elseif( get_class($object) == "Zone" )
            return "zones";
        elseif( get_class($object) == "ZoneProtectionProfile" )
            return "zone-protection-profiles";


        elseif( get_class($object) == "LogProfile" )
            return "log-forwarding-profiles";

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

    function curl_request_SCM( $url )
    {
        $this->getAccessToken();

        $url = str_replace(' ', '%20', $url);

        if( $this->showApiCalls )
        {
            PH::print_stdout($url);
        }

        $header = array("Authorization: Bearer {$this->access_token}");

        $this->curlRequest( $url, $header );


        $response = curl_exec($this->_curl_handle);
        if( $this->showApiCalls )
        {
            print $response . "\n";
        }

        $jsonArray = json_decode($response, TRUE);

        if( isset($jsonArray['_errors']) )
        {
            print_r($jsonArray['_errors']);
            derr($jsonArray['_errors'][0]['message'], null, FALSE);
        }

        return $jsonArray;
    }

    #function getResource($access_token, $type = "address", $foldertype = "folder", $folderName = "Shared", $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1)
    function getResource( $type = null, $foldertype = "folder", $folderName = null, $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1)
    {
        $url = $this->url_api;
        //Fawkes
        #$url .= "/sse/config/v1/" . $type . "?folder=" . $folder;
        //Buckbeak
        if( $type !== null
            && ( strpos( $type, "-rules") !== FALSE || strpos( $type, "-profiles") !== FALSE || strpos( $type, "profile-groups") !== FALSE )
            && $type !== "log-forwarding-profiles"
        )
            $url .= "/config/security/v1/" . $type . "?".$foldertype."=" . $folderName;
        else
            $url .= "/config/objects/v1/" . $type . "?".$foldertype."=" . $folderName;

        $url .= "&limit=" . $this->global_limit;

        if( $offset !== "" )
            $url .= "&offset=" . $offset;

        if( $type !== null && strpos($type, "-rule") !== FALSE )
        {
            $url .= "&position=" . $prePost;
        }

        $date = date('Y-m-d H:i:s');
        #PH::print_stdout( "     time: ".$date);
        #PH::print_stdout("     -1 '". $folderName. "' object: " . $type. " URL: '".$url."'");




        $jsonArray = $this->curl_request_SCM( $url );


        //first time working
        //https://api.strata.paloaltonetworks.com/config/setup/v1/folders?limit=200&offset=0
        //issue here:
        //https://api.strata.paloaltonetworks.com/config/objects/v1/?folder=&limit=200&offset=200
        if( $jsonArray !== null
            && isset($jsonArray['total'])
            && $jsonArray['total'] > ($this->global_limit - 1)
            && $jsonArray['total'] > ($runtime * $this->global_limit)
        )
        {
            $offset = $this->global_limit * $runtime;
            $runtime++;
            $resource = $this->getResource( $type, $foldertype, $folderName, $this->global_limit, $prePost, $offset, $runtime);

            foreach( $resource['data'] as $data )
                $jsonArray['data'][] = $data;
        }


        return $jsonArray;
    }


    function getResourceSetup( $type = null, $foldertype = "folder", $folderName = null, $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1)
    {
        $url = $this->url_api;

        //Buckbeak
        $url .= "/config/setup/v1/" . $type . "?";


        $url .= "limit=" . $this->global_limit;

        if( $offset !== "" )
            $url .= "&offset=" . $offset;



        $jsonArray = $this->curl_request_SCM( $url );


        //first time working
        //https://api.strata.paloaltonetworks.com/config/setup/v1/folders?limit=200&offset=0
        //issue here:
        //https://api.strata.paloaltonetworks.com/config/objects/v1/?folder=&limit=200&offset=200
        if( $jsonArray !== null
            && isset($jsonArray['total'])
            && $jsonArray['total'] > ($this->global_limit - 1)
            && $jsonArray['total'] > ($runtime * $this->global_limit)
        )
        {
            $offset = $this->global_limit * $runtime;
            $runtime++;
            $resource = $this->getResourceSetup( $type, $foldertype, $folderName, $this->global_limit, $prePost, $offset, $runtime);

            foreach( $resource['data'] as $data )
                $jsonArray['data'][] = $data;
        }


        return $jsonArray;
    }

    function getResourceURL( $url_config, $type = null, $foldertype = "folder", $folder = null, $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1)
    {
        if( $this->showApiCalls )
        {
            PH::print_stdout("urlconfig: ".$url_config);
        }

        $url = $this->url_api;
        $url .= "" . $url_config;

        if( $type !== null && $folder !== null )
        {
            //Fawkes
            #$url .= "/sse/config/v1/" . $type . "?folder=" . $folder;
            //Buckbeak
            $url .= "/config/objects/v1/" . $type . "?".$foldertype."=" . $folder;
            if( $this->showApiCalls )
                PH::print_stdout("URL: ".$url);
        }
        elseif( $type == null && $folder !== null )
        {
            if(strpos( $url, "?" ) !== FALSE)
                $url .= "&".$foldertype."=" . $folder;
            else
                $url .= "?".$foldertype."=" . $folder;

            if( $this->showApiCalls )
                PH::print_stdout("URL: ".$url);
        }
        #elseif( $type == null && $folder == null )
        #    $url .= "&".$foldertype."=" . $folder;

        if( $limit !== null )
        {
            #$url .= "&limit=" . $this->global_limit;
            if(strpos( $url, "?" ) !== FALSE)
                $url .= "&limit=" . $limit;
            else
                $url .= "?limit=" . $limit;

            if( $this->showApiCalls )
                PH::print_stdout("URL: ".$url);
        }


        if( $offset !== null )
        {
            if(strpos( $url, "?" ) !== FALSE)
                $url .= "&offset=" . $offset;
            else
                $url .= "?offset=" . $limit;

            if( $this->showApiCalls )
                PH::print_stdout("URL: ".$url);
        }


        if( $type !== null )
        {
            if (strpos($type, "-rule") !== FALSE) {
                $url .= "&position=" . $prePost;

                if ($this->showApiCalls)
                    PH::print_stdout("URL: " . $url);
            }
        }


        $date = date('Y-m-d H:i:s');
        PH::print_stdout( "     time: ".$date);
        PH::print_stdout("   -2 '". $folder. "' object: " . $type. " URL: '".$url."'");


        if( strpos($url, "parent1=200") !== FALSE )
            derr( "check" );


        $jsonArray = $this->curl_request_SCM( $url);


        if( $jsonArray !== null
            && isset($jsonArray['total'])
            && $jsonArray['total'] > ($this->global_limit - 1)
            && $jsonArray['total'] > ($runtime * $this->global_limit)
        )
        {
            $offset = $this->global_limit * $runtime;
            $runtime++;

            if( $this->showApiCalls )
            {
                PH::print_stdout("Type: '".$type."'");
                PH::print_stdout("Foldertype: '".$foldertype."'");
                PH::print_stdout("Folder: '".$folder."'");
            }

            $resource = $this->getResource( $type, $foldertype, $folder, $this->global_limit, $prePost, $offset, $runtime);


            if( isset( $resource['msg'] ) && $resource['msg'] == "Access denied" )
            {
                PH::print_stdout("Type: '".$type."'");
                PH::print_stdout("Foldertype: '".$foldertype."'");
                PH::print_stdout("Folder: '".$folder."'");
                derr( $resource['msg'], null, TRUE );
            }

            foreach( $resource['data'] as $data )
                $jsonArray['data'][] = $data;
        }


        return $jsonArray;
    }

    function getNetworkResource( $type = "zones", $foldertype = "folder", $folderName = "Prisma Access", $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1)
    {
        $url = $this->url_api;
        //Fawkes
        #$url .= "/sse/config/v1/" . $type . "?folder=" . $folder;
        //Buckbeak
        $url .= "/config/network/v1/" . $type . "?".$foldertype."=" . $folderName;


        $url .= "&limit=" . $this->global_limit;

        if( $offset !== "" )
            $url .= "&offset=" . $offset;

        if( strpos($type, "-rule") !== FALSE )
        {
            $url .= "&position=" . $prePost;
        }


        PH::print_stdout("   -3 '". $folderName. "' object: " . $type);


        $jsonArray = $this->curl_request_SCM( $url);


        if( $jsonArray !== null
            && isset($jsonArray['total'])
            && $jsonArray['total'] > ($this->global_limit - 1)
            && $jsonArray['total'] > ($runtime * $this->global_limit)
        )
        {
            $offset = $this->global_limit * $runtime;
            $runtime++;
            $resource = $this->getNetworkResource( $type, $foldertype, $folderName, $this->global_limit, $prePost, $offset, $runtime);

            foreach( $resource['data'] as $data )
                $jsonArray['data'][] = $data;
        }


        return $jsonArray;
    }

    function getSCMapi( $url_config, $runtime = 1)
    {
        $url = $this->url_api;
        $url .= "" . $url_config;



        return $this->curl_request_SCM( $url);
    }

    function loadSCMConfig($folder, $sub, $utilType, $ruleType = "security")
    {
        $typeArray = $this->getTypeArray($utilType);
        foreach( $typeArray as $type )
        {
            if( $folder == "Service Connections" && strpos($type, "-rule") !== FALSE )
                continue;

            if( ($folder == "Prisma Access" || $folder == "Shared") && strpos($type, "zones") !== FALSE )
                continue;

            $foldertype = "folder";
            if( get_class($sub) == "Container" )
                $foldertype = "folder";
            elseif( get_class($sub) == "DeviceCloud" )
                $foldertype = "device";
            elseif( get_class($sub) == "DeviceOnPrem" )
                $foldertype = "device";
            elseif( get_class($sub) == "Snippet" )
                $foldertype = "snippet";

            if( $utilType == "zone" || $utilType == "zone-protection-profile" )
                $resource = $this->getNetworkResource( $type, $foldertype, $folder, $this->global_limit);
            else
                $resource = $this->getResource( $type, $foldertype, $folder, $this->global_limit);

            if( $resource !== null )
            {
                if( $this->showApiCalls )
                {
                    //PH::print_stdout("|" . $folder . " - " . $type);
                    //print_r($resource);
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
                $resource = $this->getResource( $type, $foldertype, $folder, $this->global_limit, 'post');

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
            if( isset( $object['folder'] ) )
            {
                if( $object['folder'] === "predefined" )
                    continue;

                if( $object['folder'] !== $folder )
                    continue;
            }
            elseif( isset( $object['snippet'] ) )
            {
                if( $object['snippet'] !== $folder )
                    continue;
            }
            elseif( isset( $object['device'] ) )
            {
                if( $object['device'] !== $folder )
                    continue;
            }

            if( $this->showApiCalls )
            {
                #print_r($object);
            }

            if( $type === "addresses" )
            {
                //Todo: import via:
                /*
                $profileStoreName = "AddressStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
                 */
                if( isset( $object['id'] ) )
                {
                    $tmp_address = $sub->addressStore->find($object['name']);
                    if( $tmp_address !== null )
                        continue;

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

                    $tmp_address->setSASEID( $object['id'] );
                }
            }
            elseif( $type === "tags" )
            {
                //Todo: import via:
                /*
                $profileStoreName = "TagStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
                 */
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
                //Todo: import via:
                /*
                $profileStoreName = "AddressStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
                 */
                if( isset( $object['id'] ) )
                {
                    if( isset($object['static']) )
                    {
                        $tmp_addressgroup = $sub->addressStore->find($object['name']);
                        if( $tmp_addressgroup !== null )
                            continue;

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
                //Todo: import via:
                /*
                $profileStoreName = "SecurityRuleStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
                 */
                $tmp_service = $sub->serviceStore->find($object['name']);
                if( $tmp_service !== null )
                    continue;

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
                //Todo: import via:
                /*
                $profileStoreName = "SecurityRuleStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
                 */
                if( isset( $object['id'] ) )
                {
                    $tmp_servicegroup = $sub->serviceStore->find($object['name']);
                    if( $tmp_servicegroup !== null )
                        continue;

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
                //Todo: import via:
                /*
                $profileStoreName = "SecurityRuleStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
                 */
                $tmp_schedule = $sub->scheduleStore->find($object['name']);
                if( $tmp_schedule !== null )
                    continue;

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
            elseif( $type === "log-forwarding-profiles" )
            {
                $profileStoreName = "LogProfileStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }
            elseif( $type === "security-rules" )
            {
                //Todo: import via:
                /*
                $profileStoreName = "SecurityRuleStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
                 */
                $tmp_rule = null;

                $tmp_rule = $sub->securityRules->find($object['name']);
                if( $tmp_rule !== null )
                    continue;

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
                if( isset($object['source-user']) )
                    foreach( $object['source-user'] as $obj )
                    {
                        if( $obj === "any" )
                            continue;
                        $tmp_rule->userID_addUser($obj);
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


                if( isset($object['log_start']) )
                    if( $object['log_start'] == FALSE )
                        $tmp_rule->setLogStart(FALSE);
                    else
                        $tmp_rule->setLogStart(TRUE);
                if( isset($object['log_end']) )
                    if( $object['log_end'] == FALSE )
                        $tmp_rule->setLogEnd(FALSE);
                    else
                        $tmp_rule->setLogEnd(TRUE);

                if( isset($object['negate_source']) )
                    if( $object['negate_source'] === TRUE )
                        $tmp_rule->setSourceIsNegated(TRUE);
                if( isset($object['negate_destination']) )
                    if( $object['negate_destination'] === TRUE )
                        $tmp_rule->setDestinationIsNegated(TRUE);
            }

            //Todo: specify profiles import
            elseif( $type === "anti-spyware-profiles" )
            {
                $profileStoreName = "AntiSpywareProfileStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }
            elseif( $type === "dns-security-profiles" )
            {
                $profileStoreName = "DNSSecurityProfileStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }
            elseif( $type === "file-blocking-profiles" )
            {
                $profileStoreName = "FileBlockingProfileStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }
            elseif( $type === "saas-security-profiles" )
            {
                $profileStoreName = "SaasSecurityProfileStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }
            elseif( $type === "vulnerability-protection-profiles" )
            {
                $profileStoreName = "VulnerabilityProfileStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }
            elseif( $type === "wildfire-anti-virus-profiles" )
            {
                $profileStoreName = "VirusAndWildfireProfileStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }
            elseif( $type === "url-access-profiles" )
            {
                $profileStoreName = "URLProfileStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }
            elseif( $type === "ai-security-profiles" )
            {
                if( isset( $object['id'] ) )
                {
                    #$tmp_ai_security = $sub->VirusAndWildfireProfileStore->find($object['name']);
                    #if ($tmp_ai_security !== null)
                    #    continue;

                    #$tmp_ai_security = $sub->VirusAndWildfireProfileStore->findOrCreate($object['name']);
                }
                PH::print_stdout($type . " - not finalised");
                print_r( $object );
            }
            //Todo: missing http-header-profiles

            //Todo: specify profile-groups import
            elseif( $type === "profile-groups" )
            {
                $profileStoreName = "securityProfileGroupStore";
                $return = $this->SCM_API_object_import_preperation($object, $sub, $profileStoreName);

                if( $return === "continue" )
                    continue;
            }

            elseif( $type == "zones" )
            {
                $profileStoreName = "zoneStore";


                if( isset( $object['id'] ) )
                {
                    //does CONTAINER/DEVICECLOUD/SNIPPET have zone/ interface directly attached?????
                    $tmp_url = $sub->$profileStoreName->find($object['name']);
                    if ($tmp_url !== null)
                        return "continue";


                    $dom = null;
                    $rootEntry = null;
                    $this->SCM_API_prepareMethodForImport( $object, $dom, $rootEntry );

                    // Start the conversion
                    $this->SCM_API_arrayToXml($dom, $rootEntry, $object);

                    $this->SCM_API_SP_object_import($dom, $sub, $profileStoreName, $object);
                }

            }
            elseif( $type == "zone-protection-profiles" )
            {
                ///config/network/v1/zone-protection-profiles
                $profileStoreName = "zoneProtectionProfileStore";


                if( isset( $object['id'] ) )
                {
                    //does CONTAINER/DEVICECLOUD/SNIPPET have zone/ interface directly attached?????
                    $tmp_url = $sub->network->$profileStoreName->find($object['name']);
                    if ($tmp_url !== null)
                        return "continue";


                    $dom = null;
                    $rootEntry = null;
                    $this->SCM_API_prepareMethodForImport( $object, $dom, $rootEntry );

                    // Start the conversion
                    $this->SCM_API_arrayToXml($dom, $rootEntry, $object);

                    #DH::DEBUGprintDOMDocument($dom->firstChild);
                    $this->SCM_API_SP_object_import($dom, $sub, $profileStoreName, $object);
                }
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

        #if( get_class($object->owner->owner) == "Container" || get_class($object->owner->owner) == "DeviceCloud"
        #    || get_class($object->owner->owner) == "DeviceOnPrem" )
        if( get_class($object->owner->owner) == "Container" )
            $bodyArray['folder'] = $object->owner->owner->name();
        elseif( get_class($object->owner->owner) == "Snippet" )
            $bodyArray['snippet'] = $object->owner->owner->name();
        elseif( get_class($object->owner->owner) == "DeviceCloud"
            || get_class($object->owner->owner) == "DeviceOnPrem" )
            $bodyArray['device'] = $object->owner->owner->name();
        $bodyArray['name'] = $object->name();


        if( get_class( $object ) == "Address" )
        {
            //SCM-API

            $bodyArray['description'] = $object->description();
            $tagArray = $object->tags->getAll();
            foreach($tagArray as $tag)
                $bodyArray['tag'][] = $tag->name();
            if( $object->isType_ipNetmask() )
                $bodyArray['ip_netmask'] = $object->value();
            elseif( $object->isType_FQDN() )
                $bodyArray['fqdn'] = $object->value();

            return $bodyArray;
        }
        if( get_class( $object ) == "AddressGroup" )
        {
            //SCM-API

            $bodyArray['description'] = $object->description();

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
            //SCM-API

            $bodyArray['description'] = $object->description();
            $tagArray = $object->tags->getAll();
            foreach($tagArray as $tag)
                $bodyArray['tag'][] = $tag->name();
            if( $object->isTcp() )
                $bodyArray['protocol']['tcp']['port'] = $object->getDestPort();
            elseif( $object->isUdp() )
                $bodyArray['protocol']['udp']['port'] = $object->getDestPort();

            return $bodyArray;
        }
        elseif( get_class( $object ) == "Tag" )
        {
            //SCM-API

            $bodyArray['comments'] = $object->getComments();

            $color = $object->getColor();
            $color = ucwords($color);
            if( $color === "dark green" )
               $color = "Olive";
            $bodyArray['color'] = $color;

            return $bodyArray;
        }
        elseif( get_class( $object ) == "LogProfile" )
        {
            $tmp_match_list_array = array();
            foreach( $object->type() as $key => $name )
            {
                if( isset($name['notSet']))
                    continue;
                else
                {
                    foreach ($name as $name_key => $type)
                    {
                        $tmp_array = array( "name" => $name_key, "log_type" => $key );

                        foreach ($type as $type_key => $type_value)
                        {
                            $tmp_array[$type_key] =  $type_value ;
                        }
                        $tmp_match_list_array[] = $tmp_array;
                    }
                }
            }
            $bodyArray['match_list'] = $tmp_match_list_array;

            return $bodyArray;
        }
        else
        {
            mwarning( "object: ".get_class($object)." not implemented yet", null, false);
            DH::DEBUGprintDOMDocument($object->xmlroot);
            return $bodyArray;
        }

    }

    private function curlRequest($url, $header = null)
    {
        //GET
        //List
        //get an address

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
        //sendPOSTRequest()
        //CREATE

        $this->getAccessToken();

        $header = array( "Content-Type: application/json", "Authorization: Bearer {$this->access_token}");

        $bodyArray = $this->getDataFromObject( $element );
        if( empty($bodyArray) )
        {
            derr( "empty object - check", $element, false );
        }


        $sub_type = null;
        $folder = null;
        if( isset($bodyArray['folder']) )
        {
            $sub_type = "folder";

            $folder = $bodyArray['folder'];
            if($folder == "Prisma Access")
                //Todo: validate, but it looks like to no longer needed
                //$folder = "Shared";
            unset( $bodyArray['folder'] );
        }
        elseif( isset($bodyArray['snippet']) )
        {
            $sub_type = "snippet";
            $folder = $bodyArray['snippet'];

            unset( $bodyArray['snippet'] );
        }
        elseif( isset($bodyArray['device']) )
        {
            $sub_type = "device";
            $folder = $bodyArray['device'];

            unset( $bodyArray['device'] );
        }


        $url = $this->url_api;

        $type = $this->getTypeURL($element);

        //Fawkes
        #$url .= "/sse/config/v1/" . $type . "?folder=" . $folder;
        //Buckbeak
        if( $this->showApiCalls )
        {
            #PH::print_stdout( $type );
            #PH::print_stdout( $sub_type );
            #PH::print_stdout( $folder );
            #PH::print_stdout();
        }
        $url .= "/config/objects/v1/" . $type . "?".$sub_type."=" . $folder;

        $body = json_encode($bodyArray);

        if( $this->showApiCalls )
        {
            PH::print_stdout( "URL: ".$url);
            PH::print_stdout( "BODY: ".$body );
            PH::print_stdout( "METHOD: POST" );
        }

        $this->curlRequest( $url, $header );

        curl_setopt($this->_curl_handle, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($this->_curl_handle, CURLOPT_POST,           1 );
        curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS,     $body );


        $response = curl_exec($this->_curl_handle);

        $this->displayCurlResponse( $response );
    }

    public function sendPUTRequest( $element )
    {
        //UPDATE
        //PUT

        $this->getAccessToken();

        $header = array( "Content-Type: application/json", "Authorization: Bearer {$this->access_token}");

        $bodyArray = $this->getDataFromObject( $element );
        if( empty($bodyArray) )
            derr( "empty object - check", $element, false );

        $url = $this->url_api;

        $type = $this->getTypeURL($element);

        //Fawkes
        #$url .= "/sse/config/v1/" . $type . "/" . $element->getSaseID();
        //Buckbeak
        $url .= "/config/objects/v1/" . $type . "/" . $element->getSaseID();

        $body = json_encode($bodyArray);

        if( $this->showApiCalls )
        {
            PH::print_stdout( "URL: ".$url);
            PH::print_stdout( "BODY: ".$body );
            PH::print_stdout( "METHOD: PUT" );
        }

        $this->curlRequest( $url, $header );

        curl_setopt($this->_curl_handle, CURLOPT_CUSTOMREQUEST, 'PUT');

        curl_setopt($this->_curl_handle, CURLOPT_POST,           1 );
        curl_setopt($this->_curl_handle, CURLOPT_POSTFIELDS,     $body );


        $response = curl_exec($this->_curl_handle);

        $this->displayCurlResponse( $response );
    }

    public function sendDELETERequest($object )
    {
        //DELETE

        $this->getAccessToken();

        $header = array( "Authorization: Bearer {$this->access_token}");

        $url = $this->url_api;

        $type = $this->getTypeURL($object);

        $saseID = $object->getSaseID();
        if( empty($saseID) )
            derr( "for DELETE request SaseID must be present", null, FALSE );

        #$url .= "/sse/config/v1/" . $type . "/" . $saseID;

        //Buckbeak
        $url .= "/config/objects/v1/" . $type . "/" . $saseID;

        if( $this->showApiCalls )
        {
            PH::print_stdout( "URL: ".$url);
            #PH::print_stdout( "ID: ".$saseID );
            PH::print_stdout( "METHOD: DELETE" );
        }


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


    private function SCM_API_arrayToXml(&$dom, &$parentNode, $data): void
    {
        foreach ($data as $key => $value)
        {
            // Skip metadata keys not needed in the final XML tags
            if (in_array($key, ['id', 'name', 'folder', 'snippet', 'device', 'description']))
                continue;

            // Handle naming convention: convert underscores to dashes
            $tagName = str_replace('_', '-', $key);

            if( is_array($value) )
            {
                // Check if this is a list of entries (numeric keys)
                if( isset($value[0]) && is_array($value[0]) )
                {
                    $container = $dom->createElement($tagName);
                    $parentNode->appendChild($container);

                    foreach ($value as $item)
                    {
                        $entry = $dom->createElement('entry');
                        // If the item has a 'name', use it as an attribute
                        if (isset($item['name']))
                        {
                            $entry->setAttribute('name', $item['name']);
                            unset($item['name']); // Remove so it doesn't become a child tag
                        }
                        $container->appendChild($entry);
                        $this->SCM_API_arrayToXml($dom, $entry, $item);
                    }
                }
                else
                {
                    // Regular associative nested array
                    $element = $dom->createElement($tagName);
                    $parentNode->appendChild($element);
                    $this->SCM_API_arrayToXml($dom, $element, $value);
                }
            }
            else
            {
                // It's a flat value
                // Custom logic for specific values like cloud-inline-analysis
                if( $value == '1' || $value == '0' )
                    $value = ($value == '1') ? 'yes' : 'no';

                if( is_numeric($tagName) )
                    $tagName = "member";

                $element = $dom->createElement($tagName, htmlspecialchars($value));
                $parentNode->appendChild($element);
            }
        }
    }

    private function SCM_API_prepareMethodForImport( $data, &$dom, &$rootEntry)
    {
        $dom = new DOMDocument('1.0', 'utf-8');
        $dom->formatOutput = true;

        // Create the root entry element
        $rootEntry = $dom->createElement('entry');
        $dom->appendChild($rootEntry);

        $entry = $dom->firstChild;
        if( isset($data['name'] ) )
            $entry->setAttribute( 'name', $data['name'] );
        if( isset($data['id'] ) )
            $entry->setAttribute( 'uuid', $data['id'] );
    }

    private function SCM_API_object_import_preperation($object, $sub, $profileStoreName)
    {
        if( isset( $object['id'] ) )
        {
            $tmp_url = $sub->$profileStoreName->find($object['name']);
            if ($tmp_url !== null)
                return "continue";


            $dom = null;
            $rootEntry = null;
            $this->SCM_API_prepareMethodForImport( $object, $dom, $rootEntry );

            // Start the conversion
            $this->SCM_API_arrayToXml($dom, $rootEntry, $object);

            $this->SCM_API_SP_object_import($dom, $sub, $profileStoreName, $object);

            return true;
        }

        return false;
    }
    private function SCM_API_SP_object_import($dom, $sub, $storeType, $object)
    {
        #print "STORE: ".$storeType."\n";

        if( $storeType == 'zoneProtectionProfileStore' )
        {}
        else
        {
            if( $sub->$storeType->xmlroot == null)
            {
                if( $sub->$storeType->xmlroot == null)
                    $sub->$storeType->createXmlRoot();
            }
        }

        if( $storeType == 'zoneProtectionProfileStore' )
            $ownerDocument = $sub->network->$storeType->owner->xmlroot->ownerDocument;
        else
            $ownerDocument = $sub->$storeType->xmlroot->ownerDocument;

        $tmpNode = $ownerDocument->importNode($dom->firstChild, true);


        if( $storeType == 'AntiSpywareProfileStore' )
            $newProf = new AntiSpywareProfile('dummy', $sub->$storeType);
        elseif( $storeType == 'DNSSecurityProfileStore' )
            $newProf = new DNSSecurityProfile('dummy', $sub->$storeType);
        elseif( $storeType == 'FileBlockingProfileStore' )
            $newProf = new FileBlockingProfile('dummy', $sub->$storeType);
        elseif( $storeType == 'VulnerabilityProfileStore' )
            $newProf = new VulnerabilityProfile('dummy', $sub->$storeType);
        elseif( $storeType == 'VirusAndWildfireProfileStore' )
            $newProf = new VirusAndWildfireProfile('dummy', $sub->$storeType);
        elseif( $storeType == 'URLProfileStore' )
            $newProf = new URLProfile('dummy', $sub->$storeType);


        elseif( $storeType == 'securityProfileGroupStore' )
            $newProf = new SecurityProfileGroup('dummy', $sub->$storeType);

        elseif( $storeType == 'zoneStore' )
            $newProf = new Zone('dummy', $sub->$storeType);

        elseif( $storeType == 'zoneProtectionProfileStore' )
            $newProf = new ZoneProtectionProfile('dummy', $sub->network->$storeType);
        elseif( $storeType == 'LogProfileStore' )
            $newProf = new LogProfile( 'dummy', $sub->$storeType);
        else
        {
            print "StoreType: '".$storeType."\n";
            derr("implementation needed");
        }

        #print "CLASS: ".get_class($newProf)."\n";

        /** @var Container|DeviceCloud|DeviceOnPrem $sub */

        if( get_class($newProf) == 'SecurityProfileGroup' )
        {
            $newProf->load_from_domxml($tmpNode, $sub->securityProfileGroupStore);

            $newProf->owner = null;
            $sub->securityProfileGroupStore->addSecurityProfileGroup($newProf);
        }

        elseif( get_class($newProf) == 'Zone' )
        {
            $newProf->load_from_domxml($tmpNode);

            $newProf->owner = null;
            $sub->zoneStore->addZone($newProf);
        }
        elseif( get_class($newProf) == 'ZoneProtectionProfile' )
        {
            $newProf->load_from_domxml($tmpNode);

            $newProf->owner = null;
            $sub->network->zoneProtectionProfileStore->addProfil($newProf);
        }
        elseif( get_class($newProf) == 'LogProfile' )
        {
            $newProf->load_from_domxml($tmpNode);

            $newProf->owner = null;
            $sub->LogProfileStore->addLogProfile($newProf);
        }
        else
        {
            $newProf->load_from_domxml($tmpNode);

            $newProf->owner = null;
            $sub->$storeType->addSecurityProfile($newProf);
        }

        if( isset($object['id']) )
            $newProf->setSaseID($object['id']);
    }

}
