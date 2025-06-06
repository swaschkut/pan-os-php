<?php


class SecurityProfileStore extends ObjStore
{

    /** @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf|null */
    public $owner;
    public $name = 'temporaryname';

    public $type = '**needsomethinghere**';

    protected $fastMemToIndex = null;
    protected $fastNameToIndex = null;

    public $nameIndex = array();

    /** @var URLProfile[] */
    public $_all = array();

    /** @var URLProfile[] */
    public $_SecurityProfiles = array();


    /** @var null|SecurityProfileStore */
    public $parentCentralStore = null;

    public $threatRuleStore = array();

    public static $childn = 'SecurityProfile';

    private $secprof_array = array('virus', 'spyware', 'vulnerability', 'file-blocking', 'wildfire-analysis', 'url-filtering', 'custom-url-category', 'predefined-url', 'data-filtering');
    private $secprof_fawkes_array = array('virus-and-wildfire-analysis', 'spyware', 'vulnerability', 'file-blocking', 'dns-security', 'url-filtering', 'custom-url-category', 'predefined-url', 'saas-security');
    /** @var DOMElement */
    public $securityProfileRoot;

    public $bp_json_file = null;
    public $bp_details_array = null;



    static private $storeNameByType = array(
        'URLProfile' => array('name' => 'URL', 'varName' => 'urlSecProf', 'xpathRoot' => 'url-filtering'),
        'SaasSecurityProfile' => array('name' => 'SaasSecurity', 'varName' => 'saasSecProf', 'xpathRoot' => 'saas-security'),

        'AntiVirusProfile' => array('name' => 'Virus', 'varName' => 'avSecProf', 'xpathRoot' => 'virus'),

        'VirusAndWildfireProfile' => array('name' => 'VirusAndWildfire', 'varName' => 'avawfSecProf', 'xpathRoot' => 'virus-and-wildfire-analysis'),
        'DNSSecurityProfile' => array('name' => 'DNSSecurity', 'varName' => 'dnsSecProf', 'xpathRoot' => 'dns-security'),

        'AntiSpywareProfile' => array('name' => 'AntiSpyware', 'varName' => 'asSecProf', 'xpathRoot' => 'spyware'),
        'VulnerabilityProfile' => array('name' => 'Vulnerability', 'varName' => 'fbSecProf', 'xpathRoot' => 'vulnerability'),
        'FileBlockingProfile' => array('name' => 'FileBlocking', 'varName' => 'fbSecProf', 'xpathRoot' => 'file-blocking'),
        'WildfireProfile' => array('name' => 'Wildfire', 'varName' => 'wfSecProf', 'xpathRoot' => 'wildfire-analysis'),
        'DataFilteringProfile' => array('name' => 'DataFiltering', 'varName' => 'dfSecProf', 'xpathRoot' => 'data-filtering'),
        'DoSProtectionProfile' => array('name' => 'DoSProtection', 'varName' => 'dosSecProf', 'xpathRoot' => 'XYZ'),

        'customURLProfile' => array('name' => 'customURL', 'varName' => 'customUrlSecProf', 'xpathRoot' => 'custom-url-category'),
        'PredefinedSecurityProfileURL' => array('name' => 'predefinedURL', 'varName' => 'predefinedUrlSecProf', 'xpathRoot' => 'predefined-url-category'),

        'PredefinedSecurityProfileVirus' => array('name' => 'predefinedVirus', 'varName' => 'predefinedVirusSecProf', 'xpathRoot' => 'predefined-Virus'),
        'PredefinedSecurityProfileSpyware' => array('name' => 'predefinedSpyware', 'varName' => 'predefinedSpywareSecProf', 'xpathRoot' => 'predefined-Spyware'),
        'PredefinedSecurityProfileVulnerability' => array('name' => 'predefinedVulnerability', 'varName' => 'predefinedVulnerabilitySecProf', 'xpathRoot' => 'predefined-Vulnerability'),
        'PredefinedSecurityProfileFileBlocking' => array('name' => 'predefinedFileblocking', 'varName' => 'predefinedFileblockingSecProf', 'xpathRoot' => 'predefined-Fileblocking'),
        'PredefinedSecurityProfileWildfire' => array('name' => 'predefinedWildfire', 'varName' => 'predefinedWildfireSecProf', 'xpathRoot' => 'predefined-Wildfire'),
        'PredefinedSecurityProfileUrlFiltering' => array('name' => 'predefinedURLProfile', 'varName' => 'predefinedUrlFilteringSecProfiles', 'xpathRoot' => 'predefined-url-filtering '),


        'DecryptionProfile' => array('name' => 'Decryption', 'varName' => 'decryptProf', 'xpathRoot' => 'decryption'),
        'HipObjectsProfile' => array('name' => 'HIP-Objects', 'varName' => 'hipObjProf', 'xpathRoot' => 'hip-objects'),
        'HipProfilesProfile' => array('name' => 'HIP-Profiles', 'varName' => 'hipProfProf', 'xpathRoot' => 'hip-profiles'),

        'GTPProfile' => array('name' => 'GTP-Profiles', 'varName' => 'gtpProf', 'xpathRoot' => 'gtp'),
        'SCEPProfile' => array('name' => 'SCEP-Profiles', 'varName' => 'scepProf', 'xpathRoot' => 'scep'),
        'PacketBrokerProfile' => array('name' => 'PacketBroker-Profiles', 'varName' => 'packetBrokerProf', 'xpathRoot' => 'packet-broker'),

        'SDWanErrorCorrectionProfile' => array('name' => 'SDWan-Error-Correction-Profiles', 'varName' => 'sdwanErrorCorrectionProf', 'xpathRoot' => 'sdwan-error-correction'),
        'SDWanPathQualityProfile' => array('name' => 'SDWan-Path-Quality-Profiles', 'varName' => 'sdwanPathQualityProf', 'xpathRoot' => 'sdwan-path-quality'),
        'SDWanSaasQualityProfile' => array('name' => 'SDWan-Saas-Quality-Profiles', 'varName' => 'sdwanSaasQualityProf', 'xpathRoot' => 'sdwan-saas-quality'),
        'SDWanTrafficDistributionProfile' => array('name' => 'SDWan-Traffic-Distribution-Profiles', 'varName' => 'sdwanTrafficDistributionProf', 'xpathRoot' => 'sdwan-traffic-distribution'),

        'DataObjectsProfile' => array('name' => 'Data-Objects-Profiles', 'varName' => 'dataObjectsProf', 'xpathRoot' => 'data-objects')
    );


    public function name()
    {
        return $this->name;
    }

    public function __construct($owner, $profileType)
    {
        $this->bp_json_file = dirname(__FILE__)."/../../utils/api/v1/bp/scm_bp_sp_panw.json";
        if( PH::$shadow_bp_jsonfilename == null )
            PH::$shadow_bp_jsonfilename = $this->bp_json_file;

        $this->classn = &self::$childn;

        $this->owner = $owner;
        $this->o = array();

        $allowedTypes = array_keys(self::$storeNameByType);
        if( !in_array($profileType, $allowedTypes) )
            derr("Error : type '$profileType' is not a valid one");

        $this->type = $profileType;

        $this->name = self::$storeNameByType[$this->type]['name'];

        $storeType = $profileType."Store";

        $this->setParentCentralStore( $storeType );

        $this->_SecurityProfiles = array();



    }

    public $predefinedStore_appid_version = null;

    /** @var null|SecurityProfileStore */
    public static $predefinedURLStore = null;
    public static $predefinedVirusStore = null;
    public static $predefinedSpywareStore = null;
    public static $predefinedVulnerabilityStore = null;
    public static $predefinedFileblockingStore = null;
    public static $predefinedWildfireStore = null;
    public static $predefinedUrlFitleringStore = null;

    /**
     * @return SecurityProfileStore|null
     */
    public static function getURLPredefinedStore( $owner )
    {
        if( self::$predefinedURLStore !== null )
            return self::$predefinedURLStore;


        self::$predefinedURLStore = new SecurityProfileStore( $owner, "PredefinedSecurityProfileURL");
        self::$predefinedURLStore->setName('predefined URL');
        self::$predefinedURLStore->load_url_categories_from_predefinedfile();

        return self::$predefinedURLStore;
    }

    public static function getUrlFilteringPredefinedStore( $owner )
    {
        if( self::$predefinedUrlFitleringStore !== null )
            return self::$predefinedUrlFitleringStore;


        self::$predefinedUrlFitleringStore = new SecurityProfileStore( $owner, "PredefinedSecurityProfileUrlFiltering");
        self::$predefinedUrlFitleringStore->setName('predefined UrlFiltering');
        self::$predefinedUrlFitleringStore->load_url_filtering_from_predefinedfile();

        return self::$predefinedUrlFitleringStore;
    }

    /**
     * @return SecurityProfileStore|null
     */
    public static function getVirusPredefinedStore( $owner )
    {
        if( self::$predefinedVirusStore !== null )
            return self::$predefinedVirusStore;


        self::$predefinedVirusStore = new SecurityProfileStore( $owner, "PredefinedSecurityProfileVirus");
        self::$predefinedVirusStore->setName('predefined Virus');
        self::$predefinedVirusStore->load_virus_rules_from_predefinedfile();

        return self::$predefinedVirusStore;
    }

    public static function getSpywarePredefinedStore( $owner )
    {
        if( self::$predefinedSpywareStore !== null )
            return self::$predefinedSpywareStore;


        self::$predefinedSpywareStore = new SecurityProfileStore( $owner, "PredefinedSecurityProfileSpyware");
        self::$predefinedSpywareStore->setName('predefined Spyware');
        self::$predefinedSpywareStore->load_spyware_rules_from_predefinedfile();

        return self::$predefinedSpywareStore;
    }

    public static function getVulnerabilityPredefinedStore( $owner )
    {
        if( self::$predefinedVulnerabilityStore !== null )
            return self::$predefinedVulnerabilityStore;


        self::$predefinedVulnerabilityStore = new SecurityProfileStore( $owner, "PredefinedSecurityProfileVulnerability");
        self::$predefinedVulnerabilityStore->setName('predefined Vulnerability');
        self::$predefinedVulnerabilityStore->load_vulnerability_rules_from_predefinedfile();

        return self::$predefinedVulnerabilityStore;
    }

    public static function getFileBlockingPredefinedStore( $owner )
    {
        if( self::$predefinedFileblockingStore !== null )
            return self::$predefinedFileblockingStore;


        self::$predefinedFileblockingStore = new SecurityProfileStore( $owner, "PredefinedSecurityProfileFileBlocking");
        self::$predefinedFileblockingStore->setName('predefined FileBlocking');
        self::$predefinedFileblockingStore->load_fileblocking_rules_from_predefinedfile();

        return self::$predefinedFileblockingStore;
    }

    public static function getWildfirePredefinedStore( $owner )
    {
        if( self::$predefinedWildfireStore !== null )
            return self::$predefinedWildfireStore;


        self::$predefinedWildfireStore = new SecurityProfileStore( $owner, "PredefinedSecurityProfileWildfire");
        self::$predefinedWildfireStore->setName('predefined Wildfire');
        self::$predefinedWildfireStore->load_wildfire_rules_from_predefinedfile();

        return self::$predefinedWildfireStore;
    }

    public function load_from_domxml(DOMElement $xml )
    {
        $this->securityProfileRoot = $xml;

        $duplicatesRemoval = array();


        if( $xml !== null )
        {
            $this->xmlroot = $xml;

            foreach( $xml->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;
                if( $node->tagName != 'entry' )
                {
                    mwarning("A SecyrityProfile entry with tag '{$node->tagName}' was found and ignored");
                    continue;
                }
                $tmp_name = DH::findAttribute('name', $node);
                /** @var URLProfile|customURLProfile $nr */
                $nr = new $this->type($tmp_name, $this);
                $nr->load_from_domxml($node);
                if( PH::$enableXmlDuplicatesDeletion )
                {
                    if( isset($this->nameIndex[$nr->name()]) )
                    {
                        mwarning("SecProf named '{$nr->name()}' is present twice on the config and was cleaned by PAN-OS-PHP");
                        $duplicatesRemoval[] = $node;
                        continue;
                    }
                }

                $this->nameIndex[$nr->name()] = $nr;
                $this->fastNameToIndex[$nr->name()] = $nr;

                //
                $this->_SecurityProfiles[ $nr->name() ] = $nr;
                #$this->_SecurityProfiles[$this->name] = $nr;
                $this->_all[] = $nr;
                #$this->_all[$this->name] = $nr;
                $this->o[] = $nr;
            }
        }
    }

    public function load_url_categories_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/pan-url-categories', $xmlDoc);
        $this->load_predefined_url_categories_from_domxml($cursor);

    }

    public function load_url_filtering_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/profiles/url-filtering', $xmlDoc);
        $this->load_predefined_url_filtering_from_domxml($cursor);

    }

    public function load_virus_rules_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/profiles/virus', $xmlDoc);

        $this->load_predefined_virus_rules_from_domxml( $cursor );
    }

    public function load_spyware_rules_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/profiles/spyware', $xmlDoc);

        $this->load_predefined_spyware_rules_from_domxml( $cursor );
    }

    public function load_vulnerability_rules_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/profiles/vulnerability', $xmlDoc);

        $this->load_predefined_vulnerability_rules_from_domxml( $cursor );
    }

    public function load_fileblocking_rules_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/profiles/file-blocking', $xmlDoc);

        $this->load_predefined_fileblocking_rules_from_domxml( $cursor );
    }

    public function load_wildfire_rules_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        $xmlDoc = new DOMDocument();
        $xmlDoc->load($filename, XML_PARSE_BIG_LINES);


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/profiles/wildfire-analysis', $xmlDoc);

        $this->load_predefined_wildfire_rules_from_domxml( $cursor );
    }

    /**
     * Look for a rule named $name. Return NULL if not found
     * @param string $name
     * @return null|URLProfile|AntiVirusProfile|customURLProfile
     */
    /*public function find($name)
    {
        if( !is_string($name) )
            derr("String was expected for rule name");

        if( isset($this->fastNameToIndex[$name]) )
            return $this->_SecurityProfiles[ $name ];

        return null;
    }*/

    /**
     * Should only be called from a CentralStore or give unpredictable results
     * @param string $objectName
     * @param ReferenceableObject $ref
     * @param bool $nested
     * @return null|URLProfile|AntiVirusProfile|customURLProfile
     */
    public function find($objectName, $ref = null, $nested = TRUE)
    {
        $f = null;

        if( isset($this->fastNameToIndex[$objectName]) )
        {
            $foundObject = $this->_SecurityProfiles[ $objectName ];
            $foundObject->addReference($ref);
            return $foundObject;
        }

        /*
        if( isset($this->_all[$objectName]) )
        {
            $foundObject = $this->_all[$objectName];
            $foundObject->addReference($ref);
            return $foundObject;
        }*/

        /*
        // when load a PANOS firewall attached to a Panorama
        if( $nested && isset($this->panoramaShared) )
        {
            $f = $this->panoramaShared->find($objectName, $ref, FALSE);

            if( $f !== null )
                return $f;
        }
        // when load a PANOS firewall attached to a Panorama
        if( $nested && isset($this->panoramaDG) )
        {
            $f = $this->panoramaDG->find($objectName, $ref, FALSE);
            if( $f !== null )
                return $f;
        }
        */

        if( $nested && $this->parentCentralStore !== null )
        {
            $f = $this->parentCentralStore->find($objectName, $ref, $nested);
        }

        return $f;
    }

    public function findOrCreate($fn, $ref = null, $nested = TRUE)
    {
        $f = $this->find($fn, $ref, $nested);

        if( $f !== null )
            return $f;

        $f = $this->createTmp($fn, $ref);

        return $f;
    }

    /**
     * @param URLProfile|AntiVirusProfile|customURLProfile
     * @return bool
     */
    function inStore($SecurityProfile)
    {
        $serial = spl_object_hash($SecurityProfile);

        if( isset($this->fastMemToIndex[$serial]) )
            return TRUE;

        return FALSE;
    }

    /**
     * Returns an Array with all SecurityProfiles inside this store
     * @param null|string|string[] $withFilter
     * @return CustomProfileURL[]|URLProfile
     */
    public function &securityProfiles($withFilter = null)
    {
        $query = null;

        if( $withFilter !== null && $withFilter !== '' )
        {
            $queryContext = array();

            if( is_array($withFilter) )
            {
                $filter = &$withFilter['query'];
                $queryContext['nestedQueries'] = &$withFilter;
            }
            else
                $filter = &$withFilter;

            $errMesg = '';
            $query = new RQuery('securityprofile');
            if( $query->parseFromString($filter, $errMsg) === FALSE )
                derr("error while parsing query: {$errMesg}");

            $res = array();

            foreach( $this->o as $securityProfile )
            {
                $queryContext['object'] = $securityProfile;
                if( $query->matchSingleObject($queryContext) )
                    $res[] = $securityProfile;
            }

            return $res;
        }

        $res = $this->o;

        return $res;
    }

    /**
     * Counts the number of SecurityProfiles in this store
     *
     */
    public function count()
    {
        return count($this->_SecurityProfiles);
    }

    public function removeAllSecurityProfiles()
    {
        $this->removeAll();
        $this->rewriteXML();
    }


    /**
     * @param string $base
     * @param string $suffix
     * @param integer|string $startCount
     * @return string
     */
    public function findAvailableSecurityProfileName($base, $suffix, $startCount = '')
    {
        $maxl = 31;
        $basel = strlen($base);
        $suffixl = strlen($suffix);
        $inc = $startCount;
        $basePlusSuffixL = $basel + $suffixl;

        while( TRUE )
        {
            $incl = strlen(strval($inc));

            if( $basePlusSuffixL + $incl > $maxl )
            {
                $newname = substr($base, 0, $basel - $suffixl - $incl) . $suffix . $inc;
            }
            else
                $newname = $base . $suffix . $inc;

            if( $this->find($newname) === null )
                return $newname;

            if( $startCount == '' )
                $startCount = 0;
            $inc++;
        }
    }


    /**
     * return tags in this store
     * @return SecurityProfile[]
     */
    public function tags()
    {
        return $this->o;
    }


    /**
     * @param URLProfile|customURLProfile|AntiVirusProfile|AntiSpywareProfile|FileBlockingProfile|VulnerabilityProfile|WildfireProfile|VirusAndWildfireProfile|DNSSecurityProfile|DecryptionProfile|HipObjectsProfile|HipProfilesProfile|SaasSecurityProfile $rule
     * @return bool
     */
    public function addSecurityProfile($rule)
    {

        if( !is_object($rule) )
            derr('this function only accepts Rule class objects');

        if( $rule->owner !== null )
            derr('Trying to add a rule that has a owner already !');


        $ser = spl_object_hash($rule);


        if( !isset($this->fastMemToIndex[$ser]) )
        {
            $rule->owner = $this;

            $this->_SecurityProfiles[ $rule->name() ] = $rule;
            $this->_all[] = $rule;
            $this->o[] = $rule;

            $index = lastIndex($this->_SecurityProfiles);
            $this->fastMemToIndex[$ser] = $index;
            $this->fastNameToIndex[$rule->name()] = $index;

            if( $this->xmlroot === null )
                $this->createXmlRoot();

            $this->xmlroot->appendChild($rule->xmlroot);

            return TRUE;
        }
        else
            derr('You cannot add a SecurityProfiles that is already here :)');


        return FALSE;

    }


    /**
     * Creates a new URLProfileStore in this store. It will be placed at the end of the list.
     * @param string $name name of the new Rule
     * @param bool $inPost create it in post or pre (if applicable)
     * @return URLProfile
     */
    public function newSecurityProfileURL($name)
    {
        $rule = new URLProfile($name, $this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, URLProfile::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addSecurityProfile($rule);

        return $rule;
    }

    /**
     * Creates a new customURLProfileStore in this store. It will be placed at the end of the list.
     * @param string $name name of the new Rule
     * @param bool $inPost create it in post or pre (if applicable)
     * @return customURLProfile
     */
    public function newCustomSecurityProfileURL($name)
    {
        $rule = new customURLProfile($name, $this);

        if( $this->owner->version < 90 )
            $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, customURLProfile::$templatexml);
        else
            $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, customURLProfile::$templatexml_v9);

        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addSecurityProfile($rule);

        return $rule;
    }

    /**
     * Creates a new PredefinedSecurityProfileURL in this store. It will be placed at the end of the list.
     * @param string $name name of the new Rule
     * @param bool $inPost create it in post or pre (if applicable)
     * @return customURLProfile
     */
    public function newPredefinedSecurityProfileURL($name)
    {
        $rule = new PredefinedSecurityProfileURL($this);

        #$xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, PredefinedSecurityProfileURL::$templatexml);
        #$rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        #$this->addSecurityProfile($rule);

        return $rule;
    }

    public function load_predefined_url_categories_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;


            $nodeName1 = $appx->nodeName;
            if( $nodeName1 == "hidden-entries" )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("Predefined URL category name not found\n");

            $app = $this->newPredefinedSecurityProfileURL($appName);
            #$app->type = 'predefined';

            $this->add($app);
        }

        sort($this->o);
    }

    public function newPredefinedSecurityProfileVirus($name)
    {
        $rule = new PredefinedSecurityProfileURL($this);

        #$xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, PredefinedSecurityProfileURL::$templatexml);
        #$rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        #$this->addSecurityProfile($rule);

        return $rule;
    }

    public function load_predefined_url_filtering_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;


            $nodeName1 = $appx->nodeName;
            if( $nodeName1 == "hidden-entries" )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("Predefined Virus rule name not found\n");

            #DH::DEBUGprintDOMDocument($appx);
            $app = new URLProfile( $appName, $this );
            $app->load_from_domxml($appx);

            #$app = $this->newPredefinedSecurityProfileURL($appName);
            ##$app->type = 'predefined';

            $this->nameIndex[$app->name()] = $app;
            $this->fastNameToIndex[$app->name()] = $app;

            //
            $this->_SecurityProfiles[ $app->name() ] = $app;
            #$this->_SecurityProfiles[$this->name] = $app;
            $this->_all[] = $app;
            #$this->_all[$this->name] = $app;
            $this->o[] = $app;

            $this->add($app);
        }

        sort($this->o);
    }

    public function load_predefined_virus_rules_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;


            $nodeName1 = $appx->nodeName;
            if( $nodeName1 == "hidden-entries" )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("Predefined Virus rule name not found\n");

            #DH::DEBUGprintDOMDocument($appx);
            $app = new AntiVirusProfile( $appName, $this );
            $app->load_from_domxml($appx);

            #$app = $this->newPredefinedSecurityProfileURL($appName);
            ##$app->type = 'predefined';

            $this->nameIndex[$app->name()] = $app;
            $this->fastNameToIndex[$app->name()] = $app;

            //
            $this->_SecurityProfiles[ $app->name() ] = $app;
            #$this->_SecurityProfiles[$this->name] = $app;
            $this->_all[] = $app;
            #$this->_all[$this->name] = $app;
            $this->o[] = $app;

            $this->add($app);
        }

        sort($this->o);
    }

    public function load_predefined_spyware_rules_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;


            $nodeName1 = $appx->nodeName;
            if( $nodeName1 == "hidden-entries" )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("Predefined Spyware rule name not found\n");

            #DH::DEBUGprintDOMDocument($appx);
            $app = new AntiSpywareProfile( $appName, $this );
            $app->load_from_domxml($appx);

            #$app = $this->newPredefinedSecurityProfileURL($appName);
            ##$app->type = 'predefined';

            $this->nameIndex[$app->name()] = $app;
            $this->fastNameToIndex[$app->name()] = $app;

            //
            $this->_SecurityProfiles[ $app->name() ] = $app;
            #$this->_SecurityProfiles[$this->name] = $app;
            $this->_all[] = $app;
            #$this->_all[$this->name] = $app;
            $this->o[] = $app;

            $this->add($app);
        }

        sort($this->o);
    }

    public function load_predefined_vulnerability_rules_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;


            $nodeName1 = $appx->nodeName;
            if( $nodeName1 == "hidden-entries" )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("Predefined Spyware rule name not found\n");

            #DH::DEBUGprintDOMDocument($appx);
            $app = new VulnerabilityProfile( $appName, $this );
            $app->load_from_domxml($appx);

            #$app = $this->newPredefinedSecurityProfileURL($appName);
            ##$app->type = 'predefined';

            $this->nameIndex[$app->name()] = $app;
            $this->fastNameToIndex[$app->name()] = $app;

            //
            $this->_SecurityProfiles[ $app->name() ] = $app;
            #$this->_SecurityProfiles[$this->name] = $app;
            $this->_all[] = $app;
            #$this->_all[$this->name] = $app;
            $this->o[] = $app;

            $this->add($app);
        }

        sort($this->o);
    }

    public function load_predefined_fileblocking_rules_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;


            $nodeName1 = $appx->nodeName;
            if( $nodeName1 == "hidden-entries" )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("Predefined Spyware rule name not found\n");

            #DH::DEBUGprintDOMDocument($appx);
            $app = new FileBlockingProfile( $appName, $this );
            $app->load_from_domxml($appx);

            #$app = $this->newPredefinedSecurityProfileURL($appName);
            ##$app->type = 'predefined';

            $this->nameIndex[$app->name()] = $app;
            $this->fastNameToIndex[$app->name()] = $app;

            //
            $this->_SecurityProfiles[ $app->name() ] = $app;
            #$this->_SecurityProfiles[$this->name] = $app;
            $this->_all[] = $app;
            #$this->_all[$this->name] = $app;
            $this->o[] = $app;

            $this->add($app);
        }

        #sort($this->o);
    }

    public function load_predefined_wildfire_rules_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $appx )
        {
            if( $appx->nodeType != XML_ELEMENT_NODE )
                continue;


            $nodeName1 = $appx->nodeName;
            if( $nodeName1 == "hidden-entries" )
                continue;

            $appName = DH::findAttribute('name', $appx);
            if( $appName === FALSE )
                derr("Predefined Spyware rule name not found\n");

            #DH::DEBUGprintDOMDocument($appx);
            $app = new WildfireProfile( $appName, $this );
            $app->load_from_domxml($appx);

            #$app = $this->newPredefinedSecurityProfileURL($appName);
            ##$app->type = 'predefined';

            $this->nameIndex[$app->name()] = $app;
            $this->fastNameToIndex[$app->name()] = $app;

            //
            $this->_SecurityProfiles[ $app->name() ] = $app;
            #$this->_SecurityProfiles[$this->name] = $app;
            $this->_all[] = $app;
            #$this->_all[$this->name] = $app;
            $this->o[] = $app;

            $this->add($app);
        }

        sort($this->o);
    }

    /**
     * @param SecurityProfile| URLProfile | AntiSpywareProfile | AntiVirusProfile | VulnerabilityProfile | FileBlockingProfile | WildfireProfile | customURLProfile $tag
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeSecurityProfile( $tag)
    {
        $ret = $this->remove($tag);

        #if( $ret && !$tag->isTmpSecProf() && $this->xmlroot !== null )
        if( $ret && $this->xmlroot !== null )
        {
            $this->xmlroot->removeChild($tag->xmlroot);
        }

        return $ret;
    }

    /**
     * @param SecurityProfile| URLProfile | AntiSpywareProfile | AntiVirusProfile | VulnerabilityProfile | FileBlockingProfile | WildfireProfile | customURLProfile $securityProfile
     * @return bool
     */
    public function API_removeSecurityProfile( $securityProfile)
    {
        $xpath = null;

        #if( !$securityProfile->isTmp() )
        $xpath = $securityProfile->owner->getXPath();
        $xpath .= "/entry[@name='".$securityProfile->name()."']";

        $ret = $this->removeSecurityProfile($securityProfile);

        #if( $ret && !$securityProfile->isTmp() )
        if( $ret )
        {
            $con = findConnectorOrDie($this);
            if( $con->isAPI() )
                $con->sendDeleteRequest($xpath);
        }

        return $ret;
    }

    public function &getXPath()
    {
        $str = '';

        if( $this->owner->isDeviceGroup() || $this->owner->isVirtualSystem() || $this->owner->isContainer() || $this->owner->isDeviceCloud() )
            $str = $this->owner->getXPath();
        elseif( $this->owner->isPanorama() || $this->owner->isFirewall() )
            $str = '/config/shared';
        else
            derr('unsupported');

        $str = $str . '/profiles/'.self::$storeNameByType[$this->type]['xpathRoot'];

        return $str;
    }


    private function &getBaseXPath()
    {
        if( $this->owner->isPanorama() || $this->owner->isFirewall() )
        {
            $str = "/config/shared";
        }
        else
            #$str = $this->owner->getXPath();
            $str = $this->getXPath();


        return $str;
    }

    public function &getSecurityProfileStoreXPath()
    {
        $path = $this->getBaseXPath();
        return $path;
    }

    /**
     * @return * @param SecurityProfile| URLProfile | AntiSpywareProfile | AntiVirusProfile | VulnerabilityProfile | FileBlockingProfile | WildfireProfile | customURLProfile []
     */
    public function nestedPointOfView()
    {
        $current = $this;

        $objects = array();

        while( TRUE )
        {
            if( get_class( $current->owner ) == "PanoramaConf" )
                $location = "shared";
            else
                $location = $current->owner->name();

            foreach( $current->o as $o )
            {
                if( !isset($objects[$o->name()]) )
                    $objects[$o->name()] = $o;
                else
                {
                    $tmp_o = &$objects[ $o->name() ];
                    $tmp_ref_count = $tmp_o->countReferences();

                    if( $tmp_ref_count == 0 )
                    {
                        //Todo: check if object value is same; if same to not add ref
                        if( $location != "shared" )
                            foreach( $o->refrules as $ref )
                                $tmp_o->addReference( $ref );
                    }
                }
            }

            $storeType = "customURLProfileStore";
            if( isset($current->owner->parentDeviceGroup) && $current->owner->parentDeviceGroup !== null )
                $current = $current->owner->parentDeviceGroup->$storeType;
            elseif( isset($current->owner->parentContainer) && $current->owner->parentContainer !== null )
                $current = $current->owner->parentContainer->$storeType;
            elseif( isset($current->owner->owner) && $current->owner->owner !== null && !$current->owner->owner->isFawkes() && !$current->owner->owner->isBuckbeak() )
                $current = $current->owner->owner->$storeType;
            else
                break;
        }

        return $objects;
    }

    public function getBPjsonFile()
    {
        if( $this->bp_details_array == null )
        {
            $this->bp_details_array = array();
            ###############################
            //add bp JSON filename to UTIL???
            //so this can be flexible if customer like to use its own file

            if( PH::$shadow_bp_jsonfile == null )
            {
                $JSONarray = file_get_contents( $this->bp_json_file);

                if( $JSONarray === false )
                    derr("cannot open file '{$this->bp_json_file}");

                $details = json_decode($JSONarray, true);

                if( $details === null )
                    derr( "invalid JSON file provided", null, FALSE );

                $this->bp_details_array = $details;
                PH::$shadow_bp_jsonfile = $details;
            }
            else
                $this->bp_details_array = PH::$shadow_bp_jsonfile;
        }

        return $this->bp_details_array;
    }

    public function rewriteXML()
    {
        if( count($this->o) > 0 )
        {
            if( $this->xmlroot === null )
                return;

            $this->xmlroot->parentNode->removeChild($this->xmlroot);
            $this->xmlroot = null;
        }

        if( $this->xmlroot === null )
        {
            if( count($this->o) > 0 )
                DH::findFirstElementOrCreate('profiles', $this->owner->xmlroot);
        }

        DH::clearDomNodeChilds($this->xmlroot);
        foreach( $this->o as $o )
        {
            if( !$o->isTmpSecProf() )
                $this->xmlroot->appendChild($o->xmlroot);
        }
    }


    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            if( $this->owner->isPanorama() || $this->owner->isFirewall() )
                $xml = $this->owner->sharedroot;
            else
                $xml = $this->owner->xmlroot;

            $SecurityProfileTypeForXml = self::$storeNameByType[$this->type]['xpathRoot'];
            $xml = DH::findFirstElementOrCreate('profiles', $xml);

            $this->xmlroot = DH::findFirstElementOrCreate($SecurityProfileTypeForXml, $xml);
        }
    }

}