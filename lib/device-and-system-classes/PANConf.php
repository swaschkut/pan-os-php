<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * Your journey will start from PANConf or PanoramaConf
 *
 * Code:
 *
 *  $pan = new PANConf();
 *
 *  $pan->load_from_file('config.txt');
 *
 *  $vsys1 = $pan->findVirtualSystem('vsys1');
 *
 *  $vsys1->display_statistics();
 *
 * And there you go !
 *
 */
class PANConf
{

    use PathableName;
    use PanSubHelperTrait;

    /** @var DOMElement */
    public $xmlroot;

    /** @var DOMDocument */
    public $xmldoc;

    /** @var DOMElement */
    public $sharedroot;
    /** @var DOMDocument */
    public $devicesroot;
    /** @var DOMElement */
    public $localhostroot;

    public $deviceconfigroot;

    /** @var DOMElement|null */
    public $vsyssroot;

    public $name = '';

    /** @var AddressStore */
    public $addressStore = null;

    /** @var ServiceStore */
    public $serviceStore = null;

    public $version = null;

    public $timezone = null;

    /** @var VirtualSystem[] */
    public $virtualSystems = array();

    /** @var VirtualSystem[] */
    public $sharedGateways = array();

    /** @var PanAPIConnector|null $connector */
    public $connector = null;

    /** @var null|Template */
    public $owner = null;

    /** @var NetworkPropertiesContainer */
    public $network;

    /** @var AppStore */
    public $appStore;

    /** @var ThreatStore */
    public $threatStore;

    /** @var TagStore */
    public $tagStore;

    /** @var SecurityProfileStore */
    public $urlStore;
    public $AntiVirusPredefinedStore;
    public $AntiSpywarePredefinedStore;
    public $VulnerabilityPredefinedStore;
    public $FileBlockingPredefinedStore;
    public $WildfirePredefinedStore;
    public $UrlFilteringPredefinedStore;


    protected $securityProfilebaseroot;

    /** @var SecurityProfileStore */
    public $URLProfileStore = null;

    /** @var SecurityProfileStore */
    public $customURLProfileStore = null;

    /** @var SecurityProfileStore */
    public $AntiVirusProfileStore = null;

    /** @var ThreatPolicyStore */
    public $ThreatPolicyStore = null;

    /** @var DNSPolicyStore */
    public $DNSPolicyStore = null;

    /** @var SecurityProfileStore */
    public $VulnerabilityProfileStore = null;

    /** @var SecurityProfileStore */
    public $AntiSpywareProfileStore = null;

    /** @var SecurityProfileStore */
    public $FileBlockingProfileStore = null;

    /** @var SecurityProfileStore */
    public $DataFilteringProfileStore = null;

    /** @var SecurityProfileStore */
    public $WildfireProfileStore = null;


    /** @var SecurityProfileGroupStore */
    public $securityProfileGroupStore = null;

    /** @var SecurityProfileStore */
    public $DecryptionProfileStore = null;

    /** @var SecurityProfileStore */
    public $HipObjectsProfileStore = null;

    /** @var SecurityProfileStore */
    public $HipProfilesProfileStore = null;

    /** @var SecurityProfileStore */
    public $GTPProfileStore = null;

    /** @var SecurityProfileStore */
    public $SCEPProfileStore = null;

    /** @var SecurityProfileStore */
    public $PacketBrokerProfileStore = null;

    /** @var SecurityProfileStore */
    public $SDWanErrorCorrectionProfileStore = null;

    /** @var SecurityProfileStore */
    public $SDWanPathQualityProfileStore = null;

    /** @var SecurityProfileStore */
    public $SDWanSaasQualityProfileStore = null;

    /** @var SecurityProfileStore */
    public $SDWanTrafficDistributionProfileStore = null;

    /** @var SecurityProfileStore */
    public $DataObjectsProfileStore = null;
    
    /** @var ScheduleStore */
    public $scheduleStore = null;

    /** @var EDLStore */
    public $EDLStore = null;

    /** @var LogProfileStore */
    public $LogProfileStore = null;

    /** @var CertificateStore */
    public $certificateStore = null;

    /** @var SSL_TLSServiceProfileStore */
    public $SSL_TLSServiceProfileStore = null;

    public $_public_cloud_server = null;

    public $_advance_routing_enabled = false;

    public $_auditComment = false;

    public $panorama = null;

    public function name()
    {
        return $this->name;
    }

    /**
     * @param PanoramaConf|null $withPanorama
     * @param string|null $serial
     * @param Template|null $fromTemplate
     */
    public function __construct($withPanorama = null, $serial = null, $fromTemplate = null)
    {
        if( $withPanorama !== null )
            $this->panorama = $withPanorama;
        if( $serial !== null )
            $this->serial = $serial;

        $this->owner = $fromTemplate;

        $this->tagStore = new TagStore($this);
        $this->tagStore->setName('tagStore');

        $this->appStore = AppStore::getPredefinedStore( $this );

        $this->threatStore = ThreatStore::getPredefinedStore( $this );

        $this->urlStore = SecurityProfileStore::getURLPredefinedStore( $this );


        $this->serviceStore = new ServiceStore($this);
        $this->serviceStore->name = 'services';

        $this->addressStore = new AddressStore($this);
        $this->addressStore->name = 'addresses';


        $this->customURLProfileStore = new SecurityProfileStore($this, "customURLProfile");
        $this->customURLProfileStore->name = 'CustomURL';

        $this->URLProfileStore = new SecurityProfileStore($this, "URLProfile");
        $this->URLProfileStore->name = 'URL';

        $this->AntiVirusProfileStore = new SecurityProfileStore($this, "AntiVirusProfile");
        $this->AntiVirusProfileStore->name = 'AntiVirus';


        $this->ThreatPolicyStore = new ThreatPolicyStore($this, "ThreatPolicy");
        $this->ThreatPolicyStore->name = 'ThreatPolicy';

        $this->DNSPolicyStore = new DNSPolicyStore($this, "DNSPolicy");
        $this->DNSPolicyStore->name = 'DNSPolicy';

        $this->VulnerabilityProfileStore = new SecurityProfileStore($this, "VulnerabilityProfile");
        $this->VulnerabilityProfileStore->name = 'Vulnerability';

        $this->AntiSpywareProfileStore = new SecurityProfileStore($this, "AntiSpywareProfile");
        $this->AntiSpywareProfileStore->name = 'AntiSpyware';

        $this->FileBlockingProfileStore = new SecurityProfileStore($this, "FileBlockingProfile");
        $this->FileBlockingProfileStore->name = 'FileBlocking';

        $this->DataFilteringProfileStore = new SecurityProfileStore($this, "DataFilteringProfile");
        $this->DataFilteringProfileStore->name = 'DataFiltering';

        $this->WildfireProfileStore = new SecurityProfileStore($this, "WildfireProfile");
        $this->WildfireProfileStore->name = 'WildFire';


        $this->securityProfileGroupStore = new SecurityProfileGroupStore($this);
        $this->securityProfileGroupStore->name = 'SecurityProfileGroups';


        $this->DecryptionProfileStore = new SecurityProfileStore($this, "DecryptionProfile");
        $this->DecryptionProfileStore->name = 'Decryption';

        $this->HipObjectsProfileStore = new SecurityProfileStore($this, "HipObjectsProfile");
        $this->HipObjectsProfileStore->name = 'HipObjects';

        $this->HipProfilesProfileStore = new SecurityProfileStore($this, "HipProfilesProfile");
        $this->HipProfilesProfileStore->name = 'HipProfiles';

        $this->scheduleStore = new ScheduleStore($this);
        $this->scheduleStore->setName('scheduleStore');

        $this->EDLStore = new EDLStore($this);
        $this->EDLStore->setName('EDLStore');

        $this->LogProfileStore = new LogProfileStore($this);
        $this->LogProfileStore->setName('LogProfileStore');

        $this->certificateStore = new CertificateStore($this);
        $this->certificateStore->setName('certificateStore');

        $this->SSL_TLSServiceProfileStore = new SSL_TLSServiceProfileStore($this);
        $this->SSL_TLSServiceProfileStore->setName('SSL_TLSServiceStore');

        $this->network = new NetworkPropertiesContainer($this);
    }


    public function load_from_xmlstring(&$xml)
    {
        $xmlDoc = new DOMDocument();

        if( $xmlDoc->loadXML($xml, XML_PARSE_BIG_LINES) !== TRUE )
            derr('Invalid XML file found');

        $this->load_from_domxml($xmlDoc);
    }

    /**
     * @param $xml DOMElement|DOMDocument
     * @throws Exception
     */
    public function load_from_domxml($xml, $debugLoadTime = false)
    {
        if( $xml->nodeType == XML_DOCUMENT_NODE )
        {
            $this->xmldoc = $xml;
            $this->xmlroot = DH::findFirstElementOrDie('config', $this->xmldoc);
        }
        elseif( $xml->nodeType == XML_ELEMENT_NODE )
        {
            $this->xmlroot = $xml;

            #$tmp_root = $this->owner->xmlroot;
            #$tmp_doc = DH::findFirstElementOrDie('config', $tmp_root);

            $dom = new DOMDocument();
            $domNode = $dom->importNode($xml, TRUE);

            $dom->appendChild($domNode);
            $this->xmldoc = $dom;
        }


        if( $this->owner !== null )
        {
            $this->version = $this->owner->owner->version;
        }
        else
        {
            $versionAttr = DH::findAttribute('version', $this->xmlroot);
            if( $versionAttr !== FALSE )
            {
                $this->version = PH::versionFromString($versionAttr);
            }
            else
            {
                if( isset($this->connector) && $this->connector !== null )
                    $version = $this->connector->getSoftwareVersion();
                else
                {
                    mwarning('cannot find PANOS version used for make this config', null, false);
                    $version['version'] = "X.Y.Z";
                }


                $this->version = $version['version'];
            }
        }


        $this->devicesroot = DH::findFirstElementOrCreate('devices', $this->xmlroot);

        $this->localhostroot = DH::findFirstElement('entry', $this->devicesroot);
        if( $this->localhostroot === FALSE )
        {
            $this->localhostroot = DH::createElement($this->devicesroot, 'entry');
            $this->localhostroot->setAttribute('name', 'localhost.localdomain');
        }

        $this->vsyssroot = DH::findFirstElement('vsys', $this->localhostroot);


        $this->deviceconfigroot = DH::findFirstElement('deviceconfig', $this->localhostroot);


        //
        // Extract setting related configs
        //
        if( $this->deviceconfigroot !== FALSE )
        {
            $settingroot = DH::findFirstElement('setting', $this->deviceconfigroot);
            if( $settingroot !== FALSE )
            {
                $tmp1 = DH::findFirstElement('wildfire', $settingroot);
                if( $tmp1 !== FALSE )
                {
                    $tmp2 = DH::findFirstElement('public-cloud-server', $tmp1);
                    if( $tmp2 )
                    {
                        $this->_public_cloud_server = $tmp1->textContent;
                    }
                }

                $managementroot = DH::findFirstElement('management', $settingroot);
                if( $managementroot !== FALSE )
                {
                    $auditComment = DH::findFirstElement('rule-require-audit-comment', $managementroot);
                    if( $auditComment != FALSE )
                        if( $auditComment->textContent === "yes" )
                            $this->_auditComment = TRUE;
                }

                $advanceRoutingroot = DH::findFirstElement('advance-routing', $settingroot);
                if( $advanceRoutingroot !== FALSE )
                {
                    if( $advanceRoutingroot->textContent === "yes" )
                        $this->_advance_routing_enabled = TRUE;
                }
            }

            $systemroot = DH::findFirstElement('system', $this->deviceconfigroot);
            if( $systemroot !== FALSE )
            {
                $timezone = DH::findFirstElement('timezone', $systemroot);
                if( $timezone )
                {
                    $this->timezone = $timezone->textContent;

                    PH::enableExceptionSupport();
                    try
                    {
                        date_default_timezone_set($timezone->textContent);
                    }
                    catch(Exception $e)
                    {
                        $timezone_backward = PH::timezone_backward_migration( $this->timezone );
                        if( $timezone_backward !== null )
                        {
                            $this->timezone = $timezone_backward;
                            date_default_timezone_set($timezone_backward);

                            PH::print_stdout("   --------------");
                            PH::print_stdout( " X Timezone: $timezone->textContent is not supported with this PHP version. ".$this->timezone." is used." );
                            PH::print_stdout("   - the timezone is IANA deprecated. Please change to a supported one:");

                            PH::print_stdout();
                            PH::print_stdout("   -- '".$this->timezone."'");
                            PH::print_stdout("   --------------");
                            PH::print_stdout();
                        }
                        else
                        {
                            PH::print_stdout("timezone: '".$this->timezone."' not supported by IANA");
                        }
                    }
                    PH::disableExceptionSupport();
                }
            }
        }
        //


        // Now listing and extracting all DeviceConfig configurations
        if( $this->vsyssroot !== FALSE )
        {
            foreach( $this->vsyssroot->childNodes as $node )
            {

            }
        }


        if( $this->owner === null )
        {
            if( $debugLoadTime )
                PH::print_DEBUG_loadtime("shared");

            $this->sharedroot = DH::findFirstElementOrDie('shared', $this->xmlroot);
            //
            // Extract Tag objects
            //
            if( $this->version >= 60 )
            {
                $tmp = DH::findFirstElement('tag', $this->sharedroot);
                if( $tmp !== FALSE )
                    $this->tagStore->load_from_domxml($tmp);
            }
            // End of Tag objects extraction


            //
            // Extract region objects
            //
            $tmp = DH::findFirstElement('region', $xml);
            if( $tmp !== FALSE )
                $this->addressStore->load_regions_from_domxml($tmp);
            //print "VSYS '".$this->name."' address objectsloaded\n" ;
            // End of address objects extraction

            //
            // Shared address objects extraction
            //
            $tmp = DH::findFirstElementorCreate('address', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->addressStore->load_addresses_from_domxml($tmp);
            // end of address extraction

            //
            // Extract address groups
            //
            $tmp = DH::findFirstElementorCreate('address-group', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->addressStore->load_addressgroups_from_domxml($tmp);
            // End of address groups extraction

            //
            // Extract services
            //
            $tmp = DH::findFirstElement('service', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->serviceStore->load_services_from_domxml($tmp);
            // End of address groups extraction

            //
            // Extract service groups
            //
            $tmp = DH::findFirstElement('service-group', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->serviceStore->load_servicegroups_from_domxml($tmp);
            // End of address groups extraction

            //
            // Extract application
            //
            $tmp = DH::findFirstElement('application', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->appStore->load_application_custom_from_domxml($tmp);
            // End of address extraction

            //
            // Extract application filter
            //
            $tmp = DH::findFirstElement('application-filter', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->appStore->load_application_filter_from_domxml($tmp);
            // End of application filter groups extraction

            //
            // Extract application groups
            //
            $tmp = DH::findFirstElement('application-group', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->appStore->load_application_group_from_domxml($tmp);
            // End of address groups extraction


            // Extract SecurityProfiles objects
            //
            $this->securityProfilebaseroot = DH::findFirstElement('profiles', $this->sharedroot);
            if( $this->securityProfilebaseroot === FALSE )
                $this->securityProfilebaseroot = null;

            if( $this->securityProfilebaseroot !== null )
            {
                //
                // custom URL category extraction
                //
                $tmproot = DH::findFirstElement('custom-url-category', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->customURLProfileStore->load_from_domxml($tmproot);
                    #$this->urlStore->load_from_domxml($tmproot);
                }


                //
                // URL Profile extraction
                //
                $tmproot = DH::findFirstElement('url-filtering', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    #$tmprulesroot = DH::findFirstElement('rules', $tmproot);
                    #if( $tmprulesroot !== FALSE )
                    $this->URLProfileStore->load_from_domxml($tmproot);
                }

                //
                // AntiVirus Profile extraction
                //
                $tmproot = DH::findFirstElement('virus', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    #$tmprulesroot = DH::findFirstElement('rules', $tmproot);
                    #if( $tmprulesroot !== FALSE )
                    $this->AntiVirusProfileStore->load_from_domxml($tmproot);
                }

                //
                // FileBlocking Profile extraction
                //
                $tmproot = DH::findFirstElement('file-blocking', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    #$tmprulesroot = DH::findFirstElement('rules', $tmproot);
                    #if( $tmprulesroot !== FALSE )
                    $this->FileBlockingProfileStore->load_from_domxml($tmproot);
                }

                //
                // DataFiltering Profile extraction
                //
                $tmproot = DH::findFirstElement('data-filtering', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    #$tmprulesroot = DH::findFirstElement('rules', $tmproot);
                    #if( $tmprulesroot !== FALSE )
                    $this->DataFilteringProfileStore->load_from_domxml($tmproot);
                }

                //
                // vulnerability Profile extraction
                //
                $tmproot = DH::findFirstElement('vulnerability', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    #$tmprulesroot = DH::findFirstElement('rules', $tmproot);
                    #if( $tmprulesroot !== FALSE )
                    $this->VulnerabilityProfileStore->load_from_domxml($tmproot);
                }

                //
                // spyware Profile extraction
                //
                $tmproot = DH::findFirstElement('spyware', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    #$tmprulesroot = DH::findFirstElement('rules', $tmproot);
                    #if( $tmprulesroot !== FALSE )
                    $this->AntiSpywareProfileStore->load_from_domxml($tmproot);
                }

                //
                // wildfire Profile extraction
                //
                $tmproot = DH::findFirstElement('wildfire-analysis', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    #$tmprulesroot = DH::findFirstElement('rules', $tmproot);
                    #if( $tmprulesroot !== FALSE )
                    $this->WildfireProfileStore->load_from_domxml($tmproot);
                }

                //
                // Decryption Profile extraction
                //
                $tmproot = DH::findFirstElement('decryption', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->DecryptionProfileStore->load_from_domxml($tmproot);
                }

                //
                // HipObjects Profile extraction
                //
                $tmproot = DH::findFirstElement('hip-objects', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->HipObjectsProfileStore->load_from_domxml($tmproot);
                }

                //
                // HipProfiles Profile extraction
                //
                $tmproot = DH::findFirstElement('hip-profiles', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->HipProfilesProfileStore->load_from_domxml($tmproot);
                }
            }

            //
            // Extract SecurityProfile groups in this DV
            //
            $tmp = DH::findFirstElement('profile-group', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->securityProfileGroupStore->load_securityprofile_groups_from_domxml($tmp);
            // End of address groups extraction

            //
            // Extract schedule objects
            //
            $tmp = DH::findFirstElement('schedule', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->scheduleStore->load_from_domxml($tmp);
            // End of address groups extraction

            //
            // Extract EDL objects
            //
            $tmp = DH::findFirstElement('external-list', $xml);
            if( $tmp !== FALSE )
                $this->EDLStore->load_from_domxml($tmp);
            // End of EDL extraction

            //
            // Extract LogProfile objects
            //
            $tmp2 = DH::findFirstElement('log-settings', $xml);
            if( $tmp2 !== FALSE )
                $tmp = DH::findFirstElement('profiles', $tmp2);
            if( $tmp2 !== FALSE && $tmp !== FALSE )
                $this->LogProfileStore->load_from_domxml($tmp);
            // End of LogProfile extraction

            //
            // Extract Certificate objects
            //
            $tmp = DH::findFirstElement('certificate', $this->sharedroot);
            if( $tmp !== FALSE )
            {
                $this->certificateStore->load_from_domxml($tmp);
            }
            // End of Certificate objects extraction

            //
            // Extract ssl-tls-service-profile objects
            //
            $tmp = DH::findFirstElement('ssl-tls-service-profile', $this->sharedroot);
            if( $tmp !== FALSE )
            {
                $this->SSL_TLSServiceProfileStore->load_from_domxml($tmp);
            }
            // End of SSL_TLSServiceProfile objects extraction
        }

        $this->AntiVirusPredefinedStore = SecurityProfileStore::getVirusPredefinedStore( $this );
        $this->AntiSpywarePredefinedStore = SecurityProfileStore::getSpywarePredefinedStore( $this );
        $this->VulnerabilityPredefinedStore = SecurityProfileStore::getVulnerabilityPredefinedStore( $this );
        $this->UrlFilteringPredefinedStore = SecurityProfileStore::getUrlFilteringPredefinedStore( $this );
        $this->FileBlockingPredefinedStore = SecurityProfileStore::getFileBlockingPredefinedStore( $this );
        $this->WildfirePredefinedStore = SecurityProfileStore::getWildfirePredefinedStore( $this );


        //
        // Extract network related configs
        //
        //Todo: 20250101 - can network part be moved after vsys reading ?? - virutalsystem reading interfaces, must be done later to get address references
        $tmp = DH::findFirstElement('network', $this->localhostroot);
        if( $tmp !== FALSE )
        {
            if( $debugLoadTime )
                PH::print_DEBUG_loadtime("network");
            $this->network->load_from_domxml($tmp);
        }
        //

        // Now listing and extracting all VirtualSystem configurations
        if( $this->vsyssroot !== FALSE )
        {
            foreach ($this->vsyssroot->childNodes as $node) {
                if ($node->nodeType != 1) continue;
                //PH::print_stdout(  "DOM type: ".$node->nodeType );

                $localVirtualSystemName = DH::findAttribute('name', $node);

                if ($localVirtualSystemName === FALSE || strlen($localVirtualSystemName) < 1)
                    derr('cannot find VirtualSystem name');

                $dg = null;

                if (isset($this->panorama))
                {
                    if ($this->panorama->_fakeMode)
                        $dg = $this->panorama->findDeviceGroup($localVirtualSystemName);
                    else
                        $dg = $this->panorama->findApplicableDGForVsys($this->serial, $localVirtualSystemName);
                }

                if ($dg !== FALSE && $dg !== null)
                    $localVsys = new VirtualSystem($this, $dg);
                else
                    $localVsys = new VirtualSystem($this);

                if ($debugLoadTime)
                    PH::print_DEBUG_loadtime("vsys");

                $localVsys->load_from_domxml($node);
                $this->virtualSystems[] = $localVsys;

                $importedInterfaces = $localVsys->importedInterfaces->interfaces();
                foreach ($importedInterfaces as &$ifName) {
                    $ifName->importedByVSYS = $localVsys;
                }
            }
        }


        //
        // Extract network IKE / IPsec related configs
        //
        $tmp = DH::findFirstElement('network', $this->localhostroot);
        if( $tmp !== FALSE )
        {
            if( $debugLoadTime )
                PH::print_DEBUG_loadtime("network part 2");
            $this->network->load_from_domxml_2($tmp);
        }
        //
    }


    /**
     * !!OBSOLETE!!
     * @obsolete
     * @param string $name
     * @return VirtualSystem|null
     */
    public function findVSYS_by_Name($name)
    {
        mwarning('use of obsolete function, please use findVirtualSystem() instead!');
        return $this->findVirtualSystem($name);
    }

    /**
     * @param string $name
     * @return VirtualSystem|null
     */
    public function findVSYS_by_displayName($displayname)
    {
        $tmp_vsys = $this->getVirtualSystems();
        foreach( $tmp_vsys as $vsys )
        {
            if( $vsys->alternativeName() == $displayname )
                return $vsys;

        }

        return null;
    }

    /**
     * @param string $name
     * @return VirtualSystem|null
     */
    public function findSharedGateway_by_displayName($displayname)
    {
        $tmp_vsys = $this->getSharedGateways();
        foreach( $tmp_vsys as $vsys )
        {
            if( $vsys->alternativeName() == $displayname )
                return $vsys;

        }

        return null;
    }

    /**
     * @param string $name
     * @return VirtualSystem|null
     */
    public function findVirtualSystem($name)
    {
        //what about 'panoramaPushedConfig'
        foreach( $this->virtualSystems as $vsys )
        {
            if( $vsys->name() == $name )
            {
                return $vsys;
            }
        }

        return null;
    }

    /**
     * @param string $name
     * @return VirtualSystem|null
     */
    public function findSharedGateway($name)
    {
        foreach( $this->sharedGateways as $vsys )
        {
            if( $vsys->name() == $name )
            {
                return $vsys;
            }
        }

        return null;
    }

    /**
     * @param string $fileName
     * @param bool $printMessage
     */
    public function save_to_file($fileName, $printMessage = TRUE, $lineReturn = TRUE, $indentingXml = 0, $indentingXmlIncreament = 1)
    {
        if( $printMessage )
            PH::print_stdout( "Now saving PANConf to file '$fileName'...");

        $xml = &DH::dom_to_xml($this->xmlroot, $indentingXml, $lineReturn, -1, $indentingXmlIncreament + 1);

        $path_parts = pathinfo($fileName);
        if (!is_dir($path_parts['dirname']))
            mkdir($path_parts['dirname'], 0777, true);

        file_put_contents($fileName, $xml);

        if( $printMessage )
            PH::print_stdout( "     done!" );
    }

    /**
     * @param $fileName string
     */
    public function load_from_file($fileName)
    {
        $filecontents = file_get_contents($fileName);

        $this->load_from_xmlstring($filecontents);
    }

    public function API_load_from_running(PanAPIConnector $conn)
    {
        $this->connector = $conn;

        $xmlDoc = $this->connector->getRunningConfig();
        $this->load_from_domxml($xmlDoc);
    }

    public function API_load_from_candidate(PanAPIConnector $conn)
    {
        $this->connector = $conn;

        $xmlDoc = $this->connector->getCandidateConfig();
        $this->load_from_domxml($xmlDoc);
    }

    /**
     * send current config to the firewall and save under name $config_name
     *
     */
    public function API_uploadConfig($config_name = 'panconfigurator-default.xml')
    {

        PH::print_stdout(  "Uploading config to device...." );

        $url = "&type=import&category=configuration";

        $this->connector->sendRequest($url, FALSE, DH::dom_to_xml($this->xmlroot), $config_name);



    }

    /**
     * @return VirtualSystem[]
     */
    public function getVirtualSystems()
    {
        return $this->virtualSystems;
    }

    /**
     * @return VirtualSystem[]
     */
    public function getSharedGateways()
    {
        return $this->sharedGateways;
    }

    public function display_statistics( $connector = null, $debug = false, $actions = 'display' )
    {
        $displayAvailable = FALSE;
        if( $actions == 'display-available' )
            $displayAvailable = TRUE;

        /*
        //todo: missing stuff
                routing
         - static-routes
         - custom-report
        dhcp
        edl
        gp-gateway
        gp-portal
        gpgateway-tunnel
        gre-tunnel
        ike-gateway
        ike-profile
        ipsec-tunnel
        ipsec-profile
        log-profile
        zone-protection-profile
         */

        $numSecRules = 0;
        $numNatRules = 0;
        $numQosRules = 0;
        $numPbfRules = 0;
        $numDecryptRules = 0;
        $numAppOverrideRules = 0;
        $numCaptivePortalRules = 0;
        $numAuthenticationRules = 0;
        $numDosRules = 0;

        $numTunnelRules = 0;
        $numDefaultRules = 0;
        $numNetworkBrokerRules = 0;
        $numSDwanRules = 0;


        $gnservices = $this->serviceStore->countServices();
        $gnservicesUnused = $this->serviceStore->countUnusedServices();
        $gnserviceGs = $this->serviceStore->countServiceGroups();
        $gnserviceGsUnused = $this->serviceStore->countUnusedServiceGroups();
        $gnTmpServices = $this->serviceStore->countTmpServices();

        $gnaddresss = $this->addressStore->countAddresses();
        $gnaddresssUnused = $this->addressStore->countUnusedAddresses();
        $gnaddressGs = $this->addressStore->countAddressGroups();
        $gnaddressGsUnused = $this->addressStore->countUnusedAddressGroups();
        $gnTmpAddresses = $this->addressStore->countTmpAddresses();
        $gnRegionAddresses = $this->addressStore->countRegionObjects();

        $numInterfaces = $this->network->ipsecTunnelStore->count() + $this->network->ethernetIfStore->count();
        $numSubInterfaces = $this->network->ethernetIfStore->countSubInterfaces();

        $gTagCount = $this->tagStore->count();
        $gTagUnusedCount = $this->tagStore->countUnused();

        $gCertificatCount = $this->certificateStore->count();

        $gSSL_TLSServiceProfileCount = $this->SSL_TLSServiceProfileStore->count();

        $gLogProfileCount = $this->LogProfileStore->count();

        foreach( $this->virtualSystems as $vsys )
        {

            $numSecRules += $vsys->securityRules->count();
            $numNatRules += $vsys->natRules->count();
            $numQosRules += $vsys->qosRules->count();
            $numPbfRules += $vsys->pbfRules->count();
            $numDecryptRules += $vsys->decryptionRules->count();
            $numAppOverrideRules += $vsys->appOverrideRules->count();
            $numCaptivePortalRules += $vsys->captivePortalRules->count();
            $numAuthenticationRules += $vsys->authenticationRules->count();
            $numDosRules += $vsys->dosRules->count();

            $numTunnelRules += $vsys->tunnelInspectionRules->count();
            $numDefaultRules += $vsys->defaultSecurityRules->count();
            $numNetworkBrokerRules += $vsys->networkPacketBrokerRules->count();
            $numSDwanRules += $vsys->sdWanRules->count();

            $gnservices += $vsys->serviceStore->countServices();
            $gnservicesUnused += $vsys->serviceStore->countUnusedServices();
            $gnserviceGs += $vsys->serviceStore->countServiceGroups();
            $gnserviceGsUnused += $vsys->serviceStore->countUnusedServiceGroups();
            $gnTmpServices += $vsys->serviceStore->countTmpServices();

            $gnaddresss += $vsys->addressStore->countAddresses();
            $gnaddresssUnused += $vsys->addressStore->countUnusedAddresses();
            $gnaddressGs += $vsys->addressStore->countAddressGroups();
            $gnaddressGsUnused += $vsys->addressStore->countUnusedAddressGroups();
            $gnTmpAddresses += $vsys->addressStore->countTmpAddresses();
            $gnRegionAddresses = $vsys->addressStore->countRegionObjects();

            $gTagCount += $vsys->tagStore->count();
            $gTagUnusedCount += $vsys->tagStore->countUnused();

            $gCertificatCount += $vsys->certificateStore->count();

            $gSSL_TLSServiceProfileCount += $vsys->SSL_TLSServiceProfileStore->count();

            $gLogProfileCount += $vsys->LogProfileStore->count();

            if( isset(PH::$args['loadpanoramapushedconfig']) && isset($vsys->parentDeviceGroup) )
            {
                $numSecRules += $vsys->parentDeviceGroup->securityRules->count();
                $numNatRules += $vsys->parentDeviceGroup->natRules->count();
                $numQosRules += $vsys->parentDeviceGroup->qosRules->count();
                $numPbfRules += $vsys->parentDeviceGroup->pbfRules->count();
                $numDecryptRules += $vsys->parentDeviceGroup->decryptionRules->count();
                $numAppOverrideRules += $vsys->parentDeviceGroup->appOverrideRules->count();
                $numCaptivePortalRules += $vsys->parentDeviceGroup->captivePortalRules->count();
                $numAuthenticationRules += $vsys->parentDeviceGroup->authenticationRules->count();
                $numDosRules += $vsys->parentDeviceGroup->dosRules->count();

                $numTunnelRules += $vsys->parentDeviceGroup->tunnelInspectionRules->count();
                $numDefaultRules += $vsys->parentDeviceGroup->defaultSecurityRules->count();
                $numNetworkBrokerRules += $vsys->parentDeviceGroup->networkPacketBrokerRules->count();
                $numSDwanRules += $vsys->parentDeviceGroup->sdWanRules->count();

                $gnservices += $vsys->parentDeviceGroup->serviceStore->countServices();
                $gnservicesUnused += $vsys->parentDeviceGroup->serviceStore->countUnusedServices();
                $gnserviceGs += $vsys->parentDeviceGroup->serviceStore->countServiceGroups();
                $gnserviceGsUnused += $vsys->parentDeviceGroup->serviceStore->countUnusedServiceGroups();
                $gnTmpServices += $vsys->parentDeviceGroup->serviceStore->countTmpServices();

                $gnaddresss += $vsys->parentDeviceGroup->addressStore->countAddresses();
                $gnaddresssUnused += $vsys->parentDeviceGroup->addressStore->countUnusedAddresses();
                $gnaddressGs += $vsys->parentDeviceGroup->addressStore->countAddressGroups();
                $gnaddressGsUnused += $vsys->parentDeviceGroup->addressStore->countUnusedAddressGroups();
                $gnTmpAddresses += $vsys->parentDeviceGroup->addressStore->countTmpAddresses();
                $gnRegionAddresses += $vsys->parentDeviceGroup->addressStore->countRegionObjects();

                $gTagCount += $vsys->parentDeviceGroup->tagStore->count();
                $gTagUnusedCount += $vsys->parentDeviceGroup->tagStore->countUnused();

                $gCertificatCount += $vsys->parentDeviceGroup->tagStore->count();

                $gLogProfileCount += $vsys->parentDeviceGroup->LogProfileStore->count();
            }

        }

        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $this );
        $stdoutarray['statstype'] = "objects";

        $header = "Statistics for PANConf '" . $this->name . "'";
        $stdoutarray['header'] = $header;

        if( $connector !== null )
        {
            /** @var PanAPIConnector$connector */
            if( $connector->info_model == "PA-VM" )
                $stdoutarray['model'] = $connector->info_vmlicense;
            else
                $stdoutarray['model'] = $connector->info_model;
        }

        $stdoutarray['security rules'] = $numSecRules;

        $stdoutarray['nat rules'] = $numNatRules;

        $stdoutarray['qos rules'] = $numQosRules;

        $stdoutarray['pbf rules'] = $numPbfRules;

        $stdoutarray['decryption rules'] = $numDecryptRules;

        $stdoutarray['app-override rules'] = $numAppOverrideRules;

        $stdoutarray['capt-portal rules'] = $numCaptivePortalRules;

        $stdoutarray['authentication rules'] = $numAuthenticationRules;

        $stdoutarray['dos rules'] = $numDosRules;

        $stdoutarray['tunnel-inspection rules'] = $numTunnelRules;
        $stdoutarray['default-security rules'] = $numDefaultRules;
        $stdoutarray['network-packet-broker rules'] = $numNetworkBrokerRules;
        $stdoutarray['sdwan rules'] = $numSDwanRules;


        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects']['shared'] = $this->addressStore->countAddresses();
        $stdoutarray['address objects']['total VSYSs'] = $gnaddresss;
        $stdoutarray['address objects']['unused'] = $gnaddresssUnused;

        $stdoutarray['addressgroup objects'] = array();
        $stdoutarray['addressgroup objects']['shared'] = $this->addressStore->countAddressGroups();
        $stdoutarray['addressgroup objects']['total VSYSs'] = $gnaddressGs;
        $stdoutarray['addressgroup objects']['unused'] = $gnaddressGsUnused;

        $stdoutarray['temporary address objects'] = array();
        $stdoutarray['temporary address objects']['shared'] = $this->addressStore->countTmpAddresses();
        $stdoutarray['temporary address objects']['total VSYSs'] = $gnTmpAddresses;

        $stdoutarray['region objects'] = array();
        $stdoutarray['region objects']['shared'] = $this->addressStore->countRegionObjects();
        $stdoutarray['region objects']['total VSYSs'] = $gnRegionAddresses;

        $stdoutarray['service objects'] = array();
        $stdoutarray['service objects']['shared'] = $this->serviceStore->countServices();
        $stdoutarray['service objects']['total VSYSs'] = $gnservices;
        $stdoutarray['service objects']['unused'] = $gnservicesUnused;

        $stdoutarray['servicegroup objects'] = array();
        $stdoutarray['servicegroup objects']['shared'] = $this->serviceStore->countServiceGroups();
        $stdoutarray['servicegroup objects']['total VSYSs'] = $gnserviceGs;
        $stdoutarray['servicegroup objects']['unused'] = $gnserviceGsUnused;

        $stdoutarray['temporary service objects'] = array();
        $stdoutarray['temporary service objects']['shared'] = $this->serviceStore->countTmpServices();
        $stdoutarray['temporary service objects']['total VSYSs'] = $gnTmpServices;


        $stdoutarray['tag objects'] = array();
        $stdoutarray['tag objects']['shared'] = $this->tagStore->count();
        $stdoutarray['tag objects']['total VSYSs'] = $gTagCount;
        $stdoutarray['tag objects']['unused'] = $gTagUnusedCount;


        $stdoutarray['certificate objects'] = array();
        $stdoutarray['certificate objects']['shared'] = $this->certificateStore->count();
        $stdoutarray['certificate objects']['total VSYSs'] = $gCertificatCount;

        $stdoutarray['SSL_TLSServiceProfile objects'] = array();
        $stdoutarray['SSL_TLSServiceProfile objects']['shared'] = $this->SSL_TLSServiceProfileStore->count();
        $stdoutarray['SSL_TLSServiceProfile objects']['total VSYSs'] = $gSSL_TLSServiceProfileCount;

        $stdoutarray['LogProfile objects'] = array();
        $stdoutarray['LogProfile objects']['shared'] = $this->LogProfileStore->count();
        $stdoutarray['LogProfile objects']['total VSYSs'] = $gLogProfileCount;

        #$stdoutarray['zones'] = $this->zoneStore->count();
        #$stdoutarray['apps'] = $this->appStore->count();

        $stdoutarray['interfaces'] = array();
        $stdoutarray['interfaces']['total'] = $numInterfaces;
        $stdoutarray['interfaces']['ethernet'] = $this->network->ethernetIfStore->count();

        $stdoutarray['sub-interfaces'] = array();
        $stdoutarray['sub-interfaces']['total'] = $numSubInterfaces;
        $stdoutarray['sub-interfaces']['ethernet'] = $this->network->ethernetIfStore->countSubInterfaces();

        $stdoutarray['routing'] = array();
        $stdoutarray['routing']['virtual'] = $this->network->virtualRouterStore->count();
        $stdoutarray['routing']['logical'] = $this->network->logicalRouterStore->count();

        $stdoutarray['ZPProfile objects'] = array();
        $stdoutarray['ZPProfile objects']['total'] = $this->network->zoneProtectionProfileStore->count();


        if( !PH::$shadow_json && $actions == "display"  )
            PH::print_stdout( $stdoutarray, true );

        if( $actions == "display-available" )
        {
            PH::stats_remove_zero_arrays($stdoutarray);
            if( !PH::$shadow_json )
                PH::print_stdout( $stdoutarray, true );
        }

        PH::$JSON_TMP[] = $stdoutarray;


        if( !PH::$shadow_json and $actions == "display-bpa" )
            $this->display_bp_statistics( $debug, $actions );
    }

    public function display_bp_statistics( $debug = false, $actions = "display" )
    {
        $stdoutarray = array();
        $stdoutarray['type'] = get_class( $this );

        $header = "Statistics for ".get_class( $this )." '" . PH::boldText('Firewall full') . "'";
        $stdoutarray['header'] = $header;
        $stdoutarray['statstype'] = "adoption";

        foreach( $this->getVirtualSystems() as $virtualSystem )
        {
            $stdoutarray2 = $virtualSystem->get_bp_statistics( $actions );
            foreach ($stdoutarray2 as $key2 => $stdoutarray_value)
            {
                if( $key2 == "header" || $key2 == "type" || $key2 == "statstype" )
                    continue;

                if( strpos( $key2, "calc" ) !== FALSE || strpos( $key2, "percentage" ) !== FALSE )
                    continue;

                if (isset($stdoutarray[$key2]))
                    $stdoutarray[$key2] += intval($stdoutarray_value);
                else
                    $stdoutarray[$key2] = intval($stdoutarray_value);
            }
        }

        $percentageArray = array();

        $percentageArray_visibility = array();

        $ruleForCalculation = $stdoutarray['security rules allow enabled'];

        $stdoutarray['log at end calc'] =  $stdoutarray['log at end'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at end percentage'] = floor(( $stdoutarray['log at end'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at end percentage'] = 0;
        $percentageArray_adoption['Logging']['value'] = $stdoutarray['log at end percentage'];
        $percentageArray_adoption['Logging']['group'] = 'Logging';

        $stdoutarray['log prof set calc'] =  $stdoutarray['log prof set'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log prof set percentage'] = floor(( $stdoutarray['log prof set'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log prof set percentage'] = 0;
        $percentageArray_adoption['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_adoption['Log Forwarding Profiles']['group'] = 'Logging';

        $stdoutarray['wf adoption calc'] =  $stdoutarray['wf adoption'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf adoption percentage'] = floor(( $stdoutarray['wf adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf adoption percentage'] = 0;
        $percentageArray_adoption['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf adoption percentage'];
        $percentageArray_adoption['Wildfire Analysis Profiles']['group'] = 'Wildfire';

        $stdoutarray['zone protection calc'] =  $stdoutarray['zone protection'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['zone protection percentage'] = floor(( $stdoutarray['zone protection'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['zone protection percentage'] = 0;
        $percentageArray_adoption['Zone Protection']['value'] = $stdoutarray['zone protection percentage'];
        $percentageArray_adoption['Zone Protection']['group'] = 'Zone Protection';

        $stdoutarray['app id calc'] =  $stdoutarray['app id'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['app id percentage'] = floor( ( $stdoutarray['app id'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['app id percentage'] = 0;
        $percentageArray_adoption['App-ID']['value'] = $stdoutarray['app id percentage'];
        $percentageArray_adoption['App-ID']['group'] = 'Apps, Users, Ports';

        $stdoutarray['user id calc'] =  $stdoutarray['user id'] ."/". $stdoutarray['security rules'];
        if( $ruleForCalculation !== 0 )
            $stdoutarray['user id percentage'] = floor( ( $stdoutarray['user id'] / $stdoutarray['security rules'] ) * 100 );
        else
            $stdoutarray['user id percentage'] = 0;
        $percentageArray_adoption['User-ID']['value'] = $stdoutarray['user id percentage'];
        $percentageArray_adoption['User-ID']['group'] = 'Apps, Users, Ports';

        $stdoutarray['service port calc'] = $stdoutarray['service port'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['service port percentage'] = floor( ( $stdoutarray['service port'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['service port percentage'] = 0;
        $percentageArray_adoption['Service/Port']['value'] = $stdoutarray['service port percentage'];
        $percentageArray_adoption['Service/Port']['group'] = 'Apps, Users, Ports';

        $stdoutarray['av adoption calc'] = $stdoutarray['av adoption'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av adoption percentage'] = floor( ( $stdoutarray['av adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av adoption percentage'] = 0;
        $percentageArray_adoption['Antivirus Profiles']['value'] = $stdoutarray['av adoption percentage'];
        $percentageArray_adoption['Antivirus Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['as adoption calc'] = $stdoutarray['as adoption'] . "/" . $ruleForCalculation ;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as adoption percentage'] = floor( ( $stdoutarray['as adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as adoption percentage'] = 0;
        $percentageArray_adoption['Anti-Spyware Profiles']['value'] = $stdoutarray['as adoption percentage'];
        $percentageArray_adoption['Anti-Spyware Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['vp adoption calc'] = $stdoutarray['vp adoption'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp adoption percentage'] = floor( ( $stdoutarray['vp adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp adoption percentage'] = 0;
        $percentageArray_adoption['Vulnerability Profiles']['value'] = $stdoutarray['vp adoption percentage'];
        $percentageArray_adoption['Vulnerability Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['fb adoption calc'] = $stdoutarray['fb adoption' ]." / " . $ruleForCalculation ;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb adoption percentage'] = floor( ( $stdoutarray['fb adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb adoption percentage'] = 0;
        $percentageArray_adoption['File Blocking Profiles']['value'] = $stdoutarray['fb adoption percentage'];
        $percentageArray_adoption['File Blocking Profiles']['group'] = 'Data Loss Prevention';

        $stdoutarray['data adoption calc'] = $stdoutarray['data adoption'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['data adoption percentage'] = floor( ( $stdoutarray['data adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['data adoption percentage'] = 0;
        $percentageArray_adoption['Data Filtering']['value'] = $stdoutarray['data adoption percentage'];
        $percentageArray_adoption['Data Filtering']['group'] = 'Data Loss Prevention';

        $stdoutarray['url-site-access adoption calc'] = $stdoutarray['url-site-access adoption'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access adoption percentage'] = floor( ( $stdoutarray['url-site-access adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access adoption percentage'] = 0;
        $percentageArray_adoption['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access adoption percentage'];
        $percentageArray_adoption['URL Filtering Profiles']['group'] = 'URL Filtering';

        $stdoutarray['url-credential adoption calc'] =  $stdoutarray['url-credential adoption'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential adoption percentage'] = floor( ( $stdoutarray['url-credential adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential adoption percentage'] = 0;
        $percentageArray_adoption['Credential Theft Prevention']['value'] = $stdoutarray['url-credential adoption percentage'];
        $percentageArray_adoption['Credential Theft Prevention']['group'] = 'URL Filtering';

        $stdoutarray['dns-list adoption calc'] = $stdoutarray['dns-list adoption'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list adoption percentage'] = floor( ( $stdoutarray['dns-list adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list adoption percentage'] = 0;
        #$percentageArray_adoption['DNS List']['value'] = $stdoutarray['dns-list adoption percentage'];

        $stdoutarray['dns-security adoption calc'] =  $stdoutarray['dns-security adoption'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security adoption percentage'] = floor( ( $stdoutarray['dns-security adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security adoption percentage'] = 0;
        $percentageArray_adoption['DNS Security']['value'] = $stdoutarray['dns-security adoption percentage'];
        $percentageArray_adoption['DNS Security']['group'] = 'DNS Security';

        $percentageArray['adoption'] = $percentageArray_adoption;

        //----------
        $percentageArray_visibility = array();

        $ruleForCalculation = $stdoutarray['security rules allow enabled'];

        $stdoutarray['log at end calc'] =  $stdoutarray['log at end'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at end percentage'] = floor(( $stdoutarray['log at end'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at end percentage'] = 0;
        $percentageArray_visibility['Logging']['value'] = $stdoutarray['log at end percentage'];
        $percentageArray_visibility['Logging']['group'] = 'Logging';

        $stdoutarray['log prof set calc'] =  $stdoutarray['log prof set'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log prof set percentage'] = floor(( $stdoutarray['log prof set'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log prof set percentage'] = 0;
        $percentageArray_visibility['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_visibility['Log Forwarding Profiles']['group'] = 'Logging';

        $stdoutarray['wf visibility calc'] =  $stdoutarray['wf visibility'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf visibility percentage'] = floor(( $stdoutarray['wf visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf visibility percentage'] = 0;
        $percentageArray_visibility['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf visibility percentage'];
        $percentageArray_visibility['Wildfire Analysis Profiles']['group'] = 'Wildfire';


        $stdoutarray['zone protection calc'] =  $stdoutarray['zone protection'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['zone protection percentage'] = floor(( $stdoutarray['zone protection'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['zone protection percentage'] = 0;
        $percentageArray_visibility['Zone Protection']['value'] = $stdoutarray['zone protection percentage'];
        $percentageArray_visibility['Zone Protection']['group'] = 'Zone Protection';

        $stdoutarray['app id calc'] =  $stdoutarray['app id'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['app id percentage'] = floor( ( $stdoutarray['app id'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['app id percentage'] = 0;
        $percentageArray_visibility['App-ID']['value'] = $stdoutarray['app id percentage'];
        $percentageArray_visibility['App-ID']['group'] = 'Apps, Users, Ports';

        $stdoutarray['user id calc'] =  $stdoutarray['user id'] ."/". $stdoutarray['security rules'];
        if( $ruleForCalculation !== 0 )
            $stdoutarray['user id percentage'] = floor( ( $stdoutarray['user id'] / $stdoutarray['security rules'] ) * 100 );
        else
            $stdoutarray['user id percentage'] = 0;
        $percentageArray_visibility['User-ID']['value'] = $stdoutarray['user id percentage'];
        $percentageArray_visibility['User-ID']['group'] = 'Apps, Users, Ports';

        $stdoutarray['service port calc'] = $stdoutarray['service port'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['service port percentage'] = floor( ( $stdoutarray['service port'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['service port percentage'] = 0;
        $percentageArray_visibility['Service/Port']['value'] = $stdoutarray['service port percentage'];
        $percentageArray_visibility['Service/Port']['group'] = 'Apps, Users, Ports';

        $stdoutarray['av visibility calc'] = $stdoutarray['av visibility'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av visibility percentage'] = floor( ( $stdoutarray['av visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av visibility percentage'] = 0;
        $percentageArray_visibility['Antivirus Profiles']['value'] = $stdoutarray['av visibility percentage'];
        $percentageArray_visibility['Antivirus Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['as visibility calc'] = $stdoutarray['as visibility'] . "/" . $ruleForCalculation ;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as visibility percentage'] = floor( ( $stdoutarray['as visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as visibility percentage'] = 0;
        $percentageArray_visibility['Anti-Spyware Profiles']['value'] = $stdoutarray['as visibility percentage'];
        $percentageArray_visibility['Anti-Spyware Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['vp visibility calc'] = $stdoutarray['vp visibility'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp visibility percentage'] = floor( ( $stdoutarray['vp visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp visibility percentage'] = 0;
        $percentageArray_visibility['Vulnerability Profiles']['value'] = $stdoutarray['vp visibility percentage'];
        $percentageArray_visibility['Vulnerability Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['fb visibility calc'] = $stdoutarray['fb visibility' ]." / " . $ruleForCalculation ;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb visibility percentage'] = floor( ( $stdoutarray['fb visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb visibility percentage'] = 0;
        $percentageArray_visibility['File Blocking Profiles']['value'] = $stdoutarray['fb visibility percentage'];
        $percentageArray_visibility['File Blocking Profiles']['group'] = 'Data Loss Prevention';

        $stdoutarray['data visibility calc'] = $stdoutarray['data visibility'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['data visibility percentage'] = floor( ( $stdoutarray['data visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['data visibility percentage'] = 0;
        $percentageArray_visibility['Data Filtering']['value'] = $stdoutarray['data visibility percentage'];
        $percentageArray_visibility['Data Filtering']['group'] = 'Data Loss Prevention';

        $stdoutarray['url-site-access visibility calc'] = $stdoutarray['url-site-access visibility'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access visibility percentage'] = floor( ( $stdoutarray['url-site-access visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access visibility percentage'] = 0;
        $percentageArray_visibility['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access visibility percentage'];
        $percentageArray_visibility['URL Filtering Profiles']['group'] = 'URL Filtering';

        $stdoutarray['url-credential visibility calc'] =  $stdoutarray['url-credential visibility'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential visibility percentage'] = floor( ( $stdoutarray['url-credential visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential visibility percentage'] = 0;
        $percentageArray_visibility['Credential Theft Prevention']['value'] = $stdoutarray['url-credential visibility percentage'];
        $percentageArray_visibility['Credential Theft Prevention']['group'] = 'URL Filtering';

        $stdoutarray['dns-list visibility calc'] = $stdoutarray['dns-list visibility'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list visibility percentage'] = floor( ( $stdoutarray['dns-list visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list visibility percentage'] = 0;
        #$percentageArray_visibility['DNS List']['value'] = $stdoutarray['dns-list visibility percentage'];

        $stdoutarray['dns-security visibility calc'] =  $stdoutarray['dns-security visibility'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security visibility percentage'] = floor( ( $stdoutarray['dns-security visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security visibility percentage'] = 0;
        $percentageArray_visibility['DNS Security']['value'] = $stdoutarray['dns-security visibility percentage'];
        $percentageArray_visibility['DNS Security']['group'] = 'DNS Security';

        $percentageArray['visibility'] = $percentageArray_visibility;


        $percentageArray_best_practice = array();
        $stdoutarray['log at not start calc'] = $stdoutarray['log at not start'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at not start percentage'] = floor(( $stdoutarray['log at not start'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at not start percentage'] = 0;
        $percentageArray_best_practice['Logging']['value'] = $stdoutarray['log at not start percentage'];
        $percentageArray_best_practice['Logging']['group'] = 'Logging';
        #$percentageArray_best_practice['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];

        $stdoutarray['wf best-practice calc'] = $stdoutarray['wf best-practice'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf best-practice percentage'] = floor( ( $stdoutarray['wf best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf best-practice percentage'] = 0;
        $percentageArray_best_practice['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf best-practice percentage'];
        $percentageArray_best_practice['Wildfire Analysis Profiles']['group'] = 'Wildfire';

        #$percentageArray_best_practice['Zone Protection']['value'] = '---';
        #$percentageArray_best_practice['App-ID']['value'] = $stdoutarray['app id percentage'];
        #$percentageArray_best_practice['User-ID']['value'] = $stdoutarray['user id percentage'];
        #$percentageArray_best_practice['Service/Port']['value'] = $stdoutarray['service port percentage'];

        $stdoutarray['av best-practice calc'] = $stdoutarray['av best-practice'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av best-practice percentage'] = floor( ( $stdoutarray['av best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av best-practice percentage'] = 0;
        $percentageArray_best_practice['Antivirus Profiles']['value'] = $stdoutarray['av best-practice percentage'];
        $percentageArray_best_practice['Antivirus Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['as best-practice calc'] = $stdoutarray['as best-practice']." / " . $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as best-practice percentage'] = floor( ( $stdoutarray['as best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as best-practice percentage'] = 0;
        $percentageArray_best_practice['Anti-Spyware Profiles']['value'] = $stdoutarray['as best-practice percentage'];
        $percentageArray_best_practice['Anti-Spyware Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['vp best-practice calc'] = $stdoutarray['vp best-practice'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp best-practice percentage'] = floor( ( $stdoutarray['vp best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp best-practice percentage'] = 0;
        $percentageArray_best_practice['Vulnerability Profiles']['value'] = $stdoutarray['vp best-practice percentage'];
        $percentageArray_best_practice['Vulnerability Profiles']['group'] = 'Threat Prevention';

        $stdoutarray['fb best-practice calc'] = $stdoutarray['fb best-practice' ]." / " . $ruleForCalculation ;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb best-practice percentage'] = floor( ( $stdoutarray['fb best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb best-practice percentage'] = 0;
        $percentageArray_best_practice['File Blocking Profiles']['value'] = $stdoutarray['fb best-practice percentage'];
        $percentageArray_best_practice['File Blocking Profiles']['group'] = 'Data Loss Prevention';

        #$percentageArray_best_practice['Data Filtering'] = '---';

        $stdoutarray['url-site-access best-practice calc'] = $stdoutarray['url-site-access best-practice'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access best-practice percentage'] = floor( ( $stdoutarray['url-site-access best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access best-practice percentage'] = 0;
        $percentageArray_best_practice['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access best-practice percentage'];
        $percentageArray_best_practice['URL Filtering Profiles']['group'] = 'URL Filtering';

        $stdoutarray['url-credential best-practice calc'] = $stdoutarray['url-credential best-practice'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential best-practice percentage'] = floor( ( $stdoutarray['url-credential best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential best-practice percentage'] = 0;
        $percentageArray_best_practice['Credential Theft Prevention']['value'] = $stdoutarray['url-credential best-practice percentage'];
        $percentageArray_best_practice['Credential Theft Prevention']['group'] = 'URL Filtering';

        $stdoutarray['dns-list best-practice calc'] = $stdoutarray['dns-list best-practice'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list best-practice percentage'] = floor( ( $stdoutarray['dns-list best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list best-practice percentage'] = 0;
        #$percentageArray_best_practice['DNS List']['value'] = $stdoutarray['dns-list best-practice percentage'];

        $stdoutarray['dns-security best-practice calc'] = $stdoutarray['dns-security best-practice'] ."/". $ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security best-practice percentage'] = floor( ( $stdoutarray['dns-security best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security best-practice percentage'] = 0;
        $percentageArray_best_practice['DNS Security']['value'] = $stdoutarray['dns-security best-practice percentage'];
        $percentageArray_best_practice['DNS Security']['group'] = 'DNS Security';

        $percentageArray['best-practice'] = $percentageArray_best_practice;

        $stdoutarray['percentage'] = $percentageArray;

        //Todo swaschkut 20251014
        //todo: validate if information must be changed bas on bp_sp_panw.json
        PH::validateIncludedInBPA( $stdoutarray );

        $percentageArray_adoption = $stdoutarray['percentage']['adoption'];
        $percentageArray_visibility = $stdoutarray['percentage']['visibility'];
        $percentageArray_best_practice = $stdoutarray['percentage']['best-practice'];

        if( !PH::$shadow_json && $actions == "display-bpa")
        {
            PH::print_stdout( $header );

            PH::print_stdout("adoption");
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_adoption as $key => $value )
            {
                if( strpos($value['value'], "---") !== False )
                {
                    $string = $value['value'];
                }
                else
                {
                    $string = "";
                    $test = floor( ($value['value']/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value['value'], $string));
            }

            echo $tbl->getTable();


            PH::print_stdout("visibility");
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_visibility as $key => $value )
            {
                if( strpos($value['value'], "---") !== False )
                {
                    $string = $value['value'];
                }
                else
                {
                    $string = "";
                    $test = floor( ($value['value']/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value['value'], $string));
            }

            echo $tbl->getTable();

            PH::print_stdout("best-practice");
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_best_practice as $key => $value )
            {
                if( strpos($value['value'], "---") !== False )
                {
                    $string = $value['value'];
                }
                else
                {
                    $string = "";
                    $test = floor( ($value['value']/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value['value'], $string));
            }

            echo $tbl->getTable();

            PH::print_stdout( );
        }



        if( !PH::$shadow_json && $debug && $actions == "display" )
            PH::print_stdout( $stdoutarray, true );

        if( $actions == "display-available" )
        {
            PH::stats_remove_zero_arrays($stdoutarray);
            if( !PH::$shadow_json )
                PH::print_stdout( $stdoutarray, true );
        }

        PH::$JSON_TMP[] = $stdoutarray;
    }

    public function isFirewall()
    {
        return TRUE;
    }

    public function createVirtualSystem($vsysID, $displayName = '')
    {
        if( !is_numeric($vsysID) )
            derr("new vsys id must be an integer but '$vsysID' was provided");

        $newVsysName = 'vsys' . $vsysID;

        if( $this->findVirtualSystem($newVsysName) !== null )
            derr("cannot create '$newVsysName' because it already exists");

        if( $this->owner != null && get_class($this->owner) ==  "Template")
            $xmlNode = DH::importXmlStringOrDie($this->xmldoc, Template::$templateVSYSxml);
        else
            $xmlNode = DH::importXmlStringOrDie($this->xmldoc, VirtualSystem::$templateXml);

        $xmlNode->setAttribute('name', $newVsysName);
        if( strlen($displayName) > 0 )
        {
            if( $this->owner != null && get_class($this->owner) ==  "Template")
            {

            }
            else
                DH::createElement($xmlNode, 'display-name', $displayName);

        }

        $domNode = $this->vsyssroot->ownerDocument->importNode( $xmlNode, true );
        $this->vsyssroot->appendChild($domNode);

        $newVsys = new VirtualSystem($this);
        $newVsys->load_from_domxml($xmlNode);

        $this->virtualSystems[] = $newVsys;

        return $newVsys;
    }

    /**
     * Remove a VirtualSystem.
     * @param VirtualSystem $vsys
     **/
    public function removeVirtualSystem( $vsys )
    {
        $VSYSname = $vsys->name();

        //remove VSYS from XML
        $xPath = "/config/devices/entry[@name='localhost.localdomain']/vsys";
        $dgNode = DH::findXPathSingleEntryOrDie($xPath, $this->xmlroot);

        $DGremove = DH::findFirstElementByNameAttrOrDie('entry', $VSYSname, $dgNode);
        $dgNode->removeChild( $DGremove );

        unset($this->virtualSystems[ $VSYSname ]);
    }

    /**
     * Remove a VirtualSystem.
     * @param VirtualSystem $vsys
     **/
    public function removeSharedGateway( $vsys )
    {
        $VSYSname = $vsys->name();

        //remove VSYS from XML
        $xPath = "/config/devices/entry[@name='localhost.localdomain']/network/shared-gateway";
        $dgNode = DH::findXPathSingleEntryOrDie($xPath, $this->xmlroot);

        $DGremove = DH::findFirstElementByNameAttrOrDie('entry', $VSYSname, $dgNode);
        $dgNode->removeChild( $DGremove );


        //remove XMLnode "shared-gateway" if no XML childNodes are available
        if( !DH::hasChild($dgNode) )
        {
            $xPath2 = "/config/devices/entry[@name='localhost.localdomain']/network";
            $dgNode2 = DH::findXPathSingleEntryOrDie($xPath2, $this->xmlroot);

            $dgNode2->removeChild( $dgNode );
        }

        unset($this->sharedGateways[ $VSYSname ]);
    }

    public function findSubSystemByName($location)
    {
        $vsys = $this->findVirtualSystem($location);
        if( $vsys === null )
            $vsys = $this->findSharedGateway($location);
        return $vsys;
    }

    // this is for !shared
    public function childDeviceGroups()
    {
        return $this->getVirtualSystems();
    }
}

