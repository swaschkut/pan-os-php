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
    use StatCollectorTrait;

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

    public $sizeArray = array();
    public $sizeArrayShared = array();

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

    public function __destruct()
    {
        $this->cleanupMemory();
    }

    /**
     * Cleans up memory by setting all object references to null.
     * This helps PHP's garbage collector handle circular references.
     */
    public function cleanupMemory()
    {
        // Clear DOM references first - these hold the most memory
        $this->xmldoc = null;
        $this->xmlroot = null;
        $this->sharedroot = null;
        $this->devicesroot = null;
        $this->localhostroot = null;
        $this->deviceconfigroot = null;
        $this->vsyssroot = null;

        // Clear virtual systems
        if( isset($this->virtualSystems) && is_array($this->virtualSystems) )
        {
            foreach( $this->virtualSystems as $vsys )
            {
                if( method_exists($vsys, 'cleanupMemory') )
                    $vsys->cleanupMemory();
            }
            $this->virtualSystems = array();
        }

        // Clear shared gateways
        if( isset($this->sharedGateways) && is_array($this->sharedGateways) )
        {
            $this->sharedGateways = array();
        }

        // Clear object stores
        $this->tagStore = null;
        $this->appStore = null;
        $this->threatStore = null;
        $this->urlStore = null;
        $this->serviceStore = null;
        $this->addressStore = null;

        // Clear security profile stores
        $this->customURLProfileStore = null;
        $this->URLProfileStore = null;
        $this->AntiVirusProfileStore = null;
        $this->ThreatPolicyStore = null;
        $this->DNSPolicyStore = null;
        $this->VulnerabilityProfileStore = null;
        $this->AntiSpywareProfileStore = null;
        $this->FileBlockingProfileStore = null;
        $this->DataFilteringProfileStore = null;
        $this->WildfireProfileStore = null;
        $this->securityProfileGroupStore = null;

        // Clear additional profile stores
        $this->DecryptionProfileStore = null;
        $this->HipObjectsProfileStore = null;
        $this->HipProfilesProfileStore = null;
        $this->GTPProfileStore = null;
        $this->SCEPProfileStore = null;
        $this->PacketBrokerProfileStore = null;
        $this->SDWanErrorCorrectionProfileStore = null;
        $this->SDWanPathQualityProfileStore = null;
        $this->SDWanSaasQualityProfileStore = null;
        $this->SDWanTrafficDistributionProfileStore = null;
        $this->DataObjectsProfileStore = null;

        // Clear other stores
        $this->scheduleStore = null;
        $this->EDLStore = null;
        $this->LogProfileStore = null;
        $this->certificateStore = null;
        $this->SSL_TLSServiceProfileStore = null;

        // Clear network properties
        $this->network = null;

        // Clear other references
        $this->connector = null;
        $this->owner = null;
        $this->panorama = null;
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

                        }
                        else
                        {
                            #PH::print_stdout("timezone: '".$this->timezone."' not supported by IANA");
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
            $tmp = DH::findFirstElement('address', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->addressStore->load_addresses_from_domxml($tmp);
            // end of address extraction

            //
            // Extract address groups
            //
            $tmp = DH::findFirstElement('address-group', $this->sharedroot);
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
                }


                //
                // URL Profile extraction
                //
                $tmproot = DH::findFirstElement('url-filtering', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->URLProfileStore->load_from_domxml($tmproot);
                }

                //
                // AntiVirus Profile extraction
                //
                $tmproot = DH::findFirstElement('virus', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->AntiVirusProfileStore->load_from_domxml($tmproot);
                }

                //
                // FileBlocking Profile extraction
                //
                $tmproot = DH::findFirstElement('file-blocking', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->FileBlockingProfileStore->load_from_domxml($tmproot);
                }

                //
                // DataFiltering Profile extraction
                //
                $tmproot = DH::findFirstElement('data-filtering', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->DataFilteringProfileStore->load_from_domxml($tmproot);
                }

                //
                // vulnerability Profile extraction
                //
                $tmproot = DH::findFirstElement('vulnerability', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->VulnerabilityProfileStore->load_from_domxml($tmproot);
                }

                //
                // spyware Profile extraction
                //
                $tmproot = DH::findFirstElement('spyware', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
                    $this->AntiSpywareProfileStore->load_from_domxml($tmproot);
                }

                //
                // wildfire Profile extraction
                //
                $tmproot = DH::findFirstElement('wildfire-analysis', $this->securityProfilebaseroot);
                if( $tmproot !== FALSE )
                {
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
            $tmp = DH::findFirstElement('external-list', $this->sharedroot);
            if( $tmp !== FALSE )
                $this->EDLStore->load_from_domxml($tmp);
            // End of EDL extraction

            //
            // Extract LogProfile objects
            //
            $tmp2 = DH::findFirstElement('log-settings', $this->sharedroot);
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
        $statsArray = array();

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


        $this->get_mainDevice_statistics($statsArray);



        foreach( $this->virtualSystems as $vsys )
        {
            $cur = $vsys;
            $this->get_combined_subDevice_statistics($statsArray, $vsys, true );


            if( isset(PH::$args['loadpanoramapushedconfig']) && isset($cur->parentDeviceGroup) )
                $this->get_combined_subDevice_statistics($statsArray, $vsys->parentDeviceGroup, true );

        }


        //$this->display_PANConf_statistics_NEW( $debug, $actions, $statsArray, $connector );
        $this->display_statistics_NEW( $debug, $actions, $statsArray, $connector );



        if( !PH::$shadow_json and $actions == "display-bpa" )
            $this->display_bp_statistics( $debug, $actions );



        foreach( $this->virtualSystems as $vsys )
        {
            if( !PH::$shadow_json and $actions == "display-bpa" )
                $vsys->display_bp_statistics( $debug, $actions );
        }
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
            $stdoutarray2 = $virtualSystem->get_bp_statistics( );
            foreach ($stdoutarray2 as $key2 => $stdoutarray_value)
            {
                if( $key2 == "header" || $key2 == "type" || $key2 == "statstype" )
                    continue;

                if( strpos( $key2, "calc" ) !== FALSE
                    || strpos( $key2, "percentage" ) !== FALSE

                )
                {

                    continue;
                }


                if (isset($stdoutarray[$key2]))
                    $stdoutarray[$key2] += intval($stdoutarray_value);
                else
                    $stdoutarray[$key2] = intval($stdoutarray_value);
            }
        }

        $this->bp_calculation( $stdoutarray );


        $percentageArray = $this->get_bp_percentageArray($stdoutarray);

        $stdoutarray['percentage'] = $percentageArray;

        PH::$JSON_TMP[] = $stdoutarray;

        $this->generate_table( $stdoutarray, $debug, $actions );
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

