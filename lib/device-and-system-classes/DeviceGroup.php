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


class DeviceGroup
{

    use PathableName;
    use PanSubHelperTrait;
    use XmlConvertible;
    use StatCollectorTrait;

    /** String */
    protected $name;

    /** @var PanoramaConf */
    public $owner = null;


    /** @var DOMElement */
    public $devicesRoot;

    public $userGroupSourceRoot;

    /** @var AddressStore */
    public $addressStore = null;
    /** @var ServiceStore */
    public $serviceStore = null;


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

    public static $templatexml = '<entry name="**Need a Name**"><address></address><post-rulebase><security><rules></rules></security><nat><rules></rules></nat></post-rulebase>
									<pre-rulebase><security><rules></rules></security><nat><rules></rules></nat></pre-rulebase>
									</entry>';


    /** @var AppStore */
    public $appStore;

    /** @var ThreatStore */
    public $threatStore;

    /** @var TagStore */
    public $tagStore = null;

    /** @var ZoneStore */
    public $zoneStore = null;

    /** @var RuleStore */
    public $securityRules = null;

    /** @var RuleStore */
    public $natRules = null;

    /** @var RuleStore */
    public $decryptionRules = null;

    /** @var RuleStore */
    public $appOverrideRules;

    /** @var RuleStore */
    public $captivePortalRules;

    /** @var RuleStore */
    public $authenticationRules;

    /** @var RuleStore */
    public $pbfRules;

    /** @var RuleStore */
    public $qosRules;

    /** @var RuleStore */
    public $dosRules;

    /** @var RuleStore */
    public $tunnelInspectionRules;

    /** @var RuleStore */
    public $defaultSecurityRules = null;
    public $defaultIntraZoneRuleSet = False;
    public $defaultInterZoneRuleSet = False;

    /** @var RuleStore */
    public $networkPacketBrokerRules;

    /** @var RuleStore */
    public $sdWanRules;

    /**
     * @var null|DeviceGroup
     */
    public $parentDeviceGroup = null;

    /** @var DeviceGroup[] */
    public $_childDeviceGroups = array();

    /** @var Array */
    private $devices = array();

    /** @var NetworkPropertiesContainer */
    public $_fakeNetworkProperties;

    public $version = null;

    public $device = null;
    public $apiCache = null;

    public $debugLoadTime = false;

    public $sizeArray = array();

    public function __construct($owner)
    {
        $this->owner = $owner;
        $this->version = &$owner->version;

        $this->device = array();

        $this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';

        $this->zoneStore = $owner->zoneStore;

        //this is not working correctly - each DG has its own appstore
        #$this->appStore = $owner->appStore;
        $this->appStore = new AppStore($this);
        $this->appStore->name = 'customApplication';

        $this->threatStore = $owner->threatStore;

        $this->serviceStore = new ServiceStore($this);
        $this->serviceStore->name = 'services';

        $this->addressStore = new AddressStore($this);
        $this->addressStore->name = 'address';


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

        $this->GTPProfileStore = new SecurityProfileStore($this, "GTPProfile");
        $this->GTPProfileStore->name = 'GTPProfiles';

        $this->SCEPProfileStore = new SecurityProfileStore($this, "SCEPProfile");
        $this->SCEPProfileStore->name = 'SCEPProfiles';

        $this->PacketBrokerProfileStore = new SecurityProfileStore($this, "PacketBrokerProfile");
        $this->PacketBrokerProfileStore->name = 'PacketBrokerProfiles';

        $this->SDWanErrorCorrectionProfileStore = new SecurityProfileStore($this, "SDWanErrorCorrectionProfile");
        $this->SDWanErrorCorrectionProfileStore->name = 'SDWanErrorCorrectionProfiles';

        $this->SDWanPathQualityProfileStore = new SecurityProfileStore($this, "SDWanPathQualityProfile");
        $this->SDWanPathQualityProfileStore->name = 'SDWanPathQualityProfiles';

        $this->SDWanSaasQualityProfileStore = new SecurityProfileStore($this, "SDWanSaasQualityProfile");
        $this->SDWanSaasQualityProfileStore->name = 'SDWanSaasQualityProfiles';

        $this->SDWanTrafficDistributionProfileStore = new SecurityProfileStore($this, "SDWanTrafficDistributionProfile");
        $this->SDWanTrafficDistributionProfileStore->name = 'SDWanTrafficDistributionProfiles';

        $this->DataObjectsProfileStore = new SecurityProfileStore($this, "DataObjectsProfile");
        $this->DataObjectsProfileStore->name = 'DataObjectsProfileStoreProfiles';


        $this->scheduleStore = new ScheduleStore($this);
        $this->scheduleStore->setName('scheduleStore');

        $this->EDLStore = new EDLStore($this);
        $this->EDLStore->setName('EDLStore');

        $this->LogProfileStore = new LogProfileStore($this);
        $this->LogProfileStore->setName('LogProfileStore');

        $this->securityRules = new RuleStore($this, 'SecurityRule', TRUE);
        $this->natRules = new RuleStore($this, 'NatRule', TRUE);
        $this->decryptionRules = new RuleStore($this, 'DecryptionRule', TRUE);
        $this->appOverrideRules = new RuleStore($this, 'AppOverrideRule', TRUE);
        $this->captivePortalRules = new RuleStore($this, 'CaptivePortalRule', TRUE);
        $this->authenticationRules = new RuleStore($this, 'AuthenticationRule', TRUE);
        $this->pbfRules = new RuleStore($this, 'PbfRule', TRUE);
        $this->qosRules = new RuleStore($this, 'QoSRule', TRUE);
        $this->dosRules = new RuleStore($this, 'DoSRule', TRUE);
        $this->tunnelInspectionRules = new RuleStore($this, 'TunnelInspectionRule', TRUE);

        $this->defaultSecurityRules = new RuleStore($this, 'DefaultSecurityRule', TRUE);

        $this->networkPacketBrokerRules = new RuleStore($this, 'NetworkPacketBrokerRule', TRUE);
        $this->sdWanRules = new RuleStore($this, 'SDWanRule', TRUE);

        $this->_fakeNetworkProperties = $this->owner->_fakeNetworkProperties;
        $this->dosRules->_networkStore = $this->_fakeNetworkProperties;
        $this->pbfRules->_networkStore = $this->_fakeNetworkProperties;
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
        // Clear DOM reference
        $this->xmlroot = null;

        // Clear object stores
        $this->tagStore = null;
        $this->zoneStore = null;
        #$this->certificateStore = null;
        #$this->SSL_TLSServiceProfileStore = null;
        #$this->appStore = null;
        $this->threatStore = null;
        #$this->urlStore = null;
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

        // Clear rule stores
        $this->securityRules = null;
        $this->natRules = null;
        $this->decryptionRules = null;
        $this->appOverrideRules = null;
        $this->captivePortalRules = null;
        $this->authenticationRules = null;
        $this->pbfRules = null;
        $this->qosRules = null;
        $this->dosRules = null;
        $this->tunnelInspectionRules = null;
        $this->defaultSecurityRules = null;
        $this->networkPacketBrokerRules = null;
        $this->sdWanRules = null;

        // Clear other properties
        $this->_fakeNetworkProperties = null;
        $this->owner = null;
    }

    public function load_from_templateXml()
    {
        if( $this->owner === null )
            derr('cannot be used if owner === null');

        $fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

        if( !$fragment->appendXML(self::$templatexml) )
            derr('error occured while loading device group template xml');

        $element = $this->owner->devicegrouproot->appendChild($fragment);

        $this->load_from_domxml($element);
    }

    public function init_load_from_domxml_devices($xml, $debugLoadTime = false)
    {
        $this->debugLoadTime = $debugLoadTime;

        $this->xmlroot = $xml;

        // this DeviceGroup has a name ?
        $this->name = DH::findAttribute('name', $xml);
        if ($this->name === FALSE)
            derr("DeviceGroup name not found\n");

        if ($debugLoadTime)
            PH::print_DEBUG_loadtime("devices");

        // Devices extraction
        $this->devicesRoot = DH::findFirstElement('devices', $xml);
        if ($this->devicesRoot !== FALSE) {
            foreach ($this->devicesRoot->childNodes as $device) {
                if ($device->nodeType != 1) continue;
                $devname = DH::findAttribute('name', $device);
                $vsyslist = array();

                $vsysChild = DH::firstChildElement($device);

                if ($vsysChild !== FALSE) {
                    foreach ($vsysChild->childNodes as $vsysentry) {
                        if ($vsysentry->nodeType != 1) continue;
                        $vname = DH::findAttribute('name', $vsysentry);
                        $vsyslist[$vname] = $vname;
                    }
                } else {
                    //print "No vsys for device '$devname'\n";
                    $vsyslist['vsys1'] = 'vsys1';
                }

                $this->devices[$devname] = array('serial' => $devname, 'vsyslist' => $vsyslist);
                foreach ($this->devices as $serial => $array) {
                    $managedFirewall = $this->owner->managedFirewallsStore->find($serial);
                    if ($managedFirewall !== null) {
                        $managedFirewall->addDeviceGroup($this->name);
                        $managedFirewall->addReference($this);
                    }

                }
            }
        }
    }

    /**
     * !! Should not be used outside of a PanoramaConf constructor. !!
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml, $debugLoadTime = false)
    {
        $this->xmlroot = $xml;

        // this DeviceGroup has a name ?
        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("DeviceGroup name not found\n");

        /*
        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("devices");

        // Devices extraction
        $this->devicesRoot = DH::findFirstElement('devices', $xml);
        if( $this->devicesRoot !== FALSE )
        {
            foreach( $this->devicesRoot->childNodes as $device )
            {
                if( $device->nodeType != 1 ) continue;
                $devname = DH::findAttribute('name', $device);
                $vsyslist = array();

                $vsysChild = DH::firstChildElement($device);

                if( $vsysChild !== FALSE )
                {
                    foreach( $vsysChild->childNodes as $vsysentry )
                    {
                        if( $vsysentry->nodeType != 1 ) continue;
                        $vname = DH::findAttribute('name', $vsysentry);
                        $vsyslist[$vname] = $vname;
                    }
                }
                else
                {
                    //print "No vsys for device '$devname'\n";
                    $vsyslist['vsys1'] = 'vsys1';
                }

                $this->devices[$devname] = array('serial' => $devname, 'vsyslist' => $vsyslist);
                foreach( $this->devices as $serial => $array )
                {
                    $managedFirewall = $this->owner->managedFirewallsStore->find($serial);
                    if( $managedFirewall !== null )
                    {
                        $managedFirewall->addDeviceGroup($this->name);
                        $managedFirewall->addReference($this);
                    }

                }
            }
        }
        */

        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("tag");
        //
        // Extract Tag objects
        //
        if( $this->owner->version >= 60 )
        {
            $tmp = DH::findFirstElement('tag', $xml);
            if( $tmp !== FALSE )
                $this->tagStore->load_from_domxml($tmp);
        }
        // End of Tag objects extraction


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("region");
        //
        // Extract region objects
        //
        $tmp = DH::findFirstElement('region', $xml);
        if( $tmp !== FALSE )
            $this->addressStore->load_regions_from_domxml($tmp);
        //print "VSYS '".$this->name."' address objectsloaded\n" ;
        // End of address objects extraction

        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("address");
        //
        // Extract address objects
        //
        $tmp = DH::findFirstElement('address', $xml);
        if( $tmp !== FALSE )
            $this->addressStore->load_addresses_from_domxml($tmp);
        // End of address objects extraction


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("address-group");
        //
        // Extract address groups in this DV
        //
        $tmp = DH::findFirstElement('address-group', $xml);
        if( $tmp !== FALSE )
            $this->addressStore->load_addressgroups_from_domxml($tmp);
        // End of address groups extraction


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("service");
        //												//
        // Extract service objects in this VirtualSystem			//
        //												//
        $tmp = DH::findFirstElement('service', $xml);
        if( $tmp !== FALSE )
            $this->serviceStore->load_services_from_domxml($tmp);
        // End of <service> extraction


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("service-group");
        //												//
        // Extract service groups in this VirtualSystem			//
        //												//
        $tmp = DH::findFirstElement('service-group', $xml);
        if( $tmp !== FALSE )
            $this->serviceStore->load_servicegroups_from_domxml($tmp);
        // End of <service-group> extraction

        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("application");
        //
        // Extract application
        //
        $tmp = DH::findFirstElement('application', $xml);
        if( $tmp !== FALSE )
            $this->appStore->load_application_custom_from_domxml($tmp);
        // End of application extraction

        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("application-filter");
        //
        // Extract application filter
        //
        $tmp = DH::findFirstElement('application-filter', $xml);
        if( $tmp !== FALSE )
            $this->appStore->load_application_filter_from_domxml($tmp);
        // End of application filter groups extraction

        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("application-group");
        //
        // Extract application groups
        //
        $tmp = DH::findFirstElement('application-group', $xml);
        if( $tmp !== FALSE )
            $this->appStore->load_application_group_from_domxml($tmp);
        // End of application groups extraction


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("profiles");
        // Extract SecurityProfiles objects
        //
        $this->securityProfilebaseroot = DH::findFirstElement('profiles', $xml);
        if( $this->securityProfilebaseroot === FALSE )
            $this->securityProfilebaseroot = null;

        if( $this->securityProfilebaseroot !== null )
        {
            //
            // custom URL category extraction
            //
            $tmproot = DH::findFirstElement('custom-url-category', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->customURLProfileStore->load_from_domxml($tmproot);


            //
            // URL Profile extraction
            //
            $tmproot = DH::findFirstElement('url-filtering', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->URLProfileStore->load_from_domxml($tmproot);

            //
            // AntiVirus Profile extraction
            //
            $tmproot = DH::findFirstElement('virus', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->AntiVirusProfileStore->load_from_domxml($tmproot);

            //
            // FileBlocking Profile extraction
            //
            $tmproot = DH::findFirstElement('file-blocking', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->FileBlockingProfileStore->load_from_domxml($tmproot);

            //
            // DataFiltering Profile extraction
            //
            $tmproot = DH::findFirstElement('data-filtering', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->DataFilteringProfileStore->load_from_domxml($tmproot);

            //
            // vulnerability Profile extraction
            //
            $tmproot = DH::findFirstElement('vulnerability', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->VulnerabilityProfileStore->load_from_domxml($tmproot);

            //
            // spyware Profile extraction
            //
            $tmproot = DH::findFirstElement('spyware', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->AntiSpywareProfileStore->load_from_domxml($tmproot);

            //
            // wildfire Profile extraction
            //
            $tmproot = DH::findFirstElement('wildfire-analysis', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
                $this->WildfireProfileStore->load_from_domxml($tmproot);

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

            //
            // GTP Profile extraction
            //
            $tmproot = DH::findFirstElement('gtp', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->GTPProfileStore->load_from_domxml($tmproot);
            }

            //
            // SCEP Profile extraction
            //
            $tmproot = DH::findFirstElement('scep', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->SCEPProfileStore->load_from_domxml($tmproot);
            }

            //
            // PacketBroker Profile extraction
            //
            $tmproot = DH::findFirstElement('packet-broker', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->PacketBrokerProfileStore->load_from_domxml($tmproot);
            }

            //
            // SDWan Error Correction Profile extraction
            //
            $tmproot = DH::findFirstElement('sdwan-error-correction', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->SDWanErrorCorrectionProfileStore->load_from_domxml($tmproot);
            }

            //
            // SDWan Path Quality Profile extraction
            //
            $tmproot = DH::findFirstElement('sdwan-path-quality', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->SDWanPathQualityProfileStore->load_from_domxml($tmproot);
            }

            //
            // SDWan Saas Quality Profile extraction
            //
            $tmproot = DH::findFirstElement('sdwan-saas-quality', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->SDWanSaasQualityProfileStore->load_from_domxml($tmproot);
            }

            //
            // SDWan Traffic Distribution Profile extraction
            //
            $tmproot = DH::findFirstElement('sdwan-traffic-distribution', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->SDWanTrafficDistributionProfileStore->load_from_domxml($tmproot);
            }

            //
            // DataObjects Profile extraction
            //
            $tmproot = DH::findFirstElement('data-objects', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->DataObjectsProfileStore->load_from_domxml($tmproot);
            }
        }


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("profile-group");
        //
        // Extract SecurityProfile groups in this DV
        //
        $tmp = DH::findFirstElement('profile-group', $xml);
        if( $tmp !== FALSE )
            $this->securityProfileGroupStore->load_securityprofile_groups_from_domxml($tmp);
        // End of address groups extraction


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("schedule");
        //
        // Extract schedule objects
        //
        $tmp = DH::findFirstElement('schedule', $xml);
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

        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("pre-/post-rulebase");
        //
        // Extracting policies
        //
        $prerulebase = DH::findFirstElement('pre-rulebase', $xml);
        $postrulebase = DH::findFirstElement('post-rulebase', $xml);

        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('security', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('security', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->securityRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('nat', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('nat', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->natRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('decryption', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('decryption', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->decryptionRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('application-override', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('application-override', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->appOverrideRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('captive-portal', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('captive-portal', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->captivePortalRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('authentication', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('authentication', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->authenticationRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('pbf', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('pbf', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->pbfRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('qos', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('qos', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->qosRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('dos', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('dos', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->dosRules->load_from_domxml($tmp, $tmpPost);

        //tunnel-inspect
        $xmlTagName = "tunnel-inspect";
        $var = "tunnelInspectionRules";
        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement($xmlTagName, $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement($xmlTagName, $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->$var->load_from_domxml($tmp, $tmpPost);

        //default-security-Rules are only available on POST
        $xmlTagName = "default-security-rules";
        $var = "defaultSecurityRules";
        if( $prerulebase === FALSE )
            $tmp = null;
        else
            $tmp = null;
        if( $postrulebase === FALSE )
        {
            $tmpPost = null;
            #$postrulebase = DH::findFirstElementOrCreate('post-rulebase', $xml);
        }
        else{
            $sub = new Sub();
            $sub->owner = $this;
            $sub->rulebaseroot = $postrulebase;
            $sub->defaultSecurityRules = $this->defaultSecurityRules;
            $tmpPost = $sub->load_defaultSecurityRule( );
        }
        if( $tmpPost !== null && $tmpPost !== FALSE )
            $this->$var->load_from_domxml($tmp, $tmpPost);

        //network-packet-broker
        $xmlTagName = "network-packet-broker";
        $var = "networkPacketBrokerRules";
        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement($xmlTagName, $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement($xmlTagName, $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->$var->load_from_domxml($tmp, $tmpPost);

        //sdwan
        $xmlTagName = "sdwan";
        $var = "sdWanRules";
        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement($xmlTagName, $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement($xmlTagName, $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->$var->load_from_domxml($tmp, $tmpPost);
        //
        // end of policies extraction
        //



        $this->userGroupSourceRoot = DH::findFirstElement('user-group-source', $xml);
        if( $this->userGroupSourceRoot !== false )
        {
            $master_devide_node = DH::findFirstElement('master-device', $this->userGroupSourceRoot);
            if( $master_devide_node !== FALSE )
            {
                $device_node = DH::findFirstElement('device', $master_devide_node);
                if( $device_node !== FALSE )
                {
                    $serial = $device_node->textContent;
                    //Todo: is there a need to set a references??? already done above
                }
            }
        }

        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("nestedPointOfView");
        $this->addressStore->nestedPointOfView();
        $this->serviceStore->nestedPointOfView();
        $this->tagStore->nestedPointOfView();
        $this->scheduleStore->nestedPointOfView();
        $this->EDLStore->nestedPointOfView();
        $this->LogProfileStore->nestedPointOfView();
        $this->appStore->nestedPointOfView();

    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='" . $this->name . "']";

        return $str;
    }


    /**
     * @param bool $includeSubDeviceGroups look for device inside sub device-groups
     * @return array
     */
    public function getDevicesInGroup($includeSubDeviceGroups = FALSE)
    {
        $devices = $this->devices;

        if( $includeSubDeviceGroups )
        {
            foreach( $this->_childDeviceGroups as $childDG )
            {
                $subDevices = $childDG->getDevicesInGroup(TRUE);
                foreach( $subDevices as $subDevice )
                {
                    $serial = $subDevice['serial'];

                    if( isset($devices[$serial]) )
                    {
                        foreach( $subDevice['vsyslist'] as $vsys )
                        {
                            $devices[$serial]['vsyslist'][$vsys] = $vsys;
                        }
                    }
                    else
                        $devices[$serial] = $subDevice;
                }
            }
        }

        return $devices;
    }

    public function name()
    {
        return $this->name;
    }

    public function setName($newName)
    {
        $this->xmlroot->setAttribute('name', $newName);

        $this->name = $newName;
    }

    public function isDeviceGroup()
    {
        return TRUE;
    }



    /**
     * @param bool $nested
     * @return DeviceGroup[]
     */
    public function childDeviceGroups($nested = FALSE)
    {
        if( $nested )
        {
            $dgs = array();

            foreach( $this->_childDeviceGroups as $dg )
            {
                $dgs[$dg->name()] = $dg;
                $tmp = $dg->childDeviceGroups(TRUE);
                foreach( $tmp as $sub )
                    $dgs[$sub->name()] = $sub;
            }

            return $dgs;
        }

        return $this->_childDeviceGroups;
    }

    /**
     * @return DeviceGroup[]
     */
    public function parentDeviceGroups()
    {
        if( $this->name() == 'shared' )
        {
            $dgs[$this->name()] = $this;
            return $dgs;
        }

        $dg_tmp = $this;
        $dgs = array();

        while( $dg_tmp !== null )
        {
            $dgs[$dg_tmp->name()] = $dg_tmp;
            $dg_tmp = $dg_tmp->parentDeviceGroup;
        }

        return $dgs;
    }


    public function addDevice( $serial, $vsys = "vsys1" )
    {
        if( isset( $this->devices[$serial] ) && $vsys !== "vsys1" )
        {
            $this->devices[$serial]['vsyslist'][$vsys] = $vsys;
        }
        else
        {
            $vsyslist['vsys1'] = 'vsys1';
            $this->devices[$serial] = array('serial' => $serial, 'vsyslist' => $vsyslist);
        }
        //XML manipulation missing
        $newXmlNode = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, "<entry name='{$serial}'/>");
        $devicenode = $this->devicesRoot->appendChild($newXmlNode);
    }


    public function removeDevice( $serial, $debug = false )
    {
        if( isset( $this->devices[$serial] ) )
        {
            unset( $this->devices[$serial] );
            //missing XML manipulation

            $user_group_source_node = DH::findFirstElement("user-group-source", $this->xmlroot);
            if( $user_group_source_node !== false )
            {
                if( $debug )
                    DH::DEBUGprintDOMDocument($user_group_source_node);
                $master_device_node = DH::findFirstElement("master-device", $user_group_source_node);
                if($master_device_node !== false)
                {
                    $device_node = DH::findFirstElement("device", $master_device_node);
                    if($device_node->textContent == $serial)
                        DH::removeChild( $user_group_source_node, $master_device_node );
                }
            }

            if( $this->devicesRoot !== FALSE )
            {
                foreach( $this->devicesRoot->childNodes as $device )
                {
                    if( $device->nodeType != 1 ) continue;
                    $devname = DH::findAttribute('name', $device);

                    if( $devname === $serial )
                    {
                        if( count($this->devices) > 0 )
                            DH::removeChild( $this->devicesRoot, $device );
                        else
                            DH::clearDomNodeChilds($this->devicesRoot);
                        return true;
                    }
                }
            }
        }

        return null;
    }

    public function removeDeviceAny( )
    {
        $this->FirewallsSerials = array();

        if( $this->devicesRoot !== FALSE )
            $this->devicesRoot->parentNode->removeChild( $this->devicesRoot );

        return null;
    }
}


