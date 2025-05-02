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


    /**
     * !! Should not be used outside of a PanoramaConf constructor. !!
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml, $debugLoadTime = false)
    {
        $this->xmlroot = $xml;

        // this VirtualSystem has a name ?
        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("VirtualSystem name not found\n");

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


    public function display_statistics( $debug = false, $actions = "display")
    {
        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $this );
        $stdoutarray['statstype'] = "objects";

        $header = "Statistics for DG '" . PH::boldText($this->name) . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['security rules'] = array();
        $stdoutarray['security rules']['pre'] = $this->securityRules->countPreRules();
        $stdoutarray['security rules']['post'] = $this->securityRules->countPostRules();

        $stdoutarray['nat rules'] = array();
        $stdoutarray['nat rules']['pre'] = $this->natRules->countPreRules();
        $stdoutarray['nat rules']['post'] = $this->natRules->countPostRules();

        $stdoutarray['qos rules'] = array();
        $stdoutarray['qos rules']['pre'] = $this->qosRules->countPreRules();
        $stdoutarray['qos rules']['post'] = $this->qosRules->countPostRules();

        $stdoutarray['pbf rules'] = array();
        $stdoutarray['pbf rules']['pre'] = $this->pbfRules->countPreRules();
        $stdoutarray['pbf rules']['post'] = $this->pbfRules->countPostRules();

        $stdoutarray['decrypt rules'] = array();
        $stdoutarray['decrypt rules']['pre'] = $this->decryptionRules->countPreRules();
        $stdoutarray['decrypt rules']['post'] = $this->decryptionRules->countPostRules();

        $stdoutarray['app-override rules'] = array();
        $stdoutarray['app-override rules']['pre'] = $this->appOverrideRules->countPreRules();
        $stdoutarray['app-override rules']['post'] = $this->appOverrideRules->countPostRules();

        $stdoutarray['captive-portal rules'] = array();
        $stdoutarray['captive-portal rules']['pre'] = $this->captivePortalRules->countPreRules();
        $stdoutarray['captive-portal rules']['post'] = $this->captivePortalRules->countPostRules();

        $stdoutarray['authentication rules'] = array();
        $stdoutarray['authentication rules']['pre'] = $this->authenticationRules->countPreRules();
        $stdoutarray['authentication rules']['post'] = $this->authenticationRules->countPostRules();

        $stdoutarray['dos rules'] = array();
        $stdoutarray['dos rules']['pre'] = $this->dosRules->countPreRules();
        $stdoutarray['dos rules']['post'] = $this->dosRules->countPostRules();

        $stdoutarray['tunnel-inspection rules'] = array();
        $stdoutarray['tunnel-inspection rules']['pre'] = $this->tunnelInspectionRules->countPreRules();
        $stdoutarray['tunnel-inspection rules']['post'] = $this->tunnelInspectionRules->countPostRules();

        $stdoutarray['default-security rules'] = array();
        $stdoutarray['default-security rules']['pre'] = $this->defaultSecurityRules->countPreRules();
        $stdoutarray['default-security rules']['post'] = $this->defaultSecurityRules->countPostRules();

        $stdoutarray['network-packet-broker rules'] = array();
        $stdoutarray['network-packet-broker rules']['pre'] = $this->networkPacketBrokerRules->countPreRules();
        $stdoutarray['network-packet-broker rules']['post'] = $this->networkPacketBrokerRules->countPostRules();

        $stdoutarray['sdwan rules'] = array();
        $stdoutarray['sdwan rules']['pre'] = $this->sdWanRules->countPreRules();
        $stdoutarray['sdwan rules']['post'] = $this->sdWanRules->countPostRules();

        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects']['total'] = $this->addressStore->count();
        $stdoutarray['address objects']['address'] = $this->addressStore->countAddresses();
        $stdoutarray['address objects']['group'] = $this->addressStore->countAddressGroups();
        $stdoutarray['address objects']['tmp'] = $this->addressStore->countTmpAddresses();
        $stdoutarray['address objects']['region'] = $this->addressStore->countRegionObjects();
        $stdoutarray['address objects']['unused'] = $this->addressStore->countUnused();

        $stdoutarray['service objects'] = array();
        $stdoutarray['service objects']['total'] = $this->serviceStore->count();
        $stdoutarray['service objects']['service'] = $this->serviceStore->countServices();
        $stdoutarray['service objects']['group'] = $this->serviceStore->countServiceGroups();
        $stdoutarray['service objects']['tmp'] = $this->serviceStore->countTmpServices();
        $stdoutarray['service objects']['unused'] = $this->serviceStore->countUnused();

        $stdoutarray['tag objects'] = array();
        $stdoutarray['tag objects']['total'] = $this->tagStore->count();
        $stdoutarray['tag objects']['unused'] = $this->tagStore->countUnused();

        $stdoutarray['securityProfileGroup objects'] = array();
        $stdoutarray['securityProfileGroup objects']['total'] = $this->securityProfileGroupStore->count();

        $stdoutarray['Anti-Spyware objects'] = array();
        $stdoutarray['Anti-Spyware objects']['total'] = $this->AntiSpywareProfileStore->count();
        $stdoutarray['Vulnerability objects'] = array();
        $stdoutarray['Vulnerability objects']['total'] = $this->VulnerabilityProfileStore->count();
        $stdoutarray['Antivirus objects'] = array();
        $stdoutarray['Antivirus objects']['total'] = $this->AntiVirusProfileStore->count();
        $stdoutarray['Wildfire objects'] = array();
        $stdoutarray['Wildfire objects']['total'] = $this->WildfireProfileStore->count();
        $stdoutarray['URL objects'] = array();
        $stdoutarray['URL objects']['total'] = $this->URLProfileStore->count();
        $stdoutarray['custom URL objects'] = array();
        $stdoutarray['custom URL objects']['total'] = $this->customURLProfileStore->count();
        $stdoutarray['File-Blocking objects'] = array();
        $stdoutarray['File-Blocking objects']['total'] = $this->FileBlockingProfileStore->count();
        $stdoutarray['Decryption objects'] = array();
        $stdoutarray['Decryption objects']['total'] = $this->DecryptionProfileStore->count();

        $stdoutarray['HipObject objects'] = array();
        $stdoutarray['HipObject objects']['total'] = $this->HipObjectsProfileStore->count();
        $stdoutarray['HipProfile objects'] = array();
        $stdoutarray['HipProfile objects']['total'] = $this->HipProfilesProfileStore->count();

        $stdoutarray['GTP objects'] = array();
        $stdoutarray['GTP objects']['total'] = $this->GTPProfileStore->count();
        $stdoutarray['SCEP objects'] = array();
        $stdoutarray['SCEP objects']['total'] = $this->SCEPProfileStore->count();
        $stdoutarray['PacketBroker objects'] = array();
        $stdoutarray['PacketBroker objects']['total'] = $this->PacketBrokerProfileStore->count();

        $stdoutarray['SDWanErrorCorrection objects'] = array();
        $stdoutarray['SDWanErrorCorrection objects']['total'] = $this->SDWanErrorCorrectionProfileStore->count();
        $stdoutarray['SDWanPathQuality objects'] = array();
        $stdoutarray['SDWanPathQuality objects']['total'] = $this->SDWanPathQualityProfileStore->count();
        $stdoutarray['SDWanSaasQuality objects'] = array();
        $stdoutarray['SDWanSaasQuality objects']['total'] = $this->SDWanSaasQualityProfileStore->count();
        $stdoutarray['SDWanTrafficDistribution objects'] = array();
        $stdoutarray['SDWanTrafficDistribution objects']['total'] = $this->SDWanTrafficDistributionProfileStore->count();

        $stdoutarray['DataObjects objects'] = array();
        $stdoutarray['DataObjects objects']['total'] = $this->DataObjectsProfileStore->count();

        #$stdoutarray['zones'] = $this->zoneStore->count();
        #$stdoutarray['apps'] = $this->appStore->count();


        #PH::$JSON_TMP[$this->name] = $stdoutarray;
        PH::$JSON_TMP[] = $stdoutarray;

        if( !PH::$shadow_json && $actions == "display")
            PH::print_stdout( $stdoutarray, true );

        $this->display_bp_statistics( $debug, $actions );
    }


    public function get_bp_statistics()
    {
        $sub = $this;
        $sub_ruleStore = $sub->securityRules;

        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $sub );
        $stdoutarray['statstype'] = "adoption";

        $header = "BP/Visibility Statistics for VSYS '" . PH::boldText($sub->name) . "' | '" . $sub->toString() . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['security rules'] = $sub_ruleStore->count();

        $stdoutarray['security rules allow'] = count( $sub_ruleStore->rules( "(action is.allow)" ) );
        $stdoutarray['security rules allow enabled'] = count( $sub_ruleStore->rules( "(action is.allow) and (rule is.enabled)" ) );
        $stdoutarray['security rules allow disabled'] = count( $sub_ruleStore->rules( "(action is.allow) and (rule is.disabled)" ) );
        $stdoutarray['security rules enabled'] = count( $sub_ruleStore->rules( "(rule is.enabled)" ) );
        $stdoutarray['security rules deny'] = count( $sub_ruleStore->rules( "!(action is.allow)" ) );
        $stdoutarray['security rules deny enabled'] = count( $sub_ruleStore->rules( "!(action is.allow) and (rule is.enabled)" ) );
        $ruleForCalculation = $stdoutarray['security rules allow enabled'];

        $generalFilter = "(rule is.enabled) and ";
        $generalFilter_allow = "(rule is.enabled) and (action is.allow) and ";
        //Logging
        $stdoutarray['log at end'] = count( $sub_ruleStore->rules( $generalFilter."(log at.end)" ) );
        $stdoutarray['log at end calc'] = $stdoutarray['log at end']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at end percentage'] = floor(( $stdoutarray['log at end'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at end percentage'] = 0;
        $stdoutarray['log at not start'] = count( $sub_ruleStore->rules( $generalFilter."!(log at.start)" ) );
        $stdoutarray['log at not start calc'] = $stdoutarray['log at not start']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log at not start percentage'] = floor(( $stdoutarray['log at not start'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log at not start percentage'] = 0;

        //Log Forwarding Profiles
        $stdoutarray['log prof set'] = count( $sub_ruleStore->rules( $generalFilter."(logprof is.set)" ) );
        $stdoutarray['log prof set calc'] = $stdoutarray['log prof set']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['log prof set percentage'] = floor(( $stdoutarray['log prof set'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['log prof set percentage'] = 0;

        //Wildfire Analysis Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.visibility" );
        $stdoutarray['wf visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['wf visibility calc'] = $stdoutarray['wf visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf visibility percentage'] = floor(( $stdoutarray['wf visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.best-practice" );
        $stdoutarray['wf best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['wf best-practice calc'] = $stdoutarray['wf best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf best-practice percentage'] = floor( ( $stdoutarray['wf best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "wf is.adoption" );
        $stdoutarray['wf adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['wf adoption calc'] = $stdoutarray['wf adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['wf adoption percentage'] = floor(( $stdoutarray['wf adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['wf adoption percentage'] = 0;

        //Zone Protection
        //Todo: no valid filter yet available - also how to filter? based on from and/or to zone??
        $stdoutarray['zone protection'] = "NOT available";
        $filter_array = array('query' => $generalFilter."!(from is.any) and (from all.has.from.query subquery1)", 'subquery1' => "zpp is.set" );
        $stdoutarray['zone protection'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['zone protection calc'] = $stdoutarray['zone protection']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['zone protection percentage'] = floor( ( $stdoutarray['zone protection'] / $stdoutarray['security rules enabled'] ) * 100 );
        else
            $stdoutarray['zone protection percentage'] = 0;

        // App-ID
        $stdoutarray['app id'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(app is.any)" ) );
        $stdoutarray['app id calc'] = $stdoutarray['app id']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['app id percentage'] = floor( ( $stdoutarray['app id'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['app id percentage'] = 0;

        //User-ID
        $stdoutarray['user id'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(user is.any)" ) );
        $stdoutarray['user id calc'] = $stdoutarray['user id']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['user id percentage'] = floor( ( $stdoutarray['user id'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['user id percentage'] = 0;
        //Service/Port
        $stdoutarray['service port'] = count( $sub_ruleStore->rules( $generalFilter_allow."!(service is.any)" ) );
        $stdoutarray['service port calc'] = $stdoutarray['service port']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['service port percentage'] = floor( ( $stdoutarray['service port'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['service port percentage'] = 0;

        //Antivirus Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.visibility" );
        $stdoutarray['av visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['av visibility calc'] = $stdoutarray['av visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av visibility percentage'] = floor( ( $stdoutarray['av visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.best-practice" );
        $stdoutarray['av best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['av best-practice calc'] = $stdoutarray['av best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av best-practice percentage'] = floor( ( $stdoutarray['av best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "av is.adoption" );
        $stdoutarray['av adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['av adoption calc'] = $stdoutarray['av adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['av adoption percentage'] = floor( ( $stdoutarray['av adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['av adoption percentage'] = 0;

        //Anti-Spyware Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.visibility" );
        $stdoutarray['as visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['as visibility calc'] = $stdoutarray['as visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as visibility percentage'] = floor( ( $stdoutarray['as visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.best-practice" );
        $stdoutarray['as best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['as best-practice calc'] = $stdoutarray['as best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as best-practice percentage'] = floor( ( $stdoutarray['as best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "as is.adoption" );
        $stdoutarray['as adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['as adoption calc'] = $stdoutarray['as adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['as adoption percentage'] = floor( ( $stdoutarray['as adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['as adoption percentage'] = 0;

        //Vulnerability Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.visibility" );
        $stdoutarray['vp visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['vp visibility calc'] = $stdoutarray['vp visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp visibility percentage'] = floor( ( $stdoutarray['vp visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.best-practice" );
        $stdoutarray['vp best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['vp best-practice calc'] = $stdoutarray['vp best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp best-practice percentage'] = floor( ( $stdoutarray['vp best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "vp is.adoption" );
        $stdoutarray['vp adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['vp adoption calc'] = $stdoutarray['vp adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['vp adoption percentage'] = floor( ( $stdoutarray['vp adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['vp adoption percentage'] = 0;

        //File Blocking Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.visibility" );
        $stdoutarray['fb visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['fb visibility calc'] = $stdoutarray['fb visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb visibility percentage'] = floor( ( $stdoutarray['fb visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.best-practice" );
        $stdoutarray['fb best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['fb best-practice calc'] = $stdoutarray['fb best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb best-practice percentage'] = floor( ( $stdoutarray['fb best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "fb is.adoption" );
        $stdoutarray['fb adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['fb adoption calc'] = $stdoutarray['fb adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['fb adoption percentage'] = floor( ( $stdoutarray['fb adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['fb adoption percentage'] = 0;

        //Data Filtering
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "df is.visibility" );
        $stdoutarray['data visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['data visibility calc'] = $stdoutarray['data visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['data visibility percentage'] = floor( ( $stdoutarray['data visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['data visibility percentage'] = 0;
        $stdoutarray['data best-practice'] = "NOT available";
        //--
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "df is.adoption" );
        $stdoutarray['data adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['data adoption calc'] = $stdoutarray['data adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['data adoption percentage'] = floor( ( $stdoutarray['data adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['data adoption percentage'] = 0;

        //URL Filtering Profiles
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.visibility" );
        $stdoutarray['url-site-access visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-site-access visibility calc'] = $stdoutarray['url-site-access visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access visibility percentage'] = floor( ( $stdoutarray['url-site-access visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.best-practice" );
        $stdoutarray['url-site-access best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-site-access best-practice calc'] = $stdoutarray['url-site-access best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access best-practice percentage'] = floor( ( $stdoutarray['url-site-access best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.site-access is.adoption" );
        $stdoutarray['url-site-access adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-site-access adoption calc'] = $stdoutarray['url-site-access adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-site-access adoption percentage'] = floor( ( $stdoutarray['url-site-access adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-site-access adoption percentage'] = 0;

        //Credential Theft Prevention
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.visibility" );
        $stdoutarray['url-credential visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-credential visibility calc'] = $stdoutarray['url-credential visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential visibility percentage'] = floor( ( $stdoutarray['url-credential visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.best-practice" );
        $stdoutarray['url-credential best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-credential best-practice calc'] = $stdoutarray['url-credential best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential best-practice percentage'] = floor( ( $stdoutarray['url-credential best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "url.user-credential-detection is.adoption" );
        $stdoutarray['url-credential adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['url-credential adoption calc'] = $stdoutarray['url-credential adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['url-credential adoption percentage'] = floor( ( $stdoutarray['url-credential adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['url-credential adoption percentage'] = 0;

        //DNS List
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.visibility" );
        $stdoutarray['dns-list visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-list visibility calc'] = $stdoutarray['dns-list visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list visibility percentage'] = floor( ( $stdoutarray['dns-list visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.best-practice" );
        $stdoutarray['dns-list best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-list best-practice calc'] = $stdoutarray['dns-list best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list best-practice percentage'] = floor( ( $stdoutarray['dns-list best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-list is.adoption" );
        $stdoutarray['dns-list adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-list adoption calc'] = $stdoutarray['dns-list adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-list adoption percentage'] = floor( ( $stdoutarray['dns-list adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-list adoption percentage'] = 0;

        //DNS Security
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.visibility" );
        $stdoutarray['dns-security visibility'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-security visibility calc'] = $stdoutarray['dns-security visibility']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security visibility percentage'] = floor( ( $stdoutarray['dns-security visibility'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security visibility percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.best-practice" );
        $stdoutarray['dns-security best-practice'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-security best-practice calc'] = $stdoutarray['dns-security best-practice']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security best-practice percentage'] = floor( ( $stdoutarray['dns-security best-practice'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security best-practice percentage'] = 0;
        //--
        $filter_array = array('query' => $generalFilter_allow."(secprof has.from.query subquery1)", 'subquery1' => "dns-security is.adoption" );
        $stdoutarray['dns-security adoption'] = count( $sub_ruleStore->rules( $filter_array ) );
        $stdoutarray['dns-security adoption calc'] = $stdoutarray['dns-security adoption']."/".$ruleForCalculation;
        if( $ruleForCalculation !== 0 )
            $stdoutarray['dns-security adoption percentage'] = floor( ( $stdoutarray['dns-security adoption'] / $ruleForCalculation ) * 100 );
        else
            $stdoutarray['dns-security adoption percentage'] = 0;

        $percentageArray = array();

        $percentageArray_adoption = array();
        $percentageArray_adoption['Logging'] = $stdoutarray['log at end percentage'];
        $percentageArray_adoption['Log Forwarding Profiles'] = $stdoutarray['log prof set percentage'];
        $percentageArray_adoption['Wildfire Analysis Profiles'] = $stdoutarray['wf visibility percentage'];
        $percentageArray_adoption['Zone Protection'] = $stdoutarray['zone protection percentage'];
        $percentageArray_adoption['App-ID'] = $stdoutarray['app id percentage'];
        $percentageArray_adoption['User-ID'] = $stdoutarray['user id percentage'];
        $percentageArray_adoption['Service/Port'] = $stdoutarray['service port percentage'];

        $percentageArray_adoption['Antivirus Profiles'] = $stdoutarray['av adoption percentage'];
        $percentageArray_adoption['Anti-Spyware Profiles'] = $stdoutarray['as adoption percentage'];
        $percentageArray_adoption['Vulnerability Profiles'] = $stdoutarray['vp adoption percentage'];
        $percentageArray_adoption['File Blocking Profiles'] = $stdoutarray['fb adoption percentage'];
        $percentageArray_adoption['Data Filtering'] = $stdoutarray['data adoption percentage'];
        $percentageArray_adoption['URL Filtering Profiles'] = $stdoutarray['url-site-access adoption percentage'];
        $percentageArray_adoption['Credential Theft Prevention'] = $stdoutarray['url-credential adoption percentage'];
        #$percentageArray_adoption['DNS List'] = $stdoutarray['dns-list adoption percentage'];
        $percentageArray_adoption['DNS Security'] = $stdoutarray['dns-security adoption percentage'];

        $percentageArray['adoption'] = $percentageArray_adoption;

        $percentageArray_visibility = array();
        $percentageArray_visibility['Logging'] = $stdoutarray['log at end percentage'];
        $percentageArray_visibility['Log Forwarding Profiles'] = $stdoutarray['log prof set percentage'];
        $percentageArray_visibility['Wildfire Analysis Profiles'] = $stdoutarray['wf visibility percentage'];
        $percentageArray_visibility['Zone Protection'] = $stdoutarray['zone protection percentage'];
        $percentageArray_visibility['App-ID'] = $stdoutarray['app id percentage'];
        $percentageArray_visibility['User-ID'] = $stdoutarray['user id percentage'];
        $percentageArray_visibility['Service/Port'] = $stdoutarray['service port percentage'];

        $percentageArray_visibility['Antivirus Profiles'] = $stdoutarray['av visibility percentage'];
        $percentageArray_visibility['Anti-Spyware Profiles'] = $stdoutarray['as visibility percentage'];
        $percentageArray_visibility['Vulnerability Profiles'] = $stdoutarray['vp visibility percentage'];
        $percentageArray_visibility['File Blocking Profiles'] = $stdoutarray['fb visibility percentage'];
        $percentageArray_visibility['Data Filtering'] = $stdoutarray['data visibility percentage'];
        $percentageArray_visibility['URL Filtering Profiles'] = $stdoutarray['url-site-access visibility percentage'];
        $percentageArray_visibility['Credential Theft Prevention'] = $stdoutarray['url-credential visibility percentage'];
        $percentageArray_visibility['DNS List'] = $stdoutarray['dns-list visibility percentage'];
        $percentageArray_visibility['DNS Security'] = $stdoutarray['dns-security visibility percentage'];

        $percentageArray['visibility'] = $percentageArray_visibility;

        $percentageArray_best_practice = array();
        $percentageArray_best_practice['Logging'] = $stdoutarray['log at not start percentage'];
        #$percentageArray_best_practice['Log Forwarding Profiles'] = $stdoutarray['log prof set percentage'];

        $percentageArray_best_practice['Wildfire Analysis Profiles'] = $stdoutarray['wf best-practice percentage'];
        #$percentageArray_best_practice['Zone Protection'] = '---';
        #$percentageArray_best_practice['App-ID'] = $stdoutarray['app id percentage'];
        #$percentageArray_best_practice['User-ID'] = $stdoutarray['user id percentage'];
        #$percentageArray_best_practice['Service/Port'] = $stdoutarray['service port percentage'];

        $percentageArray_best_practice['Antivirus Profiles'] = $stdoutarray['av best-practice percentage'];
        $percentageArray_best_practice['Anti-Spyware Profiles'] = $stdoutarray['as best-practice percentage'];
        $percentageArray_best_practice['Vulnerability Profiles'] = $stdoutarray['vp best-practice percentage'];
        $percentageArray_best_practice['File Blocking Profiles'] = $stdoutarray['fb best-practice percentage'];
        #$percentageArray_best_practice['Data Filtering'] = '---';
        $percentageArray_best_practice['URL Filtering Profiles'] = $stdoutarray['url-site-access best-practice percentage'];
        $percentageArray_best_practice['Credential Theft Prevention'] = $stdoutarray['url-credential best-practice percentage'];
        #$percentageArray_best_practice['DNS List'] = $stdoutarray['dns-list best-practice percentage'];
        $percentageArray_best_practice['DNS Security'] = $stdoutarray['dns-security best-practice percentage'];

        $percentageArray['best-practice'] = $percentageArray_best_practice;

        $stdoutarray['percentage'] = $percentageArray;

        return $stdoutarray;
    }


    public function display_bp_statistics( $debug = false, $actions = "display" )
    {
        $stdoutarray = $this->get_bp_statistics(  );
        PH::$JSON_TMP[] = $stdoutarray;

        $percentageArray_adoption = $stdoutarray['percentage']['adoption'];
        $percentageArray_visibility = $stdoutarray['percentage']['visibility'];
        $percentageArray_best_practice = $stdoutarray['percentage']['best-practice'];

        if( !PH::$shadow_json && $actions == "display" )
        {
            PH::print_stdout("adoption");
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_adoption as $key => $value )
            {
                if( strpos($value, "---") !== False )
                {
                    $string = $value;
                }
                else
                {
                    $string = "";
                    $test = floor( ($value/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value, $string));
            }

            echo $tbl->getTable();

            PH::print_stdout("visibility");
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_visibility as $key => $value )
            {
                if( strpos($value, "---") !== False )
                {
                    $string = $value;
                }
                else
                {
                    $string = "";
                    $test = floor( ($value/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value, $string));
            }

            echo $tbl->getTable();

            PH::print_stdout("best-practice");
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_best_practice as $key => $value )
            {
                if( strpos($value, "---") !== False )
                {
                    $string = $value;
                }
                else
                {
                    $string = "";
                    $test = floor( ($value/10) * 2 );
                    $string = str_pad($string, $test, "*", STR_PAD_LEFT);
                }
                $tbl->addRow(array($key, $value, $string));
            }

            echo $tbl->getTable();
        }


        #PH::$JSON_TMP[$this->name] = $stdoutarray;
        PH::$JSON_TMP[] = $stdoutarray;


        if( !PH::$shadow_json && $debug && $actions == "display" )
            PH::print_stdout( $stdoutarray, true );

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


