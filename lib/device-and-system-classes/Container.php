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


class Container
{

    //Todo: 20210226 missing stuff //old template -> so all network part

    use PathableName;
    use PanSubHelperTrait;

    /** String */
    protected $name;

    /** @var FawkesConf */
    public $owner = null;

    /** @var DOMElement */
    public $xmlroot;

    /** @var DOMElement */
    public $devicesRoot;

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
    public $VirusAndWildfireProfileStore = null;

    /** @var SecurityProfileStore */
    public $DNSSecurityProfileStore = null;

    /** @var SecurityProfileStore */
    public $SaasSecurityProfileStore = null;

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
    #public $AntiVirusProfileStore = null;

    /** @var SecurityProfileStore */
    #public $WildfireProfileStore = null;


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

    //Todo: add secprofiles and secprofgroups| 20200312 swaschkut
  /*  public static $templateContainerxml = '<entry name="**Need a Name**"><address></address><post-rulebase><security><rules></rules></security><nat><rules></rules></nat></post-rulebase>
									<pre-rulebase><security><rules></rules></security><nat><rules></rules></nat></pre-rulebase>
									<profiles>
									<url-filtering></url-filtering><dns-security></dns-security><spyware></spyware><vulnerability></vulnerability><file-blocking></file-blocking><virus-and-wildfire-analysis></virus-and-wildfire-analysis>
									<saas-security></saas-security><custom-url-category></custom-url-category><decryption></decryption>
									<hip-objects></hip-objects><hip-profiles></hip-profiles>
									</profiles>
									<region></region><external-list></external-list><dynamic-user-group></dynamic-user-group>

									</entry>';
*/
    public static $templateContainerxml = '<entry name="**Need a Name**"><address></address><post-rulebase><security><rules></rules></security><nat><rules></rules></nat></post-rulebase>
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

    /** @var RuleStore */
    public $networkPacketBrokerRules;

    /** @var RuleStore */
    public $sdWanRules;


    /**
     * @var null|Container
     */
    public $parentContainer = null;

    /** @var Container[] */
    public $_childContainers = array();

    /** @var Array */
    private $devices = array();

    public $device;

    /** @var NetworkPropertiesContainer */
    public $_fakeNetworkProperties;

    public $version = null;


    public function __construct($owner)
    {
        $this->owner = $owner;
        $this->version = &$owner->version;

        $this->device = array();

        $this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';

        //Todo: swaschkut 20210718 each Container should also have its own zoneStore???
        $this->zoneStore = $owner->zoneStore;
        #$this->zoneStore = new ZoneStore($this);
        #$this->zoneStore->setName('zoneStore');

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

        #$this->AntiVirusProfileStore = new SecurityProfileStore($this, "AntiVirusProfile");
        #$this->AntiVirusProfileStore->name = 'AntiVirus';

        $this->VirusAndWildfireProfileStore = new SecurityProfileStore($this, "VirusAndWildfireProfile");
        $this->VirusAndWildfireProfileStore->name = 'VirusAndWildfire';

        $this->DNSSecurityProfileStore = new SecurityProfileStore($this, "DNSSecurityProfile");
        $this->DNSSecurityProfileStore->name = 'DNSSecurity';

        $this->SaasSecurityProfileStore = new SecurityProfileStore($this, "SaasSecurityProfile");
        $this->SaasSecurityProfileStore->name = 'SaasSecurity';

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

        #$this->WildfireProfileStore = new SecurityProfileStore($this, "SecurityProfileWildFire");
        #$this->WildfireProfileStore->name = 'WildFire';


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

    public function load_from_templateContainerXml( )
    {
        if( $this->owner === null )
            derr('cannot be used if owner === null');

        $fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

        if( !$fragment->appendXML(self::$templateContainerxml) )
            derr('error occured while loading device group template xml');

        $element = $this->owner->containerroot->appendChild($fragment);

        $this->load_from_domxml($element);
    }


    /**
     * !! Should not be used outside of a PanoramaConf constructor. !!
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        // this VirtualSystem has a name ?
        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("VirtualSystem name not found\n");

        //
        // Extract Tag objects
        //

        $tmp = DH::findFirstElement('tag', $xml);
        if( $tmp !== FALSE )
            $this->tagStore->load_from_domxml($tmp);
        // End of Tag objects extraction


        //
        // Extract region objects
        //
        $tmp = DH::findFirstElement('region', $xml);
        if( $tmp !== FALSE )
            $this->addressStore->load_regions_from_domxml($tmp);
        // End of region objects extraction

        //
        // Extract address objects
        //
        $tmp = DH::findFirstElement('address', $xml);
        if( $tmp !== FALSE )
            $this->addressStore->load_addresses_from_domxml($tmp);
        // End of address objects extraction


        //
        // Extract address groups in this DV
        //
        $tmp = DH::findFirstElement('address-group', $xml);
        if( $tmp !== FALSE )
            $this->addressStore->load_addressgroups_from_domxml($tmp);
        // End of address groups extraction


        //												//
        // Extract service objects in this VirtualSystem			//
        //												//
        $tmp = DH::findFirstElement('service', $xml);
        if( $tmp !== FALSE )
            $this->serviceStore->load_services_from_domxml($tmp);
        // End of <service> extraction


        //												//
        // Extract service groups in this VirtualSystem			//
        //												//
        $tmp = DH::findFirstElement('service-group', $xml);
        if( $tmp !== FALSE )
            $this->serviceStore->load_servicegroups_from_domxml($tmp);
        // End of <service-group> extraction

        //
        // Extract application
        //
        $tmp = DH::findFirstElement('application', $xml);
        if( $tmp !== FALSE )
            $this->appStore->load_application_custom_from_domxml($tmp);
        // End of application extraction

        //
        // Extract application filter
        //
        $tmp = DH::findFirstElement('application-filter', $xml);
        if( $tmp !== FALSE )
            $this->appStore->load_application_filter_from_domxml($tmp);
        // End of application filter groups extraction

        //
        // Extract application groups
        //
        $tmp = DH::findFirstElement('application-group', $xml);
        if( $tmp !== FALSE )
            $this->appStore->load_application_group_from_domxml($tmp);
        // End of application groups extraction


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
            $tmproot = DH::findFirstElement('virus-and-wildfire-analysis', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->VirusAndWildfireProfileStore->load_from_domxml($tmproot);
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
                $this->DataFilteringProfileStore->load_from_domxml($tmproot);

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
            // DNSSecurity Profile extraction
            //
            $tmproot = DH::findFirstElement('dns-security', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->DNSSecurityProfileStore->load_from_domxml($tmproot);
            }

            //
            // SaasSecurity Profile extraction
            //
            $tmproot = DH::findFirstElement('saas-security', $this->securityProfilebaseroot);
            if( $tmproot !== FALSE )
            {
                $this->SaasSecurityProfileStore->load_from_domxml($tmproot);
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


        //
        // Extract SecurityProfile groups in this DV
        //
        $tmp = DH::findFirstElement('profile-group', $xml);
        if( $tmp !== FALSE )
            $this->securityProfileGroupStore->load_securityprofile_groups_from_domxml($tmp);
        // End of address groups extraction

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

        if( $prerulebase === FALSE )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('tunnel-inspect', $prerulebase);
            if( $tmp !== FALSE )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === FALSE )
                $tmp = null;
        }
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('tunnel-inspect', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
                $tmpPost = null;
        }
        $this->tunnelInspectionRules->load_from_domxml($tmp, $tmpPost);

        //default-security-Rules are only available on POST
        if( $prerulebase === FALSE )
            $tmp = null;
        else
            $tmp = null;
        if( $postrulebase === FALSE )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('default-security-rules', $postrulebase);
            if( $tmpPost !== FALSE )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === FALSE )
            {
                $sub = new Sub();
                $sub->rulebaseroot = $postrulebase;
                $sub->defaultSecurityRules = $this->defaultSecurityRules;
                $tmpPost = $sub->load_defaultSecurityRule( );
            }
        }
        if( $tmpPost !== FALSE )
            $this->defaultSecurityRules->load_from_domxml($tmp, $tmpPost);

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

        /*
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
                $vsyslist['vsys1'] = 'vsys1';
            }

            $this->devices[$devname] = array('serial' => $devname, 'vsyslist' => $vsyslist);
            foreach( $this->devices as $serial => $array )
            {
                $managedFirewall = $this->owner->managedFirewallsStore->find($serial);
                if( $managedFirewall !== null )
                    $managedFirewall->addDeviceGroup($this->name);
            }
        }
        */

        $this->addressStore->nestedPointOfView();
        $this->serviceStore->nestedPointOfView();
        $this->tagStore->nestedPointOfView();
        $this->scheduleStore->nestedPointOfView();
        $this->appStore->nestedPointOfView();
    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/container/entry[@name='" . $this->name . "']";

        return $str;
    }


    /**
     * @param bool $includeSubContainers look for device inside sub device-groups
     * @return array
     */
    public function getDevicesInGroup($includeSubContainers = FALSE)
    {
        $devices = $this->devices;

        if( $includeSubContainers )
        {
            foreach( $this->_childContainers as $childContainer )
            {
                $subDevices = $childContainer->getDevicesInGroup(TRUE);
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

    public function isContainer()
    {
        return TRUE;
    }


    public function display_statistics()
    {
        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $this );

        $header = "Statistics for Container '" . PH::boldText($this->name) . "'";
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

        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects']['total'] = $this->addressStore->count();
        $stdoutarray['address objects']['address'] = $this->addressStore->countAddresses();
        $stdoutarray['address objects']['group'] = $this->addressStore->countAddressGroups();
        $stdoutarray['address objects']['tmp'] = $this->addressStore->countTmpAddresses();
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

        /*
        $stdoutarray['securityProfile objects'] = array();
        $stdoutarray['securityProfile objects']['Anti-Spyware'] = $this->AntiSpywareProfileStore->count();
        $stdoutarray['securityProfile objects']['Vulnerability'] = $this->VulnerabilityProfileStore->count();
        $stdoutarray['securityProfile objects']['WildfireAndAntivirus'] = $this->VirusAndWildfireProfileStore->count();
        $stdoutarray['securityProfile objects']['DNS-Security'] = $this->DNSSecurityProfileStore->count();
        $stdoutarray['securityProfile objects']['Saas-Security'] = $this->SaasSecurityProfileStore->count();
        $stdoutarray['securityProfile objects']['URL'] = $this->URLProfileStore->count();
        $stdoutarray['securityProfile objects']['File-Blocking'] = $this->FileBlockingProfileStore->count();
        $stdoutarray['securityProfile objects']['Decryption'] = $this->DecryptionProfileStore->count();
        */

        $stdoutarray['Anti-Spyware objects'] = array();
        $stdoutarray['Anti-Spyware objects']['total'] = $this->AntiSpywareProfileStore->count();
        $stdoutarray['Vulnerability objects'] = array();
        $stdoutarray['Vulnerability objects']['total'] = $this->VulnerabilityProfileStore->count();
        $stdoutarray['WildfireAndAntivirus objects'] = array();
        $stdoutarray['WildfireAndAntivirus objects']['total'] = $this->VirusAndWildfireProfileStore->count();

        $stdoutarray['DNS-Security objects'] = array();
        $stdoutarray['DNS-Security objects']['total'] = $this->DNSSecurityProfileStore->count();
        $stdoutarray['Saas-Security objects'] = array();
        $stdoutarray['Saas-Security objects']['total'] = $this->SaasSecurityProfileStore->count();

        $stdoutarray['URL objects'] = array();
        $stdoutarray['URL objects']['total'] = $this->URLProfileStore->count();
        $stdoutarray['custom URL objects'] = array();
        $stdoutarray['custom URL objects']['total'] = $this->customURLProfileStore->count();
        $stdoutarray['File-Blocking objects'] = array();
        $stdoutarray['File-Blocking objects']['total'] = $this->FileBlockingProfileStore->count();
        $stdoutarray['Data-Filtering objects'] = array();
        $stdoutarray['Data-Filtering objects']['total'] = $this->DataFilteringProfileStore->count();
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

        $return = array();
        $return['CONTAINER-stat'] = $stdoutarray;
        #PH::print_stdout( $return );
        PH::print_stdout( $stdoutarray, true );

    }

    public function display_bp_statistics( $debug = false )
    {
        $stdoutarray = array();
        #PH::$JSON_TMP[$this->name] = $stdoutarray;
        PH::$JSON_TMP[] = $stdoutarray;


        if( !PH::$shadow_json && $debug )
            PH::print_stdout( $stdoutarray, true );

    }

    /**
     * @param bool $nested
     * @return Container[]
     */
    public function childContainers($nested = FALSE)
    {
        if( $nested )
        {
            $dgs = array();

            foreach( $this->_childContainers as $dg )
            {
                $dgs[$dg->name()] = $dg;
                $tmp = $dg->childContainers(TRUE);
                foreach( $tmp as $sub )
                    $containers[$sub->name()] = $sub;
            }

            return $containers;
        }

        return $this->_childContainers;
    }

    /**
     * @return Container[]
     */
    public function parentContainers()
    {
        if( $this->name() == 'shared' )
        {
            $dgs[$this->name()] = $this;
            return $dgs;
        }

        $container_tmp = $this;
        $containers = array();

        while( $container_tmp !== null )
        {
            $containers[$container_tmp->name()] = $container_tmp;
            $container_tmp = $container_tmp->parentContainer;
        }

        return $containers;
    }

}


