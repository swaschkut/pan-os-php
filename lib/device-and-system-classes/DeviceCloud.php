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

class DeviceCloud
{
    use PathableName;
    use PanSubHelperTrait;

    /** @var AddressStore */
    public $addressStore = null;
    /** @var ServiceStore */
    public $serviceStore = null;


    /** @var TagStore|null */
    public $tagStore = null;

    /** @var AppStore|null */
    public $appStore = null;

    /** @var ThreatStore|null */
    public $threatStore = null;

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

/*
    public static $templateCloudxml = '<entry name="**Need a Name**"><address></address>
                                    <rulebase><security><rules></rules></security><nat><rules></rules></nat></rulebase>
									<profiles>
									<url-filtering></url-filtering><dns-security></dns-security><spyware></spyware><vulnerability></vulnerability><file-blocking></file-blocking><virus-and-wildfire-analysis></virus-and-wildfire-analysis>
									<saas-security></saas-security><custom-url-category></custom-url-category><decryption></decryption>
									<hip-objects></hip-objects><hip-profiles></hip-profiles>
									</profiles>
									<region></region><external-list></external-list><dynamic-user-group></dynamic-user-group>
									</entry>';
*/
    public static $templateCloudxml = '<entry name="**Need a Name**"><address></address>
                                    <rulebase><security><rules></rules></security><nat><rules></rules></nat></rulebase>
									</entry>';

    /** @var string */
    public $name;

    /** @var string */
    protected $_alternativeName = '';

    /** @var FawkesConf|Buckbeak|null */
    public $owner = null;

    /** @var DOMElement */
    public $xmlroot;


    protected $rulebaseroot;

    /** @var RuleStore */
    public $securityRules;

    /** @var RuleStore */
    public $natRules;

    /** @var RuleStore */
    public $decryptionRules;

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


    /** @var ZoneStore */
    public $zoneStore = null;

    /** @var InterfaceContainer */
    public $importedInterfaces;

    /** @var VirtualRouterContainer */
    public $importedVirtualRouter;

    /** @var Container parentContainer in case it load as part of Panorama */
    public $parentContainer = null;

    public $version = null;

    /** @var FawkesConf|Buckbeak|null $owner */
    public function __construct( $owner, Container|null $applicableDG = null)
    {
        $this->owner = $owner;

        $this->parentContainer = $applicableDG;

        $this->version = &$owner->version;

        $this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';

        #$this->importedInterfaces = new InterfaceContainer($this, $owner->network);
        #$this->importedVirtualRouter = new VirtualRouterContainer($this, $owner->network);

        #$this->appStore = $owner->appStore;
        $this->appStore = new AppStore($this);
        $this->appStore->name = 'customApplication';

        $this->threatStore = $owner->threatStore;

        $this->zoneStore = new ZoneStore($this);
        $this->zoneStore->setName('zoneStore');


        $this->serviceStore = new ServiceStore($this);
        $this->serviceStore->name = 'services';

        $this->addressStore = new AddressStore($this);
        $this->addressStore->name = 'addresses';


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

        $this->securityRules = new RuleStore($this, 'SecurityRule');
        $this->securityRules->name = 'Security';

        $this->natRules = new RuleStore($this, 'NatRule');
        $this->natRules->name = 'NAT';

        $this->decryptionRules = new RuleStore($this, 'DecryptionRule');
        $this->decryptionRules->name = 'Decryption';

        $this->appOverrideRules = new RuleStore($this, 'AppOverrideRule');
        $this->appOverrideRules->name = 'AppOverride';

        $this->captivePortalRules = new RuleStore($this, 'CaptivePortalRule');
        $this->captivePortalRules->name = 'CaptivePortal';

        $this->authenticationRules = new RuleStore($this, 'AuthenticationRule');
        $this->authenticationRules->name = 'Authentication';

        $this->pbfRules = new RuleStore($this, 'PbfRule');
        $this->pbfRules->name = 'PBF';

        $this->qosRules = new RuleStore($this, 'QoSRule');
        $this->qosRules->name = 'QoS';

        $this->dosRules = new RuleStore($this, 'DoSRule');
        $this->dosRules->name = 'DoS';

        $this->tunnelInspectionRules = new RuleStore($this, 'TunnelInspectionRule', TRUE);
        $this->tunnelInspectionRules->name = 'TunnelInspection';

        $this->defaultSecurityRules = new RuleStore($this, 'DefaultSecurityRule', TRUE);
        $this->defaultSecurityRules->name = "DefaultSecurity";

        $this->networkPacketBrokerRules = new RuleStore($this, 'NetworkPacketBrokerRule', TRUE);
        $this->networkPacketBrokerRules->name = 'NetworkPacketBroker';

        $this->sdWanRules = new RuleStore($this, 'SDWanRule', TRUE);
        $this->sdWanRules->name = 'SDWan';

        #$this->dosRules->_networkStore = $this->owner->network;
        #$this->pbfRules->_networkStore = $this->owner->network;
    }

    public function load_from_templateCloudeXml( )
    {
        if( $this->owner === null )
            derr('cannot be used if owner === null');

        $fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

        if( !$fragment->appendXML(self::$templateCloudxml) )
            derr('error occured while loading device group template xml');

        $element = $this->owner->cloudroot->appendChild($fragment);

        $this->load_from_domxml($element);
    }

    /**
     * !! Should not be used outside of a PANConf constructor. !!
     *
     */
    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        // this VSYS has a name ?
        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("DeviceCloud name not found\n", $xml);


        $tmp_parentContainer = DH::findFirstElement('parent', $xml);
        if( $tmp_parentContainer !== FALSE )
        {
            $this->parentContainer = $tmp_parentContainer->textContent;

            $parentContainer = $this->owner->findContainer( $this->parentContainer );
            if( $parentContainer === null )
                mwarning("DeviceCloud '$this->name' has Container '{$this->parentContainer}' listed as parent but it cannot be found in XML");
            else
            {
                $parentContainer->_childContainers[$this->name] = $this;
                $this->parentContainer = $parentContainer;

                /*
                $this->addressStore->parentCentralStore = $parentContainer->addressStore;
                $this->serviceStore->parentCentralStore = $parentContainer->serviceStore;
                $this->tagStore->parentCentralStore = $parentContainer->tagStore;
                $this->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
                $this->appStore->parentCentralStore = $parentContainer->appStore;
                $this->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
                */
                //Todo: swaschkut 20210505 - check if other Stores must be added
                //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile

                $storeType = array(
                    'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                    'securityProfileGroupStore',

                    'URLProfileStore', 'VirusAndWildfireProfileStore', 'FileBlockingProfileStore',
                    'DataFilteringProfileStore',
                    'VulnerabilityProfileStore', 'AntiSpywareProfileStore',
                    //'WildfireProfileStore',
                    'DecryptionProfileStore', 'HipObjectsProfileStore',

                    'DNSSecurityProfileStore', 'SaasSecurityProfileStore'

                );

                foreach( $storeType as $type )
                    $this->$type->parentCentralStore = $parentContainer->$type;
            }
        }


        // this VSYS has a display-name ?
        $displayNameNode = DH::findFirstElement('display-name', $xml);
        if( $displayNameNode !== FALSE )
            $this->_alternativeName = $displayNameNode->textContent;


        //
        // loading the imported objects list
        //
        /*
        $importroot = DH::findFirstElementOrCreate('import', $xml);
        $networkRoot = DH::findFirstElementOrCreate('network', $importroot);
        $tmp = DH::findFirstElementOrCreate('interface', $networkRoot);
        $this->importedInterfaces->load_from_domxml($tmp);

        $tmp = DH::findFirstElementOrCreate('virtual-router', $networkRoot);
        $this->importedVirtualRouter->load_from_domxml($tmp);
        */
        //

        if( $this->owner->owner === null )
        {

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
            // Extract service objects in this VSYS			//
            //												//
            $tmp = DH::findFirstElement('service', $xml);
            if( $tmp !== FALSE )
                $this->serviceStore->load_services_from_domxml($tmp);
            // End of <service> extraction


            //												//
            // Extract service groups in this VSYS			//
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
            // End of address extraction

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
            // End of application groups groups extraction


            // Extract SecurityProfiles objects
            //
            $this->securityProfilebaseroot = DH::findFirstElement('profiles', $xml);
            if( $this->securityProfilebaseroot === FALSE )
                $this->securityProfilebaseroot = null;

            if( $this->owner->owner === null && $this->securityProfilebaseroot !== null )
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
        }




        //
        // add reference to address object, if interface IP-address is using this object
        //
        /*
        foreach( $this->importedInterfaces->interfaces() as $interface )
        {
            if( $interface->isEthernetType() && $interface->type() == "layer3" )
                $interfaces = $interface->getLayer3IPv4Addresses();
            elseif( $interface->isVlanType() || $interface->isLoopbackType() || $interface->isTunnelType() )
                $interfaces = $interface->getIPv4Addresses();
            else
                $interfaces = array();


            foreach( $interfaces as $layer3IPv4Address )
            {
                if( substr_count($layer3IPv4Address, '.') != 3 )
                {
                    $object = $this->addressStore->find($layer3IPv4Address);
                    if( is_object($object) )
                        $object->addReference($interface);
                    else
                    {
                        //Todo: fix needed too many warnings - if address object is coming from other address store
                        #mwarning("interface configured objectname: " . $layer3IPv4Address . " not found.\n", $interface);
                    }

                }
            }
        }
        */
        //Todo: addressobject reference missing for: IKE gateway / GP Portal / GP Gateway (where GP is not implemented at all)


        //
        // Extract Zone objects
        //
        $tmp = DH::findFirstElement('zone', $xml);
        if( $tmp != FALSE )
            $this->zoneStore->load_from_domxml($tmp);
        // End of Zone objects extraction


        $this->rulebaseroot = DH::findFirstElement('rulebase', $xml);
        if( $this->rulebaseroot === FALSE )
            $this->rulebaseroot = null;

        if( $this->owner->owner === null && $this->rulebaseroot !== null )
        {
            //
            // Security Rules extraction
            //
            $tmproot = DH::findFirstElement('security', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->securityRules->load_from_domxml($tmprulesroot);
            }

            //
            // Nat Rules extraction
            //
            $tmproot = DH::findFirstElement('nat', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->natRules->load_from_domxml($tmprulesroot);
            }

            //
            // Decryption Rules extraction
            //
            $tmproot = DH::findFirstElement('decryption', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElementOrCreate('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->decryptionRules->load_from_domxml($tmprulesroot);
            }

            //
            // Decryption Rules extraction
            //
            $tmproot = DH::findFirstElement('application-override', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->appOverrideRules->load_from_domxml($tmprulesroot);
            }

            //
            // Captive Portal Rules extraction
            //
            $tmproot = DH::findFirstElement('captive-portal', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->captivePortalRules->load_from_domxml($tmprulesroot);
            }

            //
            // Authenticaiton Rules extraction
            //
            $tmproot = DH::findFirstElement('authentication', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->authenticationRules->load_from_domxml($tmprulesroot);
            }

            //
            // PBF Rules extraction
            //
            $tmproot = DH::findFirstElement('pbf', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->pbfRules->load_from_domxml($tmprulesroot);
            }

            //
            // QoS Rules extraction
            //
            $tmproot = DH::findFirstElement('qos', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->qosRules->load_from_domxml($tmprulesroot);
            }

            //
            // DoS Rules extraction
            //
            $tmproot = DH::findFirstElement('dos', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->dosRules->load_from_domxml($tmprulesroot);
            }

            //
            // tunnelinspection Rules extraction
            //
            $tmproot = DH::findFirstElement('tunnel-inspect', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->tunnelInspectionRules->load_from_domxml($tmprulesroot);
            }

            //
            // defaultSecurity Rules extraction
            //
            /*
            $tmproot = DH::findFirstElement('default-security-rules', $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->defaultSecurityRules->load_from_domxml($tmprulesroot);
            }
            */
            $sub = new Sub();
            $sub->rulebaseroot = $this->rulebaseroot;
            $sub->defaultSecurityRules = $this->defaultSecurityRules;
            $tmprulesroot = $sub->load_defaultSecurityRule( );
            if( $tmprulesroot !== FALSE )
                $this->defaultSecurityRules->load_from_domxml($tmprulesroot);


            //
            // network-packet-broker Rules extraction
            //
            $xmlTagName = "network-packet-broker";
            $var = "networkPacketBrokerRules";
            $tmproot = DH::findFirstElement($xmlTagName, $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->$var->load_from_domxml($tmprulesroot);
            }

            //
            // sdwan Rules extraction
            //
            $xmlTagName = "sdwan";
            $var = "sdWanRules";
            $tmproot = DH::findFirstElement($xmlTagName, $this->rulebaseroot);
            if( $tmproot !== FALSE )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== FALSE )
                    $this->$var->load_from_domxml($tmprulesroot);
            }
        }
    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='" . $this->name . "']";

        return $str;
    }

    public function isDeviceCloud()
    {
        return TRUE;
    }

    public function display_statistics()
    {
        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $this );

        $header = "Statistics for VSYS '" . PH::boldText($this->name) . "' | '" . $this->toString() . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['security rules'] = $this->securityRules->count();

        $stdoutarray['nat rules'] = $this->natRules->count();

        $stdoutarray['qos rules'] = $this->qosRules->count();

        $stdoutarray['pbf rules'] = $this->pbfRules->count();

        $stdoutarray['decryption rules'] = $this->decryptionRules->count();

        $stdoutarray['app-override rules'] = $this->appOverrideRules->count();

        $stdoutarray['capt-portal rules'] = $this->captivePortalRules->count();

        $stdoutarray['authentication rules'] = $this->authenticationRules->count();

        $stdoutarray['dos rules'] = $this->dosRules->count();


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


        $stdoutarray['zones'] = $this->zoneStore->count();
        $stdoutarray['apps'] = $this->appStore->count();


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
     * @return string
     */
    public function name()
    {
        return $this->name;
    }


    public function setName($newName)
    {
        $this->xmlroot->setAttribute('name', $newName);
        $this->name = $newName;
    }

    /**
     * @return string
     */
    public function alternativeName()
    {
        return $this->_alternativeName;
    }

    public function setAlternativeName($newName)
    {
        if( $newName == $this->_alternativeName )
            return FALSE;

        if( $newName === null || strlen($newName) == 0 )
        {
            $node = DH::findFirstElement('display-name', $this->xmlroot);
            if( $node === FALSE )
                return FALSE;

            $this->xmlroot->removeChild($node);
            return TRUE;
        }

        if( $this->owner->owner != null && get_class($this->owner->owner) ==  "Template")
        {
        }
        else
        {
            $node = DH::findFirstElementOrCreate('display-name', $this->xmlroot);
            DH::setDomNodeText($node, $newName);
        }

        $this->_alternativeName = $newName;

        return TRUE;
    }


    static public $templateXml = '<entry name="temporarynamechangemeplease"><address/><address-group/><service/><service-group/><rulebase></rulebase></entry>';

}
