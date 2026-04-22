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
 *  $pan = new PanoramaConf();
 *
 *  $pan->load_from_file('config.txt');
 *
 *  $pan->display_statistics();
 *
 * And there you go !
 *
 */
class PanoramaConf
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
    public $devicesroot;
    public $localhostlocaldomain;

    public $deviceconfigroot;

    /** @var DOMElement */
    public $localhostroot;

    /** @var string[]|DomNode */
    public $templateroot;

    /** @var string[]|DomNode */
    public $templatestackroot;

    /** @var string[]|DomNode */
    public $devicegrouproot;

    /** @var string[]|DomNode */
    public $logcollectorgrouproot;


    public $version = null;

    public $timezone = null;

    public $managedFirewallsSerials = array();
    public $managedFirewallsStore;
    public $managedFirewallsSerialsModel = array();

    /** @var DeviceGroup[] */
    public $deviceGroups = array();

    /** @var Template[] */
    public $templates = array();

    /** @var TemplateStack[] */
    public $templatestacks = array();

    /** @var LogCollectorGroup[] */
    public $logCollectorGroups = array();

    /** @var RuleStore */
    public $securityRules;

    /** @var RuleStore */
    public $natRules;

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
    public $defaultSecurityRules;
    public $defaultIntraZoneRuleSet = False;
    public $defaultInterZoneRuleSet = False;

    /** @var RuleStore */
    public $networkPacketBrokerRules;

    /** @var RuleStore */
    public $sdWanRules;


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

    /** @var ZoneStore */
    public $zoneStore = null;

    /** @var CertificateStore */
    public $certificateStore = null;

    /** @var SSL_TLSServiceProfileStore */
    public $SSL_TLSServiceProfileStore = null;

    /** @var PANConf[] */
    public $managedFirewalls = array();


    /** @var PanAPIConnector|null $connector */
    public $connector = null;

    /** @var AppStore */
    public $appStore;
    /** @var AppStore */
    public $predefinedappStore;

    /** @var ThreatStore */
    public $threatStore;

    /** @var SecurityProfileStore */
    public $urlStore;
    public $AntiVirusPredefinedStore;
    public $AntiSpywarePredefinedStore;
    public $VulnerabilityPredefinedStore;
    public $FileBlockingPredefinedStore;
    public $WildfirePredefinedStore;
    public $UrlFilteringPredefinedStore;

    /** @var TagStore */
    public $tagStore;

    public $_fakeMode = FALSE;

    /** @var NetworkPropertiesContainer */
    public $_fakeNetworkProperties;

    public $name = '';


    public $_public_cloud_server = null;
    public $_auditComment = false;

    public $debugLoadTime = false;

    public $sizeArray = array();
    public $sizeArrayShared = array();

    public function name()
    {
        return $this->name;
    }

    public function __construct()
    {
        $this->tagStore = new TagStore($this);
        $this->tagStore->setName('tagStore');

        $this->zoneStore = new ZoneStore($this);
        $this->zoneStore->setName('zoneStore');

        $this->certificateStore = new CertificateStore($this);
        $this->certificateStore->setName('certificateStore');

        $this->SSL_TLSServiceProfileStore = new SSL_TLSServiceProfileStore($this);
        $this->SSL_TLSServiceProfileStore->setName('SSL_TLSServiceStore');

        $this->predefinedappStore = AppStore::getPredefinedStore( $this );
        $this->appStore = new AppStore($this);
        $this->appStore->name = 'apps';
        $this->appStore->parentCentralStore = $this->predefinedappStore;

        $this->threatStore = ThreatStore::getPredefinedStore( $this );

        $this->urlStore = SecurityProfileStore::getURLPredefinedStore( $this);

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

        $this->_fakeNetworkProperties = new NetworkPropertiesContainer($this);

        $this->dosRules->_networkStore = $this->_fakeNetworkProperties;
        $this->pbfRules->_networkStore = $this->_fakeNetworkProperties;

        #$this->managedFirewallsStore = new ManagedDeviceStore($this, 'managedFirewall', TRUE);
        $this->managedFirewallsStore = new ManagedDeviceStore( $this );
    }

    public function __destruct()
    {
        $this->cleanupMemory();
    }

    /**
     * Cleans up memory by setting all object references to null.
     * This helps PHP's garbage collector handle circular references.
     */
    public function cleanupMemory(): void
    {
        // Clear DOM references first - these hold the most memory
        $this->xmldoc = null;
        $this->xmlroot = null;

        // Clear device groups - they hold references to many objects
        if( isset($this->deviceGroups) && is_array($this->deviceGroups) )
        {
            foreach( $this->deviceGroups as $dg )
            {
                if( method_exists($dg, 'cleanupMemory') )
                    $dg->cleanupMemory();
            }
            $this->deviceGroups = array();
        }

        // Clear templates
        if( isset($this->templates) && is_array($this->templates) )
        {
            foreach( $this->templates as $template )
            {
                if( method_exists($template, 'cleanupMemory') )
                    $template->cleanupMemory();
            }
            $this->templates = array();
        }

        // Clear template stacks
        if( isset($this->templatestacks) && is_array($this->templatestacks) )
        {
            $this->templatestacks = array();
        }

        // Clear object stores
        $this->tagStore = null;
        $this->zoneStore = null;
        $this->certificateStore = null;
        $this->SSL_TLSServiceProfileStore = null;
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
        $this->managedFirewallsStore = null;
        $this->connector = null;
    }

    public function load_from_xmlstring(&$xml)
    {
        $this->xmldoc = new DOMDocument();

        if( $this->xmldoc->loadXML($xml, XML_PARSE_BIG_LINES) !== TRUE )
            derr('Invalid XML file found');

        $this->load_from_domxml($this->xmldoc);
    }

    /**
     * @param DOMElement|DOMDocument $xml
     * @throws Exception
     */
    public function load_from_domxml($xml, $debugLoadTime = false)
    {
        $this->debugLoadTime = $debugLoadTime;

        if( $xml->nodeType == XML_DOCUMENT_NODE )
        {
            $this->xmldoc = $xml;
            $this->xmlroot = DH::findFirstElementOrDie('config', $this->xmldoc);
        }
        else
        {
            $this->xmldoc = $xml->ownerDocument;
            $this->xmlroot = $xml;
        }

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
                mwarning('cannot find PANORAMA PANOS version used for make this config', null, False);
                $version['version'] = "X.Y.Z";
                #derr('cannot find PANOS version used for make this config');
            }

            $this->version = $version['version'];
        }


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("mgt-config");

        $tmp = DH::findFirstElementOrCreate('mgt-config', $this->xmlroot);
        $tmp = DH::findFirstElement('devices', $tmp);
        if( $tmp !== false )
            $this->managedFirewallsStore->load_from_domxml($tmp);
        #$this->managedFirewallsSerials = $this->managedFirewallsStore->get_serial_from_xml($tmp, TRUE);


        if( is_object($this->connector) )
        {
            $this->managedFirewallsSerialsModel = $this->connector->panorama_getConnectedFirewallsSerials();
            foreach( $this->managedFirewallsSerialsModel as $serial => $fw )
            {
                $managedFirewall = $this->managedFirewallsStore->find($serial);
                $managedFirewall->isConnected = true;

                $managedFirewall->mgmtIP = $fw[ 'ip-address' ];
                $managedFirewall->version = $fw[ 'sw-version' ];
                $managedFirewall->model = $fw[ 'model' ];
                $managedFirewall->hostname = $fw[ 'hostname' ];
            }
        }


        $this->sharedroot = DH::findFirstElementOrCreate('shared', $this->xmlroot);

        $this->devicesroot = DH::findFirstElementOrDie('devices', $this->xmlroot);

        $this->localhostroot = DH::findFirstElementByNameAttrOrDie('entry', 'localhost.localdomain', $this->devicesroot);
        /*
        $this->localhostroot = DH::findFirstElement('entry', $this->devicesroot);
        if( $this->localhostroot === false )
        {
            $this->localhostroot = DH::createElement($this->devicesroot, 'entry');
            $this->localhostroot->setAttribute('name', 'localhost.localdomain');
        }
        */

        $this->deviceconfigroot = DH::findFirstElement('deviceconfig', $this->localhostroot);

        $this->devicegrouproot = DH::findFirstElementOrCreate('device-group', $this->localhostroot);
        $this->templateroot = DH::findFirstElementOrCreate('template', $this->localhostroot);
        $this->templatestackroot = DH::findFirstElementOrCreate('template-stack', $this->localhostroot);
        $this->logcollectorgrouproot = DH::findFirstElement('log-collector-group', $this->localhostroot);

        //above is general part
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //Todo: shared address object part
        //part2:  everything what is needed for Template
        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("shared objects");
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
        $tmp = DH::findFirstElement('region', $this->sharedroot);
        if( $tmp !== false )
            $this->addressStore->load_regions_from_domxml($tmp);
        // End of region objects extraction

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

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //Todo: part3 Template - DONE
        //Todo: part4 Template-Stack - DONE
        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("Template");
        //
        // loading templates
        //
        foreach( $this->templateroot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $ldv = new Template('*tmp*', $this);
            $ldv->load_from_domxml($node, $this->debugLoadTime);
            $this->templates[] = $ldv;
            #PH::print_stdout(  "Template '{$ldv->name()}' found" );
        }
        //
        // end of Templates
        //

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //this is old part3 and will be new part4 move it higher - DONE
        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("TemplateStack");
        //
        // loading templatestacks
        //
        foreach( $this->templatestackroot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $ldv = new TemplateStack('*tmp*', $this);
            $ldv->load_from_domxml($node);
            $this->templatestacks[] = $ldv;
            //PH::print_stdout(  "TemplateStack '{$ldv->name()}' found" );

            //Todo: add templates to templatestack
        }
        //
        // end of Templates
        //

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////

        //Todo: add DG hierarchy, and create DG, with parent and child relation
        //Todo: part1
        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("DeviceGroup part1");
        //
        // loading Device Groups now
        //
        if( $this->version < 70 || $this->_fakeMode )
        {
            foreach( $this->devicegrouproot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;
                $lvname = $node->nodeName;
                //PH::print_stdout(  "Device Group '$lvname' found" );

                $ldv = new DeviceGroup($this);

                #$doc = new DOMDocument();
                #$doc->loadXML(DeviceGroup::$templatexml, XML_PARSE_BIG_LINES);
                #$node = DH::findFirstElementOrDie('entry', $doc);
                #$ldv->load_from_domxml($node);
                #$ldv->xmlroot = $node;

                #$ldv->setName($lvname);
                //Todo: swaschkut 20251109 - load it in part2
                $ldv->init_load_from_domxml_devices($node, $debugLoadTime);
                $this->deviceGroups[] = $ldv;
            }
        }
        else
        {
            if( $this->version < 80 )
                $dgMetaDataNode = DH::findXPathSingleEntry('/config/readonly/dg-meta-data/dginfo', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntry('/config/readonly/devices/entry/device-group', $this->xmlroot);

            $dgToParent = array();
            $parentToDG = array();

            if( $dgMetaDataNode !== false )
                foreach( $dgMetaDataNode->childNodes as $node )
                {
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $dgName = DH::findAttribute('name', $node);
                    if( $dgName === FALSE )
                        derr("DeviceGroup name attribute not found in dg-meta-data", $node);

                    $parentDG = DH::findFirstElement('parent-dg', $node);
                    if( $parentDG === FALSE )
                    {
                        $dgToParent[$dgName] = 'shared';
                        $parentToDG['shared'][] = $dgName;
                    }
                    else
                    {
                        $dgToParent[$dgName] = $parentDG->textContent;
                        $parentToDG[$parentDG->textContent][] = $dgName;
                    }
                }

            $dgLoadOrder = array('shared');


            while( count($parentToDG) > 0 )
            {
                $dgLoadOrderCount = count($dgLoadOrder);

                foreach( $dgLoadOrder as &$dgName )
                {
                    if( isset($parentToDG[$dgName]) )
                    {
                        foreach( $parentToDG[$dgName] as &$newDGName )
                        {
                            $dgLoadOrder[] = $newDGName;
                        }
                        unset($parentToDG[$dgName]);
                    }
                }

                if( count($dgLoadOrder) <= $dgLoadOrderCount )
                {
                    PH::print_stdout(  "Problems could be available with the following DeviceGroup(s)" );
                    #print_r($dgLoadOrder);
                    print_r($parentToDG);
                    foreach( $parentToDG as $key => $dgName )
                    {
                        PH::print_stdout( "there is no DeviceGroup name: ".$key." available");
                        $tmp = DH::findFirstElementByNameAttr( "entry", $dgName[0], $dgMetaDataNode );
                        derr('dg-meta-data seems to be corrupted, parent.child template cannot be calculated ', $tmp, FALSE);
                    }
                }
            }

            /*PH::print_stdout(  "DG loading order:" );
            foreach( $dgLoadOrder as &$dgName )
                PH::print_stdout(  " - {$dgName}");*/


            $deviceGroupNodes = array();

            foreach( $this->devicegrouproot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $nodeNameAttr = DH::findAttribute('name', $node);
                if( $nodeNameAttr === FALSE )
                    derr("DeviceGroup 'name' attribute was not found", $node);

                if( !is_string($nodeNameAttr) || $nodeNameAttr == '' )
                    derr("DeviceGroup 'name' attribute has invalid value", $node);

                $deviceGroupNodes[$nodeNameAttr] = $node;
            }

            foreach( $dgLoadOrder as $dgIndex => &$dgName )
            {
                if( $dgName == 'shared' )
                    continue;

                if( !isset($deviceGroupNodes[$dgName]) )
                {
                    mwarning("DeviceGroup '$dgName' is listed in dg-meta-data but doesn't exist in XML");
                    //unset($dgLoadOrder[$dgIndex]);
                    continue;
                }

                $ldv = new DeviceGroup($this);

                #$doc = new DOMDocument();
                #$doc->loadXML(DeviceGroup::$templatexml, XML_PARSE_BIG_LINES);
                #$node = DH::findFirstElementOrDie('entry', $doc);
                #$ldv->load_from_domxml($node);
                #$ldv->xmlroot = $node;

                #$ldv->setName($dgName);

                if( !isset($dgToParent[$dgName]) )
                {
                    mwarning("DeviceGroup '$dgName' has not parent associated, assuming SHARED");
                }
                elseif( $dgToParent[$dgName] == 'shared' )
                {
                    // do nothing
                }
                else
                {
                    $parentDG = $this->findDeviceGroup($dgToParent[$dgName]);
                    if( $parentDG === null )
                        mwarning("DeviceGroup '$dgName' has DG '{$dgToParent[$dgName]}' listed as parent but it cannot be found in XML",null, false);
                    else
                    {
                        $parentDG->_childDeviceGroups[$dgName] = $ldv;
                        $ldv->parentDeviceGroup = $parentDG;

                        $storeType = array(
                            'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                            'EDLStore', 'LogProfileStore',

                            'securityProfileGroupStore',

                            'URLProfileStore', 'AntiVirusProfileStore', 'FileBlockingProfileStore', 'DataFilteringProfileStore',
                            'VulnerabilityProfileStore', 'AntiSpywareProfileStore', 'WildfireProfileStore',
                            'DecryptionProfileStore', 'HipObjectsProfileStore', 'customURLProfileStore'

                        );

                        foreach( $storeType as $type )
                            $ldv->$type->parentCentralStore = $parentDG->$type;
                    }
                }

                if( $debugLoadTime )
                    PH::print_DEBUG_loadtime("DeviceGroup1 - ".$dgName);

                //Todo: swaschkut 20251109 load it in part2
                #$ldv->load_from_domxml($deviceGroupNodes[$dgName], $debugLoadTime);
                $ldv->init_load_from_domxml_devices($deviceGroupNodes[$dgName], $debugLoadTime);
                $this->deviceGroups[] = $ldv;

            }

        }
        //
        // End of DeviceGroup loading
        //

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //Todo: part6 - all other parts related to shared - keep it - DONE
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
        // End of application extraction

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
        // End of application groups extraction


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
                $this->DataFilteringProfileStore->load_from_domxml($tmproot);

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
        $this->AntiVirusPredefinedStore = SecurityProfileStore::getVirusPredefinedStore( $this );
        $this->AntiSpywarePredefinedStore = SecurityProfileStore::getSpywarePredefinedStore( $this );
        $this->VulnerabilityPredefinedStore = SecurityProfileStore::getVulnerabilityPredefinedStore( $this );
        $this->UrlFilteringPredefinedStore = SecurityProfileStore::getUrlFilteringPredefinedStore( $this );
        $this->FileBlockingPredefinedStore = SecurityProfileStore::getFileBlockingPredefinedStore( $this );
        $this->WildfirePredefinedStore = SecurityProfileStore::getWildfirePredefinedStore( $this );


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
        // Extracting policies
        //
        $prerulebase = DH::findFirstElement('pre-rulebase', $this->sharedroot);
        $postrulebase = DH::findFirstElement('post-rulebase', $this->sharedroot);

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
        $this->dosRules->load_from_domxml($tmp, $tmpPost);//


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
        $this->tunnelInspectionRules->load_from_domxml($tmp, $tmpPost);//


        //default-security-Rules are only available on POST
        if( $prerulebase === FALSE )
            $tmp = null;
        else
            $tmp = null;
        if( $postrulebase === FALSE )
        {
            #$tmpPost = null;
            $postrulebase = DH::findFirstElementOrCreate('post-rulebase', $this->sharedroot);
        }

        #else{
            $sub = new Sub();
            $sub->owner = $this;
            $sub->rulebaseroot = $postrulebase;
            $sub->defaultSecurityRules = $this->defaultSecurityRules;
            $tmpPost = $sub->load_defaultSecurityRule( );
        #}
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

        //network-packet-broker
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

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //Todo: this was former place of Template and Template-Stack

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("DeviceGroup part2");
        //
        // loading Device Groups now
        //
        if( $this->version < 70 || $this->_fakeMode )
        {
            foreach( $this->devicegrouproot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;
                $lvname = $node->nodeName;
                //PH::print_stdout(  "Device Group '$lvname' found" );

                $ldv = $this->findDeviceGroup( $lvname );
                if( $ldv === null )
                {
                    $ldv = new DeviceGroup($this);
                    $this->deviceGroups[] = $ldv;
                }

                $ldv->load_from_domxml($node, $debugLoadTime);

            }
        }
        else
        {
            if( $this->version < 80 )
                $dgMetaDataNode = DH::findXPathSingleEntry('/config/readonly/dg-meta-data/dginfo', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntry('/config/readonly/devices/entry/device-group', $this->xmlroot);

            $dgToParent = array();
            $parentToDG = array();

            if( $dgMetaDataNode !== false )
                foreach( $dgMetaDataNode->childNodes as $node )
                {
                    if( $node->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $dgName = DH::findAttribute('name', $node);
                    if( $dgName === FALSE )
                        derr("DeviceGroup name attribute not found in dg-meta-data", $node);

                    $parentDG = DH::findFirstElement('parent-dg', $node);
                    if( $parentDG === FALSE )
                    {
                        $dgToParent[$dgName] = 'shared';
                        $parentToDG['shared'][] = $dgName;
                    }
                    else
                    {
                        $dgToParent[$dgName] = $parentDG->textContent;
                        $parentToDG[$parentDG->textContent][] = $dgName;
                    }
                }

            $dgLoadOrder = array('shared');


            while( count($parentToDG) > 0 )
            {
                $dgLoadOrderCount = count($dgLoadOrder);

                foreach( $dgLoadOrder as &$dgName )
                {
                    if( isset($parentToDG[$dgName]) )
                    {
                        foreach( $parentToDG[$dgName] as &$newDGName )
                        {
                            $dgLoadOrder[] = $newDGName;
                        }
                        unset($parentToDG[$dgName]);
                    }
                }
            }

            /*PH::print_stdout(  "DG loading order:" );
            foreach( $dgLoadOrder as &$dgName )
                PH::print_stdout(  " - {$dgName}");*/


            $deviceGroupNodes = array();

            foreach( $this->devicegrouproot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $nodeNameAttr = DH::findAttribute('name', $node);
                if( $nodeNameAttr === FALSE )
                    derr("DeviceGroup 'name' attribute was not found", $node);

                if( !is_string($nodeNameAttr) || $nodeNameAttr == '' )
                    derr("DeviceGroup 'name' attribute has invalid value", $node);

                $deviceGroupNodes[$nodeNameAttr] = $node;
            }

            foreach( $dgLoadOrder as $dgIndex => &$dgName )
            {
                if( $dgName == 'shared' )
                    continue;

                if( !isset($deviceGroupNodes[$dgName]) )
                {
                    mwarning("DeviceGroup '$dgName' is listed in dg-meta-data but doesn't exist in XML");
                    //unset($dgLoadOrder[$dgIndex]);
                    continue;
                }

                //already created in part1
                #$ldv = new DeviceGroup($this);
                $ldv = $this->findDeviceGroup( $dgName );

                if( $debugLoadTime )
                    PH::print_DEBUG_loadtime("DeviceGroup2 - ".$dgName);

                $ldv->load_from_domxml($deviceGroupNodes[$dgName], $debugLoadTime);
                //already added in part1
                #$this->deviceGroups[] = $ldv;

            }

        }
        //
        // End of DeviceGroup loading
        //

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //Todo: keep this part as it is - DONE
        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("LogCollectorGroup");
        //
        // loading LogCollectorGroup
        //
        if( $this->logcollectorgrouproot !== FALSE )
        {
            foreach( $this->logcollectorgrouproot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;

                #$ldv = new LogCollectorGroup('*tmp*', $this);
                $ldv = new LogCollectorGroup( $this);
                $ldv->load_from_domxml($node);
                $this->logCollectorGroups[] = $ldv;
                //PH::print_stdout(  "TemplateStack '{$ldv->name()}' found" );

                //Todo: add templates to templatestack
            }
        }
        //
        // end of LogCollectorGroup
        //


        if( $debugLoadTime )
            PH::print_DEBUG_loadtime("Device config");
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
                        $timezone_backward = PH::timezone_backward_migration($this->timezone);
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
    }


    /**
     * @param string $name
     * @return DeviceGroup|null
     */
    public function findDeviceGroup($name)
    {
        if( $name == "shared" )
            return $this;

        foreach( $this->deviceGroups as $dg )
        {
            if( $dg->name() == $name )
                return $dg;
        }

        return null;
    }

    /**
     * @param string $name
     * @return Template|null
     */
    public function findTemplate($name)
    {
        foreach( $this->templates as $template )
        {
            if( $template->name() == $name )
                return $template;
        }

        return null;
    }

    /**
     * @param string $name
     * @return TemplateStack|null
     */
    public function findTemplateStack($name)
    {
        foreach( $this->templatestacks as $templatestack )
        {
            if( $templatestack->name() == $name )
                return $templatestack;
        }

        return null;
    }

    /**
     * @param string $name
     * @return TemplateStack|null
     */
    public function findManagedDevice($name)
    {
        foreach( $this->managedFirewallsSerials as $managedFirewall )
        {
            if( $managedFirewall->name() == $name )
                return $managedFirewall;
        }

        return null;
    }
    /**
     * @param string $fileName
     * @param bool $printMessage
     * @param int $indentingXml
     */
    public function save_to_file($fileName, $printMessage = TRUE, $lineReturn = TRUE, $indentingXml = 0, $indentingXmlIncrement = 2)
    {
        if( $printMessage )
            PH::print_stdout( "Now saving PANConf to file '$fileName'..." );

        //Todo: swaschkut check
        //$indentingXmlIncrement was 2 per default for Panroama
        $xml = &DH::dom_to_xml($this->xmlroot, $indentingXml, $lineReturn, -1, $indentingXmlIncrement);

        $path_parts = pathinfo($fileName);
        if (!is_dir($path_parts['dirname']))
            mkdir($path_parts['dirname'], 0777, true);

        file_put_contents($fileName, $xml);

        if( $printMessage )
            PH::print_stdout( "     done!");
    }

    /**
     * @param string $fileName
     */
    public function load_from_file($fileName)
    {
        $filecontents = file_get_contents($fileName);

        $this->load_from_xmlstring($filecontents);

    }


    public function display_statistics( $connector = null, $debug = false, $actions = "display", $location = false ): void
    {
        //Todo: swaschkut 20251017 template / template-stack missing

        $statsArray = array();

        $this->get_mainDevice_statistics( $statsArray);

        if( PH::$shadow_loaddghierarchy )
        {
            $parentDGS = array();
            if( $location !== false )
            {
                /** @var DeviceGroup $DG_object */
                $DG_object = $this->findDeviceGroup($location);
                if( $DG_object !== null )
                {
                    if( get_class($DG_object) !== 'PanoramaConf' )
                        $parentDGS = $DG_object->parentDeviceGroups();
                }
            }
        }

        foreach( $this->deviceGroups as $cur )
        {
            if( PH::$shadow_loaddghierarchy && !empty($parentDGS) )
            {
                if( !isset($parentDGS[$cur->name()]) )
                    continue;
            }

            $this->get_combined_subDevice_statistics($statsArray, $cur );
        }

        foreach( $this->templates as $template )
        {
            #$statsArray['gCertificatCount'] += $template->certificateStore->count();

            #$statsArray['gSSL_TLSServiceProfileCount'] += $template->SSL_TLSServiceProfileStore->count();
        }

        $stdoutarray = array();

        $stdoutarray['type'] = get_class( $this );
        $stdoutarray['statstype'] = "objects";

        if( !PH::$shadow_loaddghierarchy )
            $header = "Statistics for ".get_class( $this )." '" . $this->name . "'";
        else
            $header = "Statistics for ".get_class( $this ).": DG-Hierarchy location: '" .$location. "'";

        $subName = "shared";
        $sub = $this;

        $this->display_mainDevice_statistics($stdoutarray, $statsArray, $sub, $subName, $header);


        $this->display_size_NEW($stdoutarray);


        if( !PH::$shadow_json && $actions == "display"  )
            PH::print_stdout( $stdoutarray, true );


        if( !PH::$shadow_json && $actions == "display-size"  )
        {
            PH::stats_remove_zero_arrays($sub->sizeArray);
            PH::print_stdout( $sub->sizeArray, true );
        }

        if( $actions == "display-available" )
        {
            PH::stats_remove_zero_arrays($stdoutarray);
            if( !PH::$shadow_json )
                PH::print_stdout( $stdoutarray, true );
        }

        if( $actions == "display" || $actions == "display-available" )
            PH::$JSON_TMP[] = $stdoutarray;



        if( !PH::$shadow_loaddghierarchy )
            $this->display_bp_statistics( $debug, $actions );
        else
            $this->display_bp_statistics( $debug, $actions, $location );

        if( !PH::$shadow_loaddghierarchy )
        {
            $this->display_shared_statistics( $connector, $debug, $actions );
        }

    }

    public function display_shared_statistics( $connector = null, $debug = false, $actions = "display" ): void
    {
        $statsArray = array();



        $this->display_statistics_NEW($debug, $actions, $statsArray, $connector, "shared" );


        $this->display_bp_shared_statistics( $debug, $actions );
    }


    public function display_bp_statistics( $debug = false, $actions = "display", $location = false )
    {
        $stdoutarray = $this->get_bp_statistics();
        $stdoutarray['type'] = get_class( $this );

        if( !PH::$shadow_loaddghierarchy )
            $header = "Statistics for ".get_class( $this )." '" . PH::boldText('Panorama full') . "'";
        else
            $header = "Statistics for ".get_class( $this ).": DG-Hierarchy location: '" .$location. "'";

        $stdoutarray['header'] = $header;
        $stdoutarray['statstype'] = "adoption";

        foreach( $this->getDeviceGroups() as $deviceGroup )
        {
            $stdoutarray2 = $deviceGroup->get_bp_statistics();
            foreach ($stdoutarray2 as $key2 => $stdoutarray_value)
            {
                if( $key2 == "header" || $key2 == "type" || $key2 == "statstype" )
                    continue;

                if( strpos( $key2, "calc" ) !== FALSE
                    || strpos( $key2, "percentage" ) !== FALSE
                    || strpos( $key2, "type" ) !== FALSE
                )
                {
                    unset($stdoutarray[$key2]);
                    continue;
                }


                if (isset($stdoutarray[$key2]))
                    $stdoutarray[$key2] = intval($stdoutarray[$key2]) + intval($stdoutarray_value);
                else
                    $stdoutarray[$key2] = intval($stdoutarray_value);
            }
        }

        $this->bp_calculation( $stdoutarray );


        $percentageArray = $this->get_bp_percentageArray($stdoutarray);

        $stdoutarray['percentage'] = $percentageArray;

        PH::$JSON_TMP[] = $stdoutarray;

        $this->generate_table($stdoutarray, $debug, $actions);
    }

    public function display_bp_shared_statistics( $debug = false, $actions = "display" )
    {

        $stdoutarray = $this->get_bp_statistics( $actions );

        $stdoutarray['type'] = "DeviceGroup";
        $header = "BP/Visibility Statistics for PanoramaConf '" . PH::boldText("shared") . "' | ";
        $stdoutarray['header'] = $header;

        $this->generate_table($stdoutarray, $debug, $actions);
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
     * @param $config_filename string filename you want to save config in PANOS
     */
    public function API_uploadConfig($config_filename = 'panconfigurator-default.xml')
    {
        PH::print_stdout(  "Uploadig config to device...." );

        $url = "&type=import&category=configuration&category=configuration";
        $this->connector->sendRequest($url, FALSE, DH::dom_to_xml($this->xmlroot), $config_filename);


    }


    /**
     * send current config to the firewall and save under name $config_name
     * @param $config_filename string filename you want to save config in PANOS
     */
    public function API_uploadCertificate($certFileName, $certName, $certFileFormat, $password = null, $template = null, $vsys = "vsys1")
    {
        PH::print_stdout(  "Uploadig certificate to device...." );

        $fileContent = file_get_contents($certFileName);
        $url = "&type=import&category=keypair&certificate-name=".$certName."&format=".$certFileFormat;

        if( $password !== null )
            $url .= "&passphrase=".$password;
        if( $template !== null )
            $url .= "&target-tpl=".$template."&target-tpl-vsys=".$vsys;

        $this->connector->sendRequest($url, FALSE, $fileContent, $certFileName);


    }

    /**
     *    load all managed firewalls configs from API from running config if $fromRunning = TRUE
     */
    public function API_loadManagedFirewallConfigs($fromRunning)
    {
        $this->managedFirewalls = array();

        $connector = findConnectorOrDie($this);

        foreach( $this->managedFirewallsSerials as $serial )
        {
            $fw = new PANConf($this, $serial);
            $fw->panorama = $this;
            $newCon = new PanAPIConnector($connector->apihost,
                $connector->apikey,
                'panos-via-panorama',
                $serial,
                $connector->port);
            $fw->API_load_from_candidate($newCon);
        }

    }

    /**
     *    load all managed firewalls configs from a directory
     * @var string $fromDirectory
     */
    public function loadManagedFirewallsConfigs($fromDirectory = './')
    {
        $this->managedFirewalls = array();

        $files = scandir($fromDirectory);

        foreach( $this->managedFirewallsSerials as &$serial )
        {
            $fw = FALSE;
            foreach( $files as &$file )
            {
                $pos = strpos($file, $serial);
                if( $pos !== FALSE )
                {
                    //$fc = file_get_contents($file);
                    //if( $fc === FALSE )
                    //	derr("could not open file '$file'");

                    PH::print_stdout(  "Loading FW '$serial' from file '$file'.");

                    $fw = new PANConf($this, $serial);
                    $fw->panorama = $this;
                    $fw->load_from_file($fromDirectory . '/' . $file);
                    $this->managedFirewalls[] = $fw;
                    break;
                }

            }
            if( $fw === FALSE )
            {
                derr("couldn't find a suitable file to load for FW '$serial'");
            }
        }

        //derr('not implemented yet');
    }


    /**
     * @param string $deviceSerial
     * @param string $vsysName
     * @return DeviceGroup|bool
     */
    public function findApplicableDGForVsys($deviceSerial, $vsysName)
    {
        if( $deviceSerial === null || strlen($deviceSerial) < 1 )
            derr('invalid serial provided!');
        if( $vsysName === null || strlen($vsysName) < 1 )
            derr('invalid vsys provided!');

        //PH::print_stdout(  "looking for serial $deviceSerial  and vsys $vsysName" );

        foreach( $this->deviceGroups as $dv )
        {
            $ds = $dv->getDevicesInGroup();
            foreach( $ds as &$d )
            {
                if( $d['serial'] == $deviceSerial )
                {
                    //PH::print_stdout(  "serial found" );
                    if( array_search($vsysName, $d['vsyslist']) !== FALSE )
                    {
                        //PH::print_stdout(  "match!" );
                        return $dv;
                    }
                }
            }
        }

        return FALSE;
    }

    /**
     * Create a blank device group. Return that DV object.
     * @param string $name
     * @return DeviceGroup
     **/
    public function createDeviceGroup($name, $parentDGname = null)
    {
        $newDG = new DeviceGroup($this);
        $newDG->load_from_templateXml();
        $newDG->setName($name);

        $this->deviceGroups[] = $newDG;

        if( $this->version >= 70 )
        {
            if( $this->version >= 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/max-internal-id', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/max-dg-id', $this->xmlroot);

            $dgMaxID = $dgMetaDataNode->textContent;
            $dgMaxID++;
            DH::setDomNodeText($dgMetaDataNode, "{$dgMaxID}");

            if( $this->version >= 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/device-group', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            $parentXMLnode = "";
            if( $parentDGname !== null )
            {
                $parentDG = $this->findDeviceGroup( $parentDGname );
                if( $parentDG === null )
                    mwarning("DeviceGroup '$name' has DeviceGroup '{$parentDGname}' listed as parent but it cannot be found in XML");
                else
                    $parentXMLnode = "<parent-dg>".$parentDGname."</parent-dg>";
            }
            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$dgMaxID}</id>".$parentXMLnode."</entry>");
            else
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id>".$parentXMLnode."</entry>");

            $dgMetaDataNode->appendChild($newXmlNode);
        }

        if( $parentDGname !== null )
        {
            $parentDG = $this->findDeviceGroup( $parentDGname );
            if( $parentDG === null )
                mwarning("DeviceGroup '$name' has DeviceGroup '{$parentDGname}' listed as parent but it cannot be found in XML");
            else
            {
                $parentDG->_childDeviceGroups[$name] = $newDG;

                //Todo: swaschkut 20210505 - check if other Stores must be added
                //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile

                $storeType = array(
                    'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                    'securityProfileGroupStore',

                    'URLProfileStore', 'AntiVirusProfileStore', 'FileBlockingProfileStore',
                    'DataFilteringProfileStore',
                    'VulnerabilityProfileStore', 'AntiSpywareProfileStore',
                    'WildfireProfileStore',
                    'DecryptionProfileStore', 'HipObjectsProfileStore', 'customURLProfileStore',

                    'LogProfileStore'

                );

                foreach( $storeType as $type )
                    $newDG->$type->parentCentralStore = $parentDG->$type;
            }
        }

        return $newDG;
    }

    public function setParentDG($name, $parentDGname = null)
    {
        if( $this->version >= 70 )
        {

            if( $this->version >= 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/device-group', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            $parentXMLnode = "";
            if( $parentDGname !== null )
            {
                $parentDG = $this->findDeviceGroup( $parentDGname );
                if( $parentDG === null )
                    mwarning("DeviceGroup '$name' has DeviceGroup '{$parentDGname}' listed as parent but it cannot be found in XML");
                else
                    $parentXMLnode = "<parent-dg>".$parentDGname."</parent-dg>";
            }

            $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, $parentXMLnode);

            $readOnlyDG = DH::findFirstElementByNameAttrOrDie( "entry", $name, $dgMetaDataNode );
            $readOnlyDG->appendChild($newXmlNode);

        }
    }

    public function API_syncDGparentEntry($name, $parentDGname)
    {
        $cmd = "<request><move-dg><entry name=\"".$name."\"><new-parent-dg>".$parentDGname."</new-parent-dg></entry></move-dg></request>";
        $con = findConnectorOrDie($this);

        if( $con->isAPI() )
            $con->sendOpRequest($cmd);
    }

    /**
     * Remove a device group.
     * @param DeviceGroup $DG
     **/
    public function removeDeviceGroup( $DG )
    {
        $DGname = $DG->name();
        $childDGs = $DG->_childDeviceGroups;
        if( count( $childDGs ) !== 0 )
        {
            mwarning("DeviceGroup '$DGname' has ChildDGs. Delete of DG not possible.");
            return;
        }
        else
        {
            //remove DG from XML
            $xPath = "/config/devices/entry[@name='localhost.localdomain']/device-group";
            $dgNode = DH::findXPathSingleEntryOrDie($xPath, $this->xmlroot);

            $DGremove = DH::findFirstElementByNameAttrOrDie('entry', $DGname, $dgNode);
            $dgNode->removeChild( $DGremove );

            //remove DG from DG Meta
            if( $this->version >= 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/device-group', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            $DGmetaData = DH::findFirstElementByNameAttrOrDie('entry', $DGname, $dgMetaDataNode);
            $dgMetaDataNode->removeChild( $DGmetaData );

            unset($this->deviceGroups[ $DGname ]);
        }


        //API: send empty DG node
        /*
        $xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$objectsLocation."']";

        $apiArgs = Array();
        $apiArgs['type'] = 'config';
        $apiArgs['action'] = 'delete';
        $apiArgs['xpath'] = &$xpath;

        PH::print_stdout(  "     "."*** delete each member from ".$entry." " );

        if( $configInput['type'] == 'api' )
            $response = $pan->connector->sendRequest($apiArgs);
         */


    }
    /**
     * @return DeviceGroup[]
     */
    public function getDeviceGroups()
    {
        return $this->deviceGroups;
    }


    /**
     * Create a blank template. Return that template object.
     * @param string $name
     * @return Template
     **/
    public function createTemplate($name)
    {
        $newTemplate = new Template($name, $this);
        $newTemplate->load_from_templateXml();
        $newTemplate->setName($name);

        $this->templates[] = $newTemplate;


        if( $this->version >= 70 )
        {
            if( $this->version >= 80 )
                $tempMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/max-internal-id', $this->xmlroot);
            else
            {
                //not available for template in version >= 70 and < 80
                #$dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/max-dg-id', $this->xmlroot);
            }


            $tempMaxID = $tempMetaDataNode->textContent;
            $tempMaxID++;
            DH::setDomNodeText($tempMetaDataNode, "{$tempMaxID}");

            if( $this->version >= 80 )
                $tempMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/template', $this->xmlroot);
            else
            {
                //not available for template in version >= 70 and < 80
                #$dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);
            }


            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$tempMaxID}</id></entry>");
            else
            {
                //not available for template in version >= 70 and < 80
                #$newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$tempMaxID}</dg-id></entry>");
            }


            $tempMetaDataNode->appendChild($newXmlNode);
        }


        return $newTemplate;
    }

    /**
     * Remove a template.
     * @param Template $template
     **/
    public function removeTemplate( $template )
    {
        $Templatename = $template->name();

        #$template->display_references();

        /*
         * //warning if template is used in TemplateStack
         * //implementation missing also in actions-device line 294
         * DeviceCallContext::$supportedActions['Template-delete'] = array(
         *
        $childDGs = $DG->_childDeviceGroups;
        if( count( $childDGs ) !== 0 )
        {
            mwarning("DeviceGroup '$DGname' has ChildDGs. Delete of DG not possible.");
            return;
        }
        else
        {
        */
            //remove Template from XML
            $xPath = "/config/devices/entry[@name='localhost.localdomain']/template";
            $dgNode = DH::findXPathSingleEntryOrDie($xPath, $this->xmlroot);

            $remove = DH::findFirstElementByNameAttrOrDie('entry', $Templatename, $dgNode);
            $dgNode->removeChild( $remove );


        unset($this->templates[$Templatename]);
            //Todo: cleanup memory
        //}
    }


    /**
     * Create a blank templateStack. Return that templateStack object.
     * @param string $name
     * @return TemplateStack
     **/
    public function createTemplateStack($name)
    {
        $newTemplateStack = new TemplateStack($name, $this);
        $newTemplateStack->load_from_templatestackXml();
        $newTemplateStack->setName($name);

        $this->templatestacks[] = $newTemplateStack;


        if( $this->version >= 70 )
        {
            if( $this->version >= 80 )
                $tempMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/max-internal-id', $this->xmlroot);
            else
            {
                //not available for template in version >= 70 and < 80
                #$dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/max-dg-id', $this->xmlroot);
            }


            $tempMaxID = $tempMetaDataNode->textContent;
            $tempMaxID++;
            DH::setDomNodeText($tempMetaDataNode, "{$tempMaxID}");

            if( $this->version >= 80 )
                $tempMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/template-stack', $this->xmlroot);
            else
            {
                //not available for template in version >= 70 and < 80
                #$dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);
            }


            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$tempMaxID}</id></entry>");
            else
            {
                //not available for template in version >= 70 and < 80
                #$newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$tempMaxID}</dg-id></entry>");
            }


            $tempMetaDataNode->appendChild($newXmlNode);
        }


        return $newTemplateStack;
    }

    /**
     * Remove a template.
     * @param TemplateStack $templateStack
     **/
    public function removeTemplateStack( $templateStack )
    {
        $TemplateStackname = $templateStack->name();

        #$templateStack->display_references();

        /*
         * //warning if template is used in TemplateStack
         * //implementation missing also in actions-device line 294
         * DeviceCallContext::$supportedActions['Template-delete'] = array(
         *
        $childDGs = $DG->_childDeviceGroups;
        if( count( $childDGs ) !== 0 )
        {
            mwarning("DeviceGroup '$DGname' has ChildDGs. Delete of DG not possible.");
            return;
        }
        else
        {
        */
        //remove TemplateSTack from XML
        $xPath = "/config/devices/entry[@name='localhost.localdomain']/template-stack";
        $dgNode = DH::findXPathSingleEntryOrDie($xPath, $this->xmlroot);

        $remove = DH::findFirstElementByNameAttrOrDie('entry', $TemplateStackname, $dgNode);
        $dgNode->removeChild( $remove );

        unset($this->templatestacks[$TemplateStackname]);
        
        //}
    }

    /**
     * @return Template[]
     */
    public function getTemplates()
    {
        return $this->templates;
    }

    /**
     * @return TemplateStack[]
     */
    public function getTemplatesStacks()
    {
        return $this->templatestacks;
    }
    public function isPanorama()
    {
        return TRUE;
    }

    public function findSubSystemByName($location)
    {
        return $this->findDeviceGroup($location);
    }

    public function childDeviceGroups()
    {
        return $this->getDeviceGroups();
    }
}



