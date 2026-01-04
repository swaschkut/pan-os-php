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
class BuckbeakConf
{
    use PathableName;
    use PanSubHelperTrait;


    /** @var DOMElement */
    public $xmlroot;

    /** @var DOMDocument */
    public $xmldoc;

    /** @var DOMElement */
    public $devicesroot;
    public $localhostlocaldomain;

    /** @var DOMElement */
    public $localhostroot;

    /** @var string[]|DomNode */
    public $devicecloudroot;

    /** @var string[]|DomNode */
    public $cloudroot;

    /** @var string[]|DomNode */
    public $onpremroot;

    /** @var string[]|DomNode */
    public $snippetroot;

    /** @var string[]|DomNode */
    public $containerroot;

    public $version = null;

    public $managedFirewallsSerials = array();
    public $managedFirewallsStore;
    public $managedFirewallsSerialsModel = array();

    /** @var Container[] */
    public $containers = array();

    /** @var DeviceCloud[] */
    public $clouds = array();

    /** @var DeviceOnPrem[] */
    public $onprems = array();

    /** @var Snippet[] */
    public $snippets = array();


    /** @var PANConf[] */
    public $managedFirewalls = array();


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

    /** @var SecurityProfileStore */
    public $urlStore;


    public $AntiVirusPredefinedStore;
    public $AntiSpywarePredefinedStore;
    public $VulnerabilityPredefinedStore;
    public $FileBlockingPredefinedStore;
    public $WildfirePredefinedStore;
    public $UrlFilteringPredefinedStore;


    /** @var ThreatPolicyStore */
    public $ThreatPolicyStore = null;

    /** @var DNSPolicyStore */
    public $DNSPolicyStore = null;


    /** @var ZoneStore */
    public $zoneStore = null;

    public $_fakeMode = FALSE;

    public $sizeArray = array();
    public $sizeArrayShared = array();

    /** @var NetworkPropertiesContainer */
    public $_fakeNetworkProperties;

    public $name = '';

    public function name()
    {
        return $this->name;
    }

    public function __construct()
    {
        //Todo: zoneStore in Fawkes Config MUST not be there; this is normally handled in a different way
        // old usage from Panorama in Rulezonecontainer; fix it later
        $this->zoneStore = new ZoneStore($this);
        $this->zoneStore->setName('zoneStore');


        $this->appStore = AppStore::getPredefinedStore( $this );

        $this->threatStore = ThreatStore::getPredefinedStore( $this );

        $this->urlStore = SecurityProfileStore::getURLPredefinedStore( $this );

        $this->_fakeNetworkProperties = new NetworkPropertiesContainer($this);


        $this->managedFirewallsStore = new ManagedDeviceStore($this, 'managedFirewall', TRUE);


        $this->ThreatPolicyStore = new ThreatPolicyStore($this, "ThreatPolicy");
        $this->ThreatPolicyStore->name = 'ThreatPolicy';

        $this->DNSPolicyStore = new DNSPolicyStore($this, "DNSPolicy");
        $this->DNSPolicyStore->name = 'DNSPolicy';


        $this->AntiVirusPredefinedStore = SecurityProfileStore::getVirusPredefinedStore( $this );
        $this->AntiSpywarePredefinedStore = SecurityProfileStore::getSpywarePredefinedStore( $this );
        $this->VulnerabilityPredefinedStore = SecurityProfileStore::getVulnerabilityPredefinedStore( $this );
        $this->UrlFilteringPredefinedStore = SecurityProfileStore::getUrlFilteringPredefinedStore( $this );
        $this->FileBlockingPredefinedStore = SecurityProfileStore::getFileBlockingPredefinedStore( $this );
        $this->WildfirePredefinedStore = SecurityProfileStore::getWildfirePredefinedStore( $this );
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
    public function load_from_domxml($xml)
    {
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
            {
                $version = $this->connector->getSoftwareVersion();
                $this->version = $version['version'];
            }

            else
                $this->version = "not defined";


        }


        #$tmp = DH::findFirstElementOrCreate('mgt-config', $this->xmlroot);
        #$this->managedFirewallsSerials = $this->managedFirewallsStore->get_serial_from_xml($tmp, TRUE);


        if( is_object($this->connector) )
            $this->managedFirewallsSerialsModel = $this->connector->panorama_getConnectedFirewallsSerials();


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

        $this->snippetroot = DH::findFirstElementOrCreate('snippet', $this->localhostroot);

        $this->containerroot = DH::findFirstElementOrCreate('container', $this->localhostroot);
        $this->devicecloudroot = DH::findFirstElementOrCreate('device', $this->localhostroot);
        $this->cloudroot = DH::findFirstElementOrCreate('cloud', $this->devicecloudroot);

        $this->onpremroot = DH::findFirstElement('on-prem', $this->devicecloudroot);



        $tmp = DH::findFirstElement('managed-devices', $this->localhostroot);

        //->devices/snippet
        //
        // loading snippets
        //
        foreach( $this->snippetroot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $ldv = new Snippet( $this );

            $ldv->load_from_domxml( $node );
            $this->snippets[] = $ldv;
        }



        //->devices/container
        //
        // loading Containers now
        //


        $containerMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry/container', $this->xmlroot);

        $containerToParent = array();
        $parentToDG = array();

        if( $containerMetaDataNode !== false )
            foreach( $containerMetaDataNode->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $containerName = DH::findAttribute('name', $node);
                if( $containerName === FALSE )
                    derr("Container name attribute not found in container-meta-data", $node);

                $containerLoadOrder[] = $containerName;
                //parent information not available in fawkes read-only; direct
            }



/*
        PH::print_stdout( "1Container loading order:" );
        foreach( $containerLoadOrder as &$dgName )
            PH::print_stdout(  " - {$dgName}" );
*/

        $containerNodes = array();

        foreach( $this->containerroot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $nodeNameAttr = DH::findAttribute('name', $node);
            if( $nodeNameAttr === FALSE )
                derr("Container 'name' attribute was not found", $node);

            if( !is_string($nodeNameAttr) || $nodeNameAttr == '' )
                derr("Container 'name' attribute has invalid value", $node);

            $parentContainer = DH::findFirstElement('parent', $node);
            if( $parentContainer === FALSE )
            {
                $containerToParent[$nodeNameAttr] = 'All';
                $parentToContainer['All'][] = $nodeNameAttr;
            }
            else
            {
                $containerToParent[$nodeNameAttr] = $parentContainer->textContent;
                $parentToContainer[$parentContainer->textContent][] = $nodeNameAttr;
            }

            $containerNodes[$nodeNameAttr] = $node;
        }


        $containerLoadOrder = array('All');


        while( count($parentToContainer) > 0 )
        {
            $containerLoadOrderCount = count($containerLoadOrder);

            foreach( $containerLoadOrder as &$dgName )
            {
                if( isset($parentToContainer[$dgName]) )
                {
                    foreach( $parentToContainer[$dgName] as &$newDGName )
                    {
                        if( $newDGName != 'All' )
                            $containerLoadOrder[] = $newDGName;
                    }
                    unset($parentToContainer[$dgName]);
                }
            }

            if( count($containerLoadOrder) <= $containerLoadOrderCount )
            {
                PH::print_stdout(  "Problems could be available with the following Container(s)" );
                PH::print_stdout(  "COUNT LoadOrder: ".count($containerLoadOrder) );
                PH::print_stdout(  "COUNT LoadOrderCount: ".$containerLoadOrderCount );
                print_r($containerLoadOrder);
                #derr('container-meta-data seems to be corrupted, parent.child template cannot be calculated ', $containerMetaDataNode);
            }


        }

        foreach( $containerLoadOrder as $containerIndex => &$containerName )
        {
            #if( $containerName == 'All' )
            #    continue;


            if( !isset($containerNodes[$containerName]) )
            {
                mwarning("Container '$containerName' is listed in dg-meta-data but doesn't exist in XML");
                //unset($dgLoadOrder[$dgIndex]);
                continue;
            }

            $ldv = new Container($this);
            if( !isset($containerToParent[$containerName]) )
            {
                mwarning("Container '$containerName' has not parent associated, assuming All");
            }
            else
            {
                $parentContainer = $this->findContainer($containerToParent[$containerName]);
                if( $parentContainer === null )
                {
                    if( $containerToParent[$containerName] == 'All' )
                    {
                        // do nothing
                    }
                    else
                        mwarning("Container '$containerName' has Container '{$containerToParent[$containerName]}' listed as parent but it cannot be found in XML");
                }
                else
                {
                    $parentContainer->_childContainers[$containerName] = $ldv;
                    $ldv->parentContainer = $parentContainer;

                    /*
                    $ldv->addressStore->parentCentralStore = $parentContainer->addressStore;
                    $ldv->serviceStore->parentCentralStore = $parentContainer->serviceStore;
                    $ldv->tagStore->parentCentralStore = $parentContainer->tagStore;
                    $ldv->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
                    $ldv->appStore->parentCentralStore = $parentContainer->appStore;
                    $ldv->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
                    */
                    //Todo: swaschkut 20210505 - check if other Stores must be added
                    //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile

                    $storeType = array(
                        'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                        'securityProfileGroupStore',

                        'URLProfileStore', 'VirusAndWildfireProfileStore', 'FileBlockingProfileStore',
                        //'DataFilteringProfileStore',
                        'VulnerabilityProfileStore', 'AntiSpywareProfileStore',
                        //'WildfireProfileStore',
                        'DecryptionProfileStore', 'HipObjectsProfileStore', 'customURLProfileStore',

                        'DNSSecurityProfileStore', 'SaasSecurityProfileStore'

                    );

                    foreach( $storeType as $type )
                        $ldv->$type->parentCentralStore = $parentContainer->$type;
                }
            }
            
            $ldv->load_from_domxml($containerNodes[$containerName]);
            $this->containers[] = $ldv;

        }
        //
        // End of Container loading
        //

        //->devices/device/cloud
        //
        // loading clouds
        //
        foreach( $this->cloudroot->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE ) continue;

            $ldv = new DeviceCloud( $this );

            $ldv->load_from_domxml( $node );
            $this->clouds[] = $ldv;
        }
        //
        // end of DeviceCloud
        //

        //->devices/device/on-prem
        //
        // loading onpremss
        //
        if( $this->onpremroot !== false )
        {
            foreach( $this->onpremroot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;

                $ldv = new DeviceOnPrem( $this );

                $ldv->load_from_domxml( $node );
                $this->onprems[] = $ldv;
            }
        }

        //
        // end of DeviceCloud
        //


        //
        // end of DeviceCloud
        //

        #$this->managedFirewallsSerials = $this->managedFirewallsStore->get_serial_from_xml($tmp, TRUE);
        if( $tmp !== false )
            $this->managedFirewallsStore->load_from_domxml($tmp);
    }


    /**
     * @param string $name
     * @return Container|null
     */
    public function findContainer($name)
    {
        foreach( $this->containers as $dg )
        {
            if( $dg->name() == $name )
                return $dg;
        }

        return null;
    }

    /**
     * @param string $name
     * @return DeviceCloud|null
     */
    public function findDeviceCloud($name)
    {
        foreach( $this->clouds as $template )
        {
            if( $template->name() == $name )
                return $template;
        }

        return null;
    }

    /**
     * @param string $name
     * @return DeviceOnPrem|null
     */
    public function findDeviceOnPrem($name)
    {
        foreach( $this->onprems as $template )
        {
            if( $template->name() == $name )
                return $template;
        }

        return null;
    }


    public function createSnippet($name )
    {
        $newDG = new Snippet($this);

        $xmlNode = DH::importXmlStringOrDie($this->xmldoc, DeviceCloud::$templateXml);

        $xmlNode->setAttribute('name', $name);

        #$newDG->load_from_domxml($xmlNode);
        $newDG->load_from_templateSnippetXml();
        $newDG->setName($name);


        $this->snippets[] = $newDG;

        /*
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
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/snippets', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$dgMaxID}</id></entry>");
            else
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id></entry>");

            $dgMetaDataNode->appendChild($newXmlNode);
        }
        */

        $parentContainer = $this->findContainer( "All" );
        if( $parentContainer === null )
            mwarning("Container '$name' has Container 'All' listed as parent but it cannot be found in XML");
        else
        {
            $parentContainer->_childContainers[$name] = $newDG;
            $newDG->parentContainer = $parentContainer;

            /*
            $newDG->addressStore->parentCentralStore = $parentContainer->addressStore;
            $newDG->serviceStore->parentCentralStore = $parentContainer->serviceStore;
            $newDG->tagStore->parentCentralStore = $parentContainer->tagStore;
            $newDG->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
            $newDG->appStore->parentCentralStore = $parentContainer->appStore;
            $newDG->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
            */
            //Todo: swaschkut 20210505 - check if other Stores must be added
            //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile

            $storeType = array(
                'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                'securityProfileGroupStore',

                'URLProfileStore', 'VirusAndWildfireProfileStore', 'FileBlockingProfileStore',
                //'DataFilteringProfileStore',
                'VulnerabilityProfileStore', 'AntiSpywareProfileStore',
                //'WildfireProfileStore',
                'DecryptionProfileStore', 'HipObjectsProfileStore', 'customURLProfileStore',

                'DNSSecurityProfileStore', 'SaasSecurityProfileStore'

            );

            foreach( $storeType as $type )
                $newDG->$type->parentCentralStore = $parentContainer->$type;
        }

        return $newDG;
    }

    /**
     * @param string $name
     * @return Snippet|null
     */
    public function findSnippet($name)
    {
        foreach( $this->snippets as $template )
        {
            if( $template->name() == $name )
                return $template;
        }

        return null;
    }

    public function getSnippets()
    {
        return $this->snippets;
    }

    /**
     * @param string $fileName
     * @param bool $printMessage
     * @param int $indentingXml
     */
    public function save_to_file($fileName, $printMessage = TRUE, $lineReturn = TRUE, $indentingXml = 0, $indentingXmlIncreament = 1)
    {
        if( $printMessage )
            PH::print_stdout( "Now saving BuckbeakConf to file '$fileName'..." );

        //Todo: swaschkut check
        //$indentingXmlIncreament was 2 per default for Panroama
        $xml = &DH::dom_to_xml($this->xmlroot, $indentingXml, $lineReturn, -1, $indentingXmlIncreament + 1);

        $path_parts = pathinfo($fileName);
        if (!is_dir($path_parts['dirname']))
            mkdir($path_parts['dirname'], 0777, true);

        file_put_contents($fileName, $xml);

        if( $printMessage )
            PH::print_stdout( "     done!" );
    }

    /**
     * @param string $fileName
     */
    public function load_from_file($fileName)
    {
        $filecontents = file_get_contents($fileName);

        $this->load_from_xmlstring($filecontents);

    }

    #public function display_statistics( $return = false )
    public function display_statistics( $connector = null, $debug = false, $actions = "display", $location = false ): void
    {

        $container_all = $this->findContainer( "All");
        
        $gpreSecRules = $container_all->securityRules->countPreRules();
        $gpreNatRules = $container_all->natRules->countPreRules();
        $gpreDecryptRules = $container_all->decryptionRules->countPreRules();
        $gpreAppOverrideRules = $container_all->appOverrideRules->countPreRules();
        $gpreCPRules = $container_all->captivePortalRules->countPreRules();
        $gpreAuthRules = $container_all->authenticationRules->countPreRules();
        $gprePbfRules = $container_all->pbfRules->countPreRules();
        $gpreQoSRules = $container_all->qosRules->countPreRules();
        $gpreDoSRules = $container_all->dosRules->countPreRules();

        $gpostSecRules = $container_all->securityRules->countPostRules();
        $gpostNatRules = $container_all->natRules->countPostRules();
        $gpostDecryptRules = $container_all->decryptionRules->countPostRules();
        $gpostAppOverrideRules = $container_all->appOverrideRules->countPostRules();
        $gpostCPRules = $container_all->captivePortalRules->countPostRules();
        $gpostAuthRules = $container_all->authenticationRules->countPostRules();
        $gpostPbfRules = $container_all->pbfRules->countPostRules();
        $gpostQoSRules = $container_all->qosRules->countPostRules();
        $gpostDoSRules = $container_all->dosRules->countPostRules();

        $gnservices = $container_all->serviceStore->countServices();
        $gnservicesUnused = $container_all->serviceStore->countUnusedServices();
        $gnserviceGs = $container_all->serviceStore->countServiceGroups();
        $gnserviceGsUnused = $container_all->serviceStore->countUnusedServiceGroups();
        $gnTmpServices = $container_all->serviceStore->countTmpServices();

        $gnaddresss = $container_all->addressStore->countAddresses();
        $gnaddresssUnused = $container_all->addressStore->countUnusedAddresses();
        $gnaddressGs = $container_all->addressStore->countAddressGroups();
        $gnaddressGsUnused = $container_all->addressStore->countUnusedAddressGroups();
        $gnTmpAddresses = $container_all->addressStore->countTmpAddresses();

        $gTagCount = $container_all->tagStore->count();
        $gTagUnusedCount = $container_all->tagStore->countUnused();

        $gnsecprofgroups = $container_all->securityProfileGroupStore->count();


        $gnsecprofAS = $container_all->AntiSpywareProfileStore->count();
        $gnsecprofVB = $container_all->VulnerabilityProfileStore->count();
        $gnsecprofAVWF = $container_all->VirusAndWildfireProfileStore->count();
        $gnsecprofDNS = $container_all->DNSSecurityProfileStore->count();
        $gnsecprofSaas = $container_all->SaasSecurityProfileStore->count();
        $gnsecprofURL = $container_all->URLProfileStore->count();
        $gnsecprofFB = $container_all->FileBlockingProfileStore->count();

        $gnsecprofDecr = $container_all->DecryptionProfileStore->count();
        $gnsecprofHipProf = $container_all->HipProfilesProfileStore->count();
        $gnsecprofHipObj = $container_all->HipObjectsProfileStore->count();

        foreach( $this->containers as $cur )
        {
            if( $cur->name() == "All" )
                continue;

            $gpreSecRules += $cur->securityRules->countPreRules();
            $gpreNatRules += $cur->natRules->countPreRules();
            $gpreDecryptRules += $cur->decryptionRules->countPreRules();
            $gpreAppOverrideRules += $cur->appOverrideRules->countPreRules();
            $gpreCPRules += $cur->captivePortalRules->countPreRules();
            $gpreAuthRules += $cur->authenticationRules->countPreRules();
            $gprePbfRules += $cur->pbfRules->countPreRules();
            $gpreQoSRules += $cur->qosRules->countPreRules();
            $gpreDoSRules += $cur->dosRules->countPreRules();

            $gpostSecRules += $cur->securityRules->countPostRules();
            $gpostNatRules += $cur->natRules->countPostRules();
            $gpostDecryptRules += $cur->decryptionRules->countPostRules();
            $gpostAppOverrideRules += $cur->appOverrideRules->countPostRules();
            $gpostCPRules += $cur->captivePortalRules->countPostRules();
            $gpostAuthRules += $cur->authenticationRules->countPostRules();
            $gpostPbfRules += $cur->pbfRules->countPostRules();
            $gpostQoSRules += $cur->qosRules->countPostRules();
            $gpostDoSRules += $cur->dosRules->countPostRules();

            $gnservices += $cur->serviceStore->countServices();
            $gnservicesUnused += $cur->serviceStore->countUnusedServices();
            $gnserviceGs += $cur->serviceStore->countServiceGroups();
            $gnserviceGsUnused += $cur->serviceStore->countUnusedServiceGroups();
            $gnTmpServices += $cur->serviceStore->countTmpServices();

            $gnaddresss += $cur->addressStore->countAddresses();
            $gnaddresssUnused += $cur->addressStore->countUnusedAddresses();
            $gnaddressGs += $cur->addressStore->countAddressGroups();
            $gnaddressGsUnused += $cur->addressStore->countUnusedAddressGroups();
            $gnTmpAddresses += $cur->addressStore->countTmpAddresses();

            $gTagCount += $cur->tagStore->count();
            $gTagUnusedCount += $cur->tagStore->countUnused();

            $gnsecprofgroups += $cur->securityProfileGroupStore->count();

            $gnsecprofAS += $cur->AntiSpywareProfileStore->count();
            $gnsecprofVB += $cur->VulnerabilityProfileStore->count();
            $gnsecprofAVWF += $cur->VirusAndWildfireProfileStore->count();
            $gnsecprofDNS += $cur->DNSSecurityProfileStore->count();
            $gnsecprofSaas += $cur->SaasSecurityProfileStore->count();
            $gnsecprofURL += $cur->URLProfileStore->count();
            $gnsecprofFB += $cur->FileBlockingProfileStore->count();

            $gnsecprofDecr += $cur->DecryptionProfileStore->count();
            $gnsecprofHipProf += $cur->HipProfilesProfileStore->count();
            $gnsecprofHipObj += $cur->HipObjectsProfileStore->count();
        }

        foreach( $this->clouds as $cur )
        {
            if( $cur->name() == "All" )
                continue;

            $gpreSecRules += $cur->securityRules->count();
            $gpreNatRules += $cur->natRules->count();
            $gpreDecryptRules += $cur->decryptionRules->count();
            $gpreAppOverrideRules += $cur->appOverrideRules->count();
            $gpreCPRules += $cur->captivePortalRules->count();
            $gpreAuthRules += $cur->authenticationRules->count();
            $gprePbfRules += $cur->pbfRules->count();
            $gpreQoSRules += $cur->qosRules->count();
            $gpreDoSRules += $cur->dosRules->count();

            /*
            $gpreSecRules += $cur->securityRules->countPreRules();
            $gpreNatRules += $cur->natRules->countPreRules();
            $gpreDecryptRules += $cur->decryptionRules->countPreRules();
            $gpreAppOverrideRules += $cur->appOverrideRules->countPreRules();
            $gpreCPRules += $cur->captivePortalRules->countPreRules();
            $gpreAuthRules += $cur->authenticationRules->countPreRules();
            $gprePbfRules += $cur->pbfRules->countPreRules();
            $gpreQoSRules += $cur->qosRules->countPreRules();
            $gpreDoSRules += $cur->dosRules->countPreRules();

            $gpostSecRules += $cur->securityRules->countPostRules();
            $gpostNatRules += $cur->natRules->countPostRules();
            $gpostDecryptRules += $cur->decryptionRules->countPostRules();
            $gpostAppOverrideRules += $cur->appOverrideRules->countPostRules();
            $gpostCPRules += $cur->captivePortalRules->countPostRules();
            $gpostAuthRules += $cur->authenticationRules->countPostRules();
            $gpostPbfRules += $cur->pbfRules->countPostRules();
            $gpostQoSRules += $cur->qosRules->countPostRules();
            $gpostDoSRules += $cur->dosRules->countPostRules();
            */

            $gnservices += $cur->serviceStore->countServices();
            $gnservicesUnused += $cur->serviceStore->countUnusedServices();
            $gnserviceGs += $cur->serviceStore->countServiceGroups();
            $gnserviceGsUnused += $cur->serviceStore->countUnusedServiceGroups();
            $gnTmpServices += $cur->serviceStore->countTmpServices();

            $gnaddresss += $cur->addressStore->countAddresses();
            $gnaddresssUnused += $cur->addressStore->countUnusedAddresses();
            $gnaddressGs += $cur->addressStore->countAddressGroups();
            $gnaddressGsUnused += $cur->addressStore->countUnusedAddressGroups();
            $gnTmpAddresses += $cur->addressStore->countTmpAddresses();

            $gTagCount += $cur->tagStore->count();
            $gTagUnusedCount += $cur->tagStore->countUnused();

            $gnsecprofgroups += $cur->securityProfileGroupStore->count();

            $gnsecprofAS += $cur->AntiSpywareProfileStore->count();
            $gnsecprofVB += $cur->VulnerabilityProfileStore->count();
            $gnsecprofAVWF += $cur->VirusAndWildfireProfileStore->count();
            $gnsecprofDNS += $cur->DNSSecurityProfileStore->count();
            $gnsecprofSaas += $cur->SaasSecurityProfileStore->count();
            $gnsecprofURL += $cur->URLProfileStore->count();
            $gnsecprofFB += $cur->FileBlockingProfileStore->count();

            $gnsecprofDecr += $cur->DecryptionProfileStore->count();
            $gnsecprofHipProf += $cur->HipProfilesProfileStore->count();
            $gnsecprofHipObj += $cur->HipObjectsProfileStore->count();
        }

        $stdoutarray = array();

        $header = "Statistics for BuckbeakConf '" . $this->name . "'";
        $stdoutarray['header'] = $header;

        $stdoutarray['pre security rules'] = array();
        $stdoutarray['pre security rules']['All'] = $container_all->securityRules->countPreRules();
        $stdoutarray['pre security rules']['total_DGs'] = $gpreSecRules;

        $stdoutarray['post security rules'] = array();
        $stdoutarray['post security rules']['All'] = $container_all->securityRules->countPostRules();
        $stdoutarray['post security rules']['total_DGs'] = $gpostSecRules;


        $stdoutarray['pre nat rules'] = array();
        $stdoutarray['pre nat rules']['All'] = $container_all->natRules->countPreRules();
        $stdoutarray['pre nat rules']['total_DGs'] = $gpreNatRules;

        $stdoutarray['post nat rules'] = array();
        $stdoutarray['post nat rules']['All'] = $container_all->natRules->countPostRules();
        $stdoutarray['post nat rules']['total_DGs'] = $gpostNatRules;


        $stdoutarray['pre qos rules'] = array();
        $stdoutarray['pre qos rules']['All'] = $container_all->qosRules->countPreRules();
        $stdoutarray['pre qos rules']['total_DGs'] = $gpreQoSRules;

        $stdoutarray['post qos rules'] = array();
        $stdoutarray['post qos rules']['All'] = $container_all->qosRules->countPostRules();
        $stdoutarray['post qos rules']['total_DGs'] = $gpostQoSRules;


        $stdoutarray['pre pbf rules'] = array();
        $stdoutarray['pre pbf rules']['All'] = $container_all->pbfRules->countPreRules();
        $stdoutarray['pre pbf rules']['total_DGs'] = $gprePbfRules;

        $stdoutarray['post pbf rules'] = array();
        $stdoutarray['post pbf rules']['All'] = $container_all->pbfRules->countPostRules();
        $stdoutarray['post pbf rules']['total_DGs'] = $gpostPbfRules;


        $stdoutarray['pre decryption rules'] = array();
        $stdoutarray['pre decryption rules']['All'] = $container_all->decryptionRules->countPreRules();
        $stdoutarray['pre decryption rules']['total_DGs'] = $gpreDecryptRules;

        $stdoutarray['post decryption rules'] = array();
        $stdoutarray['post decryption rules']['All'] = $container_all->decryptionRules->countPostRules();
        $stdoutarray['post decryption rules']['total_DGs'] = $gpostDecryptRules;


        $stdoutarray['pre app-override rules'] = array();
        $stdoutarray['pre app-override rules']['All'] = $container_all->appOverrideRules->countPreRules();
        $stdoutarray['pre app-override rules']['total_DGs'] = $gpreAppOverrideRules;

        $stdoutarray['post app-override rules'] = array();
        $stdoutarray['post app-override rules']['All'] = $container_all->appOverrideRules->countPostRules();
        $stdoutarray['post app-override rules']['total_DGs'] = $gpostAppOverrideRules;


        $stdoutarray['pre capt-portal rules'] = array();
        $stdoutarray['pre capt-portal rules']['All'] = $container_all->captivePortalRules->countPreRules();
        $stdoutarray['pre capt-portal rules']['total_DGs'] = $gpreCPRules;

        $stdoutarray['post capt-portal rules'] = array();
        $stdoutarray['post capt-portal rules']['All'] = $container_all->captivePortalRules->countPostRules();
        $stdoutarray['post capt-portal rules']['total_DGs'] = $gpostCPRules;


        $stdoutarray['pre authentication rules'] = array();
        $stdoutarray['pre authentication rules']['All'] = $container_all->authenticationRules->countPreRules();
        $stdoutarray['pre authentication rules']['total_DGs'] = $gpreAuthRules;

        $stdoutarray['post authentication rules'] = array();
        $stdoutarray['post authentication rules']['All'] = $container_all->authenticationRules->countPostRules();
        $stdoutarray['post authentication rules']['total_DGs'] = $gpostAuthRules;


        $stdoutarray['pre dos rules'] = array();
        $stdoutarray['pre dos rules']['All'] = $container_all->dosRules->countPreRules();
        $stdoutarray['pre dos rules']['total_DGs'] = $gpreDoSRules;

        $stdoutarray['post dos rules'] = array();
        $stdoutarray['post dos rules']['All'] = $container_all->dosRules->countPostRules();
        $stdoutarray['post dos rules']['total_DGs'] = $gpostDoSRules;



        $stdoutarray['address objects'] = array();
        $stdoutarray['address objects']['All'] = $container_all->addressStore->countAddresses();
        $stdoutarray['address objects']['total_DGs'] = $gnaddresss;
        $stdoutarray['address objects']['unused'] = $gnaddresssUnused;

        $stdoutarray['addressgroup objects'] = array();
        $stdoutarray['addressgroup objects']['All'] = $container_all->addressStore->countAddressGroups();
        $stdoutarray['addressgroup objects']['total_DGs'] = $gnaddressGs;
        $stdoutarray['addressgroup objects']['unused'] = $gnaddressGsUnused;

        $stdoutarray['temporary address objects'] = array();
        $stdoutarray['temporary address objects']['All'] = $container_all->addressStore->countTmpAddresses();
        $stdoutarray['temporary address objects']['total_DGs'] = $gnTmpAddresses;


        $stdoutarray['service objects'] = array();
        $stdoutarray['service objects']['All'] = $container_all->serviceStore->countServices();
        $stdoutarray['service objects']['total_DGs'] = $gnservices;
        $stdoutarray['service objects']['unused'] = $gnservicesUnused;

        $stdoutarray['servicegroup objects'] = array();
        $stdoutarray['servicegroup objects']['All'] = $container_all->serviceStore->countServiceGroups();
        $stdoutarray['servicegroup objects']['total_DGs'] = $gnserviceGs;
        $stdoutarray['servicegroup objects']['unused'] = $gnserviceGsUnused;

        $stdoutarray['temporary service objects'] = array();
        $stdoutarray['temporary service objects']['All'] = $container_all->serviceStore->countTmpServices();
        $stdoutarray['temporary service objects']['total_DGs'] = $gnTmpServices;


        $stdoutarray['tag objects'] = array();
        $stdoutarray['tag objects']['All'] = $container_all->tagStore->count();
        $stdoutarray['tag objects']['total_DGs'] = $gTagCount;
        $stdoutarray['tag objects']['unused'] = $gTagUnusedCount;

        $stdoutarray['securityProfileGroup objects'] = array();
        $stdoutarray['securityProfileGroup objects']['All'] = $container_all->securityProfileGroupStore->count();
        $stdoutarray['securityProfileGroup objects']['total_DGs'] = $gnsecprofgroups;

        $stdoutarray['securityProfile Anti-Spyware objects'] = array();
        $stdoutarray['securityProfile Anti-Spyware objects']['All'] = $container_all->AntiSpywareProfileStore->count();
        $stdoutarray['securityProfile Anti-Spyware objects']['total_DGs'] = $gnsecprofAS;

        $stdoutarray['securityProfile Vulnerability objects'] = array();
        $stdoutarray['securityProfile Vulnerability objects']['All'] = $container_all->VulnerabilityProfileStore->count();
        $stdoutarray['securityProfile Vulnerability objects']['total_DGs'] = $gnsecprofVB;

        $stdoutarray['securityProfile WildfireAndAnti-Virus objects'] = array();
        $stdoutarray['securityProfile WildfireAndAnti-Virus objects']['All'] = $container_all->VirusAndWildfireProfileStore->count();
        $stdoutarray['securityProfile WildfireAndAnti-Virus objects']['total_DGs'] = $gnsecprofAVWF;

        $stdoutarray['securityProfile DNS objects'] = array();
        $stdoutarray['securityProfile DNS objects']['All'] = $container_all->DNSSecurityProfileStore->count();
        $stdoutarray['securityProfile DNS objects']['total_DGs'] = $gnsecprofDNS;

        $stdoutarray['securityProfile Saas objects'] = array();
        $stdoutarray['securityProfile Saas objects']['All'] = $container_all->SaasSecurityProfileStore->count();
        $stdoutarray['securityProfile Saas objects']['total_DGs'] = $gnsecprofSaas;

        $stdoutarray['securityProfile URL objects'] = array();
        $stdoutarray['securityProfile URL objects']['All'] = $container_all->URLProfileStore->count();
        $stdoutarray['securityProfile URL objects']['total_DGs'] = $gnsecprofURL;


        $stdoutarray['securityProfile File-Blocking objects'] = array();
        $stdoutarray['securityProfile File-Blocking objects']['All'] = $container_all->FileBlockingProfileStore->count();
        $stdoutarray['securityProfile File-Blocking objects']['total_DGs'] = $gnsecprofFB;


        $stdoutarray['securityProfile Decryption objects'] = array();
        $stdoutarray['securityProfile Decryption objects']['All'] = $container_all->DecryptionProfileStore->count();
        $stdoutarray['securityProfile Decryption objects']['total_DGs'] = $gnsecprofDecr;


        $stdoutarray['zones'] = $this->zoneStore->count();
        #$stdoutarray['apps'] = $this->appStore->count();

        /*
        $stdoutarray['interfaces'] = array();
        $stdoutarray['interfaces']['total'] = $numInterfaces;
        $stdoutarray['interfaces']['ethernet'] = $this->network->ethernetIfStore->count();

        $stdoutarray['sub-interfaces'] = array();
        $stdoutarray['sub-interfaces']['total'] = $numSubInterfaces;
        $stdoutarray['sub-interfaces']['ethernet'] = $this->network->ethernetIfStore->countSubInterfaces();
        */

        /*
         * OLD
        $return = array();
        $return['PanoramaConf-stat'] = $stdoutarray;

        if( $return )
        {
            return $stdoutarray;
        }
        else
            {
            #PH::print_stdout( $return );
            PH::print_stdout( $stdoutarray, true  );
        }
        return null;
        */

        if( !PH::$shadow_json && $actions == "display"  )
            PH::print_stdout( $stdoutarray, true );

        $this->sizeArray['type'] = get_class( $this );
        $this->sizeArray['statstype'] = "objects";
        $this->sizeArray['header'] = $header;
        $this->sizeArray['kb Panorama'] = DH::dom_get_config_size($this->xmlroot);
        #$this->sizeArray['kb security rules'] = $size_securityRules;
        #$this->sizeArray['kb address objects'] = $size_addressStore;
        #$this->sizeArray['kb service objects'] = $size_serviceStore;
        #$this->sizeArray['kb tag objects'] = $size_tagStore;
        #$this->sizeArray['kb custom URL objects'] = $size_customURLProfileStore;

        if( !PH::$shadow_json && $actions == "display-size"  )
        {
            PH::stats_remove_zero_arrays($this->sizeArray);
            PH::print_stdout( $this->sizeArray, true );
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

        #if( !PH::$shadow_loaddghierarchy )
        #    $this->display_shared_statistics( $connector, $debug, $actions );
    }

    public function get_bp_statistics( $actions = "display")
    {
        #$sub = $this;
        #$sub_ruleStore = $sub->securityRules;

        $container_all = $this->findContainer( "All");
        $sub_ruleStore = $container_all->securityRules;

        $stdoutarray = array();

        #if( empty($this->name))
        #    $stdoutarray['type'] = get_class( $this );
        #else
            $stdoutarray['type'] = "Container";

        $stdoutarray['statstype'] = "adoption";

        $header = "BP/Visibility Statistics for BuckbeakConf '" . PH::boldText($this->name) . "' | '" . $this->toString() . "'";
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
        $stdoutarray['log at not start'] = count( $sub_ruleStore->rules( $generalFilter." !(log at.start)" ) );
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
        $stdoutarray['user id'] = count( $sub_ruleStore->rules( $generalFilter."!(user is.any)" ) );
        $stdoutarray['user id calc'] = $stdoutarray['user id']."/".$stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['user id percentage'] = floor( ( $stdoutarray['user id'] / $stdoutarray['security rules enabled'] ) * 100 );
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
        $percentageArray_adoption['Logging']['value'] = $stdoutarray['log at end percentage'];
        $percentageArray_adoption['Logging']['group'] = 'Logging';
        $percentageArray_adoption['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_adoption['Log Forwarding Profiles']['group'] = 'Logging';
        $percentageArray_adoption['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf visibility percentage'];
        $percentageArray_adoption['Wildfire Analysis Profiles']['group'] = 'Wildfire';
        $percentageArray_adoption['Zone Protection']['value'] = $stdoutarray['zone protection percentage'];
        $percentageArray_adoption['Zone Protection']['group'] = 'Zone Protection';
        $percentageArray_adoption['App-ID']['value'] = $stdoutarray['app id percentage'];
        $percentageArray_adoption['App-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_adoption['User-ID']['value'] = $stdoutarray['user id percentage'];
        $percentageArray_adoption['User-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_adoption['Service/Port']['value'] = $stdoutarray['service port percentage'];
        $percentageArray_adoption['Service/Port']['group'] = 'Apps, Users, Ports';

        $percentageArray_adoption['Antivirus Profiles']['value'] = $stdoutarray['av adoption percentage'];
        $percentageArray_adoption['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['Anti-Spyware Profiles']['value'] = $stdoutarray['as adoption percentage'];
        $percentageArray_adoption['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['Vulnerability Profiles']['value'] = $stdoutarray['vp adoption percentage'];
        $percentageArray_adoption['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_adoption['File Blocking Profiles']['value'] = $stdoutarray['fb adoption percentage'];
        $percentageArray_adoption['File Blocking Profiles']['group'] = 'Data Loss Prevention';
        $percentageArray_adoption['Data Filtering']['value'] = $stdoutarray['data adoption percentage'];
        $percentageArray_adoption['Data Filtering']['group'] = 'Data Loss Prevention';
        $percentageArray_adoption['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access adoption percentage'];
        $percentageArray_adoption['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_adoption['Credential Theft Prevention']['value'] = $stdoutarray['url-credential adoption percentage'];
        $percentageArray_adoption['Credential Theft Prevention']['group'] = 'URL Filtering';
        #$percentageArray_adoption['DNS List'] = $stdoutarray['dns-list adoption percentage'];
        $percentageArray_adoption['DNS Security']['value'] = $stdoutarray['dns-security adoption percentage'];
        $percentageArray_adoption['DNS Security']['group'] = 'DNS Security';

        $percentageArray['adoption'] = $percentageArray_adoption;

        $percentageArray_visibility = array();
        $percentageArray_visibility['Logging']['value'] = $stdoutarray['log at end percentage'];
        $percentageArray_visibility['Logging']['group'] = 'Logging';
        $percentageArray_visibility['Log Forwarding Profiles']['value'] = $stdoutarray['log prof set percentage'];
        $percentageArray_visibility['Log Forwarding Profiles']['group'] = 'Logging';
        $percentageArray_visibility['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf visibility percentage'];
        $percentageArray_visibility['Wildfire Analysis Profiles']['group'] = 'Wildfire';
        $percentageArray_visibility['Zone Protection']['value'] = $stdoutarray['zone protection percentage'];
        $percentageArray_visibility['Zone Protection']['group'] = 'Zone Protection';
        $percentageArray_visibility['App-ID']['value'] = $stdoutarray['app id percentage'];
        $percentageArray_visibility['App-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_visibility['User-ID']['value'] = $stdoutarray['user id percentage'];
        $percentageArray_visibility['User-ID']['group'] = 'Apps, Users, Ports';
        $percentageArray_visibility['Service/Port']['value'] = $stdoutarray['service port percentage'];
        $percentageArray_visibility['Service/Port']['group'] = 'Apps, Users, Ports';

        $percentageArray_visibility['Antivirus Profiles']['value'] = $stdoutarray['av visibility percentage'];
        $percentageArray_visibility['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Anti-Spyware Profiles']['value'] = $stdoutarray['as visibility percentage'];
        $percentageArray_visibility['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['Vulnerability Profiles']['value'] = $stdoutarray['vp visibility percentage'];
        $percentageArray_visibility['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_visibility['File Blocking Profiles']['value'] = $stdoutarray['fb visibility percentage'];
        $percentageArray_visibility['File Blocking Profiles']['group'] = 'Data Loss Prevention';
        $percentageArray_visibility['Data Filtering']['value'] = $stdoutarray['data visibility percentage'];
        $percentageArray_visibility['Data Filtering']['group'] = 'Data Loss Prevention';
        $percentageArray_visibility['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access visibility percentage'];
        $percentageArray_visibility['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_visibility['Credential Theft Prevention']['value'] = $stdoutarray['url-credential visibility percentage'];
        $percentageArray_visibility['Credential Theft Prevention']['group'] = 'URL Filtering';
        #$percentageArray_visibility['DNS List'] = $stdoutarray['dns-list visibility percentage'];
        $percentageArray_visibility['DNS Security']['value'] = $stdoutarray['dns-security visibility percentage'];
        $percentageArray_visibility['DNS Security']['group'] = 'DNS Security';

        $percentageArray['visibility'] = $percentageArray_visibility;

        $percentageArray_best_practice = array();
        $percentageArray_best_practice['Logging']['value'] = $stdoutarray['log at not start percentage'];
        $percentageArray_best_practice['Logging']['group'] = 'Logging';
        #$percentageArray_best_practice['Log Forwarding Profiles'] = $stdoutarray['log prof set percentage'];

        $percentageArray_best_practice['Wildfire Analysis Profiles']['value'] = $stdoutarray['wf best-practice percentage'];
        $percentageArray_best_practice['Wildfire Analysis Profiles']['group'] = 'Wildfire';
        #$percentageArray_best_practice['Zone Protection']['value'] = '---';
        #$percentageArray_best_practice['App-ID']['value'] = $stdoutarray['app id percentage'];
        #$percentageArray_best_practice['User-ID']['value'] = $stdoutarray['user id percentage'];
        #$percentageArray_best_practice['Service/Port']['value'] = $stdoutarray['service port percentage'];

        $percentageArray_best_practice['Antivirus Profiles']['value'] = $stdoutarray['av best-practice percentage'];
        $percentageArray_best_practice['Antivirus Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Anti-Spyware Profiles']['value'] = $stdoutarray['as best-practice percentage'];
        $percentageArray_best_practice['Anti-Spyware Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['Vulnerability Profiles']['value'] = $stdoutarray['vp best-practice percentage'];
        $percentageArray_best_practice['Vulnerability Profiles']['group'] = 'Threat Prevention';
        $percentageArray_best_practice['File Blocking Profiles']['value'] = $stdoutarray['fb best-practice percentage'];
        $percentageArray_best_practice['File Blocking Profiles']['group'] = 'Data Loss Prevention';
        #$percentageArray_best_practice['Data Filtering']['value'] = '---';
        $percentageArray_best_practice['URL Filtering Profiles']['value'] = $stdoutarray['url-site-access best-practice percentage'];
        $percentageArray_best_practice['URL Filtering Profiles']['group'] = 'URL Filtering';
        $percentageArray_best_practice['Credential Theft Prevention']['value'] = $stdoutarray['url-credential best-practice percentage'];
        $percentageArray_best_practice['Credential Theft Prevention']['group'] = 'URL Filtering';
        #$percentageArray_best_practice['DNS List']['value'] = $stdoutarray['dns-list best-practice percentage'];
        $percentageArray_best_practice['DNS Security']['value'] = $stdoutarray['dns-security best-practice percentage'];
        $percentageArray_best_practice['DNS Security']['group'] = 'DNS Security';

        $percentageArray['best-practice'] = $percentageArray_best_practice;

        $stdoutarray['percentage'] = $percentageArray;

        return $stdoutarray;
    }


    public function display_bp_statistics( $debug = false, $actions = "display", $location = false )
    {
        $stdoutarray = $this->get_bp_statistics( $actions );

        $stdoutarray['type'] = get_class( $this );


        if( !PH::$shadow_loaddghierarchy )
            $header = "Statistics for ".get_class( $this )." '" . PH::boldText('Buckbeak full') . "'";
        else
            $header = "Statistics for ".get_class( $this ).": Folder-Hierarchy location: '" .$location. "'";

        $stdoutarray['header'] = $header;
        $stdoutarray['statstype'] = "adoption";


        $folderArray = $this->getContainers();
        $tmpArray = $this->getDeviceClouds();
        $folderArray = array_merge( $tmpArray, $folderArray );
        $tmpArray = $this->getDeviceOnPrems();
        $folderArray = array_merge( $tmpArray, $folderArray );

        foreach( $folderArray as $deviceGroup )
        {
            $stdoutarray2 = $deviceGroup->get_bp_statistics();
            foreach ($stdoutarray2 as $key2 => $stdoutarray_value)
            {
                if( $key2 == "header" || $key2 == "type" || $key2 == "statstype" )
                    continue;

                if( strpos( $key2, "calc" ) !== FALSE || strpos( $key2, "percentage" ) !== FALSE || strpos( $key2, "type" ) !== FALSE )
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

        $percentageArray = array();

        $percentageArray_adoption = array();

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

        $stdoutarray['user id calc'] =  $stdoutarray['user id'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['user id percentage'] = floor( ( $stdoutarray['user id'] / $stdoutarray['security rules enabled'] ) * 100 );
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

//-------------
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

        $stdoutarray['user id calc'] =  $stdoutarray['user id'] ."/". $stdoutarray['security rules enabled'];
        if( $stdoutarray['security rules enabled'] !== 0 )
            $stdoutarray['user id percentage'] = floor( ( $stdoutarray['user id'] / $stdoutarray['security rules enabled'] ) * 100 );
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
            PH::getBPjsonFile();

            PH::print_stdout( $header );

            $string_check = "adoption";
            PH::print_stdout($string_check);
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_adoption as $key => $value )
            {
                if( isset( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] ) )
                {
                    if( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] === false )
                        continue;
                }
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


            $string_check = "visibility";
            PH::print_stdout($string_check);
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_visibility as $key => $value )
            {
                if( isset( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] ) )
                {
                    if( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] === false )
                        continue;
                }
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

            $string_check = "best-practice";
            PH::print_stdout($string_check);
            $tbl = new ConsoleTable();
            $tbl->setHeaders(
                array('Type', 'percentage', "%")
            );
            foreach( $percentageArray_best_practice as $key => $value )
            {
                if( isset( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] ) )
                {
                    if( PH::$shadow_bp_jsonfile['included-in-bpa'][$string_check][$key] === false )
                        continue;
                }
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

            PH::print_stdout();
        }

        if( !PH::$shadow_json && $debug && $actions == "display-bpa")
            PH::print_stdout( $stdoutarray, true );

        if( $actions == "display-bpa" )
            PH::$JSON_TMP[] = $stdoutarray;
    }

    /**
     * Create a blank device group. Return that DV object.
     * @param string $name
     * @return Container
     **/
    public function createContainer($name, $parentContainerName)
    {
        $newDG = new Container($this);
        $newDG->load_from_templateContainerXml();
        $newDG->setName($name);

        $parentNode = DH::findFirstElementOrCreate('parent', $newDG->xmlroot );
        DH::setDomNodeText($parentNode, $parentContainerName );

        $this->containers[] = $newDG;

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
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/container', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$dgMaxID}</id></entry>");
            else
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id></entry>");

            $dgMetaDataNode->appendChild($newXmlNode);
        }

        $parentContainer = $this->findContainer( $parentContainerName );
        if( $parentContainer === null )
            mwarning("Container '$name' has Container '{$parentContainerName}' listed as parent but it cannot be found in XML");
        else
        {
            $parentContainer->_childContainers[$name] = $newDG;
            $newDG->parentContainer = $parentContainer;

            /*
            $newDG->addressStore->parentCentralStore = $parentContainer->addressStore;
            $newDG->serviceStore->parentCentralStore = $parentContainer->serviceStore;
            $newDG->tagStore->parentCentralStore = $parentContainer->tagStore;
            $newDG->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
            $newDG->appStore->parentCentralStore = $parentContainer->appStore;
            $newDG->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
            */
            //Todo: swaschkut 20210505 - check if other Stores must be added
            //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile

            $storeType = array(
                'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                'securityProfileGroupStore',

                'URLProfileStore', 'VirusAndWildfireProfileStore', 'FileBlockingProfileStore',
                //'DataFilteringProfileStore',
                'VulnerabilityProfileStore', 'AntiSpywareProfileStore',
                //'WildfireProfileStore',
                'DecryptionProfileStore', 'HipObjectsProfileStore', 'customURLProfileStore',

                'DNSSecurityProfileStore', 'SaasSecurityProfileStore'
            );

            foreach( $storeType as $type )
                $newDG->$type->parentCentralStore = $parentContainer->$type;
        }

        return $newDG;
    }

    /**
     * @return Container[]
     */
    public function getContainers()
    {
        return $this->containers;
    }


    /**
     * Create a blank template. Return that template object.
     * @param string $name
     * @return DeviceCloud
     **/
    public function createDeviceCloud($name, $parentContainer_txt )
    {
        $newDG = new DeviceCloud($this);

        $xmlNode = DH::importXmlStringOrDie($this->xmldoc, DeviceCloud::$templateXml);

        $xmlNode->setAttribute('name', $name);

        #$newDG->load_from_domxml($xmlNode);
        $newDG->load_from_templateCloudeXml();
        $newDG->setName($name);

        $parentNode = DH::findFirstElementOrCreate('parent', $newDG->xmlroot );
        DH::setDomNodeText($parentNode, $parentContainer_txt );

        $this->clouds[] = $newDG;

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
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/device/cloud', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$dgMaxID}</id></entry>");
            else
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id></entry>");

            $dgMetaDataNode->appendChild($newXmlNode);
        }

        $parentContainer = $this->findContainer( $parentContainer_txt );
        if( $parentContainer === null )
            mwarning("Container '$name' has Container '{$parentContainer_txt}' listed as parent but it cannot be found in XML");
        else
        {
            $parentContainer->_childContainers[$name] = $newDG;
            $newDG->parentContainer = $parentContainer;

            /*
            $newDG->addressStore->parentCentralStore = $parentContainer->addressStore;
            $newDG->serviceStore->parentCentralStore = $parentContainer->serviceStore;
            $newDG->tagStore->parentCentralStore = $parentContainer->tagStore;
            $newDG->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
            $newDG->appStore->parentCentralStore = $parentContainer->appStore;
            $newDG->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
            */
            //Todo: swaschkut 20210505 - check if other Stores must be added
            //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile

            $storeType = array(
                'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                'securityProfileGroupStore',

                'URLProfileStore', 'VirusAndWildfireProfileStore', 'FileBlockingProfileStore',
                //'DataFilteringProfileStore',
                'VulnerabilityProfileStore', 'AntiSpywareProfileStore',
                //'WildfireProfileStore',
                'DecryptionProfileStore', 'HipObjectsProfileStore', 'customURLProfileStore',

                'DNSSecurityProfileStore', 'SaasSecurityProfileStore'

            );

            foreach( $storeType as $type )
                $newDG->$type->parentCentralStore = $parentContainer->$type;
        }

        return $newDG;
    }

    /**
     * @return DeviceCloud[]
     */
    public function getDeviceClouds()
    {
        return $this->clouds;
    }

    /**
     * Create a blank template. Return that template object.
     * @param string $name
     * @return DeviceOnPrem
     **/
    public function createDeviceOnPrem($name, $parentContainer_txt )
    {
        $newDG = new DeviceOnPrem($this);

        $xmlNode = DH::importXmlStringOrDie($this->xmldoc, DeviceOnPrem::$templateXml);

        $xmlNode->setAttribute('name', $name);

        #$newDG->load_from_domxml($xmlNode);
        $newDG->load_from_templateOnPremXml();
        $newDG->setName($name);

        $parentNode = DH::findFirstElementOrCreate('parent', $newDG->xmlroot );
        DH::setDomNodeText($parentNode, $parentContainer_txt );

        $this->onprems[] = $newDG;

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
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/device/on-prem', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$dgMaxID}</id></entry>");
            else
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id></entry>");

            $dgMetaDataNode->appendChild($newXmlNode);
        }

        $parentContainer = $this->findContainer( $parentContainer_txt );
        if( $parentContainer === null )
            mwarning("Container '$name' has Container '{$parentContainer_txt}' listed as parent but it cannot be found in XML");
        else
        {
            $parentContainer->_childContainers[$name] = $newDG;
            $newDG->parentContainer = $parentContainer;

            /*
            $newDG->addressStore->parentCentralStore = $parentContainer->addressStore;
            $newDG->serviceStore->parentCentralStore = $parentContainer->serviceStore;
            $newDG->tagStore->parentCentralStore = $parentContainer->tagStore;
            $newDG->scheduleStore->parentCentralStore = $parentContainer->scheduleStore;
            $newDG->appStore->parentCentralStore = $parentContainer->appStore;
            $newDG->securityProfileGroupStore->parentCentralStore = $parentContainer->securityProfileGroupStore;
            */
            //Todo: swaschkut 20210505 - check if other Stores must be added
            //- appStore;scheduleStore/securityProfileGroupStore/all kind of SecurityProfile

            $storeType = array(
                'addressStore', 'serviceStore', 'tagStore', 'scheduleStore', 'appStore',

                'securityProfileGroupStore',

                'URLProfileStore', 'VirusAndWildfireProfileStore', 'FileBlockingProfileStore',
                //'DataFilteringProfileStore',
                'VulnerabilityProfileStore', 'AntiSpywareProfileStore',
                //'WildfireProfileStore',
                'DecryptionProfileStore', 'HipObjectsProfileStore', 'customURLProfileStore',

                'DNSSecurityProfileStore', 'SaasSecurityProfileStore'

            );

            foreach( $storeType as $type )
                $newDG->$type->parentCentralStore = $parentContainer->$type;
        }

        return $newDG;
    }


    /**
     * @return DeviceOnPrem[]
     */
    public function getDeviceOnPrems()
    {
        return $this->onprems;
    }

    public function isBuckbeak()
    {
        return TRUE;
    }

    public function findSubSystemByName($location)
    {
        $return = $this->findContainer($location);
        if( $return == null )
            $return = $this->findDeviceCloud($location);
        if( $return == null )
            $return = $this->findDeviceOnPrem($location);
        if( $return == null )
            $return = $this->findSnippet($location);
        return $return;
    }

}



