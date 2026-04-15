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
    use StatCollectorTrait;


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
    public $VirusAndWildfireProfileStore;


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


        $this->predefinedappStore = AppStore::getPredefinedStore( $this );
        $this->appStore = new AppStore($this);
        $this->appStore->name = 'apps';
        $this->appStore->parentCentralStore = $this->predefinedappStore;

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
        $this->VirusAndWildfireProfileStore = SecurityProfileStore::getVirusAndWildfirePredefinedStore( $this );
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

        $this->onpremroot = DH::findFirstElementOrCreate('on-prem', $this->devicecloudroot);



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

            $ldv = $this->findContainer($containerName);
            if( $ldv === null )
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
                    {
                        $this->container_validation[$containerName] = $containerToParent[$containerName];

                        $parentContainer = new Container($this);
                        $parentContainer->setName( $containerToParent[$containerName] );

                        #mwarning("Container '$containerName' has Container '{$containerToParent[$containerName]}' listed as parent but it cannot be found in XML",null, false);
                    }

                }

                if( $parentContainer !== null )
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

                        'DNSSecurityProfileStore', 'SaasSecurityProfileStore',

                        'LogProfileStore'

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
            mwarning("Container '$name' has Container 'All' listed as parent but it cannot be found in XML",null, true);
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

        $container_all->get_mainDevice_statistics( $statsArray);



        foreach( $this->containers as $cur )
        {
            if( $cur->name() == "All" )
                continue;

            $this->get_combined_subDevice_statistics($statsArray, $cur );
        }

        foreach( $this->clouds as $cur )
        {
            if( $cur->name() == "All" )
                continue;

            $this->get_combined_subDevice_statistics($statsArray, $cur, true );
        }

        #$stdoutarray = array();

        $header = "Statistics for ".get_class( $this )." '" . $this->name . "'";

        $subName = "All";
        $sub = $container_all;

        $this->display_mainDevice_statistics($stdoutarray, $statsArray, $sub, $subName, $header);


        //how to handle Buckbeak config???
        #$this->display_size_NEW($stdoutarray);


        $sub = $this;
        if( !PH::$shadow_json && $actions == "display" )
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
            $sub->display_bp_statistics( $debug, $actions );
        else
            $sub->display_bp_statistics( $debug, $actions, $location );

        if( get_class( $sub ) == 'PanoramaConf' )
        {
            if( !PH::$shadow_loaddghierarchy )
                $sub->display_shared_statistics( $connector, $debug, $actions );
        }
    }



    public function display_bp_statistics( $debug = false, $actions = "display", $location = false )
    {
        $stdoutarray = $this->get_bp_statistics( );

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

        //Todo: swaschkut 20260106
        // how to include snippets??? attach to folder/container??

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


        $this->bp_calculation( $stdoutarray );

        $percentageArray = $this->get_bp_percentageArray( $stdoutarray );


        $stdoutarray['percentage'] = $percentageArray;

        PH::$JSON_TMP[] = $stdoutarray;

        $this->generate_table($stdoutarray, $debug, $actions);
    }

    /**
     * Create a blank device group. Return that DV object.
     * @param string $name
     * @return Container
     **/
    public function createContainer($name, $parentContainerName = "All"): Container
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
            mwarning("Container '$name' has Container '{$parentContainerName}' listed as parent but it cannot be found in XML",null, true);

        if( $parentContainer !== null )
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
    public function getContainers(): array
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
            mwarning("Container '$name' has Container '{$parentContainer_txt}' listed as parent but it cannot be found in XML",null, true);
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
            {
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry[@name="localhost.localdomain"]/device/on-prem', $this->xmlroot);
                //$dgMetaDataNode = DH::findXPathSingleEntryOrCreate('/config/readonly/devices/entry[@name="localhost.localdomain"]/device/on-prem', $this->xmlroot);
            }

            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);

            if( $this->version >= 80 )
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><id>{$dgMaxID}</id></entry>");
            else
                $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id></entry>");

            $dgMetaDataNode->appendChild($newXmlNode);
        }

        $parentContainer = $this->findContainer( $parentContainer_txt );
        //todo: issue
        if( $parentContainer === null )
        {
            mwarning("Container '$name' has Container '{$parentContainer_txt}' listed as parent but it cannot be found in XML",null, true);

            #$this->container_validation[$containerName] = $containerToParent[$containerName];

            #$parentContainer = new Container($this);
            #$parentContainer->setName( $containerToParent[$containerName] );
        }

        if( $parentContainer !== null )
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



