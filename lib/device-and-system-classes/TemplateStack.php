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

class TemplateStack
{
    use ReferenceableObject;
    use PathableName;
    use PanSubHelperTrait;
    use XmlConvertible;

    /** @var PanoramaConf */
    public $owner;

    /** @var  array */
    public $templates = array();

    protected $templateRoot = null;

    /** @var DOMElement */
    public $devicesRoot;
    public $userGroupSourceRoot;

    public $xmlroot = null;

    public $FirewallsSerials = array();

    /** @var CertificateStore */
    public $certificateStore = null;

    /** @var  PANConf */
    public $deviceConfiguration;

    /**
     * Template constructor.
     * @param string $name
     * @param PanoramaConf $owner
     */
    public function __construct($name, $owner)
    {
        $this->name = $name;
        $this->owner = $owner;
        $this->deviceConfiguration = new PANConf(null, null, $this);

        $this->certificateStore = new CertificateStore($this);
        $this->certificateStore->setName('certificateStore');
    }

    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("templatestack name not found\n", $xml);

        #print "template-stack: ".$this->name."\n";
        $this->templateRoot = DH::findFirstElement('templates', $xml);

        if( $this->templateRoot !== FALSE )
        {
            foreach( $this->templateRoot->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE ) continue;

                $ldv = $node->textContent;

                $template = $this->owner->findTemplate( $ldv );
                $this->templates[] = $template;

                $template->addReference( $this );
            }
        }

        $this->devicesRoot = DH::findFirstElement('devices', $xml);
        if( $this->devicesRoot !== false )
        {
            $this->FirewallsSerials = $this->owner->managedFirewallsStore->get_serial_from_xml($this->devicesRoot, TRUE);
            #$this->FirewallsSerials = $this->owner->managedFirewallsStore->get_serial_from_xml($tmp);
            foreach( $this->FirewallsSerials as $serial => $managedFirewall )
            {
                if( $managedFirewall !== null )
                {
                    $managedFirewall->addTemplateStack($this->name);
                    $managedFirewall->addReference( $this );
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

        //Todo: how common it is to have device config inside templateStack???
        $tmp = DH::findFirstElement('config', $xml);

        if( $tmp !== false )
        {
            $this->deviceConfiguration->load_from_domxml($tmp);

            $shared = DH::findFirstElement('shared', $tmp);
            if( $shared !== false )
            {
                //
                // Extract Certificate objects
                //
                $tmp = DH::findFirstElement('certificate', $shared);
                if( $tmp !== FALSE )
                {
                    $this->certificateStore->load_from_domxml($tmp);
                }
                // End of Certificate objects extraction
            }
        }


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

    public function isTemplateStack()
    {
        return TRUE;
    }

    /**
     * Add a member to this group, it must be passed as an object
     * @param Template $newObject Object to be added
     * @param bool $rewriteXml
     * @return bool
     */
    public function addTemplate($newObject, $position, $rewriteXml = TRUE)
    {
        if( !is_object($newObject) )
            derr("Only objects can be passed to this function");

        if( get_class( $newObject ) !== "Template" )
        {
            mwarning("only objects of class Template can be added to a Template-Stack!");
            return FALSE;
        }

        if( $position !== 'bottom' )
        {
            mwarning("Template position only bottom is supported right now!");
            return null;
        }


        if( !in_array($newObject, $this->templates, TRUE) )
        {
            $this->templates[] = $newObject;
            $newObject->addReference($this);
            if( $rewriteXml && $this->owner !== null )
            {
                DH::createElement($this->templateRoot, 'member', $newObject->name());
            }

            return TRUE;
        }

        return FALSE;
    }

    /**
     * Add a member to this group, it must be passed as an object
     * @param Template $newObject Object to be added
     * @return bool
     */
    public function API_addTemplate($newObject, $position)
    {
        $ret = $this->addTemplate($newObject, $position);

        if( $ret )
        {
            $con = findConnector($this);
            $xpath = $this->getXPath();
            if( $con->isAPI() )
                $con->sendSetRequest($xpath."/templates", "<member>{$newObject->name()}</member>");
        }

        return $ret;
    }

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/template-stack/entry[@name='" . $this->name . "']";

        return $str;
    }

    public function load_from_templatestackXml()
    {
        if( $this->owner === null )
            derr('cannot be used if owner === null');

        $fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

        if( !$fragment->appendXML(self::$templatestackxml) )
            derr('error occured while loading TEMPLATE-STACK template xml');

        $element = $this->owner->templatestackroot->appendChild($fragment);

        $this->load_from_domxml($element);
    }

    /*
    public static $templatestackxml = '<entry name="**Need a Name**">
                                        <user-group-source><master-device/></user-group-source>
                                        <settings/>
                                        <devices/>
									</entry>';
    */

    public static $templatestackxml = '<entry name="**Need a Name**">
                                        <devices/>
									</entry>';

    public function addDevice( $serial, $vsys = "vsys1" )
    {
        if( isset( $this->FirewallsSerials[$serial] ) && $vsys !== "vsys1" )
        {
            $this->FirewallsSerials[$serial]['vsyslist'][$vsys] = $vsys;
        }
        else
        {
            $vsyslist['vsys1'] = 'vsys1';
            $this->FirewallsSerials[$serial] = array('serial' => $serial, 'vsyslist' => $vsyslist);
        }
        //XML manipulation missing
        $newXmlNode = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, "<entry name='{$serial}'/>");
        $devicenode = $this->devicesRoot->appendChild($newXmlNode);
    }


    public function removeDevice( $serial )
    {
        if( isset( $this->FirewallsSerials[$serial] ) )
        {
            unset( $this->FirewallsSerials[$serial] );
            //missing XML manipulation

            $user_group_source_node = DH::findFirstElement("user-group-source", $this->xmlroot);
            if( $user_group_source_node !== false )
            {
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
                        if( count($this->FirewallsSerials) > 0 )
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

