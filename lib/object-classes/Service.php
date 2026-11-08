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


class Service
{
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;
    use ServiceCommon;

    protected $_protocol = 'tcp';
    protected $_dport = '';
    protected $_sport = '';
    protected $_timeout = '';
    protected $_halfclose_timeout = '';
    protected $_timewait_timeout = '';

    public $migrated;
    public $ancestor;
    public $childancestor;

    /** @var null|DOMElement */
    // protocolRoot / tcpOrUdpRoot / dportroot are not stored any more (each held DOM node costs ~0.5 KB in PHP),
    // they are looked up from xmlroot when needed, see __get(), protocolNode(), tcpOrUdpNode()

    /** @var null|DOMElement */


    /** @var null|DOMElement */


    public $type = '';

    /** @var ServiceStore */
    public $owner = null;

    /** @var TagRuleContainer */
    public $tags;

    public $overrideroot = FALSE;

    /**
     * @param $name
     * @param ServiceStore $owner
     * @param bool $fromTemplateXml
     */
    function __construct($name, $owner = null, $fromTemplateXml = FALSE)
    {
        $this->owner = $owner;

        if( $fromTemplateXml )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            if( $this->owner->serviceRoot !== null )
                $rootDoc = $this->owner->serviceRoot->ownerDocument;
            else
            {
                $tmpXML = DH::findFirstElementOrCreate( "service", $this->owner->owner->xmlroot );
                $this->owner->load_services_from_domxml( $tmpXML );
                $rootDoc = $this->owner->owner->xmlroot->ownerDocument;
            }

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);
            $this->owner = null;

            $this->setName($name);
        }
        else
            $this->name = $name;

        $this->tags = new TagRuleContainer($this);
    }


    /**
     * @param DOMElement $xml
     * @throws Exception
     */
    /** <protocol> of this service */
    private function protocolNode()
    {
        return DH::findFirstElementOrDie('protocol', $this->xmlroot);
    }

    /** <tcp> or <udp> below <protocol> */
    private function tcpOrUdpNode()
    {
        $node = DH::findFirstElement($this->_protocol, $this->protocolNode());
        if( $node === FALSE )
            derr("Error: <".$this->_protocol."> not found for service " . $this->name);
        return $node;
    }

    /**
     * compatibility for the former public properties protocolRoot / tcpOrUdpRoot / dportroot / overrideroot nodes
     */
    public function __get($name)
    {
        if( $name == 'protocolRoot' )
            return $this->xmlroot === null ? null : $this->protocolNode();
        if( $name == 'tcpOrUdpRoot' )
            return $this->xmlroot === null ? null : $this->tcpOrUdpNode();
        if( $name == 'dportroot' )
            return $this->xmlroot === null ? null : DH::findFirstElement('port', $this->tcpOrUdpNode());

        trigger_error("Undefined property: ".get_class($this)."::\$".$name, E_USER_NOTICE);
        return null;
    }

    public function load_from_domxml($xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("service name not found\n");

        $this->_load_description_from_domxml();

        //
        // seeking <protocol>
        //
        $protocolRoot = DH::findFirstElementOrDie('protocol', $xml);

        $tcpOrUdpRoot = DH::findFirstElement('tcp', $protocolRoot);

        if( $tcpOrUdpRoot === FALSE )
        {
            $this->_protocol = 'udp';
            $tcpOrUdpRoot = DH::findFirstElement('udp', $protocolRoot);
        }
        if( $tcpOrUdpRoot === FALSE )
            derr("Error: <tcp> or <udp> not found for service" . $this->name . "\n");

        $dportroot = DH::findFirstElementOrDie('port', $tcpOrUdpRoot);

        $this->_dport = $dportroot->textContent;

        $sportroot = DH::findFirstElement('source-port', $tcpOrUdpRoot);
        if( $sportroot !== FALSE )
        {
            $this->_sport = $sportroot->textContent;
        }

        if( $this->owner->owner->version >= 60 )
        {
            $tagRoot = DH::findFirstElement('tag', $xml);
            if( $tagRoot !== FALSE )
                $this->tags->load_from_domxml($tagRoot);
        }

        $overrideroot = DH::findFirstElement('override', $tcpOrUdpRoot);
        // only a flag is kept; the <override> node is looked up again where needed
        $this->overrideroot = ( $overrideroot !== FALSE );
        if( $overrideroot !== FALSE )
        {
            $override_noyes = DH::findFirstElement('yes', $overrideroot);
            if( $override_noyes !== FALSE )
            {
                $timeoutroot = DH::findFirstElement('timeout', $override_noyes);
                if( $timeoutroot != FALSE )
                    $this->_timeout = $timeoutroot->textContent;

                $halfclose_timeoutroot = DH::findFirstElement('halfclose-timeout', $override_noyes);
                if( $halfclose_timeoutroot != FALSE )
                    $this->_halfclose_timeout = $halfclose_timeoutroot->textContent;

                $timewait_timeoutroot = DH::findFirstElement('timewait-timeout', $override_noyes);
                if( $timewait_timeoutroot != FALSE )
                    $this->_timewait_timeout = $timewait_timeoutroot->textContent;
            }
        }
    }

    public function display(&$tmp_txt)
    {
        $tmp_txt = "     * " . get_class($this) . " '{$this->name()}'     value: '{$this->protocol()}/{$this->getDestPort()}'";
        PH::$JSON_TMP['sub']['object'][$this->name()]['value'] = "{$this->protocol()}/{$this->getDestPort()}";

        if( $this->description() != "" )
            $tmp_txt .= "    desc: '{$this->description()}'";
        PH::$JSON_TMP['sub']['object'][$this->name()]['description'] = $this->description();

        if( $this->getSourcePort() != "" )
            $tmp_txt .= "    sourceport: '" . $this->getSourcePort() . "'";
        PH::$JSON_TMP['sub']['object'][$this->name()]['sourceport'] = $this->getSourcePort();

        if( $this->getTimeout() != "" )
            $tmp_txt .= "    timeout: '" . $this->getTimeout() . "'";
        PH::$JSON_TMP['sub']['object'][$this->name()]['timeout'] = $this->getTimeout();

        if( $this->getHalfcloseTimeout() != "" )
            $tmp_txt .= "    HalfcloseTimeout: '" . $this->getHalfcloseTimeout() . "'";
        PH::$JSON_TMP['sub']['object'][$this->name()]['halfclosetimeout'] = $this->getHalfcloseTimeout();

        if( $this->getTimewaitTimeout() != "" )
            $tmp_txt .= "    TimewaitTimeout: '" . $this->getTimewaitTimeout() . "'";
        PH::$JSON_TMP['sub']['object'][$this->name()]['timewaittimeout'] = $this->getTimewaitTimeout();

        if( strpos($this->getDestPort(), ",") !== FALSE )
            $tmp_txt .= "    count values: '" . (substr_count($this->getDestPort(), ",") + 1) . "' length: " . strlen($this->getDestPort());
        PH::$JSON_TMP['sub']['object'][$this->name()]['count values'] = (substr_count($this->getDestPort(), ",") + 1);
        PH::$JSON_TMP['sub']['object'][$this->name()]['string legth'] = strlen($this->getDestPort());
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function setDestPort($newPorts)
    {
        if( strlen($newPorts) == 0 )
            derr("invalid blank value for newPorts");

        if( strlen($newPorts) > 1023 )
            derr("invalid value for destinationPort. string length >1023");

        if( $newPorts == $this->_dport )
            return FALSE;

        $this->_dport = $newPorts;
        $tmp = DH::findFirstElementOrCreate('port', $this->tcpOrUdpNode(), $this->_dport);
        DH::setDomNodeText($tmp, $newPorts);
        return TRUE;
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function API_setDestPort($newPorts)
    {
        $ret = $this->setDestPort($newPorts);
        if( $ret )
            $this->API_sync();

        return $ret;
    }


    public function setSourcePort($newPorts)
    {
        if( $newPorts === null || strlen($newPorts) == 0 )
        {
            if( strlen($this->_sport) == 0 )
                return FALSE;

            $this->_sport = $newPorts;
            $sportroot = DH::findFirstElement('source-port', $this->tcpOrUdpNode());
            if( $sportroot !== FALSE )
                $this->tcpOrUdpNode()->removeChild($sportroot);

            return TRUE;
        }
        if( $this->_sport == $newPorts )
            return FALSE;

        if( strlen($this->_sport) == 0 )
        {
            DH::findFirstElementOrCreate('source-port', $this->tcpOrUdpNode(), $newPorts);
            return TRUE;
        }
        $sportroot = DH::findFirstElementOrCreate('source-port', $this->tcpOrUdpNode());
        DH::setDomNodeText($sportroot, $newPorts);
        return TRUE;
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function API_setSourcePort($newPorts)
    {
        $ret = $this->setSourcePort($newPorts);
        if( $ret )
            $this->API_sync();

        return $ret;
    }

    public function isTcp()
    {
        if( $this->_protocol == 'tcp' )
            return TRUE;

        return FALSE;
    }

    public function isUdp()
    {
        if( $this->_protocol == 'udp' )
            return TRUE;

        return FALSE;
    }

    /**
     * @param string $newProtocol
     */
    public function setProtocol($newProtocol)
    {
        if( $newProtocol != 'tcp' && $newProtocol != 'udp' )
            derr("unsupported protocol '{$newProtocol}'");

        if( $newProtocol == $this->_protocol )
            return;

        $this->_protocol = $newProtocol;

        $protocolRoot = $this->protocolNode();
        DH::clearDomNodeChilds($protocolRoot);

        $tcpOrUdpRoot = DH::createElement($protocolRoot, $this->_protocol);

        DH::createElement($tcpOrUdpRoot, 'port', $this->_dport);

        if( strlen($this->_sport) > 0 )
            DH::createElement($tcpOrUdpRoot, 'source-port', $this->_dport);
    }

    /**
     * @param string $newTimeout
     * @return bool
     */
    public function setTimeoutGeneral($type, $newTimeout)
    {
        if( strlen($newTimeout) == 0 )
            derr("invalid blank value for newTimeout setting");

        $clear = false;
        if( $type == "timeout" )
        {
            if( $newTimeout == $this->_timeout )
                return FALSE;
            if( $newTimeout > 604800 )
            {
                derr( "timewait value must between 1-604800", null, False );
                return FALSE;
            }
            if( $newTimeout == 3600 )
            {
                $clear = true;
                $this->_timeout = "";
            }
            else
                $this->_timeout = $newTimeout;
        }
        elseif( $type == "halfclose" )
        {
            if( !$this->isTcp() )
                return FALSE;
            if( $newTimeout == $this->_halfclose_timeout )
            {
                return FALSE;
            }
            if( $newTimeout > 604800 )
            {
                derr( "timewait value must between 1-604800", null, False );
                return FALSE;
            }
            if( $newTimeout == 120 )
            {
                $clear = true;
                $this->_halfclose_timeout = "";
            }
            else
                $this->_halfclose_timeout = $newTimeout;
        }
        elseif( $type == "timewait" )
        {
            if( !$this->isTcp() )
                return FALSE;
            if( $newTimeout == $this->_timewait_timeout )
                return FALSE;

            if( $newTimeout > 600 )
            {
                derr( "timewait value must between 1-600", null, False );
                return FALSE;
            }
            if( $newTimeout == 15 )
            {
                $clear = true;
                $this->_timewait_timeout = "";
            }
            else
                $this->_timewait_timeout = $newTimeout;
        }


        $tmp_override = DH::findFirstElementOrCreate('override', $this->tcpOrUdpNode());
        $tmpno = DH::findFirstElement('no', $tmp_override);
        if( $tmpno !== false )
            $tmp_override->removeChild( $tmpno );
        $tmpyes = DH::findFirstElementOrCreate('yes', $tmp_override);

        if( $type == "timeout" )
            $tmp_timeout = DH::findFirstElementOrCreate('timeout', $tmpyes, $this->_timeout);
        elseif( $type == "halfclose" )
            $tmp_timeout = DH::findFirstElementOrCreate('halfclose-timeout', $tmpyes, $this->_halfclose_timeout);
        elseif( $type == "timewait" )
            $tmp_timeout = DH::findFirstElementOrCreate('timewait-timeout', $tmpyes, $this->_timewait_timeout);

        if( $clear )
        {
            $tmpyes->removeChild( $tmp_timeout );
            if( empty($this->_timeout) and empty($this->_halfclose_timeout) and empty($this->_timewait_timeout) )
            {
                $tmp_override->removeChild( $tmpyes );
                $tmpno = DH::findFirstElementOrCreate('no', $tmp_override);
            }
        }
        else
            DH::setDomNodeText($tmp_timeout, $newTimeout);

        return TRUE;
    }


    /**
     * @param string $newPorts
     * @return bool
     */
    public function setTimeout($newTimeout)
    {
        return $this->setTimeoutGeneral("timeout", $newTimeout);
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function API_setTimeout($newTimeout)
    {
        $ret = $this->setTimeout($newTimeout);
        if( $ret )
            $this->API_sync();

        return $ret;
    }

    /**
     * @param string $newHalfCloseTimeout
     * @return bool
     */
    public function setHalfCloseTimeout($newHalfCloseTimeout)
    {
        if( !$this->isTcp() )
            return FALSE;
        return $this->setTimeoutGeneral("halfclose", $newHalfCloseTimeout);
    }

    /**
     * @param string $newHalfCloseTimeout
     * @return bool
     */
    public function API_setHalfCloseTimeout($newHalfCloseTimeout)
    {
        $ret = $this->setHalfCloseTimeout($newHalfCloseTimeout);
        if( $ret )
            $this->API_sync();

        return $ret;
    }

    /**
     * @param string $newTimeWaitTimeout
     * @return bool
     */
    public function setTimeWaitTimeout($newTimeWaitTimeout)
    {
        if( !$this->isTcp() )
            return FALSE;
        return $this->setTimeoutGeneral("timewait", $newTimeWaitTimeout);
    }

    /**
     * @param string $newTimeWaitTimeout
     * @return bool
     */
    public function API_setTimeWaitTimeout($newTimeWaitTimeout)
    {
        $ret = $this->setTimeWaitTimeout($newTimeWaitTimeout);
        if( $ret )
            $this->API_sync();

        return $ret;
    }


    /**
     * @param string $newPorts
     * @return bool
     */
    public function removeTimeout()
    {
        $this->_timeout = "";
        $this->_halfclose_timeout = "";
        $this->_timewait_timeout = "";

        $tmp = DH::findFirstElement('override', $this->tcpOrUdpNode());
        if( $tmp !== false )
        {
            $tmpyes = DH::findFirstElement('yes', $tmp);
            if( $tmpyes !== false )
            {
                $tmp->removeChild( $tmpyes );
                $tmpno = DH::findFirstElementOrCreate('no', $tmp);
                return TRUE;
            }
        }

        return FALSE;
    }

    /**
     * @param string $newPorts
     * @return bool
     */
    public function API_removeTimeout()
    {
        $ret = $this->removeTimeout();
        if( $ret )
            $this->API_sync();

        return $ret;
    }

    /**
     * @return string
     */
    public function protocol()
    {
        if( $this->isTmpSrv() )
        {
            if( $this->name() == 'service-http' )
                return 'tcp';
            if( $this->name() == 'service-https' )
                return 'tcp';
            return 'tmp';
        }

        else
            return $this->_protocol;
    }

    /**
     * @return string
     */
    public function getDestPort()
    {
        if( $this->isTmpSrv() )
        {
            if( $this->name() == 'service-http' )
                return '80';
            if( $this->name() == 'service-https' )
                return '443';
        }

        return $this->_dport;
    }

    /**
     * @return string
     */
    public function getSourcePort()
    {
        return $this->_sport;
    }

    /**
     * @return string
     */
    public function getTimeout()
    {
        return $this->_timeout;
    }

    /**
     * @return string
     */
    public function getHalfcloseTimeout()
    {
        return $this->_halfclose_timeout;
    }

    /**
     * @return string
     */
    public function getTimewaitTimeout()
    {
        return $this->_timewait_timeout;
    }

    /**
     * @return string
     */
    public function getOverride()
    {
        if( $this->_timeout == "" && $this->_halfclose_timeout == "" && $this->_timewait_timeout == "" )
            return "";
        else
            return $this->_timeout . "," . $this->_halfclose_timeout . "," . $this->_timewait_timeout;
    }

    /**
     * @param string $newName
     */
    public function setName($newName)
    {
        $this->setRefName($newName);

        if( $this->xmlroot !== null )
            $this->xmlroot->setAttribute('name', $newName);
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newName);

        if( $c->isAPI())
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getServiceStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }

    public function isService()
    {
        return TRUE;
    }


    public function isTmpSrv()
    {
        if( $this->type == 'tmp' )
            return TRUE;

        return FALSE;
    }


    /**
     * @param $otherObject Service|ServiceStore
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isService() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(Service $otherObject)
    {
        if( $otherObject->name() == "service-http" && $this->name() == "service-http" )
        {}
        elseif( $otherObject->name() == "service-https" && $this->name() == "service-https" )
        {}
        else
        {
            if( $this->isTmpSrv() && !$otherObject->isTmpSrv() )
                return FALSE;

            if( $otherObject->isTmpSrv() && !$this->isTmpSrv() )
                return FALSE;
        }

        if( $otherObject->_protocol !== $this->_protocol )
            return FALSE;

        if( $otherObject->_dport !== $this->_dport )
            return FALSE;

        if( $otherObject->_sport !== $this->_sport )
            return FALSE;

        if( $otherObject->getOverride() !== $this->getOverride() )
            return FALSE;

        return TRUE;
    }

    /**
     * @return ServiceDstPortMapping
     * @throws Exception
     */
    public function dstPortMapping()
    {
        if( $this->isTmpSrv() )
        {
            if( $this->name() == 'service-http' )
                return ServiceDstPortMapping::mappingFromText('80', TRUE);
            if( $this->name() == 'service-https' )
                return ServiceDstPortMapping::mappingFromText('443', TRUE);

            return new ServiceDstPortMapping();
        }


        if( $this->_protocol == 'tcp' )
            $tcp = TRUE;
        else
            $tcp = FALSE;

        return ServiceDstPortMapping::mappingFromText($this->_dport, $tcp);
    }

    /**
     * @return ServiceSrcPortMapping
     * @throws Exception
     */
    public function srcPortMapping()
    {
        if( $this->isTmpSrv() )
            return new ServiceSrcPortMapping();

        if( $this->_protocol == 'tcp' )
            $tcp = TRUE;
        else
            $tcp = FALSE;

        return ServiceSrcPortMapping::mappingFromText($this->_sport, $tcp);
    }

    public function API_delete()
    {
        if( $this->isTmpSrv() )
            derr('cannot be called on a Tmp service object');

        return $this->owner->API_remove($this);
    }

    public function removeReference($object)
    {
        $this->super_removeReference($object);

        if( $this->isTmpSrv() && $this->countReferences() == 0 && $this->owner !== null )
        {
            $this->owner->remove($this);
        }

    }

    static protected $templatexml = '<entry name="**temporarynamechangeme**"><protocol><tcp><port>0</port></tcp></protocol></entry>';
    static protected $templatexmlroot = null;

}
