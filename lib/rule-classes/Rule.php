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

class Rule
{

    use PathableName;
    use centralServiceStoreUser;
    use centralAddressStoreUser;
    use ObjectWithDescription;
    use RuleWithGroupTag;
    use XmlConvertible;

    protected $name = 'temporaryname';
    protected $disabled = FALSE;

    public $secprofgroupUndefined = null;

    /**
     * @var ZoneRuleContainer
     */
    public $from = null;
    /**
     * @var ZoneRuleContainer
     */
    public $to = null;
    /**
     * @var AddressRuleContainer
     */
    public $source;
    /**
     * @var AddressRuleContainer
     */
    public $destination;

    /**
     * @var TagRuleContainer
     */
    public $tags;

    /** @var GroupTagRuleContainer */
    public $grouptag;

    /**
     * @var ServiceRuleContainer
     */
    public $services;

    /**
     * @var RuleStore
     */
    public $owner = null;

    /** @var null|string[][] */
    protected $_targets = null;

    protected $_targetIsNegated = FALSE;


    private $uuid;

    /**
     * Returns name of this rule
     * @return string
     */
    public function name()
    {
        return $this->name;
    }

    /**
     * Returns uuid of this rule
     * @return string
     */
    public function uuid()
    {
        return $this->uuid;
    }

    /**
     * Returns uuid of this rule
     * @return bool
     */
    public function setUUID( $uuid)
    {
        $this->uuid = $uuid;
        return true;
    }

    /**
     *
     * @return bool
     */
    public function isDisabled()
    {
        return $this->disabled;
    }

    /**
     *
     * @return bool
     */
    public function isEnabled()
    {
        if( $this->disabled )
            return FALSE;

        return TRUE;
    }

    /**
     * For developer use only
     */
    protected function load_from()
    {
        $tmp = DH::findFirstElementOrCreate('from', $this->xmlroot);
        $this->from->load_from_domxml($tmp);
    }


    /**
     * For developer use only
     */
    protected function load_to()
    {
        $tmp = DH::findFirstElementOrCreate('to', $this->xmlroot);
        $this->to->load_from_domxml($tmp);
    }


    /**
     * For developer use only
     */
    protected function load_source()
    {
        $tmp = DH::findFirstElementOrCreate('source', $this->xmlroot);
        $this->source->load_from_domxml($tmp);
    }

    /**
     * For developer use only
     */
    protected function load_destination()
    {
        $tmp = DH::findFirstElementOrCreate('destination', $this->xmlroot);
        $this->destination->load_from_domxml($tmp);
    }

    /**
     * For developer use only
     *
     */
    protected function load_common_from_domxml()
    {
        if( $this->owner->owner->version >= 90 )
        {
            $this->uuid = DH::findAttribute('uuid', $this->xmlroot);
        }

        foreach( $this->xmlroot->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;


            if( $node->nodeName == 'disabled' )
            {
                $lstate = strtolower($node->textContent);
                if( $lstate == 'yes' )
                {
                    $this->disabled = TRUE;
                }
            }
            else if( $node->nodeName == 'tag' )
            {
                $this->tags->load_from_domxml($node);
            }
            else if( $node->nodeName == 'group-tag' )
            {
                $this->grouptag->load_from_domxml($node);
                /*
                $this->grouptag->xmlroot = $node;
                $grouptagName = $node->textContent;
                $tmpTag = $this->owner->owner->tagStore->find( $grouptagName, $this->grouptag);
                $this->grouptag->addTag($tmpTag);
                */
            }
            else if( $node->nodeName == 'description' )
            {
                $this->_description = $node->textContent;
            }
            else if( $node->nodeName == 'target' )
            {
                $targetNegateNode = DH::findFirstElement('negate', $node);
                if( $targetNegateNode !== FALSE )
                {
                    $this->_targetIsNegated = yesNoBool($targetNegateNode->textContent);
                }

                $targetDevicesNodes = DH::findFirstElement('devices', $node);

                if( $targetDevicesNodes !== FALSE )
                {
                    foreach( $targetDevicesNodes->childNodes as $targetDevicesNode )
                    {
                        if( $targetDevicesNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        /**  @var DOMElement $targetDevicesNode */

                        $targetSerial = $targetDevicesNode->getAttribute('name');
                        if( strlen($targetSerial) < 1 )
                        {
                            mwarning('a target with empty serial number was found', $targetDevicesNodes);
                            continue;
                        }

                        $managedFirewall = null;
                        if( $this->owner->owner !== null && get_class( $this->owner->owner ) == "PanoramaConf" )
                            $managedFirewall = $this->owner->owner->managedFirewallsStore->find($targetSerial);
                        elseif( $this->owner->owner->owner !== null && get_class( $this->owner->owner->owner ) == "PanoramaConf" )
                            $managedFirewall = $this->owner->owner->owner->managedFirewallsStore->find($targetSerial);

                        if( $managedFirewall !== null )
                            $managedFirewall->addReference( $this );


                        if( $this->_targets === null )
                            $this->_targets = array();

                        $vsysNodes = DH::firstChildElement($targetDevicesNode);

                        if( $vsysNodes === FALSE )
                        {
                            $this->_targets[$targetSerial] = array();
                            //mwarning($targetSerial, $targetDevicesNode);
                        }
                        else
                        {
                            foreach( $vsysNodes->childNodes as $vsysNode )
                            {
                                if( $vsysNode->nodeType != XML_ELEMENT_NODE )
                                    continue;
                                /**  @var DOMElement $vsysNode */
                                $vsysName = $vsysNode->getAttribute('name');
                                if( strlen($vsysName) < 1 )
                                    continue;

                                $this->_targets[$targetSerial][$vsysName] = $vsysName;
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @return bool TRUE if an update was made
     */
    public function target_setAny()
    {
        if( $this->_targets === null )
            return FALSE;

        $this->_targets = null;

        $node = DH::findFirstElement('target', $this->xmlroot);
        if( $node !== FALSE )
        {
            $deviceNode = DH::findFirstElement('devices', $node);
            if( $deviceNode !== FALSE )
                $node->removeChild($deviceNode);
        }

        return TRUE;
    }

    /**
     * @return bool TRUE if an update was made
     */
    public function API_target_setAny()
    {
        $ret = $this->target_setAny();

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            if( $con->isAPI() )
                $con->sendDeleteRequest($this->getXPath() . '/target/devices');
        }

        return $ret;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function target_addDevice($serialNumber, $vsys = null)
    {
        if( strlen($serialNumber) < 4 )
            derr("unsupported serial number to be added in target: '{$serialNumber}'");

        if( $vsys !== null && strlen($vsys) < 1 )
            derr("unsupported vsys value to be added in target : '{$vsys}'");

        if( $this->_targets === null )
            $this->_targets = array();

        if( !isset($this->_targets[$serialNumber]) )
        {
            $this->_targets[$serialNumber] = array();
            if( $vsys !== null )
                $this->_targets[$serialNumber][$vsys] = $vsys;

            $this->target_rewriteXML();
            return TRUE;
        }

        if( count($this->_targets[$serialNumber]) == 0 )
        {
            if( $vsys === null )
                return FALSE;

            derr("attempt to add a VSYS ({$vsys}) in target of a rule that is mentioning a firewall ({$serialNumber}) that is not multi-vsys");
        }

        if( $vsys === null )
            derr("attempt to add a non multi-vsys firewall ({$serialNumber}) in a target that is multi-vsys");

        $this->_targets[$serialNumber][$vsys] = $vsys;
        $this->target_rewriteXML();

        return TRUE;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function API_target_addDevice($serialNumber, $vsys)
    {
        $ret = $this->target_addDevice($serialNumber, $vsys);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $targetNode = DH::findFirstElementOrDie('target', $this->xmlroot);
            $targetString = DH::dom_to_xml($targetNode);
            $con->sendEditRequest($this->getXPath() . '/target', $targetString);
        }

        return $ret;
    }


    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function target_removeDevice($serialNumber, $vsys = null, $debug = false)
    {
        if( strlen($serialNumber) < 4 )
            derr("unsupported serial number to be added in target: '{$serialNumber}'");

        if( $vsys !== null && strlen($vsys) < 1 )
            derr("unsupported vsys value to be added in target : '{$vsys}'");

        if( $this->_targets === null )
            return FALSE;

        if( !isset($this->_targets[$serialNumber]) )
            return FALSE;

        if( count($this->_targets[$serialNumber]) == 0 )
        {
            if( $vsys === null || $vsys === "ANY" )
            {
                if( $vsys === "ANY" && $debug )
                    PH::print_stdout("DEBUG - Rule: ".$this->name()." remove Target");
                unset($this->_targets[$serialNumber]);
                if( count($this->_targets) == 0 )
                    $this->_targets = null;
                $this->target_rewriteXML();
                return TRUE;
            }

            derr("attempt to remove a VSYS ({$vsys}) in target of a rule that is mentioning a firewall ({$serialNumber}) which is not multi-vsys");
        }

        if( $vsys === null )
            derr("attempt to remove a non multi-vsys firewall ({$serialNumber}) in a target that is multi-vsys");

        if( $vsys === "ANY" )
        {
            if( $debug )
                PH::print_stdout("DEBUG - Rule: ".$this->name()." remove Target");
            unset($this->_targets[$serialNumber]);
        }
        else
        {
            if( !isset($this->_targets[$serialNumber][$vsys]) )
                return FALSE;

            unset($this->_targets[$serialNumber][$vsys]);

            if( count($this->_targets[$serialNumber]) == 0 )
                unset($this->_targets[$serialNumber]);
        }

        $this->target_rewriteXML();

        return TRUE;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function API_target_removeDevice($serialNumber, $vsys)
    {
        $ret = $this->target_removeDevice($serialNumber, $vsys);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $targetNode = DH::findFirstElementOrDie('target', $this->xmlroot);
            $targetString = DH::dom_to_xml($targetNode);
            $con->sendEditRequest($this->getXPath() . '/target', $targetString);
        }

        return $ret;
    }


    public function target_rewriteXML()
    {
        $targetNode = DH::findFirstElementOrCreate('target', $this->xmlroot);

        DH::clearDomNodeChilds($targetNode);
        DH::createElement($targetNode, 'negate', boolYesNo($this->_targetIsNegated));

        if( $this->_targets === null )
            return;

        $devicesNode = DH::createElement($targetNode, 'devices');

        foreach( $this->_targets as $serial => &$vsysList )
        {
            $entryNode = DH::createElement($devicesNode, 'entry');
            $entryNode->setAttribute('name', $serial);
            if( count($vsysList) > 0 )
            {
                $vsysNode = DH::createElement($entryNode, 'vsys');
                foreach( $vsysList as $vsys )
                {
                    $vsysEntryNode = DH::createElement($vsysNode, 'entry');
                    $vsysEntryNode->setAttribute('name', $vsys);
                }
            }
        }
    }

    /**
     * @return bool TRUE if an update was made
     * @var bool $TRUEorFALSE
     */
    public function target_negateSet($TRUEorFALSE)
    {
        if( $this->_targetIsNegated === $TRUEorFALSE )
            return FALSE;

        $this->_targetIsNegated = $TRUEorFALSE;

        $node = DH::findFirstElementOrCreate('target', $this->xmlroot);
        DH::findFirstElementOrCreate('negate', $node, boolYesNo($TRUEorFALSE));

        return TRUE;
    }

    public function target_isNegated()
    {
        return $this->_targetIsNegated;
    }

    /**
     * @return bool TRUE if an update was made
     * @var bool $TRUEorFALSE
     */
    public function API_target_negateSet($TRUEorFALSE)
    {
        $ret = $this->target_negateSet($TRUEorFALSE);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $con->sendSetRequest($this->getXPath() . '/target', '<negate>' . boolYesNo($TRUEorFALSE) . '</negate>');
        }

        return $ret;
    }


    public function targets()
    {
        return $this->_targets;
    }

    public function targets_toString()
    {
        if( !isset($this->_targets) )
            return 'any';

        $str = '';

        foreach( $this->_targets as $device => $vsyslist )
        {
            if( strlen($str) > 0 )
                $str .= ',';

            if( count($vsyslist) == 0 )
                $str .= $device;
            else
            {
                $first = TRUE;
                foreach( $vsyslist as $vsys )
                {
                    if( !$first )
                        $str .= ',';
                    $first = FALSE;
                    $str .= $device . '/' . $vsys;
                }
            }

        }

        return $str;
    }

    function target_Hash()
    {
        $string = $this->targets_toString().boolYesNo($this->target_isNegated());

        return md5( $string );
    }

    public function target_isAny()
    {
        return $this->_targets === null;
    }

    /**
     * @param string $deviceSerial
     * @param string|null $vsys
     * @return bool
     */
    public function target_hasDeviceAndVsys($deviceSerial, $vsys = null)
    {
        if( $this->_targets === null )
            return FALSE;

        if( !isset($this->_targets[$deviceSerial]) )
            return FALSE;

        if( count($this->_targets[$deviceSerial]) == 0 && $vsys === null )
            return TRUE;

        if( $vsys === null )
            return FALSE;

        return isset($this->_targets[$deviceSerial][$vsys]);
    }


    /**
     * For developer use only
     *
     */
    protected function rewriteSDisabled_XML()
    {
        if( $this->disabled )
        {
            $find = DH::findFirstElementOrCreate('disabled', $this->xmlroot);
            DH::setDomNodeText($find, 'yes');
        }
        else
        {
            $find = DH::findFirstElementOrCreate('disabled', $this->xmlroot);
            DH::setDomNodeText($find, 'no');
        }
    }

    /**
     * disable rule if $disabled = true, enable it if not
     * @param bool $disabled
     * @return bool true if value has changed
     */
    public function setDisabled($disabled)
    {
        $old = $this->disabled;
        $this->disabled = $disabled;

        if( $disabled != $old )
        {
            $this->rewriteSDisabled_XML();
            return TRUE;
        }

        return FALSE;
    }

    /**
     * disable rule if $disabled = true, enable it if not
     * @param bool $disabled
     * @return bool true if value has changed
     */
    public function API_setDisabled($disabled)
    {
        $ret = $this->setDisabled($disabled);

        if( $ret )
        {
            $xpath = $this->getXPath() . '/disabled';
            $con = findConnectorOrDie($this);
            if( $this->disabled )
                $con->sendEditRequest($xpath, '<disabled>yes</disabled>');
            else
                $con->sendEditRequest($xpath, '<disabled>no</disabled>');
        }

        return $ret;
    }

    public function setEnabled($enabled)
    {
        if( $enabled )
            return $this->setDisabled(FALSE);
        else
            return $this->setDisabled(TRUE);
    }

    public function API_setEnabled($enabled)
    {
        if( $enabled )
            return $this->API_setDisabled(FALSE);
        else
            return $this->API_setDisabled(TRUE);
    }


    public function &getXPath()
    {
        $str = $this->owner->getXPath($this) . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    /**
     * return true if change was successful false if not (duplicate rulename?)
     * @param string $name new name for the rule
     * @return bool
     */
    public function setName($name)
    {

        if( $this->name == $name )
            return TRUE;

        if( isset($this->owner) && $this->owner !== null )
        {
            if( $this->owner->isRuleNameAvailable($name) )
            {
                $oldname = $this->name;
                $this->name = $name;
                $this->owner->ruleWasRenamed($this, $oldname);
            }
            else
                return FALSE;
        }

        $this->name = $name;

        $this->xmlroot->setAttribute('name', $name);

        return TRUE;

    }

    /**
     * @param string $newname
     */
    public function API_setName($newname)
    {
        $con = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newname);

        $con->sendRenameRequest($xpath, $newname);
    }

    public function API_clearPolicyAppUsageDATA()
    {
        $con = findConnectorOrDie($this);

        if( $con->info_PANOS_version_int >= 90 )
        {
            $cmd = '<clear><policy-app-usage-data><ruleuuid>' . $this->uuid() . '</ruleuuid></policy-app-usage-data></clear>';
            $res = $con->sendOpRequest($cmd, TRUE);
            ///api/?type=op&cmd=<clear><policy-app-usage-data><ruleuuid></ruleuuid></policy-app-usage-data></clear>
        }
        else
        {
            PH::print_stdout( "  PAN-OS version must be 9.0 or higher" );
        }

        return null;
    }

    public function prepareRuleHitCount( $apiType = "show", $all = false, $serial = "", $vsyslist = array())
    {
        $system = $this->owner->owner;

        $ruleType = $this->ruleNature();
        $ruleTypeEND = "";

        $realRuleName = $this->name();

        #print get_class($system)."\n";
        if( $system->isPanorama() )
        {
            $systemInfoStart = "";
            $systemInfoEnd = "";

            $systemName = "";
            $systemNameEnd = "";

            $prepost = "pre";
            if( $this->isPostRule() )
                $prepost = "post";

            $rulebase = "<".$prepost."-rulebase>";
            $rulebaseEnd = "</".$prepost."-rulebase>";

            $rulename = "<rule-name><entry name='";
            $rulenameEnd = "'/></rule-name>";

            return null;
        }
        elseif( $system->isFirewall() )
        {
            return null;
        }
        elseif(  $system->isDeviceGroup() )
        {
            if( $apiType == "show" )
            {
                $systemInfoStart = "<device-group>";
                $systemInfoEnd = "</device-group>";

                $systemName = "<entry name='".$system->name()."'>";
                $systemNameEnd = "</entry>";
            }
            else
            {
                $systemInfoStart = "";
                $systemInfoEnd = "";

                $systemName = "";
                $systemNameEnd = "";
            }

            $prepost = "pre";
            if( $this->isPostRule() )
                $prepost = "post";

            $rulebase = "<".$prepost."-rulebase>";
            $rulebaseEnd = "</".$prepost."-rulebase>";

            #$rulename = "<rule-name><entry name='";
            $rulename = "<rule-name>";
            #$rulenameEnd = "'/></rule-name>";
            if( $apiType == "show")
            {
                $realRuleName = "<entry name='".$realRuleName."'/>";
                $rulenameEnd = "</rule-name>";

                #$ruleTypeStart = "<".$ruleType.">";
                #$ruleTypeEND = "</".$ruleType.">";
                $ruleTypeStart = "<entry name='".$ruleType."'>";
                $ruleTypeEND = "</entry>";
            }

            if( $apiType == "clear")
            {
                $rulebase = "<rulebase>";
                $rulebaseEnd = "</rulebase>";

                $rulename = "<rule-name><entry name='".$realRuleName."'>";
                $realRuleName = "";

                $tmp_string = "<device><entry name='".$serial."'><vsys><list>";
                foreach( $vsyslist as $vsys )
                    $tmp_string .= "<member>".$vsys."</member>";
                if( count($vsyslist) == 0 )
                    $tmp_string .= "<member>vsys1</member>";
                $tmp_string .= "</list></vsys></entry></device></entry>";
                $rulenameEnd = $tmp_string."</rule-name>";

                $ruleTypeStart = "<entry name='".$ruleType."'>";
                $ruleTypeEND = "</entry>";
            }

            //<rule-base><entry ...><rules><entry name="demo2-1"><device-vsys><entry name="child/1234567890/vsys1">


        }
        elseif( $system->isVirtualSystem() )
        {
            $systemInfoStart = "<vsys><vsys-name>";
            $systemInfoEnd = "</vsys-name></vsys>";
            //Firewall
            $systemName = "<entry name='".$system->name()."'>";
            $systemNameEnd = "</entry>";

            $rulebase = "<rule-base>";
            $rulebaseEnd = "</rule-base>";

            $rulename = "<list><member>";
            $rulenameEnd = "</member></list>";

            $ruleTypeStart = "<entry name='".$ruleType."'>";
            $ruleTypeEND = "</entry>";
        }

        //Type

        $cmd = "<".$apiType."><rule-hit-count>".$systemInfoStart.$systemName;

        if( $all )
            $cmd .= $rulebase.$ruleTypeStart."<rules><all/>";
        else
            $cmd .= $rulebase.$ruleTypeStart."<rules>".$rulename.$realRuleName.$rulenameEnd;

        $cmd .= "</rules>".$ruleTypeEND.$rulebaseEnd;
        $cmd .= $systemNameEnd.$systemInfoEnd."</rule-hit-count></".$apiType.">";

        return $cmd;
    }

    public function API_clearRuleHitCount( $all )
    {
        $con = findConnectorOrDie($this);

        if( $con->info_PANOS_version_int >= 90 )
        {
            $system = $this->owner->owner;
            if( get_class($system) === "DeviceGroup" )
            {
                $devices = $system->getDevicesInGroup();
                foreach( $devices as $device )
                {
                    $this->clearRuleHitCount( $all, $con, $device);
                }
            }
            else
            {
                $this->clearRuleHitCount( $all, $con);
            }
        }
        else
        {
            PH::print_stdout( "  PAN-OS version must be 9.0 or higher" );
        }

        return null;
    }

    private function clearRuleHitCount( $all, $con, $device = array() )
    {
        if( empty($device) )
            $cmd = $this->prepareRuleHitCount('clear', $all );
        else
            $cmd = $this->prepareRuleHitCount('clear', $all, $device['serial'], $device['vsyslist']);

        if( $cmd == null )
        {
            PH::print_stdout( "   * not working for Panorama/FW shared" );
            return;
        }

        $res = $con->sendOpRequest($cmd, TRUE);
        $res = DH::findFirstElement( "result", $res);
        $padding = "    * ";
        if( $res->textContent === "Succeeded to reset rule hit count for specified rules" )
            PH::print_stdout( $padding." reset rule hit count successful." );
        else
            PH::print_stdout( $padding.$res->textContent );
    }

    public function API_showRuleHitCount( $all = false, $print = TRUE )
    {
        $con = findConnectorOrDie($this);

        $rule_hitcount_array = array();

        if( $con->info_PANOS_version_int >= 90 )
        {
            $system = $this->owner->owner;
            $cmd = $this->prepareRuleHitCount('show', $all);

            if( $cmd == null )
            {
                PH::print_stdout( "   * not working for Panorama/FW shared" );
                return;
            }


            $res = $con->sendOpRequest($cmd, TRUE);
            $res = DH::findFirstElement( "result", $res);


            $res = DH::findFirstElement( "rule-hit-count", $res);
            if( !$res )
                return null;

            if( $system->isPanorama() )
            {
                DH::DEBUGprintDOMDocument($res);
            }
            elseif( $system->isDeviceGroup() && $system->name() !== ""  )
            {
                #DH::DEBUGprintDOMDocument($res);
                $res = DH::findFirstElement( "device-group", $res);
            }

            elseif( $system->isVirtualSystem() )
                $res = DH::findFirstElement( "vsys", $res);

            if( $system->isDeviceGroup() && $system->name() === ""  )
            {
                #$res = DH::findFirstElement( "entry", $res);
                $res = $res;
            }
            else
                $res = DH::findFirstElement( "entry", $res);

            $res = DH::findFirstElement( "rule-base", $res);
            $res = DH::findFirstElement( "entry", $res);
            $res = DH::findFirstElement( "rules", $res);
            $res = DH::findFirstElement( "entry", $res);


            if( $system->isDeviceGroup()  )
            {
                DH::DEBUGprintDOMDocument($res);
                //<rule-base><entry ...><rules><entry name="demo2-1"><device-vsys><entry name="child/1234567890/vsys1">
                $res = DH::findFirstElement( "device-vsys", $res);
                $res = DH::findFirstElement( "entry", $res);
            }

            if( $res !== FALSE )
            {
                $latest = DH::findFirstElement( "latest", $res);
                $hit_count = DH::findFirstElement( "hit-count", $res);
                $last_hit_timestamp = DH::findFirstElement( "last-hit-timestamp", $res);
                $last_reset_timestamp = DH::findFirstElement( "last-reset-timestamp", $res);

                $first_hit_timestamp = DH::findFirstElement( "first-hit-timestamp", $res);
                $rule_creation_timestamp = DH::findFirstElement( "rule-creation-timestamp", $res);
                $rule_modification_timestamp = DH::findFirstElement( "rule-modification-timestamp", $res);

                //create Array and return
                $padding = "    * ";
                if( $latest )
                {
                    if( $print )
                        PH::print_stdout( $padding."latest: ".$latest->textContent );
                    $rule_hitcount_array['latest'] = $latest->textContent;
                }

                if( $hit_count)
                {
                    if( $print )
                        PH::print_stdout( $padding."hit-count: ".$hit_count->textContent );
                    $rule_hitcount_array['hit-count'] = $hit_count->textContent;
                }

                if( $last_hit_timestamp )
                {
                    $unixTimestamp = $last_hit_timestamp->textContent;
                    if( $unixTimestamp === "0" || $unixTimestamp === "" )
                        $result = "0";
                    else
                        $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                    if( $print )
                        PH::print_stdout( $padding."last-hit: ".$result );
                    $rule_hitcount_array['last-hit'] = $result;
                }

                if( $last_reset_timestamp )
                {
                    $unixTimestamp = $last_reset_timestamp->textContent;
                    if( $unixTimestamp === "0" || $unixTimestamp === "" )
                        $result = "0";
                    else
                        $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                    if( $print )
                        PH::print_stdout( $padding."last-reset: ".$result );
                    $rule_hitcount_array['last-reset'] = $result;
                }

                if( $first_hit_timestamp )
                {
                    $unixTimestamp = $first_hit_timestamp->textContent;
                    if( $unixTimestamp === "0" || $unixTimestamp === "" )
                        $result = "0";
                    else
                        $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                    if( $print )
                        PH::print_stdout( $padding."first-hit: ".$result );
                    $rule_hitcount_array['first-hit'] = $result;
                }

                if( $rule_creation_timestamp )
                {
                    $unixTimestamp = $rule_creation_timestamp->textContent;
                    if( $unixTimestamp === "" )
                        $result = 0;
                    else
                        $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                    if( $print )
                        PH::print_stdout( $padding."rule-creation: ".$result );
                    $rule_hitcount_array['rule-creation'] = $result;
                }
                if( $rule_modification_timestamp )
                {
                    $unixTimestamp = $rule_modification_timestamp->textContent;
                    if( $unixTimestamp === "" )
                        $result = 0;
                    else
                        $result = date( 'Y-m-d H:i:s', $unixTimestamp );
                    if( $print )
                        PH::print_stdout( $padding."rule-modification: ".$result );
                    $rule_hitcount_array['rule-modification'] = $result;
                }
            }

        }
        else
        {
            if( $print )
                PH::print_stdout( "  PAN-OS version must be 9.0 or higher" );
        }

        return $rule_hitcount_array;
    }

    public function API_apps_seen()
    {
        $rule_array = array();

        $rule_uuid = $this->uuid();
        $cmd = "<show><policy-app-details><rules><member>".$rule_uuid."</member></rules>
<resultfields><member>apps-seen</member><member>last-app-seen-since-count</member><member>days-no-new-app-count</member></resultfields><trafficTimeframe>30</trafficTimeframe><appsSeenTimeframe>any</appsSeenTimeframe><vsysName>vsys1</vsysName><type>security</type><position>main</position><summary>no</summary></policy-app-details></show>";

        $connector = findConnectorOrDie($this);
        $res = $connector->sendOpRequest($cmd);
        $res = DH::findFirstElement( "result", $res);
        $res = DH::findFirstElement( "rules", $res);
        $rule = DH::findFirstElementByNameAttr( "entry", $this->name(), $res );

        if( $rule !== null && $rule !== false )
        {
            $apps_seen = DH::findFirstElement( "apps-seen", $rule);
            $app_array = array();
            foreach( $apps_seen->childNodes as $app )
            {
                /** @var DOMElement $app */
                if( $app->nodeType != XML_ELEMENT_NODE )
                    continue;

                $application = DH::findFirstElement( "application", $app);
                $bytes = DH::findFirstElement( "bytes", $app);
                $first_seen = DH::findFirstElement( "first-seen", $app);
                $last_seen = DH::findFirstElement( "last-seen", $app);

                $app_array[$application->textContent] = array(
                    "name" => $application->textContent,
                    "bytes" => $bytes->textContent,
                    "first_seen" => $first_seen->textContent,
                    "last_seen" => $last_seen->textContent,
                );
                #print "APP: ".$application->textContent."\n";
                #DH::DEBUGprintDOMDocument( $app );
            }

            #print_r($app_array);
            $apps = array_keys($app_array);

            $apps_allowed_count = DH::findFirstElement( "apps-allowed-count", $rule);
            $days_no_new_app_count = DH::findFirstElement( "days-no-new-app-count", $rule);
            $last_app_seen_since_count = DH::findFirstElement( "last-app-seen-since-count", $rule);

            $rule_array = array( "apps-seen-count" =>  count($app_array),
                "apps-seen" => $app_array,
                "apps-allowed-count" => $apps_allowed_count->textContent,
                "days-no-new-app-count" => $days_no_new_app_count->textContent,
                "last-app-seen-since-count" => $last_app_seen_since_count->textContent,
            );
        }

        return $rule_array;
    }

    function zoneCalculation($fromOrTo, $mode = "append", $virtualRouter = "*autodetermine*", $template_name = "*notPanorama*", $vsys_name = "*notPanorama*", $isAPI = FALSE )
    {
        //DEFAULT settings:
        $mode_default = "append";
        $virtualRouter_default = "*autodetermine*";
        $template_default = "*notPanorama*";
        $vsys_default = "*notPanorama*";


        $padding = '     ';
        $cachedIPmapping = array();


        ////////////////////////
        /// plain starting calculation

        $addrContainerIsNegated = FALSE;

        $zoneContainer = null;
        $addressContainer = null;

        if( $fromOrTo == 'from' )
        {
            $zoneContainer = $this->from;
            $addressContainer = $this->source;
            if( $this->isSecurityRule() && $this->sourceIsNegated() )
                $addrContainerIsNegated = TRUE;
        }
        elseif( $fromOrTo == 'to' )
        {
            $zoneContainer = $this->to;
            $addressContainer = $this->destination;
            if( $this->isSecurityRule() && $this->destinationIsNegated() )
                $addrContainerIsNegated = TRUE;
        }
        else
            derr('unsupported');

        //Workaround
        $zoneContainer->findParentCentralStore('zoneStore');
        $zoneStore = $zoneContainer->parentCentralStore;


        $system = $this->owner->owner;

        $RouterStore = "virtualRouterStore";
        if( get_class($system) == "VirtualSystem" && isset($system->owner) && get_class($system->owner) == "PANConf" )
        {
            if( $system->owner->_advance_routing_enabled )
                $RouterStore = "logicalRouterStore";
        }

        /** @var VirtualRouter $virtualRouterToProcess */
        $virtualRouterToProcess = null;

        if( !isset($cachedIPmapping) )
            $cachedIPmapping = array();

        $serial = spl_object_hash($this->owner);
        $configIsOnLocalFirewall = FALSE;

        if( !isset($cachedIPmapping[$serial]) )
        {
            if( $system->isDeviceGroup() || $system->isPanorama() )
            {
                $firewall = null;
                $panorama = $system;
                if( $system->isDeviceGroup() )
                    $panorama = $system->owner;

                if( $template_name == $template_default )
                    derr('with Panorama configs, you need to specify a template name');

                if( $virtualRouter == $virtualRouter_default )
                    derr('with Panorama configs, you need to specify virtualRouter argument. Available virtual routes are: ');

                $_tmp_explTemplateName = explode('@', $template_name);
                if( count($_tmp_explTemplateName) > 1 )
                {
                    $firewall = new PANConf();
                    $configIsOnLocalFirewall = TRUE;
                    $doc = null;

                    if( strtolower($_tmp_explTemplateName[0]) == 'api' )
                    {
                        $panoramaConnector = findConnector($system);
                        $connector = new PanAPIConnector($panoramaConnector->apihost, $panoramaConnector->apikey, 'panos-via-panorama', $_tmp_explTemplateName[1]);
                        $connector->setShowApiCalls( $panoramaConnector->showApiCalls );

                        $firewall->connector = $connector;
                        $doc = $connector->getMergedConfig();
                        $firewall->load_from_domxml($doc);

                        //This is to get full routing table incl. dynamic routing for zone-calculation
                        $cmd = "<show><routing><route><virtual-router>".$virtualRouter."</virtual-router></route></routing></show>";
                        $res = $connector->sendOpRequest($cmd, TRUE);

                        $res = DH::findFirstElement( "result", $res);
                        $entries = $res->getElementsByTagName('entry');

                        /** @var VirtualRouter $vr */
                        $tmp_vr = $firewall->network->$RouterStore->findVirtualRouter( $virtualRouter );

                        foreach( $entries as $key => $child )
                        {
                            $destination = DH::findFirstElement( "destination", $child)->textContent;
                            $nexthop = DH::findFirstElement( "nexthop", $child)->textContent;
                            $metric = DH::findFirstElement( "metric", $child)->textContent;
                            $interface = DH::findFirstElement( "interface", $child)->textContent;
                            $routeTable = DH::findFirstElement( "route-table", $child)->textContent;
                            $flags = DH::findFirstElement( "flags", $child)->textContent;

                            //skip e.g. multicast
                            if( $routeTable != "unicast" )
                                continue;

                            //skip Host route - nexthop == 0.0.0.0 / no interface
                            if( strpos( $flags, "H" ) !== FALSE )
                                continue;

                            $routename = "RouteAPI_" . $key;

                            $newRoute = new StaticRoute('***tmp**', $tmp_vr);
                            $tmpRoute = $newRoute->create_staticroute_from_variables( $routename, $destination, $nexthop, $metric, $interface );

                            $tmp_vr->addstaticRoute($tmpRoute);
                        }

                        unset($connector);
                    }
                    elseif( strtolower($_tmp_explTemplateName[0]) == 'file' )
                    {
                        $filename = $_tmp_explTemplateName[1];
                        if( !file_exists($filename) )
                            derr("cannot read firewall configuration file '{$filename}''");
                        $doc = new DOMDocument();
                        if( !$doc->load($filename, XML_PARSE_BIG_LINES) )
                            derr("invalive xml file" . libxml_get_last_error()->message);
                        unset($filename);
                    }
                    else
                        derr("unsupported method: {$_tmp_explTemplateName[0]}@");


                    // delete rules to avoid loading all the config
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/devices/entry/vsys/entry/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/shared/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");

                    //PH::print_stdout( "\n\n deleted $deletedNodesCount nodes " );

                    $firewall->load_from_domxml($doc);

                    unset($deletedNodesCount);
                    unset($doc);
                }


                /** @var Template $template */
                if( !$configIsOnLocalFirewall )
                {
                    $template = $panorama->findTemplate($template_name);
                    if( $template === null )
                        derr("cannot find Template named '{$template_name}'. Available template list:" . PH::list_to_string($panorama->templates));
                }

                if( $configIsOnLocalFirewall )
                    $virtualRouterToProcess = $firewall->network->$RouterStore->findVirtualRouter($virtualRouter);
                else
                    $virtualRouterToProcess = $template->deviceConfiguration->network->$RouterStore->findVirtualRouter($virtualRouter);

                if( $virtualRouterToProcess === null )
                {
                    if( $configIsOnLocalFirewall )
                        $tmpVar = $firewall->network->$RouterStore->virtualRouters();
                    else
                        $tmpVar = $template->deviceConfiguration->network->$RouterStore->virtualRouters();

                    derr("cannot find VirtualRouter named '{$virtualRouter}' in Template '{$template_name}'. Available VR list: " . PH::list_to_string($tmpVar));
                }

                if( (!$configIsOnLocalFirewall && count($template->deviceConfiguration->virtualSystems) == 1) || ($configIsOnLocalFirewall && count($firewall->virtualSystems) == 1) )
                {
                    if( $configIsOnLocalFirewall )
                        $system = $firewall->virtualSystems[0];
                    else
                        $system = $template->deviceConfiguration->virtualSystems[0];
                }
                else
                {
                    $vsysConcernedByVR = $virtualRouterToProcess->findConcernedVsys();
                    if( count($vsysConcernedByVR) == 1 )
                    {
                        $system = array_pop($vsysConcernedByVR);
                    }
                    elseif( $vsys_name == '*autodetermine*' )
                    {
                        derr("cannot autodetermine resolution context from Template '{$template}' VR '{$virtualRouter}'' , multiple VSYS are available: " . PH::list_to_string($vsysConcernedByVR) . ". Please provide choose a VSYS.");
                    }
                    else
                    {
                        if( $configIsOnLocalFirewall )
                            $vsys = $firewall->findVirtualSystem($vsys_name);
                        else
                            $vsys = $template->deviceConfiguration->findVirtualSystem($vsys_name);
                        if( $vsys === null )
                            derr("cannot find VSYS '{$vsys_name}' in Template '{$template_name}'");
                        $system = $vsys;
                    }
                }

                //derr(DH::dom_to_xml($template->deviceConfiguration->xmlroot));
                //$tmpVar = $system->importedInterfaces->interfaces();
                //derr(count($tmpVar)." ".PH::list_to_string($tmpVar));
            }
            else if( $virtualRouter != '*autodetermine*' )
            {
                $virtualRouterToProcess = $system->owner->network->$RouterStore->findVirtualRouter($virtualRouter);
                if( $virtualRouterToProcess === null )
                    derr("VirtualRouter named '{$virtualRouter}' not found");
            }
            else
            {
                $vRouters = $system->owner->network->$RouterStore->virtualRouters();
                $foundRouters = array();

                foreach( $vRouters as $router )
                {
                    foreach( $router->attachedInterfaces->interfaces() as $if )
                    {
                        if( $system->importedInterfaces->hasInterfaceNamed($if->name()) )
                        {
                            $foundRouters[] = $router;
                            break;
                        }
                    }
                }

                PH::print_stdout( $padding . " - VSYS/DG '{$system->name()}' has interfaces attached to " . count($foundRouters) . " virtual routers" );
                if( count($foundRouters) > 1 )
                    derr("more than 1 suitable virtual routers found, please specify one of the following: " . PH::list_to_string($foundRouters));
                if( count($foundRouters) == 0 )
                    derr("no suitable VirtualRouter found, please force one or check your configuration");

                $virtualRouterToProcess = $foundRouters[0];
            }
            $cachedIPmapping[$serial] = $virtualRouterToProcess->getIPtoZoneRouteMapping($system);
        }


        $ipMapping = &$cachedIPmapping[$serial];

        if( $addressContainer->isAny() && $this->isSecurityRule() )
        {
            PH::print_stdout( $padding . " - SKIPPED : address container is ANY()" );
            return;
        }

        if( $this->isSecurityRule() )
            $resolvedZones = &$addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4'], $addrContainerIsNegated);
        else
            $resolvedZones = &$addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4']);

        if( count($resolvedZones) == 0 )
        {
            PH::print_stdout( $padding . " - WARNING : no zone resolved (FQDN? IPv6?)" );
            return;
        }


        $plus = array();
        foreach( $zoneContainer->zones() as $zone )
            $plus[$zone->name()] = $zone->name();

        $minus = array();
        $common = array();

        foreach( $resolvedZones as $zoneName => $zone )
        {
            if( isset($plus[$zoneName]) )
            {
                unset($plus[$zoneName]);
                $common[] = $zoneName;
                continue;
            }
            $minus[] = $zoneName;
        }

        if( count($common) > 0 )
            PH::print_stdout( $padding . " - untouched zones: " . PH::list_to_string($common) . "" );
        if( count($minus) > 0 )
            PH::print_stdout( $padding . " - missing zones: " . PH::list_to_string($minus) . "" );
        if( count($plus) > 0 )
            PH::print_stdout( $padding . " - unneeded zones: " . PH::list_to_string($plus) . "" );

        if( $mode == 'replace' )
        {
            PH::print_stdout( $padding . " - REPLACE MODE, syncing with (" . count($resolvedZones) . ") resolved zones.");
            if( $addressContainer->isAny() )
                PH::print_stdout( $padding . " *** IGNORED because value is 'ANY' ***" );
            elseif( count($resolvedZones) == 0 )
                PH::print_stdout( $padding . " *** IGNORED because no zone was resolved ***" );
            elseif( count($minus) == 0 && count($plus) == 0 )
            {
                PH::print_stdout( $padding . " *** IGNORED because there is no diff ***" );
            }
            else
            {
                PH::print_stdout();

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    if( count($common) > 0 )
                    {
                        foreach( $minus as $zoneToAdd )
                        {
                            $newRuleName = $this->owner->findAvailableName($this->name());
                            $newRule = $this->owner->cloneRule($this, $newRuleName);
                            $newRule->to->setAny();
                            $newRule->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                            PH::print_stdout( $padding . " - cloned NAT rule with name '{$newRuleName}' and TO zone='{$zoneToAdd}'" );
                            if( $isAPI )
                            {
                                $newRule->API_sync();
                                $newRule->owner->API_moveRuleAfter($newRule, $this);
                            }
                            else
                                $newRule->owner->moveRuleAfter($newRule, $this);
                        }
                        return;
                    }

                    $first = TRUE;
                    foreach( $minus as $zoneToAdd )
                    {
                        if( $first )
                        {
                            $this->to->setAny();
                            $this->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                            PH::print_stdout( $padding . " - changed original NAT 'TO' zone='{$zoneToAdd}'" );
                            if( $isAPI )
                                $this->to->API_sync();
                            $first = FALSE;
                            continue;
                        }
                        $newRuleName = $this->owner->findAvailableName($this->name());
                        $newRule = $this->owner->cloneRule($this, $newRuleName);
                        $newRule->to->setAny();
                        $newRule->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                        PH::print_stdout( $padding . " - cloned NAT rule with name '{$newRuleName}' and TO zone='{$zoneToAdd}'" );
                        if( $isAPI )
                        {
                            $newRule->API_sync();
                            $newRule->owner->API_moveRuleAfter($newRule, $this);
                        }
                        else
                            $newRule->owner->moveRuleAfter($newRule, $this);
                    }

                    return;
                }

                $zoneContainer->setAny();
                foreach( $resolvedZones as $zone )
                    $zoneContainer->addZone($zoneStore->findOrCreate($zone));
                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
        elseif( $mode == 'append' )
        {
            PH::print_stdout( $padding . " - APPEND MODE: adding missing (" . count($minus) . ") zones only.");

            if( $addressContainer->isAny() )
            {
                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    foreach( $zoneStore->getAll() as $zone )
                        $allZones[] = $zone->name();

                    //swaschkut 20220316 - for migration parser
                    $this->setDisabled( TRUE );
                    //self::zoneCalculationNatClone( $allZones, $zoneStore, $padding, $isAPI );
                }
                else
                    PH::print_stdout( " *** IGNORED because value is 'ANY' ***" );
            }
            elseif( count($minus) == 0 )
                PH::print_stdout( " *** IGNORED because no missing zones were found ***" );
            else
            {
                PH::print_stdout();

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    self::zoneCalculationNatClone( $minus, $zoneStore, $padding, $isAPI );

                    return;
                }

                foreach( $minus as $zone )
                {
                    $zoneContainer->addZone($zoneStore->findOrCreate($zone));
                }

                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
        elseif( $mode == 'unneeded-tag-add' )
        {
            PH::print_stdout( $padding . " - UNNEEDED-TAG-ADD MODE: adding rule tag for unneeded zones.");

            if( $addressContainer->isAny() )
                PH::print_stdout( " *** IGNORED because value is 'ANY' ***" );
            elseif( count($plus) == 0 )
                PH::print_stdout( " *** IGNORED because no unneeded zones were found ***" );
            else
            {
                PH::print_stdout();

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    derr($padding . ' NAT rules are not supported yet');
                }

                if( $fromOrTo == 'from' )
                    $tag_add = 'unneeded-from-zone';
                elseif( $fromOrTo == 'to' )
                    $tag_add = 'unneeded-to-zone';

                $objectFind = $this->tags->parentCentralStore->findOrCreate($tag_add);
                $this->tags->addTag($objectFind);

                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
    }

    function addressCalculationByZones($srcOrDst, $mode = "append", $virtualRouter = "*autodetermine*", $template_name = "*notPanorama*", $vsys_name = "*notPanorama*", $isAPI = FALSE )
    {
        //DEFAULT settings:
        $mode_default = "append";
        $virtualRouter_default = "*autodetermine*";
        $template_default = "*notPanorama*";
        $vsys_default = "*notPanorama*";


        $padding = '     ';
        $cachedIPmapping = array();


        ////////////////////////
        /// plain starting calculation

        $addrContainerIsNegated = FALSE;

        $zoneContainer = null;
        $addressContainer = null;

        if( $srcOrDst == 'src' )
        {
            $zoneContainer = $this->from;
            $addressContainer = $this->source;
            if( $this->isSecurityRule() && $this->sourceIsNegated() )
                $addrContainerIsNegated = TRUE;
        }
        elseif( $srcOrDst == 'dst' )
        {
            $zoneContainer = $this->to;
            $addressContainer = $this->destination;
            if( $this->isSecurityRule() && $this->destinationIsNegated() )
                $addrContainerIsNegated = TRUE;
        }
        else
            derr('unsupported');

        //Workaround
        $zoneContainer->findParentCentralStore('zoneStore');
        $zoneStore = $zoneContainer->parentCentralStore;


        $system = $this->owner->owner;

        $RouterStore = "virtualRouterStore";
        if( get_class($system) == "VirtualSystem" && isset($system->owner) && get_class($system->owner) == "PANConf" )
        {
            if( $system->owner->_advance_routing_enabled )
                $RouterStore = "logicalRouterStore";
        }
        if( $RouterStore == "logicalRouterStore" )
            derr( "Locigal Router not yet suported", null, FALSE );

        /** @var VirtualRouter $virtualRouterToProcess */
        $virtualRouterToProcess = null;

        if( !isset($cachedIPmapping) )
            $cachedIPmapping = array();

        $serial = spl_object_hash($this->owner);
        $configIsOnLocalFirewall = FALSE;

        if( !isset($cachedIPmapping[$serial]) )
        {
            if( $system->isDeviceGroup() || $system->isPanorama() )
            {
                $firewall = null;
                $panorama = $system;
                if( $system->isDeviceGroup() )
                    $panorama = $system->owner;

                if( $template_name == $template_default )
                    derr('with Panorama configs, you need to specify a template name');

                if( $virtualRouter == $virtualRouter_default )
                    derr('with Panorama configs, you need to specify virtualRouter argument. Available virtual routes are: ');

                $_tmp_explTemplateName = explode('@', $template_name);
                if( count($_tmp_explTemplateName) > 1 )
                {
                    $firewall = new PANConf();
                    $configIsOnLocalFirewall = TRUE;
                    $doc = null;

                    if( strtolower($_tmp_explTemplateName[0]) == 'api' )
                    {
                        $panoramaConnector = findConnector($system);
                        $connector = new PanAPIConnector($panoramaConnector->apihost, $panoramaConnector->apikey, 'panos-via-panorama', $_tmp_explTemplateName[1]);
                        $connector->setShowApiCalls( $panoramaConnector->showApiCalls );

                        $firewall->connector = $connector;
                        $doc = $connector->getMergedConfig();
                        $firewall->load_from_domxml($doc);

                        //Todo 20241109 swaschkut extend with logical-router part
                        //This is to get full routing table incl. dynamic routing for zone-calculation
                        $cmd = "<show><routing><route><virtual-router>".$virtualRouter."</virtual-router></route></routing></show>";
                        $res = $connector->sendOpRequest($cmd, TRUE);

                        $res = DH::findFirstElement( "result", $res);
                        $entries = $res->getElementsByTagName('entry');

                        /** @var VirtualRouter $vr */
                        $tmp_vr = $firewall->network->virtualRouterStore->findVirtualRouter( $virtualRouter );

                        foreach( $entries as $key => $child )
                        {
                            $destination = DH::findFirstElement( "destination", $child)->textContent;
                            $nexthop = DH::findFirstElement( "nexthop", $child)->textContent;
                            $metric = DH::findFirstElement( "metric", $child)->textContent;
                            $interface = DH::findFirstElement( "interface", $child)->textContent;
                            $routeTable = DH::findFirstElement( "route-table", $child)->textContent;
                            $flags = DH::findFirstElement( "flags", $child)->textContent;

                            //skip e.g. multicast
                            if( $routeTable != "unicast" )
                                continue;

                            //skip Host route - nexthop == 0.0.0.0 / no interface
                            if( strpos( $flags, "H" ) !== FALSE )
                                continue;

                            $routename = "RouteAPI_" . $key;

                            $newRoute = new StaticRoute('***tmp**', $tmp_vr);
                            $tmpRoute = $newRoute->create_staticroute_from_variables( $routename, $destination, $nexthop, $metric, $interface );

                            $tmp_vr->addstaticRoute($tmpRoute);
                        }

                        unset($connector);
                    }
                    elseif( strtolower($_tmp_explTemplateName[0]) == 'file' )
                    {
                        $filename = $_tmp_explTemplateName[1];
                        if( !file_exists($filename) )
                            derr("cannot read firewall configuration file '{$filename}''");
                        $doc = new DOMDocument();
                        if( !$doc->load($filename, XML_PARSE_BIG_LINES) )
                            derr("invalive xml file" . libxml_get_last_error()->message);
                        unset($filename);
                    }
                    else
                        derr("unsupported method: {$_tmp_explTemplateName[0]}@");


                    // delete rules to avoid loading all the config
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/devices/entry/vsys/entry/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");
                    $deletedNodesCount = DH::removeChildrenElementsMatchingXPath("/config/shared/rulebase/*", $doc);
                    if( $deletedNodesCount === FALSE )
                        derr("xpath issue");

                    //PH::print_stdout( "\n\n deleted $deletedNodesCount nodes " );

                    $firewall->load_from_domxml($doc);

                    unset($deletedNodesCount);
                    unset($doc);
                }


                /** @var Template $template */
                if( !$configIsOnLocalFirewall )
                {
                    $template = $panorama->findTemplate($template_name);
                    if( $template === null )
                        derr("cannot find Template named '{$template_name}'. Available template list:" . PH::list_to_string($panorama->templates));
                }

                if( $configIsOnLocalFirewall )
                    $virtualRouterToProcess = $firewall->network->virtualRouterStore->findVirtualRouter($virtualRouter);
                else
                    $virtualRouterToProcess = $template->deviceConfiguration->network->virtualRouterStore->findVirtualRouter($virtualRouter);

                if( $virtualRouterToProcess === null )
                {
                    if( $configIsOnLocalFirewall )
                        $tmpVar = $firewall->network->virtualRouterStore->virtualRouters();
                    else
                        $tmpVar = $template->deviceConfiguration->network->virtualRouterStore->virtualRouters();

                    derr("cannot find VirtualRouter named '{$virtualRouter}' in Template '{$template_name}'. Available VR list: " . PH::list_to_string($tmpVar));
                }

                if( (!$configIsOnLocalFirewall && count($template->deviceConfiguration->virtualSystems) == 1) || ($configIsOnLocalFirewall && count($firewall->virtualSystems) == 1) )
                {
                    if( $configIsOnLocalFirewall )
                        $system = $firewall->virtualSystems[0];
                    else
                        $system = $template->deviceConfiguration->virtualSystems[0];
                }
                else
                {
                    $vsysConcernedByVR = $virtualRouterToProcess->findConcernedVsys();
                    if( count($vsysConcernedByVR) == 1 )
                    {
                        $system = array_pop($vsysConcernedByVR);
                    }
                    elseif( $vsys_name == '*autodetermine*' )
                    {
                        derr("cannot autodetermine resolution context from Template '{$template}' VR '{$virtualRouter}'' , multiple VSYS are available: " . PH::list_to_string($vsysConcernedByVR) . ". Please provide choose a VSYS.");
                    }
                    else
                    {
                        if( $configIsOnLocalFirewall )
                            $vsys = $firewall->findVirtualSystem($vsys_name);
                        else
                            $vsys = $template->deviceConfiguration->findVirtualSystem($vsys_name);
                        if( $vsys === null )
                            derr("cannot find VSYS '{$vsys_name}' in Template '{$template_name}'");
                        $system = $vsys;
                    }
                }

                //derr(DH::dom_to_xml($template->deviceConfiguration->xmlroot));
                //$tmpVar = $system->importedInterfaces->interfaces();
                //derr(count($tmpVar)." ".PH::list_to_string($tmpVar));
            }
            else if( $virtualRouter != '*autodetermine*' )
            {
                $virtualRouterToProcess = $system->owner->network->virtualRouterStore->findVirtualRouter($virtualRouter);
                if( $virtualRouterToProcess === null )
                    derr("VirtualRouter named '{$virtualRouter}' not found");
            }
            else
            {
                $vRouters = $system->owner->network->virtualRouterStore->virtualRouters();
                $foundRouters = array();

                foreach( $vRouters as $router )
                {
                    foreach( $router->attachedInterfaces->interfaces() as $if )
                    {
                        if( $system->importedInterfaces->hasInterfaceNamed($if->name()) )
                        {
                            $foundRouters[] = $router;
                            break;
                        }
                    }
                }

                PH::print_stdout( $padding . " - VSYS/DG '{$system->name()}' has interfaces attached to " . count($foundRouters) . " virtual routers" );
                if( count($foundRouters) > 1 )
                    derr("more than 1 suitable virtual routers found, please specify one of the following: " . PH::list_to_string($foundRouters));
                if( count($foundRouters) == 0 )
                    derr("no suitable VirtualRouter found, please force one or check your configuration");

                $virtualRouterToProcess = $foundRouters[0];
            }
            $cachedIPmapping[$serial] = $virtualRouterToProcess->getIPtoZoneRouteMapping($system);
        }


        $ipMapping = &$cachedIPmapping[$serial];

        if( $zoneContainer->isAny() )
        {
            PH::print_stdout( $padding . " - SKIPPED : zone container is ANY()" );
            return;
        }

        if( $addressContainer->isAny() && $this->isSecurityRule() )
        {
            PH::print_stdout( $padding . " - CONTINUE : address container is ANY()" );
            #return;
        }
        else
        {
            PH::print_stdout( $padding . " - SKIPPED : address container is NOT ANY()" );
            return;
        }


        foreach( $zoneContainer->zones() as $zone )
        {
            print "zone: ".$zone->name()."\n";
            foreach( $ipMapping['ipv4'] as $ipMap )
            {
                #print_r($ipMap);
                if( isset($ipMap['zone']) )
                {
                    #print "validate zone: ".$ipMap['zone']."\n";
                    if( $zone->name() == $ipMap['zone'] )
                    {
                        $tmp_adddress = $this->owner->owner->addressStore->findOrCreate($ipMap['network']);
                        $addressContainer->addObject( $tmp_adddress );
                    }
                }
            }
        }

        return;

        //Todo: calculate address from zon
        if( $this->isSecurityRule() )
        {
            $resolvedZones = &$addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4'], $addrContainerIsNegated);
            #print_r($ipMapping);
        }
        else
        {
            $resolvedZones = &$addressContainer->calculateZonesFromIP4Mapping($ipMapping['ipv4']);
        }


        if( count($resolvedZones) == 0 )
        {
            PH::print_stdout( $padding . " - WARNING : no zone resolved (FQDN? IPv6?)" );
            return;
        }


        $plus = array();
        foreach( $zoneContainer->zones() as $zone )
            $plus[$zone->name()] = $zone->name();

        $minus = array();
        $common = array();

        foreach( $resolvedZones as $zoneName => $zone )
        {
            if( isset($plus[$zoneName]) )
            {
                unset($plus[$zoneName]);
                $common[] = $zoneName;
                continue;
            }
            $minus[] = $zoneName;
        }

        if( count($common) > 0 )
            PH::print_stdout( $padding . " - untouched zones: " . PH::list_to_string($common) . "" );
        if( count($minus) > 0 )
            PH::print_stdout( $padding . " - missing zones: " . PH::list_to_string($minus) . "" );
        if( count($plus) > 0 )
            PH::print_stdout( $padding . " - unneeded zones: " . PH::list_to_string($plus) . "" );

        if( $mode == 'replace' )
        {
            PH::print_stdout( $padding . " - REPLACE MODE, syncing with (" . count($resolvedZones) . ") resolved zones.");
            if( $addressContainer->isAny() )
                PH::print_stdout( $padding . " *** IGNORED because value is 'ANY' ***" );
            elseif( count($resolvedZones) == 0 )
                PH::print_stdout( $padding . " *** IGNORED because no zone was resolved ***" );
            elseif( count($minus) == 0 && count($plus) == 0 )
            {
                PH::print_stdout( $padding . " *** IGNORED because there is no diff ***" );
            }
            else
            {
                PH::print_stdout();

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    if( count($common) > 0 )
                    {
                        foreach( $minus as $zoneToAdd )
                        {
                            $newRuleName = $this->owner->findAvailableName($this->name());
                            $newRule = $this->owner->cloneRule($this, $newRuleName);
                            $newRule->to->setAny();
                            $newRule->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                            PH::print_stdout( $padding . " - cloned NAT rule with name '{$newRuleName}' and TO zone='{$zoneToAdd}'" );
                            if( $isAPI )
                            {
                                $newRule->API_sync();
                                $newRule->owner->API_moveRuleAfter($newRule, $this);
                            }
                            else
                                $newRule->owner->moveRuleAfter($newRule, $this);
                        }
                        return;
                    }

                    $first = TRUE;
                    foreach( $minus as $zoneToAdd )
                    {
                        if( $first )
                        {
                            $this->to->setAny();
                            $this->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                            PH::print_stdout( $padding . " - changed original NAT 'TO' zone='{$zoneToAdd}'" );
                            if( $isAPI )
                                $this->to->API_sync();
                            $first = FALSE;
                            continue;
                        }
                        $newRuleName = $this->owner->findAvailableName($this->name());
                        $newRule = $this->owner->cloneRule($this, $newRuleName);
                        $newRule->to->setAny();
                        $newRule->to->addZone($zoneStore->findOrCreate($zoneToAdd));
                        PH::print_stdout( $padding . " - cloned NAT rule with name '{$newRuleName}' and TO zone='{$zoneToAdd}'" );
                        if( $isAPI )
                        {
                            $newRule->API_sync();
                            $newRule->owner->API_moveRuleAfter($newRule, $this);
                        }
                        else
                            $newRule->owner->moveRuleAfter($newRule, $this);
                    }

                    return;
                }

                $zoneContainer->setAny();
                foreach( $resolvedZones as $zone )
                    $zoneContainer->addZone($zoneStore->findOrCreate($zone));
                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
        elseif( $mode == 'append' )
        {
            PH::print_stdout( $padding . " - APPEND MODE: adding missing (" . count($minus) . ") zones only.");

            if( $addressContainer->isAny() )
            {
                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    foreach( $zoneStore->getAll() as $zone )
                        $allZones[] = $zone->name();

                    //swaschkut 20220316 - for migration parser
                    $this->setDisabled( TRUE );
                    //self::zoneCalculationNatClone( $allZones, $zoneStore, $padding, $isAPI );
                }
                else
                    PH::print_stdout( " *** IGNORED because value is 'ANY' ***" );
            }
            elseif( count($minus) == 0 )
                PH::print_stdout( " *** IGNORED because no missing zones were found ***" );
            else
            {
                PH::print_stdout();

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    self::zoneCalculationNatClone( $minus, $zoneStore, $padding, $isAPI );

                    return;
                }

                foreach( $minus as $zone )
                {
                    $zoneContainer->addZone($zoneStore->findOrCreate($zone));
                }

                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
        elseif( $mode == 'unneeded-tag-add' )
        {
            PH::print_stdout( $padding . " - UNNEEDED-TAG-ADD MODE: adding rule tag for unneeded zones.");

            if( $addressContainer->isAny() )
                PH::print_stdout( " *** IGNORED because value is 'ANY' ***" );
            elseif( count($plus) == 0 )
                PH::print_stdout( " *** IGNORED because no unneeded zones were found ***" );
            else
            {
                PH::print_stdout();

                if( $this->isNatRule() && $fromOrTo == 'to' )
                {
                    derr($padding . ' NAT rules are not supported yet');
                }

                if( $fromOrTo == 'from' )
                    $tag_add = 'unneeded-from-zone';
                elseif( $fromOrTo == 'to' )
                    $tag_add = 'unneeded-to-zone';

                $objectFind = $this->tags->parentCentralStore->findOrCreate($tag_add);
                $this->tags->addTag($objectFind);

                if( $isAPI )
                    $zoneContainer->API_sync();
            }
        }
    }

    public function zoneCalculationNatClone( $zoneArray, $zoneStore, $padding, $isAPI )
    {
        foreach( $zoneArray as $zoneToAdd )
        {
            $newRuleName = $this->owner->findAvailableName($this->name());
            $newRule = $this->owner->cloneRule($this, $newRuleName);
            $newRule->to->setAny();

            $newRule->to->addZone($zoneStore->findOrCreate($zoneToAdd));
            PH::print_stdout( $padding . " - cloned NAT rule with name '{$newRuleName}' and TO zone='{$zoneToAdd}'" );
            if( $isAPI )
            {
                $newRule->API_sync();
                $newRule->owner->API_moveRuleAfter($newRule, $this);
            }
            else
                $newRule->owner->moveRuleAfter($newRule, $this);
        }

        if( $this->to->isAny() )
        {
            PH::print_stdout( " remove origin NAT rule as TO zone ANY is not allowed" );
            $this->owner->remove( $this );
        }
    }

    public function ruleUsageFast( $context, $hitType )
    {
        /** @var @var RuleRQueryContext $context */


        $supported_hitType = array( 'hit-count', 'last-hit-timestamp', 'first-hit-timestamp', 'rule-creation-timestamp', 'rule-modification-timestamp');
        if( !in_array( $hitType, $supported_hitType ) )
            derr( "supported hitType: ".implode( ", ", $supported_hitType ) );


        #$unused_flag = 'unused' . $this->ruleNature();
        $unused_flag = $hitType . $this->ruleNature();
        $rule_base = $this->ruleNature();

        $sub = $this->owner->owner;
        if( !$sub->isVirtualSystem() && !$sub->isDeviceGroup() )
        {
            PH::print_stdout( PH::boldText("   **WARNING**:") . "this filter is only supported on non Shared rules " . $this->toString() . "" );
            return null;
        }


        $connector = findConnector($sub);

        if( $connector === null )
            derr("this filter is available only from API enabled PANConf objects");

        if( !isset($sub->apiCache) )
            $sub->apiCache = array();

        // caching results for speed improvements
        if( !isset($sub->apiCache[$unused_flag]) )
        {
            $sub->apiCache[$unused_flag] = array();

            if( $this->owner->owner->version < 81 )
                $apiCmd = '<show><running><rule-use><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $sub->name() . '</vsys></rule-use></running></show>';
            else
                $apiCmd = '<show><running><rule-use><highlight><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $sub->name() . '</vsys></highlight></rule-use></running></show>';


            if( $sub->isVirtualSystem() )
            {
                PH::print_stdout( "Firewall: " . $connector->info_hostname . " (serial: '" . $connector->info_serial . "', PAN-OS: '" . $connector->info_PANOS_version . "') was rebooted '" . $connector->info_uptime . "' ago." );
                $apiResult = $connector->sendCmdRequest($apiCmd);

                $rulesXml = DH::findXPath('/result/rules/entry', $apiResult);
                for( $i = 0; $i < $rulesXml->length; $i++ )
                {
                    $ruleName = $rulesXml->item($i)->textContent;
                    $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                }

                if( $this->owner->owner->version >= 81 )
                    self::ruleUsage81( $sub, null, $rule_base, $connector, $hitType, $unused_flag, $context );
            }
            else
            {
                $devices = $sub->getDevicesInGroup(TRUE);

                $connectedDevices = $connector->panorama_getConnectedFirewallsSerials();
                foreach( $devices as $id => $device )
                {
                    if( !isset($connectedDevices[$device['serial']]) )
                    {
                        unset($devices[$id]);
                        PH::print_stdout( "\n  - firewall device with serial: " . $device['serial'] . " is not connected." );
                    }
                }

                $firstLoop = TRUE;

                foreach( $devices as $device )
                {
                    $newConnector = new PanAPIConnector($connector->apihost, $connector->apikey, 'panos-via-panorama', $device['serial']);
                    $newConnector->setShowApiCalls($connector->showApiCalls);
                    $newConnector->refreshSystemInfos();
                    PH::print_stdout( "Firewall: " . $newConnector->info_hostname . " (serial: '" . $newConnector->info_serial . "', PAN-OS: '" . $newConnector->info_PANOS_version . "') was rebooted '" . $newConnector->info_uptime . "' ago." );
                    $tmpCache = array();

                    foreach( $device['vsyslist'] as $vsys )
                    {
                        if( $newConnector->info_PANOS_version_int < 81 )
                            $apiCmd = '<show><running><rule-use><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $vsys . '</vsys></rule-use></running></show>';
                        else
                            $apiCmd = '<show><running><rule-use><highlight><rule-base>' . $rule_base . '</rule-base><type>unused</type><vsys>' . $vsys . '</vsys></highlight></rule-use></running></show>';

                        $apiResult = $newConnector->sendCmdRequest($apiCmd);

                        $rulesXml = DH::findXPath('/result/rules/entry', $apiResult);

                        for( $i = 0; $i < $rulesXml->length; $i++ )
                        {
                            $ruleName = $rulesXml->item($i)->textContent;
                            if( $firstLoop )
                                $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                            else
                            {
                                $tmpCache[$ruleName] = $ruleName;
                            }
                        }

                        if( $newConnector->info_PANOS_version_int >= 81 )
                            self::ruleUsage81( $sub, $vsys, $rule_base, $newConnector, $hitType, $unused_flag, $context );

                        if( !$firstLoop )
                        {
                            $operator = $context->operator;
                            if($operator == "is.unused.fast")
                            {
                                foreach( $sub->apiCache[$unused_flag] as $unusedEntry )
                                {
                                    if( !isset($tmpCache[$unusedEntry]) )
                                        unset($sub->apiCache[$unused_flag][$unusedEntry]);
                                }
                            }
                        }

                        $firstLoop = FALSE;
                    }
                }
            }

            #foreach($sub->apiCache[$unused_flag] as  $ruleName => $entry)
            #    print $ruleName."\n";
        }

        if( isset($sub->apiCache[$unused_flag][$this->name()]) )
            return TRUE;
        else
            return FALSE;

        return null;
    }

    function ruleUsage81( &$sub, $vsys, $rule_base, $connector, $hitType, $unused_flag, $context )
    {
            if( $vsys !== null)
                $name = $vsys;
            else
                $name = $sub->name();

            $apiCmd2 = '<show><rule-hit-count><vsys><vsys-name><entry%20name="' . $name . '"><rule-base><entry%20name="' . $rule_base . '"><rules>';
            $apiCmd2 .= '<all></all>';
            $apiCmd2 .= '</rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>';

            PH::print_stdout( "additional check needed as PAN-OS >= 8.1.X" );

            $apiResult = $connector->sendCmdRequest($apiCmd2);

            $rulesXml = DH::findXPath('/result/rule-hit-count/vsys/entry/rule-base/entry/rules/entry', $apiResult);
            for( $i = 0; $i < $rulesXml->length; $i++ )
            {
                $ruleName = $rulesXml->item($i)->getAttribute('name');

                foreach( $rulesXml->item($i)->childNodes as $node )
                {
                    if( $node->nodeName == $hitType )
                    {
                        if( $hitType == "hit-count" )
                        {
                            $hitcount_value = $node->textContent;
                            $operator = $context->operator;
                            $filter_hitcount = $context->value;
                            if($operator == "is.unused.fast")
                            {
                                if( $hitcount_value == 0 )
                                {
                                    //match, no unset
                                }
                                else
                                {
                                    if( isset($sub->apiCache[$unused_flag][$ruleName]) )
                                        unset($sub->apiCache[$unused_flag][$ruleName]);
                                }
                            }
                            else
                            {
                                if( $operator == '=' )
                                    $operator = '==';

                                $operator_string = $hitcount_value." ".$operator." ".$filter_hitcount;
                                #print $ruleName."|".$operator_string."\n";

                                if( eval("return $operator_string;" ) )
                                {
                                    //match, no unset
                                    if( !isset($sub->apiCache[$unused_flag][$ruleName]) )
                                        $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                                }
                                else
                                {
                                    if( isset($sub->apiCache[$unused_flag][$ruleName]) )
                                        unset($sub->apiCache[$unused_flag][$ruleName]);
                                }
                            }
                        }
                        elseif( $hitType == "last-hit-timestamp" || $hitType == "first-hit-timestamp"
                            || $hitType == "rule-creation-timestamp"
                            || $hitType == "rule-modification-timestamp" )
                        {
                            $timestamp_value = $node->textContent;
                            if( $context->value == 0 )
                                $filter_timestamp = $context->value;
                            else
                                $filter_timestamp = strtotime($context->value);
                            $operator = $context->operator;
                            if( $operator == '=' )
                                $operator = '==';
                            
                            $operator_string = $timestamp_value." ".$operator." ".$filter_timestamp;
                            if( $operator == '==' && $timestamp_value == 0 )
                            {
                                //match, no unset
                                if( !isset($sub->apiCache[$unused_flag][$ruleName]) )
                                    $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                            }
                            elseif( $timestamp_value != 0 && eval("return $operator_string;" ) )
                            {
                                //match, no unset
                                if( !isset($sub->apiCache[$unused_flag][$ruleName]) )
                                    $sub->apiCache[$unused_flag][$ruleName] = $ruleName;
                            }
                            else
                            {
                                if( isset($sub->apiCache[$unused_flag][$ruleName]) )
                                    unset($sub->apiCache[$unused_flag][$ruleName]);
                            }
                        }
                    }
                }
            }
    }

    public function ServiceResolveSummary( $RuleReferenceLocation = null )
    {
        $port_mapping_text = array();

        if( $this->isDecryptionRule() )
            return array();
        if( $this->isAppOverrideRule() )
            return $this->ports();


        if( $this->isNatRule() )
        {
            if( $this->service !== null )
                return array($this->service);
            return array('tcp/0-65535', 'udp/0-65535');
        }

        if( $this->services->isAny() )
            return array('tcp/0-65535', 'udp/0-65535');
        if( $this->services->isApplicationDefault() )
        {
            if( $this->apps->isAny() )
                return array('application-default');
            else
            {
                $app_array = array();
                $port_mapping_text = array();

                $applications = $this->apps->getAll();
                foreach( $applications as $app )
                {
                    /** @var App $app */
                    $app_array = array_merge($app_array, $app->getAppsRecursive());
                }

                foreach( $app_array as $app )
                    $app->getAppServiceDefault(FALSE, $port_mapping_text);

                return $port_mapping_text;
            }
        }


        $objects = $this->services->getAll();

        if( $RuleReferenceLocation !== null )
        {
            foreach( $objects as $key => $member )
                $objects[$key] = $RuleReferenceLocation->serviceStore->find($member->name());
        }

        $array = array();
        foreach( $objects as $object )
        {
            #$port_mapping = $object->dstPortMapping();
            $port_mapping = $object->dstPortMapping( array(), $this->owner->owner );
            $mapping_texts = $port_mapping->mappingToText();

            //TODO: handle predefined service objects in a different way
            if( $object->name() == 'service-http' )
                $mapping_texts = 'tcp/80';
            if( $object->name() == 'service-https' )
                $mapping_texts = 'tcp/443';


            if( strpos($mapping_texts, " ") !== FALSE )
                $mapping_text_array = explode(" ", $mapping_texts);
            else
                $mapping_text_array[] = $mapping_texts;


            $protocol = "tmp";
            foreach( $mapping_text_array as $mapping_text )
            {
                if( strpos($mapping_text, "tcp/") !== FALSE )
                    $protocol = "tcp/";
                elseif( strpos($mapping_text, "udp/") !== FALSE )
                    $protocol = "udp/";

                $mapping_text = str_replace($protocol, "", $mapping_text);
                $mapping_text = explode(",", $mapping_text);

                foreach( $mapping_text as $mapping )
                {

                    if( !in_array($protocol . $mapping, $port_mapping_text) )
                    {
                        $port_mapping_text[$protocol . $mapping] = $protocol . $mapping;

                        if( strpos($mapping, "-") !== FALSE )
                        {
                            $array[$protocol . $mapping] = $protocol . $mapping;
                            $range = explode("-", $mapping);
                            for( $i = $range[0]; $i <= $range[1]; $i++ )
                                $array[$protocol . $i] = $protocol . $i;
                        }
                        else
                            $array[$protocol . $mapping] = $protocol . $mapping;
                    }
                }
            }
        }

        return $port_mapping_text;
    }

    public function ServiceAppDefaultResolveSummary()
    {
        $port_mapping_text = array();

        if( $this->isDecryptionRule() )
            return array();
        if( $this->isAppOverrideRule() )
            return array();
        if( $this->isNatRule() )
            return array();

        if( $this->apps->isAny() )
            return array( 'application-default' );
        else
        {
            $app_array = array();
            $port_mapping_text = array();

            $applications = $this->apps->getAll();
            foreach( $applications as $app )
            {
                /** @var App $app */
                $app_array = array_merge( $app_array, $app->getAppsRecursive() );
            }

            foreach( $app_array as $app )
                $app->getAppServiceDefault( false, $port_mapping_text );

            return $port_mapping_text;
        }
    }


    public function SP_isBestPractice()
    {
        if( !$this->isSecurityRule() && !$this->isDefaultSecurityRule() )
            return FALSE;
        if( !$this->securityProfileIsBlank()
            && $this->securityProfileType() == "group" )
        {
            $group_name = $this->securityProfileGroup();
            /** @var SecurityProfileGroup $group */
            $group = $this->owner->owner->securityProfileGroupStore->find($group_name);
            if( $group === NULL )
            {
                mwarning( "Secrule: '".$this->name()."' has SecProfGroup: '".$group_name."' defined, but can not be found", null, false );
                return FALSE;
            }

            if( $group->is_best_practice() )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            $profiles = $this->securityProfiles_obj();
            if( count($profiles) > 0 )
            {
                $bp_set = FALSE;
                foreach ($profiles as $type => $profile) {
                    if ($type == "virus" || $type == "spyware" || $type == "vulnerability")
                    {
                        /** @var AntiVirusProfile $profile */
                        if (is_object($profile))
                        {
                            if ($profile->is_best_practice())
                                $bp_set = TRUE;
                            else
                                return FALSE;
                        }
                        else
                        {
                            mwarning("BP SPG check1 not possible - SecurityProfile type: " . $type . " name '" . $profile . "' not found", null, false);
                            return FALSE;
                        }
                    }
                }
                if( !isset($profiles['virus']) )
                    return FALSE;
                if( !isset($profiles['spyware']) )
                    return FALSE;
                if( !isset($profiles['vulnerability']) )
                    return FALSE;

                if ($bp_set)
                    return TRUE;
                else
                    return FALSE;
            }
            return null;
        }
    }

    public function SP_isVisibility()
    {
        if( !$this->isSecurityRule() && !$this->isDefaultSecurityRule() )
            return FALSE;
        if( !$this->securityProfileIsBlank()
            && $this->securityProfileType() == "group" )
        {
            $group_name = $this->securityProfileGroup();
            /** @var SecurityProfileGroup $group */
            $group = $this->owner->owner->securityProfileGroupStore->find($group_name);

            if( $group->is_visibility() )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            $profiles = $this->securityProfiles_obj();
            if( count($profiles) > 0 )
            {
                $bp_set = FALSE;
                foreach ($profiles as $type => $profile)
                {
                    if ($type == "virus" || $type == "spyware" || $type == "vulnerability")
                    {
                        /** @var AntiVirusProfile $profile */
                        if (is_object($profile))
                        {
                            if ($profile->is_visibility())
                                $bp_set = TRUE;
                            else
                                return FALSE;
                        }
                        else
                        {
                            mwarning("BP SPG check2 not possible - SecurityProfile type: " . $type . " name '" . $profile . "' not found", null, false);
                            return FALSE;
                        }
                    }
                }
                if( !isset($profiles['virus']) )
                    return FALSE;
                if( !isset($profiles['spyware']) )
                    return FALSE;
                if( !isset($profiles['vulnerability']) )
                    return FALSE;

                if ($bp_set)
                    return TRUE;
                else
                    return FALSE;
            }
            return null;
        }
    }

    public function SP_isAdoption()
    {
        if( !$this->isSecurityRule() && !$this->isDefaultSecurityRule() )
            return FALSE;
        if( !$this->securityProfileIsBlank()
            && $this->securityProfileType() == "group" )
        {
            $group_name = $this->securityProfileGroup();
            /** @var SecurityProfileGroup $group */
            $group = $this->owner->owner->securityProfileGroupStore->find($group_name);

            if( $group->is_adoption() )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            $profiles = $this->securityProfiles_obj();
            if( count($profiles) > 0 )
            {
                $bp_set = FALSE;
                foreach ($profiles as $type => $profile)
                {
                    if ($type == "virus" || $type == "spyware" || $type == "vulnerability")
                    {
                        /** @var AntiVirusProfile $profile */
                        if (is_object($profile))
                        {
                            if ($profile->is_adoption())
                                $bp_set = TRUE;
                            else
                                return FALSE;
                        }
                        else
                        {
                            mwarning("BP SPG check2 not possible - SecurityProfile type: " . $type . " name '" . $profile . "' not found", null, false);
                            return FALSE;
                        }
                    }
                }
                if( !isset($profiles['virus']) )
                    return FALSE;
                if( !isset($profiles['spyware']) )
                    return FALSE;
                if( !isset($profiles['vulnerability']) )
                    return FALSE;

                if ($bp_set)
                    return TRUE;
                else
                    return FALSE;
            }
            return null;
        }
    }

    public function getRuleThreatLog( $date, $context, $operator, $perRule = false )
    {
        if( !$this->isSecurityRule() && !$this->isDoSRule() &&  !$this->isPbfRule() && !$this->isQoSRule() )
            return FALSE;

        $threatArray = array();

        $d_actual = time();
        $char_counter_array = count_chars($date,1);
        if( strpos( $date, "/" ) !== FALSE )
        {
            $d2 = DateTime::createFromFormat('Y/m/d', $date);
            $d = $d2->getTimestamp();
        }
        elseif(  isset($char_counter_array['-']) and $char_counter_array['-'] == 2)
        {
            $d2 = DateTime::createFromFormat('d-m-Y', $date);
            $d = $d2->getTimestamp();

        }

        else
        {
            $d = $d_actual;
            if( $date !== 0 )
            {
                $d = $d_actual + ($date)*24*3600;
            }
            $d2 = new DateTime('@' . $d);
            #$d2 = new DateTime();
            #$d2->setTimestamp($d);
        }
        //var_dump($d);
        //exit();
        /////////////////
        if( empty($context->cachedList) )
        {
            $query_operator = "geq";
            if( $operator == ">" )
                $query_operator = "geq";
            elseif( $operator == "<" )
                $query_operator = "leq";
            else
                derr( "actual supported operator '>' and '<'", null, false );

            $year = $d2->format("Y");
            $month = $d2->format("m");
            $day = $d2->format("d");
            $query_date = $year."/".$month."/".$day;
            //( receive_time geq '2025/01/12 00:00:00' ) and (time_generated geq '2025/01/12 00:00:00')
            //$query = "(time_generated geq '".$d." 00:00:00')";
            if( $perRule )
                $query = "(time_generated ".$query_operator." '".$query_date." 00:00:00') and ( severity geq 'medium' )  and ( rule eq '".$this->name()."' )";
            else
                $query = "(time_generated ".$query_operator." '".$query_date." 00:00:00') and ( severity geq 'medium' )";

            $tmp_array = array();
            $full_array = array();
            $orig_query = $query;
            do
            {
                //get threat-log per day
                $apiArgs = Array();
                $apiArgs['type'] = 'log';
                $apiArgs['log-type'] = 'threat';
                $apiArgs['nlogs'] = '5000';
                if( !empty($query) )
                    $apiArgs['query'] = $query;

                $connector = findConnector($this->owner->owner);

                if( $connector === null )
                    derr("this filter is available only from API enabled PANConf objects");

                $tmp_array = $connector->getLog($apiArgs);
                $full_array = array_merge($tmp_array, $full_array);

                $last_array_entry = end($tmp_array);
                $query = $orig_query." and (time_generated leq '".$last_array_entry['time_generated']."')";

            }while( (count($tmp_array) == 5000) );
            $context->cachedList = $full_array;

            PH::print_stdout( "------------------------------------------------------------------------");
            PH::print_stdout("Threat Log count: ".count($context->cachedList));
        }

        $counter = 0;
        foreach( $context->cachedList as $threat_log )
        {
            if( isset( $threat_log['rule'] ) )
            {
                if( $threat_log['rule'] === $this->name() )
                {
                    $threatArray[$this->name()][] = $threat_log;

                    $counter++;
                    if( $counter > 10 )
                        break;
                }
            }
        }

        if( $perRule )
            $context->cachedList = array();

        return $threatArray;
    }
    public function isPreRule()
    {
        return $this->owner->ruleIsPreRule($this);
    }

    public function isPostRule()
    {
        return $this->owner->ruleIsPostRule($this);
    }


    public function isSecurityRule()
    {
        return FALSE;
    }

    public function isNatRule()
    {
        return FALSE;
    }

    public function isDecryptionRule()
    {
        return FALSE;
    }

    public function isAppOverrideRule()
    {
        return FALSE;
    }

    public function isCaptivePortalRule()
    {
        return FALSE;
    }

    public function isAuthenticationRule()
    {
        return FALSE;
    }

    public function isPbfRule()
    {
        return FALSE;
    }

    public function isQoSRule()
    {
        return FALSE;
    }

    public function isDoSRule()
    {
        return FALSE;
    }

    public function isTunnelInspectionRule()
    {
        return FALSE;
    }

    public function isDefaultSecurityRule()
    {
        return FALSE;
    }

    public function isNetworkPacketBrokerRule()
    {
        return FALSE;
    }

    public function isSDWanRule()
    {
        return FALSE;
    }

    public function ruleNature()
    {
        return 'unknown';
    }

}




