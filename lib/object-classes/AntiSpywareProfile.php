<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class AntiSpywareProfile extends SecurityProfile2
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    /** @var string|null */
    protected $value;

    public $_all;

    /** @var SecurityProfileStore|null */
    public $owner;

    public $secprof_type;

    public $threatException = array();
    public $rules_obj = array();
    public $dns_rules_obj = array();
    public $additional = array();

    public $cloud_inline_analysis_enabled = false;

    /**
     * you should not need this one for normal use
     * @param string $name
     * @param SecurityProfileStore $owner
     * @param bool $fromXmlTemplate
     */
    function __construct( $name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->owner = $owner;

        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $this->owner->securityProfileRoot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->name = $name;
            $this->xmlroot->setAttribute('name', $name);
        }

        $this->name = $name;
    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newName);

        if( $c->isAPI() )
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml)
    {
        $this->secprof_type = "spyware";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("Spyware SecurityProfile name not found\n");


        $tmp_rule = DH::findFirstElement('rules', $xml);
        if( $tmp_rule !== FALSE )
        {
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $rule_name = DH::findAttribute('name', $tmp_entry1);
                if( $rule_name === FALSE )
                    derr("VB severity name not found\n");

                $threadPolicy_obj = new ThreatPolicySpyware( $rule_name, $this );
                $threadPolicy_obj->spywarepolicy_load_from_domxml( $tmp_entry1 );
                $this->rules_obj[] = $threadPolicy_obj;
                $threadPolicy_obj->addReference( $this );
                
                $this->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);
            }
        }

        $tmp_threat_exception = DH::findFirstElement('threat-exception', $xml);
        if( $tmp_threat_exception !== FALSE )
        {
            $tmp_array[$this->secprof_type][$this->name]['threat-exception'] = array();
            foreach( $tmp_threat_exception->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $tmp_name = DH::findAttribute('name', $tmp_entry1);
                if( $tmp_name === FALSE )
                    derr("VB severity name not found\n");

                $this->threatException[$tmp_name]['name'] = $tmp_name;


                if( get_class($this->owner->owner) == "DeviceGroup" )
                    $threatStore = $this->owner->owner->owner->threatStore;
                else
                    $threatStore = $this->owner->owner->threatStore;

                $threat_obj = $threatStore->find($tmp_name);
                if($threat_obj !== null)
                    $threat_obj->addReference($this);


                $action = DH::findFirstElement('action', $tmp_entry1);
                if( $action !== FALSE )
                {
                    if( $action->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_action = DH::firstChildElement($action);
                    if( $tmp_action !== FALSE )
                    {
                        $tmp_array[$this->secprof_type][$this->name]['threat-exception'][$tmp_name]['action'] = $tmp_action->nodeName;
                        $this->threatException[$tmp_name]['action'] = $tmp_action->nodeName;
                        if($threat_obj !== null)
                            $this->threatException[$tmp_name]['default-action'] = $threat_obj->defaultAction();
                    }
                }

                $exemptIP = DH::findFirstElement('exempt-ip', $tmp_entry1);
                $this->threatException[$tmp_name]['exempt-ip'] = array();
                if( $exemptIP !== FALSE )
                {
                    foreach( $exemptIP->childNodes as $tmp_entry2 )
                    {
                        if ($tmp_entry2->nodeType != XML_ELEMENT_NODE)
                            continue;

                        $this->threatException[$tmp_name]['exempt-ip'][] = DH::findAttribute("name", $tmp_entry2);
                    }
                }
            }
        }

        $tmp_rule = DH::findFirstElement('mica-engine-spyware-enabled', $xml);
        if( $tmp_rule !== FALSE )
        {
            /*
               <mica-engine-spyware-enabled>
                 <entry name="HTTP Command and Control detector">
                    <inline-policy-action>alert</inline-policy-action>
                 </entry>
            */
            $this->additional['mica-engine-spyware-enabled'] = array();
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                    continue;

                $name = DH::findAttribute("name", $tmp_entry1);
                $tmp_inline_policy_action = DH::findFirstElement("inline-policy-action", $tmp_entry1);
                if( $tmp_inline_policy_action !== FALSE )
                    $this->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'] = $tmp_inline_policy_action->textContent;
            }
        }
        //<cloud-inline-analysis>yes</cloud-inline-analysis>
        $tmp_rule = DH::findFirstElement('cloud-inline-analysis', $xml);
        if( $tmp_rule !== FALSE )
        {
            if( $tmp_rule->textContent == "yes")
                $this->cloud_inline_analysis_enabled = true;
        }
        $tmp_rule = DH::findFirstElement('botnet-domains', $xml);
        if( $tmp_rule !== FALSE )
        {
            $this->additional['botnet-domain'] = array();
            /*
                 <sinkhole>
                    <ipv4-address>sinkhole.paloaltonetworks.com</ipv4-address>
                    <ipv6-address>2600:5200::1</ipv6-address>
                 </sinkhole>
             */
            $tmp_sinkhole = DH::findFirstElement('sinkhole', $tmp_rule);
            if( $tmp_sinkhole !== FALSE )
            {
                $this->additional['botnet-domain']['sinkhole'] = array();
                $tmp_sinkhole_ipv4 = DH::findFirstElement('ipv4-address', $tmp_sinkhole);
                if( $tmp_sinkhole_ipv4 !== FALSE )
                    $this->additional['botnet-domain']['sinkhole']['ipv4-address'] = $tmp_sinkhole_ipv4->textContent;
                $tmp_sinkhole_ipv6 = DH::findFirstElement('ipv6-address', $tmp_sinkhole);
                if( $tmp_sinkhole_ipv6 !== FALSE )
                    $this->additional['botnet-domain']['sinkhole']['ipv6-address'] = $tmp_sinkhole_ipv6->textContent;
            }

            $tmp_lists = DH::findFirstElement('lists', $tmp_rule);
            if( $tmp_lists !== FALSE )
            {
                $this->additional['botnet-domain']['lists'] = array();
                foreach( $tmp_lists->childNodes as $tmp_entry1 )
                {
                    if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                        continue;

                    /*
                     <lists>
                        <entry name="default-paloalto-dns">
                           <action>
                              <alert/>
                           </action>
                           <packet-capture>disable</packet-capture>
                        </entry>
                     */

                    $name = DH::findAttribute("name", $tmp_entry1);
                    $action_element = DH::findFirstElement("action", $tmp_entry1);
                    if( $action_element !== FALSE )
                        $this->additional['botnet-domain']['lists'][$name]['action'] = $action_element->firstElementChild->nodeName;
                    $tmp_packet_capture = DH::findFirstElement("packet-capture", $tmp_entry1);
                    if( $tmp_packet_capture !== FALSE )
                        $this->additional['botnet-domain']['lists'][$name]['packet-capture'] = $tmp_packet_capture->textContent;
                }
            }

            $tmp_dns_security_categories = DH::findFirstElement('dns-security-categories', $tmp_rule);
            if( $tmp_dns_security_categories !== FALSE )
            {
                $this->additional['botnet-domain']['dns-security-categories'] = array();
                foreach( $tmp_dns_security_categories->childNodes as $tmp_entry1 )
                {
                    if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                        continue;

                    /*
                    <dns-security-categories>
                        <entry name="pan-dns-sec-adtracking">
                           <log-level>default</log-level>
                           <action>default</action>
                           <packet-capture>disable</packet-capture>
                        </entry>
                    */

                    $name = DH::findAttribute("name", $tmp_entry1);

                    $dnsPolicy_obj = new DNSPolicy( $name, $this );
                    $dnsPolicy_obj->load_from_domxml( $tmp_entry1 );
                    $this->dns_rules_obj[] = $dnsPolicy_obj;
                    $dnsPolicy_obj->addReference( $this );

                    $this->owner->owner->DNSPolicyStore->add($dnsPolicy_obj);

                    $this->additional['botnet-domain']['dns-security-categories'][] = $dnsPolicy_obj;
                    /*
                    $tmp_log_level = DH::findFirstElement("log-level", $tmp_entry1);
                    if( $tmp_log_level !== FALSE )
                        $this->additional['botnet-domain']['dns-security-categories'][$name]['log-level'] = $tmp_log_level->textContent;
                    $tmp_action = DH::findFirstElement("action", $tmp_entry1);
                    if( $tmp_action !== FALSE )
                        $this->additional['botnet-domain']['dns-security-categories'][$name]['action'] = $tmp_action->textContent;
                    $tmp_packet_capture = DH::findFirstElement("packet-capture", $tmp_entry1);
                    if( $tmp_packet_capture !== FALSE )
                        $this->additional['botnet-domain']['dns-security-categories'][$name]['packet-capture'] = $tmp_packet_capture->textContent;
                    */
                }
            }

            $tmp_whitelists = DH::findFirstElement('whitelist', $tmp_rule);
            if( $tmp_whitelists !== FALSE )
            {
                $this->additional['botnet-domain']['whitelist'] = array();
                foreach ($tmp_whitelists->childNodes as $tmp_entry1)
                {
                    if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $name = DH::findAttribute("name", $tmp_entry1);
                    $tmp_whitelists_description = DH::findFirstElement('description', $tmp_entry1);
                    $this->additional['botnet-domain']['whitelist'][$name]['name'] = $name;
                    if( $tmp_whitelists_description !== FALSE )
                        $this->additional['botnet-domain']['whitelist'][$name]['description'] = $tmp_whitelists_description->textContent;
                }
            }
        }

        return TRUE;
    }

    public function display()
    {
        PH::print_stdout( "     * " . get_class($this) . " '" . $this->name() . "'");
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);

        #PH::print_stdout();
        //Todo: continue for display out

        if( !empty( $this->rules_obj ) )
        {
            PH::print_stdout("        - Signature Policies:");
            foreach ($this->rules_obj as $rulename => $rule)
                $rule->display();
        }

        if( !empty( $this->threatException ) )
        {
            PH::print_stdout("        - Signature Exceptions:" );

            foreach( $this->threatException as $threatname => $threat )
            {
                PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['name'] = $threat['name'];

                $string = "             '" . $threat['name'] . "'";
                if( isset( $threat['action'] ) )
                {
                    $string .= "  - action : '".$threat['action']."'";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['action'] = $threat['action'];
                }
                if( isset( $threat['default-action'] ) )
                {
                    $string .= "  - default-action : '".$threat['default-action']."'";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['default-action'] = $threat['default-action'];
                }
                if( isset( $threat['exempt-ip'] ) )
                {
                    $string .= "  - exempt-ip: ".implode( ",", $threat['exempt-ip'] );
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['exempt-ip'] = $threat['exempt-ip'];
                }
                PH::print_stdout(  $string );
            }
        }

        if( !empty( $this->additional ) )
        {
            if( !empty( $this->additional['botnet-domain'] ) )
            {
                PH::print_stdout("        ----------------------------------------");
                PH::print_stdout("        - DNS Policies:" );

                foreach( $this->additional['botnet-domain'] as $type => $threat )
                {
                    PH::print_stdout("          * ".$type.":" );
                    if( $type == "lists" )
                    {
                        #print_r($this->additional['botnet-domain'][$type]);
                        foreach( $this->additional['botnet-domain']['lists'] as $name => $value )
                        {
                            PH::print_stdout("            - ".$name." -  action: ".$value['action'] ." -  packet-capture: ".$value['packet-capture'] );
                        }
                    }
                    elseif( $type == "sinkhole" )
                    {
                        foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                        {
                            PH::print_stdout("            - ".$name.": ".$value );
                        }
                    }
                    elseif( $type == "dns-security-categories" )
                    {
                        foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                        {
                            $padding = "    ";
                            $value->display( $padding);
                        }
                    }
                    elseif( $type == "whitelist" )
                    {
                        foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                        {
                            $string = "            - '".$value['name']."'";
                            if(isset($value['description']))
                                $string .= "| description:'".$value['description']."'";
                            PH::print_stdout( $string );
                        }
                    }
                }
            }

            if( !empty( $this->additional['mica-engine-spyware-enabled'] ) )
            {
                PH::print_stdout("        ----------------------------------------");
                $enabled = "[no]";
                if( $this->cloud_inline_analysis_enabled )
                    $enabled = "[yes]";
                PH::print_stdout("        - mica-engine-spyware-enabled: ". $enabled);

                foreach ($this->additional['mica-engine-spyware-enabled'] as $name => $threat)
                    PH::print_stdout("          * " . $name . " - inline-policy-action :" . $this->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action']);
            }
        }

        #PH::print_stdout();
    }

    public function spyware_dnslist_best_practice()
    {
        if( $this->secprof_type != 'spyware' )
            return null;

        if( isset($this->additional['botnet-domain']) && isset($this->additional['botnet-domain']['lists']) )
        {
            foreach( $this->additional['botnet-domain']['lists'] as $name => $array)
            {
                if( $name == "default-paloalto-dns" )
                {
                    if( isset($name['action']) && $array['action'] == "sinkhole" )
                        return TRUE;
                }
            }
        }

        return FALSE;
    }

    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

