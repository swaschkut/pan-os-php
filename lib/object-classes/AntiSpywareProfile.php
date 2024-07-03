<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class AntiSpywareProfile
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
    public $rules = array();
    public $additional = array();

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

        #PH::print_stdout( "\nsecprofURL TMP: object named '".$this->name."' found" );

        #$this->owner->_SecurityProfiles[$this->secprof_type][$this->name] = $this;
        #$this->owner->_all[$this->secprof_type][$this->name] = $this;
        #$this->owner->o[] = $this;


        //predefined URL category
        //$tmp_array[$this->secprof_type][$typeName]['allow']['URL category'] = all predefined URL category


        $tmp_rule = DH::findFirstElement('rules', $xml);
        if( $tmp_rule !== FALSE )
        {
            #$tmp_array[$this->secprof_type][$this->secprof_type][$this->name]['rules'] = array();
            $tmp_array[$this->secprof_type][$this->name]['rules'] = array();
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $vb_severity = DH::findAttribute('name', $tmp_entry1);
                if( $vb_severity === FALSE )
                    derr("VB severity name not found\n");

                $severity = DH::findFirstElement('severity', $tmp_entry1);
                if( $severity !== FALSE )
                {
                    if( $severity->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['severity'] = array();
                    $this->rules[$vb_severity]['severity'] = array();
                    foreach( $severity->childNodes as $member )
                    {
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['severity'][$member->textContent] = $member->textContent;
                        $this->rules[$vb_severity]['severity'][$member->textContent] = $member->textContent;
                    }
                }

                $severity = DH::findFirstElement('file-type', $tmp_entry1);
                if( $severity !== FALSE )
                {
                    if( $severity->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['file-type'] = array();
                    $this->rules[$vb_severity]['file-type'] = array();
                    foreach( $severity->childNodes as $member )
                    {
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['file-type'][$member->textContent] = $member->textContent;
                        $this->rules[$vb_severity]['file-type'][$member->textContent] = $member->textContent;
                    }
                }

                $action = DH::findFirstElement('action', $tmp_entry1);
                if( $action !== FALSE )
                {
                    if( $action->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_action = DH::firstChildElement($action);
                    if( $tmp_action !== FALSE )
                    {
                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['action'] = $tmp_action->nodeName;
                        $this->rules[$vb_severity]['action'] = $tmp_action->nodeName;
                    }

                    if( $this->secprof_type == 'file-blocking' )
                    {
                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['action'] = $action->textContent;
                        $this->rules[$vb_severity]['action'] = $action->textContent;
                    }

                }

                $packet_capture = DH::findFirstElement('packet-capture', $tmp_entry1);
                if( $packet_capture !== FALSE )
                {
                    if( $packet_capture->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['packet-capture'] = $packet_capture->textContent;
                    $this->rules[$vb_severity]['packet-capture'] = $packet_capture->textContent;
                }

                $direction = DH::findFirstElement('direction', $tmp_entry1);
                if( $direction !== FALSE )
                {
                    if( $direction->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['direction'] = $direction->textContent;
                    $this->rules[$vb_severity]['direction'] = $direction->textContent;
                }

                $analysis = DH::findFirstElement('analysis', $tmp_entry1);
                if( $analysis !== FALSE )
                {
                    if( $analysis->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['analysis'] = $analysis->textContent;
                    $this->rules[$vb_severity]['analysis'] = $analysis->textContent;
                }
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

                $action = DH::findFirstElement('action', $tmp_entry1);
                if( $action !== FALSE )
                {
                    if( $action->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_action = DH::firstChildElement($action);
                    $tmp_array[$this->secprof_type][$this->name]['threat-exception'][$tmp_name]['action'] = $tmp_action->nodeName;
                    $this->threatException[$tmp_name]['action'] = $tmp_action->nodeName;
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
                $this->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action'] = DH::findFirstElement("inline-policy-action", $tmp_entry1)->textContent;
            }
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
                $this->additional['botnet-domain']['sinkhole']['ipv4-address'] = $tmp_sinkhole_ipv4->textContent;
                $tmp_sinkhole_ipv6 = DH::findFirstElement('ipv6-address', $tmp_sinkhole);
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
                    $this->additional['botnet-domain']['lists'][$name]['action'] = $action_element->firstElementChild->nodeName;
                    $this->additional['botnet-domain']['lists'][$name]['packet-capture'] = DH::findFirstElement("packet-capture", $tmp_entry1)->textContent;
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
                    $this->additional['botnet-domain']['dns-security-categories'][$name]['log-level'] = DH::findFirstElement("log-level", $tmp_entry1)->textContent;
                    $this->additional['botnet-domain']['dns-security-categories'][$name]['action'] = DH::findFirstElement("action", $tmp_entry1)->textContent;
                    $this->additional['botnet-domain']['dns-security-categories'][$name]['packet-capture'] = DH::findFirstElement("packet-capture", $tmp_entry1)->textContent;
                }
            }

            $tmp_whitelists = DH::findFirstElement('whitelist', $tmp_rule);
            if( $tmp_whitelists !== FALSE )
            {
                $this->additional['botnet-domain']['whitelist'] = array();
                foreach ($tmp_whitelists->childNodes as $tmp_entry1) {
                    if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                        continue;

                    $name = DH::findAttribute("name", $tmp_entry1);
                    $this->additional['botnet-domain']['whitelist'][$name] = $tmp_entry1->textContent;
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

        if( !empty( $this->rules ) )
        {
            PH::print_stdout("        - rules:");

            foreach ($this->rules as $rulename => $rule)
            {
                $string = "";
                #PH::print_stdout("          * '".$rulename."':");
                $string .= "          '".$rulename."':";

                if( isset( $rule['severity'] ) )
                {
                    #PH::print_stdout("             severity: '".implode(",", $rule['severity'])."'");
                    $string .= " - severity: '".implode(",", $rule['severity'])."'";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['rule'][$rulename]['severity'] = implode(",", $rule['severity']);
                }

                if( isset( $rule['action'] ) )
                {
                    #PH::print_stdout("             action: '".$rule['action']."'");
                    $string .= " - action: '".$rule['action']."'";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['rule'][$rulename]['action'] = $rule['action'];
                }

                if( isset( $rule['packet-capture'] ) )
                {
                    #PH::print_stdout("             packet-capture: '".$rule['packet-capture']."'");
                    $string .= " - packet-capture: '".$rule['packet-capture']."'";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['rule'][$rulename]['packet-capture'] = $rule['packet-capture'];
                }
                #print_r($rule);
                PH::print_stdout( $string );
            }
        }

        if( !empty( $this->threatException ) )
        {
            PH::print_stdout("        - threat-exception:" );

            foreach( $this->threatException as $threatname => $threat )
            {
                PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['name'] = $threat['name'];

                $string = "             '" . $threat['name'] . "'";
                if( isset( $threat['action'] ) )
                {
                    $string .= "  - action : '".$threat['action']."'";
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['action'] = $threat['action'];
                }

                PH::print_stdout(  $string );
            }
        }

        if( !empty( $this->additional ) )
        {
            if( !empty( $this->additional['botnet-domain'] ) )
            {
                PH::print_stdout("        - botnet-domain:" );

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
                            $string = "";
                            $string .= "            - '".PH::boldText($name)."'";

                            $string .= " - log-level: '".$value['log-level']."'";
                            $string .= " - action: '".$value['action']."'";
                            $string .= " - packet-capture: '".$value['packet-capture']."'";

                            PH::print_stdout($string );
                        }
                    }
                    elseif( $type == "whitelist" )
                    {
                        foreach( $this->additional['botnet-domain'][$type] as $name => $value )
                        {
                            PH::print_stdout("            - ".$name.": ".$value );
                        }
                    }
                }
            }

            if( !empty( $this->additional['mica-engine-spyware-enabled'] ) )
            {
                PH::print_stdout("        - mica-engine-spyware-enabled:");

                foreach ($this->additional['mica-engine-spyware-enabled'] as $name => $threat)
                    PH::print_stdout("          * " . $name . " - inline-policy-action :" . $this->additional['mica-engine-spyware-enabled'][$name]['inline-policy-action']);
            }
        }

        #PH::print_stdout();
    }


    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

