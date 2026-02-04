<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class WildfireProfile extends SecurityProfile2
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

    public $rules_obj = array();

    public $rule_coverage = array();

    public $cloud_inline_analysis_enabled = false;

    public $additional = array();

    /**
     * you should not need this one for normal use
     * @param string $name
     * @param SecurityProfileStore $owner
     * @param bool $fromXmlTemplate
     */
    function __construct($name, $owner, $fromXmlTemplate = FALSE)
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

        if( $c->isAPI())
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml)
    {
        $this->secprof_type = "wildfire";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("WildFire SecurityProfile name not found\n");



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

                $threadPolicy_obj = new ThreatPolicyWildfire( $rule_name, $this );
                $threadPolicy_obj->wildfirepolicy_load_from_domxml( $tmp_entry1 );
                $this->rules_obj[] = $threadPolicy_obj;
                $threadPolicy_obj->addReference( $this );

                $this->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);
            }
        }

        $tmp_rule = DH::findFirstElement('cloud-inline-analysis', $xml);
        if( $tmp_rule !== FALSE )
        {
            if( $tmp_rule->textContent == "yes")
                $this->cloud_inline_analysis_enabled = true;
        }

        $tmp_rule = DH::findFirstElement('mica-engine-wildfire-rules', $xml);
        if( $tmp_rule !== FALSE && !$tmp_rule->hasChildNodes() )
        {
            $xml->removeChild($tmp_rule);
            $tmp_rule = DH::findFirstElement('mica-engine-wildfire-rules', $xml);
        }
        if( $tmp_rule !== FALSE )
        {
            $this->additional['mica-engine-wildfire-rules'] = array();
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                    continue;

                $name = DH::findAttribute("name", $tmp_entry1);

                $tmp_action = DH::findFirstElement("action", $tmp_entry1);
                if( $tmp_action !== FALSE )
                    $this->additional['mica-engine-wildfire-rules'][$name]['action'] = $tmp_action->textContent;

                $tmp_direction = DH::findFirstElement("direction", $tmp_entry1);
                if( $tmp_direction !== FALSE )
                    $this->additional['mica-engine-wildfire-rules'][$name]['direction'] = $tmp_direction->textContent;

                $tmp_application = DH::findFirstElement("application", $tmp_entry1);
                if( $tmp_application !== FALSE )
                {
                    $tmp_app_array = array();
                    foreach( $tmp_application->childNodes as $tmp_entry_app )
                    {
                        if ($tmp_entry_app->nodeType != XML_ELEMENT_NODE)
                            continue;

                        $tmp_app_array[$tmp_entry_app->textContent] = $tmp_entry_app->textContent;
                    }
                    $this->additional['mica-engine-wildfire-rules'][$name]['application'] = $tmp_app_array;
                }
                $tmp_file_type = DH::findFirstElement("file-type", $tmp_entry1);
                if( $tmp_file_type !== FALSE )
                {
                    $tmp_file_type_array = array();
                    foreach( $tmp_file_type->childNodes as $tmp_entry_file_type )
                    {
                        if ($tmp_entry_file_type->nodeType != XML_ELEMENT_NODE)
                            continue;

                        $tmp_file_type_array[$tmp_entry_file_type->textContent] = $tmp_entry_file_type->textContent;
                    }
                    $this->additional['mica-engine-wildfire-rules'][$name]['file-type'] = $tmp_file_type_array;
                }
                /*
                     <entry name="wf_inline_rule1">
                      <application>
                        <member>any</member>
                      </application>
                      <file-type>
                        <member>any</member>
                      </file-type>
                      <direction>both</direction> //download/both
                      <action>alert</action> //allow/alert/block
                    </entry>
                 */
            }
        }
        return TRUE;
    }

    public function display()
    {
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);


        if( !empty( $this->rules_obj ) )
        {
            PH::print_stdout("        - wildfire-rules:");

            foreach ($this->rules_obj as $rulename => $rule)
            {
                $rule->display();
            }
        }

        if( !empty( $this->additional['mica-engine-wildfire-rules'] ) )
        {
            PH::print_stdout("        ----------------------------------------");
            $cloud_enabled = "no";
            if( $this->cloud_inline_analysis_enabled )
                $cloud_enabled = "yes";
            PH::print_stdout("        - wildfire-inline-rules: [mica-engine-enabled: ".$cloud_enabled."]");

            foreach ($this->additional['mica-engine-wildfire-rules'] as $rulename => $rule)
                PH::print_stdout("          '".$rulename."': - fileType: '".implode(",", $rule['file-type'])."' - application: '".implode(",", $rule['application'])."' - direction: '".$rule['direction']."'  - action: '".$rule['action']."'" );
        }
    }

    public function wildfire_rules_best_practice()
    {
        $bp_set = null;
        if (!empty($this->rules_obj))
        {
            $bp_set = false;


            $check_array = $this->rules_obj[0]->wildfire_rule_bp_visibility_JSON( "visibility", "wildfire" );
            $checkBP_array = $this->rules_obj[0]->wildfire_rule_bp_visibility_JSON( "bp", "wildfire" );
            $this->wildfire_rules_coverage();


            foreach( $checkBP_array[0]['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    if( $checkBP_array[0]['analysis'] !== $this->rule_coverage[$bp_array]['analysis'] )
                        return false;
                    else
                        $bp_set = true;
                }
                #else
                #    return false;
            }

            foreach( $check_array[0]['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    $checkAction = $check_array[0]['analysis'];
                    if( strpos( $checkAction, "!" ) !== FALSE )
                    {
                        $checkAction = str_replace("!", "", $checkAction);
                        if( $checkAction === $this->rule_coverage[$bp_array]['analysis'] )
                            return false;
                        else
                            $bp_set = true;
                    }
                    else
                    {
                        if( $checkAction !== $this->rule_coverage[$bp_array]['analysis'] )
                            return false;
                        else
                            $bp_set = true;
                    }

                }
            }


            #########################################################
            /*
            foreach ($this->rules_obj as $rulename => $rule)
            {
                /** @var ThreatPolicyWildfire $rule */
                /*
                if ($rule->wildfire_rule_best_practice())
                    #$bp_set = true;
                    return true;
                else
                    #return false;
                    $bp_set = false;
            }
            */
        }
        return $bp_set;
    }

    public function wildfire_rules_visibility()
    {
        $bp_set = null;
        if (!empty($this->rules_obj)) {
            $bp_set = false;

            foreach ($this->rules_obj as $rulename => $rule) {
                /** @var ThreatPolicyWildfire $rule */
                if ($rule->wildfire_rule_visibility())
                    #$bp_set = true;
                    return true;
                else
                    $bp_set = false;
                    #return false;
            }
        }
        return $bp_set;
    }

    public function wildfire_rules_coverage()
    {
        if (!empty($this->rules_obj))
        {
            foreach ($this->rules_obj as $rulename => $rule)
            {
                /** @var ThreatPolicyWildfire $rule */
                foreach( $rule->filetype as $filetype_detail )
                {
                    if( !isset($this->rule_coverage[$filetype_detail]) )
                    {
                        $this->rule_coverage[$filetype_detail]['direction'] = $rule->direction;
                        $this->rule_coverage[$filetype_detail]['analysis'] = $rule->analysis;
                    }
                }
            }
        }
    }

    public function is_best_practice()
    {
        if( $this->owner->owner->version >= 111 )
        {
            if( $this->wildfire_rules_best_practice()
                && $this->cloud_inline_analysis_best_practice($this->owner->bp_json_file)
            )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            if( $this->wildfire_rules_best_practice()
            )
                return TRUE;
            else
                return FALSE;
        }
    }

    public function is_visibility()
    {
        if( $this->owner->owner->version >= 111 )
        {
            if( $this->wildfire_rules_visibility()
                && $this->cloud_inline_analysis_visibility($this->owner->bp_json_file)
                #&& $this->spyware_dns_security_visibility() && $this->spyware_dnslist_visibility()
            )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            if( $this->wildfire_rules_visibility()
                #&& $this->spyware_dns_security_visibility() && $this->spyware_dnslist_visibility()
            )
                return TRUE;
            else
                return FALSE;
        }
    }

    public function is_adoption()
    {
        #if at least one spyware rule is set -> adoption, if not false
        if( count($this->rules_obj) > 0 )
            return true;
        else
            return false;
    }

    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

