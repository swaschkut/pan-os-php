<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class FileBlockingProfile extends SecurityProfile2
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
        $this->secprof_type = "file-blocking";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("FileBlocking SecurityProfile name not found\n");



        $tmp_rule = DH::findFirstElement('rules', $xml);
        if( $tmp_rule !== FALSE )
        {
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if( $tmp_entry1->nodeType != XML_ELEMENT_NODE )
                    continue;

                $rule_name = DH::findAttribute('name', $tmp_entry1);
                if( $rule_name === FALSE )
                    derr("FileBlocking Rule name not found\n");

                $threadPolicy_obj = new ThreatPolicyFileBlocking( $rule_name, $this );
                $threadPolicy_obj->fileblockingpolicy_load_from_domxml( $tmp_entry1 );
                $this->rules_obj[] = $threadPolicy_obj;
                $threadPolicy_obj->addReference( $this );

                $this->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);
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
            PH::print_stdout("        - threat-rules:");

            foreach ($this->rules_obj as $rulename => $rule)
            {
                $rule->display();
            }
        }
    }


    public function fileblocking_rules_best_practice()
    {
        $bp_set = null;
        if (!empty($this->rules_obj))
        {
            $bp_set = false;

            $check_array = $this->rules_obj[0]->fileblocking_rule_bp_visibility_JSON( "visibility", "file-blocking" );
            $checkBP_array = $this->rules_obj[0]->fileblocking_rule_bp_visibility_JSON( "bp", "file-blocking" );
            $this->fileblocking_rules_coverage();

            foreach( $checkBP_array['block']['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    if( $checkBP_array['block']['action'] !== $this->rule_coverage[$bp_array]['action'] )
                        return false;
                    else
                        $bp_set = true;
                }
                elseif( isset($this->rule_coverage['any']) && $checkBP_array['block']['action'] === $this->rule_coverage['any']['action'] )
                {
                    $bp_set = true;
                    break;
                }
                else
                    return false;
            }

            foreach( $check_array['alert']['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    $checkAction = $check_array['alert']['action'][0];
                    if( strpos( $checkAction, "!" ) !== FALSE )
                    {
                        $checkAction = str_replace("!", "", $checkAction);
                        if( $checkAction === $this->rule_coverage[$bp_array]['action'] )
                            return false;
                        else
                            $bp_set = true;
                    }
                    else
                    {
                        if( isset($this->rule_coverage['any']) && $checkBP_array['block']['action'] === $this->rule_coverage['any']['action'] )
                            $bp_set = true;
                        elseif( $checkAction !== $this->rule_coverage[$bp_array]['action'] )
                            return false;
                        else
                            $bp_set = true;
                    }
                }
            }

            /*
            foreach ($this->rules_obj as $rulename => $rule)
            {
                /** @var ThreatPolicyFileblocking $rule */
                /*
                if ($rule->fileblocking_rule_best_practice())
                {
                    $bp_set = true;
                    #print "true\n";
                }
                else
                {
                    $bp_set = false;
                    #print "false\n";
                }
            }
            */
        }
        return $bp_set;
    }

    public function fileblocking_rules_visibility()
    {
        $bp_set = null;
        if (!empty($this->rules_obj))
        {
            $bp_set = false;

            foreach ($this->rules_obj as $rulename => $rule)
            {
                /** @var ThreatPolicyFileblocking $rule */
                if ($rule->fileblocking_rule_visibility())
                    #$bp_set = true;
                    return true;
                else
                    #return false;
                    $bp_set = false;
            }
        }
        return $bp_set;
    }

    public function fileblocking_rules_coverage()
    {
        if (!empty($this->rules_obj))
        {
            foreach ($this->rules_obj as $rulename => $rule)
            {
                /** @var ThreatPolicyFileblocking $rule */
                foreach( $rule->filetype() as $filtetype_detail )
                {
                    if( !isset($this->rule_coverage[$filtetype_detail]) )
                    {
                        $this->rule_coverage[$filtetype_detail]['action'] = $rule->action();
                    }
                }
            }
        }
    }

    public function is_best_practice()
    {
        if( $this->fileblocking_rules_best_practice()
            #&& $this->spyware_dns_security_best_practice() && $this->spyware_dnslist_best_practice()
            #&& $this->vulnerability_exception_best_practice()
            && $this->fileblocking_rules_visibility()
        )
            return TRUE;
        else
            return FALSE;
    }

    public function is_visibility()
    {
        if( $this->fileblocking_rules_visibility()
            #&& $this->spyware_dns_security_visibility() && $this->spyware_dnslist_visibility()
        )
            return TRUE;
        else
            return FALSE;
    }


    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

