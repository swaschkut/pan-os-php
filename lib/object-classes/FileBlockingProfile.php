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

                if( $this->owner !== null && $this->owner->owner !== null )
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


    /** @return bool|null null: file-blocking -> rule -> bp -> block -> filetype not listed in the BP JSON (N/A) */
    public function fileblocking_rules_best_practice()
    {
        $checkBP_array = PH::getBPjsonFile()['file-blocking']['rule']['bp'] ?? array();
        if( empty( $checkBP_array['block']['filetype'] ) || !is_array( $checkBP_array['block']['filetype'] ) )
            return null;
        // action / direction not listed: not checked
        $bp_action = $checkBP_array['block']['action'] ?? null;
        $bp_direction = $checkBP_array['block']['direction'] ?? null;

        $bp_set = false;
        if (!empty($this->rules_obj))
        {
            /*
             // how to validate if a rule is missing
            foreach( $this->rules_obj as $rulename => $rule )
            {
                if( $rule->fileblocking_rule_best_practice() )
                    return true;
            }

            return false;
            */

            //////////////////////////
            /// OLD
            ///
            ///
            $this->fileblocking_rules_coverage();

            foreach( $checkBP_array['block']['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {
                    if( ( $bp_action !== null && $bp_action !== $this->rule_coverage[$bp_array]['action'] )
                        || ( $bp_direction !== null && $bp_direction !== $this->rule_coverage[$bp_array]['direction'] )
                    )
                        return false;
                    else
                        $bp_set = true;
                }
                elseif( isset($this->rule_coverage['any'])
                    && ( $bp_action === null || $bp_action === $this->rule_coverage['any']['action'] )
                    && ( $bp_direction === null || $bp_direction === $this->rule_coverage['any']['direction'] )
                )
                {
                    $bp_set = true;
                    break;
                }
                else
                    return false;
            }

            if( $this->fileblocking_rules_visibility() === FALSE )     // null: visibility not listed
                return false;

        }
        return $bp_set;
    }

    /** @return bool|null null: file-blocking -> rule -> visibility not listed in the visibility JSON (N/A) */
    public function fileblocking_rules_visibility()
    {
        if( empty( PH::getBPjsonFile()['file-blocking']['rule']['visibility'] ) )
            return null;

        $bp_set = false;
        if (!empty($this->rules_obj))
        {
            //how to validate that a rule is missing
            foreach( $this->rules_obj as $rulename => $rule )
            {

                if( $rule->fileblocking_rule_visibility() === TRUE )
                    return true;
            }

            return false;


            /*
            //////////////////////////
            /// OLD
            ///
            $check_array = $this->rules_obj[0]->fileblocking_rule_bp_visibility_JSON( "visibility", "file-blocking" );
            $this->fileblocking_rules_coverage();

            #print_r( $check_array  );
            #print_r( $this->rule_coverage );

            foreach( $check_array['alert']['filetype'] as $bp_array )
            {
                if( isset($this->rule_coverage[$bp_array]) )
                {

                    if( $check_array['alert']['action'] !== $this->rule_coverage[$bp_array]['action']
                        || $check_array['alert']['direction'] !== $this->rule_coverage[$bp_array]['direction']
                        ||  (isset($this->rule_coverage[$bp_array]['application']) && !isset( $this->rule_coverage[$bp_array]['application'][ $check_array['alert']['application'] ] ) )

                    )
                    {
                        #print "    SET FALSE - not return2 ????\n";
                        $bp_set = false;
                    }

                    else
                    {

                        $bp_set = true;

                        return TRUE;
                    }
                }

                if( isset($this->rule_coverage['any'])
                    && $check_array['alert']['action'] === $this->rule_coverage['any']['action']
                    && $check_array['alert']['direction'] === $this->rule_coverage['any']['direction']
                    &&  isset( $this->rule_coverage['any']['application'][$check_array['alert']['application']] )
                )
                {
                    #print "--------------\n";
                    #print "NAME: ".$this->name()."\n";
                    #print "    RETURN TRUE\n";
                    #print "--------------\n";
                    return TRUE;
                }
                else
                {
                    #print "    SET FALSE - not return????\n";
                    $bp_set = false;
                }

            }
        */
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
                        $this->rule_coverage[$filtetype_detail]['direction'] = $rule->direction();
                        $this->rule_coverage[$filtetype_detail]['application'] = $rule->application();
                    }
                }
            }
        }
    }

    public function is_best_practice()
    {
        if( $this->fileblocking_rules_best_practice() !== FALSE
        )
            return TRUE;
        else
            return FALSE;
    }

    public function is_visibility()
    {
        if( $this->fileblocking_rules_visibility() !== FALSE
        )
            return TRUE;
        else
            return FALSE;
    }

    public function is_adoption()
    {
        if( count($this->rules_obj) > 0 )
            return true;
        else
            return false;
    }

    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';


    /**
     * Base XML of the iron-skillet file blocking profiles
     * (iron-skillet templates/panorama/snippets/profiles_file_blocking.xml):
     * 'Outbound-FB', 'Inbound-FB', 'Internal-FB' (without dll), 'Alert-Only-FB'.
     * The same for every version.
     *
     * @param string $version iron-skillet PAN-OS version folder, e.g. "11.1"
     * @return string
     */
    public static function ironSkilletXml( $version )
    {
        if( !in_array( $version, array( '10.0', '10.1', '10.2', '11.0', '11.1', '11.2', '12.1' ), TRUE ) )
        {
            derr( "iron-skillet file blocking profiles are not available for PAN-OS version '" . $version . "'", null, false );
            return null;
        }

        $blocked = array( '7z', 'bat', 'chm', 'class', 'cpl', 'dll', 'hlp', 'hta', 'jar', 'ocx', 'pif', 'scr', 'torrent', 'vbe', 'wsf' );
        $blockedInternal = array_values( array_diff( $blocked, array( 'dll' ) ) );

        // profile => rule name => array( file types, action )
        $profiles = array(
            'Outbound-FB' => array( 'Alert-All' => array( array( 'any' ), 'alert' ), 'Block' => array( $blocked, 'block' ) ),
            'Inbound-FB' => array( 'Alert-All' => array( array( 'any' ), 'alert' ), 'Block' => array( $blocked, 'block' ) ),
            'Internal-FB' => array( 'Alert-All' => array( array( 'any' ), 'alert' ), 'Block' => array( $blockedInternal, 'block' ) ),
            'Alert-Only-FB' => array( 'Alert-Only' => array( array( 'any' ), 'alert' ) ),
        );

        $xml = '<root>';
        foreach( $profiles as $name => $rules )
        {
            $xml .= '<entry name="' . $name . '"><rules>';
            foreach( $rules as $ruleName => $rule )
            {
                $xml .= '<entry name="' . $ruleName . '"><application><member>any</member></application><file-type>';
                foreach( $rule[0] as $fileType )
                    $xml .= '<member>' . $fileType . '</member>';
                $xml .= '</file-type><direction>both</direction><action>' . $rule[1] . '</action></entry>';
            }
            $xml .= '</rules></entry>';
        }

        return $xml . '</root>';
    }


    public function rules_AlertOnlySet(&$add_FB_alert)
    {
        foreach( $this->rules_obj as $rule )
        {
            /** @var ThreatPolicyFileBlocking $rule */
            if( $rule->action() == "alert"
                && $rule->direction() == "both"
                && in_array("any", $rule->application() )
                && in_array("any", $rule->filetype() )
            )
            {
                $add_FB_alert = false;
                break;
            }

        }

        if( $add_FB_alert )
        {
            $tmp_name = "alert_vcp";
            $threadPolicy_obj = new ThreatPolicyFileBlocking( $tmp_name, $this);
            $threadPolicy_obj->type = "ThreatPolicyFileBlocking";

            $threadPolicy_obj->action = "alert";
            $threadPolicy_obj->direction = "both";
            $threadPolicy_obj->filetype[] = "any";
            $threadPolicy_obj->application[] = "any";

            $this->rules_obj[] = $threadPolicy_obj;
            $threadPolicy_obj->addReference( $this );

            $this->owner->owner->ThreatPolicyStore->add($threadPolicy_obj);

            $threadPolicy_obj->newThreatPolicyXML($this->xmlroot, $tmp_name, null, $threadPolicy_obj->action);
        }
    }
    public function AlertOnlySet()
    {

    }

    public function BestPractice()
    {

    }
}

