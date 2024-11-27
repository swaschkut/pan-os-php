<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class AntiVirusProfile extends SecurityProfile2
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

    public $ftp = array();
    public $http = array();
    public $http2 = array();
    public $imap = array();
    public $pop3 = array();
    public $smb = array();
    public $smtp = array();

    public $threatException = array();
    public $additional = array();


    public $tmp_virus_prof_array = array('http', 'http2','smtp', 'imap', 'pop3', 'ftp', 'smb');

    public $tmp_virus_prof_mica_array = array('Windows Executables', 'PowerShell Script 1', 'PowerShell Script 2', 'Executable Linked Format', 'MSOffice', 'Shell', 'OOXML', 'MachO');


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
        $this->secprof_type = "virus";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("Virus SecurityProfile name not found\n");

        #print "\nsecprofURL TMP: object named '".$this->name."' found\n";

        #$this->owner->_SecurityProfiles[$this->name] = $this;
        #$this->owner->_all[$this->name] = $this;
        #$this->owner->o[] = $this;


        //predefined URL category
        //$tmp_array[$this->secprof_type][$typeName]['allow']['URL category'] = all predefined URL category


        $tmp_decoder = DH::findFirstElement('decoder', $xml);
        if( $tmp_decoder !== FALSE )
        {
            $tmp_array = array();

            $tmp_decoder_http2_found = false;
            foreach( $tmp_decoder->childNodes as $tmp_entry )
            {
                if( $tmp_entry->nodeType != XML_ELEMENT_NODE )
                    continue;


                $appName = DH::findAttribute('name', $tmp_entry);
                if( $appName == "http2" )
                    $tmp_decoder_http2_found = true;
                if( $appName === FALSE )
                    derr("Virus SecurityProfile decoder name not found\n");

                $action = DH::findFirstElement('action', $tmp_entry);
                if( $action !== FALSE )
                {
                    $this->$appName['action'] = $action->textContent;
                }
                else
                {
                    $this->$appName['action'] = "----";
                }


                $action_wildfire = DH::findFirstElement('wildfire-action', $tmp_entry);
                if( $action_wildfire !== FALSE )
                {
                    $this->$appName['wildfire-action'] = $action_wildfire->textContent;
                }
                else
                {
                    $this->$appName['wildfire-action'] = "----";
                }

                $action_mlav_action = DH::findFirstElement('mlav-action', $tmp_entry);
                if( $action_mlav_action !== FALSE )
                {
                    $this->$appName['mlav-action'] = $action_mlav_action->textContent;
                }
                else
                {
                    $this->$appName['mlav-action'] = "----";
                }
            }

            $http2_xml_string = '<entry name="http2">
  <action>allow</action>
  <wildfire-action>allow</wildfire-action>
  <mlav-action>allow</mlav-action>
</entry>';

            if( !$tmp_decoder_http2_found && $this->owner->owner->version >= 90 )
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $http2_xml_string);
                $tmp_decoder->appendChild($xmlElement);

                $this->http2['action'] = "allow";
                $this->http2['wildfire-action'] = "allow";
                $this->http2['mlav-action'] = "allow";
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

        $tmp_rule = DH::findFirstElement('mlav-engine-filebased-enabled', $xml);
        if( $tmp_rule !== FALSE && !$tmp_rule->hasChildNodes() )
        {
            $xml->removeChild($tmp_rule);
            $tmp_rule = DH::findFirstElement('mlav-engine-filebased-enabled', $xml);
        }

        if( $tmp_rule !== FALSE )
        {
            $this->additional['mlav-engine-filebased-enabled'] = array();
            $tmp_mica_OOXML_found = false;
            $tmp_mica_MachO_found = false;
            foreach( $tmp_rule->childNodes as $tmp_entry1 )
            {
                if ($tmp_entry1->nodeType != XML_ELEMENT_NODE)
                    continue;

                $name = DH::findAttribute("name", $tmp_entry1);
                if( $name == "OOXML" )
                    $tmp_mica_OOXML_found = TRUE;
                elseif( $name == "MachO" )
                    $tmp_mica_MachO_found = TRUE;

                $tmp_inline_policy_action = DH::findFirstElement("mlav-policy-action", $tmp_entry1);
                if( $tmp_inline_policy_action !== FALSE )
                    $this->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action'] = $tmp_inline_policy_action->textContent;
                else
                {
                    $tmp_inline_policy_action = DH::findFirstElementOrCreate("mlav-policy-action", $tmp_entry1);
                    $tmp_inline_policy_action->textContent = "disable";
                    $this->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action'] = "disable";
                }
            }

            $OOXML_xmlstring = '<entry name="OOXML">
  <mlav-policy-action>disable</mlav-policy-action>
</entry>';
            $MachO_xmlstring = '<entry name="MachO">
  <mlav-policy-action>disable</mlav-policy-action>
</entry>';

            if( !$tmp_mica_OOXML_found && $this->owner->owner->version >= 111)
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $OOXML_xmlstring);
                $tmp_rule->appendChild($xmlElement);

                $this->additional['mlav-engine-filebased-enabled']['OOXML']['mlav-policy-action'] = "disable";
            }
            if( !$tmp_mica_MachO_found && $this->owner->owner->version >= 111 )
            {
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $MachO_xmlstring);
                $tmp_rule->appendChild($xmlElement);

                $this->additional['mlav-engine-filebased-enabled']['MachO']['mlav-policy-action'] = "disable";
            }
        }
        else
        {
            $xmlstring = '<mlav-engine-filebased-enabled>
  <entry name="Windows Executables">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="PowerShell Script 1">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="PowerShell Script 2">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="Executable Linked Format">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="MSOffice">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="Shell">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
</mlav-engine-filebased-enabled>';

            $xmlstring_111 = '<mlav-engine-filebased-enabled>
  <entry name="Windows Executables">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="PowerShell Script 1">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="PowerShell Script 2">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="Executable Linked Format">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="MSOffice">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="Shell">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="OOXML">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
  <entry name="MachO">
    <mlav-policy-action>disable</mlav-policy-action>
  </entry>
</mlav-engine-filebased-enabled>';

            if( $this->owner->owner->version >= 111 )
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlstring_111);
            elseif( $this->owner->owner->version >= 100 )
                $xmlElement = DH::importXmlStringOrDie($this->xmlroot->ownerDocument, $xmlstring);

            if( $this->owner->owner->version >= 100 )
                $xml->appendChild($xmlElement);

            if( $this->owner->owner->version >= 100 )
            {
                $this->additional['mlav-engine-filebased-enabled']['Windows Executables']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['PowerShell Script 1']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['PowerShell Script 2']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['Executable Linked Format']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['MSOffice']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['Shell']['mlav-policy-action'] = "disable";
            }
            if( $this->owner->owner->version >= 111 )
            {
                $this->additional['mlav-engine-filebased-enabled']['OOXML']['mlav-policy-action'] = "disable";
                $this->additional['mlav-engine-filebased-enabled']['MachO']['mlav-policy-action'] = "disable";
            }
        }

        return TRUE;
    }

    public function display()
    {
        PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'    ");
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);

        //Todo: continue for print out

        foreach( $this->tmp_virus_prof_array as $key => $type )
        {
            PH::print_stdout(  "       o " . PH::boldText($type) );
            //was not set in specific config files
            if( isset( $this->$type['action'] ) )
            {
                PH::print_stdout(  "          - action:          '" . $this->$type['action'] . "'");
                PH::$JSON_TMP['sub']['object'][$this->name()]['decoder'][$type]['action'] = $this->$type['action'];
            }

            if( isset( $this->$type['wildfire-action'] ) )
            {
                PH::print_stdout(  "          - wildfire-action: '" . $this->$type['wildfire-action'] . "'" );
                PH::$JSON_TMP['sub']['object'][$this->name()]['decoder'][$type]['wildfire-action'] = $this->$type['wildfire-action'];
            }

            if( isset( $this->$type['mlav-action'] ) )
            {
                PH::print_stdout(  "          - mlav-action: '" . $this->$type['mlav-action'] . "'" );
                PH::$JSON_TMP['sub']['object'][$this->name()]['decoder'][$type]['mlav-action'] = $this->$type['mlav-action'];
            }
        }

        PH::print_stdout();

        if( !empty( $this->threatException ) )
        {
            PH::print_stdout("        - threat-exception:" );

            foreach( $this->threatException as $threatname => $threat )
            {
                PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['name'] = $threat['name'];

                $string = "             '" . $threat['name'] . "'";
                if( isset( $threat['action'] ) )
                {
                    $string .= "  - action : ".$threat['action'];
                    PH::$JSON_TMP['sub']['object'][$this->name()]['threat-exception'][$threatname]['action'] = $threat['action'];
                }

                PH::print_stdout(  $string );
            }
        }

        if( !empty( $this->additional['mlav-engine-filebased-enabled'] ) )
        {
            if( !empty( $this->additional['mlav-engine-filebased-enabled'] ) )
            {
                PH::print_stdout("        ----------------------------------------");
                PH::print_stdout("        - mlav-engine-filebased-enabled: ");

                foreach ($this->additional['mlav-engine-filebased-enabled'] as $name => $threat)
                    PH::print_stdout("          * " . $name . " - mlav-policy-action :" . $this->additional['mlav-engine-filebased-enabled'][$name]['mlav-policy-action']);
            }
        }
    }


    public function virus_bp_visibility_JSON( $checkType, $av_action_type )
    {
        #print "checktype: ".$checkType." -".$av_action_type."\n";
        //Todo: swaschkut 20241126
        //if file already read store it complete at UTIL and read array from there

        $secprof_type = "virus";
        $checkArray = array();

        if( $checkType !== "bp" && $checkType !== "visibility" )
            derr( "only 'bp' or 'visibility' argument allowed" );

        if( $av_action_type !== "action" && $av_action_type !== "wildfire-action" && $av_action_type !== "mlav-action")
            derr( "only 'action' or 'wildfire-action' or 'mlav-action' argument allowed as av_action_type" );

        ###############################
        //add bp JSON filename to UTIL???
        //so this can be flexible if customer like to use its own file

        //get actual file space
        $filename = dirname(__FILE__)."/../../utils/api/v1/bp/bp_sp_panw.json";
        $JSONarray = file_get_contents( $filename);

        if( $JSONarray === false )
            derr("cannot open file '{$filename}");

        $details = json_decode($JSONarray, true);

        if( $details === null )
            derr( "invalid JSON file provided", null, FALSE );

        if( isset($details[$secprof_type]['rule']) )
        {
            if( $checkType == "bp" )
            {
                if( isset($details[$secprof_type]['rule']['bp'][$av_action_type]))
                    $checkArray = $details[$secprof_type]['rule']['bp'][$av_action_type];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'bp' -> 'rule' defined correctly for: '".$secprof_type."' '".[$av_action_type]."'", null, FALSE );
            }
            elseif( $checkType == "visibility")
            {
                if( isset($details[$secprof_type]['rule']['visibility'][$av_action_type]))
                    $checkArray = $details[$secprof_type]['rule']['visibility'][$av_action_type];
                else
                    derr( "this JSON bp/visibility JSON file does not have 'visibility' -> 'rule' defined correctly for: '".$secprof_type."' '".[$av_action_type]."'", null, FALSE );
            }
        }

        return $checkArray;
    }

    public function check_bp_json($av_type, $check_array, $av_type_action)
    {
        if (in_array($av_type, $check_array['type']))
        {
            //action check
            foreach ($check_array['action'] as $validate_action)
            {
                $negate_string = "";
                if (strpos($validate_action, "!") !== FALSE)
                    $negate_string = "!";
                if ($negate_string . $this->$av_type[$av_type_action] === $validate_action)
                    $bestpractise = TRUE;
                else
                    $bestpractise = FALSE;
            }
        }
        else
        {
            foreach ($check_array['action-not-matching-type'] as $validate_action)
            {
                $negate_string = "";
                if (strpos($validate_action, "!") !== FALSE)
                    $negate_string = "!";
                if ($negate_string . $this->$av_type[$av_type_action] === $validate_action)
                    $bestpractise = TRUE;
                else
                    $bestpractise = FALSE;
            }
        }

        return $bestpractise;
    }

    public function check_visibility_json($av_type, $check_array, $av_type_action)
    {
        foreach( $check_array as $validate )
        {
            $negate_string = "";
            if( strpos($validate, "!" ) !== FALSE )
                $negate_string = "!";
            if( $negate_string.$this->$av_type[$av_type_action] === $validate)
                $bestpractise = FALSE;
            else
                $bestpractise = TRUE;
        }

        return $bestpractise;
    }

    public function av_action_best_practice()
    {
        /*
        $bestpractise = FALSE;

        if( $this->secprof_type != 'virus' )
            return null;

        $av_type_action = "action";
        $check_array = $this->virus_bp_visibility_JSON( "bp", $av_type_action );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_type_action] ) )
                {
                    $bestpractise = $this->check_bp_json($type, $check_array, $av_type_action);

                    if ($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }


        return $bestpractise;
        */
        return $this->av_general_action_best_practice( "action" );
    }

    public function av_action_visibility()
    {
        /*
        $bestpractise = FALSE;

        if( $this->secprof_type != 'virus' )
            return null;

        $av_type_action = "action";
        $check_array = $this->virus_bp_visibility_JSON( "visibility", $av_type_action );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset($this->$type['action']) )
                {
                    $bestpractise = $this->check_visibility_json($type, $check_array, $av_type_action);

                    if($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
        */
        return $this->av_general_action_visibility( "action" );
    }

    public function av_wildfireaction_best_practice()
    {
        /*
        $bestpractise = FALSE;

        if( $this->secprof_type != 'virus' )
            return null;

        $av_type_action = "wildfire-action";
        $check_array = $this->virus_bp_visibility_JSON( "bp", $av_type_action );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_type_action] ) )
                {
                    $bestpractise = $this->check_bp_json($type, $check_array, $av_type_action);

                    if ($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
        */
        return $this->av_general_action_best_practice( "wildfire-action" );
    }

    public function av_wildfireaction_visibility()
    {
        /*
        $bestpractise = FALSE;

        if( $this->secprof_type != 'virus' )
            return null;

        $av_type_action = "wildfire-action";
        $check_array = $this->virus_bp_visibility_JSON( "visibility", $av_type_action );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_type_action] ) )
                {
                    $bestpractise = $this->check_visibility_json($type, $check_array, $av_type_action);

                    if($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
        */
        return $this->av_general_action_visibility( "wildfire-action" );
    }

    public function av_mlavaction_best_practice()
    {
        /*
        $bestpractise = FALSE;

        if( $this->secprof_type != 'virus' )
            return null;

        $av_type_action = "mlav-action";
        $check_array = $this->virus_bp_visibility_JSON( "bp", $av_type_action );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_type_action] ) )
                {
                    $bestpractise = $this->check_bp_json($type, $check_array, $av_type_action);

                    if($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
        */
        return $this->av_general_action_best_practice( "mlav-action" );
    }

    public function av_mlavaction_is_visibility()
    {
        /*
        $bestpractise = FALSE;

        if( $this->secprof_type != 'virus' )
            return null;

        $av_type_action = "mlav-action";
        $check_array = $this->virus_bp_visibility_JSON( "visibility", $av_type_action );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_type_action] ) )
                {
                    $bestpractise = $this->check_visibility_json($type, $check_array, $av_type_action);

                    if($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
        */
        return $this->av_general_action_visibility( "mlav-action" );
    }


    public function av_general_action_best_practice( $av_type_action )
    {
        if( $av_type_action != "action" && $av_type_action != "wildfire-action" && $av_type_action != "mlav-action")
            derr( "only support specific valued like action / wildfire-action / mlav-action" );

        $bestpractise = FALSE;

        if( $this->secprof_type != 'virus' )
            return null;

        $av_type_action = "mlav-action";
        $check_array = $this->virus_bp_visibility_JSON( "bp", $av_type_action );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_type_action] ) )
                {
                    $bestpractise = $this->check_bp_json($type, $check_array, $av_type_action);

                    if($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
    }

    public function av_general_action_visibility( $av_type_action )
    {
        if( $av_type_action != "action" && $av_type_action != "wildfire-action" && $av_type_action != "mlav-action")
            derr( "only support specific valued like action / wildfire-action / mlav-action" );

        $bestpractise = FALSE;

        if( $this->secprof_type != 'virus' )
            return null;

        $check_array = $this->virus_bp_visibility_JSON( "visibility", $av_type_action );

        if( isset($this->tmp_virus_prof_array) )
        {
            foreach( $this->tmp_virus_prof_array as $key => $type )
            {
                if( isset( $this->$type[$av_type_action] ) )
                {
                    $bestpractise = $this->check_visibility_json($type, $check_array, $av_type_action);

                    if($bestpractise == FALSE)
                        return FALSE;
                }
            }
        }

        return $bestpractise;
    }

    public function is_best_practice()
    {
        if( $this->owner->owner->version >= 102 )
        {
            if ($this->av_action_best_practice() && $this->av_wildfireaction_best_practice() && $this->av_mlavaction_best_practice()
                && $this->cloud_inline_analysis_best_practice()
                #&& $this->vulnerability_exception_best_practice()
            )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            if ($this->av_action_best_practice() && $this->av_wildfireaction_best_practice() && $this->av_mlavaction_best_practice()
                #&& $this->vulnerability_exception_best_practice()
            )
                return TRUE;
            else
                return FALSE;
        }
    }

    public function is_visibility()
    {
        if( $this->owner->owner->version >= 102 )
        {
            if ($this->av_action_visibility() && $this->av_wildfireaction_visibility() && $this->av_mlavaction_is_visibility()
                && $this->cloud_inline_analysis_visibility()
            )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            if ($this->av_action_visibility() && $this->av_wildfireaction_visibility() && $this->av_mlavaction_is_visibility()
            )
                return TRUE;
            else
                return FALSE;
        }
    }

    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    static $templatexml_100 = '<entry name="**temporarynamechangeme**">
   <decoder>
      <entry name="ftp">
         <action>default</action>
         <wildfire-action>default</wildfire-action>
         <mlav-action>default</mlav-action>
      </entry>
      <entry name="http">
         <action>default</action>
         <wildfire-action>default</wildfire-action>
         <mlav-action>default</mlav-action>
      </entry>
      <entry name="http2">
         <action>default</action>
         <wildfire-action>default</wildfire-action>
         <mlav-action>default</mlav-action>
      </entry>
      <entry name="imap">
         <action>default</action>
         <wildfire-action>default</wildfire-action>
         <mlav-action>default</mlav-action>
      </entry>
      <entry name="pop3">
         <action>default</action>
         <wildfire-action>default</wildfire-action>
         <mlav-action>default</mlav-action>
      </entry>
      <entry name="smb">
         <action>default</action>
         <wildfire-action>default</wildfire-action>
         <mlav-action>default</mlav-action>
      </entry>
      <entry name="smtp">
         <action>default</action>
         <wildfire-action>default</wildfire-action>
         <mlav-action>default</mlav-action>
      </entry>
   </decoder>
   <mlav-engine-filebased-enabled>
      <entry name="Windows Executables">
         <mlav-policy-action>disable</mlav-policy-action>
      </entry>
      <entry name="PowerShell Script 1">
         <mlav-policy-action>disable</mlav-policy-action>
      </entry>
      <entry name="PowerShell Script 2">
         <mlav-policy-action>disable</mlav-policy-action>
      </entry>
      <entry name="Executable Linked Format">
         <mlav-policy-action>disable</mlav-policy-action>
      </entry>
      <entry name="MSOffice">
         <mlav-policy-action>disable</mlav-policy-action>
      </entry>
      <entry name="Shell">
         <mlav-policy-action>disable</mlav-policy-action>
      </entry>
      <entry name="OOXML">
         <mlav-policy-action>disable</mlav-policy-action>
      </entry>
      <entry name="MachO">
         <mlav-policy-action>disable</mlav-policy-action>
      </entry>
   </mlav-engine-filebased-enabled>
</entry>
';

}

