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

    public $tmp_array;

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

        #PH::print_stdout(  "\nsecprofURL TMP: object named '".$this->name."' found" );

        #$this->owner->_SecurityProfiles[$this->secprof_type][$this->name] = $this;
        #$this->owner->_all[$this->secprof_type][$this->name] = $this;
        #$this->owner->o[] = $this;


        //predefined URL category
        //$tmp_array[$this->secprof_type][$typeName]['allow']['URL category'] = all predefined URL category


        /*
        <entry name="Alert-All">
           <application>
              <member>any</member>
           </application>
           <file-type>
              <member>any</member>
           </file-type>
           <direction>both</direction>
           <action>alert</action>
        </entry>

         */

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


                $application = DH::findFirstElement('application', $tmp_entry1);
                if( $application !== FALSE )
                {
                    if( $application->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['application'] = array();
                    foreach( $application->childNodes as $member )
                    {
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['application'][$member->textContent] = $member->textContent;
                    }
                }


                $severity = DH::findFirstElement('file-type', $tmp_entry1);
                if( $severity !== FALSE )
                {
                    if( $severity->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['file-type'] = array();
                    foreach( $severity->childNodes as $member )
                    {
                        if( $member->nodeType != XML_ELEMENT_NODE )
                            continue;

                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['file-type'][$member->textContent] = $member->textContent;
                    }
                }

                $action = DH::findFirstElement('action', $tmp_entry1);
                if( $action !== FALSE )
                {
                    if( $action->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_action = DH::firstChildElement($action);
                    if( $tmp_action !== FALSE )
                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['action'] = $tmp_action->nodeName;

                    if( $this->secprof_type == 'file-blocking' )
                        $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['action'] = $action->textContent;
                }

                $direction = DH::findFirstElement('direction', $tmp_entry1);
                if( $direction !== FALSE )
                {
                    if( $direction->nodeType != XML_ELEMENT_NODE )
                        continue;

                    $tmp_array[$this->secprof_type][$this->name]['rules'][$vb_severity]['direction'] = $direction->textContent;
                }
            }
        }

        $this->tmp_array = $tmp_array;

        return TRUE;
    }

    public function display()
    {
        #PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'    ");
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);
        //Todo: continue for PH::print_stdout( ); out

        #print_r( $this->tmp_array );
        foreach( $this->tmp_array['file-blocking'][$this->name()]['rules'] as $ruleName => $rule )
        {
            PH::print_stdout("     * ".$ruleName." | application : '". implode(", ", $rule['application'])."' | file-type: '". implode(", ", $rule['file-type']). "' | direction: '".$rule['direction']."' | action: '".$rule['action']."'");
        }

    }


    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

