<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class VirusAndWildfireProfile extends SecurityProfile2
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    use sp_action_wildfire;
    use sp_action_virus;

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

    public $rules_obj = array();

    public $rule_coverage = array();

    public $cloud_inline_analysis_enabled = false;

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

        if( $c->isAPI())
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml): bool
    {
        $this->secprof_type = "virus-and-wildfire-analysis";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("VirusAndWildFire SecurityProfile name not found\n");


        $this->load_from_domxml_virus_decoder($xml);

        $this->load_from_domxml_wf_rules($xml);

        $this->load_from_domxml_wf_inlineml($xml);


        $this->load_from_domxml_virus_threat_exception($xml);

        $this->load_from_domxml_virus_inlineml($xml);


        return TRUE;
    }

    public function display(): void
    {
        PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'    ");
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);
        //Todo: continue for PH::print_stdout( ); out

        $this->display_virus_decoder();

        PH::print_stdout();

        $this->display_virus_threat_exception();

        $this->display_virus_inlineml();

        PH::print_stdout();
        PH::print_stdout();
        $this->display_wildfire();
    }

    public function is_best_practice(): bool
    {
        return false;
    }

    public function is_visibility(): bool
    {
        return false;
    }

    public function is_adoption(): bool
    {
        return false;
    }

    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

}

