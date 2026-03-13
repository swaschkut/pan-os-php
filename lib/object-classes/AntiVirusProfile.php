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
     * @throws Exception
     */
    public function setName(string $newName): bool
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    /**
     * @param string $newName
     * @throws Exception
     */
    public function API_setName(string $newName): void
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
    public function load_from_domxml(DOMElement $xml): bool
    {
        $this->secprof_type = "virus";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("Virus SecurityProfile name not found\n");


        $this->load_from_domxml_virus_decoder($xml);
        
        $this->load_from_domxml_virus_threat_exception($xml);
        
        $this->load_from_domxml_virus_inlineml($xml);

        
        return TRUE;
    }

    public function display(): void
    {
        PH::print_stdout(  "     * " . get_class($this) . " '" . $this->name() . "'    ");
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);

        //Todo: continue for print out

        $this->display_virus_decoder();

        PH::print_stdout();

        $this->display_virus_threat_exception();

        $this->display_virus_inlineml();
    }



    public function is_best_practice(): bool
    {
        if( $this->owner->owner->version >= 102 )
        {
            if ($this->av_action_best_practice()
                && $this->av_wildfireaction_best_practice()
                && $this->av_mlavaction_best_practice()
                && $this->cloud_inline_analysis_best_practice($this->owner->bp_json_file)
            )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            if ($this->av_action_best_practice()
                && $this->av_wildfireaction_best_practice()
                && $this->av_mlavaction_best_practice()
            )
                return TRUE;
            else
                return FALSE;
        }
    }

    public function is_visibility(): bool
    {
        if( $this->owner->owner->version >= 102 )
        {
            if ($this->av_action_visibility()
                && $this->av_wildfireaction_visibility()
                && $this->av_mlavaction_is_visibility()
                && $this->cloud_inline_analysis_visibility($this->owner->bp_json_file)
            )
                return TRUE;
            else
                return FALSE;
        }
        else
        {
            if ($this->av_action_visibility()
                && $this->av_wildfireaction_visibility()
                && $this->av_mlavaction_is_visibility()
            )
                return TRUE;
            else
                return FALSE;
        }
    }

    public function is_adoption(): bool
    {
        #each Anti-Virus Profile is adoption -> it must be used in SecRule

        return true;
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

