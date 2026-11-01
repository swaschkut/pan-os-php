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
                && $this->av_mlavaction_visibility()
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
                && $this->av_mlavaction_visibility()
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


    /**
     * Base XML of the iron-skillet antivirus profiles
     * (iron-skillet templates/panorama/snippets/profiles_virus.xml):
     * 'Alert-Only-AV', 'Outbound-AV', 'Inbound-AV', 'Internal-AV',
     * and 'Exception-AV' before iron-skillet 10.2.
     *
     * @param string $version iron-skillet PAN-OS version folder, e.g. "11.1"
     * @return string
     */
    public static function ironSkilletXml( $version )
    {
        if( !in_array( $version, array( '8.1', '9.1', '10.0', '10.1', '10.2', '11.0', '11.1', '11.2', '12.1' ), TRUE ) )
        {
            derr( "iron-skillet antivirus profiles are not available for PAN-OS version '" . $version . "'", null, false );
            return null;
        }

        $profiles = array(
            'Alert-Only-AV' => 'alert',
            'Outbound-AV' => 'reset-both',
            'Inbound-AV' => 'reset-both',
            'Internal-AV' => 'reset-both',
        );

        $xml = '<root>';
        foreach( $profiles as $name => $action )
            $xml .= '<entry name="' . $name . '">' . self::ironSkilletContentXml( $version, $action ) . '</entry>';

        if( version_compare( $version, '10.2', '<' ) )
            $xml .= '<entry name="Exception-AV">' . self::ironSkilletContentXml( $version, 'reset-both' )
                . '</entry>';

        return $xml . '</root>';
    }

    /**
     * Decoder and ML-AV part of an iron-skillet antivirus profile, all with one action.
     * Also used by VirusAndWildfireProfile.
     * - 9.1 and later: decoder http2
     * - 10.0 and later: mlav-action, and ML-AV models (11.1: + MachO, OOXML)
     *   MSOffice and Shell come with the content updates (content 8434 / 8543) and work on PAN-OS 10.0 and later,
     *   as the other models (predefined.xml: no minver); iron-skillet listed them in its 10.2 templates only.
     *
     * @param string $version iron-skillet PAN-OS version folder
     * @param string $action 'alert' or 'reset-both'
     * @return string
     */
    public static function ironSkilletContentXml( $version, $action )
    {
        $decoders = array( 'ftp', 'http', 'http2', 'imap', 'pop3', 'smb', 'smtp' );
        if( version_compare( $version, '9.1', '<' ) )
            $decoders = array_values( array_diff( $decoders, array( 'http2' ) ) );

        $withMlav = version_compare( $version, '10.0', '>=' );

        $xml = '<decoder>';
        foreach( $decoders as $decoder )
        {
            $xml .= '<entry name="' . $decoder . '"><action>' . $action . '</action><wildfire-action>' . $action . '</wildfire-action>';
            if( $withMlav )
                $xml .= '<mlav-action>' . $action . '</mlav-action>';
            $xml .= '</entry>';
        }
        $xml .= '</decoder>';

        if( !$withMlav )
            return $xml;

        $models = array( 'Windows Executables', 'PowerShell Script 1', 'PowerShell Script 2', 'Executable Linked Format',
            'MSOffice', 'Shell' );
        if( version_compare( $version, '11.1', '>=' ) )
            $models = array_merge( $models, array( 'MachO', 'OOXML' ) );

        $policyAction = ( $action == 'alert' ) ? 'enable(alert-only)' : 'enable';

        $xml .= '<mlav-engine-filebased-enabled>';
        foreach( $models as $model )
            $xml .= '<entry name="' . $model . '"><mlav-policy-action>' . $policyAction . '</mlav-policy-action></entry>';
        $xml .= '</mlav-engine-filebased-enabled>';

        return $xml;
    }
}

