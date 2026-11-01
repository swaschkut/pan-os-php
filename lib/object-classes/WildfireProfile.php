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

    use sp_action_wildfire;


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
        $this->secprof_type = "wildfire";
        //should be:
        //$this->secprof_type = "wildfire-analysis";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("WildFire SecurityProfile name not found\n");


        $this->load_from_domxml_wf_rules($xml);

        $this->load_from_domxml_wf_inlineml($xml);

        return TRUE;
    }



    public function display(): void
    {
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);


        $this->display_wildfire();
    }





    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';


    /**
     * Base XML of the iron-skillet WildFire analysis profiles
     * (iron-skillet templates/panorama/snippets/profiles_wildfire_analysis.xml):
     * 'Outbound-WF', 'Inbound-WF', 'Internal-WF', 'Alert-Only-WF', each forwarding all files.
     * Inline cloud analysis (mica-engine-wildfire-rules):
     * - Inbound-WF, Internal-WF: block, in 11.1 and 11.2 only
     * - Alert-Only-WF: 'wf_inline_allow' with action allow in 11.1; 'wf_inline_alert' with action alert from 11.2
     *
     * @param string $version iron-skillet PAN-OS version folder, e.g. "11.1"
     * @return string
     */
    public static function ironSkilletXml( $version )
    {
        if( !in_array( $version, array( '10.0', '10.1', '10.2', '11.0', '11.1', '11.2', '12.1' ), TRUE ) )
        {
            derr( "iron-skillet WildFire analysis profiles are not available for PAN-OS version '" . $version . "'", null, false );
            return null;
        }

        // profile => array( inline rule name, action ) or null
        $inline = array( 'Outbound-WF' => null, 'Inbound-WF' => null, 'Internal-WF' => null, 'Alert-Only-WF' => null );
        if( version_compare( $version, '11.1', '>=' ) )
        {
            if( version_compare( $version, '12.1', '<' ) )
                $inline['Inbound-WF'] = $inline['Internal-WF'] = array( 'wf_inline_block', 'block' );
            $inline['Alert-Only-WF'] = ( $version === '11.1' ) ? array( 'wf_inline_allow', 'allow' ) : array( 'wf_inline_alert', 'alert' );
        }

        $xml = '<root>';
        foreach( $inline as $name => $inlineRule )
        {
            $xml .= '<entry name="' . $name . '"><rules>' . self::ironSkilletForwardAllRuleXml() . '</rules>';
            if( $inlineRule !== null )
                $xml .= '<mica-engine-wildfire-rules><entry name="' . $inlineRule[0] . '">'
                    . '<application><member>any</member></application><file-type><member>any</member></file-type>'
                    . '<direction>both</direction><action>' . $inlineRule[1] . '</action></entry></mica-engine-wildfire-rules>'
                    . '<cloud-inline-analysis>yes</cloud-inline-analysis>';
            $xml .= '</entry>';
        }

        return $xml . '</root>';
    }

    /**
     * iron-skillet WildFire rule 'Forward-All'. Also used by VirusAndWildfireProfile.
     * @return string
     */
    public static function ironSkilletForwardAllRuleXml()
    {
        return '<entry name="Forward-All"><application><member>any</member></application><file-type><member>any</member></file-type>'
            . '<direction>both</direction><analysis>public-cloud</analysis></entry>';
    }
}

