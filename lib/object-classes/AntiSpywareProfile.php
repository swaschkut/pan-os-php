<?php


/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class AntiSpywareProfile extends SecurityProfile2
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    use sp_action_spyware;

    /** @var string|null */
    protected $value;

    public $_all;

    /** @var SecurityProfileStore|null */
    public $owner;

    public $secprof_type;

    public $threatException = array();
    public $rules_obj = array();
    public $dns_rules_obj = array();
    public $lists_obj = array();
    public $additional = array();

    public $rule_coverage = array();

    public $cloud_inline_analysis_enabled = false;

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
    public function load_from_domxml(DOMElement $xml): bool
    {
        $this->secprof_type = "spyware";
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("Spyware SecurityProfile name not found\n");


        $this->load_from_domxml_spyware_rules( $xml );

        $this->load_from_domxml_spyware_inlineml( $xml );


        $this->load_from_domxml_spyware_threat_exception( $xml );

        //Todo: not for SCM
        if( get_class( $this->owner->owner ) == "PanoramaConf"
            || get_class( $this->owner->owner ) == "DeviceGroup"
            || get_class( $this->owner->owner ) == "PANConf"
            || get_class( $this->owner->owner ) == "VirtualSystem"
        )
            $this->load_from_domxml_spyware_botnet( $xml );

        return TRUE;
    }

    public function display()
    {
        PH::print_stdout( "     * " . get_class($this) . " '" . $this->name() . "'");
        PH::$JSON_TMP['sub']['object'][$this->name()]['name'] = $this->name();
        PH::$JSON_TMP['sub']['object'][$this->name()]['type'] = get_class($this);

        $this->display_as_rules();

        $this->display_as_threatException();

        if( get_class( $this->owner->owner ) == "PanoramaConf"
            || get_class( $this->owner->owner ) == "DeviceGroup"
            || get_class( $this->owner->owner ) == "PANConf"
            || get_class( $this->owner->owner ) == "VirtualSystem"
        )
            $this->display_as_additional();
    }



    static $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    static $templatexml_100 = '<entry name="**temporarynamechangeme**">
   <botnet-domains>
      <lists>
         <entry name="default-paloalto-dns">
            <action>
               <sinkhole/>
            </action>
            <packet-capture>disable</packet-capture>
         </entry>
      </lists>
      <dns-security-categories>
         <entry name="pan-dns-sec-adtracking">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
         <entry name="pan-dns-sec-cc">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
         <entry name="pan-dns-sec-ddns">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
         <entry name="pan-dns-sec-grayware">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
         <entry name="pan-dns-sec-malware">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
         <entry name="pan-dns-sec-parked">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
         <entry name="pan-dns-sec-phishing">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
         <entry name="pan-dns-sec-proxy">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
         <entry name="pan-dns-sec-recent">
            <log-level>default</log-level>
            <action>default</action>
            <packet-capture>disable</packet-capture>
         </entry>
      </dns-security-categories>
      <sinkhole>
         <ipv4-address>pan-sinkhole-default-ip</ipv4-address>
         <ipv6-address>::1</ipv6-address>
      </sinkhole>
   </botnet-domains>
   <mica-engine-spyware-enabled>
      <entry name="HTTP Command and Control detector">
         <inline-policy-action>alert</inline-policy-action>
      </entry>
      <entry name="HTTP2 Command and Control detector">
         <inline-policy-action>alert</inline-policy-action>
      </entry>
      <entry name="SSL Command and Control detector">
         <inline-policy-action>alert</inline-policy-action>
      </entry>
      <entry name="Unknown-TCP Command and Control detector">
         <inline-policy-action>alert</inline-policy-action>
      </entry>
      <entry name="Unknown-UDP Command and Control detector">
         <inline-policy-action>alert</inline-policy-action>
      </entry>
   </mica-engine-spyware-enabled>
</entry>
';

}

