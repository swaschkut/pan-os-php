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


    /**
     * Base XML of the iron-skillet anti-spyware profiles
     * (iron-skillet templates/panorama/snippets/profiles_spyware.xml):
     * 'Outbound-AS', 'Inbound-AS', 'Internal-AS', 'Alert-Only-AS',
     * and 'Exception-AS' before iron-skillet 10.2.
     *
     * @param string $version iron-skillet PAN-OS version folder, e.g. "11.1"
     * @return string
     */
    public static function ironSkilletXml( $version )
    {
        if( !in_array( $version, array( '8.1', '9.1', '10.0', '10.1', '10.2', '11.0', '11.1', '11.2', '12.1' ), TRUE ) )
        {
            derr( "iron-skillet anti-spyware profiles are not available for PAN-OS version '" . $version . "'", null, false );
            return null;
        }

        return self::ironSkilletBuildXml( $version, TRUE );
    }

    /**
     * Base XML of the iron-skillet anti-spyware profiles for SCM
     * (iron-skillet panos_v11.1 templates/panorama/snippets/profiles_spyware_scm.xml):
     * the same profiles as ironSkilletXml(), without 'botnet-domains'.
     *
     * @param string $version iron-skillet PAN-OS version folder, only "11.1"
     * @return string
     */
    public static function ironSkilletXmlScm( $version )
    {
        if( $version !== '11.1' )
        {
            derr( "iron-skillet SCM anti-spyware profiles are not available for PAN-OS version '" . $version . "'", null, false );
            return null;
        }

        return self::ironSkilletBuildXml( $version, FALSE );
    }

    /**
     * 'botnet-domains' part of an iron-skillet anti-spyware profile. Also used by DNSSecurityProfile.
     * - 8.1: list default-paloalto-dns, sinkhole IPv4 72.5.65.111, packet capture on botnet-domains
     * - 9.1: lists default-paloalto-cloud and default-paloalto-dns
     * - 10.0 and later: list default-paloalto-dns and DNS security categories (10.1: 8 categories)
     *
     * @param string $version iron-skillet PAN-OS version folder
     * @param string $mode 'block', 'alert' or 'exception'
     * @return string
     */
    public static function ironSkilletBotnetDomainsXml( $version, $mode )
    {
        $listAction = ( $mode == 'alert' ) ? 'alert' : 'sinkhole';
        $ipv4 = version_compare( $version, '9.1', '<' ) ? '72.5.65.111' : 'sinkhole.paloaltonetworks.com';
        $sinkhole = '<sinkhole><ipv4-address>' . $ipv4 . '</ipv4-address><ipv6-address>2600:5200::1</ipv6-address></sinkhole>';

        if( version_compare( $version, '9.1', '<' ) )
            return '<botnet-domains>'
                . '<lists><entry name="default-paloalto-dns"><action><' . $listAction . '/></action></entry></lists>'
                . $sinkhole
                . '<packet-capture>' . ( $mode == 'alert' ? 'disable' : 'single-packet' ) . '</packet-capture>'
                . '</botnet-domains>';

        if( version_compare( $version, '10.0', '<' ) )
        {
            $capture = ( $mode == 'block' ) ? 'single-packet' : 'disable';
            $xml = '<botnet-domains><lists>';
            foreach( array( 'default-paloalto-cloud', 'default-paloalto-dns' ) as $list )
                $xml .= '<entry name="' . $list . '"><packet-capture>' . $capture . '</packet-capture><action><' . $listAction . '/></action></entry>';
            return $xml . '</lists>' . $sinkhole . '</botnet-domains>';
        }

        // DNS security category => array( action, packet-capture ) of the blocking profiles
        $categories = array(
            'pan-dns-sec-cc' => array( 'sinkhole', 'single-packet' ),
            'pan-dns-sec-ddns' => array( 'default', 'single-packet' ),
            'pan-dns-sec-grayware' => array( 'sinkhole', 'single-packet' ),
            'pan-dns-sec-malware' => array( 'sinkhole', 'single-packet' ),
            'pan-dns-sec-parked' => array( 'default', 'disable' ),
            'pan-dns-sec-phishing' => array( 'sinkhole', 'single-packet' ),
            'pan-dns-sec-proxy' => array( 'sinkhole', 'single-packet' ),
            'pan-dns-sec-recent' => array( 'default', 'single-packet' ),
        );
        if( version_compare( $version, '10.1', '<' ) )
            $categories = array_intersect_key( $categories, array_flip( array( 'pan-dns-sec-cc', 'pan-dns-sec-ddns', 'pan-dns-sec-malware', 'pan-dns-sec-recent' ) ) );

        $xml = '<botnet-domains><lists><entry name="default-paloalto-dns"><action><' . $listAction . '/></action>'
            . '<packet-capture>' . ( $mode == 'exception' ? 'disable' : 'single-packet' ) . '</packet-capture></entry></lists>'
            . '<dns-security-categories>';
        foreach( $categories as $category => $values )
        {
            if( $mode == 'alert' )
                $values = array( 'allow', 'single-packet' );
            elseif( $mode == 'exception' )
                $values = array( 'default', 'disable' );

            $xml .= '<entry name="' . $category . '"><log-level>default</log-level>'
                . '<action>' . $values[0] . '</action><packet-capture>' . $values[1] . '</packet-capture></entry>';
        }

        return $xml . '</dns-security-categories>' . $sinkhole . '</botnet-domains>';
    }

    /**
     * @param string $version
     * @param bool $withBotnetDomains FALSE for SCM
     * @return string
     */
    private static function ironSkilletBuildXml( $version, $withBotnetDomains )
    {
        $blockRules = array(
            'Block-Critical-High-Medium' => array( 'reset-both', array( 'critical', 'high', 'medium' ), 'single-packet' ),
            'Default-Low-Info' => array( 'default', array( 'low', 'informational' ), 'disable' ),
        );
        $profiles = array(
            'Outbound-AS' => array( 'block', $blockRules ),
            'Inbound-AS' => array( 'block', $blockRules ),
            'Internal-AS' => array( 'block', array(
                'Block-Critical-High' => array( 'reset-both', array( 'critical', 'high' ), 'single-packet' ),
                'Default-Medium-Low-Info' => array( 'default', array( 'medium', 'low', 'informational' ), 'disable' ),
            ) ),
            'Alert-Only-AS' => array( 'alert', array(
                'Alert-All' => array( 'alert', array( 'any' ), 'disable' ),
            ) ),
        );
        if( version_compare( $version, '10.2', '<' ) )
            $profiles['Exception-AS'] = array( 'exception', array() );

        $detectors = array( 'HTTP', 'HTTP2', 'SSL', 'Unknown-TCP', 'Unknown-UDP' );

        $xml = '<root>';
        foreach( $profiles as $name => $profile )
        {
            list( $mode, $rules ) = $profile;

            $xml .= '<entry name="' . $name . '">';
            if( $mode == 'exception' && version_compare( $version, '10.0', '>=' ) )
                $xml .= '<description>Used for exception cases not part of the recommended practice</description>';

            if( $withBotnetDomains )
                $xml .= self::ironSkilletBotnetDomainsXml( $version, $mode );

            if( !empty( $rules ) )
            {
                $xml .= '<rules>';
                foreach( $rules as $ruleName => $rule )
                {
                    $xml .= '<entry name="' . $ruleName . '"><action><' . $rule[0] . '/></action><severity>';
                    foreach( $rule[1] as $severity )
                        $xml .= '<member>' . $severity . '</member>';
                    $xml .= '</severity><threat-name>any</threat-name><category>any</category>'
                        . '<packet-capture>' . $rule[2] . '</packet-capture></entry>';
                }
                $xml .= '</rules>';
            }

            if( version_compare( $version, '10.2', '>=' ) )
            {
                $xml .= '<mica-engine-spyware-enabled>';
                foreach( $detectors as $detector )
                {
                    $xml .= '<entry name="' . $detector . ' Command and Control detector">'
                        . '<inline-policy-action>' . ( $mode == 'alert' ? 'alert' : 'reset-both' ) . '</inline-policy-action>';
                    if( version_compare( $version, '11.2', '>=' ) )
                        $xml .= '<local-deep-learning>enable</local-deep-learning>';
                    $xml .= '</entry>';
                }
                $xml .= '</mica-engine-spyware-enabled><cloud-inline-analysis>yes</cloud-inline-analysis>';
            }

            $xml .= '</entry>';
        }

        return $xml . '</root>';
    }
}

