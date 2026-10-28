<?php


class ThreatStore extends ObjStore
{
    /** @var array|Threat[] */
    public $vulnerability = array();

    /** @var array|Threat[] */
    public $phoneHome = array();

    public $predefinedStore_threat_version = null;

    public static $childn = 'Threat';

    /** @var null|ThreatStore */
    public static $predefinedStore = null;

    /**
     * @return ThreatStore|null
     */
    public static function getPredefinedStore( $owner )
    {
        if( self::$predefinedStore !== null )
            return self::$predefinedStore;

        self::$predefinedStore = new ThreatStore( $owner );
        self::$predefinedStore->setName('predefined Threats');
        // ~35 000 threats: read from predefined.xml on first use only, see ensureLoaded()
        self::$predefinedStore->loadPredefinedOnFirstUse = TRUE;

        return self::$predefinedStore;
    }

    /** @var bool the predefined threats are not read yet, ensureLoaded() reads them */
    public $loadPredefinedOnFirstUse = FALSE;

    public function ensureLoaded(): void
    {
        if( !$this->loadPredefinedOnFirstUse )
            return;
        $this->loadPredefinedOnFirstUse = FALSE;
        $this->load_from_predefinedfile();
    }

    public function count()
    {
        $this->ensureLoaded();
        return parent::count();
    }

    public function countUnused()
    {
        $this->ensureLoaded();
        return parent::countUnused();
    }

    public function find($name, $ref = null, $nested = TRUE)
    {
        $this->ensureLoaded();
        return parent::find($name, $ref, $nested);
    }

    public function findOrCreate($name, $ref = null)
    {
        $this->ensureLoaded();
        return parent::findOrCreate($name, $ref);
    }

    public function inStore($Obj)
    {
        $this->ensureLoaded();
        return parent::inStore($Obj);
    }

    public function getAll()
    {
        $this->ensureLoaded();
        return parent::getAll();
    }

    public function display($indentSpace = 0)
    {
        $this->ensureLoaded();
        return parent::display($indentSpace);
    }

    public function &resultingObjectSet()
    {
        $this->ensureLoaded();
        $ret = &parent::resultingObjectSet();
        return $ret;
    }

    /**
     * XML of a predefined threat (the DOM is not kept after loading, see load_from_predefinedfile()).
     * @return DOMElement|null
     */
    public function predefinedThreatXml( Threat $threat )
    {
        if( $threat->xmlroot !== null )
            return $threat->xmlroot;

        // only 'display-xml' needs it: the section is read once, then kept for further threats
        if( $this->predefinedThreatsXml === null )
            $this->predefinedThreatsXml = PH::getPredefinedXmlDoc( null, array('threats') );

        $name = $threat->name();
        foreach( array('vulnerability', 'phone-home') as $section )
        {
            $node = DH::findXPathSingleEntry( "/predefined/threats/".$section."/entry[@name=".self::xpathLiteral($name)."]", $this->predefinedThreatsXml );
            if( $node !== FALSE && $node !== null )
                return $node;
        }
        return null;
    }

    /** @var DOMDocument|null 'threats' section of predefined.xml, read by predefinedThreatXml() on first use */
    private $predefinedThreatsXml = null;

    private static function xpathLiteral( $value ): string
    {
        if( strpos($value, "'") === FALSE )
            return "'".$value."'";
        if( strpos($value, '"') === FALSE )
            return '"'.$value.'"';
        return "concat('".str_replace("'", "',\"'\",'", $value)."')";
    }

    public function load_phone_home_entry( DOMElement $threatx ): Threat
    {
        $threatName = DH::findAttribute('name', $threatx);
        if( $threatName === FALSE )
            derr("threat name not found\n");

        $threat = new ThreatSpyware($threatName, $this);
        $threat->type = 'spyware';
        $threat->xmlroot = $threatx;
        $threat->spyware_load_from_domxml( $threatx );

        $this->add($threat);

        $this->phoneHome[] = $threat;

        return $threat;
    }


    public function __construct($owner)
    {
        $this->classn = &self::$childn;

        $this->owner = $owner;
        #$this->o = &$this->apps;
        $this->o = array();

    }

    public function load_from_predefinedfile($filename = null)
    {
        if( $filename === null )
        {
            $filename = dirname(__FILE__) . '/predefined.xml';
        }

        if( realpath($filename) === realpath(dirname(__FILE__) . '/predefined.xml') )
        {
            // streamed entry by entry: the 'threats' section (~15 MB XML, ~130 MB as DOM) is never held as a whole
            $store = $this;
            foreach( array('vulnerability' => 'load_vulnerability_entry', 'phone-home' => 'load_phone_home_entry') as $section => $method )
            {
                $found = PH::eachPredefinedEntry( array('threats', $section), function( $name, $threatx ) use ( $store, $method )
                {
                    // node not kept: each entry has its own small document, freed right away
                    $store->$method( $threatx )->xmlroot = null;
                } );
                if( !$found )
                    derr( "cannot find /predefined/threats/".$section." in '".$filename."'", null, FALSE );
            }
        }
        else
        {
            $xmlDoc = PH::getPredefinedXmlDoc($filename);

            $cursor = DH::findXPathSingleEntryOrDie('/predefined/threats/vulnerability', $xmlDoc);
            $this->load_vulnerability_from_domxml($cursor);

            $cursor = DH::findXPathSingleEntryOrDie('/predefined/threats/phone-home', $xmlDoc);
            $this->load_phone_home_containers_from_domxml($cursor);
        }

        // threats are completely parsed into their properties; dropping the node pointers frees the DOM of the
        // 'threats' section (~130 MB). 'display-xml' reads the node again, see predefinedThreatXml().
        foreach( $this->o as $threat )
            $threat->xmlroot = null;


        #$appid_version = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);
        #self::$predefinedStore->predefinedStore_appid_version = $appid_version->nodeValue;

    }

    public function load_vulnerability_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $threatx )
        {
            if( $threatx->nodeType != XML_ELEMENT_NODE )
                continue;

            $this->load_vulnerability_entry( $threatx );
        }
    }

    public function load_vulnerability_entry( DOMElement $threatx ): Threat
    {
        $threatName = DH::findAttribute('name', $threatx);
        if( $threatName === FALSE )
            derr("threat name not found\n");

        $threat = new ThreatVulnerability($threatName, $this);
        $threat->type = 'vulnerability';
        $threat->xmlroot = $threatx;
        $threat->vulnerability_load_from_domxml( $threatx );

        $this->add($threat);

        $this->vulnerability[] = $threat;

        return $threat;
    }

    public function load_phone_home_containers_from_domxml(DOMElement $xml)
    {
        foreach( $xml->childNodes as $threatx )
        {
            if( $threatx->nodeType != XML_ELEMENT_NODE )
                continue;

            $this->load_phone_home_entry( $threatx );
        }
    }
}
