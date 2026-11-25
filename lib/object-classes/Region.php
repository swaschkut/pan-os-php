<?php

/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


class Region
{
    /** set by the mergers (type=object-merger) */
    public $ancestor;
    public $childancestor;

    use AddressCommon;
    use PathableName;
    use XmlConvertible;

    public $owner;
    public $_ip4Map;
    public $_ip6Map;


    private $members = array();

    /** @var DOMElement */
    private $membersRoot = null;

    /** @var bool a predefined region of PAN-OS (predefined.xml: country codes) - read only */
    private $predefined = FALSE;

    /** @var string predefined region: its help string (the country name) */
    private $helpString = '';

    /** @var string|null custom region: geo-location (latitude / longitude), null if not set */
    private $latitude = null;
    private $longitude = null;

    /**
     * you should not need this one for normal use
     * @param string $name
     * @param AddressStore $owner
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

            $rootDoc = $this->owner->addressRoot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);


            $this->owner = null;

            $this->setName( $name );
        }
        else
            $this->name = $name;

    }


    /**
     * @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
     * @ignore
     */
    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("region name not found\n");

        $this->members = array();
        $this->membersRoot = DH::findFirstElement('address', $xml);
        if( $this->membersRoot === FALSE )
            $this->membersRoot = null;

        if( $this->membersRoot !== null )
        {
            foreach( $this->membersRoot->childNodes as $member )
            {
                if( $member->nodeType != 1 ) continue;

                $this->members[] = $member->textContent;
            }
        }

        $this->latitude = null;
        $this->longitude = null;
        $geo = DH::findFirstElement('geo-location', $xml);
        if( $geo !== FALSE )
        {
            $lat = DH::findFirstElement('latitude', $geo);
            $lon = DH::findFirstElement('longitude', $geo);
            if( $lat !== FALSE )
                $this->latitude = trim($lat->textContent);
            if( $lon !== FALSE )
                $this->longitude = trim($lon->textContent);
        }

        /*
      <entry name="NAME">
        <geo-location>
          <latitude>59.335</latitude>
          <longitude>18.063</longitude>
        </geo-location>
        <address>
          <member>10.2.0.0/16</member>
        </address>
      </entry>
         */

        return TRUE;
    }

    public function isRegion()
    {
        return TRUE;
    }

    /**
     * a predefined region (country code of predefined.xml), loaded by AddressStore::getPredefinedRegionStore()
     * @param string $helpString
     * @ignore
     */
    public function setPredefined( $helpString = '' )
    {
        $this->predefined = TRUE;
        $this->helpString = (string)$helpString;
    }

    /**
     * @return bool TRUE for a predefined region of PAN-OS (read only)
     */
    public function isPredefined()
    {
        return $this->predefined;
    }

    /**
     * predefined region: the country name; custom region: '' (a region has no description in PAN-OS)
     * @return string
     */
    public function description()
    {
        return $this->helpString;
    }

    /**
     * @return string|null
     */
    public function latitude()
    {
        return $this->latitude;
    }

    /**
     * @return string|null
     */
    public function longitude()
    {
        return $this->longitude;
    }

    /**
     * latitude -90 .. 90, longitude -180 .. 180 (as PAN-OS)
     * @param string $latitude
     * @param string $longitude
     * @return string|null an error text, null if the values are valid
     */
    public static function geoLocationError( $latitude, $longitude )
    {
        foreach( array( 'latitude' => array( $latitude, 90 ), 'longitude' => array( $longitude, 180 ) ) as $what => $def )
        {
            $v = trim( (string)$def[0] );
            if( $v === '' || !is_numeric( $v ) )
                return $what . " '" . $def[0] . "' is not a number";
            if( abs( (float)$v ) > $def[1] )
                return $what . " '" . $def[0] . "' is outside -" . $def[1] . " .. " . $def[1];
        }
        return null;
    }

    /**
     * set the geo-location of a custom region
     * @param string $latitude
     * @param string $longitude
     * @return bool TRUE if changed
     */
    public function setGeoLocation( $latitude, $longitude )
    {
        $this->checkNotPredefined();
        $err = self::geoLocationError( $latitude, $longitude );
        if( $err !== null )
            derr( "region '" . $this->name . "': " . $err, null, FALSE );

        $latitude = trim( (string)$latitude );
        $longitude = trim( (string)$longitude );
        if( $this->latitude === $latitude && $this->longitude === $longitude )
            return FALSE;

        $geo = DH::findFirstElementOrCreate( 'geo-location', $this->xmlroot );
        DH::clearDomNodeChilds( $geo );
        DH::createElement( $geo, 'latitude', $latitude );
        DH::createElement( $geo, 'longitude', $longitude );
        if( $geo !== $this->xmlroot->firstChild )
            $this->xmlroot->insertBefore( $geo, $this->xmlroot->firstChild );

        $this->latitude = $latitude;
        $this->longitude = $longitude;

        return TRUE;
    }

    /**
     * remove the geo-location of a custom region
     * @return bool TRUE if changed
     */
    public function removeGeoLocation()
    {
        $this->checkNotPredefined();
        if( $this->latitude === null && $this->longitude === null )
            return FALSE;

        $geo = DH::findFirstElement( 'geo-location', $this->xmlroot );
        if( $geo !== FALSE )
            $this->xmlroot->removeChild( $geo );
        $this->latitude = null;
        $this->longitude = null;

        return TRUE;
    }

    /**
     * is a value an address member a region accepts: ip-netmask or ip-range, IPv4 or IPv6
     * @param string $value
     * @return bool
     */
    public static function isValidMember( $value )
    {
        $value = trim( (string)$value );
        if( $value === '' )
            return FALSE;

        if( strpos( $value, '-' ) !== FALSE )
        {
            $parts = explode( '-', $value );
            if( count( $parts ) != 2 )
                return FALSE;
            $a = filter_var( trim( $parts[0] ), FILTER_VALIDATE_IP );
            $b = filter_var( trim( $parts[1] ), FILTER_VALIDATE_IP );
            if( $a === FALSE || $b === FALSE )
                return FALSE;
            // both IPv4 or both IPv6, start <= end
            if( ( strpos( $a, ':' ) === FALSE ) !== ( strpos( $b, ':' ) === FALSE ) )
                return FALSE;
            return strcmp( inet_pton( $a ), inet_pton( $b ) ) <= 0;
        }

        $parts = explode( '/', $value );
        if( count( $parts ) > 2 )
            return FALSE;
        $ip = filter_var( $parts[0], FILTER_VALIDATE_IP );
        if( $ip === FALSE )
            return FALSE;
        if( count( $parts ) == 1 )
            return TRUE;
        $max = strpos( $ip, ':' ) === FALSE ? 32 : 128;
        return ctype_digit( $parts[1] ) && (int)$parts[1] <= $max;
    }

    /**
     * add an address (ip-netmask / ip-range) to a custom region
     * @param string $value
     * @return bool TRUE if added, FALSE if it is already a member
     */
    public function addMember( $value )
    {
        $this->checkNotPredefined();
        $value = trim( (string)$value );
        if( !self::isValidMember( $value ) )
            derr( "region '" . $this->name . "': '" . $value . "' is no ip-netmask / ip-range", null, FALSE );
        if( in_array( $value, $this->members, TRUE ) )
            return FALSE;

        if( $this->membersRoot === null )
            $this->membersRoot = DH::findFirstElementOrCreate( 'address', $this->xmlroot );
        DH::createElement( $this->membersRoot, 'member', $value );
        $this->members[] = $value;
        $this->resetIPMaps();

        return TRUE;
    }

    /**
     * remove an address from a custom region (the last one too: PAN-OS keeps a region without addresses)
     * @param string $value
     * @return bool TRUE if removed, FALSE if it is no member
     */
    public function removeMember( $value )
    {
        $this->checkNotPredefined();
        $value = trim( (string)$value );
        $i = array_search( $value, $this->members, TRUE );
        if( $i === FALSE )
            return FALSE;

        foreach( $this->membersRoot->childNodes as $node )
        {
            if( $node->nodeType == XML_ELEMENT_NODE && trim( $node->textContent ) === $value )
            {
                $this->membersRoot->removeChild( $node );
                break;
            }
        }
        unset( $this->members[$i] );
        $this->members = array_values( $this->members );
        if( count( $this->members ) == 0 )
        {
            $this->xmlroot->removeChild( $this->membersRoot );
            $this->membersRoot = null;
        }
        $this->resetIPMaps();

        return TRUE;
    }

    // <editor-fold desc=" ***** edits of the actions of type=region (an invalid value: Exception with the reason) *****" defaultstate="collapsed" >

    /** address-add: an ip-netmask / ip-range */
    public function editAddressAdd( string $value ): void
    {
        $this->editCheck();
        $value = trim( $value );
        if( !self::isValidMember( $value ) )
            throw new Exception( "'" . $value . "' is no ip-netmask / ip-range (IPv4 or IPv6)" );
        if( !$this->addMember( $value ) )
            throw new Exception( "'" . $value . "' is a member already" );
    }

    /** address-remove */
    public function editAddressRemove( string $value ): void
    {
        $this->editCheck();
        if( !$this->removeMember( $value ) )
            throw new Exception( "'" . trim( $value ) . "' is no member" );
    }

    /** geo-location-set: latitude -90 .. 90, longitude -180 .. 180 */
    public function editGeoLocationSet( string $latitude, string $longitude ): void
    {
        $this->editCheck();
        $err = self::geoLocationError( $latitude, $longitude );
        if( $err !== null )
            throw new Exception( $err );
        if( !$this->setGeoLocation( $latitude, $longitude ) )
            throw new Exception( 'the geo-location is the same' );
    }

    /** geo-location-remove */
    public function editGeoLocationRemove(): void
    {
        $this->editCheck();
        if( !$this->removeGeoLocation() )
            throw new Exception( 'the region has no geo-location' );
    }

    /**
     * name-rename: the region and every rule / group that uses it
     * @return int the number of users
     */
    public function editRename( string $newName ): int
    {
        $this->editCheck();
        $newName = trim( $newName );
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/', $newName ) )
            throw new Exception( "name '" . $newName . "': 1-63 characters, letters, digits, blank, . _ -" );
        if( $newName === $this->name() )
            throw new Exception( 'the name is the same' );
        if( AddressStore::isPredefinedRegionName( $newName ) )
            throw new Exception( "'" . $newName . "' is a predefined region (country code)" );
        if( self::isValidMember( $newName ) )
            throw new Exception( "'" . $newName . "' is an IP value" );
        if( $this->owner->find( $newName, null, FALSE ) !== null )
            throw new Exception( "'" . $newName . "' exists already" );
        $this->setName( $newName );
        return count( $this->getReferences() );
    }

    private function editCheck(): void
    {
        if( $this->predefined )
            throw new Exception( 'a predefined region of PAN-OS can not be changed' );
        if( $this->owner === null || $this->xmlroot === null )
            throw new Exception( 'the region is not part of a configuration' );
    }

    // </editor-fold>

    private function resetIPMaps()
    {
        unset( $this->_ip4Map );
        unset( $this->_ip6Map );
    }

    private function checkNotPredefined()
    {
        if( $this->predefined )
            derr( "region '" . $this->name . "' is a predefined region of PAN-OS - it cannot be changed", null, FALSE );
    }

    public function isTmpAddr()
    {
        return FALSE;
    }

    public function isType_ipNetmask()
    {
        return FALSE;
    }

    public function isType_ipRange()
    {
        return TRUE;
    }

    public function isType_FQDN()
    {
        return FALSE;
    }

    public function isType_TMP()
    {
        return FALSE;
    }

    public function isType_ipWildcard()
    {
        return FALSE;
    }

    public function name()
    {
        return $this->name;
    }

    /**
     * change the name of this object
     * @param string $newName
     *
     */
    public function setName($newName)
    {
        $this->checkNotPredefined();
        $this->setRefName($newName);
        $this->xmlroot->setAttribute('name', $newName);

        if( $this->isTmpAddr() )
        {
            unset($this->_ip4Map);
            unset($this->_ip6Map);
        }
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        if( $this->isTmpAddr() )
        {
            mwarning('renaming of TMP object in API is not possible, it was ignored');
            return;
        }

        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newName);

        if( $c->isAPI() )
            $c->sendRenameRequest($xpath, $newName);
    }

    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getRegionStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }

    /**
     * Return an array['start']= startip and ['end']= endip
     * @return IP4Map
     */
    public function getIP4Mapping( $RuleReferenceLocation = null)
    {
        if( isset($this->_ip4Map) )
        {
            return $this->_ip4Map;
        }

        // the custom region's IPv4 address members (ip-netmask / ip-range); a predefined region (country): its
        // addresses are only known on the firewall - unresolved
        $this->_ip4Map = new IP4Map();
        if( $this->predefined )
            $this->_ip4Map->unresolved[$this->name] = $this;
        foreach( $this->members as $member )
        {
            $member = trim( $member );
            if( $member === '' || strpos( $member, ':' ) !== FALSE )
                continue;
            $this->_ip4Map->addMap( IP4Map::mapFromText( $member ), TRUE );
        }
        $this->_ip4Map->sortAndRecalculate();

        return $this->_ip4Map;
    }

    /**
     * Return an array['start']= startip and ['end']= endip
     * @return IP6Map
     */
    public function getIP6Mapping( $RuleReferenceLocation = null)
    {
        if( isset($this->_ip6Map) )
        {
            return $this->_ip6Map;
        }

        // the IPv6 address members
        $this->_ip6Map = new IP6Map();
        if( $this->predefined )
            $this->_ip6Map->unresolved[$this->name] = $this;
        foreach( $this->members as $member )
        {
            $member = trim( $member );
            if( $member === '' || strpos( $member, ':' ) === FALSE )
                continue;
            $this->_ip6Map->addMap( IP6Map::mapFromText( $member ), TRUE );
        }
        $this->_ip6Map->sortAndRecalculate();

        return $this->_ip6Map;
    }
    public function value()
    {
        $string = implode( ", ", $this->members);
        return $string;
    }

    public function members()
    {
        return $this->members;
    }

    /**
     * @return string ie: 'ip-netmask' 'ip-range'
     */
    public function type()
    {
        return "region";
    }

    /**
     * @param $otherObject Region
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isRegion() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        if( $this->predefined || $otherObject->isPredefined() )
            return $this->predefined === $otherObject->isPredefined();

        $a = $this->members;
        $b = $otherObject->members();
        sort( $a );
        sort( $b );

        return $a === $b && $this->latitude === $otherObject->latitude() && $this->longitude === $otherObject->longitude();
    }

    static protected $templatexml = '<entry name="**temporarynamechangeme**"></entry>';
}