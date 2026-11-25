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

class EDL
{
    use AddressCommon;
    use PathableName;
    use XmlConvertible;

    /** set by the mergers (type=object-merger) */
    public $ancestor;
    public $childancestor;

    /** @var EDLStore|null */
    public $owner = null;

    public $type = null;
    public $recurring = null;
    public $url = null;

    /**
     * @param string $name
     * @param EDLStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->name = $name;


        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->setName($name);
        }

        $this->owner = $owner;
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
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getEDLStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    public function isTmp()
    {
        if( $this->xmlroot === null )
            return TRUE;
        return FALSE;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;
        $this->type = null;
        $this->recurring = null;
        $this->url = null;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("edl name not found\n", $xml);


        if( strlen($this->name) < 1 )
            derr("edl name '" . $this->name . "' is not valid.", $xml);

        $tmp_type_node = DH::findFirstElement('type', $xml);
        $tmp_type = DH::firstChildElement($tmp_type_node);
        if( $tmp_type !== FALSE )
        {
            $this->type = $tmp_type->nodeName;
            $supportedType = array('ip', 'domain', 'url', 'imei', 'imsi', 'predefined-ip', 'predefined-url');
            //todo: supported type: ip/domain/url/imei/imsi


            $tmp_recurring_node = DH::findFirstElement('recurring', $tmp_type);
            if ($tmp_recurring_node != False)
            {
                $tmp_recurring = DH::firstChildElement($tmp_recurring_node);
                if ($tmp_recurring != False)
                    $this->recurring = $tmp_recurring->nodeName;
            }

            $tmp_url_node = DH::findFirstElement('url', $tmp_type);
            if ($tmp_url_node != False)
                $this->url = $tmp_url_node->textContent;

            /*
            +<entry name="EDL_waschkut_IP">
            + <type>
            +  <ip>
            +   <recurring>
            +    <five-minute/>
            +   </recurring>
            +   <url>https://www.waschkut.de/PAN/EDL_domain.txt</url>
            +  </ip>
            + </type>
            +</entry>
            +<entry name="EDL_ip_list">
            + <type>
            +  <ip>
            +   <recurring>
            +    <five-minute/>
            +   </recurring>
            +   <url>http://</url>
            +  </ip>
            + </type>
            +</entry>
            +<entry name="EDL_url_list">
            + <type>
            +  <url>
            +   <recurring>
            +    <hourly/>
            +   </recurring>
            +   <url>http://</url>
            +  </url>
            + </type>
            +</entry>
            +<entry name="EDL_domain_list">
            + <type>
            +  <domain>
            +   <recurring>
            +    <hourly/>
            +   </recurring>
            +   <description>test</description>
            +   <url>https://www.waschkut.de/urllist.txt</url>
            +  </domain>
            + </type>
            +</entry>
            +<entry name="EDL_subscriber_identity_list">
            + <type>
            +  <imsi>
            +   <recurring>
            +    <five-minute/>
            +   </recurring>
            +   <url>http://</url>
            +  </imsi>
            + </type>
            +</entry>
            +<entry name="EDL_equipment_identity_list">
            + <type>
            +  <imei>
            +   <recurring>
            +    <five-minute/>
            +   </recurring>
            +   <url>http://</url>
            +  </imei>
            + </type>
            +</entry>
             */
            //todo - implement EDL reading type IP / FQDN
            # EDL take precedence over address / address-group  by name
            //todo: EDL of type IP-LIST can be used in security rule source/destination
        }
    }




    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isEDL()
    {
        return TRUE;
    }


    /**
     * @param $otherObject EDL
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isEDL() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(EDL $otherObject)
    {
        if( $this->isTmp() && !$otherObject->isTmp() )
            return FALSE;

        if( $otherObject->isTmp() && !$this->isTmp() )
            return FALSE;


        return TRUE;
    }

    public function type()
    {
        if( $this->isTmp() )
            return null;


        return $this->type;
    }
    public function url()
    {
        return $this->url;
    }

    public function recurring()
    {
        return $this->recurring;
    }

    // ------------------------------------------------------------------------------------------------- edit (offline)

    const EDL_TYPES = array( 'ip', 'domain', 'url', 'imsi', 'imei', 'predefined-ip', 'predefined-url' );
    const EDL_RECURRING = array( 'five-minute', 'hourly', 'daily', 'weekly', 'monthly' );
    const EDL_WEEKDAYS = array( 'sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday' );

    /** the element of the type (<type><ip>…</ip></type>); null: none yet */
    public function typeNode(): ?DOMElement
    {
        $t = DH::findFirstElement( 'type', $this->xmlroot );
        if( $t === FALSE )
            return null;
        $n = DH::firstChildElement( $t );
        return $n === FALSE ? null : $n;
    }

    private function editableTypeNode(): DOMElement
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        $n = $this->typeNode();
        if( $n === null )
            throw new Exception( 'the EDL has no type yet - type-set first' );
        return $n;
    }

    private function isPredefinedType( ?string $t = null ): bool
    {
        return strpos( (string)( $t ?? $this->type ), 'predefined-' ) === 0;
    }

    /** the value of a child of the type element ('' when not set) */
    public function typeValue( string $tag ): string
    {
        $n = $this->typeNode();
        if( $n === null )
            return '';
        $e = DH::findFirstElement( $tag, $n );
        return $e === FALSE ? '' : $e->textContent;
    }

    /** members of the exception list */
    public function exceptions(): array
    {
        $n = $this->typeNode();
        $out = array();
        $l = $n === null ? FALSE : DH::findFirstElement( 'exception-list', $n );
        if( $l !== FALSE )
            foreach( $l->childNodes as $m )
                if( $m->nodeType == XML_ELEMENT_NODE )
                    $out[] = $m->textContent;
        return $out;
    }

    private function setTypeChild( DOMElement $node, string $tag, ?string $value ): void
    {
        $e = DH::findFirstElement( $tag, $node );
        if( $value === null )
        {
            if( $e !== FALSE )
                $node->removeChild( $e );
            return;
        }
        if( $e === FALSE )
            $e = DH::createElement( $node, $tag );
        DH::setDomNodeText( $e, $value );
    }

    static private function checkSource( string $url, string $type ): void
    {
        if( $url === '' || strlen( $url ) > 255 || preg_match( '/[\s\x00-\x1F]/', $url ) )
            throw new Exception( "source '" . $url . "': 1-255 characters, no blanks" );
        if( strpos( $type, 'predefined-' ) === 0 )
        {
            if( !preg_match( '/^[a-z0-9][a-z0-9._-]*$/', $url ) )
                throw new Exception( "source '" . $url . "': the name of a predefined list (e.g. panw-bulletproof-ip-list)" );
        }
        elseif( !preg_match( '#^https?://[^/]+#i', $url ) )
            throw new Exception( "source '" . $url . "': http:// or https:// URL" );
    }

    /** type-set: ip / domain / url / imsi / imei / predefined-ip / predefined-url; $source: needed when the source does not fit */
    public function editTypeSet( string $type, string $source = '' ): void
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        if( !in_array( $type, self::EDL_TYPES, TRUE ) )
            throw new Exception( "type '" . $type . "': " . implode( ', ', self::EDL_TYPES ) );
        $old = $this->typeNode();
        if( $old !== null && $old->nodeName === $type && $source === '' )
            throw new Exception( 'the type is ' . $type . ' already' );

        $url = $source !== '' ? $source : ( $old !== null ? $this->typeValue( 'url' ) : '' );
        self::checkSource( $url, $type );

        $typeRoot = DH::findFirstElementOrCreate( 'type', $this->xmlroot );
        $new = $this->xmlroot->ownerDocument->createElement( $type );
        // the children that fit the new type move along
        $keep = $this->isPredefinedType( $type ) ? array( 'description', 'exception-list' )
            : array( 'recurring', 'description', 'certificate-profile', 'exception-list', 'auth' );
        if( $type === 'domain' )
            $keep[] = 'expand-domain';
        if( $old !== null )
            foreach( iterator_to_array( $old->childNodes ) as $c )
                if( $c->nodeType == XML_ELEMENT_NODE && in_array( $c->nodeName, $keep, TRUE ) )
                    $new->appendChild( $c );
        if( !$this->isPredefinedType( $type ) && DH::findFirstElement( 'recurring', $new ) === FALSE )
        {
            $r = DH::createElement( $new, 'recurring' );
            DH::createElement( $r, 'five-minute' );
        }
        DH::clearDomNodeChilds( $typeRoot );
        $typeRoot->appendChild( $new );
        $this->setTypeChild( $new, 'url', $url );
        $this->load_from_domxml( $this->xmlroot );
    }

    public function editSourceSet( string $url ): void
    {
        $n = $this->editableTypeNode();
        self::checkSource( $url, $n->nodeName );
        if( $this->typeValue( 'url' ) === $url )
            throw new Exception( 'the source is the same' );
        $this->setTypeChild( $n, 'url', $url );
        $this->load_from_domxml( $this->xmlroot );
    }

    /**
     * recurring-set: five-minute / hourly / daily (at) / weekly (day of week, at) / monthly (day of month, at); at: hour 0-23
     */
    public function editRecurringSet( string $interval, string $at = '', string $day = '' ): void
    {
        $n = $this->editableTypeNode();
        if( $this->isPredefinedType( $n->nodeName ) )
            throw new Exception( 'a predefined list has no update interval' );
        if( !in_array( $interval, self::EDL_RECURRING, TRUE ) )
            throw new Exception( "interval '" . $interval . "': " . implode( ', ', self::EDL_RECURRING ) );

        $rec = DH::findFirstElementOrCreate( 'recurring', $n );
        DH::clearDomNodeChilds( $rec );
        $i = DH::createElement( $rec, $interval );
        if( in_array( $interval, array( 'daily', 'weekly', 'monthly' ), TRUE ) )
        {
            if( !preg_match( '/^([01]?[0-9]|2[0-3])$/', $at ) )
                throw new Exception( "at '" . $at . "': the hour 0-23" );
            if( $interval === 'weekly' )
            {
                $day = strtolower( $day );
                if( !in_array( $day, self::EDL_WEEKDAYS, TRUE ) )
                    throw new Exception( "day '" . $day . "': " . implode( ', ', self::EDL_WEEKDAYS ) );
                DH::createElement( $i, 'day-of-week', $day );
            }
            if( $interval === 'monthly' )
            {
                if( !preg_match( '/^([1-9]|[12][0-9]|3[01])$/', $day ) )
                    throw new Exception( "day '" . $day . "': the day of the month 1-31" );
                DH::createElement( $i, 'day-of-month', $day );
            }
            DH::createElement( $i, 'at', sprintf( '%02d', (int)$at ) );
        }
        $this->load_from_domxml( $this->xmlroot );
    }

    /** the description of an EDL is inside the type element */
    public function edlDescription(): string
    {
        return $this->typeValue( 'description' );
    }

    public function editDescriptionSet( string $text ): void
    {
        $n = $this->editableTypeNode();
        if( strlen( $text ) > 255 )
            throw new Exception( 'the description is longer than 255 characters' );
        if( $text === $this->edlDescription() )
            throw new Exception( 'the description is the same' );
        $this->setTypeChild( $n, 'description', $text === '' ? null : $text );
    }

    /** certificate-profile-set: a name, or none */
    public function editCertificateProfileSet( string $name ): void
    {
        $n = $this->editableTypeNode();
        if( $this->isPredefinedType( $n->nodeName ) )
            throw new Exception( 'a predefined list has no certificate profile' );
        if( $name === '' || ( $name !== 'none' && !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/', $name ) ) )
            throw new Exception( "certificate profile '" . $name . "': a name or none" );
        if( $this->typeValue( 'certificate-profile' ) === ( $name === 'none' ? '' : $name ) )
            throw new Exception( 'the certificate profile is the same' );
        $this->setTypeChild( $n, 'certificate-profile', $name === 'none' ? null : $name );
    }

    public function editExceptionAdd( string $entry ): void
    {
        $n = $this->editableTypeNode();
        if( $entry === '' || strlen( $entry ) > 255 || preg_match( '/[\s\x00-\x1F]/', $entry ) )
            throw new Exception( "exception '" . $entry . "': 1-255 characters, no blanks" );
        if( in_array( $entry, $this->exceptions(), TRUE ) )
            throw new Exception( "'" . $entry . "' is in the exception list already" );
        DH::createElement( DH::findFirstElementOrCreate( 'exception-list', $n ), 'member', $entry );
    }

    public function editExceptionRemove( string $entry ): void
    {
        $n = $this->editableTypeNode();
        $l = DH::findFirstElement( 'exception-list', $n );
        if( $l !== FALSE )
            foreach( $l->childNodes as $m )
                if( $m->nodeType == XML_ELEMENT_NODE && $m->textContent === $entry )
                {
                    $l->removeChild( $m );
                    if( DH::firstChildElement( $l ) === FALSE )
                        $n->removeChild( $l );
                    return;
                }
        throw new Exception( "'" . $entry . "' is not in the exception list" );
    }

    /** name-rename: the object and every user that names it (references) */
    public function editRename( string $newName ): int
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/', $newName ) )
            throw new Exception( "name '" . $newName . "': 1-63 characters, letters, digits, blank, . _ -" );
        if( $newName === $this->name() )
            throw new Exception( 'the name is the same' );
        if( $this->owner->find( $newName, null, FALSE ) !== null )
            throw new Exception( "'" . $newName . "' exists already" );
        $this->setName( $newName );
        return count( $this->getReferences() );
    }

    /** expand-domain-set (type domain): yes / no */
    public function editExpandDomainSet( bool $yes ): void
    {
        $n = $this->editableTypeNode();
        if( $n->nodeName !== 'domain' )
            throw new Exception( 'only for the type domain' );
        if( ( $this->typeValue( 'expand-domain' ) === 'yes' ) === $yes )
            throw new Exception( 'expand domain is ' . ( $yes ? 'yes' : 'no' ) . ' already' );
        $this->setTypeChild( $n, 'expand-domain', $yes ? 'yes' : null );
    }
}

