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

class HipProfilesProfile extends Profile
{
    use ReferenceableObject;
    use PathableName;
    use XmlConvertible;
    use ObjectWithDescription;

    /**
     * @param SecurityProfileStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        parent::__construct($name, $owner, $fromXmlTemplate);
    }

    /**
     * objects named in <match> (quoted names): name => HipObjectsProfile|HipProfilesProfile
     * (a HIP profile can combine HIP objects and other HIP profiles)
     * @var array
     */
    public $matchObjects = array();

    public function load_from_domxml(DOMElement $xml)
    {
        $ret = parent::load_from_domxml($xml);
        $this->resolveMatchReferences();
        return $ret;
    }

    /** the match expression, e.g. ("MacOS" and "FileVault") or not "Guest" */
    public function matchText(): string
    {
        if( $this->xmlroot === null )
            return '';
        $node = DH::findFirstElement('match', $this->xmlroot);
        return ( $node === FALSE ) ? '' : $node->textContent;
    }

    /** names in a match expression (in double or single quotes), in order, without duplicates */
    public static function matchNames( string $text ): array
    {
        $names = array();
        if( preg_match_all( '/"([^"]*)"|\'([^\']*)\'/', $text, $m, PREG_SET_ORDER ) )
            foreach( $m as $set )
            {
                $name = ( isset($set[2]) && $set[2] !== '' ) ? $set[2] : $set[1];
                if( $name !== '' && !in_array( $name, $names, TRUE ) )
                    $names[] = $name;
            }
        return $names;
    }

    /**
     * references to the HIP objects / HIP profiles named in <match>, looked up from this profile's location
     * (HIP objects first, then HIP profiles). Called while loading and again once the whole store is loaded
     * (a profile can name a profile defined after it).
     */
    public function resolveMatchReferences(): void
    {
        if( $this->owner === null || !isset($this->owner->owner) )
            return;
        $location = $this->owner->owner;

        foreach( self::matchNames( $this->matchText() ) as $name )
        {
            if( isset($this->matchObjects[$name]) )
                continue;

            $object = null;
            if( isset($location->HipObjectsProfileStore) && $location->HipObjectsProfileStore !== null )
                $object = $location->HipObjectsProfileStore->find( $name );
            if( !is_object($object) && isset($location->HipProfilesProfileStore) && $location->HipProfilesProfileStore !== null )
                $object = $location->HipProfilesProfileStore->find( $name );
            if( !is_object($object) || $object === $this || !method_exists($object, 'addReference') )
                continue;

            $this->matchObjects[$name] = $object;
            $object->addReference( $this );
        }
    }

    /** the profile is deleted: the objects of its match expression lose this user */
    public function dropMatchReferences(): void
    {
        foreach( $this->matchObjects as $object )
            $object->removeReference( $this );
        $this->matchObjects = array();
    }

    /**
     * $old (a HIP object or HIP profile named in <match>) is replaced by $new: the name is changed in the
     * match expression, the references are moved
     * @return bool
     */
    public function replaceReferencedObject( $old, $new )
    {
        return $this->replaceMatchReference( $old, $new, FALSE );
    }

    public function API_replaceReferencedObject( $old, $new )
    {
        return $this->replaceMatchReference( $old, $new, TRUE );
    }

    private function replaceMatchReference( $old, $new, $apiMode ): bool
    {
        if( $old === $new || !is_object($old) || !is_object($new) || $this->xmlroot === null )
            return FALSE;

        $oldName = null;
        foreach( $this->matchObjects as $name => $object )
            if( $object === $old )
                $oldName = $name;
        if( $oldName === null )
            return FALSE;

        $node = DH::findFirstElement('match', $this->xmlroot);
        if( $node === FALSE )
            return FALSE;

        $newName = $new->name();
        $text = $node->textContent;
        $text = str_replace( array( '"' . $oldName . '"', "'" . $oldName . "'" ), array( '"' . $newName . '"', "'" . $newName . "'" ), $text );
        DH::setDomNodeText( $node, $text );

        unset( $this->matchObjects[$oldName] );
        $this->matchObjects[$newName] = $new;
        $old->removeReference( $this );
        $new->addReference( $this );

        if( $apiMode )
        {
            $con = findConnectorOrDie($this);
            if( $con->isAPI() )
                $con->sendEditRequest( $this->getXPath() . '/match', DH::dom_to_xml($node, -1, FALSE) );
        }

        return TRUE;
    }
}

