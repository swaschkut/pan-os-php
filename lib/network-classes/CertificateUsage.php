<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
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


/**
 * Who uses a certificate / a certificate profile (references): pan-os-php had only the CA entries of certificate
 * profiles (-> certificates) and decryption rules. After a firewall configuration, a template or a template stack is
 * loaded, link() goes through its XML and adds a reference for every use it finds:
 *
 *   certificates          SSL/TLS service profile <certificate>, IKE gateway local-certificate/name, GlobalProtect
 *                         (server / client certificate, root CA entries), SCEP, SSL decryption forward trust / untrust
 *                         certificate, every other leaf <certificate> / <local-certificate> / <server-certificate> …
 *   certificate profiles  every <certificate-profile> / <cert-profile> (GlobalProtect portal / gateway, IKE gateway,
 *                         authentication, LDAP / syslog server profiles, management, …)
 *
 * A name is only taken when a certificate / certificate profile of that name is in the scope of the place it is used
 * (vsys -> shared; template stack -> its templates). The user is a CertificateReference: the field (e.g.
 * "ssl-tls-service-profile/MGMT-SSL/certificate") whose owner is the object of that place when pan-os-php has one
 * (SSL/TLS service profile, GlobalProtect portal / gateway, IKE gateway, SCEP profile, …), else the location. A rename
 * of the certificate (replaceReferencedObject) changes the text of that field.
 */
class CertificateUsage
{
    /** leaf elements whose text is the name of a certificate */
    const CERT_TAGS = array( 'certificate', 'local-certificate', 'server-certificate', 'client-certificate', 'ca-certificate',
        'scep-ca-cert', 'scep-client-cert', 'portal-certificate', 'gateway-certificate', 'idp-certificate' );
    /** containers whose leaf <name> / <rsa> / <ecdsa> / <member> is the name of a certificate */
    const CERT_PARENTS = array( 'local-certificate', 'forward-trust-certificate', 'forward-untrust-certificate', 'root-ca-certificate', 'ssl-inbound-inspection' );
    const CERT_PARENT_LEAVES = array( 'name', 'rsa', 'ecdsa', 'member' );
    /** lists of certificates as <entry name="..."> */
    const CERT_LISTS = array( 'root-ca', 'trusted-root-ca', 'trusted-root-CA', 'certificate-list', 'ssl-exclude-cert' );
    /** leaf elements whose text is the name of a certificate profile */
    const PROFILE_TAGS = array( 'certificate-profile', 'cert-profile' );
    /** subtrees never searched: the stores themselves (a certificate profile's CA entries are its own references) */
    const SKIP = array( 'certificate', 'certificate-profile' );

    /**
     * @param PANConf|Template|TemplateStack $location
     */
    public static function link( $location ): void
    {
        $root = self::rootOf( $location );
        if( $root === null )
            return;
        $objects = null;
        $x = new DOMXPath( $root->ownerDocument );
        // only the elements that can name a certificate / profile (one XPath query, in libxml - a large configuration
        // is not walked in PHP)
        $self = function( array $tags ) { return implode( ' or ', array_map( function( $t ) { return 'self::' . $t; }, $tags ) ); };
        $parents = $self( self::CERT_PARENTS );
        $q = './/*[(' . $self( array_merge( self::PROFILE_TAGS, self::CERT_TAGS ) ) . ') and not(*)]'
            . ' | .//*[(' . $self( self::CERT_PARENT_LEAVES ) . ') and not(*) and parent::*[' . $parents . ']]'
            . ' | .//entry[parent::*[' . $self( self::CERT_LISTS ) . ']]';
        foreach( $x->query( $q, $root ) as $leaf )
        {
            $tag = $leaf->nodeName;
            $parent = $leaf->parentNode;
            $kind = null;
            $name = trim( $leaf->textContent );
            if( in_array( $tag, self::PROFILE_TAGS, TRUE ) )
                $kind = 'profile';
            elseif( in_array( $tag, self::CERT_TAGS, TRUE ) || ( $parent instanceof DOMElement && in_array( $parent->nodeName, self::CERT_PARENTS, TRUE ) && in_array( $tag, self::CERT_PARENT_LEAVES, TRUE ) ) )
                $kind = 'certificate';
            elseif( $tag === 'entry' && $parent instanceof DOMElement && in_array( $parent->nodeName, self::CERT_LISTS, TRUE ) )
            {
                $kind = 'certificate';
                $name = $leaf->getAttribute( 'name' );
            }
            if( $kind === null || $name === '' || self::inStore( $leaf, $root ) )
                continue;
            $scope = self::scopeOf( $location, $leaf, $root );
            $target = self::find( $scope, $kind, $name );
            if( $target === null )
                continue;
            if( $objects === null )
                $objects = self::objectsOf( $location );
            $owner = self::ownerOf( $leaf, $root, $objects ) ?? $scope;
            $target->addReference( new CertificateReference( $owner, $leaf, self::field( $leaf, $root ) ) );
        }
    }

    /** the XML of the location: a firewall: /config; a template / template stack: its <config> */
    private static function rootOf( $location ): ?DOMElement
    {
        if( ( $location instanceof Template || $location instanceof TemplateStack ) && isset( $location->xmlroot ) && $location->xmlroot instanceof DOMElement )
        {
            $c = DH::findFirstElement( 'config', $location->xmlroot );
            return $c instanceof DOMElement ? $c : null;
        }
        if( $location instanceof PANConf && isset( $location->xmlroot ) && $location->xmlroot instanceof DOMElement )
            return $location->xmlroot;
        return null;
    }

    /**
     * inside a certificate / certificate profile store (shared/certificate, vsys entry/certificate-profile, …): the
     * certificates themselves and the CA entries of the profiles (their own references)
     */
    private static function inStore( DOMElement $e, DOMElement $root ): bool
    {
        for( $n = $e->parentNode; $n instanceof DOMElement && $n !== $root; $n = $n->parentNode )
        {
            if( !in_array( $n->nodeName, self::SKIP, TRUE ) || !( $n->parentNode instanceof DOMElement ) )
                continue;
            $p = $n->parentNode;
            if( in_array( $p->nodeName, array( 'shared', 'config' ), TRUE ) || $p === $root
                || ( $p->nodeName === 'entry' && $p->parentNode instanceof DOMElement && in_array( $p->parentNode->nodeName, array( 'vsys', 'devices' ), TRUE ) ) )
                return TRUE;
        }
        return FALSE;
    }

    /** the location the name is used in: its vsys (devices/entry/vsys/entry) or the firewall / template / stack */
    private static function scopeOf( $location, DOMElement $e, DOMElement $root )
    {
        for( $n = $e->parentNode; $n instanceof DOMElement && $n !== $root; $n = $n->parentNode )
            if( $n->nodeName === 'entry' && $n->parentNode instanceof DOMElement && $n->parentNode->nodeName === 'vsys' )
            {
                $conf = $location instanceof PANConf ? $location : ( $location->deviceConfiguration ?? null );
                $vsys = $conf !== null ? $conf->findVirtualSystem( $n->getAttribute( 'name' ) ) : null;
                if( $vsys !== null )
                    return $vsys;
                break;
            }
        return $location;
    }

    /** a certificate / certificate profile of that name in the scope (vsys -> shared, template stack -> templates) */
    private static function find( $scope, string $kind, string $name )
    {
        $levels = PH::templateScopeLevels( $scope );
        if( count( $levels ) === 0 )
        {
            $levels = array( $scope );
            if( $scope instanceof VirtualSystem && isset( $scope->owner ) )
                $levels[] = $scope->owner;
        }
        $prop = $kind === 'profile' ? 'certificateProfileStore' : 'certificateStore';
        foreach( $levels as $level )
            if( isset( $level->$prop ) && $level->$prop !== null )
            {
                $o = $level->$prop->find( $name, null, FALSE );
                if( $o !== null )
                    return $o;
            }
        return null;
    }

    /** every object of the location with its XML (xmlroot) - to name the object a field belongs to */
    private static function objectsOf( $location ): array
    {
        $map = array();
        $containers = array( $location );
        $conf = $location instanceof PANConf ? $location : ( $location->deviceConfiguration ?? null );
        if( $conf !== null && $conf !== $location )
            $containers[] = $conf;
        if( $conf !== null )
            foreach( $conf->getVirtualSystems() as $vsys )
                $containers[] = $vsys;
        foreach( $containers as $c )
            if( isset( $c->network ) && is_object( $c->network ) )
                $containers[] = $c->network;
        foreach( $containers as $c )
            foreach( get_object_vars( $c ) as $v )
                if( is_object( $v ) && !( $v instanceof AddressStore ) && !( $v instanceof ServiceStore ) && !( $v instanceof RuleStore ) && method_exists( $v, 'getAll' ) )
                    foreach( (array)$v->getAll() as $o )
                        if( is_object( $o ) && isset( $o->xmlroot ) && $o->xmlroot instanceof DOMElement )
                            $map[spl_object_id( $o->xmlroot )] = $o;
        return $map;
    }

    /** the object of pan-os-php the field belongs to (the nearest entry that is one) */
    private static function ownerOf( DOMElement $e, DOMElement $root, array $objects )
    {
        for( $n = $e->parentNode; $n instanceof DOMElement && $n !== $root; $n = $n->parentNode )
            if( isset( $objects[spl_object_id( $n )] ) )
                return $objects[spl_object_id( $n )];
        return null;
    }

    /** the field as text: element names and entry names below the location, e.g. "ssl-tls-service-profile/MGMT/certificate" */
    private static function field( DOMElement $e, DOMElement $root ): string
    {
        $parts = array();
        for( $n = $e; $n instanceof DOMElement && $n !== $root; $n = $n->parentNode )
        {
            if( $n->nodeName === 'entry' )
            {
                $parts[] = $n->getAttribute( 'name' );
                continue;
            }
            if( in_array( $n->nodeName, array( 'devices', 'vsys' ), TRUE ) )
                continue;
            $parts[] = $n->nodeName;
        }
        $parts = array_reverse( $parts );
        // localhost.localdomain of devices/entry: not part of the field
        $parts = array_values( array_filter( $parts, function( $p ) { return $p !== 'localhost.localdomain'; } ) );
        return implode( '/', $parts );
    }
}

/**
 * one use of a certificate / certificate profile found by CertificateUsage: the field, its owner (the object of
 * pan-os-php it belongs to, else the location)
 */
class CertificateReference
{
    public $owner;
    /** @var DOMElement the element with the name (a leaf, or an entry of a list) */
    public $xmlroot;
    public $field;

    public function __construct( $owner, DOMElement $element, string $field )
    {
        $this->owner = $owner;
        $this->xmlroot = $element;
        $this->field = $field;
    }

    public function name()
    {
        return $this->field;
    }

    public function toString()
    {
        $o = is_object( $this->owner ) && method_exists( $this->owner, 'toString' ) ? $this->owner->toString()
            : ( is_object( $this->owner ) && method_exists( $this->owner, 'name' ) ? get_class( $this->owner ) . ":" . $this->owner->name() : '' );
        return 'CertificateReference:' . $this->field . ( $o !== '' ? ' (' . $o . ')' : '' );
    }

    /** the certificate / certificate profile was renamed or replaced: the name in this field */
    public function replaceReferencedObject( $old, $new )
    {
        if( $this->xmlroot->nodeName === 'entry' )
            $this->xmlroot->setAttribute( 'name', $new->name() );
        else
            $this->xmlroot->textContent = $new->name();
        $old->removeReference( $this );
        $new->addReference( $this );
        return TRUE;
    }

    public function API_replaceReferencedObject( $old, $new )
    {
        return $this->replaceReferencedObject( $old, $new );
    }
}
