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
 * The single fields of a security profile (PAN-OS XML, offline): the lists of entries of a profile type (rules,
 * exceptions, decoders, DNS categories) and its options - one table, one implementation for every type
 * (actions detail-entry-add / -remove / -set, detail-option-set, url.credential-action-set).
 *
 * Values: text <f>v</f>; list <f><member>v</member>…</f> (several values joined with '+'); choice <f><v/></f>;
 * entries <f><entry name="v"/>…</f>. The profile object is not read again: the XML is what is saved; the next run
 * reads it.
 */
class SecurityProfileFields
{
    const AV_ACTIONS = array( 'default', 'allow', 'alert', 'drop', 'reset-client', 'reset-server', 'reset-both' );
    const TP_ACTIONS = array( 'default', 'allow', 'alert', 'drop', 'reset-client', 'reset-server', 'reset-both' );
    const SEVERITY = array( 'any', 'critical', 'high', 'medium', 'low', 'informational' );
    const PCAP = array( 'disable', 'single-packet', 'extended-capture' );
    const YESNO = array( 'yes', 'no' );

    /**
     * per profile type: list => 'path' (below the entry of the profile), 'fixed' (entries of PAN-OS: no add / remove),
     * 'name' (regex of an entry name), 'fields' => field => array( kind, choices|null, default|null )
     */
    static public function lists(): array
    {
        $pcap = array( 'text', self::PCAP, 'disable' );
        $tpRule = array(
            'threat-name' => array( 'text', null, 'any' ),
            'category' => array( 'text', null, 'any' ),
            'severity' => array( 'list', self::SEVERITY, 'any' ),
            'action' => array( 'choice', self::TP_ACTIONS, 'default' ),
            'packet-capture' => $pcap,
        );
        $tpException = array( 'path' => 'threat-exception', 'name' => '/^[0-9]{1,10}$/', 'fields' => array(
            'action' => array( 'choice', self::TP_ACTIONS, 'default' ),
            'packet-capture' => $pcap,
            'exempt-ip' => array( 'entries', null, null ),
        ) );
        $fileRule = function( array $last ) {
            return array( 'path' => 'rules', 'name' => '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,30}$/', 'fields' => array(
                'application' => array( 'list', null, 'any' ),
                'file-type' => array( 'list', null, 'any' ),
                'direction' => array( 'text', array( 'upload', 'download', 'both' ), 'both' ),
            ) + $last );
        };

        return array(
            'virus' => array(
                'decoder' => array( 'path' => 'decoder', 'fixed' => TRUE, 'known' => array( 'http', 'http2', 'smtp', 'imap', 'pop3', 'ftp', 'smb' ), 'fields' => array(
                    'action' => array( 'text', self::AV_ACTIONS, null ),
                    'wildfire-action' => array( 'text', self::AV_ACTIONS, null ),
                    'mlav-action' => array( 'text', self::AV_ACTIONS, null ),
                ) ),
                'application-exception' => array( 'path' => 'application-exception', 'name' => '/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/', 'fields' => array(
                    'action' => array( 'text', self::AV_ACTIONS, 'default' ),
                ) ),
                'threat-exception' => array( 'path' => 'threat-exception', 'name' => '/^[0-9]{1,10}$/', 'fields' => array() ),
            ),
            'spyware' => array(
                'rule' => array( 'path' => 'rules', 'name' => '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,30}$/', 'fields' => $tpRule ),
                'threat-exception' => $tpException,
                'dns-category' => array( 'path' => 'botnet-domains/dns-security-categories', 'name' => '/^pan-dns-sec-[a-z0-9-]+$/', 'fields' => array(
                    'action' => array( 'text', array( 'default', 'allow', 'block', 'sinkhole' ), 'default' ),
                    'log-level' => array( 'text', array( 'default', 'none', 'low', 'informational', 'medium', 'high', 'critical' ), 'default' ),
                    'packet-capture' => $pcap,
                ) ),
            ),
            'vulnerability' => array(
                'rule' => array( 'path' => 'rules', 'name' => '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,30}$/', 'fields' => $tpRule + array(
                    'host' => array( 'text', array( 'any', 'client', 'server' ), 'any' ),
                    'cve' => array( 'list', null, 'any' ),
                    'vendor-id' => array( 'list', null, 'any' ),
                ) ),
                'threat-exception' => $tpException,
            ),
            'file-blocking' => array(
                'rule' => $fileRule( array( 'action' => array( 'text', array( 'alert', 'block', 'continue' ), 'alert' ) ) ),
            ),
            'wildfire' => array(
                'rule' => $fileRule( array( 'analysis' => array( 'text', array( 'public-cloud', 'private-cloud' ), 'public-cloud' ) ) ),
            ),
        );
    }

    /** per profile type: option => array( path below the profile entry, choices|null (null: an IP / text) ) */
    static public function options(): array
    {
        $yn = self::YESNO;
        return array(
            'virus' => array( 'packet-capture' => array( 'packet-capture', $yn ) ),
            'spyware' => array(
                'sinkhole-ipv4' => array( 'botnet-domains/sinkhole/ipv4-address', null ),
                'sinkhole-ipv6' => array( 'botnet-domains/sinkhole/ipv6-address', null ),
            ),
            'url-filtering' => array(
                'log-container-page-only' => array( 'log-container-page-only', $yn ),
                'safe-search-enforcement' => array( 'safe-search-enforcement', $yn ),
                'log-http-hdr-xff' => array( 'log-http-hdr-xff', $yn ),
                'log-http-hdr-user-agent' => array( 'log-http-hdr-user-agent', $yn ),
                'log-http-hdr-referer' => array( 'log-http-hdr-referer', $yn ),
                'local-inline-cat' => array( 'local-inline-cat', $yn ),
                'cloud-inline-cat' => array( 'cloud-inline-cat', $yn ),
            ),
        );
    }

    static private function profileType( $profile ): string
    {
        if( !isset( $profile->secprof_type ) || !( $profile->xmlroot instanceof DOMElement ) )
            throw new Exception( 'not a security profile with XML' );
        if( method_exists( $profile, 'isTmp' ) && $profile->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        return (string)$profile->secprof_type;
    }

    static private function listDef( $profile, string $list ): array
    {
        $type = self::profileType( $profile );
        $lists = self::lists()[$type] ?? null;
        if( $lists === null )
            throw new Exception( "profile type '" . $type . "': no lists (" . implode( ', ', array_keys( self::lists() ) ) . ')' );
        if( !isset( $lists[$list] ) )
            throw new Exception( "list '" . $list . "' of a " . $type . ' profile: ' . implode( ', ', array_keys( $lists ) ) );
        return $lists[$list];
    }

    /** the element of a path below the profile (created when $create) */
    static private function node( DOMElement $root, string $path, bool $create ): ?DOMElement
    {
        $n = $root;
        foreach( explode( '/', $path ) as $tag )
        {
            $c = DH::findFirstElement( $tag, $n );
            if( $c === FALSE )
            {
                if( !$create )
                    return null;
                $c = DH::createElement( $n, $tag );
            }
            $n = $c;
        }
        return $n;
    }

    static private function entry( DOMElement $listNode, string $name ): ?DOMElement
    {
        foreach( $listNode->childNodes as $e )
            if( $e->nodeType == XML_ELEMENT_NODE && $e->nodeName === 'entry' && $e->getAttribute( 'name' ) === $name )
                return $e;
        return null;
    }

    /** the entries of a list: name => field => value (list / entries: array) */
    static public function entries( $profile, string $list ): array
    {
        $def = self::listDef( $profile, $list );
        $out = array();
        $n = self::node( $profile->xmlroot, $def['path'], FALSE );
        if( $n === null )
            return $out;
        foreach( $n->childNodes as $e )
        {
            if( $e->nodeType != XML_ELEMENT_NODE || $e->nodeName !== 'entry' )
                continue;
            $row = array();
            foreach( $def['fields'] as $f => $fd )
                $row[$f] = self::readField( $e, $f, $fd[0] );
            $out[$e->getAttribute( 'name' )] = $row;
        }
        return $out;
    }

    static private function readField( DOMElement $e, string $f, string $kind )
    {
        $n = DH::findFirstElement( $f, $e );
        if( $kind === 'list' || $kind === 'entries' )
        {
            $vals = array();
            if( $n !== FALSE )
                foreach( $n->childNodes as $c )
                    if( $c->nodeType == XML_ELEMENT_NODE )
                        $vals[] = $kind === 'entries' ? $c->getAttribute( 'name' ) : $c->textContent;
            return $vals;
        }
        if( $n === FALSE )
            return '';
        if( $kind === 'choice' )
        {
            $c = DH::firstChildElement( $n );
            return $c === FALSE ? trim( $n->textContent ) : $c->nodeName;
        }
        return $n->textContent;
    }

    /** the value checked and normalised: list / entries split at '+' */
    static private function checkValue( string $f, array $fd, string $value )
    {
        list( $kind, $choices ) = $fd;
        $value = trim( PH::textAliases( $value ) );
        if( $kind === 'list' || $kind === 'entries' )
        {
            $vals = array_values( array_unique( array_filter( array_map( 'trim', explode( '+', $value ) ), 'strlen' ) ) );
            if( count( $vals ) == 0 )
                throw new Exception( $f . ': one value or more (joined with +)' );
            foreach( $vals as $v )
            {
                if( $choices !== null && !in_array( $v, $choices, TRUE ) )
                    throw new Exception( $f . " '" . $v . "': " . implode( ', ', $choices ) );
                if( preg_match( '/[\\x00-\\x1F]/', $v ) || strlen( $v ) > 255 )
                    throw new Exception( $f . " '" . $v . "': not valid" );
                if( $kind === 'entries' && !filter_var( explode( '/', $v )[0], FILTER_VALIDATE_IP ) )
                    throw new Exception( $f . " '" . $v . "': an IP address" );
            }
            if( count( $vals ) > 1 && in_array( 'any', $vals, TRUE ) )
                throw new Exception( $f . ': any with other values' );
            return $vals;
        }
        if( $value === '' || ( $choices !== null && !in_array( $value, $choices, TRUE ) ) )
            throw new Exception( $f . " '" . $value . "'" . ( $choices !== null ? ': ' . implode( ', ', $choices ) : ': a value' ) );
        if( preg_match( '/[\\x00-\\x1F]/', $value ) || strlen( $value ) > 255 )
            throw new Exception( $f . " '" . $value . "': not valid" );
        return $value;
    }

    static private function writeField( DOMElement $e, string $f, string $kind, $value ): void
    {
        $n = DH::findFirstElement( $f, $e );
        if( $n === FALSE )
            $n = DH::createElement( $e, $f );
        DH::clearDomNodeChilds( $n );
        if( $kind === 'list' )
            foreach( $value as $v )
                DH::createElement( $n, 'member', $v );
        elseif( $kind === 'entries' )
            foreach( $value as $v )
                DH::createElement( $n, 'entry' )->setAttribute( 'name', $v );
        elseif( $kind === 'choice' )
            DH::createElement( $n, $value );
        else
            DH::setDomNodeText( $n, $value );
    }

    /** detail-entry-add: an entry of a list with the default values of PAN-OS (rules: at the end) */
    static public function entryAdd( $profile, string $list, string $name ): void
    {
        $def = self::listDef( $profile, $list );
        if( !empty( $def['fixed'] ) )
            throw new Exception( "the entries of '" . $list . "' are fixed (PAN-OS) - detail-entry-set to change them" );
        if( !preg_match( $def['name'], $name ) )
            throw new Exception( "name '" . $name . "' is not valid for " . $list );
        $listNode = self::node( $profile->xmlroot, $def['path'], TRUE );
        if( self::entry( $listNode, $name ) !== null )
            throw new Exception( $list . " '" . $name . "' exists already" );
        $e = DH::createElement( $listNode, 'entry' );
        $e->setAttribute( 'name', $name );
        foreach( $def['fields'] as $f => $fd )
            if( $fd[2] !== null )
                self::writeField( $e, $f, $fd[0], $fd[0] === 'list' ? array( $fd[2] ) : $fd[2] );
    }

    static public function entryRemove( $profile, string $list, string $name ): void
    {
        $def = self::listDef( $profile, $list );
        if( !empty( $def['fixed'] ) )
            throw new Exception( "the entries of '" . $list . "' are fixed (PAN-OS)" );
        $listNode = self::node( $profile->xmlroot, $def['path'], FALSE );
        $e = $listNode === null ? null : self::entry( $listNode, $name );
        if( $e === null )
            throw new Exception( $list . " '" . $name . "' not found" );
        $listNode->removeChild( $e );
    }

    /** detail-entry-set: one field of an entry (a fixed list - decoder, DNS category: the entry is created when missing) */
    static public function entrySet( $profile, string $list, string $name, string $field, string $value ): string
    {
        $def = self::listDef( $profile, $list );
        if( !isset( $def['fields'][$field] ) )
            throw new Exception( "field '" . $field . "' of " . $list . ': ' . implode( ', ', array_keys( $def['fields'] ) ) );
        $fd = $def['fields'][$field];
        $v = self::checkValue( $field, $fd, $value );
        $listNode = self::node( $profile->xmlroot, $def['path'], !empty( $def['fixed'] ) || $list === 'dns-category' );
        $e = $listNode === null ? null : self::entry( $listNode, $name );
        if( $e === null && $list === 'dns-category' && preg_match( $def['name'], $name ) )
        {
            self::entryAdd( $profile, $list, $name );
            $e = self::entry( $listNode, $name );
        }
        // a decoder of PAN-OS not in the XML yet: with 'default' in every field
        if( $e === null && in_array( $name, $def['known'] ?? array(), TRUE ) )
        {
            $e = DH::createElement( $listNode, 'entry' );
            $e->setAttribute( 'name', $name );
            foreach( $def['fields'] as $f => $x )
                self::writeField( $e, $f, 'text', 'default' );
        }
        if( $e === null )
            throw new Exception( $list . " '" . $name . "' not found" . ( isset( $def['known'] ) ? ' (' . implode( ', ', $def['known'] ) . ')' : '' ) );
        if( self::readField( $e, $field, $fd[0] ) === $v )
            throw new Exception( $field . ' is the same' );
        self::writeField( $e, $field, $fd[0], $v );
        return is_array( $v ) ? implode( '+', $v ) : $v;
    }

    /** detail-option-set: an option of the profile */
    static public function optionSet( $profile, string $option, string $value ): string
    {
        $type = self::profileType( $profile );
        $opts = self::options()[$type] ?? array();
        if( !isset( $opts[$option] ) )
            throw new Exception( "option '" . $option . "' of a " . $type . ' profile' . ( count( $opts ) ? ': ' . implode( ', ', array_keys( $opts ) ) : ': none' ) );
        list( $path, $choices ) = $opts[$option];
        $value = trim( PH::textAliases( $value ) );
        if( $choices !== null && !in_array( $value, $choices, TRUE ) )
            throw new Exception( $option . " '" . $value . "': " . implode( ', ', $choices ) );
        if( $choices === null )
        {
            $ok = $option === 'sinkhole-ipv4' ? ( filter_var( $value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) || in_array( $value, array( 'pan-sinkhole-default-ip', '127.0.0.1' ), TRUE ) )
                : ( filter_var( $value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) || $value === '::1' );
            if( !$ok )
                throw new Exception( $option . " '" . $value . "': " . ( $option === 'sinkhole-ipv4' ? 'an IPv4 address or pan-sinkhole-default-ip' : 'an IPv6 address' ) );
        }
        $n = self::node( $profile->xmlroot, $path, TRUE );
        if( $n->textContent === $value )
            throw new Exception( $option . ' is ' . $value . ' already' );
        DH::setDomNodeText( $n, $value );
        return $value;
    }

    /**
     * Everything a window needs, from this one table: per list its fields (kind, choices, default), fixed / known
     * entries and the entries with their values; per option the choices and the value; url-filtering: the action of
     * every category and of the credential detection. null: a type without details here.
     */
    static public function describe( $profile ): ?array
    {
        if( !isset( $profile->secprof_type ) || !( $profile->xmlroot instanceof DOMElement ) )
            return null;
        $type = (string)$profile->secprof_type;
        $out = array( 'type' => $type, 'lists' => array(), 'options' => array() );
        foreach( self::lists()[$type] ?? array() as $list => $def )
        {
            $fields = array();
            foreach( $def['fields'] as $f => $fd )
                $fields[$f] = array( 'kind' => $fd[0], 'choices' => $fd[1], 'default' => $fd[2] );
            $out['lists'][$list] = array( 'fields' => $fields, 'fixed' => !empty( $def['fixed'] ), 'known' => $def['known'] ?? null,
                'entries' => self::entries( $profile, $list ) );
        }
        foreach( self::options()[$type] ?? array() as $opt => $od )
        {
            $n = self::node( $profile->xmlroot, $od[0], FALSE );
            $out['options'][$opt] = array( 'choices' => $od[1], 'value' => $n === null ? '' : $n->textContent );
        }
        if( $type === 'url-filtering' )
        {
            $read = function( DOMElement $root, array $actions ) {
                $r = array();
                foreach( $actions as $a )
                {
                    $l = DH::findFirstElement( $a, $root );
                    if( $l !== FALSE )
                        foreach( $l->childNodes as $m )
                            if( $m->nodeType == XML_ELEMENT_NODE )
                                $r[$m->textContent] = $a;
                }
                ksort( $r );
                return $r;
            };
            $out['categories'] = $read( $profile->xmlroot, array( 'alert', 'allow', 'block', 'continue', 'override' ) );
            $ce = DH::findFirstElement( 'credential-enforcement', $profile->xmlroot );
            $out['credential'] = $ce === FALSE ? array() : $read( $ce, array( 'alert', 'allow', 'block', 'continue' ) );
            $out['categoryActions'] = array( 'alert', 'allow', 'block', 'continue', 'override' );
            $out['credentialActions'] = array( 'alert', 'allow', 'block', 'continue' );
        }
        if( count( $out['lists'] ) == 0 && count( $out['options'] ) == 0 && !isset( $out['categories'] ) )
            return null;
        return $out;
    }

    /** url.credential-action-set: the action of a URL category for the credential detection (one action list per category) */
    static public function urlCredentialActionSet( $profile, string $category, string $action ): void
    {
        if( self::profileType( $profile ) !== 'url-filtering' )
            throw new Exception( 'only for a url-filtering profile' );
        $actions = array( 'alert', 'allow', 'block', 'continue' );
        if( !in_array( $action, $actions, TRUE ) )
            throw new Exception( "action '" . $action . "': " . implode( ', ', $actions ) );
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/', $category ) )
            throw new Exception( "category '" . $category . "': a name" );
        $ce = self::node( $profile->xmlroot, 'credential-enforcement', TRUE );
        $found = null;
        foreach( $actions as $a )
        {
            $l = DH::findFirstElement( $a, $ce );
            if( $l === FALSE )
                continue;
            foreach( iterator_to_array( $l->childNodes ) as $m )
                if( $m->nodeType == XML_ELEMENT_NODE && $m->textContent === $category )
                {
                    if( $a === $action )
                        throw new Exception( "category '" . $category . "' is " . $action . ' already' );
                    $l->removeChild( $m );
                    $found = $a;
                }
            if( DH::firstChildElement( $l ) === FALSE )
                $ce->removeChild( $l );
        }
        DH::createElement( self::node( $ce, $action, TRUE ), 'member', $category );
    }
}
