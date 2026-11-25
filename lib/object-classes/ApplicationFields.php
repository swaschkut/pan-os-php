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
 * The fields of a custom application, an application group and an application filter - one table for the actions of
 * type=application (detail-option-set, detail-entry-add / -remove, name-rename) and the window of the config viewer
 * (ObjectFieldData). Every edit changes the XML of the object and reads the object again from it. The categories,
 * subcategories and technologies are those of the predefined applications (App-ID database). Predefined applications
 * are read only (CallContext::readOnlyReason).
 */
class ApplicationFields
{
    const YESNO = array( 'yes', 'no' );
    const RISK = array( '1', '2', '3', '4', '5' );

    /**
     * custom application: option => array( kind, choices|null ); kind text | number | yesno | choice | app; in PAN-OS
     * order (a new element is written at its place)
     */
    const CUSTOM_OPTIONS = array(
        'category' => array( 'choice', 'category' ),
        'subcategory' => array( 'choice', 'subcategory' ),
        'technology' => array( 'choice', 'technology' ),
        'description' => array( 'text', null ),
        'timeout' => array( 'number', null ),
        'tcp-timeout' => array( 'number', null ),
        'udp-timeout' => array( 'number', null ),
        'tcp-half-closed-timeout' => array( 'number', null ),
        'tcp-time-wait-timeout' => array( 'number', null ),
        'risk' => array( 'choice', self::RISK ),
        'evasive-behavior' => array( 'yesno', self::YESNO ),
        'consume-big-bandwidth' => array( 'yesno', self::YESNO ),
        'used-by-malware' => array( 'yesno', self::YESNO ),
        'able-to-transfer-files' => array( 'yesno', self::YESNO ),
        'has-known-vulnerabilities' => array( 'yesno', self::YESNO ),
        'tunnels-other-apps' => array( 'yesno', self::YESNO ),
        'prone-to-misuse' => array( 'yesno', self::YESNO ),
        'pervasive-use' => array( 'yesno', self::YESNO ),
        'file-type-ident' => array( 'yesno', self::YESNO ),
        'virus-ident' => array( 'yesno', self::YESNO ),
        'data-ident' => array( 'yesno', self::YESNO ),
        'parent-app' => array( 'app', null ),
        'ip-protocol' => array( 'number', null ),
    );
    /** the elements of a custom application in PAN-OS order ('default' holds the ports / the IP protocol) */
    const CUSTOM_ORDER = array( 'default', 'category', 'subcategory', 'technology', 'description', 'timeout', 'tcp-timeout', 'udp-timeout',
        'tcp-half-closed-timeout', 'tcp-time-wait-timeout', 'risk', 'evasive-behavior', 'consume-big-bandwidth', 'used-by-malware',
        'able-to-transfer-files', 'has-known-vulnerabilities', 'tunnels-other-apps', 'prone-to-misuse', 'pervasive-use', 'file-type-ident',
        'virus-ident', 'data-ident', 'parent-app', 'signature' );

    /** application filter: the yes / no characteristics */
    const FILTER_OPTIONS = array( 'evasive', 'excessive-bandwidth-use', 'used-by-malware', 'transfers-files', 'has-known-vulnerabilities',
        'tunnels-other-apps', 'prone-to-misuse', 'pervasive' );
    /** application filter: list => element (tag: tagging/tag) */
    const FILTER_LISTS = array( 'category' => 'category', 'subcategory' => 'subcategory', 'technology' => 'technology', 'risk' => 'risk',
        'tag' => 'tagging/tag', 'exclude' => 'exclude' );
    const FILTER_ORDER = array( 'category', 'subcategory', 'technology', 'evasive', 'excessive-bandwidth-use', 'used-by-malware', 'transfers-files',
        'has-known-vulnerabilities', 'tunnels-other-apps', 'prone-to-misuse', 'pervasive', 'risk', 'tagging', 'exclude' );

    /** @var array|null category => subcategories, 'technology' => technologies */
    static private $taxonomy = null;

    /** the kind of an application object: custom | group | filter | null (predefined / tmp) */
    static public function kindOf( $app ): ?string
    {
        if( $app instanceof AppCustom )
            return 'custom';
        if( $app instanceof AppGroup )
            return 'group';
        if( $app instanceof AppFilter )
            return 'filter';
        return null;
    }

    /**
     * categories with their subcategories and the technologies of the predefined applications
     * @return array array( 'category' => array( cat => subcat[] ), 'technology' => string[] )
     */
    static public function taxonomy(): array
    {
        if( self::$taxonomy !== null )
            return self::$taxonomy;
        $cat = array();
        $tech = array();
        $store = AppStore::$predefinedStore;
        if( $store !== null )
            foreach( $store->apps() as $a )
            {
                if( is_string( $a->category ) && $a->category !== '' )
                {
                    if( !isset( $cat[$a->category] ) )
                        $cat[$a->category] = array();
                    if( is_string( $a->subCategory ) && $a->subCategory !== '' )
                        $cat[$a->category][$a->subCategory] = $a->subCategory;
                }
                if( is_string( $a->technology ) && $a->technology !== '' )
                    $tech[$a->technology] = $a->technology;
            }
        ksort( $cat );
        foreach( $cat as &$s )
        {
            $s = array_values( $s );
            sort( $s );
        }
        unset( $s );
        $tech = array_values( $tech );
        sort( $tech );
        if( $cat !== array() )
            self::$taxonomy = array( 'category' => $cat, 'technology' => $tech );
        return array( 'category' => $cat, 'technology' => $tech );
    }

    /** the choices of a taxonomy field (an empty list: not known - every value is taken) */
    static public function choices( string $what, ?string $category = null ): array
    {
        $t = self::taxonomy();
        if( $what === 'category' )
            return array_keys( $t['category'] );
        if( $what === 'technology' )
            return $t['technology'];
        if( $what === 'subcategory' )
        {
            if( $category !== null && isset( $t['category'][$category] ) )
                return $t['category'][$category];
            $all = array();
            foreach( $t['category'] as $s )
                $all = array_merge( $all, $s );
            $all = array_values( array_unique( $all ) );
            sort( $all );
            return $all;
        }
        return array();
    }

    // ------------------------------------------------------------------ description for the window

    /** null: no fields (predefined / tmp application) */
    static public function describe( $app ): ?array
    {
        $kind = self::kindOf( $app );
        if( $kind === null || $app->xmlroot === null )
            return null;
        $root = $app->xmlroot;
        if( $kind === 'group' )
            return array( 'app-kind' => 'group', 'lists' => array( 'member' => array( 'entries' => array_map( function( $m ) { return $m->name(); }, $app->members() ),
                'pick' => 'application' ) ) );
        if( $kind === 'filter' )
        {
            $options = array();
            foreach( self::FILTER_OPTIONS as $o )
                $options[$o] = array( 'value' => self::childText( $root, $o ) === 'yes' ? 'yes' : 'no', 'choices' => self::YESNO );
            $lists = array();
            foreach( self::FILTER_LISTS as $l => $path )
                $lists[$l] = array( 'entries' => self::members( $root, $path ),
                    'choices' => in_array( $l, array( 'category', 'subcategory', 'technology' ), TRUE ) ? self::choices( $l ) : ( $l === 'risk' ? self::RISK : null ),
                    'pick' => $l === 'exclude' ? 'application' : null );
            return array( 'app-kind' => 'filter', 'options' => $options, 'lists' => $lists );
        }
        $options = array();
        $category = self::childText( $root, 'category' );
        foreach( self::CUSTOM_OPTIONS as $o => $def )
        {
            $v = $o === 'ip-protocol' ? self::childText( $root, 'default/ident-by-ip-protocol' ) : self::childText( $root, $o );
            if( $def[0] === 'yesno' )
                $v = $v === 'yes' ? 'yes' : 'no';
            $choices = $def[1];
            if( is_string( $choices ) )
                $choices = self::choices( $choices, $category );
            $options[$o] = array( 'value' => $v === null ? '' : $v, 'kind' => $def[0], 'choices' => $choices, 'pick' => $def[0] === 'app' ? 'application' : null );
        }
        return array( 'app-kind' => 'custom', 'options' => $options,
            'lists' => array( 'port' => array( 'entries' => self::members( $root, 'default/port' ), 'choices' => null, 'pick' => null ) ),
            'signature' => DH::findFirstElement( 'signature', $root ) !== FALSE );
    }

    // ------------------------------------------------------------------ edits (an Exception with the reason if refused)

    /** detail-option-set: a custom application option or a filter characteristic; '' removes an option */
    static public function optionSet( $app, string $option, string $value ): void
    {
        $kind = self::checkEditable( $app );
        $value = trim( $value );
        $root = $app->xmlroot;
        if( $kind === 'filter' )
        {
            if( !in_array( $option, self::FILTER_OPTIONS, TRUE ) )
                throw new Exception( "an application filter has no option '" . $option . "' (" . implode( ', ', self::FILTER_OPTIONS ) . ")" );
            if( !in_array( $value, self::YESNO, TRUE ) )
                throw new Exception( $option . ": yes or no" );
            if( ( self::childText( $root, $option ) === 'yes' ) === ( $value === 'yes' ) )
                throw new Exception( $option . " is " . $value . " already" );
            self::setChild( $root, $option, $value === 'yes' ? 'yes' : null, self::FILTER_ORDER );
            self::reload( $app );
            return;
        }
        if( $kind !== 'custom' )
            throw new Exception( 'an application group has no options - members only' );
        if( !isset( self::CUSTOM_OPTIONS[$option] ) )
            throw new Exception( "a custom application has no option '" . $option . "' (" . implode( ', ', array_keys( self::CUSTOM_OPTIONS ) ) . ")" );
        list( $type, $choices ) = self::CUSTOM_OPTIONS[$option];
        if( is_string( $choices ) )
            $choices = self::choices( $choices, $option === 'subcategory' ? self::childText( $root, 'category' ) : null );

        if( $type === 'yesno' )
        {
            if( !in_array( $value, self::YESNO, TRUE ) )
                throw new Exception( $option . ": yes or no" );
            if( ( self::childText( $root, $option ) === 'yes' ) === ( $value === 'yes' ) )
                throw new Exception( $option . " is " . $value . " already" );
            self::setChild( $root, $option, $value, self::CUSTOM_ORDER );
            self::reload( $app );
            return;
        }

        if( $value !== '' )
        {
            if( $type === 'number' )
            {
                $max = $option === 'ip-protocol' ? 255 : 604800;
                if( !ctype_digit( $value ) || (int)$value > $max || ( $option !== 'ip-protocol' && (int)$value < 1 ) )
                    throw new Exception( $option . " '" . $value . "': a number " . ( $option === 'ip-protocol' ? '0' : '1' ) . " - " . $max );
            }
            elseif( $type === 'choice' && is_array( $choices ) && $choices !== array() && !in_array( $value, $choices, TRUE ) )
                throw new Exception( $option . " '" . $value . "': one of " . implode( ', ', $choices ) );
            elseif( $type === 'app' )
            {
                if( $value === $app->name() )
                    throw new Exception( 'an application can not be its own parent' );
                $p = $app->owner->find( $value );
                if( $p === null || $p->isTmp() || $p->isApplicationGroup() || $p->isApplicationFilter() )
                    throw new Exception( "parent-app '" . $value . "': no application of the location, above it or predefined" );
            }
            elseif( $type === 'text' && strlen( $value ) > 1023 )
                throw new Exception( $option . ': at most 1023 characters' );
        }
        elseif( in_array( $option, array( 'category', 'subcategory', 'technology', 'risk' ), TRUE ) )
            throw new Exception( $option . ' is needed by PAN-OS - it can be changed, not removed' );

        if( $option === 'ip-protocol' )
        {
            $cur = self::childText( $root, 'default/ident-by-ip-protocol' );
            if( (string)$cur === $value )
                throw new Exception( $value === '' ? 'the application is not identified by an IP protocol' : "ip-protocol is " . $value . " already" );
            if( $value !== '' && self::members( $root, 'default/port' ) !== array() )
                throw new Exception( 'the application is identified by ports - remove the ports first (PAN-OS: ports or IP protocol)' );
            $default = DH::findFirstElement( 'default', $root );
            if( $value === '' )
                $root->removeChild( $default );
            else
            {
                if( $default === FALSE )
                    $default = self::setChild( $root, 'default', '', self::CUSTOM_ORDER );
                DH::clearDomNodeChilds( $default );
                DH::createElement( $default, 'ident-by-ip-protocol', $value );
            }
            self::reload( $app );
            return;
        }

        if( (string)self::childText( $root, $option ) === $value )
            throw new Exception( $value === '' ? $option . ' is not set' : $option . " is '" . $value . "' already" );
        self::setChild( $root, $option, $value === '' ? null : $value, self::CUSTOM_ORDER );
        // a new category: a subcategory of another category does not fit any more
        if( $option === 'category' )
        {
            $sub = self::childText( $root, 'subcategory' );
            $subs = self::choices( 'subcategory', $value );
            if( $sub !== null && $subs !== array() && !in_array( $sub, $subs, TRUE ) )
                self::setChild( $root, 'subcategory', $subs[0], self::CUSTOM_ORDER );
        }
        self::reload( $app );
    }

    /** detail-entry-add: custom - port (tcp/80,443 | udp/53 | tcp/dynamic); group - member; filter - category, subcategory, technology, risk, tag, exclude */
    static public function entryAdd( $app, string $list, string $value ): void
    {
        $kind = self::checkEditable( $app );
        $value = trim( $value );
        $root = $app->xmlroot;
        if( $value === '' )
            throw new Exception( 'no value' );
        if( $kind === 'group' )
        {
            self::checkList( $kind, $list );
            $m = self::findApp( $app, $value );
            if( $m === $app )
                throw new Exception( 'a group can not be its own member' );
            if( in_array( $m->name(), array_map( function( $x ) { return $x->name(); }, $app->members() ), TRUE ) )
                throw new Exception( "'" . $value . "' is a member already" );
            DH::createElement( DH::findFirstElementOrCreate( 'members', $root ), 'member', $m->name() );
            self::reload( $app );
            return;
        }
        if( $kind === 'custom' )
        {
            self::checkList( $kind, $list );
            if( !self::validPort( $value ) )
                throw new Exception( "port '" . $value . "': tcp/<ports> or udp/<ports> - ports 0-65535, ranges a-b, several with comma, or dynamic" );
            if( self::childText( $root, 'default/ident-by-ip-protocol' ) !== null )
                throw new Exception( 'the application is identified by an IP protocol - remove it first (PAN-OS: ports or IP protocol)' );
            if( in_array( $value, self::members( $root, 'default/port' ), TRUE ) )
                throw new Exception( "'" . $value . "' is a port entry already" );
            $default = DH::findFirstElement( 'default', $root );
            if( $default === FALSE )
                $default = self::setChild( $root, 'default', '', self::CUSTOM_ORDER );
            foreach( iterator_to_array( $default->childNodes ) as $c )
                if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName !== 'port' )
                    $default->removeChild( $c );
            DH::createElement( DH::findFirstElementOrCreate( 'port', $default ), 'member', $value );
            self::reload( $app );
            return;
        }
        // filter
        self::checkList( $kind, $list );
        if( $list === 'exclude' )
            $value = self::findApp( $app, $value )->name();
        elseif( $list === 'risk' && !in_array( $value, self::RISK, TRUE ) )
            throw new Exception( "risk '" . $value . "': 1 - 5" );
        elseif( in_array( $list, array( 'category', 'subcategory', 'technology' ), TRUE ) )
        {
            $c = self::choices( $list );
            if( $c !== array() && !in_array( $value, $c, TRUE ) )
                throw new Exception( $list . " '" . $value . "': not a " . $list . " of the App-ID database" );
        }
        $path = self::FILTER_LISTS[$list];
        if( in_array( $value, self::members( $root, $path ), TRUE ) )
            throw new Exception( "'" . $value . "' is in " . $list . " already" );
        $parts = explode( '/', $path );
        $node = self::setChild( $root, $parts[0], DH::findFirstElement( $parts[0], $root ) === FALSE ? '' : null, self::FILTER_ORDER, TRUE );
        if( count( $parts ) == 2 )
            $node = DH::findFirstElementOrCreate( $parts[1], $node );
        DH::createElement( $node, 'member', $value );
        self::reload( $app );
    }

    /** detail-entry-remove */
    static public function entryRemove( $app, string $list, string $value ): void
    {
        $kind = self::checkEditable( $app );
        self::checkList( $kind, $list );
        $value = trim( $value );
        $root = $app->xmlroot;
        $path = $kind === 'group' ? 'members' : ( $kind === 'custom' ? 'default/port' : self::FILTER_LISTS[$list] );
        $node = self::node( $root, $path );
        $found = null;
        if( $node !== null )
            foreach( $node->childNodes as $c )
                if( $c->nodeType == XML_ELEMENT_NODE && trim( $c->textContent ) === $value )
                    $found = $c;
        if( $found === null )
            throw new Exception( "'" . $value . "' is not in " . $list );
        if( $kind === 'group' && count( self::members( $root, $path ) ) == 1 )
            throw new Exception( 'the last member of a group can not be removed' );
        $node->removeChild( $found );
        // an empty list goes (tagging / default with its parent)
        while( $node !== $root && !self::hasElements( $node ) )
        {
            $parent = $node->parentNode;
            $parent->removeChild( $node );
            $node = $parent;
        }
        self::reload( $app );
    }

    /**
     * name-rename: the application and every rule / group / filter that uses it
     * @return int the number of users
     */
    static public function rename( $app, string $newName ): int
    {
        self::checkEditable( $app );
        $newName = trim( $newName );
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,30}$/', $newName ) )
            throw new Exception( "name '" . $newName . "': 1-31 characters, letters, digits, blank, . _ -" );
        if( $newName === $app->name() )
            throw new Exception( 'the name is the same' );
        if( $app->owner->find( $newName ) !== null && !$app->owner->find( $newName )->isTmp() )
            throw new Exception( "'" . $newName . "' exists already (an application of the location, above it or predefined)" );
        $store = $app->owner;
        $old = $app->name();
        $app->editSetName( $newName );
        $app->xmlroot->setAttribute( 'name', $newName );
        foreach( array( 'apps_custom', 'app_groups', 'app_filters', 'apps' ) as $index )
            if( isset( $store->$index[$old] ) && $store->$index[$old] === $app )
            {
                unset( $store->$index[$old] );
                $store->$index[$newName] = $app;
            }
        return count( $app->getReferences() );
    }

    // ------------------------------------------------------------------ helpers

    static private function checkEditable( $app ): string
    {
        $kind = self::kindOf( $app );
        if( $kind === null )
            throw new Exception( 'a predefined application can not be changed' );
        if( $app->xmlroot === null || $app->owner === null )
            throw new Exception( 'the application is not part of a configuration' );
        return $kind;
    }

    static private function checkList( string $kind, string $list ): void
    {
        $lists = $kind === 'group' ? array( 'member' ) : ( $kind === 'custom' ? array( 'port' ) : array_keys( self::FILTER_LISTS ) );
        if( !in_array( $list, $lists, TRUE ) )
            throw new Exception( array( "group" => "an application group", "custom" => "a custom application", "filter" => "an application filter" )[$kind] . " has no list '" . $list . "' (" . implode( ', ', $lists ) . ")" );
    }

    static private function findApp( $app, string $name )
    {
        $m = $app->owner->find( $name );
        if( $m === null || $m->isTmp() )
            throw new Exception( "'" . $name . "': no application, group or filter of the location, above it or predefined" );
        return $m;
    }

    static private function validPort( string $v ): bool
    {
        if( !preg_match( '#^(tcp|udp)/(.+)$#', $v, $m ) )
            return FALSE;
        if( $m[2] === 'dynamic' )
            return TRUE;
        foreach( explode( ',', $m[2] ) as $p )
        {
            if( !preg_match( '/^([0-9]{1,5})(?:-([0-9]{1,5}))?$/', $p, $r ) )
                return FALSE;
            if( (int)$r[1] > 65535 || ( isset( $r[2] ) && ( (int)$r[2] > 65535 || (int)$r[2] < (int)$r[1] ) ) )
                return FALSE;
        }
        return TRUE;
    }

    static private function node( DOMElement $root, string $path ): ?DOMElement
    {
        $n = $root;
        foreach( explode( '/', $path ) as $p )
        {
            $n = DH::findFirstElement( $p, $n );
            if( $n === FALSE )
                return null;
        }
        return $n;
    }

    static private function childText( DOMElement $root, string $path ): ?string
    {
        $n = self::node( $root, $path );
        return $n === null ? null : trim( $n->textContent );
    }

    static private function members( DOMElement $root, string $path ): array
    {
        $n = self::node( $root, $path );
        $out = array();
        if( $n !== null )
            foreach( $n->childNodes as $c )
                if( $c->nodeType == XML_ELEMENT_NODE )
                    $out[] = trim( $c->textContent );
        return $out;
    }

    static private function hasElements( DOMElement $n ): bool
    {
        foreach( $n->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                return TRUE;
        return FALSE;
    }

    /**
     * an element of the entry at its place ($order); $value null: removed; '' with $keep: an empty element (a list)
     * @return DOMElement|null
     */
    static private function setChild( DOMElement $root, string $tag, ?string $value, array $order, bool $keep = FALSE ): ?DOMElement
    {
        $n = DH::findFirstElement( $tag, $root );
        if( $value === null && !$keep )
        {
            if( $n !== FALSE )
                $root->removeChild( $n );
            return null;
        }
        if( $n === FALSE )
        {
            $n = $root->ownerDocument->createElement( $tag );
            $before = null;
            $pos = array_search( $tag, $order, TRUE );
            foreach( $root->childNodes as $c )
                if( $c->nodeType == XML_ELEMENT_NODE && ( $i = array_search( $c->nodeName, $order, TRUE ) ) !== FALSE && $pos !== FALSE && $i > $pos )
                {
                    $before = $c;
                    break;
                }
            $before === null ? $root->appendChild( $n ) : $root->insertBefore( $n, $before );
        }
        if( $value !== null && $value !== '' )
            DH::setDomNodeText( $n, $value );
        return $n;
    }

    /** the object again from its XML (custom / filter: every property; group: the members with their references) */
    static private function reload( $app ): void
    {
        $app->resetLoadedProperties();
        $app->load_from_domxml( $app->xmlroot );
    }
}
