<?php
/**
 * ISC License
 *
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

/**
 * Rules as the firewalls of a location see them - names resolved to values.
 *
 * Location: a DeviceGroup (its firewalls: Shared + parent device groups + the device group, same-name objects and
 * 'ancestor-objects-take-precedence' honoured), a PanoramaConf (Shared only) or a VirtualSystem - the name resolution is
 * PH::resolveNameForFirewalls() / PH::expandForFirewalls(), the same as rule-compare resolvemode=firewall.
 *
 * Works on the rule XML (any rule type: security, nat, decryption, authentication, pbf, ...), so two configurations
 * (or a configuration before / after a change) can be compared rule by rule:
 *
 *   resolve($ruleNode, $type, $location)     field => sorted list of resolved values
 *   signature($resolved)                     array( match hash, action hash )
 *   firewallRulebase($pan, $location)        the rules reaching the firewalls of $location, in evaluation order
 *   compare($viewA, $viewB, $keyMap)         rule pairs: same / changed (with the fields) / only in A / only in B
 *
 * Resolved values:
 *   source / destination   'any' or IPv4 / IPv6 ranges (merged, start-end) + 'fqdn:<value>', 'edl:<name>',
 *                          'region:<name>', 'unresolved:<name>'
 *   service                'any', 'application-default' or 'tcp/...', 'udp/...', 'sport:...' (port mapping)
 *   application            application names with groups expanded, 'filter:<name>' for application filters
 *   profiles               'group:<name>' resolved to '<type>:<profile>' entries, or the profiles of the rule
 *   other fields           member values / text as configured (zones, users, URL categories, HIP, action, ...)
 * Fields not listed in FIELDS are compared as canonical XML ('other').
 */
class RuleResolver
{
    /** rule fields with resolved values; everything else of the rule goes canonicalised into 'other' */
    const FIELDS = array(
        'from', 'to', 'source', 'destination', 'negate-source', 'negate-destination', 'source-user', 'application', 'service',
        'category', 'source-hip', 'destination-hip', 'action', 'profile-setting',
    );
    /** fields of the match part (the rest is the action part); for non-security rules 'other' belongs to the match too */
    const MATCH = array( 'type', 'from', 'to', 'source', 'destination', 'negate-source', 'negate-destination', 'source-user',
        'application', 'service', 'category', 'source-hip', 'destination-hip' );
    /** not compared at all: documentation, targeting, logging, ids */
    const IGNORE = array( 'description', 'tag', 'group-tag', 'target', 'disabled', 'log-setting', 'log-start', 'log-end',
        'log-end-only', 'uuid', 'rule-type-hint' );

    /**
     * @param DOMElement $node rule entry
     * @param string $type rule type (security, nat, decryption, ...)
     * @param DeviceGroup|PanoramaConf|VirtualSystem $location
     * @return array field => array of strings (sorted), plus 'type'
     */
    public static function resolve( $node, $type, $location )
    {
        $r = array( 'type' => array( $type ) );
        $other = array();
        foreach( $node->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE || in_array($c->nodeName, self::IGNORE, TRUE) )
                continue;
            $f = $c->nodeName;
            if( !in_array($f, self::FIELDS, TRUE) )
            {
                $other[] = self::canon( $c );
                continue;
            }
            $values = self::values( $c );
            if( $f == 'source' || $f == 'destination' )
                $r[$f] = self::addresses( $values, $location );
            elseif( $f == 'service' )
                $r[$f] = self::services( $values, $location );
            elseif( $f == 'application' )
                $r[$f] = self::applications( $values, $location );
            elseif( $f == 'profile-setting' )
                $r['profiles'] = self::profiles( $c, $location );
            else
                $r[$f] = self::sorted( $values );
        }
        // defaults so that a missing element equals its default value
        foreach( array( 'negate-source' => 'no', 'negate-destination' => 'no' ) as $f => $d )
            if( !isset($r[$f]) ) $r[$f] = array( $d );
        if( $type == 'security' && !isset($r['profiles']) )
            $r['profiles'] = array( 'none' );
        sort( $other );
        $r['other'] = $other;
        ksort( $r );
        return $r;
    }

    /** array( match hash, action hash ) */
    public static function signature( array $resolved )
    {
        $m = array(); $a = array();
        $security = isset($resolved['type']) && $resolved['type'] === array( 'security' );
        foreach( $resolved as $f => $v )
        {
            if( in_array($f, self::MATCH, TRUE) || ( $f == 'other' && !$security ) )
                $m[$f] = $v;
            else
                $a[$f] = $v;
        }
        return array( md5(json_encode($m)), md5(json_encode($a)) );
    }

    /** fields that differ between two resolved rules */
    public static function diff( array $a, array $b )
    {
        $out = array();
        foreach( array_unique( array_merge(array_keys($a), array_keys($b)) ) as $f )
        {
            $va = isset($a[$f]) ? $a[$f] : array();
            $vb = isset($b[$f]) ? $b[$f] : array();
            if( $va !== $vb )
                $out[$f] = array( 'only_in_a' => array_values(array_diff($va, $vb)), 'only_in_b' => array_values(array_diff($vb, $va)) );
        }
        return $out;
    }

    ////////////////////////////////////////////////////////////////////////////////

    /**
     * the rules reaching the firewalls of $location, in evaluation order:
     * Panorama: shared pre, device group pre top-down, device group post bottom-up, shared post; firewall: vsys rules
     * @return array of array( key, level, rulebase (pre|post|rulebase), type, name, node )
     */
    public static function firewallRulebase( $pan, $location, $types = null )
    {
        $out = array();
        if( $location instanceof DeviceGroup || $location instanceof PanoramaConf )
        {
            $chain = array();
            if( $location instanceof DeviceGroup )
                for( $dg = $location; $dg !== null; $dg = $dg->parentDeviceGroup )
                    $chain[] = $dg;
            $top = array_reverse( $chain );
            $levels = array( 'pre-rulebase' => array_merge( array( 'shared' => $pan->sharedroot ), self::dgRoots($top) ),
                'post-rulebase' => array_merge( self::dgRoots($chain), array( 'shared' => $pan->sharedroot ) ) );
            foreach( $levels as $w => $roots )
                foreach( $roots as $level => $root )
                    foreach( self::rules( $root, $w, $types ) as $r )
                        $out[] = $r + array( 'level' => $level, 'rulebase' => $w == 'pre-rulebase' ? 'pre' : 'post',
                            'key' => $level . '/' . ( $w == 'pre-rulebase' ? 'pre' : 'post' ) . '/' . $r['type'] . '/' . $r['name'] );
        }
        else
            foreach( self::rules( $location->xmlroot, 'rulebase', $types ) as $r )
                $out[] = $r + array( 'level' => $location->name(), 'rulebase' => 'rulebase', 'key' => $location->name() . '/' . $r['type'] . '/' . $r['name'] );
        return $out;
    }

    /**
     * resolve a rule base view (firewallRulebase) once: adds 'resolved' and 'signature' to every rule
     */
    public static function resolveView( array $view, $location )
    {
        foreach( $view as $i => $r )
        {
            $view[$i]['resolved'] = self::resolve( $r['node'], $r['type'], $location );
            $view[$i]['signature'] = self::signature( $view[$i]['resolved'] );
        }
        return $view;
    }

    /**
     * compare two resolved views; $keyMap maps a key of A to the key of the same rule in B (default: same key)
     * @return array( 'same' => [keyA => keyB], 'changed' => [keyA => array( keyB, diff )], 'only_a' => [keyA], 'only_b' => [keyB] )
     */
    public static function compare( array $viewA, array $viewB, $keyMap = null )
    {
        $byB = array();
        foreach( $viewB as $r ) $byB[$r['key']] = $r;
        $res = array( 'same' => array(), 'changed' => array(), 'only_a' => array(), 'only_b' => array() );
        $seen = array();
        foreach( $viewA as $r )
        {
            $kb = $keyMap === null ? $r['key'] : ( is_callable($keyMap) ? $keyMap($r) : ( isset($keyMap[$r['key']]) ? $keyMap[$r['key']] : $r['key'] ) );
            if( $kb === null || !isset($byB[$kb]) )
            {
                $res['only_a'][] = $r['key'];
                continue;
            }
            $seen[$kb] = TRUE;
            if( $r['signature'] === $byB[$kb]['signature'] )
                $res['same'][$r['key']] = $kb;
            else
                $res['changed'][$r['key']] = array( $kb, self::diff( $r['resolved'], $byB[$kb]['resolved'] ) );
        }
        foreach( $viewB as $r )
            if( !isset($seen[$r['key']]) )
                $res['only_b'][] = $r['key'];
        return $res;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // fields

    /** IPv4 / IPv6 ranges + non-IP entries */
    public static function addresses( array $names, $location )
    {
        if( !count($names) || in_array('any', $names, TRUE) )
            return array( 'any' );
        // IPv6 ranges are merged here: IPMap::sortAndRecalculate() compares the 128 bit values as floats (pan-os-php
        // sortArrayByStartValue() / '+ 1'), which mixes up neighbouring IPv6 addresses
        $m4 = new IP4Map(); $m6 = array(); $other = array();
        foreach( $names as $n )
        {
            $o = PH::resolveNameForFirewalls( 'addressStore', $n, $location );
            if( $o === null )
            {
                if( !self::addLiteral( $n, $m4, $m6 ) )
                    $other['unresolved:' . $n] = TRUE;
                continue;
            }
            $leaves = PH::expandForFirewalls( 'addressStore', $o, $location );
            if( !count($leaves) && method_exists($o, 'isGroup') && $o->isGroup() )
                $other['empty-group:' . $o->name()] = TRUE;
            foreach( $leaves as $leaf )
                self::addLeaf( $leaf, $m4, $m6, $other );
        }
        $out = array();
        $m4->sortAndRecalculate();
        $s = $m4->dumpToString();
        if( $s !== '' )
            foreach( explode(',', $s) as $e ) $out[] = $e;
        foreach( self::mergeBig( $m6 ) as $r )
            $out[] = self::bigCmp($r[0], $r[1]) == 0 ? cidr::inet_itop($r[0]) : cidr::inet_itop($r[0]) . '-' . cidr::inet_itop($r[1]);
        $other = array_keys( $other );
        sort( $other );
        return array_merge( $out, $other );
    }

    private static function addLiteral( $text, IP4Map $m4, array &$m6 )
    {
        $t = trim( $text );
        $isRange = strpos($t, '-') !== FALSE;
        $parts = $isRange ? explode('-', $t, 2) : explode('/', $t, 2);
        $ip = $parts[0];
        if( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== FALSE )
        {
            $m4->addMap( IP4Map::mapFromText($t), TRUE );
            return TRUE;
        }
        if( filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== FALSE )
        {
            foreach( IP6Map::mapFromText($t)->getMapArray() as $e )
                $m6[] = array( (string)$e['start'], (string)$e['end'] );
            return TRUE;
        }
        return FALSE;
    }

    private static function addLeaf( $leaf, IP4Map $m4, array &$m6, array &$other )
    {
        if( method_exists($leaf, 'isEDL') && $leaf->isEDL() )
        {
            $other['edl:' . $leaf->name()] = TRUE;
            return;
        }
        if( method_exists($leaf, 'isRegion') && $leaf->isRegion() )
        {
            $other['region:' . $leaf->name()] = TRUE;
            return;
        }
        if( method_exists($leaf, 'isType_FQDN') && $leaf->isType_FQDN() )
        {
            $other['fqdn:' . $leaf->value()] = TRUE;
            return;
        }
        if( method_exists($leaf, 'isTmpAddr') && $leaf->isTmpAddr() )
        {
            if( !self::addLiteral( $leaf->name(), $m4, $m6 ) )
                $other['unresolved:' . $leaf->name()] = TRUE;
            return;
        }
        if( method_exists($leaf, 'value') && ( method_exists($leaf, 'isType_ipNetmask') && ( $leaf->isType_ipNetmask() || $leaf->isType_ipRange() ) ) )
        {
            if( self::addLiteral( $leaf->value(), $m4, $m6 ) )
                return;
        }
        if( method_exists($leaf, 'getIP4Mapping') )
        {
            $map = $leaf->getIP4Mapping();
            if( $map->count() )
            {
                $m4->addMap( $map, TRUE );
                return;
            }
        }
        $other['unresolved:' . $leaf->name()] = TRUE;
    }

    /** 'any', 'application-default' or port mapping text */
    public static function services( array $names, $location )
    {
        if( !count($names) || in_array('any', $names, TRUE) )
            return array( 'any' );
        $out = array();
        $dst = new ServiceDstPortMapping();
        $src = new ServiceSrcPortMapping();
        $has = FALSE;
        foreach( $names as $n )
        {
            if( $n == 'application-default' )
            {
                $out['application-default'] = TRUE;
                continue;
            }
            $o = PH::resolveNameForFirewalls( 'serviceStore', $n, $location );
            if( $o === null )
            {
                $out['unresolved:' . $n] = TRUE;
                continue;
            }
            foreach( PH::expandForFirewalls( 'serviceStore', $o, $location ) as $leaf )
            {
                if( !method_exists($leaf, 'dstPortMapping') || ( method_exists($leaf, 'isTmpSrv') && $leaf->isTmpSrv() ) )
                {
                    $out['unresolved:' . $leaf->name()] = TRUE;
                    continue;
                }
                $dst->mergeWithMapping( $leaf->dstPortMapping( array(), $location ) );
                $src->mergeWithMapping( $leaf->srcPortMapping( array(), $location ) );
                $has = TRUE;
            }
        }
        if( $has )
        {
            foreach( explode(',', $dst->mappingToText()) as $e ) if( $e !== '' ) $out[$e] = TRUE;
            // a full source port range is the default (no source port configured) - not part of the value
            foreach( explode(',', $src->mappingToText()) as $e )
                if( $e !== '' && $e !== 'tcp/0-65535' && $e !== 'udp/0-65535' ) $out['sport:' . $e] = TRUE;
        }
        $out = array_keys( $out );
        sort( $out );
        return $out;
    }

    /** application names, groups expanded (by name, as the firewalls of $location see them) */
    public static function applications( array $names, $location, array &$visited = array() )
    {
        if( !count($names) || in_array('any', $names, TRUE) )
            return array( 'any' );
        $out = array();
        foreach( $names as $n )
        {
            if( isset($visited[$n]) )
                continue;
            $o = isset($location->appStore) && $location->appStore !== null ? PH::resolveNameForFirewalls( 'appStore', $n, $location ) : null;
            if( $o !== null && $o->isApplicationGroup() && method_exists($o, 'members') )
            {
                $visited[$n] = TRUE;
                $members = array();
                foreach( $o->members() as $m ) $members[] = $m->name();
                foreach( self::applications( $members, $location, $visited ) as $a ) $out[$a] = TRUE;
            }
            elseif( $o !== null && $o->isApplicationFilter() )
                $out['filter:' . $n] = TRUE;
            else
                $out[$n] = TRUE;
        }
        $out = array_keys( $out );
        sort( $out );
        return $out;
    }

    /** profile group resolved to its profiles: '<type>:<profile>' (+ 'group:<name>' when the group is not found) */
    public static function profiles( $setting, $location )
    {
        $out = array();
        $g = DH::findFirstElement( 'group', $setting );
        if( $g !== FALSE )
        {
            foreach( self::values( $g ) as $name )
            {
                $o = isset($location->securityProfileGroupStore) && $location->securityProfileGroupStore !== null
                    ? PH::resolveNameForFirewalls( 'securityProfileGroupStore', $name, $location ) : null;
                if( $o === null || !isset($o->xmlroot) || $o->xmlroot === null )
                {
                    $out[] = 'group:' . $name;
                    continue;
                }
                foreach( $o->xmlroot->childNodes as $c )
                    if( $c->nodeType == XML_ELEMENT_NODE )
                        foreach( self::values($c) as $p ) $out[] = $c->nodeName . ':' . $p;
            }
        }
        $p = DH::findFirstElement( 'profiles', $setting );
        if( $p !== FALSE )
            foreach( $p->childNodes as $c )
                if( $c->nodeType == XML_ELEMENT_NODE )
                    foreach( self::values($c) as $v ) $out[] = $c->nodeName . ':' . $v;
        if( !count($out) )
            $out[] = 'none';
        sort( $out );
        return array_values( array_unique($out) );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // helpers

    /** compare two non-negative integers given as decimal strings (128 bit IPv6 values) */
    public static function bigCmp( $a, $b )
    {
        $a = ltrim( (string)$a, '0' ); $b = ltrim( (string)$b, '0' );
        if( strlen($a) != strlen($b) )
            return strlen($a) < strlen($b) ? -1 : 1;
        return strcmp( $a, $b ) <=> 0;
    }

    /** decimal string + 1 */
    public static function bigInc( $a )
    {
        $a = (string)$a;
        for( $i = strlen($a) - 1; $i >= 0; $i-- )
        {
            if( $a[$i] != '9' )
                return substr($a, 0, $i) . chr( ord($a[$i]) + 1 ) . str_repeat('0', strlen($a) - $i - 1);
        }
        return '1' . str_repeat( '0', strlen($a) );
    }

    /** merge ranges array( start, end ) of decimal strings - overlapping and adjacent ranges are joined */
    public static function mergeBig( array $ranges )
    {
        usort( $ranges, function( $x, $y ) { return self::bigCmp($x[0], $y[0]); } );
        $out = array();
        foreach( $ranges as $r )
        {
            $n = count( $out );
            if( $n && self::bigCmp( $r[0], self::bigInc($out[$n-1][1]) ) <= 0 )
            {
                if( self::bigCmp( $r[1], $out[$n-1][1] ) > 0 )
                    $out[$n-1][1] = $r[1];
            }
            else
                $out[] = $r;
        }
        return $out;
    }

    /** member values, or the text of an element without members */
    public static function values( $node )
    {
        $out = array();
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == 'member' )
                $out[] = trim( $c->textContent );
        if( !count($out) && trim($node->textContent) !== '' && $node->getElementsByTagName('*')->length == 0 )
            $out[] = trim( $node->textContent );
        return $out;
    }

    private static function sorted( array $v )
    {
        sort( $v );
        return array_values( array_unique($v) );
    }

    /** canonical string of an element (whitespace and ids removed, member order irrelevant) */
    public static function canon( $node )
    {
        $d = new DOMDocument();
        $n = $d->importNode( $node, TRUE );
        $d->appendChild( $n );
        $x = new DOMXPath( $d );
        foreach( iterator_to_array($x->query('//text()[normalize-space(.)=""]')) as $t ) $t->parentNode->removeChild( $t );
        foreach( iterator_to_array($x->query('//@uuid | //@admin | //@dirtyId | //@time | //@loc | //@src')) as $a ) $a->ownerElement->removeAttributeNode( $a );
        foreach( iterator_to_array($x->query('//*[member]')) as $p )
        {
            $m = array();
            foreach( iterator_to_array($p->childNodes) as $c )
                if( $c->nodeName == 'member' ) { $m[] = trim($c->textContent); $p->removeChild($c); }
            sort( $m );
            foreach( $m as $v ) { $e = $d->createElement('member'); $e->appendChild($d->createTextNode($v)); $p->appendChild($e); }
        }
        return $n->C14N();
    }

    private static function dgRoots( array $dgs )
    {
        $o = array();
        foreach( $dgs as $dg ) $o[$dg->name()] = $dg->xmlroot;
        return $o;
    }

    /** rules of a rule base below $parent: array of array( type, name, node ) */
    public static function rules( $parent, $which, $types = null )
    {
        $out = array();
        if( $parent === null || $parent === FALSE )
            return $out;
        $rb = DH::findFirstElement( $which, $parent );
        if( $rb === FALSE )
            return $out;
        foreach( $rb->childNodes as $t )
        {
            if( $t->nodeType != XML_ELEMENT_NODE || $t->nodeName == 'default-security-rules' || ( $types !== null && !in_array($t->nodeName, $types, TRUE) ) )
                continue;
            $rules = DH::findFirstElement( 'rules', $t );
            if( $rules === FALSE )
                continue;
            foreach( $rules->childNodes as $e )
                if( $e->nodeType == XML_ELEMENT_NODE && $e->nodeName == 'entry' && $e->hasAttribute('name') )
                    $out[] = array( 'type' => $t->nodeName, 'name' => $e->getAttribute('name'), 'node' => $e );
        }
        return $out;
    }
}
