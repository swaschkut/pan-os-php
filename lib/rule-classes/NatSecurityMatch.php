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
 * NAT rule -> the security rules its traffic meets.
 *
 * PAN-OS: the NAT policy matches the original packet; the security policy matches the pre-NAT addresses and service
 * and the post-NAT zones. Source NAT / no NAT do not change the zones. Destination NAT: the destination zone of the
 * security rule is the zone of the egress interface of the translated address - the route lookup in the router
 * (virtual router, or logical router with advanced routing) of the ingress interface (the interfaces of the source
 * zones of the NAT rule). The route lookup is the one of the zone calculation (getIPtoZoneRouteMapping: connected
 * subnets and static routes, the narrowest wins). Bi-directional static source NAT: also the reverse direction (traffic
 * arriving in the destination zone of the NAT rule to the translated source address).
 *
 * Where: firewall - the vsys of the NAT rule. Panorama - the NAT rule in a device group (or shared): every firewall of
 * that device group and its children (and vsys) the rule targets, with the template stack / template of the firewall
 * (its templates merged, the first one wins, variables with the values of the firewall). Firewalls with the same
 * device group, template stack, vsys and values are one context. No firewall assigned: every template stack /
 * template (not one of a stack) with a vsys that has the source zones of the NAT rule ("no device assigned").
 *
 * The security rules in their order (Panorama: shared pre, device group pre top-down, post bottom-up, shared post -
 * the local rules of a firewall are not known); disabled rules and rules not targeting the firewall are skipped.
 * Per rule: zones, source, destination, service - full / partial / none (unknown: FQDN, dynamic group, EDL,
 * application-default). Only allow rules are listed: until the first rule that covers the traffic fully every allow rule
 * that covers a part; after it: shadowed (never reached). A deny / drop / reset rule that covers the traffic fully before
 * any allow rule is named in a note, the allow rules after it are shadowed.
 *
 * Limits: dynamic routes (OSPF / BGP) are not in the configuration - a zone found only by a default route is marked
 * uncertain; IPv4 NAT rules only (nat64 / nptv6: not analysed).
 */
class NatSecurityMatch
{
    const MAX_IP4 = 4294967295;

    /** @var array merged PANConf per template stack / template and values of the variables */
    static private $confCache = array();
    /** @var array route -> zone records per router and vsys */
    static private $routeCache = array();

    /** @var array analyse() per NAT rule (filters) */
    static private $resultCache = array();

    static public function resetCache(): void
    {
        self::$confCache = array();
        self::$routeCache = array();
        self::$resultCache = array();
    }

    /** analyse() once per NAT rule (the filters of one run) */
    static public function cachedAnalyse( NatRule $nat ): array
    {
        $key = spl_object_hash( $nat );
        if( !isset( self::$resultCache[$key] ) )
            self::$resultCache[$key] = self::analyse( $nat );
        return self::$resultCache[$key];
    }

    /**
     * @return array 'nat', 'kind' (destination / source / none / bidirectional), 'notes', 'directions' => list of
     *   'direction' (forward / reverse), 'summary' (full / partial / missing / unknown), 'contexts' => list of 'context',
     *   'devices', 'vsys', 'postNatZones', 'zoneNotes', 'summary', 'matches' => list of 'rule', 'location', 'position',
     *   'state' (match / shadowed), 'coverage' (full / partial), 'details' (zones, source, destination, service), 'notes'
     */
    static public function analyse( NatRule $nat, bool $strip = TRUE ): array
    {
        $out = array( 'nat' => $nat->name(), 'kind' => self::kind( $nat ), 'notes' => array(), 'directions' => array() );

        $natType = $nat->getNatRuleType();
        if( $natType !== null && $natType !== '' && $natType !== 'ipv4' )
        {
            $out['notes'][] = "NAT rule type '" . $natType . "': only ipv4 NAT rules are analysed";
            return $out;
        }
        if( $nat->isDisabled() )
            $out['notes'][] = 'the NAT rule is disabled';

        $contexts = self::contexts( $nat, $out['notes'] );

        $directions = array( 'forward' );
        if( $nat->sourceNatTypeIs_Static() && $nat->isBiDirectional() )
            $directions[] = 'reverse';

        foreach( $directions as $direction )
        {
            $dirOut = array( 'direction' => $direction, 'summary' => 'missing', 'contexts' => array() );
            foreach( $contexts as $ctx )
                $dirOut['contexts'][] = self::analyseContext( $nat, $direction, $ctx );
            $dirOut['summary'] = self::worst( array_column( $dirOut['contexts'], 'summary' ) );
            $out['directions'][] = $dirOut;
        }

        return $strip ? self::stripObjects( $out ) : $out;
    }

    static public function kind( NatRule $nat ): string
    {
        if( $nat->sourceNatTypeIs_Static() && $nat->isBiDirectional() )
            return 'bidirectional';
        if( $nat->destinationNatIsEnabled() )
            return $nat->sourceNatIsEnabled() ? 'destination+source' : 'destination';
        if( $nat->sourceNatIsEnabled() )
            return 'source';
        return 'none';
    }

    /** the worst of several summaries: missing < unknown < partial < full */
    static private function worst( array $list ): string
    {
        if( count( $list ) == 0 )
            return 'unknown';
        foreach( array( 'missing', 'blocked', 'unknown', 'partial' ) as $s )
            if( in_array( $s, $list, TRUE ) )
                return $s;
        return 'full';
    }

    // ------------------------------------------------------------------------------------------------- contexts

    /**
     * @return array list of 'label', 'devices' (serials), 'conf' (PANConf), 'vsys' (VirtualSystem), 'rules'
     *   (SecurityRule[] in order), 'note'
     */
    static private function contexts( NatRule $nat, array &$notes ): array
    {
        $sub = $nat->owner->owner;

        // firewall: the vsys of the NAT rule
        if( $sub instanceof VirtualSystem )
        {
            $conf = $sub->owner;
            return array( array( 'label' => 'vsys ' . $sub->name(), 'deviceGroup' => null, 'devices' => array(), 'conf' => $conf, 'vsys' => $sub,
                'rules' => $sub->securityRules->rules(), 'note' => null ) );
        }

        if( !( $sub instanceof DeviceGroup ) && !( $sub instanceof PanoramaConf ) )
        {
            $notes[] = 'location of the NAT rule not supported: ' . get_class( $sub );
            return array();
        }

        $pano = $sub instanceof PanoramaConf ? $sub : $sub->owner;
        $groups = $sub instanceof PanoramaConf ? $pano->getDeviceGroups() : array_merge( array( $sub ), $sub->childDeviceGroups( TRUE ) );

        $contexts = array();
        foreach( $groups as $dg )
        {
            $ruleSet = $dg->securityRules->resultingRuleSet();
            foreach( $dg->getDevicesInGroup( FALSE ) as $serial => $info )
            {
                $device = $pano->managedFirewallsStore->find( $serial );
                $stack = $device !== null ? $device->getTemplateStack() : null;
                $template = $device !== null ? $device->getTemplate() : null;
                $tname = $stack !== null && $stack !== '' ? $stack : ( $template !== null && $template !== '' ? $template : null );

                foreach( $info['vsyslist'] as $vsysName )
                {
                    if( !self::targetApplies( $nat, $serial, $vsysName ) )
                        continue;

                    $rules = array();
                    foreach( $ruleSet as $r )
                        if( self::targetApplies( $r, $serial, $vsysName ) )
                            $rules[] = $r;

                    $conf = null; $vsys = null; $note = null;
                    if( $tname === null )
                        $note = 'firewall ' . $serial . ' has no template stack / template';
                    else
                    {
                        $conf = self::deviceConf( $pano, $tname, $serial, $note );
                        if( $conf !== null )
                        {
                            $vsys = $conf->findVirtualSystem( $vsysName );
                            if( $vsys === null )
                                $note = "vsys '" . $vsysName . "' not found in template " . $tname;
                        }
                    }

                    $key = $dg->name() . '|' . (string)$tname . '|' . $vsysName . '|' . ( $conf !== null ? spl_object_hash( $conf ) : '-' )
                        . '|' . md5( implode( ',', array_map( function( $r ) { return spl_object_hash( $r ); }, $rules ) ) );
                    if( isset( $contexts[$key] ) )
                    {
                        $contexts[$key]['devices'][] = $serial;
                        continue;
                    }
                    $contexts[$key] = array( 'label' => 'device-group ' . $dg->name() . ' / ' . ( $tname !== null ? 'template ' . $tname : 'no template' ) . ' / ' . $vsysName,
                        'deviceGroup' => $dg->name(), 'devices' => array( $serial ), 'conf' => $conf, 'vsys' => $vsys, 'rules' => $rules, 'note' => $note );
                }
            }
        }

        if( count( $contexts ) > 0 )
            return array_values( $contexts );

        // no firewall assigned: the template stacks / templates with a vsys that has the source zones of the NAT rule
        $rules = $sub instanceof PanoramaConf ? array_merge( $pano->securityRules->preRules(), $pano->securityRules->postRules() )
            : $sub->securityRules->resultingRuleSet();
        $fromZones = $nat->from->isAny() ? array() : array_map( function( $z ) { return $z->name(); }, $nat->from->zones() );
        // a template of a template stack is no configuration of its own (only the stack is)
        $inStack = array();
        foreach( $pano->templatestacks as $st )
            foreach( $st->templates as $t )
                if( is_object( $t ) )
                    $inStack[$t->name()] = TRUE;
        foreach( array_merge( $pano->templatestacks, $pano->templates ) as $t )
        {
            if( $t instanceof Template && isset( $inStack[$t->name()] ) )
                continue;
            $note = null;
            $conf = self::deviceConf( $pano, $t->name(), null, $note );
            if( $conf === null )
                continue;
            foreach( $conf->getVirtualSystems() as $vsys )
            {
                $have = array_map( function( $z ) { return $z->name(); }, $vsys->zoneStore->zones() );
                if( count( $have ) == 0 || count( array_diff( $fromZones, $have ) ) > 0 )
                    continue;
                $contexts[] = array( 'label' => ( $t instanceof TemplateStack ? 'template-stack ' : 'template ' ) . $t->name() . ' / ' . $vsys->name() . ' (no device assigned)',
                    'deviceGroup' => $sub instanceof DeviceGroup ? $sub->name() : 'shared', 'devices' => array(), 'conf' => $conf, 'vsys' => $vsys, 'rules' => $rules, 'note' => $note );
            }
        }
        if( count( $contexts ) == 0 )
            $notes[] = 'no firewall of the device group and no template with the source zones of the NAT rule';

        return $contexts;
    }

    /** a rule applies to a firewall / vsys (Panorama target, negate); no serial: always */
    static public function targetApplies( Rule $rule, ?string $serial, ?string $vsys ): bool
    {
        if( $serial === null || $rule->target_isAny() )
            return TRUE;
        $t = $rule->targets();
        $in = isset( $t[$serial] ) && ( count( $t[$serial] ) == 0 || ( $vsys !== null && isset( $t[$serial][$vsys] ) ) );
        return $rule->target_isNegated() ? !$in : $in;
    }

    /**
     * The configuration a firewall gets from its template stack / template: the templates of the stack merged (the
     * stack itself first, then its templates in their order - the first one wins), the variables replaced with the
     * values of the firewall (serial; null: the values of the templates). Loaded as one PANConf (cached).
     */
    static public function deviceConf( PanoramaConf $pano, string $name, ?string $serial, ?string &$note ): ?PANConf
    {
        $stack = $pano->findTemplateStack( $name );
        $template = $stack === null ? $pano->findTemplate( $name ) : null;
        if( $stack === null && $template === null )
        {
            $note = "template stack / template '" . $name . "' not found";
            return null;
        }

        // layers from the lowest to the highest priority
        $layers = array();
        if( $stack !== null )
        {
            foreach( array_reverse( $stack->templates ) as $t )
                if( is_object( $t ) && isset( $t->xmlroot ) )
                    $layers[] = $t->xmlroot;
            $layers[] = $stack->xmlroot;
        }
        else
            $layers[] = $template->xmlroot;

        $variables = array();
        foreach( $layers as $layer )
            self::readVariables( DH::findFirstElement( 'variable', $layer ), $variables );
        if( $serial !== null )
            foreach( $layers as $layer )
            {
                $devices = DH::findFirstElement( 'devices', $layer );
                if( $devices === FALSE )
                    continue;
                foreach( $devices->childNodes as $d )
                    if( $d->nodeType == XML_ELEMENT_NODE && DH::findAttribute( 'name', $d ) === $serial )
                        self::readVariables( DH::findFirstElement( 'variable', $d ), $variables );
            }

        $doc = new DOMDocument();
        $v = (int)$pano->version;
        $root = $doc->createElement( 'config' );
        $root->setAttribute( 'version', intdiv( $v, 10 ) . '.' . ( $v % 10 ) . '.0' );
        $doc->appendChild( $root );
        foreach( $layers as $layer )
        {
            $config = DH::findFirstElement( 'config', $layer );
            if( $config !== FALSE )
                self::overlay( $root, $config );
        }
        if( count( $variables ) > 0 )
            self::replaceVariables( $root, $variables );

        // the firewall part only (no rules in templates; Panorama parts are not needed)
        foreach( array( 'mgt-config', 'shared' ) as $tag )
            if( DH::findFirstElement( $tag, $root ) === FALSE )
                $root->appendChild( $doc->createElement( $tag ) );

        $key = md5( $doc->saveXML() );
        if( isset( self::$confCache[$key] ) )
            return self::$confCache[$key];

        try
        {
            $conf = new PANConf();
            $conf->load_from_domxml( $doc );
        }
        catch( Throwable $e )
        {
            $note = "template '" . $name . "' could not be read: " . $e->getMessage();
            return null;
        }

        return self::$confCache[$key] = $conf;
    }

    static private function readVariables( $node, array &$variables ): void
    {
        if( $node === FALSE || $node === null )
            return;
        foreach( $node->childNodes as $e )
        {
            if( $e->nodeType != XML_ELEMENT_NODE )
                continue;
            $name = DH::findAttribute( 'name', $e );
            $type = DH::findFirstElement( 'type', $e );
            if( $name === FALSE || $type === FALSE )
                continue;
            $value = DH::firstChildElement( $type );
            if( $value !== FALSE && trim( $value->textContent ) !== '' )
                $variables[$name] = trim( $value->textContent );
        }
    }

    /** $src over $dst: same tag (and name) merged, leaves and member lists replaced */
    static private function overlay( DOMElement $dst, DOMElement $src ): void
    {
        foreach( $src->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            $name = $c->hasAttribute( 'name' ) ? $c->getAttribute( 'name' ) : null;

            $match = null;
            foreach( $dst->childNodes as $d )
                if( $d->nodeType == XML_ELEMENT_NODE && $d->nodeName === $c->nodeName
                    && ( $name === null ? !$d->hasAttribute( 'name' ) : $d->getAttribute( 'name' ) === $name ) )
                {
                    $match = $d;
                    break;
                }

            $leaf = TRUE;
            foreach( $c->childNodes as $cc )
                if( $cc->nodeType == XML_ELEMENT_NODE && $cc->nodeName !== 'member' )
                {
                    $leaf = FALSE;
                    break;
                }
            $hasChildren = DH::firstChildElement( $c ) !== FALSE;

            $copy = $dst->ownerDocument->importNode( $c, TRUE );
            if( $match === null )
                $dst->appendChild( $copy );
            elseif( $leaf && ( $hasChildren || trim( $c->textContent ) !== '' || DH::firstChildElement( $match ) === FALSE ) )
                $dst->replaceChild( $copy, $match );
            elseif( !$leaf )
                self::overlay( $match, $c );
        }
    }

    static private function replaceVariables( DOMElement $node, array $variables ): void
    {
        if( $node->hasAttribute( 'name' ) && isset( $variables[$node->getAttribute( 'name' )] ) )
            $node->setAttribute( 'name', $variables[$node->getAttribute( 'name' )] );
        $hasElement = FALSE;
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
            {
                $hasElement = TRUE;
                self::replaceVariables( $c, $variables );
            }
        if( !$hasElement && isset( $variables[trim( $node->textContent )] ) )
            $node->textContent = $variables[trim( $node->textContent )];
    }

    // ------------------------------------------------------------------------------------------------- one context

    static private function analyseContext( NatRule $nat, string $direction, array $ctx ): array
    {
        $res = array( 'context' => $ctx['label'], 'deviceGroup' => $ctx['deviceGroup'], 'devices' => $ctx['devices'], 'postNatZones' => array(), 'zoneNotes' => array(),
            'summary' => 'unknown', 'matches' => array(), 'blockedBy' => null, 'mismatches' => array(), 'notes' => array() );
        if( $ctx['note'] !== null )
            $res['notes'][] = $ctx['note'];

        $vsys = $ctx['vsys'];
        $universe = array();
        if( $vsys !== null )
            foreach( $vsys->zoneStore->zones() as $z )
                $universe[$z->name()] = TRUE;
        $universe = array_keys( $universe );

        $names = function( ZoneRuleContainer $c ) use ( $universe ) {
            return $c->isAny() ? $universe : array_map( function( $z ) { return $z->name(); }, $c->zones() );
        };

        // the traffic of the NAT rule, as the security policy sees it
        if( $direction == 'forward' )
        {
            $from = $names( $nat->from );
            $src = self::addressSide( $nat->source );
            $dst = self::addressSide( $nat->destination );
            $service = $nat->service;
            if( $nat->destinationNatIsEnabled() )
            {
                $to = self::postNatZones( $nat->dnathost, $from, $ctx, $res );
            }
            else
                $to = $names( $nat->to );
        }
        else
        {
            // bi-directional static NAT, reverse: arriving in the destination zone of the NAT rule, to the translated
            // source address; translated back to the original source - its zone by the route lookup
            $from = $names( $nat->to );
            $src = array( 'any' => TRUE, 'ranges' => array(), 'unresolved' => array() );
            $dst = self::addressSide( $nat->snathosts );
            $service = null;
            $to = self::postNatZones( $nat->source, $from, $ctx, $res );
        }

        if( $vsys === null && count( $res['notes'] ) == 0 )
            $res['notes'][] = 'zones of the firewall unknown';

        $firstFull = null;
        $blockedBy = null;
        $position = 0;
        foreach( $ctx['rules'] as $rule )
        {
            $position++;
            if( !( $rule instanceof SecurityRule ) || $rule->isDisabled() )
                continue;

            $m = self::coverRule( $rule, $from, $to, $src, $dst, $service, $universe );
            if( $m['coverage'] === 'none' )
                continue;

            // only allow rules are listed; a deny / drop / reset rule that covers the traffic fully before any allow
            // rule ends the list - every allow rule after it is shadowed
            if( $rule->action() !== 'allow' )
            {
                if( $firstFull === null && $m['coverage'] === 'full' )
                {
                    $firstFull = $rule;
                    $blockedBy = $rule;
                    $res['blockedBy'] = array( 'rule' => $rule->name(), 'action' => $rule->action(), 'location' => self::ruleLocation( $rule ),
                        'locationName' => $rule->owner->owner instanceof PanoramaConf ? 'shared' : $rule->owner->owner->name(), 'position' => $position );
                    $res['notes'][] = "traffic blocked by rule '" . $rule->name() . "' (" . $rule->action() . ', ' . self::ruleLocation( $rule ) . ')';
                }
                continue;
            }

            // only what allowed traffic really reaches: a rule after the first full one is shadowed - not listed
            if( $firstFull !== null )
                continue;
            $o = $rule->owner->owner;
            $entry = array( 'rule' => $rule->name(), 'location' => self::ruleLocation( $rule ),
                'locationName' => $o instanceof PanoramaConf ? 'shared' : ( method_exists( $o, 'name' ) ? $o->name() : '' ), 'position' => $position,
                'state' => $firstFull === null ? 'match' : 'shadowed', 'coverage' => $m['coverage'], 'details' => $m['details'],
                'action' => $rule->action(), 'notes' => $m['notes'] );
            $res['matches'][] = $entry;
            if( $firstFull === null && $m['coverage'] === 'full' )
                $firstFull = $rule;
        }

        if( $blockedBy !== null )
            $res['summary'] = count( $res['matches'] ) > 0 ? 'partial' : 'blocked';
        elseif( $firstFull !== null )
            $res['summary'] = 'full';
        elseif( count( $res['matches'] ) > 0 )
            $res['summary'] = 'partial';
        else
            $res['summary'] = $to === null && $vsys === null ? 'unknown' : 'missing';

        // destination NAT: allow rules written the way of other vendors (post-NAT address, pre-NAT zone, translated port)
        $uncertain = count( array_filter( $res['postNatZones'], function( $z ) { return $z['uncertain']; } ) ) > 0;
        if( $direction == 'forward' && $nat->destinationNatIsEnabled() && $to !== null && $vsys !== null && $uncertain )
            $res['notes'][] = 'post-NAT zone only by the default route: no security rule to adapt is proposed';
        elseif( $direction == 'forward' && $nat->destinationNatIsEnabled() && $to !== null && $vsys !== null )
        {
            $listed = array_column( $res['matches'], 'rule' );
            $res['mismatches'] = self::mismatches( $nat, $ctx, $from, $to, $src, $dst, $names( $nat->to ), $universe, $listed );
            // the traffic is allowed fully already: nothing to adapt for it (shown, not changed)
            if( $res['summary'] === 'full' )
                foreach( $res['mismatches'] as $i => $m )
                    $res['mismatches'][$i]['covered'] = $firstFull->name();
        }

        return $res;
    }

    // ------------------------------------------------------------------------------------------------- mismatches

    /**
     * Allow rules for the traffic of a destination NAT rule that PAN-OS does not match the way they are written (rules
     * of other vendors: the security rule after the NAT):
     *   post-nat-address   the destination is the translated (real) address instead of the original one
     *   pre-nat-zone       the original address, but not the post-NAT zone (e.g. the zone of the NAT rule)
     *   translated-port    the service is the translated port instead of the original one
     * Only rules whose source zones / source meet the NAT rule. 'scope' full: the corrected rule allows exactly the
     * NAT traffic the rule names; partial: it would allow more (a part of a translated pool, more ports, other zones)
     * - reported, a change only with approval. 'fix': in-place (the rule carries only this NAT traffic) or clone (a new
     * rule before it, the rule stays for its other traffic).
     */
    static private function mismatches( NatRule $nat, array $ctx, array $from, array $postZones, array $src, array $pre, array $natTo, array $universe, array $listed ): array
    {
        $out = array();
        $post = self::addressSide( $nat->dnathost );
        if( $post['any'] || count( $post['ranges'] ) == 0 || $pre['any'] || count( $pre['ranges'] ) == 0 )
            return $out;

        $natPorts = self::servicePorts( $nat->service );
        $translatedPort = $nat->dnatports !== null && $nat->dnatports !== '' ? (int)$nat->dnatports : null;
        $tPorts = null;
        if( $translatedPort !== null )
        {
            $tPorts = array( 'tcp' => array(), 'udp' => array() );
            foreach( array( 'tcp', 'udp' ) as $proto )
                if( $natPorts === null || count( $natPorts[$proto] ) > 0 )
                    $tPorts[$proto] = array( array( $translatedPort, $translatedPort ) );
        }

        $fromSet = array_flip( $from );
        $postSet = array_flip( $postZones );
        $position = 0;
        foreach( $ctx['rules'] as $rule )
        {
            $position++;
            if( !( $rule instanceof SecurityRule ) || $rule->isDisabled() || $rule->action() !== 'allow' || in_array( $rule->name(), $listed, TRUE ) )
                continue;
            if( $rule->destination->isAny() || $rule->destinationIsNegated() || $rule->sourceIsNegated() )
                continue;

            $notes = array();
            // the source side must meet the NAT rule
            $rFrom = $rule->from->isAny() ? $universe : array_map( function( $z ) { return $z->name(); }, $rule->from->zones() );
            $fromCommon = array_values( array_filter( $rFrom, function( $z ) use ( $fromSet ) { return isset( $fromSet[$z] ); } ) );
            if( count( $fromCommon ) == 0 )
                continue;
            if( self::coverAddresses( $src, $rule->source, FALSE, $notes, 'source' ) === 'none' )
                continue;

            $rd = self::addressSide( $rule->destination );
            $rTo = $rule->to->isAny() ? $universe : array_map( function( $z ) { return $z->name(); }, $rule->to->zones() );
            $reachesPost = count( array_intersect( $rTo, $postZones ) ) > 0;

            $hitsPost = count( self::rangesIntersect( $rd['ranges'], $post['ranges'] ) ) > 0;
            $hitsPre = count( self::rangesIntersect( $rd['ranges'], $pre['ranges'] ) ) > 0;

            $patterns = array();
            $exact = TRUE;
            $inPlace = TRUE;
            if( $hitsPost && !$hitsPre )
            {
                $patterns[] = 'post-nat-address';
                // the whole translated address in the rule; in place only when the rule names nothing else and only
                // zones of the NAT rule
                if( count( self::rangesSubtract( $post['ranges'], $rd['ranges'] ) ) > 0 )
                {
                    $exact = FALSE;
                    $notes[] = 'the rule names only a part of the translated address ' . self::rangesToText( $post['ranges'] );
                }
                if( count( self::rangesSubtract( $rd['ranges'], $post['ranges'] ) ) > 0 || count( $rd['unresolved'] ) > 0 )
                    $inPlace = FALSE;
                if( count( $rFrom ) != count( $fromCommon ) )
                    $inPlace = FALSE;
                // its destination zones: only post-NAT zones (else the original address would be allowed into them)
                if( $rule->to->isAny() || count( array_diff( $rTo, $postZones ) ) > 0 )
                    $inPlace = FALSE;
            }
            elseif( $hitsPre && !$reachesPost )
            {
                $patterns[] = 'pre-nat-zone';
                if( count( self::rangesSubtract( $pre['ranges'], $rd['ranges'] ) ) > 0 )
                {
                    $exact = FALSE;
                    $notes[] = 'the rule names only a part of the original destination ' . self::rangesToText( $pre['ranges'] );
                }
                // the post-NAT zone added to the rule: only when it names nothing but the NAT addresses
                if( count( self::rangesSubtract( $rd['ranges'], $pre['ranges'] ) ) > 0 || count( $rd['unresolved'] ) > 0 )
                    $inPlace = FALSE;
            }
            elseif( !( $hitsPre && $reachesPost ) )
                continue;

            // service: the translated port instead of the original one
            $service = 'ok';
            if( !$rule->services->isAny() && !$rule->services->isApplicationDefault() )
            {
                $rPorts = self::servicePorts( $rule->services );
                $hasOriginal = $natPorts === null ? FALSE : count( self::rangesIntersect( $natPorts['tcp'], $rPorts['tcp'] ) ) + count( self::rangesIntersect( $natPorts['udp'], $rPorts['udp'] ) ) > 0;
                $hasTranslated = $tPorts !== null && count( self::rangesIntersect( $tPorts['tcp'], $rPorts['tcp'] ) ) + count( self::rangesIntersect( $tPorts['udp'], $rPorts['udp'] ) ) > 0;
                if( $hasTranslated && !$hasOriginal )
                {
                    $patterns[] = 'translated-port';
                    $service = 'replace';
                    // exactly the translated port: the original service instead; more ports: they would be allowed
                    // on the original address too
                    $onlyT = count( self::rangesSubtract( $rPorts['tcp'], $tPorts['tcp'] ) ) + count( self::rangesSubtract( $rPorts['udp'], $tPorts['udp'] ) ) == 0;
                    if( !$onlyT || $nat->service === null )
                    {
                        $exact = FALSE;
                        $notes[] = $nat->service === null ? 'NAT rule with service any and a translated port' : 'the rule has more ports than the translated port ' . $translatedPort;
                    }
                    if( count( $patterns ) == 1 && !$onlyT )
                        $inPlace = FALSE;
                }
                // neither the original nor the translated port: not traffic of this NAT rule
                elseif( !$hasOriginal && $natPorts !== null )
                    continue;
            }
            if( count( $patterns ) == 0 )
                continue;

            // the corrected rule: what it gets
            $target = array(
                'destination' => in_array( 'post-nat-address', $patterns, TRUE ) ? self::memberNames( $nat->destination ) : null,
                'to' => $postZones,
                'from' => count( $rFrom ) == count( $fromCommon ) || $rule->from->isAny() && count( $fromCommon ) == count( $universe ) ? null : $fromCommon,
                'service' => $service === 'replace' && $nat->service !== null ? $nat->service->name() : null,
            );
            if( in_array( 'pre-nat-zone', $patterns, TRUE ) && !$inPlace )
                $target['destination'] = self::memberNames( $nat->destination );

            $o = $rule->owner->owner;
            $out[] = array( 'rule' => $rule->name(), 'location' => self::ruleLocation( $rule ),
                'locationName' => $o instanceof PanoramaConf ? 'shared' : ( method_exists( $o, 'name' ) ? $o->name() : '' ), 'position' => $position,
                'patterns' => $patterns, 'scope' => $exact ? 'full' : 'partial', 'fix' => $exact && $inPlace ? 'in-place' : 'clone',
                'target' => $target, 'notes' => array_values( array_unique( $notes ) ), 'covered' => null, '_rule' => $rule );
        }

        return $out;
    }

    /** analyse() without the rule objects of the mismatches (they are kept for applyFix only) */
    static private function stripObjects( array $a ): array
    {
        foreach( $a['directions'] as $di => $d )
            foreach( $d['contexts'] as $ci => $c )
                foreach( $c['mismatches'] as $mi => $m )
                    unset( $a['directions'][$di]['contexts'][$ci]['mismatches'][$mi]['_rule'] );
        return $a;
    }

    /**
     * The mismatches of a NAT rule, one per security rule over all firewall contexts: 'rule' (object), 'entry' (the
     * first one), 'scope' full / partial (partial when the contexts differ), 'fix' in-place / clone, 'target'
     */
    static public function mismatchPlan( NatRule $nat ): array
    {
        $a = self::analyse( $nat, FALSE );
        $plan = array();
        foreach( $a['directions'] as $d )
            foreach( $d['contexts'] as $c )
                foreach( $c['mismatches'] as $m )
                {
                    $key = spl_object_hash( $m['_rule'] );
                    if( !isset( $plan[$key] ) )
                    {
                        $plan[$key] = array( 'rule' => $m['_rule'], 'entry' => $m, 'scope' => $m['scope'], 'fix' => $m['fix'], 'target' => $m['target'], 'notes' => $m['notes'],
                            'covered' => $m['covered'] );
                        continue;
                    }
                    $p = &$plan[$key];
                    // needed as long as one firewall does not allow the traffic yet
                    if( $m['covered'] === null )
                        $p['covered'] = null;
                    if( $m['scope'] === 'partial' )
                        $p['scope'] = 'partial';
                    if( $m['fix'] === 'clone' )
                        $p['fix'] = 'clone';
                    if( $m['target'] != $p['target'] )
                    {
                        // other post-NAT zones on other firewalls: all of them - more than one firewall needs, approval
                        $p['scope'] = 'partial';
                        $p['fix'] = 'clone';
                        $p['target']['to'] = array_values( array_unique( array_merge( $p['target']['to'], $m['target']['to'] ) ) );
                        $p['notes'][] = 'the firewalls of the device group need other post-NAT zones: ' . implode( ', ', $p['target']['to'] );
                    }
                    unset( $p );
                }
        return array_values( $plan );
    }

    /**
     * Correct the allow rules of mismatchPlan(): $mode 'fix' (in place where the rule carries only this NAT traffic, else
     * a clone before it) or 'clone' (always a clone before it, the rule stays); scope partial only with $approvePartial
     * (the corrected rule would allow more than the rule names). Never more traffic than the rule names for full.
     * @return string[] lines: what was done / skipped
     */
    static public function applyFix( NatRule $nat, string $mode, bool $approvePartial, string $suffix ): array
    {
        $lines = array();
        foreach( self::mismatchPlan( $nat ) as $p )
        {
            /** @var SecurityRule $rule */
            $rule = $p['rule'];
            $what = "'" . $rule->name() . "' (" . self::ruleLocation( $rule ) . ', ' . implode( ' + ', $p['entry']['patterns'] ) . ', ' . $p['scope'] . ')';
            if( $p['covered'] !== null )
            {
                $lines[] = 'SKIPPED ' . $what . ": the traffic is allowed already by rule '" . $p['covered'] . "'";
                continue;
            }
            if( $p['scope'] === 'partial' && !$approvePartial )
            {
                $lines[] = 'SKIPPED ' . $what . ': partial - would allow more than the rule names, needs approval (approvePartial)'
                    . ( count( $p['notes'] ) ? ' - ' . implode( '; ', array_unique( $p['notes'] ) ) : '' );
                continue;
            }
            $inPlace = $mode === 'fix' && $p['fix'] === 'in-place' && $p['scope'] === 'full';

            // the objects the corrected rule needs, from the location of the security rule
            $sub = $rule->owner->owner;
            $addresses = array();
            foreach( $p['target']['destination'] ?? array() as $n )
            {
                $o = $sub->addressStore->find( $n );
                if( $o === null && filter_var( explode( '/', $n )[0], FILTER_VALIDATE_IP ) )
                    $o = $sub->addressStore->findOrCreate( $n );
                if( $o === null )
                {
                    $lines[] = 'SKIPPED ' . $what . ": address '" . $n . "' of the NAT rule is not visible in " . self::ruleLocation( $rule );
                    continue 2;
                }
                $addresses[] = $o;
            }
            $service = null;
            if( $p['target']['service'] !== null )
            {
                $service = $sub->serviceStore->find( $p['target']['service'] );
                if( $service === null )
                {
                    $lines[] = 'SKIPPED ' . $what . ": service '" . $p['target']['service'] . "' of the NAT rule is not visible in " . self::ruleLocation( $rule );
                    continue;
                }
            }

            if( $inPlace )
                $target = $rule;
            else
            {
                $newName = $rule->owner->findAvailableName( $rule->name(), $suffix );
                $target = $rule->owner->cloneRule( $rule, $newName );
                $rule->owner->moveRuleBefore( $target, $rule );
            }

            if( count( $addresses ) )
                self::setAddresses( $target->destination, $addresses );
            if( !$inPlace || in_array( 'pre-nat-zone', $p['entry']['patterns'], TRUE ) || in_array( 'post-nat-address', $p['entry']['patterns'], TRUE ) )
                self::setZones( $target->to, $p['target']['to'], !$inPlace );
            if( !$inPlace && $p['target']['from'] !== null )
                self::setZones( $target->from, $p['target']['from'], TRUE );
            if( $service !== null )
                self::setServices( $target->services, $service );

            $lines[] = ( $inPlace ? 'CHANGED ' : "CLONED as '" . $target->name() . "' before " ) . $what . ': ' . self::targetText( $p['target'] );
        }
        if( count( $lines ) == 0 )
            $lines[] = 'no security rule to adapt';
        return $lines;
    }

    static public function targetText( array $t ): string
    {
        $out = array();
        if( $t['destination'] !== null )
            $out[] = 'destination ' . implode( ', ', $t['destination'] );
        $out[] = 'to ' . implode( ', ', $t['to'] );
        if( $t['from'] !== null )
            $out[] = 'from ' . implode( ', ', $t['from'] );
        if( $t['service'] !== null )
            $out[] = 'service ' . $t['service'];
        return implode( '; ', $out );
    }

    /** the members of an address container: exactly $objects (added first - the container is never empty) */
    static private function setAddresses( AddressRuleContainer $c, array $objects ): void
    {
        $keep = array();
        foreach( $objects as $o )
        {
            $keep[$o->name()] = TRUE;
            if( !$c->has( $o ) )
                $c->addObject( $o );
        }
        foreach( $c->members() as $m )
            if( !isset( $keep[$m->name()] ) )
                $c->remove( $m );
    }

    /** zones: $names added; $exact: the others removed */
    static private function setZones( ZoneRuleContainer $c, array $names, bool $exact ): void
    {
        if( $c->parentCentralStore === null )
            $c->findParentCentralStore( 'zoneStore' );
        $keep = array();
        foreach( $names as $n )
        {
            $keep[$n] = TRUE;
            $z = $c->parentCentralStore->findOrCreate( $n );
            if( $z !== null && !$c->hasZone( $n ) )
                $c->addZone( $z );
        }
        if( $exact )
            foreach( $c->zones() as $z )
                if( !isset( $keep[$z->name()] ) )
                    $c->removeZone( $z );
    }

    static private function setServices( ServiceRuleContainer $c, $service ): void
    {
        if( !$c->has( $service ) )
            $c->add( $service );
        foreach( $c->members() as $m )
            if( $m !== $service )
                $c->remove( $m );
    }

    static private function memberNames( AddressRuleContainer $c ): array
    {
        return array_map( function( $m ) { return $m->name(); }, $c->members() );
    }

    /** TCP / UDP destination ports of a service object or of the services of a rule; null: any */
    static private function servicePorts( $svc ): ?array
    {
        if( $svc === null )
            return null;
        $out = array( 'tcp' => array(), 'udp' => array() );
        $list = $svc instanceof ServiceRuleContainer ? ( $svc->isAny() ? null : $svc->members() ) : array( $svc );
        if( $list === null )
            return null;
        foreach( $list as $m )
        {
            if( !is_object( $m ) || !method_exists( $m, 'dstPortMapping' ) )
                continue;
            $map = $m->dstPortMapping();
            foreach( $map->tcpPortMap as $e )
                $out['tcp'][] = array( (int)$e['start'], (int)$e['end'] );
            foreach( $map->udpPortMap as $e )
                $out['udp'][] = array( (int)$e['start'], (int)$e['end'] );
        }
        $out['tcp'] = self::rangesNormalize( $out['tcp'] );
        $out['udp'] = self::rangesNormalize( $out['udp'] );
        return $out;
    }

    static private function ruleLocation( Rule $rule ): string
    {
        $o = $rule->owner->owner;
        $loc = $o instanceof PanoramaConf ? 'shared' : ( method_exists( $o, 'name' ) ? $o->name() : '' );
        if( $o instanceof PanoramaConf || $o instanceof DeviceGroup )
            $loc .= $rule->isPostRule() ? ' (post)' : ' (pre)';
        return $loc;
    }

    /**
     * the zones a translated address is routed to: router of the ingress interfaces (interfaces of the zones
     * $fromZones), its route -> zone records (narrowest first); null: not known
     */
    static private function postNatZones( $translated, array $fromZones, array $ctx, array &$res ): ?array
    {
        $vsys = $ctx['vsys'];
        $conf = $ctx['conf'];
        if( $vsys === null || $conf === null )
            return null;

        $side = $translated instanceof AddressRuleContainer ? self::addressSide( $translated ) : self::addressSide( $translated );
        if( $side['any'] )
        {
            $res['zoneNotes'][] = 'translated address: any';
            return null;
        }
        if( count( $side['unresolved'] ) > 0 )
            $res['zoneNotes'][] = 'translated address not resolvable (FQDN / dynamic group): ' . implode( ', ', array_keys( $side['unresolved'] ) );
        if( count( $side['ranges'] ) == 0 )
            return null;

        $storeName = !empty( $conf->_advance_routing_enabled ) ? 'logicalRouterStore' : 'virtualRouterStore';
        if( !isset( $conf->network->$storeName ) )
            return null;

        // routers of the ingress interfaces
        $ifNames = array();
        foreach( $fromZones as $zn )
        {
            $z = $vsys->zoneStore->find( $zn );
            if( $z !== null )
                foreach( $z->interfaceNames() as $i )
                    $ifNames[$i] = TRUE;
        }
        $routers = array();
        foreach( $conf->network->$storeName->virtualRouters() as $router )
            foreach( $router->attachedInterfaces->interfaces() as $if )
                if( isset( $ifNames[$if->name()] ) && $vsys->importedInterfaces->hasInterfaceNamed( $if->name() ) )
                {
                    $routers[$router->name()] = $router;
                    break;
                }
        if( count( $routers ) == 0 )
        {
            $res['zoneNotes'][] = 'no router with an interface of the source zones (' . implode( ', ', $fromZones ) . ')';
            return null;
        }

        $zones = array();
        foreach( $routers as $router )
        {
            $key = spl_object_hash( $router ) . '|' . spl_object_hash( $vsys );
            if( !isset( self::$routeCache[$key] ) )
            {
                try
                {
                    ob_start();
                    $map = $router->getIPtoZoneRouteMapping( $vsys );
                    ob_end_clean();
                }
                catch( Throwable $e )
                {
                    ob_end_clean();
                    $res['zoneNotes'][] = 'routes of ' . $router->name() . ' not readable: ' . $e->getMessage();
                    continue;
                }
                self::$routeCache[$key] = $map['ipv4'] ?? array();
            }

            $remaining = $side['ranges'];
            foreach( self::$routeCache[$key] as $record )
            {
                $hit = self::rangesIntersect( $remaining, array( array( (int)$record['start'], (int)$record['end'] ) ) );
                if( count( $hit ) == 0 )
                    continue;
                $isDefault = ( $record['network'] ?? '' ) === '0.0.0.0/0' || ( (int)$record['start'] == 0 && (int)$record['end'] >= self::MAX_IP4 );
                $zones[$record['zone']] = TRUE;
                $res['postNatZones'][] = array( 'zone' => $record['zone'], 'router' => $router->name(), 'network' => $record['network'] ?? '',
                    'origin' => $record['origin'] ?? '', 'uncertain' => $isDefault );
                if( $isDefault )
                    $res['zoneNotes'][] = 'zone ' . $record['zone'] . ' only by the default route of ' . $router->name() . ' - uncertain (dynamic routes are not in the configuration)';
                $remaining = self::rangesSubtract( $remaining, array( array( (int)$record['start'], (int)$record['end'] ) ) );
                if( count( $remaining ) == 0 )
                    break;
            }
            if( count( $remaining ) > 0 )
                $res['zoneNotes'][] = 'no route in ' . $router->name() . ' for ' . self::rangesToText( $remaining );
        }

        return count( $zones ) > 0 ? array_keys( $zones ) : null;
    }

    // ------------------------------------------------------------------------------------------------- coverage

    /** an address side: 'any', 'ranges' (IPv4 start/end), 'unresolved' (name => object) */
    static public function addressSide( $c ): array
    {
        if( $c === null )
            return array( 'any' => TRUE, 'ranges' => array(), 'unresolved' => array() );
        if( $c instanceof AddressRuleContainer && $c->isAny() )
            return array( 'any' => TRUE, 'ranges' => array(), 'unresolved' => array() );

        $map = $c->getIP4Mapping();
        $ranges = array();
        foreach( $map->getMapArray() as $e )
            $ranges[] = array( (int)$e['start'], (int)$e['end'] );
        $unresolved = is_array( $map->unresolved ?? null ) ? $map->unresolved : array();
        // an FQDN address / EDL in the container: not in the map
        if( $c instanceof AddressRuleContainer )
            foreach( $c->members() as $m )
                if( is_object( $m ) && ( get_class( $m ) === 'EDL' || ( $m instanceof Address && $m->isType_FQDN() ) ) )
                    $unresolved[$m->name()] = $m;
        if( $c instanceof Address && $c->isType_FQDN() )
            $unresolved[$c->name()] = $c;

        return array( 'any' => FALSE, 'ranges' => self::rangesNormalize( $ranges ), 'unresolved' => $unresolved );
    }

    /**
     * one security rule against the traffic: 'coverage' full / partial / none, 'details' per field, 'notes'
     */
    static public function coverRule( SecurityRule $rule, array $from, ?array $to, array $src, array $dst, $service, array $universe ): array
    {
        $notes = array();
        $details = array();

        $details['zones'] = self::coverZones( $rule, $from, $to, $universe, $notes );
        $details['source'] = self::coverAddresses( $src, $rule->source, $rule->sourceIsNegated(), $notes, 'source' );
        $details['destination'] = self::coverAddresses( $dst, $rule->destination, $rule->destinationIsNegated(), $notes, 'destination' );
        $details['service'] = self::coverService( $service, $rule->services, $notes );

        if( in_array( 'none', $details, TRUE ) )
            $coverage = 'none';
        elseif( count( array_diff( $details, array( 'full' ) ) ) == 0 )
            $coverage = 'full';
        else
            $coverage = 'partial';

        return array( 'coverage' => $coverage, 'details' => $details, 'notes' => $notes );
    }

    static private function coverZones( SecurityRule $rule, array $from, ?array $to, array $universe, array &$notes ): string
    {
        $secFrom = $rule->from->isAny() ? null : array_flip( array_map( function( $z ) { return $z->name(); }, $rule->from->zones() ) );
        $secTo = $rule->to->isAny() ? null : array_flip( array_map( function( $z ) { return $z->name(); }, $rule->to->zones() ) );
        $type = $rule->type();

        if( $to === null )
        {
            // destination zone not known: the source zones only
            $hit = 0;
            foreach( $from as $f )
                if( $secFrom === null || isset( $secFrom[$f] ) )
                    $hit++;
            if( $hit == 0 )
                return 'none';
            $notes[] = 'destination zone not determined';
            return 'unknown';
        }

        $total = 0; $hit = 0;
        foreach( $from as $f )
            foreach( $to as $t )
            {
                $total++;
                if( $type == 'intrazone' && $f !== $t )
                    continue;
                if( $type == 'interzone' && $f === $t )
                    continue;
                if( ( $secFrom === null || isset( $secFrom[$f] ) ) && ( $secTo === null || isset( $secTo[$t] ) ) )
                    $hit++;
            }
        if( $total == 0 || $hit == 0 )
            return 'none';
        return $hit == $total ? 'full' : 'partial';
    }

    static private function coverAddresses( array $nat, AddressRuleContainer $sec, bool $negated, array &$notes, string $what ): string
    {
        if( $sec->isAny() && !$negated )
            return 'full';

        $secSide = self::addressSide( $sec );
        $secRanges = $secSide['ranges'];
        if( $negated )
            $secRanges = self::rangesSubtract( array( array( 0, self::MAX_IP4 ) ), $secRanges );

        $natRanges = $nat['any'] ? array( array( 0, self::MAX_IP4 ) ) : $nat['ranges'];

        $unknown = FALSE;
        // names on the NAT side that are no IP ranges (FQDN, dynamic group, EDL): covered when the security rule has
        // the same object
        foreach( $nat['unresolved'] as $name => $obj )
        {
            if( !$negated && $sec->hasObjectRecursive( $obj ) )
                continue;
            $unknown = TRUE;
            $notes[] = $what . ': ' . $name . ' not resolvable';
        }
        if( count( $secSide['unresolved'] ) > 0 )
        {
            $notes[] = $what . ' of the security rule has ' . implode( ', ', array_keys( $secSide['unresolved'] ) ) . ' (not resolvable)';
            $unknown = TRUE;
        }

        if( count( $natRanges ) == 0 )
            return $unknown ? 'unknown' : 'full';

        $rest = self::rangesSubtract( $natRanges, $secRanges );
        if( count( $rest ) == 0 )
            return $unknown ? 'unknown' : 'full';
        if( count( self::rangesIntersect( $natRanges, $secRanges ) ) > 0 )
            return 'partial';
        return $unknown ? 'unknown' : 'none';
    }

    /** the NAT service (null = any) against the services of the security rule */
    static private function coverService( $natService, ServiceRuleContainer $sec, array &$notes ): string
    {
        if( $sec->isAny() )
            return 'full';
        if( $sec->isApplicationDefault() )
        {
            $notes[] = 'service application-default: depends on the application';
            return 'unknown';
        }

        $secTcp = array(); $secUdp = array();
        foreach( $sec->members() as $m )
        {
            $map = $m instanceof ServiceGroup ? $m->dstPortMapping() : $m->dstPortMapping();
            foreach( $map->tcpPortMap as $e )
                $secTcp[] = array( (int)$e['start'], (int)$e['end'] );
            foreach( $map->udpPortMap as $e )
                $secUdp[] = array( (int)$e['start'], (int)$e['end'] );
        }

        if( $natService === null )
        {
            // NAT service any: every port of every protocol
            return ( count( $secTcp ) + count( $secUdp ) ) > 0 ? 'partial' : 'none';
        }

        $map = $natService->dstPortMapping();
        $natTcp = array(); $natUdp = array();
        foreach( $map->tcpPortMap as $e )
            $natTcp[] = array( (int)$e['start'], (int)$e['end'] );
        foreach( $map->udpPortMap as $e )
            $natUdp[] = array( (int)$e['start'], (int)$e['end'] );
        if( count( $natTcp ) + count( $natUdp ) == 0 )
        {
            $notes[] = 'service ' . $natService->name() . ': no TCP / UDP port';
            return 'unknown';
        }

        $restTcp = self::rangesSubtract( $natTcp, $secTcp );
        $restUdp = self::rangesSubtract( $natUdp, $secUdp );
        if( count( $restTcp ) + count( $restUdp ) == 0 )
            return 'full';
        if( count( self::rangesIntersect( $natTcp, $secTcp ) ) + count( self::rangesIntersect( $natUdp, $secUdp ) ) > 0 )
            return 'partial';
        return 'none';
    }

    // ------------------------------------------------------------------------------------------------- ranges

    static public function rangesNormalize( array $r ): array
    {
        usort( $r, function( $a, $b ) { return $a[0] <=> $b[0]; } );
        $out = array();
        foreach( $r as $e )
        {
            $n = count( $out );
            if( $n > 0 && $e[0] <= $out[$n - 1][1] + 1 )
                $out[$n - 1][1] = max( $out[$n - 1][1], $e[1] );
            else
                $out[] = $e;
        }
        return $out;
    }

    static public function rangesSubtract( array $a, array $b ): array
    {
        $out = self::rangesNormalize( $a );
        foreach( self::rangesNormalize( $b ) as $s )
        {
            $next = array();
            foreach( $out as $e )
            {
                if( $s[1] < $e[0] || $s[0] > $e[1] )
                {
                    $next[] = $e;
                    continue;
                }
                if( $s[0] > $e[0] )
                    $next[] = array( $e[0], $s[0] - 1 );
                if( $s[1] < $e[1] )
                    $next[] = array( $s[1] + 1, $e[1] );
            }
            $out = $next;
            if( count( $out ) == 0 )
                break;
        }
        return $out;
    }

    static public function rangesIntersect( array $a, array $b ): array
    {
        $out = array();
        foreach( self::rangesNormalize( $a ) as $x )
            foreach( self::rangesNormalize( $b ) as $y )
            {
                $s = max( $x[0], $y[0] );
                $e = min( $x[1], $y[1] );
                if( $s <= $e )
                    $out[] = array( $s, $e );
            }
        return self::rangesNormalize( $out );
    }

    static private function rangesToText( array $r ): string
    {
        return implode( ', ', array_map( function( $e ) {
            return $e[0] == $e[1] ? long2ip( $e[0] ) : long2ip( $e[0] ) . '-' . long2ip( $e[1] );
        }, $r ) );
    }

    // ------------------------------------------------------------------------------------------------- output

    /** the result as text lines (display-nat-security) */
    static public function toText( array $a, string $padding = '    ' ): array
    {
        $lines = array();
        $lines[] = $padding . "NAT -> security: '" . $a['nat'] . "' (" . $a['kind'] . ')';
        foreach( $a['notes'] as $n )
            $lines[] = $padding . '  ! ' . $n;
        foreach( $a['directions'] as $d )
        {
            $lines[] = $padding . '  direction ' . $d['direction'] . ': ' . $d['summary'];
            foreach( $d['contexts'] as $c )
            {
                $lines[] = $padding . '    - ' . $c['context'] . ( count( $c['devices'] ) ? ' [' . implode( ', ', $c['devices'] ) . ']' : '' ) . ': ' . $c['summary'];
                if( count( $c['postNatZones'] ) )
                    $lines[] = $padding . '      post-NAT zone: ' . implode( ', ', array_map( function( $z ) {
                        return $z['zone'] . ' (' . $z['router'] . ' ' . $z['network'] . ( $z['uncertain'] ? ', uncertain' : '' ) . ')';
                    }, $c['postNatZones'] ) );
                foreach( array_merge( $c['notes'], array_values( array_unique( $c['zoneNotes'] ) ) ) as $n )
                    $lines[] = $padding . '      ! ' . $n;
                foreach( $c['matches'] as $m )
                {
                    $det = array();
                    foreach( $m['details'] as $k => $v )
                        $det[] = $k . ' ' . $v;
                    $lines[] = $padding . '      ' . str_pad( '#' . $m['position'], 5 ) . str_pad( $m['rule'], 32 ) . ' ' . str_pad( $m['location'], 18 ) . ' '
                        . str_pad( $m['state'] == 'shadowed' ? 'shadowed' : $m['coverage'], 9 ) . ' ' . $m['action'] . '  [' . implode( ', ', $det ) . ']';
                    foreach( array_unique( $m['notes'] ) as $n )
                        $lines[] = $padding . '           ' . $n;
                }
                if( count( $c['matches'] ) == 0 && $c['blockedBy'] === null )
                    $lines[] = $padding . '      no allow rule';
                foreach( $c['mismatches'] as $m )
                {
                    $lines[] = $padding . '      to adapt: ' . str_pad( '#' . $m['position'], 5 ) . str_pad( $m['rule'], 32 ) . ' ' . str_pad( $m['location'], 18 ) . ' '
                        . implode( ' + ', $m['patterns'] ) . ', ' . $m['scope'] . ', ' . $m['fix'] . ' -> ' . self::targetText( $m['target'] )
                        . ( $m['covered'] !== null ? " (not needed: allowed by '" . $m['covered'] . "')" : '' );
                    foreach( $m['notes'] as $n )
                        $lines[] = $padding . '                 ' . $n;
                }
            }
        }
        return $lines;
    }
}
