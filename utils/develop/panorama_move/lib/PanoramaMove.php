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
 * Move device groups (with parents, devices, template stacks, templates and shared objects) from Panorama A (file1)
 * to Panorama B (file2) - offline on the XML files. todo/panorama-move-concept.md
 *
 *   check()    calculation + conflict checks + shared rule impact + name problems -> findings, plan (nothing written)
 *   execute()  transfer into B, cleanup of A (only when check() has no blocking finding or it is accepted)
 */
class PanoramaMove
{
    /** @var PanoramaConf */
    public $A;
    /** @var PanoramaConf */
    public $B;
    public $file1;
    public $file2;
    public $selected = array();
    public $targetParent = null;
    public $sharedRules = 'skip';
    /** 'report' | 'copy-missing': shared setting blocks without named entries (ssl-decrypt, response pages, ...) */
    public $sharedSettings = 'report';
    /** path => array( 'node' => A node, 'status' => same|missing|differs|only-in-file2 ) */
    public $settings = array();
    /** 'same' | 'different': master key of file2 compared to file1 (stated by the user, not checkable offline) */
    public $masterKey = 'same';
    /** encrypted values (master key) in the transferred configuration: location, path, field - never the value */
    public $secrets = array();

    /** prefix of values encrypted with the master key */
    const SECRET_PREFIX = '-AQ==';

    /** name => 'move' | 'copy' */
    public $dgAction = array();
    /** name => parent name in B (null = shared) */
    public $dgParentB = array();
    public $dgReason = array();
    /** serial => array( 'dg' => name, 'vsys' => [] ) */
    public $devices = array();
    public $stackAction = array();
    public $templateAction = array();
    public $stackReason = array();
    public $templateReason = array();
    /** key path|name => array( 'path', 'name', 'node', 'action' => copy|reuse|conflict ) */
    public $sharedObjects = array();
    /** shared rule impact rows */
    public $ruleImpact = array();
    /** shared rules of file1 copied with shared-rules=to-top-dg: "pre-rulebase|type|name" => TRUE */
    public $sharedRulesToCopy = array();
    /** severity, category, name, location A, location B, proposal */
    public $findings = array();
    public $stats = array();

    /** name conflicts (D4 / D5): null = conflict=stop, otherwise the suffix of conflict=rename:<suffix> */
    public $renameSuffix = null;
    /**
     * renames in file2 (file1 keeps its names): 'device group' / 'template' / 'template stack' => [file1 name => file2 name],
     * 'rule' => ["<device group>|<rulebase>|<type>|<name>" => new name], 'shared rule' => ["<rulebase>|<type>|<name>" => new name]
     */
    public $renames = array( 'device group' => array(), 'template' => array(), 'template stack' => array(), 'rule' => array(), 'shared rule' => array() );
    /** shared object renames by name (references are text values without a type): old name => new name */
    public $objectRenames = array();
    /** device group (file1 name) => [object name => TRUE]: references not rewritten, a local object of the same name space resolves them */
    public $renameExclude = array();
    /** references rewritten to renamed shared objects: array( location, path, old, new ) */
    public $rewrites = array();
    /** panorama-ip=<server>[,<server-2>] (D8): Panorama B address for the transferred templates / stacks; null = report only */
    public $panoramaIp = null;
    /** Panorama server settings in the transferred templates / stacks: location, path, field, value, action (keep|replace|remove|variable), new */
    public $panoramaSettings = array();
    /** access domains of file1 referencing moved names / firewalls: name => array( refs => [], admins => [] ) */
    public $accessDomains = array();
    /** log collector groups of file1 with moved firewalls: name => [serials] */
    public $logCollectorGroups = array();
    /** plugins of file1 referencing moved names / firewalls: plugin => [refs] */
    public $plugins = array();
    /** master-device of a transferred device group that is not moved: device group => serial */
    public $masterDevices = array();
    /** firewalls of the relevant template stacks in file1 (kept for the follow-up after file1 is cleaned): stack => [serials] */
    public $stackSerials = array();
    /**
     * effective rule base per moved firewall, file1 before vs. simulated file2 after the move (RuleResolver):
     * list of groups (device group, firewalls, counts, changed / lost / added / covered / differs, order); null = skipped
     */
    public $rulebaseCheck = array();
    public $rulebaseCheckSkipped = null;
    /**
     * content (App-ID / threats) used by the transferred configuration: predefined application names and threat IDs,
     * names unknown to pan-os-php - Panorama B needs a content version that contains them (not in the configuration)
     */
    public $content = array( 'applications' => array(), 'threat_ids' => array(), 'unknown_applications' => array(), 'unknown_threat_ids' => array() );

    /** predefined names of pan-os-php (lib/object-classes/predefined.xml), read on first use */
    private static $predefined = null;

    /** text values below these elements are never rewritten (zones, users - not shared objects) */
    const NO_REWRITE = array( 'from', 'to', 'source-user', 'reference-templates', 'master-device', 'authorization-code' );

    const SKIP_CONTAINERS = array( 'pre-rulebase', 'post-rulebase', 'default-security-rules', 'devices', 'reference-templates', 'master-device', 'authorization-code', 'user-group-source' );
    const NO_TOKEN = array( 'description', 'comment', 'disabled', 'negate', 'action', 'log-start', 'log-end' );
    const NAMESPACES = array(
        'address' => 'address', 'address-group' => 'address', 'region' => 'address', 'external-list' => 'address',
        'service' => 'service', 'service-group' => 'service',
        'application' => 'application', 'application-group' => 'application', 'application-filter' => 'application',
    );

    public function __construct( $file1, $file2, $dgList, $targetParent = null, $sharedRules = 'skip', $sharedSettings = 'report', $masterKey = 'same', $renameSuffix = null, $panoramaIp = null )
    {
        $this->panoramaIp = ( is_array($panoramaIp) && count($panoramaIp) ) ? array_values($panoramaIp) : null;
        $this->renameSuffix = ( $renameSuffix === null || $renameSuffix === '' ) ? null : $renameSuffix;
        $this->masterKey = $masterKey;
        $this->sharedSettings = $sharedSettings;
        $this->file1 = $file1;
        $this->file2 = $file2;
        $this->A = new PanoramaConf();
        $this->A->load_from_file( $file1 );
        $this->B = new PanoramaConf();
        $this->B->load_from_file( $file2 );
        $this->selected = $dgList;
        $this->targetParent = $targetParent;
        $this->sharedRules = $sharedRules;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // helpers

    private function finding( $severity, $category, $name, $locA = '', $locB = '', $proposal = '' )
    {
        $this->findings[] = array( 'severity' => $severity, 'category' => $category, 'name' => $name, 'file1' => $locA, 'file2' => $locB, 'proposal' => $proposal );
    }

    public function blocking()
    {
        return array_values( array_filter( $this->findings, function( $f ) { return $f['severity'] == 'blocking'; } ) );
    }

    /** name of a device group / template / template stack in file2 */
    public function bName( $cat, $n )
    {
        return ( $n !== null && isset($this->renames[$cat][$n]) ) ? $this->renames[$cat][$n] : $n;
    }

    /** TRUE when a text node lies below an element whose values are no object references */
    private static function noRewrite( $t, $root )
    {
        for( $n = $t->parentNode; $n !== null && !$n->isSameNode($root); $n = $n->parentNode )
            if( in_array($n->nodeName, self::NO_TOKEN, TRUE) || in_array($n->nodeName, self::NO_REWRITE, TRUE) )
                return TRUE;
        return FALSE;
    }

    /**
     * rewrite references to renamed shared objects below $root (text values equal to an old name);
     * $exclude: names resolved by a local object of the device group; $dry: only record (check run)
     */
    private function rewriteRefs( $root, $label, $exclude = array(), $dry = FALSE )
    {
        if( !count($this->objectRenames) || $root === null )
            return 0;
        $x = new DOMXPath( $root->ownerDocument );
        $n = 0;
        foreach( iterator_to_array( $x->query('.//text()', $root) ) as $t )
        {
            $v = trim( $t->nodeValue );
            if( $v === '' || !isset($this->objectRenames[$v]) || isset($exclude[$v]) || self::noRewrite($t, $root) )
                continue;
            if( !$dry )
                $t->nodeValue = $this->objectRenames[$v];
            $this->rewrites[] = array( 'location' => $label, 'path' => self::relPath($t, $root), 'old' => $v, 'new' => $this->objectRenames[$v] );
            $n++;
        }
        return $n;
    }

    /** rename <member> values below the direct child $container (reference-templates, templates) */
    private static function renameMembers( $node, $container, $map )
    {
        $c = self::child( $node, $container );
        if( $c === null || !count($map) )
            return;
        foreach( $c->getElementsByTagName('member') as $m )
            if( isset($map[trim($m->textContent)]) )
                $m->nodeValue = $map[trim($m->textContent)];
    }

    /** rename the rules of a rulebase node: [rulebase|type|name => new] */
    private static function renameRules( $parent, $map )
    {
        foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
            foreach( self::rules( $parent, $w ) as $r )
                if( isset($map[$w . '|' . $r['type'] . '|' . $r['name']]) )
                    $r['node']->setAttribute( 'name', $map[$w . '|' . $r['type'] . '|' . $r['name']] );
    }

    /** child entries of a container node: name => DOMElement */
    public static function entries( $container )
    {
        $out = array();
        if( $container === null || $container === FALSE )
            return $out;
        foreach( $container->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == 'entry' && $c->hasAttribute('name') )
                $out[$c->getAttribute('name')] = $c;
        return $out;
    }

    public static function child( $node, $name )
    {
        if( $node === null || $node === FALSE )
            return null;
        $c = DH::findFirstElement( $name, $node );
        return $c === FALSE ? null : $c;
    }

    private static function localhost( PanoramaConf $p )
    {
        return $p->localhostroot;
    }

    public static function dgEntries( PanoramaConf $p ) { return self::entries( self::child( self::localhost($p), 'device-group' ) ); }
    public static function templateEntries( PanoramaConf $p ) { return self::entries( self::child( self::localhost($p), 'template' ) ); }
    public static function stackEntries( PanoramaConf $p ) { return self::entries( self::child( self::localhost($p), 'template-stack' ) ); }

    public static function mgtDevices( PanoramaConf $p )
    {
        $n = DH::findXPathSingleEntry( '/config/mgt-config/devices', $p->xmlroot );
        return self::entries( $n === FALSE ? null : $n );
    }

    /** serials of a devices container (DG / template / stack) */
    public static function deviceSerials( $entry )
    {
        return array_keys( self::entries( self::child( $entry, 'devices' ) ) );
    }

    /**
     * named objects below a node (shared or a device group): "path|name" => array( path, name, node )
     * path relative to the node, e.g. address, profiles/virus, log-settings/syslog
     */
    public static function objectIndex( $node, $path = '', &$out = array() )
    {
        if( $node === null )
            return $out;
        foreach( $node->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            if( $c->nodeName == 'entry' && $c->hasAttribute('name') )
            {
                if( $path !== '' )
                    $out[$path . "|" . $c->getAttribute('name')] = array( 'path' => $path, 'name' => $c->getAttribute('name'), 'node' => $c );
                continue;
            }
            if( $path === '' && in_array($c->nodeName, self::SKIP_CONTAINERS, TRUE) )
                continue;
            self::objectIndex( $c, $path === '' ? $c->nodeName : $path . "/" . $c->nodeName, $out );
        }
        return $out;
    }

    /**
     * setting blocks of shared: elements without named entries (e.g. ssl-decrypt, response-page, content-preview,
     * log-settings/<singleton>) - path => DOMElement; rule bases and default-security-rules are handled elsewhere
     */
    public static function settingBlocks( $node, $path = '', &$out = array() )
    {
        if( $node === null )
            return $out;
        foreach( $node->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE || $c->nodeName == 'entry' )
                continue;
            if( $path === '' && in_array($c->nodeName, array( 'pre-rulebase', 'post-rulebase', 'default-security-rules' ), TRUE) )
                continue;
            $p = $path === '' ? $c->nodeName : $path . "/" . $c->nodeName;
            $x = new DOMXPath( $c->ownerDocument );
            if( $x->query('.//entry[@name]', $c)->length == 0 )
                $out[$p] = $c;
            else
                self::settingBlocks( $c, $p, $out );
        }
        return $out;
    }

    /** referenced names in a subtree: all text values except descriptions and flags */
    public static function tokens( $node, &$set = array() )
    {
        if( $node === null )
            return $set;
        if( $node->nodeType == XML_TEXT_NODE || $node->nodeType == XML_CDATA_SECTION_NODE )
        {
            $t = trim($node->nodeValue);
            if( $t !== '' && $node->parentNode !== null && !in_array($node->parentNode->nodeName, self::NO_TOKEN, TRUE) )
                $set[$t] = TRUE;
            return $set;
        }
        if( $node->nodeType == XML_ELEMENT_NODE && in_array($node->nodeName, self::NO_TOKEN, TRUE) )
            return $set;
        foreach( $node->childNodes as $c )
            self::tokens( $c, $set );
        return $set;
    }

    /** canonical string of an element for value comparison (whitespace, uuid / admin attributes removed) */
    public static function canon( $node, $withDescription = TRUE )
    {
        $d = new DOMDocument();
        $n = $d->importNode( $node, TRUE );
        $d->appendChild( $n );
        $x = new DOMXPath( $d );
        foreach( iterator_to_array($x->query('//text()[normalize-space(.)=""]')) as $t )
            $t->parentNode->removeChild( $t );
        foreach( iterator_to_array($x->query('//@uuid | //@admin | //@dirtyId | //@time | //@loc | //@src')) as $a )
            $a->ownerElement->removeAttributeNode( $a );
        // encrypted values depend on the master key - not comparable, masked
        foreach( iterator_to_array($x->query('//text()[starts-with(normalize-space(.),"' . self::SECRET_PREFIX . '")]')) as $t )
            $t->nodeValue = 'ENCRYPTED';
        if( !$withDescription )
            foreach( iterator_to_array($x->query('//description')) as $t )
                $t->parentNode->removeChild( $t );
        // member order is irrelevant
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

    /** text nodes with values encrypted with the master key below $node */
    public static function secretNodes( $node )
    {
        if( $node === null )
            return array();
        $x = new DOMXPath( $node->ownerDocument );
        return iterator_to_array( $x->query('.//text()[starts-with(normalize-space(.),"' . self::SECRET_PREFIX . '")]', $node) );
    }

    /** readable path of a node below $root: element names, entries as entry[name] */
    public static function relPath( $node, $root )
    {
        $parts = array();
        $n = $node->nodeType == XML_ELEMENT_NODE ? $node : $node->parentNode;
        while( $n !== null && !$n->isSameNode($root) )
        {
            $parts[] = $n->nodeName == 'entry' && $n->hasAttribute('name') ? 'entry[' . $n->getAttribute('name') . ']' : $n->nodeName;
            $n = $n->parentNode;
        }
        return implode( '/', array_reverse($parts) );
    }

    /** remove the elements holding encrypted values (master-key=different): they are set again in file2 */
    public static function stripSecrets( $node )
    {
        $n = 0;
        foreach( self::secretNodes( $node ) as $t )
        {
            $el = $t->parentNode;
            if( $el !== null && $el->parentNode !== null )
            {
                $el->parentNode->removeChild( $el );
                $n++;
            }
        }
        return $n;
    }

    /** rules of a rulebase: array of array( type, name, node ) */
    public static function rules( $parent, $which )
    {
        $out = array();
        $rb = self::child( $parent, $which );
        if( $rb === null )
            return $out;
        foreach( $rb->childNodes as $type )
        {
            if( $type->nodeType != XML_ELEMENT_NODE || $type->nodeName == 'default-security-rules' )
                continue;
            foreach( self::entries( self::child($type, 'rules') ) as $name => $e )
                $out[] = array( 'type' => $type->nodeName, 'name' => $name, 'node' => $e );
        }
        return $out;
    }

    /** TRUE / FALSE whether a rule applies to a firewall serial; 'tags' when device tags decide (not resolvable offline) */
    public static function applies( $rule, $serial )
    {
        $t = self::child( $rule, 'target' );
        if( $t === null )
            return TRUE;
        $devs = array_keys( self::entries( self::child($t, 'devices') ) );
        $tags = self::child( $t, 'tags' );
        $negate = self::child( $t, 'negate' );
        $negate = $negate !== null && trim($negate->textContent) == 'yes';
        if( count($devs) == 0 && ( $tags === null || trim($tags->textContent) === '' ) )
            return TRUE;
        if( $tags !== null && trim($tags->textContent) !== '' && !in_array($serial, $devs, TRUE) )
            return 'tags';
        $in = in_array( $serial, $devs, TRUE );
        return $negate ? !$in : $in;
    }

    public static function ensurePath( DOMElement $root, $path )
    {
        $n = $root;
        foreach( explode('/', $path) as $p )
        {
            $c = self::child( $n, $p );
            if( $c === null )
            {
                $c = $n->ownerDocument->createElement( $p );
                $n->appendChild( $c );
            }
            $n = $c;
        }
        return $n;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // calculation (concept 3)

    public function check()
    {
        $A = $this->A; $B = $this->B;
        $this->stats['version'] = array( 'file1' => $A->version, 'file2' => $B->version );
        if( $B->version < $A->version )
            $this->finding( 'blocking', 'version', 'PAN-OS ' . $B->version, 'version ' . $A->version, 'version ' . $B->version, 'target Panorama must have the same or a newer version' );
        elseif( $B->version > $A->version )
            $this->finding( 'warning', 'version', 'PAN-OS ' . $B->version, 'version ' . $A->version, 'version ' . $B->version, 'check the configuration after the import (schema changes)' );

        $dgA = self::dgEntries( $A );
        // 3.1 device groups
        $move = array();
        foreach( $this->selected as $name )
        {
            $dg = $A->findDeviceGroup( $name );
            if( $dg === null )
            {
                $this->finding( 'blocking', 'selection', $name, 'device group not found', '', 'check dg-list' );
                continue;
            }
            $move[$name] = TRUE;
            $this->dgReason[$name] = 'selected';
            foreach( $dg->childDeviceGroups(TRUE) as $c )
                if( !isset($move[$c->name()]) )
                {
                    $move[$c->name()] = TRUE;
                    $this->dgReason[$c->name()] = 'child of ' . $name;
                    if( !in_array($c->name(), $this->selected, TRUE) )
                        $this->finding( 'warning', 'device group', $c->name(), 'child device group of ' . $name, '', 'moved together with its parent (D1)' );
                }
        }
        // parents: move when all children are moved and no own devices, otherwise copy
        $changed = TRUE;
        $copy = array();
        while( $changed )
        {
            $changed = FALSE;
            foreach( array_keys($move) + array_keys($copy) as $name )
            {
                $dg = $A->findDeviceGroup( $name );
                $p = $dg !== null ? $dg->parentDeviceGroup : null;
                if( $p === null || $p->name() == 'shared' || isset($move[$p->name()]) || isset($copy[$p->name()]) )
                    continue;
                $allMoved = TRUE;
                foreach( $p->childDeviceGroups(TRUE) as $c )
                    if( !isset($move[$c->name()]) )
                        $allMoved = FALSE;
                $own = count( $p->getDevicesInGroup(FALSE) );
                if( $allMoved && $own == 0 )
                {
                    $move[$p->name()] = TRUE;
                    $this->dgReason[$p->name()] = 'parent, all child device groups moved, no own devices';
                }
                else
                {
                    $copy[$p->name()] = TRUE;
                    $this->dgReason[$p->name()] = 'parent, still used in file1 (' . ( $allMoved ? $own . ' own device(s)' : 'other child device groups' ) . ')';
                }
                $changed = TRUE;
            }
        }
        foreach( $move as $n => $x ) $this->dgAction[$n] = 'move';
        foreach( $copy as $n => $x ) $this->dgAction[$n] = 'copy';
        foreach( array_keys($this->dgAction) as $n )
        {
            $dg = $A->findDeviceGroup( $n );
            $p = $dg->parentDeviceGroup;
            $this->dgParentB[$n] = ( $p !== null && $p->name() != 'shared' && isset($this->dgAction[$p->name()]) ) ? $p->name() : $this->targetParent;
        }

        // 3.2 devices
        foreach( $this->dgAction as $n => $act )
        {
            if( $act != 'move' )
                continue;
            foreach( $A->findDeviceGroup($n)->getDevicesInGroup(FALSE) as $serial => $d )
                $this->devices[$serial] = array( 'dg' => $n, 'vsys' => array_values( isset($d['vsyslist']) ? $d['vsyslist'] : array() ) );
        }
        foreach( $dgA as $n => $e )
            if( !isset($this->dgAction[$n]) || $this->dgAction[$n] == 'copy' )
                foreach( self::deviceSerials($e) as $s )
                    if( isset($this->devices[$s]) )
                        $this->finding( 'blocking', 'device', $s, 'vsys in moved device group ' . $this->devices[$s]['dg'] . ' and in kept device group ' . $n, '', 'a firewall can only be managed by one Panorama (D2)' );

        // 3.3 template stacks / templates
        $stacksA = self::stackEntries( $A );
        $tplA = self::templateEntries( $A );
        $relStacks = array(); $relTpl = array();
        foreach( $stacksA as $n => $e )
            foreach( self::deviceSerials($e) as $s )
                if( isset($this->devices[$s]) )
                    $relStacks[$n] = 'device ' . $s;
        foreach( $tplA as $n => $e )
            foreach( self::deviceSerials($e) as $s )
                if( isset($this->devices[$s]) )
                    $relTpl[$n] = 'device ' . $s;
        foreach( array_keys($this->dgAction) as $n )
            foreach( self::child($dgA[$n], 'reference-templates') ? DH::findFirstElement('reference-templates', $dgA[$n])->getElementsByTagName('member') : array() as $m )
            {
                $r = trim($m->textContent);
                if( isset($stacksA[$r]) ) $relStacks[$r] = isset($relStacks[$r]) ? $relStacks[$r] : 'reference-templates of ' . $n;
                elseif( isset($tplA[$r]) ) $relTpl[$r] = isset($relTpl[$r]) ? $relTpl[$r] : 'reference-templates of ' . $n;
            }
        foreach( $relStacks as $n => $why )
            foreach( self::child($stacksA[$n], 'templates') ? $stacksA[$n]->getElementsByTagName('member') : array() as $m )
                if( !isset($relTpl[trim($m->textContent)]) )
                    $relTpl[trim($m->textContent)] = 'member of template stack ' . $n;
        // usage by the remaining configuration
        $keptRefs = array();
        foreach( $dgA as $n => $e )
            if( !isset($this->dgAction[$n]) || $this->dgAction[$n] == 'copy' )
                foreach( self::child($e, 'reference-templates') ? DH::findFirstElement('reference-templates', $e)->getElementsByTagName('member') : array() as $m )
                    $keptRefs[trim($m->textContent)][] = 'reference-templates of DG ' . $n;
        foreach( $relStacks as $n => $why )
        {
            $this->stackSerials[$n] = self::deviceSerials( $stacksA[$n] );
            $other = array_diff( self::deviceSerials($stacksA[$n]), array_keys($this->devices) );
            $users = isset($keptRefs[$n]) ? $keptRefs[$n] : array();
            if( count($other) ) $users[] = count($other) . ' device(s) not moved';
            $this->stackAction[$n] = count($users) ? 'copy' : 'move';
            $this->stackReason[$n] = $why . ( count($users) ? '; still used: ' . implode(', ', $users) : '' );
        }
        foreach( $relTpl as $n => $why )
        {
            if( !isset($tplA[$n]) )
            {
                $this->finding( 'warning', 'template', $n, 'referenced (' . $why . ') but not found', '', '' );
                continue;
            }
            $users = isset($keptRefs[$n]) ? $keptRefs[$n] : array();
            $other = array_diff( self::deviceSerials($tplA[$n]), array_keys($this->devices) );
            if( count($other) ) $users[] = count($other) . ' device(s) not moved';
            foreach( $stacksA as $sn => $se )
                if( ( !isset($this->stackAction[$sn]) || $this->stackAction[$sn] == 'copy' ) && self::child($se, 'templates') )
                    foreach( $se->getElementsByTagName('member') as $m )
                        if( trim($m->textContent) == $n && DH::findFirstElement('templates', $se)->isSameNode($m->parentNode) )
                            $users[] = 'template stack ' . $sn;
            $this->templateAction[$n] = count($users) ? 'copy' : 'move';
            $this->templateReason[$n] = $why . ( count($users) ? '; still used: ' . implode(', ', array_unique($users)) : '' );
        }
        // master-device / panorama server settings in moved templates
        foreach( array_keys($this->dgAction) as $n )
            foreach( $dgA[$n]->getElementsByTagName('master-device') as $md )
            {
                $dev = self::child( $md, 'device' );
                $s = $dev !== null ? trim($dev->textContent) : trim($md->textContent);
                if( $s !== '' && !isset($this->devices[$s]) )
                {
                    $this->masterDevices[$n] = $s;
                    $this->finding( 'warning', 'device group', $n, 'master-device ' . $s . ' is not moved', '', 'choose a moved firewall as master device in file2' );
                }
            }

        $this->checkNames();
        $this->collectPanoramaSettings();
        $this->checkRules();
        $this->checkSettings();
        $this->collectShared();
        $this->previewRewrites();
        $this->collectSecrets();
        $this->checkOtherReferences();
        $this->checkUnresolved();
        $this->verifyEffectiveRulebase();
        return $this;
    }

    private function checkNames()
    {
        $dgB = self::dgEntries( $this->B ); $tplB = self::templateEntries( $this->B ); $stB = self::stackEntries( $this->B ); $devB = self::mgtDevices( $this->B );
        $lc = function( $arr ) { $o = array(); foreach( array_keys($arr) as $k ) $o[strtolower(trim($k))] = $k; return $o; };
        $sets = array(
            'device group' => array( array_keys($this->dgAction), $dgB ),
            'template' => array( array_keys($this->templateAction), $tplB ),
            'template stack' => array( array_keys($this->stackAction), $stB ),
        );
        // DG / template / stack names share the Panorama name space for containers
        $allB = $dgB + $tplB + $stB;
        // names a renamed container must not take: file2 containers + the containers transferred from file1
        $taken = array();
        foreach( array_keys($allB) as $n ) $taken[strtolower($n)] = TRUE;
        foreach( $sets as $s ) foreach( $s[0] as $n ) $taken[strtolower($n)] = TRUE;
        foreach( $sets as $cat => $s )
        {
            $l = $lc( $allB );
            foreach( $s[0] as $n )
            {
                if( isset($allB[$n]) )
                {
                    $where = 'name exists in file2 (' . ( isset($dgB[$n]) ? 'device group' : ( isset($tplB[$n]) ? 'template' : 'template stack' ) ) . ')';
                    if( $this->renameSuffix === null )
                        $this->finding( 'blocking', $cat, $n, '', $where, 'rename in file1 or file2 before the move (D4) or use conflict=rename:<suffix>' );
                    elseif( isset($taken[strtolower($n . $this->renameSuffix)]) )
                        $this->finding( 'blocking', $cat, $n, '', $where, 'rename target "' . $n . $this->renameSuffix . '" exists already - choose another suffix (D4)' );
                    else
                    {
                        $new = $n . $this->renameSuffix;
                        $taken[strtolower($new)] = TRUE;
                        $this->renames[$cat][$n] = $new;
                        $this->finding( 'warning', $cat, $n, '', $where, 'renamed to "' . $new . '" in file2 (conflict=rename, D4)' . ( strlen($new) > 31 ? ' - longer than 31 characters, check the limit of file2' : '' ) );
                    }
                }
                elseif( isset($l[strtolower(trim($n))]) )
                    $this->finding( 'warning', $cat, $n, '', 'differs only in case / blanks from ' . $l[strtolower(trim($n))], 'avoid look-alike names' );
                if( $n !== trim($n) )
                    $this->finding( 'warning', $cat, $n, 'leading / trailing blank', '', 'rename' );
                if( strlen($n) > 31 && $cat == 'device group' )
                    $this->finding( 'warning', $cat, $n, 'longer than 31 characters', '', 'check the name length limit of file2' );
            }
        }
        if( $this->targetParent !== null && !isset($dgB[$this->targetParent]) )
            $this->finding( 'blocking', 'device group', $this->targetParent, '', 'target-parent-dg not found in file2', '' );
        foreach( $this->devices as $s => $d )
            if( isset($devB[$s]) )
                $this->finding( 'blocking', 'device', $s, 'moved with ' . $d['dg'], 'serial already managed in file2', 'remove the device from file2 first' );
        // template variables
        $varsB = array();
        foreach( $tplB + $stB as $n => $e )
            foreach( $e->getElementsByTagName('variable') as $v )
                foreach( self::entries($v) as $vn => $ve )
                    $varsB[$vn] = $n;
        foreach( array_merge(array_keys($this->templateAction), array_keys($this->stackAction)) as $n )
        {
            $e = isset(self::templateEntries($this->A)[$n]) ? self::templateEntries($this->A)[$n] : self::stackEntries($this->A)[$n];
            foreach( $e->getElementsByTagName('variable') as $v )
                foreach( self::entries($v) as $vn => $ve )
                    if( isset($varsB[$vn]) )
                        $this->finding( 'info', 'template variable', $vn, 'in ' . $n, 'also defined in ' . $varsB[$vn], 'variables are per template / stack - no conflict, check the naming convention' );
        }
        // ancestor-objects-take-precedence
        $pa = $this->A->ancestorObjectsTakePrecedence(); $pb = $this->B->ancestorObjectsTakePrecedence();
        $this->stats['ancestor_objects_take_precedence'] = array( 'file1' => $pa, 'file2' => $pb );
        if( $pa !== $pb )
            $this->finding( 'warning', 'setting', 'ancestor-objects-take-precedence', $pa ? 'yes' : 'no', $pb ? 'yes' : 'no', 'objects with the same name in shared and the device group resolve differently after the move' );
    }

    /**
     * encrypted values (pre-shared keys, bind / server profile passwords, private keys, SNMP, ...) in everything that is
     * transferred. They are valid only on a Panorama with the same master key. master-key=same: copied unchanged;
     * master-key=different: removed on transfer and listed to be set again in file2. Values are never decrypted or printed.
     */
    private function collectSecrets()
    {
        $roots = array();
        $dgA = self::dgEntries( $this->A ); $tplA = self::templateEntries( $this->A ); $stA = self::stackEntries( $this->A ); $mgtA = self::mgtDevices( $this->A );
        foreach( array_keys($this->dgAction) as $n ) $roots[] = array( 'device group ' . $n, $dgA[$n] );
        foreach( array_keys($this->templateAction) as $n ) if( isset($tplA[$n]) ) $roots[] = array( 'template ' . $n, $tplA[$n] );
        foreach( array_keys($this->stackAction) as $n ) $roots[] = array( 'template stack ' . $n, $stA[$n] );
        foreach( array_keys($this->devices) as $s ) if( isset($mgtA[$s]) ) $roots[] = array( 'managed device ' . $s, $mgtA[$s] );
        foreach( $this->sharedObjects as $o )
            if( $o['action'] == 'copy' )
                $roots[] = array( 'shared ' . $o['path'] . ' ' . $o['name'], $o['node'] );
            elseif( $o['action'] == 'reuse' && count(self::secretNodes($o['node'])) )
                $this->finding( 'info', 'encrypted value', $o['path'] . ' ' . $o['name'], 'reused from file2', 'encrypted values not compared', 'the file2 object keeps its own secret - check it is the same' );
        if( $this->sharedSettings == 'copy-missing' )
            foreach( $this->settings as $p => $st )
                if( $st['status'] == 'missing' )
                    $roots[] = array( 'shared ' . $p, $st['node'] );
        foreach( $roots as $r )
            foreach( self::secretNodes( $r[1] ) as $t )
                $this->secrets[] = array( 'location' => $r[0], 'path' => self::relPath( $t, $r[1] ), 'field' => $t->parentNode->nodeName );
        $n = count( $this->secrets );
        $this->stats['encrypted_values'] = $n;
        if( $n == 0 )
            return;
        if( $this->masterKey == 'same' )
            $this->finding( 'warning', 'encrypted value', $n . ' encrypted value(s)', 'copied unchanged (master-key=same)', 'valid only with the same master key as file1',
                'the master key cannot be checked offline - confirm it on both Panoramas; otherwise use master-key=different (SECRETS_CHECKLIST.md)' );
        else
            $this->finding( 'warning', 'encrypted value', $n . ' encrypted value(s)', 'removed on transfer (master-key=different)', 'to be set in file2 after the import',
                'SECRETS_CHECKLIST.md lists every field; a commit in file2 reports the missing values' );
    }

    /**
     * shared setting blocks: they apply to every device group - compare A with B; with shared-settings=copy-missing the
     * blocks missing in B are copied (blocks that differ are never overwritten: they apply to all device groups of B)
     */
    private function checkSettings()
    {
        $sa = self::settingBlocks( $this->A->sharedroot );
        $sb = self::settingBlocks( $this->B->sharedroot );
        foreach( $sa as $p => $n )
        {
            if( trim($n->textContent) === '' && $n->getElementsByTagName('*')->length == 0 )
                continue;
            $status = !isset($sb[$p]) ? 'missing' : ( self::canon($n) === self::canon($sb[$p]) ? 'same' : 'differs' );
            $this->settings[$p] = array( 'node' => $n, 'status' => $status );
            $value = implode( ', ', array_keys( self::tokens($n) ) );
            if( $status == 'missing' )
                $this->finding( 'warning', 'shared setting', $p, $value === '' ? '(set)' : substr($value, 0, 120), 'not in file2',
                    $this->sharedSettings == 'copy-missing' ? 'copied to file2 (shared-settings=copy-missing)' : 'applies to the moved firewalls in file1 - copy with shared-settings=copy-missing or configure in file2' );
            elseif( $status == 'differs' )
                $this->finding( 'warning', 'shared setting', $p, substr($value, 0, 120), substr(implode(', ', array_keys(self::tokens($sb[$p]))), 0, 120),
                    'applies to all device groups of file2 - not overwritten, align manually if the moved firewalls need the file1 value' );
        }
        foreach( $sb as $p => $n )
            if( !isset($sa[$p]) && ( trim($n->textContent) !== '' || $n->getElementsByTagName('*')->length ) )
            {
                $this->settings[$p] = array( 'node' => null, 'status' => 'only-in-file2' );
                $this->finding( 'info', 'shared setting', $p, 'not set', 'set in file2', 'applies to the moved firewalls after the move' );
            }
    }

    /** 3.4 shared objects: closure over the referenced names + comparison with file2 */
    private function collectShared()
    {
        $sharedA = self::objectIndex( $this->A->sharedroot );
        $sharedB = self::objectIndex( $this->B->sharedroot );
        $byName = array();
        foreach( $sharedA as $k => $o )
            $byName[$o['name']][] = $k;
        $roots = array();
        $dgA = self::dgEntries( $this->A ); $tplA = self::templateEntries( $this->A ); $stA = self::stackEntries( $this->A );
        foreach( array_keys($this->dgAction) as $n ) $roots[] = $dgA[$n];
        foreach( array_keys($this->templateAction) as $n ) if( isset($tplA[$n]) ) $roots[] = $tplA[$n];
        foreach( array_keys($this->stackAction) as $n ) $roots[] = $stA[$n];
        foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
            foreach( self::rules( $this->A->sharedroot, $w ) as $r )
                if( isset($this->sharedRulesToCopy[$w . '|' . $r['type'] . '|' . $r['name']]) )
                    $roots[] = $r['node'];
        if( $this->sharedSettings == 'copy-missing' )
            foreach( $this->settings as $p => $st )
                if( $st['status'] == 'missing' )
                    $roots[] = $st['node'];
        $tokens = array();
        foreach( $roots as $r )
            self::tokens( $r, $tokens );
        $rel = array();
        $queue = array_keys( $tokens );
        while( count($queue) )
        {
            $t = array_pop( $queue );
            if( !isset($byName[$t]) )
                continue;
            foreach( $byName[$t] as $k )
            {
                if( isset($rel[$k]) )
                    continue;
                $rel[$k] = TRUE;
                foreach( array_keys( self::tokens($sharedA[$k]['node']) ) as $nt )
                    if( !isset($tokens[$nt]) ) { $tokens[$nt] = TRUE; $queue[] = $nt; }
            }
        }
        // namespaces of file2
        $nsB = array();
        foreach( $sharedB as $k => $o )
        {
            $ns = isset(self::NAMESPACES[$o['path']]) ? self::NAMESPACES[$o['path']] : $o['path'];
            $nsB[$ns][$o['name']] = $o['path'];
            $nsB[$ns . '#lc'][strtolower($o['name'])] = $o['name'];
        }
        $conflicts = array();
        foreach( array_keys($rel) as $k )
        {
            $o = $sharedA[$k];
            $ns = isset(self::NAMESPACES[$o['path']]) ? self::NAMESPACES[$o['path']] : $o['path'];
            $action = 'copy';
            if( isset($sharedB[$k]) )
            {
                if( self::canon($o['node']) === self::canon($sharedB[$k]['node']) )
                    $action = 'reuse';
                elseif( self::canon($o['node'], FALSE) === self::canon($sharedB[$k]['node'], FALSE) )
                {
                    $action = 'reuse';
                    $this->finding( 'info', 'shared object', $o['path'] . ' ' . $o['name'], 'same value', 'description differs', 'file2 version is kept' );
                }
                else
                {
                    $action = 'conflict';
                    $conflicts[$k] = array( 'used by the moved configuration', 'same name, other value' );
                }
            }
            elseif( isset($nsB[$ns][$o['name']]) )
            {
                $action = 'conflict';
                $conflicts[$k] = array( '', 'name used by ' . $nsB[$ns][$o['name']] . ' (same name space)' );
            }
            elseif( isset($nsB[$ns . '#lc'][strtolower($o['name'])]) )
                $this->finding( 'warning', 'shared object', $o['path'] . ' ' . $o['name'], '', 'differs only in case from ' . $nsB[$ns . '#lc'][strtolower($o['name'])], 'avoid look-alike names' );
            if( $o['name'] !== trim($o['name']) )
                $this->finding( 'warning', 'shared object', $o['path'] . ' "' . $o['name'] . '"', 'leading / trailing blank', '', 'rename' );
            $this->sharedObjects[$k] = array( 'path' => $o['path'], 'name' => $o['name'], 'node' => $o['node'], 'action' => $action );
        }
        $this->resolveObjectConflicts( $conflicts, $sharedA, $sharedB, $dgA );
        // predefined names
        foreach( $this->sharedObjects as $k => $o )
        {
            if( $o['path'] == 'service' && isset(ServiceStore::PREDEFINED_SERVICES[$o['name']]) )
                $this->finding( 'warning', 'predefined', 'service ' . $o['name'], 'shared object', 'predefined service', 'the configured object overrides the predefined one' );
            if( $o['path'] == 'profiles/custom-url-category' && SecurityProfileStore::getURLPredefinedStore(null)->find($o['name'], null, FALSE) !== null )
                $this->finding( 'warning', 'predefined', 'URL category ' . $o['name'], 'custom URL category', 'predefined URL category', 'rename' );
            if( $o['path'] == 'application' && $this->B->appStore->find($o['name']) !== null )
                $this->finding( 'warning', 'predefined', 'application ' . $o['name'], 'custom application', 'predefined application in file2', 'rename' );
        }
        // device group objects overriding shared objects of file2
        $pb = $this->B->ancestorObjectsTakePrecedence() ? 'yes' : 'no';
        foreach( array_keys($this->dgAction) as $n )
            foreach( self::objectIndex( $dgA[$n] ) as $k => $o )
                if( isset($sharedB[$k]) && !isset($sharedA[$k]) )
                    $this->finding( 'warning', 'override', $o['path'] . ' ' . $o['name'], 'device group ' . $n, 'also in shared of file2 (ancestor-objects-take-precedence ' . $pb . ')', $pb == 'yes' ? 'shared object of file2 wins - check the value' : 'device group object wins' );
        $this->stats['shared_objects'] = array( 'relevant' => count($this->sharedObjects),
            'renamed' => count(array_filter($this->sharedObjects, function($o){ return isset($o['rename']); })),
            'copy' => count(array_filter($this->sharedObjects, function($o){ return $o['action'] == 'copy'; })),
            'reuse' => count(array_filter($this->sharedObjects, function($o){ return $o['action'] == 'reuse'; })),
            'conflict' => count(array_filter($this->sharedObjects, function($o){ return $o['action'] == 'conflict'; })) );
    }

    /**
     * D5: shared objects with the same name and another value (or the same name space) in file2.
     * conflict=stop: blocking. conflict=rename:<suffix>: the object is copied as <name><suffix> and every reference in the
     * transferred configuration is rewritten. References are text values without a type, so all relevant shared objects
     * with that name are renamed together; reused objects that reference a renamed name are renamed as well (their value
     * in file2 would differ). Not renamed (blocking): new name taken, or the name is also a local object of another type
     * in a moved device group chain (references ambiguous).
     */
    private function resolveObjectConflicts( $conflicts, $sharedA, $sharedB, $dgA )
    {
        if( $this->renameSuffix === null )
        {
            foreach( $conflicts as $k => $c )
                $this->finding( 'blocking', 'shared object', $this->sharedObjects[$k]['path'] . ' ' . $this->sharedObjects[$k]['name'], $c[0], $c[1], 'rename in file1 before the move, align the value or use conflict=rename:<suffix> (D5)' );
            return;
        }
        $nsOf = function( $path ) { return isset(self::NAMESPACES[$path]) ? self::NAMESPACES[$path] : $path; };
        $S = array();
        foreach( $conflicts as $k => $c )
            $S[$this->sharedObjects[$k]['name']] = TRUE;
        $changed = count($S) > 0;
        while( $changed )
        {
            $changed = FALSE;
            foreach( $this->sharedObjects as $k => $o )
                if( !isset($S[$o['name']]) && $o['action'] == 'reuse' && count( array_intersect_key( self::tokens($o['node']), $S ) ) )
                {
                    $S[$o['name']] = TRUE;
                    $changed = TRUE;
                }
        }
        if( !count($S) )
            return;
        // names a renamed object must not take - any type, references carry no type
        $taken = array();
        foreach( $sharedA as $o ) $taken[$o['name']] = TRUE;
        foreach( $sharedB as $o ) $taken[$o['name']] = TRUE;
        $local = array();
        foreach( array_keys($this->dgAction) as $n )
            foreach( self::objectIndex( $dgA[$n] ) as $o )
            {
                $local[$n][$o['name']][$nsOf($o['path'])] = TRUE;
                $taken[$o['name']] = TRUE;
            }
        if( $this->targetParent !== null && ( $tp = $this->B->findDeviceGroup($this->targetParent) ) !== null )
        {
            $dgB = self::dgEntries( $this->B );
            foreach( array_merge( array( $this->targetParent ), array_keys( $tp->parentDeviceGroups() ) ) as $pn )
                if( isset($dgB[$pn]) )
                    foreach( self::objectIndex( $dgB[$pn] ) as $o )
                        $taken[$o['name']] = TRUE;
        }
        $byName = array();
        foreach( $this->sharedObjects as $k => $o )
            if( isset($S[$o['name']]) )
                $byName[$o['name']][] = $k;
        foreach( $byName as $name => $keys )
        {
            $new = $name . $this->renameSuffix;
            $nsShared = array();
            foreach( $keys as $k ) $nsShared[$nsOf($this->sharedObjects[$k]['path'])] = TRUE;
            $problem = null;
            $exclude = array();
            if( isset($taken[$new]) )
                $problem = 'rename target "' . $new . '" exists already - choose another suffix';
            else
                foreach( array_keys($this->dgAction) as $n )
                {
                    $ln = array();
                    foreach( array_merge( array( $n ), array_keys( $this->A->findDeviceGroup($n)->parentDeviceGroups() ) ) as $c )
                        if( isset($local[$c][$name]) )
                            $ln += $local[$c][$name];
                    if( !count($ln) )
                        continue;
                    if( count( array_diff_key($nsShared, $ln) ) == 0 )
                        $exclude[] = $n;
                    else
                    {
                        $problem = 'also a local object of another type in device group ' . $n . ' (or its parents) - references cannot be rewritten unambiguously, rename manually';
                        break;
                    }
                }
            if( $problem !== null )
            {
                foreach( $keys as $k )
                    if( $this->sharedObjects[$k]['action'] == 'conflict' )
                        $this->finding( 'blocking', 'shared object', $this->sharedObjects[$k]['path'] . ' ' . $name, $conflicts[$k][0], $conflicts[$k][1], $problem . ' (D5)' );
                    elseif( $this->sharedObjects[$k]['action'] == 'reuse' )
                        $this->finding( 'warning', 'shared object', $this->sharedObjects[$k]['path'] . ' ' . $name, 'references an object that is renamed or in conflict', 'reused - keeps the file2 value', $problem );
                continue;
            }
            $taken[$new] = TRUE;
            $this->objectRenames[$name] = $new;
            foreach( $exclude as $n )
                $this->renameExclude[$n][$name] = TRUE;
            foreach( $keys as $k )
            {
                $o = $this->sharedObjects[$k];
                $why = isset($conflicts[$k]) ? $conflicts[$k][1] : ( $o['action'] == 'reuse' ? 'reused object references a renamed object - its file2 value would differ' : 'same name as a renamed object (references carry no type)' );
                $this->finding( 'warning', 'shared object', $o['path'] . ' ' . $name, isset($conflicts[$k]) ? $conflicts[$k][0] : '', $why,
                    'renamed to "' . $new . '" in file2 (conflict=rename, D5)' . ( strlen($new) > 63 ? ' - longer than 63 characters' : '' ) );
                $this->sharedObjects[$k]['action'] = 'copy';
                $this->sharedObjects[$k]['rename'] = $new;
            }
            if( count($exclude) )
                $this->finding( 'info', 'shared object', $name, 'local object of the same type in device group(s) ' . implode(', ', $exclude), 'renamed to "' . $new . '"', 'references there resolve to the local object - not rewritten' );
        }
    }

    /** check run: list the references that execute will rewrite (nothing changed) */
    private function previewRewrites()
    {
        $this->rewrites = array();
        if( !count($this->objectRenames) )
            return;
        $dgA = self::dgEntries( $this->A );
        foreach( $this->sharedObjects as $o )
            if( $o['action'] == 'copy' )
                $this->rewriteRefs( $o['node'], 'shared ' . $o['path'] . ' ' . $o['name'], array(), TRUE );
        if( $this->sharedSettings == 'copy-missing' )
            foreach( $this->settings as $p => $st )
                if( $st['status'] == 'missing' )
                    $this->rewriteRefs( $st['node'], 'shared ' . $p, array(), TRUE );
        foreach( array_keys($this->dgAction) as $n )
            $this->rewriteRefs( $dgA[$n], 'device group ' . $n, isset($this->renameExclude[$n]) ? $this->renameExclude[$n] : array(), TRUE );
        foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
            foreach( self::rules( $this->A->sharedroot, $w ) as $r )
                if( isset($this->sharedRulesToCopy[$w . '|' . $r['type'] . '|' . $r['name']]) )
                    $this->rewriteRefs( $r['node'], 'shared ' . $w . ' ' . $r['type'] . ' ' . $r['name'], array(), TRUE );
    }

    /** shared rule impact per moved firewall and rule name conflicts (4a) */
    private function checkRules()
    {
        $A = $this->A; $B = $this->B;
        $dgA = self::dgEntries( $A );
        $rulesA = array( 'pre' => self::rules($A->sharedroot, 'pre-rulebase'), 'post' => self::rules($A->sharedroot, 'post-rulebase') );
        $rulesB = array( 'pre' => self::rules($B->sharedroot, 'pre-rulebase'), 'post' => self::rules($B->sharedroot, 'post-rulebase') );
        // rules are compared by their resolved values (RuleResolver): file1 shared rules as the firewalls of the moved
        // device group see them in file1, file2 shared rules as seen below the target parent in file2
        $locB = ( $this->targetParent !== null && $B->findDeviceGroup($this->targetParent) !== null ) ? $B->findDeviceGroup($this->targetParent) : $B;
        $sigB = array(); $sigBRule = array();
        foreach( $rulesB as $w => $list )
            foreach( $list as $r )
            {
                list( $m, $a ) = RuleResolver::signature( RuleResolver::resolve( $r['node'], $r['type'], $locB ) );
                $sigBRule[$w . '|' . $r['type'] . '|' . $r['name']] = $m;
                $sigB[$r['type'] . '|' . $m][] = array( 'name' => $r['name'], 'act' => $a, 'w' => $w );
            }
        $sigACache = array();
        $sigA = function( $dg, $w, $r ) use ( &$sigACache, $A ) {
            $k = $dg . '|' . $w . '|' . $r['type'] . '|' . $r['name'];
            if( !isset($sigACache[$k]) )
                $sigACache[$k] = RuleResolver::signature( RuleResolver::resolve( $r['node'], $r['type'], $A->findDeviceGroup($dg) ) );
            return $sigACache[$k];
        };
        // rule names: moved / copied DG rules vs. shared rules of file2 and the target parent chain
        $namesB = array();
        foreach( $rulesB as $w => $list )
            foreach( $list as $r )
                $namesB[$r['type'] . '|' . $r['name']] = 'shared ' . $w . '-rulebase';
        if( $this->targetParent !== null && $B->findDeviceGroup($this->targetParent) !== null )
        {
            $dgB = self::dgEntries( $B );
            foreach( $B->findDeviceGroup($this->targetParent)->parentDeviceGroups() as $pn => $pdg )
                if( isset($dgB[$pn]) )
                    foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
                        foreach( self::rules( $dgB[$pn], $w ) as $r )
                            $namesB[$r['type'] . '|' . $r['name']] = 'device group ' . $pn;
        }
        $movedNames = array();
        foreach( array_keys($this->dgAction) as $n )
            foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
                foreach( self::rules( $dgA[$n], $w ) as $r )
                    $movedNames[$r['type'] . '|' . $r['name']] = $n;
        // names a renamed rule must not take: "type|name" => TRUE (exists) or "renamed:<old name>"
        $taken = array();
        foreach( array_merge( array_keys($namesB), array_keys($movedNames) ) as $k ) $taken[$k] = TRUE;
        foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
            foreach( self::rules( $A->sharedroot, $w ) as $r )
                $taken[$r['type'] . '|' . $r['name']] = TRUE;
        foreach( array_keys($this->dgAction) as $n )
            foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
                foreach( self::rules( $dgA[$n], $w ) as $r )
                    if( isset($namesB[$r['type'] . '|' . $r['name']]) )
                        $this->ruleConflict( 'rule', $n . '|' . $w . '|' . $r['type'] . '|' . $r['name'], $r['type'], $r['name'], 'device group ' . $n, $namesB[$r['type'] . '|' . $r['name']], $taken, TRUE );

        // impact per firewall
        $groups = array();
        foreach( $this->devices as $serial => $d )
        {
            $chain = array_reverse( array_keys( $A->findDeviceGroup($d['dg'])->parentDeviceGroups() ) );
            $chainRules = 0;
            foreach( $chain as $cn )
                if( isset($dgA[$cn]) )
                    foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
                        foreach( self::rules( $dgA[$cn], $w ) as $r )
                            if( self::applies($r['node'], $serial) !== FALSE )
                                $chainRules++;
            $applyA = array(); $applyB = array(); $lost = array(); $added = array(); $differs = array(); $covered = array(); $tags = array();
            foreach( $rulesA as $w => $list )
                foreach( $list as $r )
                {
                    $ap = self::applies( $r['node'], $serial );
                    if( $ap === FALSE )
                        continue;
                    if( $ap === 'tags' ) $tags[] = $r['name'];
                    $applyA[] = $w . ':' . $r['type'] . ':' . $r['name'];
                    list( $m, $a ) = $sigA( $d['dg'], $w, $r );
                    $eq = isset($sigB[$r['type'] . '|' . $m]) ? $sigB[$r['type'] . '|' . $m] : array();
                    $same = array_filter( $eq, function($x) use ($a) { return $x['act'] === $a; } );
                    if( count($same) ) $covered[] = $r['name'] . ' = ' . array_values($same)[0]['name'];
                    elseif( count($eq) ) $differs[] = $r['name'] . ' ~ ' . $eq[0]['name'];
                    else
                    {
                        $lost[] = $w . ' ' . $r['type'] . ' ' . $r['name'];
                        $this->sharedRulesToCopy[( $w == 'pre' ? 'pre-rulebase' : 'post-rulebase' ) . '|' . $r['type'] . '|' . $r['name']] = TRUE;
                    }
                }
            foreach( $rulesB as $w => $list )
                foreach( $list as $r )
                {
                    if( self::applies( $r['node'], $serial ) === FALSE )
                        continue;
                    $applyB[] = $w . ':' . $r['type'] . ':' . $r['name'];
                    $found = FALSE;
                    $m = $sigBRule[$w . '|' . $r['type'] . '|' . $r['name']];
                    foreach( $rulesA as $wa => $la )
                        foreach( $la as $ra )
                            if( $ra['type'] == $r['type'] && self::applies($ra['node'], $serial) !== FALSE && $sigA( $d['dg'], $wa, $ra )[0] === $m )
                                $found = TRUE;
                    if( !$found ) $added[] = $w . ' ' . $r['type'] . ' ' . $r['name'];
                }
            $copied = $this->sharedRules == 'to-top-dg' ? count($lost) : 0;
            $key = md5( $d['dg'] . json_encode(array($applyA, $applyB)) );
            if( !isset($groups[$key]) )
                $groups[$key] = array( 'device_group' => $d['dg'], 'firewalls' => array(),
                    'rules_before' => count($applyA) + $chainRules, 'rules_after' => count($applyB) + $chainRules + $copied,
                    'shared_A_applying' => count($applyA), 'shared_B_applying' => count($applyB), 'device_group_rules' => $chainRules,
                    'lost' => $lost, 'added' => $added, 'covered' => $covered, 'differs' => $differs,
                    'target_by_tags' => $tags );
            $groups[$key]['firewalls'][] = $serial;
        }
        $this->ruleImpact = array_values( $groups );
        if( $this->sharedRules == 'to-top-dg' )
            foreach( array_keys($this->sharedRulesToCopy) as $k )
            {
                list( $w, $type, $name ) = explode( '|', $k, 3 );
                $other = isset($namesB[$type . '|' . $name]) ? $namesB[$type . '|' . $name] : ( isset($movedNames[$type . '|' . $name]) ? 'device group ' . $movedNames[$type . '|' . $name] : null );
                if( $other !== null )
                    $this->ruleConflict( 'shared rule', $k, $type, $name, 'shared ' . $w . ' (shared-rules=to-top-dg)', $other, $taken, FALSE );
            }
        else
            $this->sharedRulesToCopy = array();
        $lostTotal = 0;
        foreach( $this->ruleImpact as $g )
            $lostTotal += count($g['lost']) ? 1 : 0;
        if( $lostTotal )
            $this->finding( 'warning', 'shared rules', 'shared rules of file1 without equivalent in file2', 'apply to moved firewalls', 'not in file2',
                $this->sharedRules == 'to-top-dg' ? 'copied into the top moved device group(s) (shared-rules=to-top-dg)' : 'lost with shared-rules=skip - decide D3 (see impact table)' );
        foreach( $this->ruleImpact as $g )
            if( count($g['target_by_tags']) )
                $this->finding( 'warning', 'shared rules', implode(', ', $g['target_by_tags']), 'target by device tags', '', 'tags cannot be evaluated offline - counted as applying' );
        // default rules
        foreach( array( $A, $B ) as $i => $p )
        {
            $dr = self::child( $p->sharedroot, 'default-security-rules' );
            $this->stats['default_security_rules'][$i ? 'file2' : 'file1'] = $dr === null ? 'PAN-OS default' : trim(preg_replace('/\s+/', ' ', $dr->textContent));
        }
        $da = self::child( $A->sharedroot, 'default-security-rules' ); $db = self::child( $B->sharedroot, 'default-security-rules' );
        if( ( $da === null ) !== ( $db === null ) || ( $da !== null && self::canon($da) !== self::canon($db) ) )
            $this->finding( 'warning', 'default rules', 'shared default-security-rules', 'see report', 'differs', 'intrazone / interzone default rules behave differently after the move' );
        $this->stats['shared_rules'] = array( 'file1_pre' => count($rulesA['pre']), 'file1_post' => count($rulesA['post']), 'file2_pre' => count($rulesB['pre']), 'file2_post' => count($rulesB['post']) );
    }

    /**
     * rule name conflict: blocking (conflict=stop) or rename with the suffix (D4); $sameOldOk: two rules with the same old
     * name in different device group branches may get the same new name
     */
    private function ruleConflict( $cat, $key, $type, $name, $locA, $locB, &$taken, $sameOldOk )
    {
        if( $this->renameSuffix === null )
        {
            $this->finding( 'blocking', 'rule name', $type . ' ' . $name, $locA, $locB, 'rule names must be unique in the device group hierarchy - rename or use conflict=rename:<suffix>' );
            return;
        }
        $new = $name . $this->renameSuffix;
        $t = isset($taken[$type . '|' . $new]) ? $taken[$type . '|' . $new] : null;
        if( $t !== null && !( $sameOldOk && $t === 'renamed:' . $name ) )
        {
            $this->finding( 'blocking', 'rule name', $type . ' ' . $name, $locA, $locB, 'rename target "' . $new . '" exists already - choose another suffix' );
            return;
        }
        $taken[$type . '|' . $new] = 'renamed:' . $name;
        $this->renames[$cat][$key] = $new;
        $this->finding( 'warning', 'rule name', $type . ' ' . $name, $locA, $locB, 'renamed to "' . $new . '" in file2 (conflict=rename)' . ( strlen($new) > 63 ? ' - longer than 63 characters' : '' ) );
    }

    /** Panorama server elements below deviceconfig/system (PAN-OS 9.1+: panorama/local-panorama/..., before: directly) */
    public static function panoramaServerNodes( $root )
    {
        $x = new DOMXPath( $root->ownerDocument );
        return iterator_to_array( $x->query('.//deviceconfig/system//*[self::panorama-server or self::panorama-server-2]', $root) );
    }

    /**
     * D8: Panorama server settings in the transferred templates / stacks. Without panorama-ip they still point to Panorama A
     * (warning); with panorama-ip the copies in file2 get the Panorama B address - panorama-server-2 is removed when only one
     * address is given, template variables ($name) are not changed (warning, set the variable value in file2)
     */
    private function collectPanoramaSettings()
    {
        $tplA = self::templateEntries( $this->A ); $stA = self::stackEntries( $this->A );
        $roots = array();
        foreach( array_keys($this->templateAction) as $n ) if( isset($tplA[$n]) ) $roots[] = array( 'template', $n, $tplA[$n] );
        foreach( array_keys($this->stackAction) as $n ) $roots[] = array( 'template stack', $n, $stA[$n] );
        foreach( $roots as $r )
            foreach( self::panoramaServerNodes( $r[2] ) as $e )
            {
                $v = trim( $e->textContent );
                $f = $e->nodeName;
                if( substr($v, 0, 1) == '$' ) $action = 'variable';
                elseif( $this->panoramaIp === null ) $action = 'keep';
                elseif( $f == 'panorama-server' || isset($this->panoramaIp[1]) ) $action = 'replace';
                else $action = 'remove';
                $new = $action == 'replace' ? $this->panoramaIp[$f == 'panorama-server' ? 0 : 1] : null;
                $this->panoramaSettings[] = array( 'location' => $r[0] . ' ' . $r[1], 'name_in_file2' => $this->bName($r[0], $r[1]),
                    'path' => self::relPath( $e, $r[2] ), 'field' => $f, 'value' => $v, 'action' => $action, 'new' => $new );
                if( $action == 'keep' )
                    $this->finding( 'warning', $r[0], $r[1], $f . ' ' . $v, '', 'firewalls would connect to Panorama A after a push - set the Panorama B address with panorama-ip= (D8)' );
                elseif( $action == 'replace' )
                    $this->finding( 'info', $r[0], $r[1], $f . ' ' . $v, 'set to ' . $new . ' (panorama-ip)', '' );
                elseif( $action == 'remove' )
                    $this->finding( 'warning', $r[0], $r[1], $f . ' ' . $v, 'removed - panorama-ip has no second address', 'give panorama-ip=<server>,<server-2> to keep a secondary Panorama' );
                else
                    $this->finding( 'warning', $r[0], $r[1], $f . ' ' . $v, 'template variable - not changed', 'set the value of ' . $v . ' to the Panorama B address in file2' );
            }
        if( $this->panoramaIp !== null && !count($this->panoramaSettings) )
            $this->finding( 'info', 'panorama-ip', implode(', ', $this->panoramaIp), 'no Panorama server setting in the transferred templates / stacks', '', 'the firewalls keep their local setting - change it on each firewall (MIGRATION_FOLLOWUP.md)' );
    }

    /** panorama-ip on a template / stack copy in file2 */
    private function applyPanoramaIp( $node )
    {
        if( $this->panoramaIp === null )
            return;
        foreach( self::panoramaServerNodes( $node ) as $e )
        {
            if( substr(trim($e->textContent), 0, 1) == '$' )
                continue;
            if( $e->nodeName == 'panorama-server' )
                $e->nodeValue = $this->panoramaIp[0];
            elseif( isset($this->panoramaIp[1]) )
                $e->nodeValue = $this->panoramaIp[1];
            else
                $e->parentNode->removeChild( $e );
        }
    }

    /** access domains, log collector groups, plugins (7) */
    private function checkOtherReferences()
    {
        $x = new DOMXPath( $this->A->xmldoc );
        $names = array_merge( array_keys($this->dgAction), array_keys($this->templateAction), array_keys($this->stackAction) );
        foreach( $x->query('/config/mgt-config/access-domain/entry') as $ad )
        {
            $adn = $ad->getAttribute('name');
            foreach( $ad->getElementsByTagName('member') as $m )
                if( in_array(trim($m->textContent), $names, TRUE) )
                {
                    $this->accessDomains[$adn]['refs'][] = trim($m->textContent);
                    $this->finding( 'info', 'access domain', $adn, 'references ' . trim($m->textContent), 'not transferred', 'create the access domain / admin in file2 (MIGRATION_FOLLOWUP.md)' );
                }
            foreach( $ad->getElementsByTagName('entry') as $e )
                if( isset($this->devices[$e->getAttribute('name')]) )
                {
                    $this->accessDomains[$adn]['refs'][] = 'firewall ' . $e->getAttribute('name');
                    $this->finding( 'info', 'access domain', $adn, 'references firewall ' . $e->getAttribute('name'), 'not transferred', 'create the access domain / admin in file2 (MIGRATION_FOLLOWUP.md)' );
                }
        }
        // administrators using these access domains (by name - admins mapped by RADIUS / TACACS+ / SAML attributes are not in the configuration)
        foreach( array_keys($this->accessDomains) as $adn )
        {
            $this->accessDomains[$adn]['refs'] = array_values( array_unique($this->accessDomains[$adn]['refs']) );
            $this->accessDomains[$adn]['admins'] = array();
            foreach( $x->query('/config/mgt-config/users/entry') as $u )
                if( isset( self::tokens($u)[$adn] ) )
                    $this->accessDomains[$adn]['admins'][] = $u->getAttribute('name');
        }
        foreach( $x->query('/config/devices/entry/log-collector-group/entry') as $lcg )
            foreach( $lcg->getElementsByTagName('entry') as $e )
                if( isset($this->devices[$e->getAttribute('name')]) )
                {
                    $this->logCollectorGroups[$lcg->getAttribute('name')][$e->getAttribute('name')] = TRUE;
                    $this->finding( 'info', 'log collector group', $lcg->getAttribute('name'), 'device ' . $e->getAttribute('name'), 'not transferred', 'configure log collection in file2; existing logs stay with Panorama A' );
                }
        foreach( $this->logCollectorGroups as $g => $s )
            $this->logCollectorGroups[$g] = array_keys( $s );
        foreach( $x->query('/config/devices/entry/plugins/*') as $pl )
        {
            $t = self::tokens( $pl );
            foreach( $x->query('.//entry/@name', $pl) as $a ) $t[$a->value] = TRUE;
            foreach( $names as $n )
                if( isset($t[$n]) )
                {
                    $this->plugins[$pl->nodeName][] = $n;
                    $this->finding( 'warning', 'plugin', $pl->nodeName, 'references ' . $n, 'not transferred', 'check the plugin configuration' );
                }
            foreach( array_keys($this->devices) as $s )
                if( isset($t[$s]) )
                {
                    $this->plugins[$pl->nodeName][] = 'firewall ' . $s;
                    $this->finding( 'warning', 'plugin', $pl->nodeName, 'references device ' . $s, 'not transferred', 'check the plugin configuration' );
                }
        }
    }

    /**
     * the transfer into a fresh copy of file2, nothing written: returns the simulated file2 (reloaded) - used by the
     * effective rule base check of the check run, identical to what execute writes
     */
    private function simulateB()
    {
        $saveB = $this->B; $saveRewrites = $this->rewrites; $saveStats = $this->stats;
        $this->B = new PanoramaConf();
        $this->B->load_from_file( $this->file2 );
        $this->transfer();
        $xml = $this->B->xmldoc->saveXML();
        $this->B = $saveB; $this->rewrites = $saveRewrites; $this->stats = $saveStats;
        $sim = new PanoramaConf();
        $sim->load_from_xmlstring( $xml );
        return $sim;
    }

    /** key of a file1 rule (RuleResolver::firewallRulebase) in file2, null when the rule is not transferred */
    private function keyInB( $r, $dg )
    {
        $full = $r['rulebase'] == 'pre' ? 'pre-rulebase' : 'post-rulebase';
        if( $r['level'] != 'shared' && isset($this->dgAction[$r['level']]) )
        {
            $k = $r['level'] . '|' . $full . '|' . $r['type'] . '|' . $r['name'];
            $name = isset($this->renames['rule'][$k]) ? $this->renames['rule'][$k] : $r['name'];
            return $this->bName( 'device group', $r['level'] ) . '/' . $r['rulebase'] . '/' . $r['type'] . '/' . $name;
        }
        $k = $full . '|' . $r['type'] . '|' . $r['name'];
        if( $r['level'] == 'shared' && isset($this->sharedRulesToCopy[$k]) )
        {
            // copied into the top moved device group of this firewall's chain
            $top = $dg;
            while( $this->dgParentB[$top] !== $this->targetParent && isset($this->dgAction[$this->dgParentB[$top]]) )
                $top = $this->dgParentB[$top];
            $name = isset($this->renames['shared rule'][$k]) ? $this->renames['shared rule'][$k] : $r['name'];
            return $this->bName( 'device group', $top ) . '/' . $r['rulebase'] . '/' . $r['type'] . '/' . $name;
        }
        return null;
    }

    /**
     * effective rule base of every moved firewall: file1 (before) vs. the simulated file2 (after), rules resolved to their
     * values as the firewall sees them (RuleResolver). Transferred rules (device group chain, copied shared rules) must
     * stay the same - a difference means an object resolves to another value in file2 (e.g. an object of the target
     * parent overrides it). Shared rules not transferred: covered / differs / lost; file2 rules not matched: added.
     */
    private function verifyEffectiveRulebase()
    {
        $this->rulebaseCheck = array();
        if( !count($this->devices) )
            return;
        if( count($this->blocking()) )
        {
            $this->rulebaseCheckSkipped = 'blocking findings - the move cannot be simulated';
            return;
        }
        $sim = $this->simulateB();
        $views = array();
        $groups = array();
        foreach( $this->devices as $serial => $d )
        {
            $dg = $d['dg'];
            if( !isset($views[$dg]) )
            {
                $locA = $this->A->findDeviceGroup( $dg );
                $locB = $sim->findDeviceGroup( $this->bName('device group', $dg) );
                if( $locB === null )
                {
                    $this->rulebaseCheckSkipped = 'device group ' . $this->bName('device group', $dg) . ' not found in the simulated file2';
                    $this->rulebaseCheck = array();
                    return;
                }
                $views[$dg] = array( RuleResolver::resolveView( RuleResolver::firewallRulebase($this->A, $locA), $locA ),
                    RuleResolver::resolveView( RuleResolver::firewallRulebase($sim, $locB), $locB ) );
            }
            $va = array_values( array_filter( $views[$dg][0], function($r) use ($serial) { return self::applies($r['node'], $serial) !== FALSE; } ) );
            $vb = array_values( array_filter( $views[$dg][1], function($r) use ($serial) { return self::applies($r['node'], $serial) !== FALSE; } ) );
            $cmp = RuleResolver::compare( $va, $vb, function($r) use ($dg) { return $this->keyInB($r, $dg); } );
            // file1 rules without a counterpart (shared rules not transferred) against the unmatched file2 rules
            $byKey = array(); foreach( $vb as $r ) $byKey[$r['key']] = $r;
            $byKeyA = array(); foreach( $va as $r ) $byKeyA[$r['key']] = $r;
            $covered = array(); $differs = array(); $lost = array(); $usedB = array();
            foreach( $cmp['only_a'] as $ka )
            {
                $sa = $byKeyA[$ka]['signature'];
                $hit = null; $near = null;
                foreach( $cmp['only_b'] as $kb )
                {
                    if( $byKey[$kb]['signature'] === $sa ) { $hit = $kb; break; }
                    if( $near === null && $byKey[$kb]['signature'][0] === $sa[0] ) $near = $kb;
                }
                if( $hit !== null ) { $covered[$ka] = $hit; $usedB[$hit] = TRUE; }
                elseif( $near !== null ) { $differs[$ka] = array( $near, RuleResolver::diff($byKeyA[$ka]['resolved'], $byKey[$near]['resolved']) ); $usedB[$near] = TRUE; }
                else $lost[] = $ka;
            }
            $added = array_values( array_filter( $cmp['only_b'], function($k) use ($usedB) { return !isset($usedB[$k]); } ) );
            // order of the transferred rules per rule type (every type is evaluated on its own): positions in file2 must
            // keep the file1 order
            $posB = array_flip( array_keys($byKey) );
            $seq = array();
            foreach( $va as $r )
            {
                $kb = isset($cmp['same'][$r['key']]) ? $cmp['same'][$r['key']] : ( isset($cmp['changed'][$r['key']]) ? $cmp['changed'][$r['key']][0] : null );
                if( $kb !== null ) $seq[$r['type']][] = $posB[$kb];
            }
            $orderOk = TRUE;
            foreach( $seq as $s )
                for( $i = 1; $i < count($s); $i++ ) if( $s[$i] < $s[$i-1] ) $orderOk = FALSE;
            $res = array( 'device_group' => $dg, 'device_group_in_file2' => $this->bName('device group', $dg),
                'rules_before' => count($va), 'rules_after' => count($vb),
                'transferred_same' => count($cmp['same']), 'transferred_changed' => $cmp['changed'],
                'covered' => $covered, 'differs' => $differs, 'lost' => $lost, 'added' => $added, 'order_kept' => $orderOk );
            $key = md5( json_encode($res) );
            if( !isset($groups[$key]) )
                $groups[$key] = $res + array( 'firewalls' => array() );
            $groups[$key]['firewalls'][] = $serial;
        }
        $this->rulebaseCheck = array_values( $groups );
        foreach( $this->rulebaseCheck as $g )
        {
            $fw = count($g['firewalls']) . ' firewall(s) of ' . $g['device_group'];
            foreach( $g['transferred_changed'] as $ka => $c )
                $this->finding( 'warning', 'effective rule base', $ka, $fw, 'resolves differently in file2: ' . implode(', ', array_keys($c[1])),
                    'an object resolves to another value after the move (e.g. overridden in the target parent device group) - see REPORT.md' );
            if( !$g['order_kept'] )
                $this->finding( 'warning', 'effective rule base', 'rule order', $fw, 'order of the transferred rules changed', 'check the rule order in file2' );
        }
    }

    /**
     * objects referenced by the relevant device groups that resolve neither in their device group hierarchy nor in
     * shared of file1 nor as predefined name (concept 4a / 11.2), and the content they need (concept 4 / 11.1)
     */
    private function checkUnresolved()
    {
        // address / service: pan-os-php object model (tmp objects)
        foreach( array_keys($this->dgAction) as $n )
        {
            $dg = $this->A->findDeviceGroup( $n );
            foreach( $dg->addressStore->all() as $o )
                if( $o->isTmpAddr() && !preg_match('/^[0-9a-f.:\/-]+$/i', $o->name()) )
                    $this->finding( 'warning', 'unresolved', 'address ' . $o->name(), 'device group ' . $n, '', 'object is referenced but not defined' );
            foreach( $dg->serviceStore->all() as $o )
                if( $o->isTmpSrv() )
                    $this->finding( 'warning', 'unresolved', 'service ' . $o->name(), 'device group ' . $n, '', 'object is referenced but not defined' );
        }

        // other named references: XML of file1 as stored - loading with pan-os-php creates missing tags in the DOM
        $raw = self::rawDocument( $this->file1 );
        $used = array();
        $list = self::unresolvedRefs( $raw, $this->A, array_keys($this->dgAction), $used );
        $appVersion = self::predefined('version');
        foreach( $list as $u )
        {
            if( $u['kind'] == 'application' )
            {
                $this->content['unknown_applications'][$u['name']] = TRUE;
                $this->finding( 'warning', 'content', 'application ' . $u['name'], 'device group ' . $u['dg'] . ', ' . $u['where'], '',
                    'neither a custom application / group / filter nor a predefined application of pan-os-php (content ' . $appVersion . '): typo, or newer content - Panorama B needs a content version that knows it' );
            }
            elseif( $u['kind'] == 'threat' )
            {
                $this->content['unknown_threat_ids'][$u['name']] = TRUE;
                $this->finding( 'warning', 'content', 'threat ID ' . $u['name'], 'device group ' . $u['dg'] . ', ' . $u['where'], '',
                    'neither a custom threat signature nor a predefined threat of pan-os-php: newer content - Panorama B needs a content version that knows it' );
            }
            else
                $this->finding( 'warning', 'unresolved', $u['kind'] . ' ' . $u['name'], 'device group ' . $u['dg'] . ', ' . $u['where'], '', 'object is referenced but not defined' );
        }
        // array keys: numeric names (threat IDs) become integers - keep strings
        $this->content['applications'] = isset($used['application']) ? array_map( 'strval', array_keys($used['application']) ) : array();
        $this->content['threat_ids'] = isset($used['threat']) ? array_map( 'strval', array_keys($used['threat']) ) : array();
        sort( $this->content['applications'] ); sort( $this->content['threat_ids'], SORT_NATURAL );
        $this->content['unknown_applications'] = array_map( 'strval', array_keys( $this->content['unknown_applications'] ) );
        $this->content['unknown_threat_ids'] = array_map( 'strval', array_keys( $this->content['unknown_threat_ids'] ) );
        $this->stats['content'] = array( 'pan_os_php_application_version' => $appVersion,
            'predefined_applications' => count($this->content['applications']), 'threat_ids' => count($this->content['threat_ids']),
            'unknown_applications' => count($this->content['unknown_applications']), 'unknown_threat_ids' => count($this->content['unknown_threat_ids']) );
        if( count($this->content['applications']) || count($this->content['threat_ids']) )
            $this->finding( 'info', 'content', count($this->content['applications']) . ' predefined application(s), ' . count($this->content['threat_ids']) . ' threat ID(s)',
                'used by the transferred configuration', 'content version of file2 is not part of the configuration',
                'Panorama B needs the same or a newer App-ID / threat content version than Panorama A (list in plan.json)' );
    }

    /** XML file as stored, without pan-os-php (no implicit objects) */
    public static function rawDocument( $file )
    {
        $d = new DOMDocument();
        if( !@$d->load( $file, XML_PARSE_BIG_LINES ) )
            derr( "cannot load '" . $file . "'", null, FALSE );
        return $d;
    }

    /**
     * predefined names of pan-os-php: 'application' (incl. application containers), 'threat' (IDs), 'category' (URL),
     * 'profiles/<type>' (security profiles), 'version' (App-ID content version of predefined.xml)
     */
    public static function predefined( $kind )
    {
        if( self::$predefined === null )
        {
            $p = array( 'application' => array(), 'threat' => array(), 'category' => array(), 'version' => '' );
            $add = function( $k ) use ( &$p ) { return function( $name ) use ( &$p, $k ) { $p[$k][$name] = TRUE; }; };
            PH::eachPredefinedEntry( array( 'application' ), $add('application'), FALSE );
            PH::eachPredefinedEntry( array( 'application-container' ), $add('application'), FALSE );
            foreach( array( 'phone-home', 'vulnerability', 'scan', 'test-spyware', 'test-vuln' ) as $t )
                PH::eachPredefinedEntry( array( 'threats', $t ), $add('threat'), FALSE );
            $x = new DOMXPath( PH::getPredefinedXmlDoc( null, array( 'profiles' ) ) );
            foreach( $x->query('/predefined/pan-url-categories/entry/@name') as $a )
                $p['category'][$a->value] = TRUE;
            foreach( $x->query('/predefined/profiles/*/entry/@name') as $a )
                $p['profiles/' . $a->ownerElement->parentNode->nodeName][$a->value] = TRUE;
            $v = new DOMXPath( PH::getPredefinedXmlDoc( null, array( 'application-version' ) ) );
            $vn = $v->query('/predefined/application-version');
            $p['version'] = $vn->length ? trim($vn->item(0)->textContent) : '';
            self::$predefined = $p;
        }
        if( $kind == 'version' )
            return self::$predefined['version'];
        return isset(self::$predefined[$kind]) ? self::$predefined[$kind] : array();
    }

    /** where named entries of a reference kind are defined below a device group entry / shared */
    const DEFINED_IN = array(
        'tag' => array( 'tag' ),
        'schedule' => array( 'schedule' ),
        'profile-group' => array( 'profile-group' ),
        'log forwarding profile' => array( 'log-settings/profiles' ),
        'application' => array( 'application', 'application-group', 'application-filter' ),
        'category' => array( 'profiles/custom-url-category', 'external-list' ),
        'threat' => array( 'threats/vulnerability', 'threats/spyware' ),
    );

    /** security profile types of profile-setting / profile-group */
    const PROFILE_TYPES = array( 'virus', 'spyware', 'vulnerability', 'url-filtering', 'file-blocking', 'wildfire-analysis', 'data-filtering' );

    /** entry named $name of a reference kind in $container, or null */
    private static function definedEntry( $container, $kind, $name )
    {
        $paths = strpos($kind, 'profiles/') === 0 ? array( $kind ) : self::DEFINED_IN[$kind];
        foreach( $paths as $path )
        {
            $n = $container;
            foreach( explode('/', $path) as $c )
                $n = self::child( $n, $c );
            if( $n === null )
                continue;
            $e = self::entries( $n );
            if( isset($e[$name]) )
                return $e[$name];
        }
        return null;
    }

    /** text values of the member children of $node / of a single element */
    private static function members( $node )
    {
        $out = array();
        if( $node === null )
            return $out;
        $has = FALSE;
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->nodeName == 'member' )
            {
                $has = TRUE;
                if( trim($c->textContent) !== '' ) $out[] = trim($c->textContent);
            }
        if( !$has && trim($node->textContent) !== '' && DH::firstChildElement($node) === FALSE )
            $out[] = trim($node->textContent);
        return $out;
    }

    /** named references of one rule: list of array( kind, name ) */
    private static function ruleRefs( DOMElement $rule )
    {
        $out = array();
        $map = array( 'tag' => 'tag', 'group-tag' => 'tag', 'schedule' => 'schedule', 'log-setting' => 'log forwarding profile',
            'application' => 'application', 'category' => 'category' );
        foreach( $map as $el => $kind )
            foreach( self::members( self::child($rule, $el) ) as $v )
                $out[] = array( $kind, $v );
        $ps = self::child( $rule, 'profile-setting' );
        foreach( self::members( self::child($ps, 'group') ) as $v )
            $out[] = array( 'profile-group', $v );
        $profiles = self::child( $ps, 'profiles' );
        foreach( self::PROFILE_TYPES as $t )
            foreach( self::members( self::child($profiles, $t) ) as $v )
                $out[] = array( 'profiles/' . $t, $v );
        return $out;
    }

    /**
     * named references of the rules of the device groups $dgNames in $doc (XML as stored) that resolve neither in the
     * device group hierarchy (from $model) nor in shared nor as predefined name; follows application groups, profile
     * groups and the threat exceptions of vulnerability / anti-spyware profiles.
     * $used collects the predefined applications and threat IDs: kind => [name => TRUE].
     * @return array list of array( kind, name, dg, where )
     */
    public static function unresolvedRefs( DOMDocument $doc, PanoramaConf $model, array $dgNames, &$used = array() )
    {
        $x = new DOMXPath( $doc );
        $sh = $x->query('/config/shared');
        $shared = $sh->length ? $sh->item(0) : null;
        $dgXml = array();
        foreach( $x->query("/config/devices/entry[@name='localhost.localdomain']/device-group/entry") as $e )
            $dgXml[$e->getAttribute('name')] = $e;

        $out = array(); $seen = array();
        foreach( $dgNames as $n )
        {
            if( !isset($dgXml[$n]) )
                continue;
            // hierarchy: device group, parents, shared
            $chain = array( $dgXml[$n] );
            $dg = $model->findDeviceGroup( $n );
            for( $par = $dg !== null ? $dg->parentDeviceGroup : null; $par !== null; $par = $par->parentDeviceGroup )
                if( isset($dgXml[$par->name()]) ) $chain[] = $dgXml[$par->name()];
            if( $shared !== null ) $chain[] = $shared;

            $todo = array();
            foreach( array( 'pre-rulebase', 'post-rulebase' ) as $rb )
                foreach( self::childElements( self::child($dgXml[$n], $rb) ) as $type )
                    foreach( self::entries( self::child($type, 'rules') ) as $rn => $r )
                        foreach( self::ruleRefs($r) as $ref )
                            $todo[] = array( $ref[0], $ref[1], $rb . ' ' . $type->nodeName . ' rule "' . $rn . '"' );

            $done = array();
            while( count($todo) )
            {
                list( $kind, $name, $where ) = array_shift( $todo );
                if( $name === 'any' || $name === 'none' || isset($done[$kind . '|' . $name]) )
                    continue;
                $done[$kind . '|' . $name] = TRUE;
                $entry = null;
                foreach( $chain as $c )
                    if( ( $entry = self::definedEntry($c, $kind, $name) ) !== null )
                        break;
                if( $entry !== null )
                {
                    // follow groups and threat exceptions
                    if( $entry->parentNode->nodeName == 'application-group' )
                        foreach( self::members( self::child($entry, 'members') ) as $m )
                            $todo[] = array( 'application', $m, 'application group "' . $name . '"' );
                    elseif( $kind == 'profile-group' )
                        foreach( self::PROFILE_TYPES as $t )
                            foreach( self::members( self::child($entry, $t) ) as $m )
                                $todo[] = array( 'profiles/' . $t, $m, 'profile group "' . $name . '"' );
                    elseif( $kind == 'profiles/vulnerability' || $kind == 'profiles/spyware' )
                        foreach( self::entries( self::child($entry, 'threat-exception') ) as $id => $te )
                            $todo[] = array( 'threat', $id, 'threat exception of ' . substr($kind, 9) . ' profile "' . $name . '"' );
                    continue;
                }
                $pre = self::predefined( $kind );
                if( isset($pre[$name]) )
                {
                    if( $kind == 'application' || $kind == 'threat' )
                        $used[$kind][$name] = TRUE;
                    continue;
                }
                if( count($pre) == 0 && ( $kind == 'category' || $kind == 'application' || $kind == 'threat' ) )
                    continue; // predefined list not available - no statement possible
                $key = $n . '|' . $kind . '|' . $name;
                if( isset($seen[$key]) )
                    continue;
                $seen[$key] = TRUE;
                $out[] = array( 'kind' => strpos($kind, 'profiles/') === 0 ? substr($kind, 9) . ' profile' : $kind, 'name' => $name, 'dg' => $n, 'where' => $where );
            }
        }
        return $out;
    }

    private static function childElements( $node )
    {
        $out = array();
        if( $node === null )
            return $out;
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                $out[] = $c;
        return $out;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // execute (concept 5 / 6)

    public function execute( $out1, $out2 )
    {
        $this->transfer();
        $this->cleanupA();
        $this->B->save_to_file( $out2 );
        $this->A->save_to_file( $out1 );
        return $this->validate( $out1, $out2 );
    }

    private function importInto( DOMElement $parent, DOMElement $node, $before = null )
    {
        $n = $parent->ownerDocument->importNode( $node, TRUE );
        if( $before !== null )
            $parent->insertBefore( $n, $before );
        else
            $parent->appendChild( $n );
        return $n;
    }

    /** keep only the device entries of moved firewalls */
    private function filterDevices( DOMElement $entry )
    {
        $dc = self::child( $entry, 'devices' );
        if( $dc === null )
            return;
        foreach( self::entries($dc) as $s => $e )
            if( !isset($this->devices[$s]) )
                $dc->removeChild( $e );
    }

    private function transfer()
    {
        $A = $this->A; $B = $this->B;
        $log = array();
        // 1 shared objects
        $sharedB = $B->sharedroot;
        $strip = $this->masterKey == 'different';
        $removed = 0;
        $this->rewrites = array();
        foreach( $this->sharedObjects as $o )
            if( $o['action'] == 'copy' )
            {
                $n = $this->importInto( self::ensurePath($sharedB, $o['path']), $o['node'] );
                if( isset($o['rename']) ) $n->setAttribute( 'name', $o['rename'] );
                $this->rewriteRefs( $n, 'shared ' . $o['path'] . ' ' . $o['name'] );
                if( $strip ) $removed += self::stripSecrets( $n );
            }
        // 1b shared setting blocks missing in file2
        if( $this->sharedSettings == 'copy-missing' )
            foreach( $this->settings as $p => $st )
                if( $st['status'] == 'missing' )
                {
                    $parts = explode( '/', $p );
                    array_pop( $parts );
                    $n = $this->importInto( count($parts) ? self::ensurePath($sharedB, implode('/', $parts)) : $sharedB, $st['node'] );
                    $this->rewriteRefs( $n, 'shared ' . $p );
                    if( $strip ) $removed += self::stripSecrets( $n );
                }
        // 2 managed devices
        $mgtA = self::mgtDevices( $A );
        $mgtB = DH::findXPathSingleEntryOrCreate( '/config/mgt-config/devices', $B->xmlroot );
        foreach( $this->devices as $s => $d )
            if( isset($mgtA[$s]) )
            {
                $n = $this->importInto( $mgtB, $mgtA[$s] );
                if( $strip ) $removed += self::stripSecrets( $n );
            }
        // readonly containers needed by createDeviceGroup / createTemplate / createTemplateStack
        if( $B->version >= 80 )
        {
            DH::findXPathSingleEntryOrCreate( '/config/readonly/max-internal-id', $B->xmlroot );
            foreach( array( 'device-group', 'template', 'template-stack' ) as $t )
                self::ensurePath( DH::findXPathSingleEntryOrCreate('/config/readonly/devices', $B->xmlroot), 'entry' )->setAttribute('name', 'localhost.localdomain');
            $ro = DH::findXPathSingleEntry('/config/readonly/devices/entry[@name="localhost.localdomain"]', $B->xmlroot);
            foreach( array( 'device-group', 'template', 'template-stack' ) as $t )
                self::ensurePath( $ro, $t );
            $mi = DH::findXPathSingleEntry('/config/readonly/max-internal-id', $B->xmlroot);
            if( trim($mi->textContent) === '' )
                DH::setDomNodeText( $mi, '0' );
        }
        foreach( array( 'device-group', 'template', 'template-stack' ) as $t )
            self::ensurePath( $B->localhostroot, $t );
        $B->devicegrouproot = self::child( $B->localhostroot, 'device-group' );
        $B->templateroot = self::child( $B->localhostroot, 'template' );
        $B->templatestackroot = self::child( $B->localhostroot, 'template-stack' );

        // 3 device groups top-down
        $dgA = self::dgEntries( $A );
        $order = array();
        $add = function( $n ) use ( &$add, &$order ) {
            if( isset($order[$n]) ) return;
            $p = $this->dgParentB[$n];
            if( $p !== null && isset($this->dgAction[$p]) ) $add( $p );
            $order[$n] = TRUE;
        };
        foreach( array_keys($this->dgAction) as $n )
            $add( $n );
        // container renames used in reference-templates / template stack members
        $tplMap = $this->renames['template'] + $this->renames['template stack'];
        foreach( array_keys($order) as $n )
        {
            $bn = $this->bName( 'device group', $n );
            $p = $this->dgParentB[$n];
            $B->createDeviceGroup( $bn, ( $p !== null && isset($this->dgAction[$p]) ) ? $this->bName('device group', $p) : $p );
            $created = self::dgEntries( $B )[$bn];
            $new = $B->xmldoc->importNode( $dgA[$n], TRUE );
            $new->setAttribute( 'name', $bn );
            if( $this->dgAction[$n] == 'copy' )
            {
                $dc = self::child( $new, 'devices' );
                if( $dc !== null ) $new->removeChild( $dc );
            }
            self::renameMembers( $new, 'reference-templates', $tplMap );
            $ruleMap = array();
            foreach( $this->renames['rule'] as $k => $nn )
                if( strpos($k, $n . '|') === 0 )
                    $ruleMap[substr($k, strlen($n) + 1)] = $nn;
            self::renameRules( $new, $ruleMap );
            $this->rewriteRefs( $new, 'device group ' . $n, isset($this->renameExclude[$n]) ? $this->renameExclude[$n] : array() );
            if( $strip ) $removed += self::stripSecrets( $new );
            $created->parentNode->replaceChild( $new, $created );
        }
        // 4 templates, 5 template stacks
        $tplA = self::templateEntries( $A );
        foreach( array_keys($this->templateAction) as $n )
        {
            if( !isset($tplA[$n]) ) continue;
            $bn = $this->bName( 'template', $n );
            $B->createTemplate( $bn );
            $created = self::templateEntries( $B )[$bn];
            $new = $B->xmldoc->importNode( $tplA[$n], TRUE );
            $new->setAttribute( 'name', $bn );
            $this->filterDevices( $new );
            $this->applyPanoramaIp( $new );
            if( $strip ) $removed += self::stripSecrets( $new );
            $created->parentNode->replaceChild( $new, $created );
        }
        $stA = self::stackEntries( $A );
        foreach( array_keys($this->stackAction) as $n )
        {
            $bn = $this->bName( 'template stack', $n );
            $B->createTemplateStack( $bn );
            $created = self::stackEntries( $B )[$bn];
            $new = $B->xmldoc->importNode( $stA[$n], TRUE );
            $new->setAttribute( 'name', $bn );
            self::renameMembers( $new, 'templates', $this->renames['template'] );
            $this->filterDevices( $new );
            $this->applyPanoramaIp( $new );
            if( $strip ) $removed += self::stripSecrets( $new );
            $created->parentNode->replaceChild( $new, $created );
        }
        // 10 shared rules of file1 into the top device groups
        if( $this->sharedRules == 'to-top-dg' )
        {
            $dgB = self::dgEntries( $B );
            foreach( $this->dgAction as $n => $act )
            {
                if( $this->dgParentB[$n] !== $this->targetParent )
                    continue;
                foreach( array( 'pre-rulebase', 'post-rulebase' ) as $w )
                    foreach( ( $w == 'pre-rulebase' ? array_reverse( self::rules( $A->sharedroot, $w ) ) : self::rules( $A->sharedroot, $w ) ) as $r )
                    {
                        if( !isset($this->sharedRulesToCopy[$w . '|' . $r['type'] . '|' . $r['name']]) )
                            continue;
                        $rulesNode = self::ensurePath( $dgB[$this->bName('device group', $n)], $w . '/' . $r['type'] . '/rules' );
                        if( $w == 'pre-rulebase' )
                            $nr = $this->importInto( $rulesNode, $r['node'], $rulesNode->firstChild );
                        else
                            $nr = $rulesNode->insertBefore( $B->xmldoc->importNode($r['node'], TRUE), null );
                        $rk = $w . '|' . $r['type'] . '|' . $r['name'];
                        if( isset($this->renames['shared rule'][$rk]) )
                            $nr->setAttribute( 'name', $this->renames['shared rule'][$rk] );
                        $this->rewriteRefs( $nr, 'shared ' . $w . ' ' . $r['type'] . ' ' . $r['name'] );
                        if( $strip ) $removed += self::stripSecrets( $nr );
                    }
            }
        }
        $this->stats['encrypted_values_removed'] = $removed;
    }

    private function cleanupA()
    {
        $A = $this->A;
        // 1 moved device groups bottom-up
        $depth = function( $n ) use ( $A ) { return count( $A->findDeviceGroup($n)->parentDeviceGroups() ); };
        $moved = array_keys( array_filter( $this->dgAction, function( $a ) { return $a == 'move'; } ) );
        usort( $moved, function( $a, $b ) use ( $depth ) { return $depth($b) - $depth($a); } );
        foreach( $moved as $n )
            $A->removeDeviceGroup( $A->findDeviceGroup($n) );
        // 2 devices
        $mgt = DH::findXPathSingleEntry( '/config/mgt-config/devices', $A->xmlroot );
        foreach( array_keys($this->devices) as $s )
        {
            if( $mgt !== FALSE && ( $e = DH::findFirstElementByNameAttr('entry', $s, $mgt) ) !== null )
                $mgt->removeChild( $e );
        }
        $x = new DOMXPath( $A->xmldoc );
        foreach( iterator_to_array( $x->query('/config/devices/entry/template/entry/devices/entry | /config/devices/entry/template-stack/entry/devices/entry | /config/devices/entry/device-group/entry/devices/entry') ) as $e )
            if( isset($this->devices[$e->getAttribute('name')]) )
                $e->parentNode->removeChild( $e );
        foreach( iterator_to_array( $x->query('/config/devices/entry/log-collector-group/entry//devices/entry') ) as $e )
            if( isset($this->devices[$e->getAttribute('name')]) )
                $e->parentNode->removeChild( $e );
        // 3 template stacks / templates
        $removedNames = $moved;
        foreach( $this->stackAction as $n => $a )
            if( $a == 'move' && ( $o = $A->findTemplateStack($n) ) !== null ) { $A->removeTemplateStack( $o ); $removedNames[] = $n; }
        foreach( $this->templateAction as $n => $a )
            if( $a == 'move' && ( $o = $A->findTemplate($n) ) !== null ) { $A->removeTemplate( $o ); $removedNames[] = $n; }
        foreach( iterator_to_array( $x->query('/config/mgt-config/access-domain/entry//member') ) as $m )
            if( in_array(trim($m->textContent), $removedNames, TRUE) )
                $m->parentNode->removeChild( $m );
        // moved firewalls in access domains (context switch)
        foreach( iterator_to_array( $x->query('/config/mgt-config/access-domain/entry//entry[@name]') ) as $e )
            if( isset($this->devices[$e->getAttribute('name')]) )
                $e->parentNode->removeChild( $e );
        // 4 shared objects of the relevant set that are no longer referenced (fixed point)
        $cand = array();
        foreach( $this->sharedObjects as $k => $o )
            $cand[$k] = $o;
        $saved = array();
        foreach( $cand as $k => $o )
        {
            $saved[$k] = array( $o['node']->parentNode, $o['node']->nextSibling );
            $o['node']->parentNode->removeChild( $o['node'] );
        }
        $tokens = self::tokens( $A->xmlroot );
        $keep = array();
        $changed = TRUE;
        while( $changed )
        {
            $changed = FALSE;
            foreach( $cand as $k => $o )
                if( !isset($keep[$k]) && isset($tokens[$o['name']]) )
                {
                    $keep[$k] = TRUE;
                    self::tokens( $o['node'], $tokens );
                    $changed = TRUE;
                }
        }
        $this->stats['file1_removed_shared'] = array();
        foreach( $cand as $k => $o )
        {
            if( isset($keep[$k]) )
                $saved[$k][0]->insertBefore( $o['node'], $saved[$k][1] && $saved[$k][1]->parentNode === $saved[$k][0] ? $saved[$k][1] : null );
            else
                $this->stats['file1_removed_shared'][] = $o['path'] . ' ' . $o['name'];
        }
    }

    /** reload both outputs with pan-os-php and count unresolved references */
    private function validate( $out1, $out2 )
    {
        $res = array();
        foreach( array( 'file1' => $out1, 'file2' => $out2 ) as $k => $f )
        {
            $p = new PanoramaConf();
            $p->load_from_file( $f );
            $tmp = 0; $list = array();
            foreach( $p->getDeviceGroups() as $dg )
            {
                foreach( $dg->addressStore->all() as $o )
                    if( $o->isTmpAddr() && !preg_match('/^[0-9a-f.:\/-]+$/i', $o->name()) ) { $tmp++; $list[] = $dg->name() . ': address ' . $o->name(); }
                foreach( $dg->serviceStore->all() as $o )
                    if( $o->isTmpSrv() ) { $tmp++; $list[] = $dg->name() . ': service ' . $o->name(); }
            }
            // other named references (tags, schedules, profiles, profile groups, log forwarding, applications, URL categories, threat IDs)
            $dgNames = array();
            foreach( $p->getDeviceGroups() as $dg ) $dgNames[] = $dg->name();
            foreach( self::unresolvedRefs( self::rawDocument($f), $p, $dgNames ) as $u )
            {
                $tmp++;
                $list[] = $u['dg'] . ': ' . $u['kind'] . ' ' . $u['name'];
            }
            $res[$k] = array( 'file' => $f, 'device_groups' => count($p->getDeviceGroups()), 'templates' => count($p->getTemplates()),
                'template_stacks' => count($p->getTemplatesStacks()), 'unresolved' => $tmp, 'unresolved_list' => array_slice($list, 0, 50) );
        }
        $this->stats['validation'] = $res;
        return $res;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // report

    public function plan()
    {
        $shared = array();
        foreach( $this->sharedObjects as $o )
            $shared[] = array( 'path' => $o['path'], 'name' => $o['name'], 'action' => $o['action'] ) + ( isset($o['rename']) ? array( 'name_in_file2' => $o['rename'] ) : array() );
        $dgs = array();
        foreach( $this->dgAction as $n => $a )
            $dgs[] = array( 'name' => $n, 'name_in_file2' => $this->bName('device group', $n), 'action' => $a,
                'parent_in_file2' => ( $this->dgParentB[$n] !== null && isset($this->dgAction[$this->dgParentB[$n]]) ) ? $this->bName('device group', $this->dgParentB[$n]) : $this->dgParentB[$n],
                'reason' => $this->dgReason[$n] );
        $tpl = array(); $st = array();
        foreach( $this->templateAction as $n => $a ) $tpl[] = array( 'name' => $n, 'action' => $a, 'reason' => $this->templateReason[$n], 'name_in_file2' => $this->bName('template', $n) );
        foreach( $this->stackAction as $n => $a ) $st[] = array( 'name' => $n, 'action' => $a, 'reason' => $this->stackReason[$n], 'name_in_file2' => $this->bName('template stack', $n) );
        $dev = array();
        foreach( $this->devices as $s => $d ) $dev[] = array( 'serial' => $s, 'device_group' => $d['dg'], 'vsys' => $d['vsys'] );
        return array( 'schema' => 'pan-os-php-panorama-move-plan', 'version' => 1, 'created_at' => date('c'),
            'file1' => $this->file1, 'file2' => $this->file2, 'selected' => $this->selected, 'target_parent_dg' => $this->targetParent,
            'shared_rules' => $this->sharedRules, 'blocking' => count($this->blocking()),
            'device_groups' => $dgs, 'devices' => $dev, 'template_stacks' => $st, 'templates' => $tpl, 'shared_objects' => $shared,
            'shared_settings' => array_map( function( $p, $st ) { return array( 'path' => $p, 'status' => $st['status'] ); }, array_keys($this->settings), array_values($this->settings) ),
            'master_key' => $this->masterKey, 'encrypted_values' => $this->secrets,
            'conflict' => $this->renameSuffix === null ? 'stop' : 'rename:' . $this->renameSuffix,
            'renames' => array( 'device_groups' => $this->renames['device group'], 'templates' => $this->renames['template'],
                'template_stacks' => $this->renames['template stack'], 'rules' => $this->renames['rule'], 'shared_rules' => $this->renames['shared rule'],
                'shared_objects' => $this->objectRenames, 'not_rewritten_in_device_group' => array_map( 'array_keys', $this->renameExclude ) ),
            'rewritten_references' => $this->rewrites,
            'panorama_ip' => $this->panoramaIp, 'panorama_settings' => $this->panoramaSettings,
            'access_domains' => $this->accessDomains, 'log_collector_groups' => $this->logCollectorGroups, 'plugins' => $this->plugins,
            'master_devices_not_moved' => $this->masterDevices,
            'content' => $this->content,
            'effective_rulebase' => $this->rulebaseCheckSkipped !== null ? array( 'skipped' => $this->rulebaseCheckSkipped ) : $this->rulebaseCheck,
            'shared_rule_impact' => $this->ruleImpact, 'findings' => $this->findings, 'stats' => $this->stats );
    }

    /** checklist of the encrypted values to set in file2 (no values) */
    public function secretsChecklist()
    {
        $o = "# Encrypted values to set in Panorama B\n\n";
        $o .= "Generated " . date('Y-m-d H:i') . " – master-key=" . $this->masterKey . ". " . ( $this->masterKey == 'different'
            ? "These fields were removed on transfer because Panorama B uses another master key. Set each value in Panorama B (CLI / web interface) before the first commit."
            : "These fields were copied unchanged. They are valid only if Panorama B uses the same master key as Panorama A; if not, re-run with master-key=different or set them again." ) . "\n\n";
        $by = array();
        foreach( $this->secrets as $x ) $by[$x['location']][] = $x;
        foreach( $by as $loc => $list )
        {
            $o .= "## " . $loc . "\n\n";
            foreach( $list as $x ) $o .= "- [ ] `" . $x['path'] . "`\n";
            $o .= "\n";
        }
        return $o;
    }

    /**
     * MIGRATION_FOLLOWUP.md: everything panorama-move does not transfer or cannot do offline, as a checklist in the order
     * of the migration (before the import, Panorama B, per firewall, Panorama A afterwards)
     */
    public function followupMarkdown( $mode, $out1 = 'out1', $out2 = 'out2' )
    {
        $sev = array( 'blocking' => 0, 'warning' => 0, 'info' => 0 );
        foreach( $this->findings as $f ) $sev[$f['severity']]++;
        $dgB = function( $n ) { return $this->bName( 'device group', $n ); };
        $li = function( $text, $done = FALSE ) { return "- [" . ( $done ? 'x' : ' ' ) . "] " . $text . "\n"; };
        $code = function( $s ) { return '`' . str_replace('`', "'", $s) . '`'; };
        $o = "# Migration follow-up – Panorama A → Panorama B\n\n";
        $o .= "Generated " . date('Y-m-d H:i') . " by pan-os-php type=panorama-move (" . ( $mode == 'execute' ? 'execute' : 'check run' ) . ") – file1 " . $code($this->file1) . ", file2 " . $code($this->file2) . ".\n";
        $o .= "Moved firewalls: " . count($this->devices) . ", device groups move / copy: " . count(array_filter($this->dgAction, function($a){ return $a == 'move'; })) . " / " . count(array_filter($this->dgAction, function($a){ return $a == 'copy'; })) . ". ";
        $o .= "Items marked [x] were done by panorama-move; tick off the others.\n\n";

        // 1
        $o .= "## 1. Before loading the configuration into Panorama B\n\n";
        $o .= $li( "Save a named configuration snapshot on Panorama A and on Panorama B" );
        if( $mode != 'execute' || $sev['blocking'] )
            $o .= $li( "Resolve the findings in REPORT.md: " . $sev['blocking'] . " blocking, " . $sev['warning'] . " warning(s)" . ( $mode != 'execute' ? " – then run with mode=execute" : '' ) );
        if( count($this->secrets) )
            $o .= $this->masterKey == 'same'
                ? $li( "Master key: confirm Panorama B uses the same master key as Panorama A – " . count($this->secrets) . " encrypted value(s) are copied unchanged (SECRETS_CHECKLIST.md lists them)" )
                : $li( "Master key differs: set the " . count($this->secrets) . " encrypted value(s) listed in SECRETS_CHECKLIST.md in Panorama B before the first push" );
        if( $this->renameCount() )
        {
            $o .= $li( "Names in Panorama B differ from Panorama A (conflict=rename:" . $this->renameSuffix . ", " . $this->renameCount() . " renamed) – update documentation, scripts / API calls, SIEM and monitoring that use the old names (list: REPORT.md, section Renames)" );
            if( count($this->rewrites) )
                $o .= $li( "Review the " . count($this->rewrites) . " rewritten reference(s) in REPORT.md (references are found by text value)" );
        }
        if( count($this->content['applications']) || count($this->content['threat_ids']) || count($this->content['unknown_applications']) || count($this->content['unknown_threat_ids']) )
            $o .= $li( "Content: Panorama B needs the same or a newer App-ID / threat content version than Panorama A – the transferred configuration uses "
                . count($this->content['applications']) . " predefined application(s) and " . count($this->content['threat_ids']) . " threat ID(s) (plan.json, content)"
                . ( count($this->content['unknown_applications']) + count($this->content['unknown_threat_ids'])
                    ? "; unknown to pan-os-php: " . implode(', ', array_merge( $this->content['unknown_applications'], $this->content['unknown_threat_ids'] ))
                    : '' ) );
        foreach( $this->rulebaseCheck as $g )
        {
            if( count($g['transferred_changed']) )
                $o .= $li( "**" . count($g['transferred_changed']) . " transferred rule(s) resolve differently** for the firewalls of " . $code($g['device_group_in_file2']) . " after the move – an object has another value in Panorama B (REPORT.md, effective rule base)" );
            if( !$g['order_kept'] )
                $o .= $li( "Rule order of the transferred rules changed for " . $code($g['device_group_in_file2']) . " – check (REPORT.md, effective rule base)" );
        }
        $lost = array();
        foreach( $this->ruleImpact as $g ) if( count($g['lost']) ) $lost[$g['device_group']] = count($g['lost']);
        if( count($lost) && $this->sharedRules == 'skip' )
            foreach( $lost as $dg => $c )
                $o .= $li( "Shared rules of Panorama A without equivalent in Panorama B no longer apply to the firewalls of " . $code($dgB($dg)) . ": " . $c . " rule(s) – accept, recreate in Panorama B or run with shared-rules=to-top-dg (REPORT.md, shared rule impact)" );
        foreach( $this->settings as $p => $st )
            if( $st['status'] == 'differs' || ( $st['status'] == 'missing' && $this->sharedSettings != 'copy-missing' ) )
                $o .= $li( "Shared setting " . $code($p) . " " . ( $st['status'] == 'differs' ? 'differs in Panorama B (applies to all its device groups) – align if the moved firewalls need the Panorama A value' : 'is missing in Panorama B – configure it or run with shared-settings=copy-missing' ) );
        $o .= "\n";

        // 2
        $o .= "## 2. Panorama B – configuration\n\n";
        $o .= $li( "Load the configuration: import " . $code($out2) . " as named snapshot and load it, or apply the set commands of " . $code('pan-os-php type=diff file1=' . $this->file2 . ' file2=' . $out2 . ' outputformatset=set_B.txt') . "; commit to Panorama", FALSE );
        $done = $mode == 'execute';
        $o .= $li( "Device groups, templates, template stacks, managed devices (serials) and shared objects transferred" . ( $done ? '' : ' (on execute)' ) . " *(done by panorama-move)*", $done );
        foreach( $this->panoramaSettings as $p )
        {
            $where = $p['location'] . ( $p['name_in_file2'] !== null && strpos($p['location'], $p['name_in_file2']) === FALSE ? ' (file2: ' . $p['name_in_file2'] . ')' : '' );
            if( $p['action'] == 'replace' )
                $o .= $li( "Panorama server in " . $where . ": " . $p['field'] . " " . $p['value'] . " → " . $p['new'] . " *(done by panorama-move, panorama-ip)*", $done );
            elseif( $p['action'] == 'remove' )
                $o .= $li( "Panorama server in " . $where . ": " . $p['field'] . " " . $p['value'] . " removed (panorama-ip has one address) – add a secondary Panorama B address if Panorama B is an HA pair" );
            elseif( $p['action'] == 'variable' )
                $o .= $li( "Panorama server in " . $where . " uses the variable " . $code($p['value']) . " – set its value to the Panorama B address (template / stack / per-device variable)" );
            else
                $o .= $li( "Panorama server in " . $where . ": " . $p['field'] . " " . $p['value'] . " still points to Panorama A – set the Panorama B address before the first push, or run with panorama-ip=" );
        }
        foreach( $this->accessDomains as $adn => $ad )
        {
            $refs = array();
            foreach( $ad['refs'] as $r )
                $refs[] = strpos($r, 'firewall ') === 0 ? $r : ( isset($this->dgAction[$r]) ? $dgB($r) : ( isset($this->templateAction[$r]) ? $this->bName('template', $r) : $this->bName('template stack', $r) ) );
            $o .= $li( "Access domain " . $code($adn) . ": create / extend it in Panorama B with " . implode(', ', $refs)
                . ( count($ad['admins']) ? " and assign it to the administrator(s) " . implode(', ', $ad['admins']) : '' )
                . " – administrators mapped by RADIUS / TACACS+ / SAML attributes: update the mapping" );
        }
        foreach( $this->logCollectorGroups as $g => $serials )
            $o .= $li( "Log collection: add " . implode(', ', $serials) . " to a collector group of Panorama B (Panorama A: " . $code($g) . ")" );
        if( count($this->devices) && !count($this->logCollectorGroups) )
            $o .= $li( "Log collection: check log forwarding of the moved firewalls to Panorama B / its collector group" );
        foreach( $this->plugins as $pl => $refs )
            $o .= $li( "Plugin " . $code($pl) . " references " . implode(', ', array_unique($refs)) . " – configure it in Panorama B" );
        foreach( $this->masterDevices as $dg => $s )
            $o .= $li( "Device group " . $code($dgB($dg)) . ": master device " . $s . " is not moved – choose a moved firewall (User-ID)" );
        $o .= "\n";

        // 3
        $o .= "## 3. Per firewall – connect to Panorama B\n\n";
        if( !count($this->devices) )
            $o .= "No firewall is moved.\n\n";
        else
        {
            $pip = $this->panoramaIp !== null ? $this->panoramaIp[0] : '<Panorama B>';
            $o .= "Steps for each firewall (device registration auth key: Panorama B PAN-OS 10.1 or later):\n\n";
            $o .= "1. Panorama B: create a device registration auth key for the serial – " . $code('request authkey add name <key-name> lifetime <minutes> count 1 serial <serial> devtype fw') . " (or Panorama > Device Registration Auth Key)\n";
            $o .= "2. Firewall, only when it was onboarded to Panorama A with an auth key (PAN-OS 10.1 or later): " . $code('request sc3 reset') . " and " . $code('debug software restart process management-server') . " – irreversible, ends the trust to Panorama A\n";
            $o .= "3. Firewall: " . $code('request authkey set <auth-key>') . "\n";
            $o .= "4. Firewall: Panorama server → Panorama B: " . $code('set deviceconfig system panorama local-panorama panorama-server ' . $pip) . ( isset($this->panoramaIp[1]) ? ' and ' . $code('... panorama-server-2 ' . $this->panoramaIp[1]) : '' ) . ", commit (PAN-OS before 9.1: " . $code('set deviceconfig system panorama-server ' . $pip) . ")\n";
            $o .= "5. Panorama B: Panorama > Managed Devices > Summary – connected; push device group and template stack, check *In Sync*\n\n";
            $o .= "| done | serial | vsys | device group in Panorama B | template stack(s) in Panorama B |\n|---|---|---|---|---|\n";
            foreach( $this->devices as $s => $d )
            {
                $stacks = array();
                foreach( array_keys($this->stackAction) as $sn )
                    if( in_array($s, $this->stackSerials[$sn], TRUE) )
                        $stacks[] = $this->bName( 'template stack', $sn );
                $o .= "| [ ] | " . $s . " | " . ( count($d['vsys']) ? implode(', ', $d['vsys']) : '-' ) . " | " . self::md($dgB($d['dg'])) . " | " . self::md(count($stacks) ? implode(', ', $stacks) : '-') . " |\n";
            }
            $o .= "\n";
        }

        // 4
        $o .= "## 4. Panorama A – after the firewalls are connected to Panorama B\n\n";
        $o .= $li( "Load the cleaned configuration " . $code($out1) . " (or the set commands of " . $code('pan-os-php type=diff file1=' . $this->file1 . ' file2=' . $out1 . ' outputformatset=set_A.txt') . ") and commit – moved device groups, templates / stacks, firewalls and unused shared objects are removed" . ( $done ? ' *(file written by panorama-move)*' : '' ) );
        $removedAd = array();
        foreach( $this->accessDomains as $adn => $ad )
            foreach( $ad['refs'] as $r )
                if( strpos($r, 'firewall ') === 0 || ( isset($this->dgAction[$r]) ? $this->dgAction[$r] == 'move' : ( isset($this->templateAction[$r]) ? $this->templateAction[$r] == 'move' : ( isset($this->stackAction[$r]) && $this->stackAction[$r] == 'move' ) ) ) )
                    $removedAd[] = $adn . ': ' . $r;
        if( count($removedAd) )
            $o .= $li( "Access domain members of moved device groups / templates / firewalls removed in " . $code($out1) . ": " . implode('; ', $removedAd) . " *(done by panorama-move)*", $done );
        foreach( $this->plugins as $pl => $refs )
            $o .= $li( "Plugin " . $code($pl) . " of Panorama A still references " . implode(', ', array_unique($refs)) . " – remove the moved entries (not changed by panorama-move)" );
        foreach( $this->logCollectorGroups as $g => $serials )
            $o .= $li( "Logs of " . implode(', ', $serials) . " stay in collector group " . $code($g) . " of Panorama A – keep Panorama A / the collectors for the retention period" );
        if( count($this->devices) )
            $o .= $li( "Device registration auth keys / device certificates of the moved firewalls on Panorama A are no longer needed – remove them" );
        $o .= $li( "WildFire appliances and Log Collectors managed by Panorama A are not moved – re-home them if the moved firewalls should use other ones" );
        return $o;
    }

    public function renameCount()
    {
        return count($this->renames['device group']) + count($this->renames['template']) + count($this->renames['template stack'])
            + count($this->renames['rule']) + count($this->renames['shared rule']) + count($this->objectRenames);
    }

    private static function md( $s )
    {
        return str_replace( array( '|', "\n" ), array( '\|', ' ' ), (string)$s );
    }

    private static function table( $head, $rows )
    {
        $o = "| " . implode(" | ", $head) . " |\n|" . str_repeat("---|", count($head)) . "\n";
        foreach( $rows as $r )
            $o .= "| " . implode(" | ", array_map(array(__CLASS__, 'md'), $r)) . " |\n";
        return $o . "\n";
    }

    public function reportMarkdown( $mode )
    {
        $p = $this->plan();
        $sev = array( 'blocking' => 0, 'warning' => 0, 'info' => 0 );
        foreach( $this->findings as $f ) $sev[$f['severity']]++;
        $o = "# Panorama move – " . ( $mode == 'execute' ? 'execution' : 'check run' ) . "\n\n";
        $o .= "file1 (source): `" . $this->file1 . "` – file2 (target): `" . $this->file2 . "` – " . date('Y-m-d H:i') . "\n\n";
        $o .= self::table( array( 'item', 'value' ), array(
            array( 'selected device groups', implode(', ', $this->selected) ),
            array( 'target parent in file2', $this->targetParent === null ? 'shared' : $this->targetParent ),
            array( 'shared rules of file1', $this->sharedRules ),
            array( 'shared settings', $this->sharedSettings ),
            array( 'master key / encrypted values', $this->masterKey . ' / ' . count($this->secrets) . ( isset($this->stats['encrypted_values_removed']) ? ' (removed ' . $this->stats['encrypted_values_removed'] . ')' : '' ) ),
            array( 'name conflicts', $this->renameSuffix === null ? 'stop (blocking)' : 'rename with suffix "' . $this->renameSuffix . '" – ' . $this->renameCount() . ' renamed, ' . count($this->rewrites) . ' reference(s) rewritten' ),
            array( 'findings blocking / warning / info', $sev['blocking'] . ' / ' . $sev['warning'] . ' / ' . $sev['info'] ),
            array( 'device groups move / copy', count(array_filter($this->dgAction, function($a){ return $a == 'move'; })) . ' / ' . count(array_filter($this->dgAction, function($a){ return $a == 'copy'; })) ),
            array( 'firewalls', count($this->devices) ),
            array( 'template stacks move / copy', count(array_filter($this->stackAction, function($a){ return $a == 'move'; })) . ' / ' . count(array_filter($this->stackAction, function($a){ return $a == 'copy'; })) ),
            array( 'templates move / copy', count(array_filter($this->templateAction, function($a){ return $a == 'move'; })) . ' / ' . count(array_filter($this->templateAction, function($a){ return $a == 'copy'; })) ),
            array( 'shared objects copy / reuse / conflict', $this->stats['shared_objects']['copy'] . ' / ' . $this->stats['shared_objects']['reuse'] . ' / ' . $this->stats['shared_objects']['conflict'] ),
            array( 'PAN-OS version file1 / file2', $this->stats['version']['file1'] . ' / ' . $this->stats['version']['file2'] ),
            array( 'ancestor-objects-take-precedence file1 / file2', ( $this->stats['ancestor_objects_take_precedence']['file1'] ? 'yes' : 'no' ) . ' / ' . ( $this->stats['ancestor_objects_take_precedence']['file2'] ? 'yes' : 'no' ) ),
        ) );
        $o .= "## Findings\n\n";
        $f = $this->findings;
        usort( $f, function( $a, $b ) { $s = array( 'blocking' => 0, 'warning' => 1, 'info' => 2 ); return $s[$a['severity']] - $s[$b['severity']]; } );
        $o .= count($f) ? self::table( array( 'severity', 'category', 'name', 'file1', 'file2', 'proposal' ), array_map('array_values', $f) ) : "none\n\n";
        $o .= "## Device groups\n\n" . self::table( array( 'device group', 'name in file2', 'action', 'parent in file2', 'reason' ), array_map(function($d){ return array( $d['name'], $d['name_in_file2'] === $d['name'] ? '=' : $d['name_in_file2'], $d['action'], $d['parent_in_file2'] === null ? 'shared' : $d['parent_in_file2'], $d['reason'] ); }, $p['device_groups']) );
        $o .= "## Firewalls\n\n" . self::table( array( 'serial', 'device group', 'vsys' ), array_map(function($d){ return array( $d['serial'], $d['device_group'], implode(', ', $d['vsys']) ); }, $p['devices']) );
        $cont = function($d){ return array( $d['name'], $d['name_in_file2'] === $d['name'] ? '=' : $d['name_in_file2'], $d['action'], $d['reason'] ); };
        $o .= "## Template stacks\n\n" . self::table( array( 'template stack', 'name in file2', 'action', 'reason' ), array_map($cont, $p['template_stacks']) );
        $o .= "## Templates\n\n" . self::table( array( 'template', 'name in file2', 'action', 'reason' ), array_map($cont, $p['templates']) );
        $o .= "## Shared rules – impact per moved firewall\n\n";
        $o .= "Shared rules: file1 pre " . $this->stats['shared_rules']['file1_pre'] . ", post " . $this->stats['shared_rules']['file1_post'] . " – file2 pre " . $this->stats['shared_rules']['file2_pre'] . ", post " . $this->stats['shared_rules']['file2_post'] . ". Rules compared by their resolved values (RuleResolver: addresses as IP ranges, services as ports, groups expanded) – match and action / profiles.\n\n";
        $rows = array();
        foreach( $this->ruleImpact as $g )
            $rows[] = array( $g['device_group'], count($g['firewalls']) . ': ' . implode(', ', array_slice($g['firewalls'], 0, 5)) . ( count($g['firewalls']) > 5 ? ' …' : '' ),
                $g['rules_before'], $g['rules_after'], $g['shared_A_applying'], $g['shared_B_applying'], count($g['lost']), count($g['added']), count($g['covered']), count($g['differs']) );
        $o .= self::table( array( 'device group', 'firewalls', 'rules before', 'rules after', 'file1 shared applying', 'file2 shared applying', 'lost', 'added', 'covered', 'differs' ), $rows );
        foreach( $this->ruleImpact as $g )
        {
            if( !count($g['lost']) && !count($g['added']) && !count($g['differs']) )
                continue;
            $o .= "### " . $g['device_group'] . " (" . count($g['firewalls']) . " firewall(s))\n\n";
            if( count($g['lost']) ) $o .= "* lost (file1 shared, no equivalent in file2): " . implode('; ', $g['lost']) . "\n";
            if( count($g['added']) ) $o .= "* added (file2 shared, newly applying): " . implode('; ', $g['added']) . "\n";
            if( count($g['differs']) ) $o .= "* same match, other action / profiles: " . implode('; ', $g['differs']) . "\n";
            if( count($g['covered']) ) $o .= "* covered: " . implode('; ', $g['covered']) . "\n";
            $o .= "\n";
        }
        $o .= "Default security rules: file1 `" . $this->stats['default_security_rules']['file1'] . "` – file2 `" . $this->stats['default_security_rules']['file2'] . "`\n\n";
        $o .= "## Encrypted values (master key)\n\n";
        $o .= count($this->secrets) ? ( $this->masterKey == 'same'
            ? "Copied unchanged – valid only when Panorama B uses the same master key as Panorama A. The master key cannot be read from the configuration: confirm it on both Panoramas.\n\n"
            : "Removed on transfer – set them in Panorama B after the import (list: SECRETS_CHECKLIST.md). Values are never decrypted or written to the report.\n\n" )
            . self::table( array( 'location', 'field', 'path' ), array_map( function($x){ return array( $x['location'], $x['field'], $x['path'] ); }, $this->secrets ) )
            : "none\n\n";
        if( $this->renameSuffix !== null )
        {
            $o .= "## Renames in file2 (conflict=rename:" . self::md($this->renameSuffix) . ")\n\n";
            $o .= "Only the copies in file2 are renamed – file1 keeps its names. References in the transferred configuration are rewritten" . ( $mode == 'execute' ? '' : ' on execute (preview below)' ) . ".\n\n";
            $rows = array();
            foreach( array( 'device group', 'template', 'template stack' ) as $cat )
                foreach( $this->renames[$cat] as $old => $new ) $rows[] = array( $cat, $old, $new, '' );
            foreach( $this->renames['rule'] as $k => $new ) { $kp = explode('|', $k, 4); $rows[] = array( 'rule (' . $kp[1] . ' ' . $kp[2] . ')', $kp[3], $new, 'device group ' . $kp[0] ); }
            foreach( $this->renames['shared rule'] as $k => $new ) { $kp = explode('|', $k, 3); $rows[] = array( 'shared rule (' . $kp[0] . ' ' . $kp[1] . ')', $kp[2], $new, 'copied to the top device group' ); }
            $refCount = array();
            foreach( $this->rewrites as $r ) $refCount[$r['old']] = ( isset($refCount[$r['old']]) ? $refCount[$r['old']] : 0 ) + 1;
            foreach( $this->objectRenames as $old => $new )
            {
                $types = array();
                foreach( $this->sharedObjects as $so ) if( $so['name'] === $old && isset($so['rename']) ) $types[] = $so['path'];
                $rows[] = array( 'shared object (' . implode(', ', $types) . ')', $old, $new, ( isset($refCount[$old]) ? $refCount[$old] : 0 ) . ' reference(s) rewritten' );
            }
            $o .= count($rows) ? self::table( array( 'type', 'file1 name', 'file2 name', 'note' ), $rows ) : "none\n\n";
            if( count($this->rewrites) )
            {
                $byLoc = array();
                foreach( $this->rewrites as $r ) $byLoc[$r['location']][] = $r['old'] . ' → ' . $r['new'] . ' (' . $r['path'] . ')';
                $o .= "Rewritten references per location (full list in plan.json):\n\n";
                foreach( $byLoc as $loc => $list )
                    $o .= "* " . self::md($loc) . ": " . self::md( implode('; ', array_slice($list, 0, 10)) . ( count($list) > 10 ? ' … (+' . ( count($list) - 10 ) . ')' : '' ) ) . "\n";
                $o .= "\nReferences are found by text value: a zone, user or other non-object value with the name of a renamed object would be rewritten too (zones in from / to and users are excluded) – check the list.\n\n";
            }
        }
        $o .= "## Effective rule base per moved firewall (file1 before / file2 after)\n\n";
        if( $this->rulebaseCheckSkipped !== null )
            $o .= "skipped: " . self::md($this->rulebaseCheckSkipped) . "\n\n";
        elseif( !count($this->rulebaseCheck) )
            $o .= "no firewall is moved\n\n";
        else
        {
            $o .= "Every rule reaching the firewall (shared pre, device group chain, shared post), resolved to its values as the firewall sees them – addresses to IP ranges, services to ports, groups expanded (RuleResolver). The move is simulated on a copy of file2 (check run) – the same transfer as execute.\n\n";
            $rows = array();
            foreach( $this->rulebaseCheck as $g )
                $rows[] = array( $g['device_group_in_file2'], count($g['firewalls']) . ': ' . implode(', ', array_slice($g['firewalls'], 0, 5)) . ( count($g['firewalls']) > 5 ? ' …' : '' ),
                    $g['rules_before'], $g['rules_after'], $g['transferred_same'], count($g['transferred_changed']), count($g['covered']), count($g['differs']), count($g['lost']), count($g['added']), $g['order_kept'] ? 'kept' : 'CHANGED' );
            $o .= self::table( array( 'device group in file2', 'firewalls', 'rules before', 'rules after', 'transferred: same', 'transferred: changed', 'shared covered', 'shared differs', 'shared lost', 'added', 'order' ), $rows );
            foreach( $this->rulebaseCheck as $g )
            {
                if( !count($g['transferred_changed']) && !count($g['differs']) && !count($g['lost']) && !count($g['added']) )
                    continue;
                $o .= "### " . $g['device_group_in_file2'] . " (" . count($g['firewalls']) . " firewall(s))\n\n";
                foreach( $g['transferred_changed'] as $ka => $c )
                {
                    $o .= "* **changed**: `" . $ka . "` → `" . $c[0] . "`\n";
                    foreach( $c[1] as $f => $dd )
                        $o .= "  * " . $f . ": file1 only `" . implode(', ', $dd['only_in_a']) . "` – file2 only `" . implode(', ', $dd['only_in_b']) . "`\n";
                }
                foreach( $g['differs'] as $ka => $c )
                    $o .= "* same match, other action / profiles: `" . $ka . "` ~ `" . $c[0] . "` (" . implode(', ', array_keys($c[1])) . ")\n";
                if( count($g['lost']) ) $o .= "* lost (file1 shared, no equivalent in file2): `" . implode('`, `', $g['lost']) . "`\n";
                if( count($g['added']) ) $o .= "* added (file2, newly applying): `" . implode('`, `', $g['added']) . "`\n";
                $o .= "\n";
            }
        }
        $o .= "## Panorama server in the transferred templates / stacks (D8)\n\n";
        $o .= count($this->panoramaSettings) ? self::table( array( 'template / stack', 'field', 'file1 value', 'file2', 'path' ), array_map( function($p){
                $f2 = $p['action'] == 'replace' ? $p['new'] : ( $p['action'] == 'remove' ? 'removed' : ( $p['action'] == 'variable' ? 'unchanged (variable)' : 'unchanged – still Panorama A' ) );
                return array( $p['location'], $p['field'], $p['value'], $f2, $p['path'] ); }, $this->panoramaSettings ) )
            : "none" . ( $this->panoramaIp !== null ? " – panorama-ip " . implode(', ', $this->panoramaIp) . " not used, set it on the firewalls" : '' ) . "\n\n";
        $o .= "Follow-up steps (Panorama B, per firewall, Panorama A): MIGRATION_FOLLOWUP.md\n\n";
        $o .= "## Shared settings (blocks without named objects, apply to all device groups)\n\n";
        $rows = array();
        foreach( $this->settings as $path => $st )
            $rows[] = array( $path, $st['status'] == 'missing' && $this->sharedSettings == 'copy-missing' ? 'missing in file2 – copied' : $st['status'] );
        $o .= count($rows) ? self::table( array( 'setting', 'file1 vs. file2' ), $rows ) : "none\n\n";
        $o .= "## Shared objects\n\n";
        $cnt = array();
        foreach( $p['shared_objects'] as $s ) $cnt[$s['path']][$s['action']] = ( isset($cnt[$s['path']][$s['action']]) ? $cnt[$s['path']][$s['action']] : 0 ) + 1;
        $rows = array();
        $ren = array();
        foreach( $p['shared_objects'] as $s ) if( isset($s['name_in_file2']) ) $ren[$s['path']] = ( isset($ren[$s['path']]) ? $ren[$s['path']] : 0 ) + 1;
        foreach( $cnt as $path => $c ) $rows[] = array( $path, isset($c['copy']) ? $c['copy'] : 0, isset($ren[$path]) ? $ren[$path] : 0, isset($c['reuse']) ? $c['reuse'] : 0, isset($c['conflict']) ? $c['conflict'] : 0 );
        $o .= self::table( array( 'type', 'copy', 'of which renamed', 'reuse (same value in file2)', 'conflict' ), $rows );
        $o .= "Relevant objects are found by name references (text values) in the moved / copied device groups, templates and template stacks, resolved recursively; the full list is in plan.json.\n\n";
        if( isset($this->stats['validation']) )
        {
            $o .= "## Validation of the output files\n\n";
            $rows = array();
            foreach( $this->stats['validation'] as $k => $v )
                $rows[] = array( $k, $v['file'], $v['device_groups'], $v['template_stacks'], $v['templates'], $v['unresolved'] );
            $o .= self::table( array( 'file', 'output', 'device groups', 'template stacks', 'templates', 'unresolved references' ), $rows );
            foreach( $this->stats['validation'] as $k => $v )
                if( count($v['unresolved_list']) ) $o .= "* " . $k . " unresolved: " . implode('; ', $v['unresolved_list']) . "\n";
            if( isset($this->stats['file1_removed_shared']) )
                $o .= "\nRemoved from shared of file1 (no longer used): " . count($this->stats['file1_removed_shared']) . "\n\n";
            $o .= "Check with: `pan-os-php type=diff file1=<file2> file2=<out2> outputformatset=set_file2.txt` and the same for file1.\n";
        }
        return $o;
    }
}
