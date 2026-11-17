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
 * to Panorama B (file2) - offline on the XML files. CONCEPT_panorama_to_panorama_move.md
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

    const SKIP_CONTAINERS = array( 'pre-rulebase', 'post-rulebase', 'default-security-rules', 'devices', 'reference-templates', 'master-device', 'authorization-code', 'user-group-source' );
    const NO_TOKEN = array( 'description', 'comment', 'disabled', 'negate', 'action', 'log-start', 'log-end' );
    const NAMESPACES = array(
        'address' => 'address', 'address-group' => 'address', 'region' => 'address', 'external-list' => 'address',
        'service' => 'service', 'service-group' => 'service',
        'application' => 'application', 'application-group' => 'application', 'application-filter' => 'application',
    );
    const SEC_MATCH = array( 'from', 'to', 'source', 'destination', 'source-user', 'application', 'service', 'category', 'negate-source', 'negate-destination', 'source-hip', 'destination-hip' );

    public function __construct( $file1, $file2, $dgList, $targetParent = null, $sharedRules = 'skip', $sharedSettings = 'report' )
    {
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

    /** match part / action part of a rule for the equivalence check */
    public static function ruleSignature( $rule, $type )
    {
        $d = new DOMDocument();
        $n = $d->importNode( $rule, TRUE );
        $d->appendChild( $n );
        $drop = array( 'description', 'tag', 'group-tag', 'target', 'disabled', 'log-setting', 'log-start', 'log-end' );
        foreach( iterator_to_array($n->childNodes) as $c )
            if( $c->nodeType != XML_ELEMENT_NODE || in_array($c->nodeName, $drop, TRUE) )
                $n->removeChild( $c );
        $match = $d->createElement('m'); $act = $d->createElement('a');
        foreach( iterator_to_array($n->childNodes) as $c )
        {
            if( $type == 'security' && !in_array($c->nodeName, self::SEC_MATCH, TRUE) )
                $act->appendChild( $c );
            else
                $match->appendChild( $c );
        }
        return array( md5(self::canon($match, FALSE)), md5(self::canon($act, FALSE)) );
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
        $this->finding( 'info', 'device', count($this->devices) . ' firewall(s)', 'HA pairs are not visible in the Panorama configuration', '', 'make sure both HA peers are in the moved device groups' );

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
                    $this->finding( 'warning', 'device group', $n, 'master-device ' . $s . ' is not moved', '', 'choose a moved firewall as master device in file2' );
            }
        foreach( $relTpl as $n => $why )
            if( isset($tplA[$n]) )
            {
                $x = new DOMXPath( $tplA[$n]->ownerDocument );
                foreach( $x->query('.//deviceconfig/system/panorama', $tplA[$n]) as $pn )
                    $this->finding( 'warning', 'template', $n, 'Panorama server setting: ' . trim(preg_replace('/\s+/', ' ', $pn->textContent)), '', 'firewalls would still connect to Panorama A - set the Panorama B address (D8)' );
            }

        $this->checkNames();
        $this->checkRules();
        $this->checkSettings();
        $this->collectShared();
        $this->checkOtherReferences();
        $this->checkUnresolved();
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
        foreach( $sets as $cat => $s )
        {
            $l = $lc( $allB );
            foreach( $s[0] as $n )
            {
                if( isset($allB[$n]) )
                    $this->finding( 'blocking', $cat, $n, '', 'name exists in file2 (' . ( isset($dgB[$n]) ? 'device group' : ( isset($tplB[$n]) ? 'template' : 'template stack' ) ) . ')', 'rename in file1 or file2 before the move (D4)' );
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
                    $this->finding( 'blocking', 'shared object', $o['path'] . ' ' . $o['name'], 'used by the moved configuration', 'same name, other value', 'rename in file1 before the move or align the value (D5)' );
                }
            }
            elseif( isset($nsB[$ns][$o['name']]) )
            {
                $action = 'conflict';
                $this->finding( 'blocking', 'shared object', $o['path'] . ' ' . $o['name'], '', 'name used by ' . $nsB[$ns][$o['name']] . ' (same name space)', 'rename (D5)' );
            }
            elseif( isset($nsB[$ns . '#lc'][strtolower($o['name'])]) )
                $this->finding( 'warning', 'shared object', $o['path'] . ' ' . $o['name'], '', 'differs only in case from ' . $nsB[$ns . '#lc'][strtolower($o['name'])], 'avoid look-alike names' );
            if( $o['name'] !== trim($o['name']) )
                $this->finding( 'warning', 'shared object', $o['path'] . ' "' . $o['name'] . '"', 'leading / trailing blank', '', 'rename' );
            $this->sharedObjects[$k] = array( 'path' => $o['path'], 'name' => $o['name'], 'node' => $o['node'], 'action' => $action );
        }
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
            'copy' => count(array_filter($this->sharedObjects, function($o){ return $o['action'] == 'copy'; })),
            'reuse' => count(array_filter($this->sharedObjects, function($o){ return $o['action'] == 'reuse'; })),
            'conflict' => count(array_filter($this->sharedObjects, function($o){ return $o['action'] == 'conflict'; })) );
    }

    /** shared rule impact per moved firewall and rule name conflicts (4a) */
    private function checkRules()
    {
        $A = $this->A; $B = $this->B;
        $dgA = self::dgEntries( $A );
        $rulesA = array( 'pre' => self::rules($A->sharedroot, 'pre-rulebase'), 'post' => self::rules($A->sharedroot, 'post-rulebase') );
        $rulesB = array( 'pre' => self::rules($B->sharedroot, 'pre-rulebase'), 'post' => self::rules($B->sharedroot, 'post-rulebase') );
        $sigB = array();
        foreach( $rulesB as $w => $list )
            foreach( $list as $r )
            {
                list( $m, $a ) = self::ruleSignature( $r['node'], $r['type'] );
                $sigB[$r['type'] . '|' . $m][] = array( 'name' => $r['name'], 'act' => $a, 'w' => $w );
            }
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
                {
                    $movedNames[$r['type'] . '|' . $r['name']] = $n;
                    if( isset($namesB[$r['type'] . '|' . $r['name']]) )
                        $this->finding( 'blocking', 'rule name', $r['type'] . ' ' . $r['name'], 'device group ' . $n, $namesB[$r['type'] . '|' . $r['name']], 'rule names must be unique in the device group hierarchy - rename' );
                }

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
                    list( $m, $a ) = self::ruleSignature( $r['node'], $r['type'] );
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
                    list( $m, $a ) = self::ruleSignature( $r['node'], $r['type'] );
                    foreach( $rulesA as $wa => $la )
                        foreach( $la as $ra )
                            if( $ra['type'] == $r['type'] && self::applies($ra['node'], $serial) !== FALSE && self::ruleSignature($ra['node'], $ra['type'])[0] === $m )
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
                if( isset($namesB[$type . '|' . $name]) )
                    $this->finding( 'blocking', 'rule name', $type . ' ' . $name, 'shared ' . $w . ' (shared-rules=to-top-dg)', $namesB[$type . '|' . $name], 'rename' );
                if( isset($movedNames[$type . '|' . $name]) )
                    $this->finding( 'blocking', 'rule name', $type . ' ' . $name, 'shared ' . $w . ' (shared-rules=to-top-dg)', 'device group ' . $movedNames[$type . '|' . $name], 'rename' );
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

    /** access domains, log collector groups, plugins (7) */
    private function checkOtherReferences()
    {
        $x = new DOMXPath( $this->A->xmldoc );
        $names = array_merge( array_keys($this->dgAction), array_keys($this->templateAction), array_keys($this->stackAction) );
        foreach( $x->query('/config/mgt-config/access-domain/entry') as $ad )
            foreach( $ad->getElementsByTagName('member') as $m )
                if( in_array(trim($m->textContent), $names, TRUE) )
                    $this->finding( 'info', 'access domain', $ad->getAttribute('name'), 'references ' . trim($m->textContent), 'not transferred', 'create the access domain / admin in file2' );
        foreach( $x->query('/config/devices/entry/log-collector-group/entry') as $lcg )
            foreach( $lcg->getElementsByTagName('entry') as $e )
                if( isset($this->devices[$e->getAttribute('name')]) )
                    $this->finding( 'info', 'log collector group', $lcg->getAttribute('name'), 'device ' . $e->getAttribute('name'), 'not transferred', 'configure log collection in file2; existing logs stay with Panorama A' );
        foreach( $x->query('/config/devices/entry/plugins/*') as $pl )
        {
            $t = self::tokens( $pl );
            foreach( $names as $n )
                if( isset($t[$n]) )
                    $this->finding( 'warning', 'plugin', $pl->nodeName, 'references ' . $n, 'not transferred', 'check the plugin configuration' );
            foreach( array_keys($this->devices) as $s )
                if( isset($t[$s]) )
                    $this->finding( 'warning', 'plugin', $pl->nodeName, 'references device ' . $s, 'not transferred', 'check the plugin configuration' );
        }
    }

    /** objects referenced by the relevant device groups that pan-os-php cannot resolve in file1 (tmp objects) */
    private function checkUnresolved()
    {
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
        foreach( $this->sharedObjects as $o )
            if( $o['action'] == 'copy' )
                $this->importInto( self::ensurePath($sharedB, $o['path']), $o['node'] );
        // 1b shared setting blocks missing in file2
        if( $this->sharedSettings == 'copy-missing' )
            foreach( $this->settings as $p => $st )
                if( $st['status'] == 'missing' )
                {
                    $parts = explode( '/', $p );
                    array_pop( $parts );
                    $this->importInto( count($parts) ? self::ensurePath($sharedB, implode('/', $parts)) : $sharedB, $st['node'] );
                }
        // 2 managed devices
        $mgtA = self::mgtDevices( $A );
        $mgtB = DH::findXPathSingleEntryOrCreate( '/config/mgt-config/devices', $B->xmlroot );
        foreach( $this->devices as $s => $d )
            if( isset($mgtA[$s]) )
                $this->importInto( $mgtB, $mgtA[$s] );
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
        foreach( array_keys($order) as $n )
        {
            $B->createDeviceGroup( $n, $this->dgParentB[$n] );
            $created = self::dgEntries( $B )[$n];
            $new = $B->xmldoc->importNode( $dgA[$n], TRUE );
            if( $this->dgAction[$n] == 'copy' )
            {
                $dc = self::child( $new, 'devices' );
                if( $dc !== null ) $new->removeChild( $dc );
            }
            $created->parentNode->replaceChild( $new, $created );
        }
        // 4 templates, 5 template stacks
        $tplA = self::templateEntries( $A );
        foreach( array_keys($this->templateAction) as $n )
        {
            if( !isset($tplA[$n]) ) continue;
            $B->createTemplate( $n );
            $created = self::templateEntries( $B )[$n];
            $new = $B->xmldoc->importNode( $tplA[$n], TRUE );
            $this->filterDevices( $new );
            $created->parentNode->replaceChild( $new, $created );
        }
        $stA = self::stackEntries( $A );
        foreach( array_keys($this->stackAction) as $n )
        {
            $B->createTemplateStack( $n );
            $created = self::stackEntries( $B )[$n];
            $new = $B->xmldoc->importNode( $stA[$n], TRUE );
            $this->filterDevices( $new );
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
                        $rulesNode = self::ensurePath( $dgB[$n], $w . '/' . $r['type'] . '/rules' );
                        if( $w == 'pre-rulebase' )
                            $this->importInto( $rulesNode, $r['node'], $rulesNode->firstChild );
                        else
                            $rulesNode->insertBefore( $B->xmldoc->importNode($r['node'], TRUE), null );
                    }
            }
        }
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
            $shared[] = array( 'path' => $o['path'], 'name' => $o['name'], 'action' => $o['action'] );
        $dgs = array();
        foreach( $this->dgAction as $n => $a )
            $dgs[] = array( 'name' => $n, 'action' => $a, 'parent_in_file2' => $this->dgParentB[$n], 'reason' => $this->dgReason[$n] );
        $tpl = array(); $st = array();
        foreach( $this->templateAction as $n => $a ) $tpl[] = array( 'name' => $n, 'action' => $a, 'reason' => $this->templateReason[$n] );
        foreach( $this->stackAction as $n => $a ) $st[] = array( 'name' => $n, 'action' => $a, 'reason' => $this->stackReason[$n] );
        $dev = array();
        foreach( $this->devices as $s => $d ) $dev[] = array( 'serial' => $s, 'device_group' => $d['dg'], 'vsys' => $d['vsys'] );
        return array( 'schema' => 'pan-os-php-panorama-move-plan', 'version' => 1, 'created_at' => date('c'),
            'file1' => $this->file1, 'file2' => $this->file2, 'selected' => $this->selected, 'target_parent_dg' => $this->targetParent,
            'shared_rules' => $this->sharedRules, 'blocking' => count($this->blocking()),
            'device_groups' => $dgs, 'devices' => $dev, 'template_stacks' => $st, 'templates' => $tpl, 'shared_objects' => $shared,
            'shared_settings' => array_map( function( $p, $st ) { return array( 'path' => $p, 'status' => $st['status'] ); }, array_keys($this->settings), array_values($this->settings) ),
            'shared_rule_impact' => $this->ruleImpact, 'findings' => $this->findings, 'stats' => $this->stats );
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
        $o .= "## Device groups\n\n" . self::table( array( 'device group', 'action', 'parent in file2', 'reason' ), array_map(function($d){ return array( $d['name'], $d['action'], $d['parent_in_file2'] === null ? 'shared' : $d['parent_in_file2'], $d['reason'] ); }, $p['device_groups']) );
        $o .= "## Firewalls\n\n" . self::table( array( 'serial', 'device group', 'vsys' ), array_map(function($d){ return array( $d['serial'], $d['device_group'], implode(', ', $d['vsys']) ); }, $p['devices']) );
        $o .= "## Template stacks\n\n" . self::table( array( 'template stack', 'action', 'reason' ), array_map('array_values', $p['template_stacks']) );
        $o .= "## Templates\n\n" . self::table( array( 'template', 'action', 'reason' ), array_map('array_values', $p['templates']) );
        $o .= "## Shared rules – impact per moved firewall\n\n";
        $o .= "Shared rules: file1 pre " . $this->stats['shared_rules']['file1_pre'] . ", post " . $this->stats['shared_rules']['file1_post'] . " – file2 pre " . $this->stats['shared_rules']['file2_pre'] . ", post " . $this->stats['shared_rules']['file2_post'] . ". Rules compared by match (zones, addresses, users, applications, services, URL categories) and action / profiles by name.\n\n";
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
        $o .= "## Shared settings (blocks without named objects, apply to all device groups)\n\n";
        $rows = array();
        foreach( $this->settings as $path => $st )
            $rows[] = array( $path, $st['status'] == 'missing' && $this->sharedSettings == 'copy-missing' ? 'missing in file2 – copied' : $st['status'] );
        $o .= count($rows) ? self::table( array( 'setting', 'file1 vs. file2' ), $rows ) : "none\n\n";
        $o .= "## Shared objects\n\n";
        $cnt = array();
        foreach( $p['shared_objects'] as $s ) $cnt[$s['path']][$s['action']] = ( isset($cnt[$s['path']][$s['action']]) ? $cnt[$s['path']][$s['action']] : 0 ) + 1;
        $rows = array();
        foreach( $cnt as $path => $c ) $rows[] = array( $path, isset($c['copy']) ? $c['copy'] : 0, isset($c['reuse']) ? $c['reuse'] : 0, isset($c['conflict']) ? $c['conflict'] : 0 );
        $o .= self::table( array( 'type', 'copy', 'reuse (same value in file2)', 'conflict' ), $rows );
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
