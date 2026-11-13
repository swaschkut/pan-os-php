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

require_once(dirname(__FILE__) . "/SCMPrismaAccessExport.php");

/**
 * Offline compare of two scm_pa_export.php export directories ("left" and "right").
 *
 * The result is symmetric (no direction): per area / container / endpoint the entries only in left, only in right
 * and changed (field level). It is the input for the sync plan (scm_pa_sync.php, step 3).
 *
 * Identity of an entry = endpoint metadata key (default "name") inside the owning container - never the tenant
 * specific id. Before comparing, every entry is normalised: ids / owner fields / derived fields are removed, keys are
 * sorted, lists of named objects become maps keyed by name, the order of ordered lists (rules) is kept separately.
 * Secrets are compared but never written in clear text.
 *
 * Output (outdir): diff.json, diff-summary.csv, DIFF_REPORT.md
 */
class SCMPrismaAccessCompare
{
    const FORMAT_VERSION = 1;
    const MASK = '***';
    const ORDER_KEY = '#order';

    public $leftDir;
    public $rightDir;
    public $leftManifest;
    public $rightManifest;

    /** filters: areas, containers (names), types (config types / endpoint names) - null = all */
    public $filter = array( 'areas' => null, 'containers' => null, 'types' => null );
    /** additional dotted paths to ignore for every endpoint */
    public $extraIgnore = array();
    /** name map: [area][endpoint][leftName] = rightName ("*" wildcards), containers: [leftContainer] = rightContainer */
    public $nameMap = array();
    public $containerMap = array();
    /** report limits */
    public $reportMaxItems = 50;
    public $reportMaxChanges = 20;

    public $entries = array();
    public $notComparable = array();
    public $warnings = array();
    public $hierarchy = null;

    public function __construct( $leftDir, $rightDir )
    {
        $this->leftDir = rtrim($leftDir, "/\\");
        $this->rightDir = rtrim($rightDir, "/\\");
        $this->leftManifest = self::loadManifest( $this->leftDir );
        $this->rightManifest = self::loadManifest( $this->rightDir );
    }

    public static function loadManifest( $dir )
    {
        $file = $dir . "/manifest.json";
        if( !is_readable($file) )
            derr( "not an export directory (manifest.json missing): " . $dir, null, FALSE );
        $m = json_decode( file_get_contents($file), TRUE );
        if( !is_array($m) || !isset($m['endpoints']) )
            derr( "manifest.json not readable: " . $file, null, FALSE );
        return $m;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // name map

    /**
     * CSV with header area,endpoint,left,right; "*" as wildcard for area / endpoint;
     * area "config" + endpoint "container" maps folder / snippet names
     */
    public function loadNameMap( $file )
    {
        if( !is_readable($file) )
            derr( "name map not readable: " . $file, null, FALSE );
        $fh = fopen( $file, "r" );
        $header = array_map( 'trim', (array)fgetcsv( $fh, 0, ',', '"', '' ) );
        foreach( array('area', 'endpoint', 'left', 'right') as $c )
            if( !in_array($c, $header, TRUE) )
                derr( "name map " . $file . " has no column '" . $c . "'", null, FALSE );
        while( ($line = fgetcsv( $fh, 0, ',', '"', '' )) !== false )
        {
            if( count($line) == 1 && trim((string)$line[0]) === "" )
                continue;
            $row = array();
            foreach( $header as $i => $c )
                $row[$c] = isset($line[$i]) ? trim($line[$i]) : "";
            if( $row['left'] === "" || $row['right'] === "" )
                continue;
            if( $row['area'] == SCMPrismaAccessExport::AREA_CONFIG && $row['endpoint'] == 'container' )
                $this->containerMap[$row['left']] = $row['right'];
            else
                $this->nameMap[$row['area'] === "" ? "*" : $row['area']][$row['endpoint'] === "" ? "*" : $row['endpoint']][$row['left']] = $row['right'];
        }
        fclose( $fh );
    }

    /**
     * mapped name of a left entry for "area/endpoint" (endpoint without -pre / -post)
     */
    public function mapName( $endpointKey, $name )
    {
        //folders / snippets themselves follow the container map
        if( ( $endpointKey == 'config/folders' || $endpointKey == 'config/snippets' ) && isset($this->containerMap[$name]) )
            return $this->containerMap[$name];
        list($area, $endpoint) = explode("/", $endpointKey, 2);
        foreach( array( array($area, $endpoint), array($area, "*"), array("*", $endpoint), array("*", "*") ) as $c )
            if( isset($this->nameMap[$c[0]][$c[1]][$name]) )
                return $this->nameMap[$c[0]][$c[1]][$name];
        return $name;
    }

    public function hasNameMap()
    {
        return count($this->nameMap) > 0 || count($this->containerMap) > 0;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // run

    /**
     * index of the endpoint files of one manifest: "area|container|endpoint" => meta
     */
    private function indexManifest( $manifest, $side )
    {
        $index = array();
        foreach( $manifest['endpoints'] as $e )
        {
            if( !isset($e['area']) || !isset($e['name']) )
                continue;
            $container = isset($e['container']) ? $e['container_kind'] . ":" . $e['container'] : "";
            if( $side == 'left' && $container !== "" )
            {
                list($kind, $name) = explode(":", $container, 2);
                if( isset($this->containerMap[$name]) )
                    $container = $kind . ":" . $this->containerMap[$name];
            }
            $index[ $e['area'] . "|" . $container . "|" . $e['name'] ] = $e;
        }
        return $index;
    }

    private function passesFilter( $area, $container, $name )
    {
        if( $this->filter['areas'] !== null && !in_array($area, $this->filter['areas'], TRUE) )
            return false;
        if( $this->filter['containers'] !== null && $container !== "" )
        {
            list(, $cname) = explode(":", $container, 2);
            if( !in_array($cname, $this->filter['containers'], TRUE) )
                return false;
        }
        if( $this->filter['types'] !== null && $area == SCMPrismaAccessExport::AREA_CONFIG && $container !== "" )
        {
            $base = preg_replace('/-(pre|post)$/', '', $name);
            if( !in_array($base, $this->filter['types'], TRUE) && !in_array($name, $this->filter['types'], TRUE) )
                return false;
        }
        return true;
    }

    public function run()
    {
        $left = $this->indexManifest( $this->leftManifest, 'left' );
        $right = $this->indexManifest( $this->rightManifest, 'right' );

        $keys = array_unique( array_merge( array_keys($left), array_keys($right) ) );
        //stable order: area order, then container, then endpoint order
        $areaPos = array_flip( SCMPrismaAccessExport::AREAS );
        usort( $keys, function($a, $b) use( $left, $right, $areaPos ){
            $ma = isset($left[$a]) ? $left[$a] : $right[$a];
            $mb = isset($left[$b]) ? $left[$b] : $right[$b];
            $pa = isset($areaPos[$ma['area']]) ? $areaPos[$ma['area']] : 99;
            $pb = isset($areaPos[$mb['area']]) ? $areaPos[$mb['area']] : 99;
            if( $pa != $pb ) return $pa - $pb;
            $ca = isset($ma['container']) ? $ma['container_kind'] . ":" . $ma['container'] : "";
            $cb = isset($mb['container']) ? $mb['container_kind'] . ":" . $mb['container'] : "";
            if( $ca !== $cb ) return strcmp($ca, $cb);
            return ( isset($ma['order']) ? $ma['order'] : 0 ) - ( isset($mb['order']) ? $mb['order'] : 0 ) ?: strcmp($ma['name'], $mb['name']);
        } );

        foreach( $keys as $k )
        {
            list($area, $container, $name) = explode("|", $k, 3);
            if( !$this->passesFilter($area, $container, $name) )
                continue;
            $meta = SCMPrismaAccessExport::endpointMeta( $area, $name );
            if( !$meta['compare'] )
                continue;

            $l = isset($left[$k]) ? $left[$k] : null;
            $r = isset($right[$k]) ? $right[$k] : null;
            $base = array( 'area' => $area, 'container' => $container === "" ? null : $container, 'endpoint' => $name, 'endpoint_key' => $meta['endpoint'] );

            //config container that exists on one side only: compare against an empty list
            if( ( $l === null || $r === null ) && $area == SCMPrismaAccessExport::AREA_CONFIG && $container !== ""
                && $this->sideCovers( $l === null ? $this->leftManifest : $this->rightManifest, $container, $name, $l === null ) )
            {
                $present = $l === null ? $r : $l;
                if( $present['status'] !== 'ok' )
                    continue;
                $data = $this->loadData( $l === null ? $this->rightDir : $this->leftDir, $present['file'] );
                $this->entries[] = $l === null ? $this->compareEndpoint( $base, $meta, array(), $data ) : $this->compareEndpoint( $base, $meta, $data, array() );
                continue;
            }
            if( $l === null || $r === null )
            {
                $this->notComparable[] = $base + array( 'reason' => 'not exported in ' . ( $l === null ? 'left' : 'right' ),
                    'left_status' => $l === null ? null : $l['status'], 'right_status' => $r === null ? null : $r['status'] );
                continue;
            }
            if( $l['status'] !== 'ok' || $r['status'] !== 'ok' )
            {
                //both unavailable: nothing to compare, not worth a line
                if( $l['status'] == 'unavailable' && $r['status'] == 'unavailable' )
                    continue;
                $this->notComparable[] = $base + array( 'reason' => 'status left=' . $l['status'] . ' right=' . $r['status'],
                    'left_status' => $l['status'], 'right_status' => $r['status'] );
                continue;
            }

            $ld = $this->loadData( $this->leftDir, $l['file'] );
            $rd = $this->loadData( $this->rightDir, $r['file'] );
            $this->entries[] = $this->compareEndpoint( $base, $meta, $ld, $rd );
        }

        if( ( $this->filter['areas'] === null || in_array(SCMPrismaAccessExport::AREA_CONFIG, $this->filter['areas'], TRUE) )
            && is_readable($this->leftDir . "/config/hierarchy.json") && is_readable($this->rightDir . "/config/hierarchy.json") )
            $this->hierarchy = $this->compareHierarchy(
                json_decode( file_get_contents($this->leftDir . "/config/hierarchy.json"), TRUE ),
                json_decode( file_get_contents($this->rightDir . "/config/hierarchy.json"), TRUE ) );
    }

    /**
     * true if the export of $manifest would have contained the config container / type (container missing there
     * because it does not exist in that tenant, not because of a filter)
     */
    private function sideCovers( $manifest, $container, $endpoint, $isLeft )
    {
        if( !isset($manifest['areas']) || !in_array(SCMPrismaAccessExport::AREA_CONFIG, $manifest['areas'], TRUE) )
            return false;
        $options = isset($manifest['config']['options']) ? $manifest['config']['options'] : array();
        list($kind, $name) = explode(":", $container, 2);
        if( $isLeft )
        {
            $inv = array_flip($this->containerMap);
            if( isset($inv[$name]) )
                $name = $inv[$name];
        }
        if( !empty($options['containers']) && !in_array($name, $options['containers'], TRUE) )
            return false;
        $base = preg_replace('/-(pre|post)$/', '', $endpoint);
        if( !empty($options['types']) && !in_array($base, $options['types'], TRUE) )
            return false;
        if( !empty($options['scope']) )
        {
            $inScope = array_map( function($t){ return $t['name']; }, SCMPrismaAccessExport::configTypesForScope($options['scope']) );
            if( !in_array($base, $inScope, TRUE) )
                return false;
        }
        //Prisma Access folders: network / identity / device types are not exported there
        foreach( SCMPrismaAccessExport::getConfigTypes() as $t )
            if( $t['name'] == $base && $kind == 'folder' && in_array($name, SCMPrismaAccessExport::PA_FOLDERS, TRUE) && in_array($t['group'], array('network', 'identity', 'device'), TRUE) )
                return false;
        return true;
    }

    private function loadData( $dir, $file )
    {
        $path = $dir . "/" . $file;
        if( !is_readable($path) )
        {
            $this->warnings[] = "file missing: " . $path;
            return null;
        }
        $content = json_decode( file_get_contents($path), TRUE );
        return is_array($content) && array_key_exists('data', $content) ? $content['data'] : null;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // compare one endpoint

    public function compareEndpoint( $base, $meta, $leftData, $rightData )
    {
        $entry = $base + array(
            'singleton' => $meta['singleton'], 'key_fields' => $meta['key'], 'write' => $meta['write'],
            'counts' => array( 'left' => 0, 'right' => 0, 'equal' => 0, 'only_left' => 0, 'only_right' => 0, 'changed' => 0 ),
            'only_left' => array(), 'only_right' => array(), 'changed' => array(), 'order' => null, 'duplicates' => array(),
        );
        $ignore = array_merge( $meta['ignore'], $this->extraIgnore );
        $orderedPaths = is_array($meta['ordered']) ? $meta['ordered'] : array();

        if( $meta['singleton'] )
        {
            $lo = self::unwrapSingleton($leftData);
            $ro = self::unwrapSingleton($rightData);
            $entry['counts']['left'] = $lo === null ? 0 : 1;
            $entry['counts']['right'] = $ro === null ? 0 : 1;
            if( $lo === null || $ro === null )
            {
                if( $lo !== null ) { $entry['only_left'][] = array( 'key' => '_' ); $entry['counts']['only_left'] = 1; }
                if( $ro !== null ) { $entry['only_right'][] = array( 'key' => '_' ); $entry['counts']['only_right'] = 1; }
                return $entry;
            }
            $changes = array();
            self::diffValues( $this->normalize($lo, $ignore, $orderedPaths, $meta, true), $this->normalize($ro, $ignore, $orderedPaths, $meta, false), "", $changes );
            $changes = $this->maskChanges( $changes, $meta );
            if( count($changes) > 0 )
            {
                $entry['changed'][] = array( 'key' => '_', 'changes' => $changes );
                $entry['counts']['changed'] = 1;
            }
            else
                $entry['counts']['equal'] = 1;
            return $entry;
        }

        $li = $this->indexEntries( $leftData, $meta, true, $entry );
        $ri = $this->indexEntries( $rightData, $meta, false, $entry );
        $entry['counts']['left'] = count($li);
        $entry['counts']['right'] = count($ri);

        foreach( $li as $key => $lo )
        {
            if( !isset($ri[$key]) )
            {
                $entry['only_left'][] = array( 'key' => $key, 'left_id' => $lo['id'], 'left_name' => $lo['original_key'] );
                continue;
            }
            $changes = array();
            self::diffValues( $this->normalize($lo['object'], $ignore, $orderedPaths, $meta, true),
                $this->normalize($ri[$key]['object'], $ignore, $orderedPaths, $meta, false), "", $changes );
            $changes = $this->maskChanges( $changes, $meta );
            if( count($changes) > 0 )
                $entry['changed'][] = array( 'key' => $key, 'left_id' => $lo['id'], 'right_id' => $ri[$key]['id'], 'left_name' => $lo['original_key'], 'changes' => $changes );
            else
                $entry['counts']['equal']++;
        }
        foreach( $ri as $key => $ro )
            if( !isset($li[$key]) )
                $entry['only_right'][] = array( 'key' => $key, 'right_id' => $ro['id'] );

        $entry['counts']['only_left'] = count($entry['only_left']);
        $entry['counts']['only_right'] = count($entry['only_right']);
        $entry['counts']['changed'] = count($entry['changed']);

        //order of ordered endpoints (rule bases): sequence of the common keys
        if( $meta['ordered'] === true )
        {
            $lOrder = array_values( array_filter( array_keys($li), function($k) use( $ri ){ return isset($ri[$k]); } ) );
            $rOrder = array_values( array_filter( array_keys($ri), function($k) use( $li ){ return isset($li[$k]); } ) );
            if( $lOrder !== $rOrder )
                $entry['order'] = array( 'left' => $lOrder, 'right' => $rOrder );
        }

        return $entry;
    }

    private static function unwrapSingleton( $data )
    {
        if( !is_array($data) || count($data) == 0 )
            return null;
        if( array_keys($data) === range(0, count($data) - 1) )
            return count($data) == 1 ? $data[0] : $data;
        return $data;
    }

    /**
     * key => ['object', 'id', 'original_key'] in source order; left keys are mapped with the name map
     */
    private function indexEntries( $data, $meta, $isLeft, &$entry )
    {
        $index = array();
        if( !is_array($data) )
            return $index;
        foreach( $data as $i => $obj )
        {
            $parts = array();
            foreach( $meta['key'] as $f )
            {
                $v = SCMPrismaAccessExport::get($obj, $f);
                $parts[] = is_array($v) ? json_encode($v) : (string)$v;
            }
            $original = implode("|", $parts);
            if( $original === "" || $original === str_repeat("|", count($parts) - 1) )
            {
                $original = "#" . $i;
                $this->warnings[] = $entry['area'] . "/" . $entry['endpoint'] . ": entry " . $i . " without key field(s) " . implode(",", $meta['key']) . " - compared by position";
            }
            $key = $original;
            if( $isLeft && count($meta['key']) == 1 )
            {
                $key = $this->mapName( $meta['endpoint'], $original );
                //intended rename: the key field itself is not a difference
                if( $key !== $original && is_array($obj) && SCMPrismaAccessExport::get($obj, $meta['key'][0]) !== null && strpos($meta['key'][0], ".") === false )
                    $obj[$meta['key'][0]] = $key;
            }
            if( isset($index[$key]) )
            {
                $entry['duplicates'][] = ( $isLeft ? "left: " : "right: " ) . $key;
                continue;
            }
            $index[$key] = array( 'object' => $obj, 'id' => isset($obj['id']) ? $obj['id'] : null, 'original_key' => $original );
        }
        return $index;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // normalisation

    /**
     * removes ids / owner / ignored fields, sorts keys, turns lists of named objects into maps "[name]",
     * keeps the order of ordered lists in "#order"; left objects get the name map applied to their references
     */
    public function normalize( $obj, $ignore, $orderedPaths, $meta, $isLeft )
    {
        if( !empty($meta['keep_owner']) && is_array($obj) && isset($obj['folder']) )
        {
            $folder = (string)$obj['folder'];
            if( $isLeft && isset($this->containerMap[$folder]) )
                $folder = $this->containerMap[$folder];
            $obj['assigned_folder'] = $folder;
        }
        if( $isLeft && $this->hasNameMap() && is_array($obj) )
        {
            foreach( $meta['refs'] as $path => $target )
                $obj = $this->mapRefs( $obj, explode(".", $path), $target );
        }
        return self::normalizeValue( $obj, "", $ignore, $orderedPaths );
    }

    /**
     * applies the name map to the key field and all reference fields of a (raw) object - used by the sync plan
     */
    public function translateObject( $obj, $meta )
    {
        if( !is_array($obj) || !$this->hasNameMap() )
            return $obj;
        foreach( $meta['refs'] as $path => $target )
            $obj = $this->mapRefs( $obj, explode(".", $path), $target );
        if( count($meta['key']) == 1 && strpos($meta['key'][0], ".") === false && isset($obj[$meta['key'][0]]) && is_string($obj[$meta['key'][0]]) )
            $obj[$meta['key'][0]] = $this->mapName( $meta['endpoint'], $obj[$meta['key'][0]] );
        return $obj;
    }

    /**
     * name map / container map in the other direction (right -> left)
     */
    public function invertMaps()
    {
        $inv = array();
        foreach( $this->nameMap as $area => $byEndpoint )
            foreach( $byEndpoint as $endpoint => $names )
                foreach( $names as $l => $r )
                    $inv[$area][$endpoint][$r] = $l;
        $this->nameMap = $inv;
        $this->containerMap = array_flip( $this->containerMap );
    }

    private function mapRefs( $obj, $segments, $target )
    {
        if( count($segments) == 0 )
            return is_string($obj) ? $this->mapName( $target, $obj ) : $obj;
        $seg = array_shift($segments);
        $isList = substr($seg, -2) === "[]";
        $field = $isList ? substr($seg, 0, -2) : $seg;
        if( !is_array($obj) || !array_key_exists($field, $obj) )
            return $obj;
        if( $isList && is_array($obj[$field]) )
        {
            foreach( $obj[$field] as $i => $el )
                $obj[$field][$i] = $this->mapRefs( $el, $segments, $target );
        }
        else
            $obj[$field] = $this->mapRefs( $obj[$field], $segments, $target );
        return $obj;
    }

    public static function normalizeValue( $v, $path, $ignore, $orderedPaths )
    {
        //PAN-OS encrypted value: compared by the SHA1 of the cleartext (independent of the tenant master key)
        if( is_string($v) && ($sha1 = SCMPrismaAccessExport::encryptedSha1($v)) !== null )
            return "sha1:" . $sha1;
        if( !is_array($v) )
            return $v;

        $isList = ( $v === array() ) || array_keys($v) === range(0, count($v) - 1);
        if( !$isList )
        {
            $out = array();
            foreach( $v as $k => $child )
            {
                $p = $path === "" ? (string)$k : $path . "." . $k;
                if( in_array($k, SCMPrismaAccessExport::COMPARE_IGNORE_ALWAYS, TRUE) || self::isIgnored($p, $ignore) )
                    continue;
                $out[$k] = self::normalizeValue( $child, $p, $ignore, $orderedPaths );
            }
            ksort($out, SORT_STRING);
            return $out;
        }

        //list of named objects with unique names -> map
        $names = array();
        $named = count($v) > 0;
        foreach( $v as $el )
        {
            if( !is_array($el) || !isset($el['name']) || !is_scalar($el['name']) )
            {
                $named = false;
                break;
            }
            $names[] = (string)$el['name'];
        }
        if( $named && count(array_unique($names)) == count($names) )
        {
            $out = array();
            foreach( $v as $el )
                $out["[" . $el['name'] . "]"] = self::normalizeValue( $el, $path . "[" . $el['name'] . "]", $ignore, $orderedPaths );
            ksort($out, SORT_STRING);
            if( in_array($path, $orderedPaths, TRUE) )
                $out[self::ORDER_KEY] = $names;
            return $out;
        }

        $out = array();
        foreach( $v as $el )
            $out[] = self::normalizeValue( $el, $path . "[]", $ignore, $orderedPaths );
        return $out;
    }

    private static function isIgnored( $path, $ignore )
    {
        $plain = preg_replace('/\[[^\]]*\]/', '', $path);
        foreach( $ignore as $i )
        {
            if( $plain === $i || strpos($plain, $i . ".") === 0 )
                return true;
        }
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // diff

    /**
     * changes: ['path', 'type' => changed|left_only|right_only|order|secret, 'left', 'right']
     */
    public static function diffValues( $l, $r, $path, &$changes )
    {
        if( $l === $r )
            return;

        $lAssoc = is_array($l) && $l !== array() && array_keys($l) !== range(0, count($l) - 1);
        $rAssoc = is_array($r) && $r !== array() && array_keys($r) !== range(0, count($r) - 1);

        if( $lAssoc && $rAssoc )
        {
            foreach( $l as $k => $lv )
            {
                $p = self::joinPath($path, $k);
                if( !array_key_exists($k, $r) )
                    $changes[] = array( 'path' => $p, 'type' => 'left_only', 'left' => $lv, 'right' => null );
                elseif( $k === self::ORDER_KEY )
                {
                    $common = array_values( array_intersect($lv, $r[$k]) );
                    $commonR = array_values( array_intersect($r[$k], $lv) );
                    if( $common !== $commonR )
                        $changes[] = array( 'path' => $p, 'type' => 'order', 'left' => $common, 'right' => $commonR );
                }
                else
                    self::diffValues( $lv, $r[$k], $p, $changes );
            }
            foreach( $r as $k => $rv )
                if( !array_key_exists($k, $l) )
                    $changes[] = array( 'path' => self::joinPath($path, $k), 'type' => 'right_only', 'left' => null, 'right' => $rv );
            return;
        }

        if( is_array($l) && is_array($r) && !$lAssoc && !$rAssoc )
        {
            $ls = array_map('json_encode', $l);
            $rs = array_map('json_encode', $r);
            sort($ls);
            sort($rs);
            $changes[] = array( 'path' => $path, 'type' => $ls === $rs ? 'order' : 'changed', 'left' => $l, 'right' => $r );
            return;
        }

        $changes[] = array( 'path' => $path, 'type' => 'changed', 'left' => $l, 'right' => $r );
    }

    private static function joinPath( $path, $k )
    {
        if( is_string($k) && strlen($k) > 0 && $k[0] === "[" )
            return $path . $k;
        return $path === "" ? (string)$k : $path . "." . $k;
    }

    /**
     * secret fields (endpoint metadata + generic secret field names): values replaced by MASK, type "secret"
     */
    private function maskChanges( $changes, $meta )
    {
        foreach( $changes as &$c )
        {
            $encrypted = ( is_string($c['left']) && strpos($c['left'], "sha1:") === 0 ) || ( is_string($c['right']) && strpos($c['right'], "sha1:") === 0 );
            if( $encrypted || self::isSecretPath($c['path'], $meta['secret']) )
            {
                $c['type'] = $c['type'] == 'changed' ? 'secret' : $c['type'];
                $c['left'] = $c['left'] === null ? null : self::MASK;
                $c['right'] = $c['right'] === null ? null : self::MASK;
            }
            else
            {
                $c['left'] = self::maskValue( $c['left'], $meta['secret'], $c['path'] );
                $c['right'] = self::maskValue( $c['right'], $meta['secret'], $c['path'] );
            }
        }
        return $changes;
    }

    public static function isSecretPath( $path, $secretPaths )
    {
        $plain = preg_replace('/\[[^\]]*\]/', '', $path);
        foreach( $secretPaths as $s )
            if( $plain === $s || strpos($plain, $s . ".") === 0 )
                return true;
        $parts = explode(".", $plain);
        $last = end($parts);
        return preg_match(SCMPrismaAccessExport::SECRET_KEY_PATTERN, $last) && !preg_match(SCMPrismaAccessExport::SECRET_KEY_EXCLUDE, $last);
    }

    /**
     * masks secrets inside a structured value (e.g. a whole sub object only present on one side)
     */
    private static function maskValue( $v, $secretPaths, $path )
    {
        if( !is_array($v) )
            return $v;
        foreach( $v as $k => $child )
        {
            $p = self::joinPath($path, $k);
            if( !is_array($child) && $child !== null && ( self::isSecretPath($p, $secretPaths) || ( is_string($child) && strpos($child, "sha1:") === 0 ) ) )
                $v[$k] = self::MASK;
            else
                $v[$k] = self::maskValue( $child, $secretPaths, $p );
        }
        return $v;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // hierarchy

    public function compareHierarchy( $l, $r )
    {
        $result = array( 'folders_only_left' => array(), 'folders_only_right' => array(), 'folders_changed' => array(),
            'snippets_only_left' => array(), 'snippets_only_right' => array() );
        $map = function( $name ){ return isset($this->containerMap[$name]) ? $this->containerMap[$name] : $name; };

        $lf = array();
        foreach( $l['folders'] as $f )
            $lf[ $map($f['name']) ] = $f;
        $rf = array();
        foreach( $r['folders'] as $f )
            $rf[ $f['name'] ] = $f;

        foreach( $lf as $name => $f )
        {
            if( !isset($rf[$name]) )
            {
                $result['folders_only_left'][] = $name;
                continue;
            }
            $changes = array();
            $lp = $f['parent'] === null ? null : $map($f['parent']);
            if( $lp !== $rf[$name]['parent'] )
                $changes[] = array( 'path' => 'parent', 'type' => 'changed', 'left' => $lp, 'right' => $rf[$name]['parent'] );
            if( $f['type'] !== $rf[$name]['type'] )
                $changes[] = array( 'path' => 'type', 'type' => 'changed', 'left' => $f['type'], 'right' => $rf[$name]['type'] );
            $ls = array_map( $map, $f['snippets'] );
            if( $ls !== $rf[$name]['snippets'] )
            {
                $a = $ls; $b = $rf[$name]['snippets'];
                sort($a); sort($b);
                $changes[] = array( 'path' => 'snippets', 'type' => $a === $b ? 'order' : 'changed', 'left' => $ls, 'right' => $rf[$name]['snippets'] );
            }
            if( count($changes) > 0 )
                $result['folders_changed'][] = array( 'folder' => $name, 'changes' => $changes );
        }
        foreach( $rf as $name => $f )
            if( !isset($lf[$name]) )
                $result['folders_only_right'][] = $name;

        $ls = array();
        foreach( $l['snippets'] as $s )
            $ls[ $map($s['name']) ] = true;
        $rs = array();
        foreach( $r['snippets'] as $s )
            $rs[ $s['name'] ] = true;
        $result['snippets_only_left'] = array_values( array_diff( array_keys($ls), array_keys($rs) ) );
        $result['snippets_only_right'] = array_values( array_diff( array_keys($rs), array_keys($ls) ) );
        return $result;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // output

    public function summary()
    {
        $areas = array();
        foreach( $this->entries as $e )
        {
            $a = $e['area'];
            if( !isset($areas[$a]) )
                $areas[$a] = array( 'endpoints' => 0, 'endpoints_with_differences' => 0, 'equal' => 0, 'only_left' => 0, 'only_right' => 0, 'changed' => 0, 'order' => 0 );
            $areas[$a]['endpoints']++;
            foreach( array('equal', 'only_left', 'only_right', 'changed') as $c )
                $areas[$a][$c] += $e['counts'][$c];
            if( $e['order'] !== null )
                $areas[$a]['order']++;
            if( self::hasDifferences($e) )
                $areas[$a]['endpoints_with_differences']++;
        }
        $hierarchyDiffs = 0;
        if( $this->hierarchy !== null )
            foreach( $this->hierarchy as $list )
                $hierarchyDiffs += count($list);
        return array( 'areas' => $areas, 'hierarchy_differences' => $hierarchyDiffs, 'not_comparable' => count($this->notComparable),
            'identical' => $hierarchyDiffs == 0 && array_sum( array_map( function($a){ return $a['endpoints_with_differences']; }, $areas ) ) == 0 );
    }

    public static function hasDifferences( $e )
    {
        return $e['counts']['only_left'] + $e['counts']['only_right'] + $e['counts']['changed'] > 0 || $e['order'] !== null;
    }

    private static function side( $manifest, $dir )
    {
        return array( 'dir' => $dir, 'tsg_id' => isset($manifest['tsg_id']) ? $manifest['tsg_id'] : null,
            'created_at' => isset($manifest['created_at']) ? $manifest['created_at'] : null,
            'areas' => isset($manifest['areas']) ? $manifest['areas'] : null,
            'format_version' => isset($manifest['format_version']) ? $manifest['format_version'] : null );
    }

    public function write( $outDir )
    {
        if( !is_dir($outDir) && !mkdir($outDir, 0700, TRUE) )
            derr( "not possible to create " . $outDir, null, FALSE );

        $summary = $this->summary();
        $diff = array(
            'format_version' => self::FORMAT_VERSION,
            'tool' => 'pan-os-php scm_pa_compare.php',
            'created_at' => date('c'),
            'left' => self::side($this->leftManifest, $this->leftDir),
            'right' => self::side($this->rightManifest, $this->rightDir),
            'options' => array( 'filter' => $this->filter, 'extra_ignore' => $this->extraIgnore,
                'name_map' => $this->nameMap, 'container_map' => $this->containerMap ),
            'summary' => $summary,
            'hierarchy' => $this->hierarchy,
            'entries' => array_values( array_filter( $this->entries, array(__CLASS__, 'hasDifferences') ) ),
            'equal_endpoints' => array_values( array_map( function($e){ return $e['area'] . "/" . ( $e['container'] ? $e['container'] . "/" : "" ) . $e['endpoint']; },
                array_filter( $this->entries, function($e){ return !self::hasDifferences($e); } ) ) ),
            'not_comparable' => $this->notComparable,
            'warnings' => array_values( array_unique($this->warnings) ),
        );
        file_put_contents( $outDir . "/diff.json", json_encode( $diff, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );

        $fh = fopen( $outDir . "/diff-summary.csv", "w" );
        fputcsv( $fh, array('area', 'container', 'endpoint', 'left', 'right', 'equal', 'only_left', 'only_right', 'changed', 'order_changed'), ',', '"', '' );
        foreach( $this->entries as $e )
            fputcsv( $fh, array( $e['area'], $e['container'], $e['endpoint'], $e['counts']['left'], $e['counts']['right'], $e['counts']['equal'],
                $e['counts']['only_left'], $e['counts']['only_right'], $e['counts']['changed'], $e['order'] !== null ? 'yes' : '' ), ',', '"', '' );
        fclose( $fh );

        file_put_contents( $outDir . "/DIFF_REPORT.md", $this->reportMarkdown( $diff ) );

        return $diff;
    }

    private static function short( $v, $len = 80 )
    {
        if( $v === null )
            return "–";
        $s = is_scalar($v) ? ( is_bool($v) ? ( $v ? "true" : "false" ) : (string)$v ) : json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $s = str_replace( array("|", "\n", "\r"), array("\\|", " ", " "), $s );
        return mb_strlen($s) > $len ? mb_substr($s, 0, $len) . "…" : $s;
    }

    private function listLine( $items )
    {
        $shown = array_slice($items, 0, $this->reportMaxItems);
        $line = implode(", ", array_map( function($i){ return "`" . str_replace("`", "'", $i) . "`"; }, $shown ));
        if( count($items) > $this->reportMaxItems )
            $line .= " … (+" . (count($items) - $this->reportMaxItems) . ", see diff.json)";
        return $line;
    }

    public function reportMarkdown( $diff )
    {
        $L = $diff['left'];
        $R = $diff['right'];
        $md = "# Prisma Access compare report\n\n";
        $md .= "| | left | right |\n|---|---|---|\n";
        $md .= "| TSG | " . $L['tsg_id'] . " | " . $R['tsg_id'] . " |\n";
        $md .= "| export created | " . $L['created_at'] . " | " . $R['created_at'] . " |\n";
        $md .= "| areas | " . implode(", ", (array)$L['areas']) . " | " . implode(", ", (array)$R['areas']) . " |\n";
        $md .= "| directory | `" . $L['dir'] . "` | `" . $R['dir'] . "` |\n\n";
        $md .= "Generated " . $diff['created_at'] . " by scm_pa_compare.php. Secrets are compared but shown as `" . self::MASK . "`. ";
        $md .= "Ignored everywhere: " . implode(", ", SCMPrismaAccessExport::COMPARE_IGNORE_ALWAYS) . ( count($this->extraIgnore) ? ", " . implode(", ", $this->extraIgnore) : "" ) . ".\n";
        if( count($this->nameMap) || count($this->containerMap) )
            $md .= "A name map was applied to the left side (see diff.json → options).\n";
        $md .= "\n";

        $s = $diff['summary'];
        $md .= "## Summary\n\n";
        $md .= $s['identical'] ? "**No differences.**\n\n" : "";
        $md .= "| area | endpoints | with differences | equal | only left | only right | changed | order changed |\n|---|---|---|---|---|---|---|---|\n";
        foreach( $s['areas'] as $a => $c )
            $md .= "| " . $a . " | " . $c['endpoints'] . " | " . $c['endpoints_with_differences'] . " | " . $c['equal'] . " | " . $c['only_left'] . " | " . $c['only_right'] . " | " . $c['changed'] . " | " . $c['order'] . " |\n";
        $md .= "\nHierarchy differences: " . $s['hierarchy_differences'] . " · not comparable: " . $s['not_comparable'] . "\n\n";

        if( $diff['hierarchy'] !== null && $s['hierarchy_differences'] > 0 )
        {
            $h = $diff['hierarchy'];
            $md .= "## Folder / snippet hierarchy\n\n";
            foreach( array( 'folders_only_left' => 'Folders only in left', 'folders_only_right' => 'Folders only in right',
                'snippets_only_left' => 'Snippets only in left', 'snippets_only_right' => 'Snippets only in right' ) as $k => $title )
                if( count($h[$k]) > 0 )
                    $md .= "- **" . $title . ":** " . $this->listLine($h[$k]) . "\n";
            foreach( $h['folders_changed'] as $fc )
                foreach( $fc['changes'] as $c )
                    $md .= "- **Folder `" . $fc['folder'] . "` " . $c['path'] . "** (" . $c['type'] . "): left " . self::short($c['left'], 200) . " → right " . self::short($c['right'], 200) . "\n";
            $md .= "\n";
        }

        $currentArea = null;
        foreach( $diff['entries'] as $e )
        {
            if( $e['area'] !== $currentArea )
            {
                $md .= "## " . $e['area'] . "\n\n";
                $currentArea = $e['area'];
            }
            $title = ( $e['container'] ? $e['container'] . " / " : "" ) . $e['endpoint'];
            $c = $e['counts'];
            $md .= "### " . $title . "\n\n";
            $md .= "left " . $c['left'] . " · right " . $c['right'] . " · equal " . $c['equal'] . " · only left " . $c['only_left'] . " · only right " . $c['only_right'] . " · changed " . $c['changed'] . "\n\n";
            if( count($e['only_left']) > 0 )
                $md .= "- **Only in left:** " . $this->listLine( array_map( function($i){ return $i['key']; }, $e['only_left'] ) ) . "\n";
            if( count($e['only_right']) > 0 )
                $md .= "- **Only in right:** " . $this->listLine( array_map( function($i){ return $i['key']; }, $e['only_right'] ) ) . "\n";
            if( count($e['duplicates']) > 0 )
                $md .= "- **Duplicate keys (first one compared):** " . $this->listLine($e['duplicates']) . "\n";
            if( $e['order'] !== null )
                $md .= "- **Order differs.** left: " . self::short( implode(" → ", $e['order']['left']), 300 ) . " · right: " . self::short( implode(" → ", $e['order']['right']), 300 ) . "\n";
            if( count($e['changed']) > 0 )
            {
                $md .= "\n| entry | field | type | left | right |\n|---|---|---|---|---|\n";
                $shownEntries = array_slice( $e['changed'], 0, $this->reportMaxItems );
                foreach( $shownEntries as $ch )
                {
                    $name = $ch['key'] . ( isset($ch['left_name']) && $ch['left_name'] !== $ch['key'] ? " (left: " . $ch['left_name'] . ")" : "" );
                    foreach( array_slice($ch['changes'], 0, $this->reportMaxChanges) as $fc )
                        $md .= "| " . self::short($name, 60) . " | `" . self::short($fc['path'] === "" ? "(value)" : $fc['path'], 70) . "` | " . $fc['type'] . " | " . self::short($fc['left']) . " | " . self::short($fc['right']) . " |\n";
                    if( count($ch['changes']) > $this->reportMaxChanges )
                        $md .= "| " . self::short($name, 60) . " | … | | +" . (count($ch['changes']) - $this->reportMaxChanges) . " more, see diff.json | |\n";
                }
                if( count($e['changed']) > $this->reportMaxItems )
                    $md .= "\n… +" . (count($e['changed']) - $this->reportMaxItems) . " changed entries, see diff.json\n";
            }
            $md .= "\n";
        }

        if( count($diff['not_comparable']) > 0 )
        {
            $md .= "## Not comparable\n\n| area | container | endpoint | reason |\n|---|---|---|---|\n";
            foreach( $diff['not_comparable'] as $n )
                $md .= "| " . $n['area'] . " | " . ( $n['container'] ?: "" ) . " | " . $n['endpoint'] . " | " . $n['reason'] . " |\n";
            $md .= "\n";
        }
        if( count($diff['warnings']) > 0 )
        {
            $md .= "## Warnings\n\n";
            foreach( array_slice($diff['warnings'], 0, 100) as $w )
                $md .= "- " . $w . "\n";
            $md .= "\n";
        }
        $md .= "Equal endpoints: " . count($diff['equal_endpoints']) . " (listed in diff.json → equal_endpoints).\n";
        return $md;
    }
}
