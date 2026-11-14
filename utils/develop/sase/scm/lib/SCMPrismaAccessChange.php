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

require_once(dirname(__FILE__) . "/SCMPrismaAccessExport.php");
require_once(dirname(__FILE__) . "/SCMPrismaAccessCompare.php");
require_once(dirname(__FILE__) . "/SCMPrismaAccessSync.php");

/**
 * One-step change of an SCM tenant from a small change request file (scm_pa_change.php):
 *
 *   change request ──► export (only the affected containers / types) = "ist"
 *                  ──► "soll" = ist + changes (built here, no manual editing)
 *                  ──► compare soll ↔ ist ──► sync plan ──► apply dry-run
 *                  ──► [execute] apply ──► [push] ──► export again ──► verification per change
 *
 * It only chains the existing building blocks (SCMPrismaAccessExport, SCMPrismaAccessCompare, SCMPrismaAccessSync).
 * See README_pa_change.md for the file format.
 */
class SCMPrismaAccessChange
{
    const FORMAT = 'pan-os-php-scm-change-request';

    /** groups of config types that can be changed (network and device settings: sync workflow) */
    const SUPPORTED_GROUPS = array( 'objects', 'identity', 'policies' );
    /** single types of other groups (zones: with the rules that use them, e.g. Panorama device-group import) */
    const SUPPORTED_TYPES = array( 'zones', 'zone-protection-profiles', 'interface-management-profiles', 'ethernet-interfaces',
        'layer2-subinterfaces', 'layer3-subinterfaces', 'loopback-interfaces', 'tunnel-interfaces', 'vlan-interfaces' );

    /** folders below this one may be created (own folders exist only under "All Firewalls") */
    const NGFW_ROOT = 'ngfw-shared';

    /** folder levels below NGFW_ROOT (as Panorama: max. 4 device-group levels below shared) */
    const MAX_FOLDER_DEPTH = 4;

    /** directives in an entry - everything else is a field of the object */
    const DIRECTIVES = array( '_type', '_delete', '_append', '_remove', '_comment', '_internal' );

    /**
     * _internal: profile sections the public API does not have, written through the internal UI API after the public
     * create / update (HAR 2026-11-14: POST /api/config/v9.2/multiConfigure, command edit, complete entry)
     * prefix => internal object type (read back: GET /api/config/v9.2/Objects/<type>?folder=&type=&name=)
     */
    const INTERNAL_TYPES = array(
        'profiles/vulnerability' => 'VulnerabilityProtectionSecurityProfiles',
        'profiles/spyware' => 'AntiSpywareSecurityProfiles',
        'profiles/dns-security' => 'DnsSecurityProfiles',
        'profiles/virus-and-wildfire-analysis' => 'WildFireAndAntivirusSecurityProfiles',
    );

    /** folder / snippet fields only returned by the single GET, not by the list */
    const DETAIL_FIELDS = array( 'description', 'labels' );

    public $connector;
    public $tsg;
    public $outdir;
    public $runDir;
    public $options = array( 'parallel' => 8, 'page_size' => 1000, 'ui_api_host' => SCMPrismaAccessExport::UI_API_HOST_DEFAULT );
    /** internal UI API steps: dry-run / execute results */
    public $internalDry = array();
    public $internalLog = array();

    /** normalized change request: folders[], snippets[], objects[] */
    public $request;
    public $errors = array();
    /** from the change file (not sent): incomplete objects / objects not importable */
    public $incomplete = array();
    public $notImported = array();
    public $placeholders = array();
    public $warnings = array();

    /** per change: what was done in soll (create / update / delete / unchanged / absent) */
    public $changes = array();

    public $istDir;
    public $sollDir;
    public $compareDir;
    public $plan;
    public $planFile;
    public $dryRunLog;

    private $types = array();     // name => config type

    public function __construct( $connector, $tsg, $outdir )
    {
        $this->connector = $connector;
        $this->tsg = $tsg;
        $this->outdir = $outdir;
        foreach( SCMPrismaAccessExport::getConfigTypes() as $t )
            $this->types[$t['name']] = $t;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // change request

    /**
     * reads and normalizes the change request. Accepted:
     *   { "folders": [..], "snippets": [..], "objects": [ { "type": "addresses", "folder": "x", "name": "y", ... } ] }
     *   and as shorthand a list per type: { "addresses": [ { "folder": "x", "name": "y", ... } ] }
     */
    public function loadRequest( $file )
    {
        if( !is_readable($file) )
            return $this->fail( "change file not readable: " . $file );
        $j = json_decode( file_get_contents($file), TRUE );
        if( !is_array($j) )
            return $this->fail( "change file is not valid JSON: " . $file . " (" . json_last_error_msg() . ")" );
        return $this->setRequest( $j );
    }

    public function setRequest( $j )
    {
        $req = array( 'folders' => array(), 'snippets' => array(), 'objects' => array() );
        //generated change files (e.g. Panorama import): objects imported without part of their content / references
        $this->incomplete = isset($j['incomplete']) && is_array($j['incomplete']) ? $j['incomplete'] : array();
        $this->notImported = isset($j['not_imported']) && is_array($j['not_imported']) ? $j['not_imported'] : array();
        $this->placeholders = isset($j['placeholders']) && is_array($j['placeholders']) ? $j['placeholders'] : array();
        foreach( $j as $key => $list )
        {
            if( in_array($key, array('format', 'version', 'description', 'comment', '_comment', 'source', 'not_imported', 'incomplete', 'placeholders', 'warnings', 'interface_variables', 'firewalls'), TRUE) )
                continue;
            if( !is_array($list) || ( count($list) > 0 && array_keys($list) !== range(0, count($list) - 1) ) )
            {
                $this->errors[] = "'" . $key . "' must be a list";
                continue;
            }
            if( $key == 'folders' || $key == 'snippets' )
                $req[$key] = array_merge( $req[$key], $list );
            // the config type of an entry is kept in '_type': 'type' is also an SCM field (url-categories,
            // applications …) and must reach the API unchanged
            elseif( $key == 'objects' )
                foreach( $list as $e )
                {
                    // 'objects' list: "type" is the config type; the SCM field 'type' then needs "_type" for the config type
                    if( is_array($e) && !isset($e['_type']) && isset($e['_type']) )
                    {
                        $e['_type'] = $e['_type'];
                        unset( $e['_type'] );
                    }
                    $req['objects'][] = $e;
                }
            elseif( isset($this->types[$key]) )
                foreach( $list as $e )
                    $req['objects'][] = is_array($e) ? array( '_type' => $key ) + $e : $e;
            else
                $this->errors[] = "unknown key '" . $key . "' - use folders, snippets, objects or a config type (e.g. addresses)";
        }
        $this->request = $req;
        $this->validateEntries();
        return count($this->errors) == 0;
    }

    /** checks that need no tenant data */
    private function validateEntries()
    {
        foreach( array('folders', 'snippets') as $kind )
            foreach( $this->request[$kind] as $i => $e )
            {
                $where = $kind . "[" . $i . "]";
                if( !is_array($e) || !isset($e['name']) || !is_string($e['name']) || $e['name'] === "" )
                {
                    $this->errors[] = $where . ": name missing";
                    continue;
                }
                if( !empty($e['_delete']) )
                    $this->errors[] = $where . " " . $e['name'] . ": deleting " . $kind . " is not supported here (delete in SCM)";
                if( $kind == 'folders' && isset($e['_append']) || $kind == 'folders' && isset($e['_remove']) )
                    $this->errors[] = $where . " " . $e['name'] . ": _append / _remove are not supported for folders";
                if( $kind == 'snippets' && ( isset($e['_append']) || isset($e['_remove']) ) )
                    $this->errors[] = $where . " " . $e['name'] . ": _append / _remove are not supported for snippets";
            }

        foreach( $this->request['objects'] as $i => $e )
        {
            $where = "objects[" . $i . "]";
            if( !is_array($e) )
            {
                $this->errors[] = $where . ": not an object";
                continue;
            }
            if( !isset($e['_type']) || !isset($this->types[$e['_type']]) )
            {
                $this->errors[] = $where . ": unknown or missing type '" . ( isset($e['_type']) ? $e['_type'] : '' ) . "'";
                continue;
            }
            $t = $this->types[$e['_type']];
            if( !in_array($t['group'], self::SUPPORTED_GROUPS, TRUE) && !in_array($t['name'], self::SUPPORTED_TYPES, TRUE) )
                $this->errors[] = $where . ": type " . $e['_type'] . " (" . $t['group'] . ") is not supported by scm_pa_change.php - use the sync workflow (export, edit, compare, scm_pa_sync.php)";
            if( !empty($t['position']) )
            {
                if( isset($e['snippet']) && isset($e['position']) )
                    $this->errors[] = $where . " " . ( isset($e['name']) ? $e['name'] : '' ) . ": snippets have one rule base - no position";
                elseif( isset($e['folder']) && isset($e['position']) && !in_array($e['position'], array('pre', 'post'), TRUE) )
                    $this->errors[] = $where . " " . ( isset($e['name']) ? $e['name'] : '' ) . ": position must be pre or post";
            }
            elseif( isset($e['position']) )
                $this->errors[] = $where . ": position only for rule bases";
            if( !isset($e['name']) || !is_string($e['name']) || $e['name'] === "" )
                $this->errors[] = $where . ": name missing";
            if( isset($e['folder']) === isset($e['snippet']) )
                $this->errors[] = $where . " " . ( isset($e['name']) ? $e['name'] : '' ) . ": exactly one of folder / snippet is required";
            foreach( array('_append', '_remove') as $d )
                if( isset($e[$d]) )
                {
                    if( !is_array($e[$d]) || count($e[$d]) == 0 || array_keys($e[$d]) === range(0, count($e[$d]) - 1) )
                        $this->errors[] = $where . ": " . $d . " must be an object { field: [values] }";
                    else
                        foreach( $e[$d] as $f => $v )
                            if( !is_array($v) || array_keys($v) !== range(0, count($v) - 1) )
                                $this->errors[] = $where . ": " . $d . "." . $f . " must be a list";
                }
            if( !empty($e['_delete']) && ( count( array_diff_key( self::fields($e), array_flip( array('name', 'folder', 'snippet', 'position') ) ) ) > 0 || isset($e['_append']) || isset($e['_remove']) ) )
                $this->errors[] = $where . " " . $e['name'] . ": _delete together with fields";
            foreach( array_keys($e) as $k )
                if( $k !== '' && $k[0] == '_' && !in_array($k, self::DIRECTIVES, TRUE) )
                    $this->errors[] = $where . ": unknown directive " . $k;
            if( isset($e['_internal']) )
            {
                $in = $e['_internal'];
                if( !is_array($in) || !isset($in['prefix']) || !isset(self::INTERNAL_TYPES[$in['prefix']]) || !isset($in['entry']) || !is_array($in['entry']) )
                    $this->errors[] = $where . ": _internal needs prefix (" . implode(", ", array_keys(self::INTERNAL_TYPES)) . ") and entry";
                elseif( isset($e['snippet']) )
                    $this->errors[] = $where . ": _internal only for objects in folders";
                elseif( !empty($e['_delete']) )
                    $this->errors[] = $where . ": _internal together with _delete";
            }
            foreach( array('id', 'folder_id', 'snippet_id') as $k )
                if( isset($e[$k]) )
                    $this->errors[] = $where . ": field " . $k . " is set by SCM - remove it";
        }
    }

    /** types / containers the export has to cover */
    public function scope()
    {
        $types = array();
        $containers = array();
        foreach( $this->request['objects'] as $e )
        {
            $types[$e['_type']] = true;
            $containers[ isset($e['folder']) ? $e['folder'] : $e['snippet'] ] = true;
        }
        foreach( $this->request['folders'] as $f )
            $containers[$f['name']] = true;
        foreach( $this->request['snippets'] as $s )
            $containers[$s['name']] = true;
        return array( 'types' => array_keys($types), 'containers' => array_keys($containers) );
    }

    public function hasDeletes()
    {
        foreach( $this->request['objects'] as $e )
            if( !empty($e['_delete']) )
                return true;
        return false;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // run

    /** export "ist" (or a verification export) of exactly the scope of the request */
    public function export( $label )
    {
        $scope = $this->scope();
        // heavy types (applications: the list answer contains the predefined catalog of every folder) are not
        // exported as list - only the objects of the request are looked up by name
        $lookupTypes = array_values( array_intersect( $scope['types'], SCMPrismaAccessExport::CONFIG_HEAVY_TYPES ) );
        $listTypes = array_values( array_diff( $scope['types'], $lookupTypes ) );
        $e = new SCMPrismaAccessExport( $this->connector, $this->tsg, $this->outdir, null, array( SCMPrismaAccessExport::AREA_CONFIG ) );
        $e->configOptions = array(
            'containers' => $scope['containers'],
            'types' => count($listTypes) > 0 ? $listTypes : array( '-' ),
            'scope' => null,
            'mode' => 'all',
            'devices' => false,
            'predefined_snippets' => false,
            'heavy_types' => false,
            'parallel' => $this->options['parallel'],
            'page_size' => $this->options['page_size'],
        );
        $dir = $e->prepareDirectory( basename($this->runDir) . "/" . $label );
        $e->exportEndpoints();
        $e->exportConfig();
        $e->writeManifest( PH::frameworkVersion() );
        $this->addDetailFields( $dir );
        if( count($lookupTypes) > 0 )
            $this->lookupByName( $dir, $lookupTypes );
        return $dir;
    }

    /** objects of the request of these types: GET <path>?folder|snippet=&name= per object, written like an export */
    private function lookupByName( $dir, array $types )
    {
        $manifest = json_decode( file_get_contents($dir . "/manifest.json"), TRUE );
        $wanted = array();
        foreach( $this->request['objects'] as $o )
            if( in_array($o['_type'], $types, TRUE) )
            {
                $kind = isset($o['folder']) ? 'folder' : 'snippet';
                $wanted[$o['_type'] . "|" . $kind . "|" . $o[$kind]][] = $o['name'];
            }
        $n = 0;
        foreach( $wanted as $k => $names )
        {
            list($type, $kind, $cName) = explode("|", $k, 3);
            $t = $this->types[$type];
            $data = array();
            foreach( array_unique($names) as $name )
            {
                $url = $this->connector->url_api . $t['path'] . "?" . http_build_query( array( $kind => $cName, 'name' => $name ), '', '&', PHP_QUERY_RFC3986 );
                $r = $this->connector->sendSCMAPIRequest( "GET", $url, false, FALSE );
                $n++;
                if( !is_array($r['json']) )
                    continue;
                $list = isset($r['json']['data']) ? $r['json']['data'] : ( isset($r['json']['name']) ? array( $r['json'] ) : array() );
                foreach( $list as $obj )
                    if( is_array($obj) && isset($obj['name']) && $obj['name'] === $name && isset($obj[$kind]) && $obj[$kind] === $cName )
                        $data[] = $obj;
            }
            $file = SCMPrismaAccessExport::AREA_CONFIG . "/" . $kind . "s/" . SCMPrismaAccessExport::slug($cName) . "/" . sprintf("%02d", $t['order']) . "_" . $type . ".json";
            if( !is_dir( dirname($dir . "/" . $file) ) )
                mkdir( dirname($dir . "/" . $file), 0700, TRUE );
            $this->writeJson( $dir . "/" . $file, array( 'endpoint' => $type, 'area' => SCMPrismaAccessExport::AREA_CONFIG,
                'url' => $t['path'] . "?" . $kind . "=" . rawurlencode($cName), 'tsg_id' => $this->tsg, 'fetched_at' => date('c'),
                'http_code' => 200, 'status' => 'ok', 'error' => null, 'container' => $cName, 'container_kind' => $kind,
                'fetched_as' => 'by name (scm_pa_change.php)', 'data' => $data ) );
            $manifest['endpoints'][] = array( 'area' => SCMPrismaAccessExport::AREA_CONFIG, 'order' => $t['order'], 'name' => $type,
                'group' => $t['group'], 'container' => $cName, 'container_kind' => $kind, 'category' => 'dependency', 'scope' => $kind,
                'optional' => true, 'url' => $t['path'] . "?" . $kind . "=" . rawurlencode($cName), 'depends_on' => array(),
                'fetched_as' => 'by name', 'file' => $file, 'http_code' => 200, 'fetched_at' => date('c'), 'status' => 'ok', 'count' => count($data) );
        }
        $opt = isset($manifest['config']['options']['types']) && is_array($manifest['config']['options']['types']) ? $manifest['config']['options']['types'] : array();
        $manifest['config']['options']['types'] = array_values( array_unique( array_merge( array_diff($opt, array('-')), $types ) ) );
        $this->writeJson( $dir . "/manifest.json", $manifest );
        PH::print_stdout( " - [config] " . implode(", ", $types) . ": " . $n . " lookup(s) by name (no list export - predefined catalog)" );
    }

    /**
     * the folder / snippet list does not return description / labels (live 2026-11-13), the single GET does:
     * add them for the folders / snippets of the request, so that compare, plan and verification see them
     */
    private function addDetailFields( $dir )
    {
        foreach( array( 'folders' => '01_folders.json', 'snippets' => '02_snippets.json' ) as $kind => $file )
        {
            if( count($this->request[$kind]) == 0 )
                continue;
            $path = $dir . "/config/" . $file;
            $list = $this->readData( $path );
            if( $list === null )
                continue;
            $changed = false;
            foreach( $this->request[$kind] as $req )
            {
                $i = self::indexByName( $list, $req['name'] );
                if( $i === null || !isset($list[$i]['id']) )
                    continue;
                $missing = array_diff( self::DETAIL_FIELDS, array_keys($list[$i]) );
                if( count($missing) == 0 )
                    continue;
                $r = $this->connector->sendSCMAPIRequest( "GET", rtrim($this->connector->url_api, "/") . "/config/setup/v1/" . $kind . "/" . rawurlencode($list[$i]['id']), false, FALSE );
                if( $r['errors'] !== null || !is_array($r['json']) )
                {
                    $this->warnings[] = $kind . " " . $req['name'] . ": single GET failed (HTTP " . $r['http_code'] . ") - " . implode(", ", $missing) . " not known";
                    continue;
                }
                $obj = isset($r['json']['data'][0]) ? $r['json']['data'][0] : $r['json'];
                foreach( $missing as $f )
                    if( array_key_exists($f, $obj) )
                    {
                        $list[$i][$f] = $obj[$f];
                        $changed = true;
                    }
            }
            if( $changed )
                $this->writeData( $path, $list );
        }
    }

    /**
     * dry-run part: export, soll, compare, plan, apply dry-run. Returns false on errors ($this->errors).
     */
    public function prepare()
    {
        $this->runDir = $this->outdir . "/" . $this->tsg . "/change-" . date('Ymd-His');
        $this->istDir = $this->export( 'ist' );
        if( !$this->buildSoll() )
            return false;

        $this->compareDir = $this->runDir . "/compare";
        $cmp = new SCMPrismaAccessCompare( $this->sollDir, $this->istDir );
        $cmp->filter = array( 'areas' => array( SCMPrismaAccessExport::AREA_CONFIG ), 'containers' => null, 'types' => null );
        $cmp->run();
        $cmp->write( $this->compareDir );

        $sync = new SCMPrismaAccessSync( $this->compareDir . "/diff.json", array(
            'source' => 'left',
            'mode' => $this->hasDeletes() ? 'mirror' : 'additive',
            'allow_delete' => $this->hasDeletes(),
            'allow_infra' => false,
            //zones are the only network type a change request can contain
            'allow_network' => count( array_intersect( self::SUPPORTED_TYPES, $this->scope()['types'] ) ) > 0,
            'areas' => array( SCMPrismaAccessExport::AREA_CONFIG ),
            'containers' => null,
            'types' => null,
        ) );
        $plans = $sync->buildPlans();
        $this->plan = $plans[0];
        SCMPrismaAccessSync::writePlan( $this->plan, $this->runDir );
        $this->planFile = $this->runDir . "/plan.json";

        $this->dryRunLog = SCMPrismaAccessSync::apply( $this->connector, $this->plan, array( 'execute' => false ) );
        $this->writeJson( $this->runDir . "/apply-log-dry-run.json", $this->dryRunLog );
        $this->internalDry = $this->internalApply( false );
        if( count($this->internalDry) > 0 )
            $this->writeJson( $this->runDir . "/internal-dry-run.json", $this->internalDry );
        return true;
    }

    /** sends the plan, then the internal UI API edits; optional push of the touched folders (after both) */
    public function execute( $push = false, $continueOnError = false, $progress = null )
    {
        $log = SCMPrismaAccessSync::apply( $this->connector, $this->plan, array( 'execute' => true, 'push' => false, 'continue_on_error' => $continueOnError,
            'progress' => $progress ) );
        $this->internalLog = $this->internalApply( true, $progress );
        $log['internal'] = $this->internalLog;
        if( $push )
        {
            $folders = $log['folders'];
            foreach( $this->internalLog as $r )
                if( $r['status'] == 'done' && !in_array($r['folder'], $folders, TRUE) )
                    $folders[] = $r['folder'];
            $log['push'] = SCMPrismaAccessSync::push( $this->connector, $folders, true );
        }
        $this->writeJson( $this->runDir . "/apply-log-execute.json", $log );
        return $log;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // internal UI API

    /** objects of the request with _internal */
    private function internalTasks()
    {
        $tasks = array();
        foreach( $this->request['objects'] as $e )
            if( isset($e['_internal']) && isset($e['folder']) && empty($e['_delete']) )
                $tasks[] = $e;
        return $tasks;
    }

    private function internalFolderType( $folder )
    {
        return in_array( $folder, SCMPrismaAccessExport::PA_DEPLOYMENT_FOLDERS, TRUE ) ? 'cloud' : 'container';
    }

    /** live entry of the internal UI API; null = not found, false = error */
    public function internalGet( $prefix, $folder, $name )
    {
        $url = "https://" . $this->options['ui_api_host'] . "/api/config/v9.2/Objects/" . self::INTERNAL_TYPES[$prefix] . "?"
            . http_build_query( array( 'folder' => $folder, 'type' => $this->internalFolderType($folder), 'name' => $name ), '', '&', PHP_QUERY_RFC3986 );
        $r = $this->connector->sendSCMAPIRequest( "GET", $url, false, FALSE );
        if( $r['http_code'] == 404 )
            return null;
        if( $r['errors'] !== null || !is_array($r['json']) )
            return false;
        $entries = isset($r['json']['result']['entry']) ? $r['json']['result']['entry'] : array();
        if( isset($entries['@name']) )
            $entries = array( $entries );
        foreach( (array)$entries as $en )
            if( is_array($en) && isset($en['@name']) && $en['@name'] === $name )
                return $en;
        return null;
    }

    /** differences between the wanted entry and the live entry (sections of the wanted entry only, @ meta data ignored) */
    public static function internalDiff( $want, $live, $path = '' )
    {
        $diffs = array();
        foreach( $want as $k => $v )
        {
            if( is_string($k) && $k !== '' && $k[0] == '@' )
                continue;
            if( !is_array($live) || !array_key_exists($k, $live) )
            {
                $diffs[] = $path . $k . " missing";
                continue;
            }
            if( self::internalNorm($v) !== self::internalNorm($live[$k]) )
                $diffs[] = $path . $k;
        }
        return $diffs;
    }

    private static function internalNorm( $v )
    {
        if( is_object($v) )
            $v = (array)$v;
        if( !is_array($v) )
            return json_encode( (string)$v );
        if( count($v) == 0 )
            return '{}';
        $out = array();
        foreach( $v as $k => $x )
            if( !( is_string($k) && $k !== '' && $k[0] == '@' && $k !== '@name' ) )
                $out[$k] = self::internalNorm($x);
        if( array_keys($out) !== range(0, count($out) - 1) )
            ksort( $out );
        return json_encode( $out );
    }

    /** PHP arrays from JSON: empty [] that stood for an empty XML element -> {} (lists are always entry / member) */
    public static function internalPayload( $v, $key = null )
    {
        if( !is_array($v) )
            return $v;
        if( count($v) == 0 )
            return ( $key === 'entry' || $key === 'member' ) ? array() : new stdClass();
        $out = array();
        foreach( $v as $k => $x )
            $out[$k] = self::internalPayload( $x, is_int($k) ? $key : $k );
        return $out;
    }

    /**
     * dry-run: per task 'edit' (live differs), 'unchanged', 'after create' (object does not exist yet), 'error'
     * execute: 'done', 'unchanged', 'failed', 'skipped' (object not found after the public step)
     */
    public function internalApply( $execute, $progress = null )
    {
        $results = array();
        $tasks = $this->internalTasks();
        foreach( $tasks as $e )
        {
            if( $progress !== null && count($results) > 0 )
                call_user_func( $progress, end($results) + array( 'internal' => true ), count($results), count($tasks) );
            $in = $e['_internal'];
            $folder = $e['folder'];
            $r = array( 'type' => $e['_type'], 'name' => $e['name'], 'folder' => $folder, 'prefix' => $in['prefix'] );
            $live = $this->internalGet( $in['prefix'], $folder, $e['name'] );
            if( $live === false )
            {
                $r['status'] = $execute ? 'failed' : 'error';
                $r['message'] = 'internal UI API not reachable / not accepted (host ' . $this->options['ui_api_host'] . ')';
                $results[] = $r;
                continue;
            }
            if( $live === null )
            {
                $r['status'] = $execute ? 'skipped' : 'after create';
                if( $execute )
                    $r['message'] = 'object not found after the public request';
                $results[] = $r;
                continue;
            }
            $diffs = self::internalDiff( $in['entry'], $live );
            $r['sections'] = $diffs;
            if( count($diffs) == 0 )
            {
                $r['status'] = 'unchanged';
                $results[] = $r;
                continue;
            }
            if( !$execute )
            {
                $r['status'] = 'edit';
                $results[] = $r;
                continue;
            }
            $entry = self::internalPayload( $in['entry'] );
            foreach( $live as $k => $v )
                if( is_string($k) && $k !== '' && $k[0] == '@' )
                    $entry[$k] = $v;
            $q = strpos($e['name'], "'") === FALSE ? "'" . $e['name'] . "'" : '"' . $e['name'] . '"';
            $body = array( 'operations' => array( array( 'payload' => array( 'entry' => $entry ), 'command' => 'edit',
                'prefix' => $in['prefix'], 'subPath' => "entry[@name=" . $q . "]", 'isNewOnly' => 'no',
                'folder' => $folder, 'type' => $this->internalFolderType($folder) ) ) );
            $url = "https://" . $this->options['ui_api_host'] . "/api/config/v9.2/multiConfigure";
            $answer = $this->connector->sendSCMAPIRequest( "POST", $url, json_encode( $body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ), FALSE );
            $ok = $answer['errors'] === null && is_array($answer['json']) && isset($answer['json']['@status']) && $answer['json']['@status'] == 'success';
            $r['status'] = $ok ? 'done' : 'failed';
            $r['http_code'] = $answer['http_code'];
            if( !$ok )
                $r['message'] = is_array($answer['json']) ? json_encode( $answer['json'], JSON_UNESCAPED_SLASHES ) : ( is_string($answer['errors']) ? $answer['errors'] : json_encode($answer['errors']) );
            $results[] = $r;
        }
        if( $progress !== null && count($results) > 0 )
            call_user_func( $progress, end($results) + array( 'internal' => true ), count($results), count($tasks) );
        return $results;
    }

    /** export again and check every change against the tenant */
    public function verify()
    {
        $dir = $this->export( 'verify' );
        $cmp = new SCMPrismaAccessCompare( $this->sollDir, $dir );
        $cmp->filter = array( 'areas' => array( SCMPrismaAccessExport::AREA_CONFIG ), 'containers' => null, 'types' => null );
        $cmp->run();
        $cmp->write( $this->runDir . "/compare-verify" );

        $live = $this->loadContainers( $dir );
        $results = array();
        foreach( $this->changes as $c )
        {
            $obj = $this->findLive( $live, $c );
            $r = array( 'change' => $c['label'], 'action' => $c['action'] );
            if( $c['action'] == 'delete' || $c['action'] == 'absent' )
                $r['status'] = $obj === null ? 'verified' : 'failed';
            elseif( $obj === null )
            {
                $r['status'] = 'failed';
                $r['message'] = 'not found';
            }
            else
            {
                $diffs = self::subsetDiff( $c['entry'], $obj );
                $r['status'] = count($diffs) == 0 ? 'verified' : 'failed';
                if( count($diffs) > 0 )
                    $r['message'] = implode("; ", $diffs);
            }
            $results[] = $r;
        }
        //rule bases: the rules of soll must be in the same order in the tenant
        $sollEps = $this->loadContainers( $this->sollDir );
        $checked = array();
        foreach( $this->changes as $c )
        {
            if( $c['kind'] !== 'object' || !preg_match('/-rules(-pre|-post)?$/', $c['type']) )
                continue;
            $k = $c['type'] . "|" . $c['container_kind'] . "|" . $c['container'];
            if( isset($checked[$k]) || !isset($sollEps['objects'][$k]) )
                continue;
            $checked[$k] = true;
            $want = array_map( function($o){ return $o['name']; }, $sollEps['objects'][$k] );
            $have = isset($live['objects'][$k]) ? array_map( function($o){ return $o['name']; }, $live['objects'][$k] ) : array();
            $have = array_values( array_filter( $have, function($n) use( $want ){ return in_array($n, $want, TRUE); } ) );
            $r = array( 'change' => "order " . $c['type'] . " [" . $c['container_kind'] . " " . $c['container'] . "]", 'action' => 'order' );
            $r['status'] = $have === $want ? 'verified' : 'failed';
            if( $have !== $want )
                $r['message'] = "tenant: " . implode(", ", $have) . " | expected: " . implode(", ", $want);
            $results[] = $r;
        }
        foreach( $this->internalTasks() as $e )
        {
            $live = $this->internalGet( $e['_internal']['prefix'], $e['folder'], $e['name'] );
            $r = array( 'change' => "internal " . $e['_type'] . " " . $e['name'] . " [folder " . $e['folder'] . "]", 'action' => 'internal' );
            if( !is_array($live) )
            {
                $r['status'] = 'failed';
                $r['message'] = $live === null ? 'not found (internal UI API)' : 'internal UI API not reachable';
            }
            else
            {
                $diffs = self::internalDiff( $e['_internal']['entry'], $live );
                $r['status'] = count($diffs) == 0 ? 'verified' : 'failed';
                if( count($diffs) > 0 )
                    $r['message'] = "differs: " . implode(", ", $diffs);
            }
            $results[] = $r;
        }
        $this->writeJson( $this->runDir . "/verify.json", array( 'export' => $dir, 'results' => $results ) );
        return $results;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // soll = ist + changes

    public function buildSoll()
    {
        $this->sollDir = $this->runDir . "/soll";
        self::copyDir( $this->istDir, $this->sollDir );
        //the hierarchy is derived from 01_folders / 02_snippets - not compared here
        @unlink( $this->sollDir . "/config/hierarchy.json" );
        @unlink( $this->sollDir . "/config/hierarchy.txt" );

        $manifest = json_decode( file_get_contents($this->sollDir . "/manifest.json"), TRUE );
        $folders = $this->readData( $this->sollDir . "/config/01_folders.json" );
        $snippets = $this->readData( $this->sollDir . "/config/02_snippets.json" );
        if( $folders === null || $snippets === null )
            return $this->fail( "folders / snippets could not be exported - see " . $this->istDir . "/manifest.json" );

        $this->changes = array();

        // snippets first: folders can attach them
        foreach( $this->request['snippets'] as $s )
        {
            $idx = self::indexByName( $snippets, $s['name'] );
            $label = "snippet " . $s['name'];
            if( $idx === null )
            {
                $new = self::fields( $s );
                $snippets[] = $new;
                $this->changes[] = array( 'kind' => 'snippet', 'label' => $label, 'action' => 'create', 'entry' => $new, 'name' => $s['name'] );
            }
            else
            {
                if( isset($snippets[$idx]['type']) && $snippets[$idx]['type'] === 'predefined' )
                {
                    $this->errors[] = $label . ": predefined snippet cannot be changed";
                    continue;
                }
                $before = $snippets[$idx];
                $snippets[$idx] = array_merge( $snippets[$idx], self::fields($s) );
                $this->changes[] = array( 'kind' => 'snippet', 'label' => $label, 'action' => $before == $snippets[$idx] ? 'unchanged' : 'update', 'entry' => self::fields($s), 'name' => $s['name'] );
            }
        }

        // folders (in file order: a new parent before its children)
        foreach( $this->request['folders'] as $f )
        {
            $idx = self::indexByName( $folders, $f['name'] );
            $label = "folder " . $f['name'];
            if( $idx === null )
            {
                if( !isset($f['parent']) || $f['parent'] === '' )
                {
                    $this->errors[] = $label . ": parent missing";
                    continue;
                }
                $pIdx = self::indexByName( $folders, $f['parent'] );
                if( $pIdx === null )
                {
                    $this->errors[] = $label . ": parent folder '" . $f['parent'] . "' does not exist (and is not created before in the file)";
                    continue;
                }
                if( !self::isBelow( $folders, $f['parent'], self::NGFW_ROOT ) )
                {
                    $this->errors[] = $label . ": parent '" . $f['parent'] . "' is not below '" . self::NGFW_ROOT . "' (All Firewalls) - own folders can only be created there";
                    continue;
                }
                foreach( isset($f['snippets']) ? (array)$f['snippets'] : array() as $sn )
                    if( self::indexByName( $snippets, $sn ) === null )
                        $this->errors[] = $label . ": snippet '" . $sn . "' does not exist (and is not created in this file)";
                $depth = self::depthBelow( $folders, $f['parent'], self::NGFW_ROOT ) + 1;
                if( $depth > self::MAX_FOLDER_DEPTH )
                {
                    $this->errors[] = $label . ": would be folder level " . $depth . " below '" . self::NGFW_ROOT . "' - SCM allows max. " . self::MAX_FOLDER_DEPTH;
                    continue;
                }
                $new = self::fields( $f );
                $folders[] = $new;
                $this->changes[] = array( 'kind' => 'folder', 'label' => $label, 'action' => 'create', 'entry' => $new, 'name' => $f['name'] );
            }
            else
            {
                if( isset($f['parent']) && ( !isset($folders[$idx]['parent']) || $folders[$idx]['parent'] !== $f['parent'] ) )
                {
                    $this->errors[] = $label . ": exists with parent '" . ( isset($folders[$idx]['parent']) ? $folders[$idx]['parent'] : '' ) . "' - moving folders is not supported";
                    continue;
                }
                $before = $folders[$idx];
                $folders[$idx] = array_merge( $folders[$idx], self::fields($f) );
                $this->changes[] = array( 'kind' => 'folder', 'label' => $label, 'action' => $before == $folders[$idx] ? 'unchanged' : 'update', 'entry' => self::fields($f), 'name' => $f['name'] );
            }
        }

        $this->writeData( $this->sollDir . "/config/01_folders.json", $folders );
        $this->writeData( $this->sollDir . "/config/02_snippets.json", $snippets );

        // objects
        foreach( $this->request['objects'] as $e )
        {
            $type = $this->types[$e['_type']];
            $kind = isset($e['folder']) ? 'folder' : 'snippet';
            $cName = $kind == 'folder' ? $e['folder'] : $e['snippet'];
            $epName = $this->endpointName( $e );
            $label = $epName . " " . $e['name'] . " [" . $kind . " " . $cName . "]";

            $exists = $kind == 'folder' ? self::indexByName($folders, $cName) !== null : self::indexByName($snippets, $cName) !== null;
            if( !$exists )
            {
                $this->errors[] = $label . ": " . $kind . " '" . $cName . "' does not exist (and is not created in this file)";
                continue;
            }
            if( $kind == 'folder' )
            {
                $fo = $folders[ self::indexByName($folders, $cName) ];
                if( SCMPrismaAccessExport::isDeviceFolder($fo) )
                {
                    $this->errors[] = $label . ": device folder - not supported";
                    continue;
                }
                if( !SCMPrismaAccessExport::configTypeEligible( array( 'kind' => 'folder', 'name' => $cName ), $type ) )
                {
                    $this->errors[] = $label . ": type " . $type['name'] . " is not available in the Prisma Access folder " . $cName;
                    continue;
                }
            }

            $file = $this->ensureContainerFile( $manifest, $kind, $cName, $type, $epName );
            $data = $this->readData( $this->sollDir . "/" . $file );
            if( $data === null )
            {
                $this->errors[] = $label . ": " . $type['name'] . " could not be exported for " . $kind . " " . $cName . " - see " . $this->istDir . "/manifest.json";
                continue;
            }
            $idx = self::indexByName( $data, $e['name'] );
            $change = array( 'kind' => 'object', 'label' => $label, 'type' => $epName, 'container_kind' => $kind, 'container' => $cName, 'name' => $e['name'] );

            if( !empty($e['_delete']) )
            {
                if( $idx === null )
                    $change['action'] = 'absent';
                else
                {
                    array_splice( $data, $idx, 1 );
                    $change['action'] = 'delete';
                }
                $change['entry'] = array();
            }
            else
            {
                $base = $idx === null ? array( 'name' => $e['name'], $kind => $cName ) : $data[$idx];
                $new = self::applyEntry( $base, $e );
                if( $idx === null )
                {
                    $data[] = $new;
                    $change['action'] = 'create';
                }
                else
                {
                    $change['action'] = $new == $data[$idx] ? 'unchanged' : 'update';
                    $data[$idx] = $new;
                }
                $change['entry'] = $e;
            }
            $this->changes[] = $change;
            $this->writeData( $this->sollDir . "/" . $file, $data );
        }

        $manifest['source'] = 'scm_pa_change.php soll';
        $this->writeJson( $this->sollDir . "/manifest.json", $manifest );
        return count($this->errors) == 0;
    }

    /** file of a container / type in soll; for a container created by this request: new file + manifest entry */
    private function ensureContainerFile( &$manifest, $kind, $cName, $type, $epName )
    {
        foreach( $manifest['endpoints'] as $ep )
            if( $ep['area'] == SCMPrismaAccessExport::AREA_CONFIG && isset($ep['container']) && $ep['container'] === $cName
                && $ep['container_kind'] === $kind && $ep['name'] === $epName )
                return $ep['file'];

        $file = SCMPrismaAccessExport::AREA_CONFIG . "/" . $kind . "s/" . SCMPrismaAccessExport::slug($cName) . "/" . sprintf("%02d", $type['order']) . "_" . $epName . ".json";
        $url = $type['path'] . "?" . $kind . "=" . rawurlencode($cName) . ( $epName !== $type['name'] ? "&position=" . substr($epName, strlen($type['name']) + 1) : "" );
        $ep = array( 'area' => SCMPrismaAccessExport::AREA_CONFIG, 'order' => $type['order'], 'name' => $epName, 'group' => $type['group'],
            'container' => $cName, 'container_kind' => $kind, 'category' => 'dependency', 'scope' => $kind, 'optional' => true,
            'url' => $url, 'depends_on' => array(), 'fetched_as' => 'selected', 'file' => $file, 'http_code' => 200,
            'fetched_at' => date('c'), 'status' => 'ok', 'count' => 0, 'created_by' => 'scm_pa_change.php' );
        $manifest['endpoints'][] = $ep;
        if( !is_dir( dirname($this->sollDir . "/" . $file) ) )
            mkdir( dirname($this->sollDir . "/" . $file), 0700, TRUE );
        $this->writeJson( $this->sollDir . "/" . $file, array( 'endpoint' => $epName, 'area' => SCMPrismaAccessExport::AREA_CONFIG,
            'url' => $url, 'tsg_id' => $this->tsg, 'fetched_at' => date('c'), 'http_code' => 200, 'status' => 'ok', 'error' => null,
            'container' => $cName, 'container_kind' => $kind, 'created_by' => 'scm_pa_change.php', 'data' => array() ) );
        return $file;
    }

    /** endpoint (file) name of an object entry: rule bases of folders are split in pre / post */
    public function endpointName( $e )
    {
        $t = $this->types[$e['_type']];
        if( empty($t['position']) || isset($e['snippet']) )
            return $t['name'];
        return $t['name'] . "-" . ( isset($e['position']) ? $e['position'] : 'pre' );
    }

    /** fields set / appended / removed on an object */
    public static function applyEntry( $obj, $e )
    {
        foreach( self::fields($e) as $k => $v )
            if( !in_array($k, array('folder', 'snippet', 'position'), TRUE) )
                $obj[$k] = $v;
        if( isset($e['_append']) )
            foreach( $e['_append'] as $f => $values )
            {
                $cur = isset($obj[$f]) && is_array($obj[$f]) ? $obj[$f] : array();
                foreach( $values as $v )
                    if( !in_array($v, $cur, TRUE) )
                        $cur[] = $v;
                $obj[$f] = $cur;
            }
        if( isset($e['_remove']) )
            foreach( $e['_remove'] as $f => $values )
                if( isset($obj[$f]) && is_array($obj[$f]) )
                {
                    $obj[$f] = array_values( array_filter( $obj[$f], function($v) use( $values ){ return !in_array($v, $values, TRUE); } ) );
                    if( count($obj[$f]) == 0 )
                        unset( $obj[$f] );
                }
        return $obj;
    }

    /** fields of an entry without directives / addressing keys */
    public static function fields( $e )
    {
        $out = array();
        foreach( $e as $k => $v )
            if( !( is_string($k) && $k !== '' && $k[0] == '_' ) )
                $out[$k] = $v;
        return $out;
    }

    /** differences between what the change asked for and the live object (empty = verified) */
    public static function subsetDiff( $entry, $obj )
    {
        $diffs = array();
        foreach( self::fields($entry) as $k => $v )
        {
            if( in_array($k, array('folder', 'snippet', 'position'), TRUE) )
                continue;
            if( !array_key_exists($k, $obj) )
                $diffs[] = $k . " missing";
            elseif( $k === 'snippets' && is_array($v) && is_array($obj[$k]) )
            {
                //attached snippets: same order (the first wins)
                $live = array_values( array_filter( $obj[$k], function($x) use( $v ){ return in_array($x, $v, TRUE); } ) );
                if( $live !== array_values($v) )
                    $diffs[] = "snippets = " . json_encode($obj[$k]) . " (expected order " . json_encode($v) . ")";
            }
            elseif( self::norm($v) !== self::norm($obj[$k]) )
                $diffs[] = $k . " = " . json_encode($obj[$k], JSON_UNESCAPED_SLASHES) . " (expected " . json_encode($v, JSON_UNESCAPED_SLASHES) . ")";
        }
        if( isset($entry['_append']) )
            foreach( $entry['_append'] as $f => $values )
                foreach( $values as $v )
                    if( !isset($obj[$f]) || !is_array($obj[$f]) || !in_array($v, $obj[$f], TRUE) )
                        $diffs[] = $f . " does not contain " . json_encode($v);
        if( isset($entry['_remove']) )
            foreach( $entry['_remove'] as $f => $values )
                foreach( $values as $v )
                    if( isset($obj[$f]) && is_array($obj[$f]) && in_array($v, $obj[$f], TRUE) )
                        $diffs[] = $f . " still contains " . json_encode($v);
        return $diffs;
    }

    private static function norm( $v )
    {
        if( !is_array($v) )
            return json_encode($v);
        $isList = array_keys($v) === range(0, count($v) - 1);
        $out = array();
        foreach( $v as $k => $x )
            $out[$k] = self::norm($x);
        if( $isList )
            sort( $out );
        else
            ksort( $out );
        return json_encode( $out );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // helpers

    private function loadContainers( $dir )
    {
        $m = json_decode( file_get_contents($dir . "/manifest.json"), TRUE );
        $live = array( 'folders' => (array)$this->readData($dir . "/config/01_folders.json"),
            'snippets' => (array)$this->readData($dir . "/config/02_snippets.json"), 'objects' => array() );
        foreach( $m['endpoints'] as $ep )
            if( $ep['area'] == SCMPrismaAccessExport::AREA_CONFIG && isset($ep['container']) && $ep['status'] == 'ok' )
                $live['objects'][ $ep['name'] . "|" . $ep['container_kind'] . "|" . $ep['container'] ] = (array)$this->readData( $dir . "/" . $ep['file'] );
        return $live;
    }

    private function findLive( $live, $c )
    {
        if( $c['kind'] == 'folder' || $c['kind'] == 'snippet' )
        {
            $list = $live[ $c['kind'] . "s" ];
            $i = self::indexByName( $list, $c['name'] );
            return $i === null ? null : $list[$i];
        }
        $k = $c['type'] . "|" . $c['container_kind'] . "|" . $c['container'];
        if( !isset($live['objects'][$k]) )
            return null;
        $i = self::indexByName( $live['objects'][$k], $c['name'] );
        return $i === null ? null : $live['objects'][$k][$i];
    }

    /** true if $folder is $root or below it */
    public static function isBelow( $folders, $folder, $root )
    {
        $guard = 0;
        while( $folder !== null && $guard++ < 50 )
        {
            if( $folder === $root )
                return true;
            $i = self::indexByName( $folders, $folder );
            $folder = ( $i !== null && isset($folders[$i]['parent']) ) ? $folders[$i]['parent'] : null;
        }
        return false;
    }

    /** levels of $folder below $root ($root = 0) */
    public static function depthBelow( $folders, $folder, $root )
    {
        $depth = 0;
        for( $guard = 0; $folder !== null && $folder !== $root && $guard < 50; $guard++ )
        {
            $i = self::indexByName( $folders, $folder );
            $folder = ( $i !== null && isset($folders[$i]['parent']) ) ? $folders[$i]['parent'] : null;
            $depth++;
        }
        return $depth;
    }

    public static function indexByName( $list, $name )
    {
        foreach( $list as $i => $o )
            if( is_array($o) && isset($o['name']) && $o['name'] === $name )
                return $i;
        return null;
    }

    private function readData( $file )
    {
        if( !is_readable($file) )
            return null;
        $j = json_decode( file_get_contents($file), TRUE );
        if( !is_array($j) || !isset($j['status']) || $j['status'] !== 'ok' || !array_key_exists('data', $j) || !is_array($j['data']) )
            return null;
        return $j['data'];
    }

    private function writeData( $file, $data )
    {
        $j = json_decode( file_get_contents($file), TRUE );
        $j['data'] = array_values( $data );
        $this->writeJson( $file, $j );
    }

    private function writeJson( $file, $content )
    {
        file_put_contents( $file, json_encode( $content, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );
        chmod( $file, 0600 );
    }

    public static function copyDir( $from, $to )
    {
        if( !is_dir($to) )
            mkdir( $to, 0700, TRUE );
        foreach( scandir($from) as $f )
        {
            if( $f === '.' || $f === '..' )
                continue;
            if( is_dir($from . "/" . $f) )
                self::copyDir( $from . "/" . $f, $to . "/" . $f );
            else
            {
                copy( $from . "/" . $f, $to . "/" . $f );
                chmod( $to . "/" . $f, 0600 );
            }
        }
    }

    private function fail( $msg )
    {
        $this->errors[] = $msg;
        return false;
    }
}
