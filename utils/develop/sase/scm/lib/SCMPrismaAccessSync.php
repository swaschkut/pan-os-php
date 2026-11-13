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

require_once(dirname(__FILE__) . "/SCMPrismaAccessCompare.php");

/**
 * Sync of the differences of two exports into a target tenant.
 *
 *   plan  (offline): diff.json + direction + mode -> plan.json (ordered operations, editable) + PLAN_REPORT.md
 *   apply (API)    : plan.json -> target tenant; dry-run by default, "execute" sends; hash check per object;
 *                    optional push + job polling; apply-log.json
 *
 * Modes: additive (create + update), mirror (+ delete, only with allow-delete), merge (two plans, conflicts not sent).
 * plan.json never contains secrets: secret fields are placeholders that apply resolves from the secret lists
 * (psk-list.csv, bgp-secret-list.csv, secret-list.csv) of the source export.
 */
class SCMPrismaAccessSync
{
    const FORMAT_VERSION = 1;
    const SECRET_PLACEHOLDER = '__secret__';

    /** phases: order of execution */
    const PHASE_CREATE_UPDATE = 1;
    const PHASE_FOLLOWUP = 2;
    const PHASE_MOVE = 3;
    const PHASE_DELETE = 4;

    public $diff;
    public $options = array( 'source' => 'left', 'mode' => 'additive', 'allow_delete' => false, 'allow_infra' => false, 'allow_network' => false,
        'areas' => null, 'containers' => null, 'types' => null );

    /** side data: ['dir', 'manifest', 'index' => [area|container|endpoint => meta], 'files' => cache] */
    private $src;
    private $tgt;
    /** compare instance oriented source -> target (name map) */
    private $mapper;

    private $ops = array();
    private $opIndex = array();
    public $warnings = array();
    public $conflicts = array();

    /**
     * @param string|array $diff diff.json file or its decoded content
     */
    public function __construct( $diff, $options = array() )
    {
        if( is_array($diff) )
            $this->diff = $diff;
        else
        {
            if( !is_readable($diff) )
                derr( "diff.json not readable: " . $diff, null, FALSE );
            $this->diff = json_decode( file_get_contents($diff), TRUE );
        }
        if( !is_array($this->diff) || !isset($this->diff['entries']) )
            derr( "not a diff.json of scm_pa_compare.php: " . $diffFile, null, FALSE );
        $this->options = array_merge( $this->options, $options );
        if( !in_array($this->options['source'], array('left', 'right'), TRUE) )
            derr( "source must be left or right", null, FALSE );
        if( !in_array($this->options['mode'], array('additive', 'mirror', 'merge'), TRUE) )
            derr( "mode must be additive, mirror or merge", null, FALSE );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // plan

    /**
     * @return array plan (merge: array of two plans)
     */
    public function buildPlans()
    {
        if( $this->options['mode'] == 'merge' )
        {
            $plans = array();
            foreach( array('left', 'right') as $source )
                $plans[] = $this->buildPlan( $source, 'merge' );
            return $plans;
        }
        return array( $this->buildPlan( $this->options['source'], $this->options['mode'] ) );
    }

    public function buildPlan( $source, $mode )
    {
        $target = $source == 'left' ? 'right' : 'left';
        $this->ops = array();
        $this->opIndex = array();
        $this->warnings = array();
        $this->conflicts = array();

        $this->src = $this->loadSide( $this->diff[$source]['dir'] );
        $this->tgt = $this->loadSide( $this->diff[$target]['dir'] );

        //name map oriented source -> target; entry keys / containers in diff.json use right naming
        $this->mapper = new SCMPrismaAccessCompare( $this->diff['left']['dir'], $this->diff['right']['dir'] );
        $this->mapper->nameMap = $this->diff['options']['name_map'];
        $this->mapper->containerMap = $this->diff['options']['container_map'];
        $rightToLeftContainer = array_flip( $this->mapper->containerMap );
        if( $source == 'right' )
            $this->mapper->invertMaps();

        foreach( $this->diff['entries'] as $entry )
        {
            if( !$this->passesFilter($entry) )
                continue;
            $meta = SCMPrismaAccessExport::endpointMeta( $entry['area'], $entry['endpoint'] );

            //containers: right naming in diff.json
            $rightC = $entry['container'];
            $leftC = $rightC;
            if( $rightC !== null )
            {
                list($kind, $name) = explode(":", $rightC, 2);
                $leftC = $kind . ":" . ( isset($rightToLeftContainer[$name]) ? $rightToLeftContainer[$name] : $name );
            }
            $ctx = array(
                'entry' => $entry, 'meta' => $meta,
                'src_container' => $source == 'left' ? $leftC : $rightC,
                'tgt_container' => $source == 'left' ? $rightC : $leftC,
            );

            $onlySrc = $source == 'left' ? $entry['only_left'] : $entry['only_right'];
            $onlyTgt = $source == 'left' ? $entry['only_right'] : $entry['only_left'];

            foreach( $onlySrc as $item )
            {
                $srcName = $source == 'left' ? ( isset($item['left_name']) ? $item['left_name'] : $item['key'] ) : $item['key'];
                $this->planCreate( $ctx, $srcName, 'only in ' . $source );
            }

            foreach( $entry['changed'] as $item )
            {
                $srcName = $source == 'left' ? ( isset($item['left_name']) ? $item['left_name'] : $item['key'] ) : $item['key'];
                $tgtName = $source == 'left' ? $item['key'] : ( isset($item['left_name']) ? $item['left_name'] : $item['key'] );
                if( $mode == 'merge' )
                {
                    $this->conflicts[] = array( 'area' => $entry['area'], 'container' => $ctx['tgt_container'], 'endpoint' => $entry['endpoint'],
                        'name' => $tgtName, 'fields' => array_map( function($c){ return $c['path'] . " (" . $c['type'] . ")"; }, $item['changes'] ) );
                    continue;
                }
                $this->planUpdate( $ctx, $srcName, $tgtName, $item['changes'] );
            }

            foreach( $onlyTgt as $item )
            {
                $tgtName = $target == 'left' ? ( isset($item['left_name']) ? $item['left_name'] : $item['key'] ) : $item['key'];
                if( $mode == 'mirror' )
                    $this->planDelete( $ctx, $tgtName );
            }

            if( $entry['order'] !== null && $mode != 'merge' )
                $this->planMove( $ctx, $entry['order'][$source] );
        }

        $this->resolveDependencies();
        $this->checkDeletes();
        $this->splitBackupSC();
        $this->sortOps();

        return array(
            'format_version' => self::FORMAT_VERSION,
            'tool' => 'pan-os-php scm_pa_sync.php plan',
            'created_at' => date('c'),
            'diff' => array( 'created_at' => $this->diff['created_at'], 'left' => $this->diff['left'], 'right' => $this->diff['right'] ),
            'source' => array( 'side' => $source ) + $this->diff[$source],
            'target' => array( 'side' => $target ) + $this->diff[$target],
            'mode' => $mode,
            'options' => $this->options,
            'summary' => $this->planSummary(),
            'operations' => array_values($this->ops),
            'conflicts' => $this->conflicts,
            'warnings' => array_values( array_unique($this->warnings) ),
        );
    }

    private function passesFilter( $entry )
    {
        $f = $this->options;
        if( $f['areas'] !== null && !in_array($entry['area'], $f['areas'], TRUE) )
            return false;
        if( $f['containers'] !== null && $entry['container'] !== null )
        {
            list(, $name) = explode(":", $entry['container'], 2);
            if( !in_array($name, $f['containers'], TRUE) )
                return false;
        }
        if( $f['types'] !== null && $entry['area'] == SCMPrismaAccessExport::AREA_CONFIG && $entry['container'] !== null )
        {
            $base = preg_replace('/-(pre|post)$/', '', $entry['endpoint']);
            if( !in_array($base, $f['types'], TRUE) )
                return false;
        }
        return true;
    }

    private function loadSide( $dir )
    {
        $manifest = SCMPrismaAccessCompare::loadManifest( $dir );
        $index = array();
        foreach( $manifest['endpoints'] as $e )
        {
            if( !isset($e['area']) )
                continue;
            $c = isset($e['container']) ? $e['container_kind'] . ":" . $e['container'] : "";
            $index[ $e['area'] . "|" . $c . "|" . $e['name'] ] = $e;
        }
        return array( 'dir' => rtrim($dir, "/\\"), 'manifest' => $manifest, 'index' => $index, 'files' => array() );
    }

    /**
     * entries of one endpoint file of a side: name => raw object
     */
    private function sideObjects( &$side, $area, $container, $endpoint )
    {
        $k = $area . "|" . ( $container === null ? "" : $container ) . "|" . $endpoint;
        if( isset($side['files'][$k]) )
            return $side['files'][$k];
        $objects = array();
        if( isset($side['index'][$k]) && isset($side['index'][$k]['file']) && is_readable($side['dir'] . "/" . $side['index'][$k]['file']) )
        {
            $content = json_decode( file_get_contents($side['dir'] . "/" . $side['index'][$k]['file']), TRUE );
            $meta = SCMPrismaAccessExport::endpointMeta( $area, $endpoint );
            $data = isset($content['data']) ? $content['data'] : null;
            if( $meta['singleton'] )
            {
                if( is_array($data) && count($data) > 0 )
                    $objects['_'] = ( array_keys($data) === range(0, count($data) - 1) ) ? $data[0] : $data;
            }
            elseif( is_array($data) )
            {
                foreach( $data as $obj )
                {
                    $parts = array();
                    foreach( $meta['key'] as $f )
                    {
                        $v = SCMPrismaAccessExport::get($obj, $f);
                        $parts[] = is_array($v) ? json_encode($v) : (string)$v;
                    }
                    $key = implode("|", $parts);
                    if( !isset($objects[$key]) )
                        $objects[$key] = $obj;
                }
            }
        }
        $side['files'][$k] = $objects;
        return $objects;
    }

    /**
     * path of an endpoint (without query)
     */
    private function endpointUrl( $side, $area, $container, $endpoint )
    {
        $k = $area . "|" . ( $container === null ? "" : $container ) . "|" . $endpoint;
        if( !isset($side['index'][$k]['url']) )
            return null;
        $url = $side['index'][$k]['url'];
        $q = strpos($url, "?");
        return $q === false ? $url : substr($url, 0, $q);
    }

    /**
     * query parameters to keep for write requests: non-config endpoints keep e.g. folder=Mobile Users;
     * config objects carry their owner in the body, rules get position separately
     */
    private function endpointQuery( $area, $endpoint )
    {
        if( $area == SCMPrismaAccessExport::AREA_CONFIG )
            return array();
        foreach( array( $this->tgt, $this->src ) as $side )
        {
            $k = $area . "||" . $endpoint;
            if( isset($side['index'][$k]['url']) && ($q = strpos($side['index'][$k]['url'], "?")) !== false )
            {
                parse_str( substr($side['index'][$k]['url'], $q + 1), $params );
                unset( $params['limit'], $params['offset'] );
                return $params;
            }
        }
        return array();
    }

    ////////////////////////////////////////////////////////////////////////////////
    // operations

    private function opKey( $area, $container, $endpoint, $name )
    {
        return $area . "|" . $container . "|" . $endpoint . "|" . $name;
    }

    private function addOp( $op )
    {
        $k = $this->opKey( $op['area'], $op['container'], $op['endpoint'], $op['name'] . "|" . $op['action'] );
        if( isset($this->opIndex[$k]) )
            return $this->opIndex[$k];
        $op['id'] = sprintf("op-%04d", count($this->ops) + 1);
        $op += array( 'enabled' => true, 'blocked' => null, 'depends_on' => array(), 'notes' => array() );
        $this->ops[$op['id']] = $op;
        $this->opIndex[$k] = $op['id'];
        return $op['id'];
    }

    /**
     * request body: source object, translated to target names, without id / derived fields, owner set to target,
     * secrets replaced by placeholders
     */
    private function buildBody( $ctx, $srcObj, &$secrets, &$blocked, &$notes = null )
    {
        $notes = array();
        $meta = $ctx['meta'];
        $area = $ctx['entry']['area'];
        $obj = $this->mapper->translateObject( $srcObj, $meta );
        unset( $obj['id'], $obj['overridden'], $obj['override_id'], $obj['override_loc'], $obj['override_type'] );
        foreach( $meta['ignore'] as $path )
            $obj = self::unsetPath( $obj, explode(".", $path) );

        if( $area == SCMPrismaAccessExport::AREA_CONFIG && $ctx['tgt_container'] !== null )
        {
            list($kind, $name) = explode(":", $ctx['tgt_container'], 2);
            //objects of a device folder may carry the owner as "device"
            $ownerField = ( $kind == 'folder' && isset($srcObj['device']) && !isset($srcObj['folder']) ) ? 'device' : $kind;
            unset( $obj['folder'], $obj['snippet'], $obj['device'] );
            $obj[$ownerField] = $name;
        }

        //secrets
        $secrets = array();
        $blocked = null;
        $srcName = (string)SCMPrismaAccessExport::get($srcObj, isset($meta['key'][0]) ? $meta['key'][0] : 'name', '_');
        foreach( $this->secretPaths($obj, $meta) as $path )
        {
            $source = $this->secretSource( $ctx, $path, $srcName );
            if( $source === null )
            {
                $this->warnings[] = $meta['endpoint'] . " " . $srcName . ": secret field " . $path . " has no secret list - the exported (encrypted) value is sent";
                continue;
            }
            $obj = self::setPath( $obj, explode(".", $path), array( self::SECRET_PLACEHOLDER => $source ) );
            $secrets[] = array( 'path' => $path ) + $source;
            if( !$this->secretAvailable($source) )
                $blocked = "secret missing: " . $source['list'] . " " . $source['key'] . " (export the source with psk-list / fill *_new)";
            else
            {
                $v = $this->secretVerified( $source );
                if( $v === false )
                    $notes[] = "secret " . $path . ": the value in " . $source['list'] . " differs from the source tenant (new secret)";
                elseif( $v === true )
                    $notes[] = "secret " . $path . ": verified against the source tenant (SHA1)";
            }
        }
        return $obj;
    }

    /**
     * secret paths present in an object: metadata secret paths + generic secret field names
     */
    private function secretPaths( $obj, $meta )
    {
        $paths = array();
        $walk = function( $v, $path ) use( &$walk, &$paths, $meta ) {
            if( !is_array($v) )
            {
                if( $path !== "" && $v !== null && $v !== "" && !is_bool($v) && SCMPrismaAccessCompare::isSecretPath($path, $meta['secret']) )
                    $paths[] = $path;
                return;
            }
            foreach( $v as $k => $child )
                $walk( $child, $path === "" ? (string)$k : $path . "." . $k );
        };
        $walk( $obj, "" );
        return $paths;
    }

    /**
     * where apply takes the cleartext from: ['list' => file relative to the source export, 'key' => lookup key]
     */
    private function secretSource( $ctx, $path, $srcName )
    {
        $area = $ctx['entry']['area'];
        $ep = $ctx['entry']['endpoint'];
        if( $ep == 'ike-gateways' && $path == 'authentication.pre_shared_key.key' )
            return array( 'list' => $area . '/psk-list.csv', 'kind' => 'psk', 'key' => $srcName );
        if( in_array($ep, array('remote-networks', 'service-connections'), TRUE) && in_array($path, array('protocol.bgp.secret', 'bgp_peer.secret'), TRUE) )
            return array( 'list' => $area . '/bgp-secret-list.csv', 'kind' => 'bgp', 'key' => $srcName . "|" . $path );
        if( $area == SCMPrismaAccessExport::AREA_MU )
            return array( 'list' => $area . '/secret-list.csv', 'kind' => 'secret', 'key' => $ep . "|" . $srcName . "|" . $path );
        return null;
    }

    private $secretListCache = array();

    private $secretVerifiedCache = array();

    private function loadSecretListFile( $dir, $source )
    {
        $file = $dir . "/" . $source['list'];
        if( !array_key_exists($file, $this->secretListCache) )
        {
            if( !is_readable($file) )
            {
                $this->secretListCache[$file] = null;
                $this->secretVerifiedCache[$file] = array();
            }
            else
            {
                if( $source['kind'] == 'psk' )
                {
                    $l = SCMPrismaAccessExport::loadPSKList($file);
                    $l['secret'] = $l['psk'];
                }
                elseif( $source['kind'] == 'bgp' )
                    $l = SCMPrismaAccessExport::loadBGPSecretList($file);
                else
                    $l = SCMPrismaAccessExport::loadSecretList($file);
                $this->secretListCache[$file] = $l['secret'];
                $this->secretVerifiedCache[$file] = $l['verified'];
            }
        }
        return $this->secretListCache[$file];
    }

    /**
     * true / false / null: secret of the list matches the SHA1 of the exported value
     */
    private function secretVerified( $source )
    {
        $this->loadSecretListFile( $this->src['dir'], $source );
        $file = $this->src['dir'] . "/" . $source['list'];
        return isset($this->secretVerifiedCache[$file][$source['key']]) ? $this->secretVerifiedCache[$file][$source['key']] : null;
    }

    private function secretAvailable( $source )
    {
        $list = $this->loadSecretListFile( $this->src['dir'], $source );
        return $list !== null && isset($list[$source['key']]);
    }

    private function planCreate( $ctx, $srcName, $reason )
    {
        $e = $ctx['entry'];
        $meta = $ctx['meta'];
        $srcObjects = $this->sideObjects( $this->src, $e['area'], $ctx['src_container'], $e['endpoint'] );
        if( !isset($srcObjects[$srcName]) )
        {
            $this->warnings[] = $meta['endpoint'] . ": source object '" . $srcName . "' not found in the source export";
            return null;
        }
        $tgtName = $meta['singleton'] ? '_' : $this->mapper->mapName( $meta['endpoint'], $srcName );
        $body = $this->buildBody( $ctx, $srcObjects[$srcName], $secrets, $blocked, $secretNotes );

        $op = array( 'notes' => $secretNotes, 'action' => $meta['singleton'] ? 'update' : 'create', 'phase' => self::PHASE_CREATE_UPDATE,
            'area' => $e['area'], 'endpoint' => $e['endpoint'], 'endpoint_key' => $meta['endpoint'], 'write' => $meta['write'],
            'container' => $ctx['tgt_container'], 'name' => $tgtName, 'source_name' => $srcName,
            'url' => $this->endpointUrl( $this->tgt, $e['area'], $ctx['tgt_container'], $e['endpoint'] ) ?: $this->endpointUrl( $this->src, $e['area'], $ctx['src_container'], $e['endpoint'] ),
            'query' => $this->endpointQuery( $e['area'], $e['endpoint'] ),
            'position' => preg_match('/-(pre|post)$/', $e['endpoint'], $m) ? $m[1] : null,
            'target_id' => null, 'target_hash' => null, 'body' => $body, 'secrets' => $secrets, 'reason' => $reason );
        $op['blocked'] = $blocked ?: $this->writeBlock( $meta, $e['area'] );
        return $this->addOp( $op );
    }

    private function planUpdate( $ctx, $srcName, $tgtName, $changes )
    {
        $e = $ctx['entry'];
        $meta = $ctx['meta'];
        $srcObjects = $this->sideObjects( $this->src, $e['area'], $ctx['src_container'], $e['endpoint'] );
        $tgtObjects = $this->sideObjects( $this->tgt, $e['area'], $ctx['tgt_container'], $e['endpoint'] );
        if( !isset($srcObjects[$srcName]) || !isset($tgtObjects[$tgtName]) )
        {
            $this->warnings[] = $meta['endpoint'] . ": object '" . $srcName . "' / '" . $tgtName . "' not found in the exports";
            return null;
        }
        $body = $this->buildBody( $ctx, $srcObjects[$srcName], $secrets, $blocked, $secretNotes );
        $tgtObj = $tgtObjects[$tgtName];
        $op = array( 'notes' => $secretNotes, 'action' => 'update', 'phase' => self::PHASE_CREATE_UPDATE,
            'area' => $e['area'], 'endpoint' => $e['endpoint'], 'endpoint_key' => $meta['endpoint'], 'write' => $meta['write'],
            'container' => $ctx['tgt_container'], 'name' => $tgtName, 'source_name' => $srcName,
            'url' => $this->endpointUrl( $this->tgt, $e['area'], $ctx['tgt_container'], $e['endpoint'] ),
            'query' => $this->endpointQuery( $e['area'], $e['endpoint'] ),
            'position' => preg_match('/-(pre|post)$/', $e['endpoint'], $m) ? $m[1] : null,
            'target_id' => isset($tgtObj['id']) ? $tgtObj['id'] : null, 'target_hash' => self::objectHash($tgtObj, $meta),
            'body' => $body, 'secrets' => $secrets,
            'reason' => 'changed: ' . implode(", ", array_slice( array_map( function($c){ return $c['path'] === "" ? "(value)" : $c['path']; }, $changes ), 0, 10 ) ) . ( count($changes) > 10 ? ", …" : "" ) );
        $op['blocked'] = $blocked ?: $this->writeBlock( $meta, $e['area'] );
        if( $op['blocked'] === null && !$meta['singleton'] && $op['target_id'] === null )
            $op['blocked'] = "target object has no id";
        return $this->addOp( $op );
    }

    private function planDelete( $ctx, $tgtName )
    {
        $e = $ctx['entry'];
        $meta = $ctx['meta'];
        $tgtObjects = $this->sideObjects( $this->tgt, $e['area'], $ctx['tgt_container'], $e['endpoint'] );
        if( !isset($tgtObjects[$tgtName]) )
            return null;
        $tgtObj = $tgtObjects[$tgtName];
        $op = array( 'action' => 'delete', 'phase' => self::PHASE_DELETE,
            'area' => $e['area'], 'endpoint' => $e['endpoint'], 'endpoint_key' => $meta['endpoint'], 'write' => $meta['write'],
            'container' => $ctx['tgt_container'], 'name' => $tgtName, 'source_name' => null,
            'url' => $this->endpointUrl( $this->tgt, $e['area'], $ctx['tgt_container'], $e['endpoint'] ),
            'query' => $this->endpointQuery( $e['area'], $e['endpoint'] ),
            'position' => null, 'target_id' => isset($tgtObj['id']) ? $tgtObj['id'] : null, 'target_hash' => self::objectHash($tgtObj, $meta),
            'body' => null, 'secrets' => array(), 'reason' => 'only in target (mirror)' );
        $op['blocked'] = $this->writeBlock( $meta, $e['area'] );
        if( $op['blocked'] === null && !$this->options['allow_delete'] )
            $op['blocked'] = "delete not allowed (option allow-delete)";
        if( $op['blocked'] === null && $meta['singleton'] )
            $op['blocked'] = "singleton cannot be deleted";
        if( $op['blocked'] === null && $op['target_id'] === null )
            $op['blocked'] = "target object has no id";
        return $this->addOp( $op );
    }

    private function planMove( $ctx, $sequence )
    {
        $e = $ctx['entry'];
        $meta = $ctx['meta'];
        if( $meta['write'] !== 'collection' )
            return null;
        $op = array( 'action' => 'move', 'phase' => self::PHASE_MOVE,
            'area' => $e['area'], 'endpoint' => $e['endpoint'], 'endpoint_key' => $meta['endpoint'], 'write' => $meta['write'],
            'container' => $ctx['tgt_container'], 'name' => '(order)', 'source_name' => null,
            'url' => $this->endpointUrl( $this->tgt, $e['area'], $ctx['tgt_container'], $e['endpoint'] ),
            'query' => $this->endpointQuery( $e['area'], $e['endpoint'] ),
            'position' => preg_match('/-(pre|post)$/', $e['endpoint'], $m) ? $m[1] : null,
            'target_id' => null, 'target_hash' => null, 'body' => null, 'secrets' => array(),
            'sequence' => array_map( function($n) use( $meta ){ return $this->mapper->mapName( $meta['endpoint'], $n ); }, $sequence ),
            'reason' => 'order differs' );
        $op['blocked'] = $this->writeBlock( $meta, $e['area'] );
        return $this->addOp( $op );
    }

    /**
     * reason why an endpoint is not written, or null
     */
    private function writeBlock( $meta, $area )
    {
        if( $meta['endpoint'] == 'config/devices' )
            return "device onboarding / folder assignment is done in Strata Cloud Manager device management (not by the config API)";
        if( $meta['write'] == 'none' )
            return "read-only / documentation endpoint";
        if( $area == SCMPrismaAccessExport::AREA_PB )
            return "Prisma Browser sync not implemented yet (rule / section API, draft publish)";
        if( $area == SCMPrismaAccessExport::AREA_INFRA && $meta['singleton'] && !$this->options['allow_infra'] )
            return "infrastructure setting - changes are disruptive (option allow-infra)";
        if( $area == SCMPrismaAccessExport::AREA_CONFIG && !$this->options['allow_network'] )
        {
            $base = preg_replace('/^config\//', '', $meta['endpoint']);
            foreach( SCMPrismaAccessExport::getConfigTypes() as $t )
                if( $t['name'] == $base && in_array($t['group'], array('network', 'device'), TRUE) )
                    return "NGFW " . $t['group'] . " setting (interfaces, routing, device settings) - changes can interrupt traffic (option allow-network)";
        }
        return null;
    }

    public static function objectHash( $obj, $meta )
    {
        $n = SCMPrismaAccessCompare::normalizeValue( $obj, "", $meta['ignore'], is_array($meta['ordered']) ? $meta['ordered'] : array() );
        return sha1( json_encode($n) );
    }

    ////////////////////////////////////////////////////////////////////////////////
    // dependencies

    /**
     * every create / update: referenced objects must exist in the target, be created by the plan, or be added
     * from the source (dependency); otherwise warning (predefined / inherited objects are not exported)
     */
    private function resolveDependencies()
    {
        $queue = array_keys($this->ops);
        while( count($queue) > 0 )
        {
            $id = array_shift($queue);
            $op = $this->ops[$id];
            if( !in_array($op['action'], array('create', 'update'), TRUE) || !is_array($op['body']) )
                continue;
            $meta = SCMPrismaAccessExport::endpointMeta( $op['area'], $op['endpoint'] );

            //config objects in a folder / snippet that the plan creates
            if( $op['container'] !== null )
            {
                list($kind, $cname) = explode(":", $op['container'], 2);
                $dep = $this->plannedCreate( SCMPrismaAccessExport::AREA_CONFIG, $kind == 'folder' ? 'folders' : 'snippets', $cname );
                if( $dep !== null && $dep !== $id )
                    $this->ops[$id]['depends_on'][] = $dep;
            }
            //folders: parent folder / attached snippets created by the plan
            if( $op['endpoint_key'] == 'config/folders' )
            {
                foreach( array_merge( array( isset($op['body']['parent']) ? $op['body']['parent'] : null ), (array)( isset($op['body']['snippets']) ? $op['body']['snippets'] : array() ) ) as $i => $ref )
                {
                    if( !is_string($ref) )
                        continue;
                    $dep = $this->plannedCreate( SCMPrismaAccessExport::AREA_CONFIG, $i == 0 ? 'folders' : 'snippets', $ref );
                    if( $dep !== null && $dep !== $id )
                        $this->ops[$id]['depends_on'][] = $dep;
                }
            }

            foreach( $meta['refs'] as $path => $targetEndpoint )
            {
                foreach( self::valuesAt( $op['body'], explode(".", $path) ) as $refName )
                {
                    if( !is_string($refName) || $refName === "" )
                        continue;
                    list($rArea, $rEndpoint) = explode("/", $targetEndpoint, 2);
                    //self reference (backup_SC) handled by splitBackupSC
                    if( $this->targetHas($rArea, $rEndpoint, $refName, $op['container']) )
                    {
                        $dep = $this->plannedCreate( $rArea, $rEndpoint, $refName );
                        if( $dep !== null && $dep !== $id )
                            $this->ops[$id]['depends_on'][] = $dep;
                        continue;
                    }
                    $added = $this->addDependencyFromSource( $rArea, $rEndpoint, $refName, $op );
                    if( $added !== null )
                    {
                        $this->ops[$id]['depends_on'][] = $added;
                        $queue[] = $added;
                    }
                    else
                        $this->ops[$id]['notes'][] = "reference " . $path . " = '" . $refName . "' not found in source / target export (predefined or inherited?)";
                }
            }
            $this->ops[$id]['depends_on'] = array_values( array_unique($this->ops[$id]['depends_on']) );
        }
    }

    /**
     * object exists in the target export (any container of the endpoint) or is created / kept by the plan
     */
    private function targetHas( $area, $endpoint, $name, $container )
    {
        if( $this->plannedCreate($area, $endpoint, $name) !== null )
            return true;
        foreach( $this->tgt['index'] as $k => $e )
        {
            list($a, , $ep) = explode("|", $k, 3);
            if( $a !== $area || preg_replace('/-(pre|post)$/', '', $ep) !== $endpoint )
                continue;
            list(, $c, ) = explode("|", $k, 3);
            $objects = $this->sideObjects( $this->tgt, $area, $c === "" ? null : $c, $ep );
            if( isset($objects[$name]) )
            {
                //an object that the plan deletes does not count
                return !isset($this->opIndex[ $this->opKey($area, $c === "" ? null : $c, $ep, $name . "|delete") ]);
            }
        }
        return false;
    }

    private function plannedCreate( $area, $endpoint, $name )
    {
        foreach( $this->ops as $id => $op )
            if( $op['action'] == 'create' && $op['area'] == $area && preg_replace('/-(pre|post)$/', '', $op['endpoint']) == $endpoint && $op['name'] === $name )
                return $id;
        return null;
    }

    private function addDependencyFromSource( $area, $endpoint, $tgtName, $referrer )
    {
        //source name of a target name: reverse name map lookup is not needed for unmapped names
        foreach( $this->src['index'] as $k => $e )
        {
            list($a, $c, $ep) = explode("|", $k, 3);
            if( $a !== $area || preg_replace('/-(pre|post)$/', '', $ep) !== $endpoint )
                continue;
            $objects = $this->sideObjects( $this->src, $area, $c === "" ? null : $c, $ep );
            foreach( $objects as $srcName => $obj )
            {
                if( $this->mapper->mapName( $area . "/" . $endpoint, (string)$srcName ) !== $tgtName )
                    continue;
                $meta = SCMPrismaAccessExport::endpointMeta( $area, $ep );
                $tgtContainer = $c === "" ? null : $c;
                if( $tgtContainer !== null )
                {
                    list($kind, $cname) = explode(":", $tgtContainer, 2);
                    if( isset($this->mapper->containerMap[$cname]) )
                        $tgtContainer = $kind . ":" . $this->mapper->containerMap[$cname];
                }
                $ctx = array( 'entry' => array( 'area' => $area, 'endpoint' => $ep ), 'meta' => $meta,
                    'src_container' => $c === "" ? null : $c, 'tgt_container' => $tgtContainer );
                return $this->planCreate( $ctx, (string)$srcName, 'dependency of ' . $referrer['id'] . ' (' . $referrer['endpoint'] . ' ' . $referrer['name'] . ')' );
            }
        }
        return null;
    }

    /**
     * delete only if no remaining target object references the object
     */
    private function checkDeletes()
    {
        $referenced = array();
        foreach( $this->tgt['index'] as $k => $e )
        {
            list($area, $c, $ep) = explode("|", $k, 3);
            $meta = SCMPrismaAccessExport::endpointMeta( $area, $ep );
            if( count($meta['refs']) == 0 )
                continue;
            foreach( $this->sideObjects( $this->tgt, $area, $c === "" ? null : $c, $ep ) as $name => $obj )
            {
                //deleted objects do not reference anything any more, updated objects reference what their new body says
                if( isset($this->opIndex[ $this->opKey($area, $c === "" ? null : $c, $ep, $name . "|delete") ])
                    || isset($this->opIndex[ $this->opKey($area, $c === "" ? null : $c, $ep, $name . "|update") ]) )
                    continue;
                foreach( $meta['refs'] as $path => $targetEndpoint )
                    foreach( self::valuesAt( $obj, explode(".", $path) ) as $refName )
                        if( is_string($refName) )
                            $referenced[$targetEndpoint][$refName][] = $meta['endpoint'] . " " . $name;
            }
        }
        //objects that the plan creates / updates reference as well
        foreach( $this->ops as $op )
        {
            if( !in_array($op['action'], array('create', 'update'), TRUE) || !is_array($op['body']) )
                continue;
            $meta = SCMPrismaAccessExport::endpointMeta( $op['area'], $op['endpoint'] );
            foreach( $meta['refs'] as $path => $targetEndpoint )
                foreach( self::valuesAt( $op['body'], explode(".", $path) ) as $refName )
                    if( is_string($refName) )
                        $referenced[$targetEndpoint][$refName][] = $op['endpoint_key'] . " " . $op['name'] . " (" . $op['id'] . ")";
        }
        foreach( $this->ops as $id => $op )
        {
            if( $op['action'] != 'delete' || $op['blocked'] !== null )
                continue;
            $ek = preg_replace('/-(pre|post)$/', '', $op['endpoint_key']);
            if( isset($referenced[$ek][$op['name']]) )
                $this->ops[$id]['blocked'] = "still referenced by " . implode(", ", array_slice(array_unique($referenced[$ek][$op['name']]), 0, 5));
        }
    }

    /**
     * service connections created together and referencing each other as backup_SC: create without backup_SC,
     * set it afterwards (phase follow-up)
     */
    private function splitBackupSC()
    {
        foreach( $this->ops as $id => $op )
        {
            if( $op['action'] != 'create' || $op['endpoint_key'] != 'service-connections/service-connections' || empty($op['body']['backup_SC']) )
                continue;
            $backup = $op['body']['backup_SC'];
            if( $this->plannedCreate( 'service-connections', 'service-connections', $backup ) === null )
                continue;
            $follow = $op;
            unset( $follow['id'] );
            $follow['action'] = 'update';
            $follow['phase'] = self::PHASE_FOLLOWUP;
            $follow['name'] = $op['name'];
            $follow['body'] = $op['body'];
            $follow['reason'] = 'set backup_SC after all service connections exist';
            $follow['depends_on'] = array( $id, $this->plannedCreate( 'service-connections', 'service-connections', $backup ) );
            $follow['target_id'] = null;
            $follow['created_by'] = $id;
            unset( $this->ops[$id]['body']['backup_SC'] );
            $this->ops[$id]['notes'][] = "backup_SC '" . $backup . "' is set by a follow-up operation";
            $k = $this->opKey( $follow['area'], $follow['container'], $follow['endpoint'], $follow['name'] . "|followup" );
            $follow['id'] = sprintf("op-%04d", count($this->ops) + 1);
            $follow += array( 'enabled' => true, 'notes' => array() );
            $this->ops[$follow['id']] = $follow;
            $this->opIndex[$k] = $follow['id'];
        }
    }

    /**
     * phase, then area order, folders by hierarchy depth, then endpoint order; deletes in reverse
     */
    private function sortOps()
    {
        $areaPos = array_flip( SCMPrismaAccessExport::AREAS );
        $endpointPos = array();
        $i = 0;
        $exp = new SCMPrismaAccessExport( null, "", "/tmp" );
        foreach( $exp->getAllEndpoints() as $e )
            $endpointPos[$e['area'] . "/" . $e['name']] = $e['order'];
        //snippets before folders: a new folder can be created with new snippets attached
        $endpointPos['config/snippets'] = -0.5;
        $endpointPos['config/folders'] = 0;
        foreach( SCMPrismaAccessExport::getConfigTypes() as $t )
            $endpointPos['config/' . $t['name']] = $t['order'];

        $depth = array();
        $hierarchy = $this->tgtHierarchy();
        foreach( $hierarchy as $name => $d )
            $depth[$name] = $d;

        $rank = function( $op ) use( $areaPos, $endpointPos, $depth ) {
            $ep = preg_replace('/-(pre|post)$/', '', $op['endpoint_key']);
            $r = array(
                isset($areaPos[$op['area']]) ? $areaPos[$op['area']] : 99,
                isset($endpointPos[$ep]) ? $endpointPos[$ep] : 50,
            );
            //folders: parents first
            if( $op['endpoint_key'] == 'config/folders' && is_array($op['body']) )
                $r[] = isset($op['body']['parent']) && isset($depth[$op['body']['parent']]) ? $depth[$op['body']['parent']] + 1 : 0;
            else
                $r[] = 0;
            return $r;
        };
        $ops = array_values($this->ops);
        usort( $ops, function($a, $b) use( $rank ) {
            if( $a['phase'] != $b['phase'] )
                return $a['phase'] - $b['phase'];
            $ra = $rank($a);
            $rb = $rank($b);
            $cmp = $ra <=> $rb;
            if( $a['phase'] == self::PHASE_DELETE )
                $cmp = -$cmp;
            return $cmp != 0 ? $cmp : strcmp($a['id'], $b['id']);
        } );
        //dependencies must come first: move an op behind its dependencies (stable)
        $pos = array();
        foreach( $ops as $i => $op )
            $pos[$op['id']] = $i;
        $changed = true;
        $guard = 0;
        while( $changed && $guard++ < 1000 )
        {
            $changed = false;
            foreach( $ops as $i => $op )
            {
                foreach( $op['depends_on'] as $dep )
                {
                    if( isset($pos[$dep]) && $pos[$dep] > $i )
                    {
                        $moved = $ops[$pos[$dep]];
                        array_splice( $ops, $pos[$dep], 1 );
                        array_splice( $ops, $i, 0, array($moved) );
                        $pos = array();
                        foreach( $ops as $j => $o )
                            $pos[$o['id']] = $j;
                        $changed = true;
                        break 2;
                    }
                }
            }
        }
        $this->ops = array();
        $seq = 1;
        foreach( $ops as $op )
        {
            $op['seq'] = $seq++;
            $this->ops[$op['id']] = $op;
        }
    }

    private function tgtHierarchy()
    {
        $depth = array();
        foreach( array( $this->tgt['dir'], $this->src['dir'] ) as $dir )
        {
            $file = $dir . "/config/hierarchy.json";
            if( !is_readable($file) )
                continue;
            $h = json_decode( file_get_contents($file), TRUE );
            foreach( (array)$h['folders'] as $f )
                if( !isset($depth[$f['name']]) )
                    $depth[$f['name']] = $f['depth'];
        }
        return $depth;
    }

    public function planSummary()
    {
        $s = array( 'operations' => 0, 'enabled' => 0, 'blocked' => 0, 'by_action' => array(), 'by_area' => array() );
        foreach( $this->ops as $op )
        {
            $s['operations']++;
            if( $op['blocked'] !== null )
                $s['blocked']++;
            elseif( $op['enabled'] )
                $s['enabled']++;
            $s['by_action'][$op['action']] = ( isset($s['by_action'][$op['action']]) ? $s['by_action'][$op['action']] : 0 ) + 1;
            $s['by_area'][$op['area']] = ( isset($s['by_area'][$op['area']]) ? $s['by_area'][$op['area']] : 0 ) + 1;
        }
        $s['conflicts'] = count($this->conflicts);
        return $s;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // output

    public static function writePlan( $plan, $outDir, $suffix = "" )
    {
        if( !is_dir($outDir) && !mkdir($outDir, 0700, TRUE) )
            derr( "not possible to create " . $outDir, null, FALSE );
        file_put_contents( $outDir . "/plan" . $suffix . ".json", json_encode( $plan, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );
        file_put_contents( $outDir . "/PLAN_REPORT" . $suffix . ".md", self::planMarkdown($plan, "plan" . $suffix . ".json") );
    }

    private static function cell( $v, $len = 80 )
    {
        $s = str_replace( array("|", "\n"), array("\\|", " "), (string)$v );
        return mb_strlen($s) > $len ? mb_substr($s, 0, $len) . "…" : $s;
    }

    public static function planMarkdown( $plan, $planFile = "plan.json" )
    {
        $md = "# Sync plan – " . $plan['source']['tsg_id'] . " (" . $plan['source']['side'] . ") → " . $plan['target']['tsg_id'] . " (" . $plan['target']['side'] . ")\n\n";
        $md .= "| | |\n|---|---|\n";
        $md .= "| mode | **" . $plan['mode'] . "** |\n";
        $md .= "| source | TSG " . $plan['source']['tsg_id'] . ", export " . $plan['source']['created_at'] . " |\n";
        $md .= "| target | TSG " . $plan['target']['tsg_id'] . ", export " . $plan['target']['created_at'] . " |\n";
        $md .= "| options | allow-delete " . ( $plan['options']['allow_delete'] ? "yes" : "no" ) . ", allow-infra " . ( $plan['options']['allow_infra'] ? "yes" : "no" ) . ", allow-network " . ( !empty($plan['options']['allow_network']) ? "yes" : "no" ) . " |\n";
        $md .= "| created | " . $plan['created_at'] . " |\n\n";
        $s = $plan['summary'];
        $md .= "**" . $s['operations'] . " operations**: " . $s['enabled'] . " to execute, " . $s['blocked'] . " blocked";
        foreach( $s['by_action'] as $a => $n )
            $md .= " · " . $a . " " . $n;
        $md .= ( $s['conflicts'] > 0 ? " · **" . $s['conflicts'] . " conflicts** (merge, not sent)" : "" ) . "\n\n";
        $md .= "Nothing is sent by creating this plan. Review it, set `\"enabled\": false` in `" . $planFile . "` for operations you do not want, then run `scm_pa_sync.php apply` (dry-run first).\n\n";

        $blocked = array_filter( $plan['operations'], function($o){ return $o['blocked'] !== null; } );
        if( count($blocked) > 0 )
        {
            $md .= "## Blocked operations\n\n| op | action | area | container | endpoint | name | reason |\n|---|---|---|---|---|---|---|\n";
            foreach( $blocked as $o )
                $md .= "| " . $o['id'] . " | " . $o['action'] . " | " . $o['area'] . " | " . self::cell($o['container']) . " | " . $o['endpoint'] . " | " . self::cell($o['name'], 40) . " | " . self::cell($o['blocked'], 120) . " |\n";
            $md .= "\n";
        }
        $md .= "## Operations in execution order\n\n| # | op | action | area | container | endpoint | name | reason | depends on | notes |\n|---|---|---|---|---|---|---|---|---|---|\n";
        foreach( $plan['operations'] as $o )
        {
            if( $o['blocked'] !== null )
                continue;
            $notes = $o['notes'];
            if( count($o['secrets']) > 0 )
                $notes[] = "secrets from " . implode(", ", array_unique(array_map( function($x){ return $x['list']; }, $o['secrets'] )));
            if( isset($o['sequence']) )
                $notes[] = "order: " . implode(" → ", $o['sequence']);
            $md .= "| " . $o['seq'] . " | " . $o['id'] . ( $o['enabled'] ? "" : " (disabled)" ) . " | " . $o['action'] . " | " . $o['area'] . " | " . self::cell($o['container']) . " | " . $o['endpoint']
                . " | " . self::cell($o['name'], 40) . ( $o['source_name'] !== null && $o['source_name'] !== $o['name'] ? " (source: " . self::cell($o['source_name'], 30) . ")" : "" )
                . " | " . self::cell($o['reason'], 60) . " | " . implode(", ", $o['depends_on']) . " | " . self::cell(implode("; ", $notes), 120) . " |\n";
        }
        if( count($plan['conflicts']) > 0 )
        {
            $md .= "\n## Conflicts (merge – changed on both sides, not sent)\n\n| area | container | endpoint | name | fields |\n|---|---|---|---|---|\n";
            foreach( $plan['conflicts'] as $c )
                $md .= "| " . $c['area'] . " | " . self::cell($c['container']) . " | " . $c['endpoint'] . " | " . self::cell($c['name'], 40) . " | " . self::cell(implode(", ", $c['fields']), 120) . " |\n";
        }
        if( count($plan['warnings']) > 0 )
        {
            $md .= "\n## Warnings\n\n";
            foreach( array_slice($plan['warnings'], 0, 100) as $w )
                $md .= "- " . $w . "\n";
        }
        return $md;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // apply

    /**
     * @param PanSCMAPIConnector $connector target tenant
     * @param array $opts execute (bool), continue_on_error, push, ops (null | list of op ids), source_dir (override)
     * @return array apply log
     */
    public static function apply( $connector, $plan, $opts )
    {
        $opts += array( 'execute' => false, 'continue_on_error' => false, 'push' => false, 'ops' => null, 'source_dir' => null, 'skip_hash_check' => false );
        $sourceDir = $opts['source_dir'] !== null ? $opts['source_dir'] : $plan['source']['dir'];
        $sync = new SCMPrismaAccessSync( array( 'entries' => array() ) );
        $log = array( 'tool' => 'pan-os-php scm_pa_sync.php apply', 'started_at' => date('c'), 'execute' => $opts['execute'],
            'target_tsg' => $plan['target']['tsg_id'], 'results' => array(), 'push' => null );

        //ids of objects in the target: from the plan + created objects
        $ids = array();
        foreach( $plan['operations'] as $op )
            if( $op['target_id'] !== null )
                $ids[ $op['area'] . "|" . $op['endpoint'] . "|" . $op['container'] . "|" . $op['name'] ] = $op['target_id'];
        foreach( self::targetIdIndex($plan['target']['dir']) as $k => $id )
            if( !isset($ids[$k]) )
                $ids[$k] = $id;

        $done = array();
        $failed = false;
        $folders = array();
        foreach( $plan['operations'] as $op )
        {
            $res = array( 'op' => $op['id'], 'action' => $op['action'], 'endpoint' => $op['endpoint_key'], 'container' => $op['container'], 'name' => $op['name'] );
            if( $op['blocked'] !== null || !$op['enabled'] || ( $opts['ops'] !== null && !in_array($op['id'], $opts['ops'], TRUE) ) )
            {
                $res['status'] = $op['blocked'] !== null ? 'blocked' : 'skipped';
                $log['results'][] = $res;
                continue;
            }
            foreach( $op['depends_on'] as $dep )
                if( !isset($done[$dep]) )
                {
                    $res['status'] = 'skipped';
                    $res['message'] = 'dependency ' . $dep . ' not executed';
                }
            if( isset($res['status']) || ( $failed && !$opts['continue_on_error'] ) )
            {
                $res['status'] = isset($res['status']) ? $res['status'] : 'skipped';
                $log['results'][] = $res;
                continue;
            }

            $meta = SCMPrismaAccessExport::endpointMeta( $op['area'], $op['endpoint'] );
            $base = self::absoluteUrl( $connector, $op['url'] );
            $idKey = $op['area'] . "|" . $op['endpoint'] . "|" . $op['container'] . "|" . $op['name'];
            $targetId = isset($ids[$idKey]) ? $ids[$idKey] : $op['target_id'];
            $query = isset($op['query']) ? $op['query'] : array();
            $qs = function( $extra = array() ) use( $query ) {
                $all = array_merge( $query, $extra );
                return count($all) > 0 ? "?" . http_build_query( $all, '', '&', PHP_QUERY_RFC3986 ) : "";
            };

            $body = null;
            if( $op['body'] !== null )
            {
                $body = $sync->resolveSecrets( $op['body'], $op['secrets'], $sourceDir, $missing );
                if( $missing !== null )
                {
                    $res['status'] = 'failed';
                    $res['message'] = 'secret missing: ' . $missing;
                    $log['results'][] = $res;
                    $failed = true;
                    continue;
                }
            }

            $requests = array();
            if( $op['action'] == 'create' )
                $requests[] = array( 'POST', $base . $qs( $op['position'] !== null ? array( 'position' => $op['position'] ) : array() ), $body );
            elseif( $op['action'] == 'update' )
            {
                if( $meta['singleton'] )
                    $requests[] = array( 'PUT', $base . $qs(), $body );
                elseif( $targetId === null )
                {
                    $res['status'] = 'failed';
                    $res['message'] = 'no id for ' . $op['name'];
                }
                else
                    $requests[] = array( 'PUT', $base . "/" . rawurlencode($targetId) . $qs(), $body );
            }
            elseif( $op['action'] == 'delete' )
                $requests[] = array( 'DELETE', $base . "/" . rawurlencode($targetId) . $qs(), null );
            elseif( $op['action'] == 'move' )
            {
                $prev = null;
                foreach( $op['sequence'] as $name )
                {
                    $nk = $op['area'] . "|" . $op['endpoint'] . "|" . $op['container'] . "|" . $name;
                    $rid = isset($ids[$nk]) ? $ids[$nk] : null;
                    if( $rid === null )
                        continue;
                    $moveBody = $prev === null ? array( 'destination' => 'top', 'rulebase' => $op['position'] )
                        : array( 'destination' => 'after', 'rulebase' => $op['position'], 'destination_rule' => $prev );
                    //snippet rule base: no pre / post
                    if( $op['position'] === null )
                        unset( $moveBody['rulebase'] );
                    $requests[] = array( 'POST', $base . "/" . rawurlencode($rid) . ":move", $moveBody );
                    $prev = $rid;
                }
            }

            //hash check: the target object must still be as exported
            if( !$opts['skip_hash_check'] && $op['target_hash'] !== null && in_array($op['action'], array('update', 'delete'), TRUE) && !isset($res['status'])
                && ( $meta['singleton'] || ( $targetId !== null && strpos($targetId, "<new ") !== 0 ) ) )
            {
                $current = self::readTarget( $connector, ( $meta['singleton'] ? $base : $base . "/" . rawurlencode($targetId) ) . $qs(), $opts['execute'] );
                //the single GET can return other fields than the list query of the export (live: folders) -
                //read the object the same way as the export before reporting a conflict
                if( $current !== false && $current !== null && !$meta['singleton'] && self::objectHash($current, $meta) !== $op['target_hash'] )
                {
                    $listed = self::readTargetFromList( $connector, $op, $targetId );
                    if( $listed !== null )
                        $current = $listed;
                }
                if( $current !== false && $current !== null && self::objectHash($current, $meta) !== $op['target_hash'] )
                {
                    $res['status'] = 'conflict';
                    $res['message'] = 'target object changed since the export - re-export and re-plan';
                }
            }

            if( !isset($res['status']) )
            {
                $res['requests'] = array();
                foreach( $requests as $r )
                {
                    $line = array( 'method' => $r[0], 'url' => $r[1] );
                    if( !$opts['execute'] )
                    {
                        $line['dry_run'] = true;
                        $res['requests'][] = $line;
                        if( $op['action'] == 'create' )
                            $ids[$idKey] = "<new " . $op['id'] . ">";
                        continue;
                    }
                    $sendBody = $r[2] === null ? false : json_encode( self::restoreEmptyObjects( $op['endpoint'], $r[2] ) );
                    $answer = $connector->sendSCMAPIRequest( $r[0], $r[1], $sendBody, FALSE );
                    $line['http_code'] = $answer['http_code'];
                    if( $answer['errors'] !== null )
                    {
                        $line['error'] = SCMPrismaAccessExport::errorMessage( $answer['errors'] );
                        $res['requests'][] = $line;
                        $res['status'] = 'failed';
                        break;
                    }
                    if( $op['action'] == 'create' && isset($answer['json']['id']) )
                    {
                        $ids[$idKey] = $answer['json']['id'];
                        $line['id'] = $answer['json']['id'];
                    }
                    $res['requests'][] = $line;
                }
                if( !isset($res['status']) )
                    $res['status'] = $opts['execute'] ? 'done' : 'dry-run';
            }

            if( $res['status'] == 'done' || $res['status'] == 'dry-run' )
            {
                $done[$op['id']] = true;
                $folders[ self::pushFolder($op) ] = true;
            }
            elseif( $res['status'] == 'failed' || $res['status'] == 'conflict' )
                $failed = true;
            $log['results'][] = $res;
        }

        unset( $folders[""] );
        $log['folders'] = array_keys($folders);
        if( $opts['push'] && count($folders) > 0 )
            $log['push'] = self::push( $connector, array_keys($folders), $opts['execute'] );

        $counts = array();
        foreach( $log['results'] as $r )
            $counts[$r['status']] = ( isset($counts[$r['status']]) ? $counts[$r['status']] : 0 ) + 1;
        $log['summary'] = $counts;
        $log['finished_at'] = date('c');
        return $log;
    }

    /**
     * folder that has to be pushed for an operation
     */
    private static function pushFolder( $op )
    {
        if( $op['container'] !== null )
        {
            list($kind, $name) = explode(":", $op['container'], 2);
            return $kind == 'folder' ? $name : "";
        }
        $byArea = array( SCMPrismaAccessExport::AREA_RN => 'Remote Networks', SCMPrismaAccessExport::AREA_SC => 'Service Connections',
            SCMPrismaAccessExport::AREA_MU => 'Mobile Users', SCMPrismaAccessExport::AREA_INFRA => 'Prisma Access' );
        return isset($byArea[$op['area']]) ? $byArea[$op['area']] : "";
    }

    /**
     * push the candidate configuration of the given folders and wait for the job
     */
    public static function push( $connector, $folders, $execute, $maxWait = 1800 )
    {
        $url = $connector->url_api . "/config/operations/v1/config-versions/candidate:push";
        $result = array( 'folders' => $folders, 'url' => $url );

        //SCM rejects folders without a push target (no firewall below, not a Prisma Access folder):
        //HTTP 400 "push-config -> push-to unexpected node" - in the UI the push button is greyed out
        $pushable = self::pushableFolders( $connector );
        if( $pushable !== null )
        {
            $skipped = array_values( array_diff( $folders, $pushable ) );
            $folders = array_values( array_intersect( $folders, $pushable ) );
            $result['folders'] = $folders;
            if( count($skipped) > 0 )
                $result['not_pushable'] = $skipped;
            if( count($folders) == 0 )
            {
                $result['status'] = 'nothing to push';
                $result['error'] = 'no push target (no firewall below these folders, no Prisma Access folder): ' . implode(", ", $skipped)
                    . ' - the changes stay in the candidate configuration and go out with the next push of a folder with firewalls / Prisma Access';
                return $result;
            }
        }

        if( !$execute )
        {
            $result['status'] = 'dry-run';
            return $result;
        }
        $answer = $connector->sendSCMAPIRequest( "POST", $url, json_encode( array( 'folders' => $folders ) ), FALSE );
        $result['http_code'] = $answer['http_code'];
        if( $answer['errors'] !== null )
        {
            $result['status'] = 'failed';
            $result['error'] = SCMPrismaAccessExport::errorMessage( $answer['errors'] );
            return $result;
        }
        $jobId = isset($answer['json']['job_id']) ? $answer['json']['job_id'] : ( isset($answer['json']['id']) ? $answer['json']['id'] : null );
        $result['job_id'] = $jobId;
        if( $jobId === null )
        {
            $result['status'] = 'submitted';
            return $result;
        }
        $start = time();
        do
        {
            sleep(10);
            $job = $connector->sendSCMAPIRequest( "GET", $connector->url_api . "/config/operations/v1/jobs/" . rawurlencode($jobId), false, FALSE );
            $data = isset($job['json']['data'][0]) ? $job['json']['data'][0] : $job['json'];
            $status = is_array($data) ? (string)SCMPrismaAccessExport::firstOf($data, array('status_str', 'status', 'result_str')) : "";
            $result['job_status'] = $status;
            if( in_array(strtoupper($status), array('FIN', 'OK', 'SUCCESS', 'COMPLETED', 'FAIL', 'FAILED', 'PUSHFAIL'), TRUE) )
                break;
        }
        while( time() - $start < $maxWait );
        $result['status'] = in_array(strtoupper($result['job_status']), array('FIN', 'OK', 'SUCCESS', 'COMPLETED'), TRUE) ? 'done' : 'check job ' . $jobId;
        return $result;
    }

    /**
     * folders that can be pushed: folders with a firewall (device folder) and all their parents, the Prisma Access
     * folders and their parents; null if the folder list cannot be read (then nothing is filtered)
     */
    public static function pushableFolders( $connector )
    {
        $f = $connector->getSCMResourceAll( "/config/setup/v1/folders" );
        if( $f['errors'] !== null || !$f['is_list'] )
            return null;
        $d = $connector->getSCMResourceAll( "/config/setup/v1/devices" );
        $devices = ( $d['errors'] === null && $d['is_list'] ) ? $d['data'] : array();
        return self::pushableFromFolders( $f['data'], $devices );
    }

    public static function pushableFromFolders( $folders, $devices = array() )
    {
        $hierarchy = SCMPrismaAccessExport::buildHierarchy( $folders, array(), $devices );
        $pa = array_merge( SCMPrismaAccessExport::PA_DEPLOYMENT_FOLDERS, array( 'Prisma Access', 'Mobile Users Container', 'Shared' ) );
        $out = array();
        foreach( $hierarchy['folders'] as $folder )
        {
            if( !SCMPrismaAccessExport::isDeviceFolder($folder) && !in_array($folder['name'], $pa, TRUE) )
                continue;
            foreach( (array)$folder['path'] as $name )
                $out[$name] = true;
            $out[$folder['name']] = true;
        }
        return array_keys( $out );
    }

    private static function absoluteUrl( $connector, $url )
    {
        return strpos($url, "https://") === 0 ? $url : rtrim($connector->url_api, "/") . $url;
    }

    /**
     * current target object (null on error, false in dry-run without API)
     */
    private static function readTarget( $connector, $url, $execute )
    {
        $answer = $connector->sendSCMAPIRequest( "GET", $url, false, FALSE );
        if( $answer['errors'] !== null || !is_array($answer['json']) )
            return null;
        $json = $answer['json'];
        if( isset($json['data']) && is_array($json['data']) && count($json['data']) == 1 && isset($json['data'][0]) )
            return $json['data'][0];
        return $json;
    }

    private static $schema = null;

    /**
     * exports / change files are decoded as PHP arrays: an empty JSON object {} becomes [] and would be sent as a list
     * (live: "credential_enforcement.mode.ip_user must be of type object"). Where the SCM schema of the resource
     * (lib/resources/scm/scm-ngfw-config-schema.json) has an object, an empty list is sent as {}.
     */
    public static function restoreEmptyObjects( $endpoint, $body )
    {
        if( self::$schema === null )
        {
            $file = dirname(__FILE__) . "/../../../../../lib/resources/scm/scm-ngfw-config-schema.json";
            $j = is_readable($file) ? json_decode( file_get_contents($file), TRUE ) : null;
            self::$schema = isset($j['resources']) ? $j['resources'] : array();
        }
        $resource = preg_replace( '/-(pre|post)$/', '', $endpoint );
        if( !is_array($body) || !isset(self::$schema[$resource]['schema']) )
            return $body;
        return self::emptyObjectsBySchema( $body, self::$schema[$resource]['schema'] );
    }

    private static function emptyObjectsBySchema( $value, $schema )
    {
        $type = isset($schema['type']) ? $schema['type'] : 'any';
        if( $type == 'object' && is_array($value) )
        {
            if( count($value) == 0 )
                return new stdClass();
            foreach( $value as $k => $v )
                if( isset($schema['properties'][$k]) )
                    $value[$k] = self::emptyObjectsBySchema( $v, $schema['properties'][$k] );
            return $value;
        }
        if( $type == 'array' && is_array($value) && isset($schema['items']) )
        {
            foreach( $value as $k => $v )
                $value[$k] = self::emptyObjectsBySchema( $v, $schema['items'] );
            return $value;
        }
        return $value;
    }

    /**
     * object by id from the list query the export uses (folder= / snippet= of the container, tenant lists without)
     */
    private static function readTargetFromList( $connector, $op, $id )
    {
        $url = preg_replace( '#^https?://[^/]+#', '', $op['url'] );
        $url = preg_replace( '#\?.*$#', '', $url );
        if( $op['container'] !== null )
        {
            list($kind, $name) = explode(":", $op['container'], 2);
            $url .= "?" . ( $kind == 'snippet' ? 'snippet' : 'folder' ) . "=" . rawurlencode($name);
        }
        $result = $connector->getSCMResourceAll( $url );
        if( $result['errors'] !== null || !is_array($result['data']) )
            return null;
        foreach( $result['data'] as $o )
            if( is_array($o) && isset($o['id']) && $o['id'] === $id )
                return $o;
        return null;
    }

    /**
     * endpoint|container|name => id of all objects in the target export
     */
    private static function targetIdIndex( $dir )
    {
        $ids = array();
        if( !is_readable($dir . "/manifest.json") )
            return $ids;
        $manifest = json_decode( file_get_contents($dir . "/manifest.json"), TRUE );
        foreach( $manifest['endpoints'] as $e )
        {
            if( !isset($e['file']) || !is_readable($dir . "/" . $e['file']) )
                continue;
            $content = json_decode( file_get_contents($dir . "/" . $e['file']), TRUE );
            if( !isset($content['data']) || !is_array($content['data']) || ( $content['data'] !== array() && array_keys($content['data']) !== range(0, count($content['data']) - 1) ) )
                continue;
            $c = isset($e['container']) ? $e['container_kind'] . ":" . $e['container'] : null;
            foreach( $content['data'] as $obj )
                if( isset($obj['name']) && isset($obj['id']) && is_scalar($obj['name']) )
                    $ids[ $e['area'] . "|" . $e['name'] . "|" . $c . "|" . $obj['name'] ] = $obj['id'];
        }
        return $ids;
    }

    /**
     * replaces secret placeholders by the cleartext from the source secret lists
     */
    public function resolveSecrets( $body, $secrets, $sourceDir, &$missing )
    {
        $missing = null;
        foreach( $secrets as $s )
        {
            $list = $this->loadSecretListFile( $sourceDir, $s );
            if( $list === null || !isset($list[$s['key']]) )
            {
                $missing = $s['list'] . " " . $s['key'];
                return null;
            }
            $body = self::setPath( $body, explode(".", $s['path']), $list[$s['key']] );
        }
        return $body;
    }

    ////////////////////////////////////////////////////////////////////////////////
    // path helpers

    /**
     * values at a reference path ("a.b[].c")
     */
    public static function valuesAt( $obj, $segments )
    {
        if( count($segments) == 0 )
            return is_array($obj) ? array() : array( $obj );
        $seg = array_shift($segments);
        $isList = substr($seg, -2) === "[]";
        $field = $isList ? substr($seg, 0, -2) : $seg;
        if( !is_array($obj) || !array_key_exists($field, $obj) )
            return array();
        if( $isList )
        {
            $out = array();
            foreach( (array)$obj[$field] as $el )
                $out = array_merge( $out, self::valuesAt( $el, $segments ) );
            return $out;
        }
        return self::valuesAt( $obj[$field], $segments );
    }

    public static function setPath( $obj, $segments, $value )
    {
        $seg = array_shift($segments);
        if( !is_array($obj) )
            $obj = array();
        $key = ctype_digit((string)$seg) && array_key_exists((int)$seg, $obj) ? (int)$seg : $seg;
        if( count($segments) == 0 )
            $obj[$key] = $value;
        else
            $obj[$key] = self::setPath( isset($obj[$key]) ? $obj[$key] : array(), $segments, $value );
        return $obj;
    }

    public static function unsetPath( $obj, $segments )
    {
        $seg = array_shift($segments);
        if( !is_array($obj) || !array_key_exists($seg, $obj) )
            return $obj;
        if( count($segments) == 0 )
            unset( $obj[$seg] );
        else
            $obj[$seg] = self::unsetPath( $obj[$seg], $segments );
        return $obj;
    }
}
