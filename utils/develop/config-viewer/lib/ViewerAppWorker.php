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
 * Part of ViewerApp (trait: the same class - $this, private methods and self:: are those of ViewerApp):
 * the worker of an opened version (configuration loaded once, kept in memory): sessions, reads (objects, references, locations, history) and changes.
 */
trait ViewerAppWorker
{
    // ------------------------------------------------------------------ worker (configuration loaded once, kept in memory)

    private function workDir( array $project ): string
    {
        $work = $this->projectDir( $project['pid'] ) . '/work';
        @mkdir( $work, 0700, TRUE );
        return $work;
    }

    /** the socket lives in <data>/run: the path of a unix socket is limited to about 100 characters */
    private function sessionFiles( string $work, string $sid ): array
    {
        return array( 'sock' => $this->dataDir . '/run/' . $sid . '.sock', 'pid' => $work . '/' . $sid . '.pid', 'log' => $work . '/' . $sid . '.log',
            'autosave' => $work . '/' . $sid . '.autosave.xml' );
    }

    /**
     * is the worker of a session alive and ready ? By its files only: the web part may run in another container than
     * the service and its workers (no shared process ids). The worker writes its pid file at start and removes it with
     * its socket when it ends; the service removes both when it has reaped the worker (also after a crash or a kill)
     * and removes left-overs when it starts.
     */
    private static function workerAlive( array $files ): bool
    {
        return trim( (string)@file_get_contents( $files['pid'] ) ) !== '' && file_exists( $files['sock'] );
    }

    /** ask the service to stop a worker (only the service knows its process) */
    private function serviceStop( array $files ): void
    {
        $service = @stream_socket_client( 'unix://' . $this->dataDir . '/service.sock', $errno, $errstr, 5 );
        if( !$service )
            return;
        stream_set_timeout( $service, 10 );
        fwrite( $service, json_encode( array( 'cmd' => 'stop', 'pid' => $files['pid'] ) ) . "\n" );
        stream_get_contents( $service );
        fclose( $service );
    }

    /** one request to the worker: one JSON line, answer until the worker closes the connection */
    private function workerCall( array $files, array $cmd, int $timeout = 300 ): array
    {
        $conn = @stream_socket_client( 'unix://' . $files['sock'], $errno, $errstr, 5 );
        if( !$conn )
        {
            // nobody listens: the worker is gone (e.g. the service was restarted) - the next request starts a new one
            @unlink( $files['sock'] );
            @unlink( $files['pid'] );
            throw new ViewerException( 'the loaded configuration is not reachable - open the version again', 503 );
        }
        stream_set_timeout( $conn, $timeout );
        fwrite( $conn, json_encode( $cmd ) . "\n" );
        $answer = stream_get_contents( $conn );
        $meta = stream_get_meta_data( $conn );
        fclose( $conn );
        if( !empty( $meta['timed_out'] ) )
            throw new ViewerException( 'the run took longer than ' . $timeout . ' seconds', 504 );
        $r = json_decode( (string)$answer, TRUE );
        if( !is_array( $r ) )
            throw new ViewerException( 'the run stopped without an answer', 500 );
        if( empty( $r['ok'] ) )
            throw new ViewerException( $this->hidePaths( isset( $r['error'] ) && is_string( $r['error'] ) && $r['error'] !== '' ? $r['error'] : 'pan-os-php stopped with an error' ), 400 );
        return $r;
    }

    /**
     * The worker of a version: started on first use (loads the configuration once), then reused by every request
     * of every member of the project. A stopped worker that left unsaved changes behind (autosave file) gets its
     * autosave registered as a version first.
     * @return array session files
     */
    private function session( array $project, array $config, array $user ): array
    {
        $work = $this->workDir( $project );
        $row = $this->q( 'SELECT sid FROM sessions WHERE project_id = ? AND config_id = ?', array( $project['id'], $config['id'] ) )->fetch();
        if( $row )
        {
            $files = $this->sessionFiles( $work, $row['sid'] );
            if( self::workerAlive( $files ) )
                return $files;
            $this->sessionCleanup( $project, $row['sid'], $config, $user );
        }

        $sid = self::randomId();
        $files = $this->sessionFiles( $work, $sid );
        // the web server process never starts a process itself: the config-viewer service does (bin/service.php)
        $service = @stream_socket_client( 'unix://' . $this->dataDir . '/service.sock', $errno, $errstr, 5 );
        if( !$service )
            throw new ViewerException( 'the config-viewer service is not running (php utils/develop/config-viewer/bin/service.php)', 503 );
        stream_set_timeout( $service, 20 );
        fwrite( $service, json_encode( array( 'cmd' => 'start', 'config' => $config['path'] ) + $files ) . "\n" );
        $answer = json_decode( (string)stream_get_contents( $service ), TRUE );
        fclose( $service );
        if( !is_array( $answer ) || empty( $answer['ok'] ) )
            throw new ViewerException( 'the config-viewer service did not start the worker', 500 );

        $this->q( 'INSERT INTO sessions (sid, project_id, config_id, created) VALUES (?,?,?,?)', array( $sid, $project['id'], $config['id'], time() ) );
        $deadline = microtime( TRUE ) + max( 10, (int)( getenv( 'PANOSPHP_VIEWER_LOAD_TIMEOUT' ) ?: 600 ) );
        $started = FALSE;
        while( microtime( TRUE ) < $deadline )
        {
            if( file_exists( $files['sock'] ) )
                return $files;
            // the worker ended while loading: its pid file was there and is gone (worker or service removed it)
            if( trim( (string)@file_get_contents( $files['pid'] ) ) !== '' )
                $started = TRUE;
            elseif( $started )
                break;
            usleep( 100000 );
        }
        $log = $this->hidePaths( trim( (string)@file_get_contents( $files['log'] ) ) );
        $this->sessionCleanup( $project, $sid, null, $user );
        throw new ViewerException( 'the configuration could not be loaded' . ( $log !== '' ? ': ' . substr( $log, -400 ) : '' ), 500 );
    }

    /** removes the files of a stopped worker; unsaved work that was autosaved becomes a version */
    private function sessionCleanup( array $project, string $sid, ?array $config, array $user ): ?array
    {
        $files = $this->sessionFiles( $this->workDir( $project ), $sid );
        $recovered = null;
        if( $config !== null && is_file( $files['autosave'] ) && self::isPanosConfig( $files['autosave'] ) )
        {
            $file = self::randomId() . '.xml';
            if( @rename( $files['autosave'], $this->projectDir( $project['pid'] ) . '/' . $file ) )
                $recovered = $this->configInsert( $project, $user, $config['name'], $file, (int)$config['id'], 'autosave (recovered, the loaded configuration was stopped before it was saved)' );
        }
        foreach( $files as $f )
            @unlink( $f );
        $this->q( 'DELETE FROM sessions WHERE sid = ?', array( $sid ) );
        return $recovered;
    }

    private function sessionStop( array $project, int $configId ): void
    {
        $row = $this->q( 'SELECT sid FROM sessions WHERE project_id = ? AND config_id = ?', array( $project['id'], $configId ) )->fetch();
        if( !$row )
            return;
        $files = $this->sessionFiles( $this->workDir( $project ), $row['sid'] );
        if( self::workerAlive( $files ) )
        {
            try { $this->workerCall( $files, array( 'cmd' => 'close' ), 20 ); } catch( Exception $e ) { }
            // the worker removes its pid file when it ends; if it does not end, the service stops it
            for( $i = 0; $i < 30 && file_exists( $files['pid'] ); $i++ )
                usleep( 100000 );
            if( file_exists( $files['pid'] ) )
                $this->serviceStop( $files );
        }
        foreach( $files as $f )
            @unlink( $f );
        $this->q( 'DELETE FROM sessions WHERE sid = ?', array( $row['sid'] ) );
    }

    private function projectStopAll( array $project ): void
    {
        foreach( $this->q( 'SELECT config_id FROM sessions WHERE project_id = ?', array( $project['id'] ) )->fetchAll() as $r )
            $this->sessionStop( $project, (int)$r['config_id'] );
    }

    private static function flatten( $v ): array
    {
        if( !is_array( $v ) )
            return array( $v );
        $r = array();
        foreach( $v as $x )
            foreach( self::flatten( $x ) as $y )
                $r[] = $y;
        return $r;
    }

    /** server paths never leave the server */
    private function hidePaths( string $text ): string
    {
        $text = str_replace( array( $this->dataDir, $this->repoDir ), array( '<data>', '<pan-os-php>' ), $text );
        return preg_replace( '#<data>/projects/[0-9a-f]{32}/(work/)?[0-9a-f]{32}(\.autosave)?\.xml#', '<config>', $text );
    }

    /** objects of the display output as flat rows */
    private static function rows( array $json, bool $nested = FALSE ): array
    {
        $rows = array();
        foreach( $json as $key => $stores )
        {
            // the stores, under the class of the root (PANConf, PanoramaConf, …) or of a template (Template,
            // TemplateStack: network objects of a template - IKE, …)
            if( !preg_match( '/Conf$|^Template$|^TemplateStack$/', (string)$key ) || !is_array( $stores ) )
                continue;
            foreach( $stores as $store )
            {
                $sub = $store['sub'] ?? null;
                if( !is_array( $sub ) || !isset( $sub['object'] ) || !is_array( $sub['object'] ) )
                    continue;
                $location = isset( $sub['name'] ) && $sub['name'] !== '' ? (string)$sub['name'] : 'shared';
                foreach( $sub['object'] as $o )
                {
                    if( !is_array( $o ) )
                        continue;
                    unset( $o['actions'] );
                    // devices: pan-os-php names the templates of a template stack 'template' (a list), the template of
                    // a firewall 'template' and its stack 'templatestack' (name => name + templates) - for the page
                    // 'template' is the template an object is in: before, a template stack had the badge "template
                    // T1,T2" and its window asked for the wrong object (no XML, no references), its members were not shown
                    $cls = is_string( $o['type'] ?? null ) ? $o['type'] : '';
                    if( $cls === 'TemplateStack' && isset( $o['template'] ) )
                    {
                        $o['templates'] = array_values( (array)$o['template'] );
                        unset( $o['template'] );
                    }
                    if( $cls === 'ManagedDevice' )
                    {
                        if( isset( $o['template'] ) )
                        {
                            $o['device-template'] = $o['template'];
                            unset( $o['template'] );
                        }
                        if( isset( $o['templatestack'] ) && is_array( $o['templatestack'] ) )
                        {
                            $ts = array_values( $o['templatestack'] )[0] ?? array();
                            $o['templatestack'] = is_array( $ts ) && isset( $ts['name'] ) ? (string)$ts['name'] : null;
                            $o['templates'] = is_array( $ts ) && isset( $ts['templates'] ) ? array_values( (array)$ts['templates'] ) : array();
                        }
                    }
                    // a predefined object (CallContext::readOnlyReason): location "predefined" - its window reads it there
                    $row = array( 'location' => ( $o['readonly'] ?? null ) === 'predefined' ? 'predefined' : $location );
                    // Panorama: the template of a network / device object (zone, interface, …)
                    if( isset( $o['model']['item']['template'] ) && is_string( $o['model']['item']['template'] ) && $o['model']['item']['template'] !== '' )
                        $row['template'] = $o['model']['item']['template'];
                    // the template pan-os-php names (CallContext: every object of a template)
                    elseif( isset( $o['template'] ) && is_string( $o['template'] ) && $o['template'] !== '' )
                    {
                        $row['template'] = $o['template'];
                        if( $row['location'] === $o['template'] )
                            $row['location'] = 'shared';
                    }
                    // an object of the shared part of a template / template stack (certificates, certificate
                    // profiles, …): pan-os-php names the template as location - for pan-os-php it is template=<name>
                    // location=shared (before: location <template> - "location not found", no references)
                    elseif( in_array( $sub['type'] ?? '', array( 'Template', 'TemplateStack' ), TRUE ) && $location !== 'shared' )
                    {
                        $row['location'] = 'shared';
                        $row['template'] = $location;
                    }
                    if( isset( $sub['store'] ) && is_string( $sub['store'] ) )
                        $row['store'] = $sub['store'];
                    // variables of a device: in the list only their names (the window has them with values and origin)
                    if( !$nested && isset( $o['effective'] ) && is_array( $o['effective'] ) )
                    {
                        $o['variables'] = array_keys( $o['effective'] );
                        unset( $o['effective'], $o['devicevariables'] );
                    }
                    foreach( $o as $k => $v )
                        // the list: nested values flat (a list of texts); the object window: as they are ($nested)
                        $row[(string)$k] = ( is_array( $v ) && $k !== 'model' && $k !== 'fields' && !$nested ) ? array_map( 'strval', self::flatten( $v ) ) : $v;
                    $rows[] = $row;
                }
            }
        }
        return $rows;
    }

    /** 'bp' of a request: a BP JSON file of the project (file id) for this one read / change; the worker gets its path */
    private function bpArg( array $project, array $in ): array
    {
        if( !isset( $in['bp'] ) || $in['bp'] === '' )
            return array();
        return array( 'x-bp=' . $this->fileGet( $project, $in['bp'], 'bp' )['path'] );
    }

    /** read: all objects of one type, filtered by pan-os-php, from the configuration in memory */
    public function objects( array $user, $pid, $cid, array $in, int $max = 50000, bool $computed = FALSE, bool $nested = FALSE ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        // "<location>:effective": the objects a firewall of this location gets - the location and every level above it
        // (Panorama: parent device groups, shared; SCM: snippets, parent folders with their snippets); each row is
        // marked: the copy that wins for this location, or the one it is hidden by (same name, other level)
        $effective = null;
        // "<location>:effective-predefined": the same with the predefined objects of the type as the level above all
        if( is_string( $in['location'] ?? null ) && preg_match( '/^(.+):effective(-predefined)?$/', $in['location'], $m ) )
        {
            if( $p['scope'] !== null )
                throw new ViewerException( 'not allowed: the effective view reads the levels above your locations', 403 );
            $locs = $this->locations( $user, $pid, $cid );
            foreach( $locs['locations'] as $l )
                if( $l['name'] === $m[1] )
                    $effective = array( 'levels' => $l['levels'], 'ancestor' => $locs['ancestor'] && $locs['config'] === 'panorama', 'at' => $m[1] );
            if( $effective === null )
                throw new ViewerException( 'location ' . $m[1] . ' not found', 400 );
            if( ( $m[2] ?? '' ) !== '' )
                $effective['levels'][] = 'predefined';
            $in['location'] = implode( ',', $effective['levels'] );
        }
        // several levels in one list (any, a device group / folder with the ones below or above, a list): which object
        // overrides a copy of the same name on another level and where it is overridden (columns, page only)
        $locArg = is_string( $in['location'] ?? null ) ? $in['location'] : 'any';
        $overrideView = $max !== PHP_INT_MAX && !$nested && ( $locArg === 'any' || $locArg === '' || strpos( $locArg, ',' ) !== FALSE || preg_match( '/:(includechilddgs|excludemaindg)$/i', $locArg ) );
        $args = $this->queryArgs( $in, $p );
        $type = substr( array_shift( $args ), 5 );
        // the page (not REST): how many objects use each object - a 'refcount' column after 'name', for the References button
        $refcount = $max !== PHP_INT_MAX && !empty( $this->meta()['types'][$type]['references'] );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'read', 'type' => $type,
            'args' => array_merge( $args, array( 'actions=display' ), $computed ? array( 'x-computed' ) : array(), $refcount ? array( 'x-refcount' ) : array(),
                $nested ? array( 'x-xml' ) : array(), $effective !== null ? array( 'x-effective=' . $effective['at'] ) : array(),
                $overrideView ? array( 'x-override' ) : array(),
                $this->bpArg( $p, $in ) ) ) );
        $rows = self::rows( is_array( $r['json'] ?? null ) ? $r['json'] : array(), $nested );
        // predefined objects only at the locations "predefined" and "any": pan-os-php (CLI) lists them at shared too,
        // the viewer shows at shared only the objects of the configuration
        $asked = array_map( function( $l ) { return strtolower( trim( preg_replace( '/:.*$/', '', $l ) ) ); }, explode( ',', $locArg === '' ? 'any' : $locArg ) );
        if( !in_array( 'any', $asked, TRUE ) && !in_array( 'predefined', $asked, TRUE ) )
            $rows = array_values( array_filter( $rows, function( $row ) { return ( $row['location'] ?? null ) !== 'predefined'; } ) );
        elseif( count( $asked ) > 1 && in_array( 'predefined', $asked, TRUE ) )
        {
            // predefined next to shared in one list (the effective view + predefined): a predefined object only once
            $seen = array();
            $rows = array_values( array_filter( $rows, function( $row ) use ( &$seen ) {
                if( ( $row['location'] ?? null ) !== 'predefined' )
                    return TRUE;
                $key = ( $row['type'] ?? '' ) . '|' . ( $row['name'] ?? '' );
                if( isset( $seen[$key] ) )
                    return FALSE;
                return $seen[$key] = TRUE;
            } ) );
        }
        // "Extra columns" of the list: additional fields of exportToExcel (e.g. NestedMembers, ResolveIP), by name
        $extra = $in['columns'] ?? '';
        if( $extra !== '' && $extra !== null && $max !== PHP_INT_MAX )
        {
            $want = is_array( $extra ) ? $extra : explode( '|', (string)$extra );
            $allowed = $this->meta()['types'][$type]['columns'] ?? array();
            foreach( $want as $w )
                if( !is_string( $w ) || !in_array( $w, $allowed, TRUE ) )
                    throw new ViewerException( 'columns: ' . ( $allowed ? implode( ', ', $allowed ) : 'none for type ' . $type ), 400 );
            if( $want )
                $rows = $this->exportExtraColumns( $this->session( $p, $c, $user ), $type, array_merge( $args, $this->bpArg( $p, $in ) ), array_values( array_unique( $want ) ), $rows )['rows'];
        }
        if( $refcount && is_array( $r['refcounts'] ?? null ) )
        {
            // an object listed in another location than its owner (an interface in the vsys it is imported into: counted
            // at the firewall / template) - the one count of this template and name
            $byTail = null;
            foreach( $rows as $i => $row )
            {
                $tail = '|' . ( $row['template'] ?? '' ) . '|' . ( isset( $row['profile'] ) && is_string( $row['profile'] ) ? $row['profile'] . '/' : '' ) . ( $row['name'] ?? '' );
                $n = $r['refcounts'][( $row['location'] ?? '' ) . $tail] ?? null;
                if( $n === null )
                {
                    if( $byTail === null )
                    {
                        $byTail = array();
                        foreach( $r['refcounts'] as $k => $v )
                        {
                            $t = substr( (string)$k, (int)strpos( (string)$k, '|' ) );
                            $byTail[$t] = isset( $byTail[$t] ) ? FALSE : $v;
                        }
                    }
                    $n = isset( $byTail[$tail] ) && $byTail[$tail] !== FALSE ? $byTail[$tail] : null;
                }
                $new = array();
                foreach( $row as $k => $v )
                {
                    $new[$k] = $v;
                    if( $k === 'name' )
                        $new['refcount'] = $n;
                }
                $rows[$i] = $new;
            }
        }
        // the list: no API model and no field data of the window (pan-os-php 'fields')
        if( $max !== PHP_INT_MAX )
            foreach( $rows as $i => $row )
                unset( $rows[$i]['model'], $rows[$i]['fields'] );
        if( $overrideView && is_array( $r['override'] ?? null ) && count( $r['override'] ) )
            foreach( $rows as $i => $row )
            {
                $o = $r['override'][( $row['location'] ?? '' ) . '|' . ( $row['template'] ?? '' ) . '|' . ( $row['name'] ?? '' )] ?? null;
                $new = array();
                // after the name (and its refcount)
                $after = array_key_exists( 'refcount', $row ) ? 'refcount' : 'name';
                foreach( $row as $k => $v )
                {
                    $new[$k] = $v;
                    if( $k === $after )
                    {
                        $new['overrides'] = $o !== null ? $o['overrides'] : array();
                        $new['overridden in'] = $o !== null ? $o['overridden'] : array();
                    }
                }
                $rows[$i] = $new;
            }
        if( $effective !== null )
            $rows = self::effectiveRows( $rows, $effective['levels'], $effective['ancestor'], is_array( $r['effective'] ?? null ) ? $r['effective'] : array() );

        $columns = array();
        foreach( $rows as $row )
            foreach( $row as $k => $v )
                $columns[$k] = TRUE;
        return array( 'total' => count( $rows ), 'truncated' => count( $rows ) > $max, 'columns' => array_keys( $columns ),
            'rows' => array_slice( $rows, 0, $max ), 'status' => $r['status'] ?? null ) + ( $nested ? array( 'xml' => is_array( $r['xml'] ?? null ) ? $r['xml'] : array() ) : array() );
    }

    /**
     * the effective view: rows of all levels (nearest first in $levels), sorted from the top level down; per name the
     * copy that wins ('effective' => 'used') - the nearest, or the highest with ancestor precedence (Panorama) - and the
     * others 'overridden by <location>' (an address and an address group share their names, so the name decides)
     */
    private static function effectiveRows( array $rows, array $levels, bool $ancestor, array $marks = array() ): array
    {
        $pos = array_flip( $levels );
        // "predefined" as the level above all (effective view + predefined): a predefined object is used only when
        // no level of the configuration has the name - also with ancestor precedence, which is about the device groups
        $pre = $pos['predefined'] ?? null;
        $win = array();
        foreach( $rows as $row )
        {
            $n = (string)( $row['name'] ?? '' );
            $l = $pos[$row['location'] ?? ''] ?? PHP_INT_MAX;
            if( !isset( $win[$n] ) || $win[$n] === $pre )
                $win[$n] = $l;
            elseif( $l !== $pre && ( $ancestor ? $l > $win[$n] : $l < $win[$n] ) )
                $win[$n] = $l;
        }
        $out = array();
        foreach( $rows as $row )
        {
            $n = (string)( $row['name'] ?? '' );
            $l = $pos[$row['location'] ?? ''] ?? PHP_INT_MAX;
            $new = array();
            foreach( $row as $k => $v )
            {
                $new[$k] = $v;
                if( $k === 'location' )
                {
                    $new['level'] = $l === PHP_INT_MAX ? null : count( $levels ) - $l;
                    // the lookup of pan-os-php (worker: EDL before address / group / region, parents, snippets,
                    // ancestor precedence) - else (types without such a lookup) the nearest level / the highest one
                    $mark = $marks[( $row['location'] ?? '' ) . '|' . ( $row['template'] ?? '' ) . '|' . $n] ?? null;
                    if( $mark === 'used' )
                        $new['effective'] = 'used';
                    elseif( is_array( $mark ) )
                        $new['effective'] = 'overridden by ' . ( $mark['by'] ?? '?' ) . ( in_array( $mark['class'] ?? '', array( 'EDL', 'Region', 'AddressGroup', 'ServiceGroup' ), TRUE ) && $mark['class'] !== ( $row['type'] ?? '' )
                            ? ' (' . array( 'EDL' => 'EDL', 'Region' => 'region', 'AddressGroup' => 'address group', 'ServiceGroup' => 'service group' )[$mark['class']] . ')' : '' );
                    else
                        $new['effective'] = $l === $win[$n] ? 'used' : 'overridden by ' . ( $levels[$win[$n]] ?? '?' );
                }
            }
            $out[] = $new;
        }
        // from the top (shared / All) down to the location; within a level the order of pan-os-php
        $order = array_keys( $out );
        usort( $order, function( $a, $b ) use ( $out ) { return ( $out[$a]['level'] ?? 0 ) <=> ( $out[$b]['level'] ?? 0 ) ?: $a <=> $b; } );
        return array_map( function( $i ) use ( $out ) { return $out[$i]; }, $order );
    }

    /**
     * What a field of an object can take (the drop down of the object window): GET …/configs/<cid>/candidates?type=
     * &location=&name=&kind= (+ template / ruletype / securityprofiletype / profile as for a read). The names of that
     * kind (address, service, tag, zone, interface, url-category, …) in the location of the object and the locations
     * above it - pan-os-php ObjectCandidates, the levels pan-os-php resolves a name in. A member limited to locations
     * gets only the groups of those locations.
     */
    public function candidates( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $name = $in['name'] ?? null;
        if( !is_string( $name ) || $name === '' || strlen( $name ) > 300 || preg_match( '/[\x00-\x1F\x7F]/', $name ) )
            throw new ViewerException( 'name: the name of the object', 400 );
        $kind = $in['kind'] ?? null;
        if( !is_string( $kind ) || !preg_match( '/^[a-z][a-z-]{1,40}$/', $kind ) )
            throw new ViewerException( 'kind: e.g. address, service, tag, zone, interface, url-category', 400 );
        $profile = $in['profile'] ?? '';
        if( !is_string( $profile ) || strlen( $profile ) > 300 || preg_match( '/[\x00-\x1F\x7F]/', $profile ) )
            throw new ViewerException( 'profile: the security profile of the rule', 400 );
        $args = $this->queryArgs( array( 'filter' => '' ) + $in, $p );
        $type = substr( array_shift( $args ), 5 );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'candidates', 'type' => $type, 'args' => $args, 'name' => $name,
            'profile' => $profile, 'kind' => $kind ), 300 );
        if( empty( $r['ok'] ) )
            throw new ViewerException( is_string( $r['error'] ?? null ) ? $this->hidePaths( $r['error'] ) : 'the candidates could not be read', 400 );
        $groups = array();
        foreach( is_array( $r['groups'] ?? null ) ? $r['groups'] : array() as $g )
        {
            $loc = (string)( $g['location'] ?? '' );
            // a member limited to locations: only those (the label without "template ", " / vsys…", " (used in rules)")
            $base = preg_replace( '/^template | \/ .*$| \(used in rules\)$/', '', $loc );
            if( $p['scope'] !== null && !in_array( $base, $p['scope'], TRUE ) && $loc !== 'predefined' )
                continue;
            $groups[] = array( 'location' => $loc, 'names' => array_values( array_filter( (array)( $g['names'] ?? array() ), 'is_string' ) ) );
        }
        return array( 'kind' => $kind, 'groups' => $groups );
    }

    /**
     * Who uses an object: GET …/configs/<cid>/references?type=&location=&name= (+ ruletype / securityprofiletype as for a
     * read). Every object of that name in the location, with the objects that reference it (type, location, name, rule
     * type / pre-post, fields). A member limited to types / locations sees only references inside them (the others are
     * counted as 'hidden').
     */
    public function references( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $name = $in['name'] ?? null;
        if( !is_string( $name ) || $name === '' || strlen( $name ) > 300 || preg_match( '/[\x00-\x1F\x7F]/', $name ) )
            throw new ViewerException( 'name: the name of the object', 400 );
        $args = $this->queryArgs( array( 'filter' => '' ) + $in, $p );
        $type = substr( array_shift( $args ), 5 );
        if( empty( $this->meta()['types'][$type]['references'] ) )
            throw new ViewerException( 'type ' . $type . ' has no references', 400 );
        $profile = $in['profile'] ?? '';
        if( !is_string( $profile ) || strlen( $profile ) > 300 || preg_match( '/[\x00-\x1F\x7F]/', $profile ) )
            throw new ViewerException( 'profile: the security profile of the rule', 400 );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'references', 'type' => $type, 'args' => $args, 'name' => $name, 'profile' => $profile ), 300 );
        if( empty( $r['ok'] ) )
            throw new ViewerException( is_string( $r['error'] ?? null ) ? $this->hidePaths( $r['error'] ) : 'the references could not be read', 500 );
        $objects = array();
        foreach( is_array( $r['objects'] ?? null ) ? $r['objects'] : array() as $o )
        {
            $refs = array();
            $hidden = 0;
            foreach( is_array( $o['references'] ?? null ) ? $o['references'] : array() as $ref )
            {
                $t = $ref['type'] ?? null;
                if( ( $p['types'] !== null && !in_array( $t, $p['types'], TRUE ) ) || ( $p['scope'] !== null && !in_array( $ref['location'] ?? null, $p['scope'], TRUE ) ) )
                {
                    $hidden++;
                    continue;
                }
                // a reference the page can open: a type the viewer shows
                $ref['open'] = $t !== null && isset( $this->meta()['types'][$t] ) && is_string( $ref['location'] ?? null );
                $refs[] = $ref;
            }
            $objects[] = array( 'location' => $o['location'] ?? null, 'class' => $o['class'] ?? null, 'references' => $refs, 'hidden' => $hidden );
        }
        return array( 'type' => $type, 'name' => $name, 'objects' => $objects );
    }

    /**
     * NAT rule: the security rules its traffic meets, in their order (pan-os-php NatSecurityMatch, as actions=
     * display-nat-security) - per direction and firewall context. A member limited to types / locations: the security
     * rules outside of them are counted, not named.
     */
    public function natSecurity( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $name = $in['name'] ?? null;
        if( !is_string( $name ) || $name === '' || strlen( $name ) > 300 || preg_match( '/[\x00-\x1F\x7F]/', $name ) )
            throw new ViewerException( 'name: the name of the NAT rule', 400 );
        $args = $this->queryArgs( array( 'filter' => '', 'type' => 'rule', 'ruletype' => 'nat' ) + $in, $p );
        $type = substr( array_shift( $args ), 5 );
        if( $type !== 'rule' )
            throw new ViewerException( 'type: rule (NAT) only', 400 );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'natsecurity', 'type' => 'rule', 'args' => $args, 'name' => $name ), 300 );
        if( empty( $r['ok'] ) || !is_array( $r['result'] ?? null ) )
            throw new ViewerException( is_string( $r['error'] ?? null ) ? $this->hidePaths( $r['error'] ) : 'the security rules could not be read', 500 );
        $res = $r['result'];
        $typeOk = $p['types'] === null || in_array( 'rule', $p['types'], TRUE );
        foreach( $res['directions'] ?? array() as $di => $d )
        {
            // a firewall context of a device group outside the locations of the member: counted only
            $res['directions'][$di]['hiddenContexts'] = 0;
            foreach( $d['contexts'] ?? array() as $ci => $ctx )
                if( $p['scope'] !== null && isset( $ctx['deviceGroup'] ) && !in_array( $ctx['deviceGroup'], $p['scope'], TRUE ) )
                {
                    unset( $res['directions'][$di]['contexts'][$ci] );
                    $res['directions'][$di]['hiddenContexts']++;
                }
            $res['directions'][$di]['contexts'] = array_values( $res['directions'][$di]['contexts'] );
        }
        foreach( $res['directions'] ?? array() as $di => $d )
            foreach( $d['contexts'] ?? array() as $ci => $ctx )
            {
                $kept = array();
                $hidden = 0;
                foreach( $ctx['matches'] ?? array() as $m )
                {
                    if( !$typeOk || ( $p['scope'] !== null && !in_array( $m['locationName'] ?? null, $p['scope'], TRUE ) ) )
                    {
                        $hidden++;
                        continue;
                    }
                    $kept[] = $m;
                }
                $res['directions'][$di]['contexts'][$ci]['matches'] = $kept;
                $keptMm = array();
                foreach( $ctx['mismatches'] ?? array() as $m )
                {
                    if( !$typeOk || ( $p['scope'] !== null && !in_array( $m['locationName'] ?? null, $p['scope'], TRUE ) ) )
                    {
                        $hidden++;
                        continue;
                    }
                    $keptMm[] = $m;
                }
                $res['directions'][$di]['contexts'][$ci]['mismatches'] = $keptMm;
                // the rule that blocks the traffic: named only when the member may see it
                $bb = $ctx['blockedBy'] ?? null;
                if( is_array( $bb ) && ( !$typeOk || ( $p['scope'] !== null && !in_array( $bb['locationName'] ?? null, $p['scope'], TRUE ) ) ) )
                {
                    $res['directions'][$di]['contexts'][$ci]['blockedBy'] = array( 'rule' => '(outside your types / locations)', 'action' => $bb['action'] ?? '', 'location' => '', 'locationName' => null, 'position' => null );
                    $res['directions'][$di]['contexts'][$ci]['notes'] = array_values( array_filter( $ctx['notes'] ?? array(), function( $n ) { return strpos( $n, 'traffic blocked by rule' ) !== 0; } ) );
                }
                $res['directions'][$di]['contexts'][$ci]['hidden'] = $hidden;
            }
        return $res;
    }

    /**
     * REST: GET …/configs/<cid>/<resource>[/<name>] - the objects of one type as items, with paging.
     * 'model' names the shape of an item: 'display-v0' = the fields of pan-os-php actions=display (not a stable model yet).
     */
    public function resourceList( array $user, $pid, $cid, string $type, array $in, ?string $name = null, ?string $resource = null ): array
    {
        $model = $in['model'] ?? ( isset( self::SCM_RESOURCES[(string)$resource] ) ? 'scm-v1' : 'display-v0' );
        if( $model !== 'display-v0' && !( $model === 'scm-v1' && isset( self::SCM_RESOURCES[(string)$resource] ) ) )
            throw new ViewerException( 'model: display-v0' . ( isset( self::SCM_RESOURCES[(string)$resource] ) ? ' or scm-v1' : ' (this resource has no scm-v1 model yet)' ), 400 );
        $in['type'] = $type;
        foreach( self::SCM_RESOURCE_ARGS[(string)$resource] ?? array() as $k => $v )
            $in[$k] = $v;
        if( $name !== null )
        {
            // the name goes into a pan-os-php filter: only characters that can not change the filter
            if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._\-]{0,127}$/', $name ) )
                throw new ViewerException( 'object name: letters, digits, space and . _ - only (use ?filter= for other names)', 400 );
            $in['filter'] = '(name eq ' . $name . ')';
        }
        $limit = $in['limit'] ?? self::PAGE_DEFAULT;
        $offset = $in['offset'] ?? 0;
        if( !is_numeric( $limit ) || (int)$limit < 1 || (int)$limit > self::PAGE_MAX || !is_numeric( $offset ) || (int)$offset < 0 )
            throw new ViewerException( 'limit: 1-' . self::PAGE_MAX . ', offset: 0 or more', 400 );
        // ?computed=1: the values pan-os-php calculates (references, visibility, best practice, checks) as _panosphp
        $computed = isset( $in['computed'] ) && (string)$in['computed'] === '1';
        if( $computed && $model !== 'scm-v1' )
            throw new ViewerException( 'computed=1 needs the scm-v1 model', 400 );
        $r = $this->objects( $user, $pid, $cid, $in, PHP_INT_MAX, $computed );
        $items = $r['rows'];
        if( $model === 'scm-v1' )
        {
            // the SCM shaped object of the library (ApiObjectModel); one pan-os-php type can hold several SCM resources
            $scm = array();
            foreach( $items as $o )
                if( isset( $o['model']['resource'], $o['model']['item'] ) && $o['model']['resource'] === $resource && is_array( $o['model']['item'] ) )
                    $scm[] = $o['model']['item'];
            $items = $scm;
        }
        else
            foreach( $items as $i => $o )
                unset( $items[$i]['model'] );
        if( $name !== null )
        {
            $items = array_values( array_filter( $items, function( $o ) use ( $name ) { return isset( $o['name'] ) && (string)$o['name'] === $name; } ) );
            if( count( $items ) == 0 )
                throw new ViewerException( 'not found', 404 );
        }
        return array( 'type' => $type, 'resource' => $resource ?? self::resourceName( $type ), 'model' => $model, 'total' => count( $items ),
            'offset' => (int)$offset, 'limit' => (int)$limit, 'items' => array_slice( $items, (int)$offset, (int)$limit ), 'status' => $r['status'] );
    }

    /**
     * one object for the object window: GET …/configs/<cid>/object?type=&location=&name= (+ ruletype /
     * securityprofiletype) - its fields as the table shows them ('row') and its structured form ('model', the scm-v1
     * item of the library: values, members, tags as lists)
     */
    public function objectGet( array $user, $pid, $cid, array $in ): array
    {
        $name = $in['name'] ?? null;
        if( !is_string( $name ) || $name === '' || strlen( $name ) > 300 || preg_match( '/[\x00-\x1F\x7F()]/', $name ) || trim( $name ) !== $name )
            throw new ViewerException( 'name: the name of the object (no brackets)', 400 );
        $location = $in['location'] ?? '';
        $tpl = is_string( $in['template'] ?? null ) && $in['template'] !== '';
        if( !is_string( $location ) || $location === '' || ( $location === 'any' && !$tpl ) )
            throw new ViewerException( 'location: the location of the object', 400 );
        $template = is_string( $in['template'] ?? null ) ? $in['template'] : '';
        // an object of a template (Panorama): pan-os-php reads it with template= and its location (shared or a vsys of the
        // template: UTIL::templateVirtualSystem); location=any lists an interface / router imported into a vsys only at
        // the template itself - the row is matched by its location and template
        $r = $this->objects( $user, $pid, $cid, array( 'filter' => '(name eq ' . $name . ')' ) + $in, PHP_INT_MAX, FALSE, TRUE );
        // a DNS rule / threat rule: the one of this security profile
        $profile = is_string( $in['profile'] ?? null ) ? $in['profile'] : '';
        // a security profile: only one of the profile type asked for (an URL profile can have the name of a
        // virus-and-wildfire-analysis profile in the same folder)
        $st = ( $in['type'] ?? null ) === 'securityprofile' ? ( $in['securityprofiletype'] ?? 'any' ) : 'any';
        foreach( $r['rows'] as $row )
            if( ( $row['name'] ?? null ) === $name && ( $location === 'any' || ( $row['location'] ?? null ) === $location ) && ( $template === '' || ( $row['template'] ?? '' ) === $template )
                && ( $profile === '' || ( $row['profile'] ?? '' ) === $profile ) && self::spTypeMatches( $row['type'] ?? null, $st ) )
            {
                $model = is_array( $row['model']['item'] ?? null ) ? $row['model']['item'] : null;
                // the fields of the window (EDL, schedule, log forwarding, security profile details): values and choices
                $fields = is_array( $row['fields'] ?? null ) ? $row['fields'] : null;
                unset( $row['model'], $row['fields'] );
                // its XML and its history (git, the commits that changed its entry - the unsaved ones first)
                $x = $r['xml'][( $row['location'] ?? '' ) . '|' . ( $row['template'] ?? '' ) . '|' . ( isset( $row['profile'] ) && is_string( $row['profile'] ) ? $row['profile'] . '/' : '' ) . $name] ?? null;
                // an object listed in another location than its owner (an interface: in the vsys it is imported into,
                // its XML belongs to the firewall / template) - the one XML of this template and name
                if( $x === null && is_array( $r['xml'] ?? null ) )
                {
                    $tail = '|' . ( $row['template'] ?? '' ) . '|' . ( isset( $row['profile'] ) && is_string( $row['profile'] ) ? $row['profile'] . '/' : '' ) . $name;
                    $same = array_values( array_filter( array_keys( $r['xml'] ), function( $k ) use ( $tail ) { return substr( $k, -strlen( $tail ) ) === $tail; } ) );
                    if( count( $same ) === 1 )
                        $x = $r['xml'][$same[0]];
                }
                $path = is_array( $x ) && is_string( $x['path'] ?? null ) ? $x['path'] : null;
                return array( 'row' => $row, 'model' => $model, 'fields' => $fields, 'xml' => is_array( $x ) && is_string( $x['xml'] ?? null ) ? $x['xml'] : null,
                    'history' => $path !== null ? $this->objectHistory( $user, $pid, $cid, $path, ( $row['location'] ?? '' ) . ':' . $name ) : null, 'status' => $r['status'] );
            }
        throw new ViewerException( 'not found', 404 );
    }

    /**
     * "Result as new version" of a run (object-merger, rule-merger, playbook, …): the result configuration as one commit
     * on the history of the version the run ran on (refs/viewer/versions/<parent> - created from the parent file when
     * that version was never opened) into refs/viewer/versions/<new>. The objects the run changed or removed get this
     * commit in their History; the message names the run and its settings, for a merger also per object what happened
     * (Merged: removed -> kept, Not-merged: copy (kept …): reason) - so the kept object shows the run as well although
     * its own entry did not change. Never stops the save: errors only end up in the PHP error log.
     */
    private function runHistory( array $p, array $j, array $user, string $parentFile, string $newFile ): void
    {
        if( getenv( 'PANOSPHP_VIEWER_GIT' ) === '0' )
            return;
        try
        {
            $dir = $this->projectDir( $p['pid'] );
            $git = new ViewerGit( $dir . '/history.git' );
            if( !$git->ready() )
                return;
            $load = function( string $f ) {
                $d = new DOMDocument();
                if( !@$d->load( $f, LIBXML_PARSEHUGE | LIBXML_NONET ) )
                    throw new Exception( 'can not read ' . basename( $f ) );
                return ConfigObjectSplit::files( ConfigObjectSplit::state( $d ) );
            };
            $parentKey = basename( $parentFile, '.xml' );
            $head = $git->ref( 'refs/viewer/versions/' . $parentKey );
            if( $head === null )
                $head = $git->commit( 'refs/viewer/versions/' . $parentKey, null, $load( $dir . '/' . $parentFile ), array(),
                    "version " . $parentKey . "\n\nVersion: " . $parentKey . "\n", 'config-viewer', time(), TRUE );
            $git->commit( 'refs/viewer/versions/' . basename( $newFile, '.xml' ), $head, $load( $dir . '/' . $newFile ), array(),
                $this->runMessage( $p, $j, $user ), (string)$user['name'], time(), TRUE );
        }
        catch( Throwable $e )
        {
            error_log( 'config-viewer history (run ' . substr( $j['jid'], 0, 8 ) . '): ' . $e->getMessage() );
        }
    }

    /** the message of the commit of a run result: subject, per object of a merger what happened, the trailers */
    private function runMessage( array $p, array $j, array $user ): string
    {
        $args = array();
        foreach( (array)json_decode( (string)$j['args'], TRUE ) as $a )
            if( is_string( $a ) && !preg_match( '/^(in|out|exportjson|exportcsv|json)=/i', $a ) )
                $args[] = $a;
        $settings = $this->hidePaths( implode( ' ', $args ) );
        $m = ViewerGit::oneLine( substr( $j['type'] . ' run ' . substr( $j['jid'], 0, 8 ) . ( $settings !== '' ? ': ' . $settings : '' ), 0, 200 ) ) . "\n\n";
        $rep = $this->jobDir( $p, $j['jid'] ) . '/merger.json';
        $r = is_file( $rep ) && !is_link( $rep ) && filesize( $rep ) < 200000000 ? json_decode( (string)file_get_contents( $rep ), TRUE ) : null;
        $ref = function( $x ) { return is_array( $x ) ? ( ( $x['location'] ?? '' ) !== '' ? $x['location'] . ':' : '' ) . ( $x['name'] ?? '' ) : ''; };
        $lines = array();
        if( is_array( $r ) && ( $r['type'] ?? '' ) === 'rule-merger' )
        {
            foreach( $r['merged'] ?? array() as $x )
                foreach( $x['removed'] ?? array() as $o )
                    $lines[] = 'Merged: ' . ( $x['location'] ?? '' ) . ':' . ( $o['name'] ?? '' ) . ' -> ' . ( $x['location'] ?? '' ) . ':' . ( $x['rule'] ?? '' );
            foreach( $r['skipped'] ?? array() as $x )
                foreach( $x['notMergedWith'] ?? array() as $o )
                    $lines[] = 'Not-merged: ' . ( $x['location'] ?? '' ) . ':' . ( $x['rule'] ?? '' ) . ( ( $o['name'] ?? '' ) !== '' ? ' (with ' . $o['name'] . ')' : '' ) . ': ' . ( $o['reason'] ?? '' );
        }
        elseif( is_array( $r ) )
        {
            foreach( $r['merged'] ?? array() as $x )
                foreach( $x['removed'] ?? array() as $o )
                    $lines[] = 'Merged: ' . $ref( $o ) . ' -> ' . $ref( $x['kept'] ?? null );
            foreach( $r['skipped'] ?? array() as $x )
                foreach( $x['notMergedWith'] ?? array() as $o )
                    $lines[] = 'Not-merged: ' . $ref( $o ) . ( isset( $x['kept'] ) ? ' (kept ' . $ref( $x['kept'] ) . ')' : '' ) . ': ' . trim( implode( ' ', (array)( $x['reason'] ?? array() ) ) );
        }
        foreach( $lines as $l )
            $m .= ViewerGit::oneLine( substr( $l, 0, 2000 ) ) . "\n";
        if( count( $lines ) )
            $m .= "\n";
        $m .= 'Type: ' . ViewerGit::oneLine( (string)$j['type'] ) . "\n" . 'Run: ' . substr( $j['jid'], 0, 8 ) . "\n";
        if( $settings !== '' )
            $m .= 'Settings: ' . ViewerGit::oneLine( $settings ) . "\n";
        return $m;
    }

    /**
     * the commits of the history of the version (unsaved changes, then the versions it came from) that changed one
     * entry: commit, time, user, subject, the change (trailers), the text of the entry after it (null: removed)
     */
    private function objectHistory( array $user, $pid, $cid, string $path, string $object = '' ): ?array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $git = new ViewerGit( $this->projectDir( $p['pid'] ) . '/history.git' );
        if( !is_file( $git->dir() . '/HEAD' ) )
            return null;
        $key = basename( $c['file'], '.xml' );
        $ref = $git->ref( 'refs/viewer/work/' . $key ) !== null ? 'refs/viewer/work/' . $key : 'refs/viewer/versions/' . $key;
        $list = array();
        $seen = array();
        // the lines of a run commit (Merged: / Not-merged:) about this object: "<location>:<name>" as a whole
        $about = function( array $e ) use ( $object ) {
            if( $object === '' )
                return array();
            $q = preg_quote( $object, '/' );
            return array_values( array_filter( $e['notes'] ?? array(), function( $l ) use ( $q ) {
                return preg_match( '/(?:^[A-Za-z-]+: |-> |\(kept |\(with )' . $q . '(?=$| |:|\))/', $l ) === 1; } ) );
        };
        foreach( $git->log( $ref, 30, $path ) as $e )
        {
            $e['text'] = $git->show( $e['commit'], $path );
            $e['notes'] = $about( $e );
            $seen[$e['commit']] = TRUE;
            $list[] = $e;
        }
        // run results (merger) that name this object without changing its entry (e.g. the kept object of a merge)
        $order = array();
        foreach( $git->log( $ref, 200 ) as $i => $e )
        {
            $order[$e['commit']] = $i;
            if( !isset( $seen[$e['commit']] ) && isset( $e['change']['run'] ) && count( $notes = $about( $e ) ) > 0 )
            {
                $e['text'] = $git->show( $e['commit'], $path );
                $e['notes'] = $notes;
                $list[] = $e;
            }
        }
        // newest first: the order of git (commits of the same second keep their order)
        usort( $list, function( $a, $b ) use ( $order ) {
            return ( $order[$a['commit']] ?? PHP_INT_MAX ) <=> ( $order[$b['commit']] ?? PHP_INT_MAX ) ?: $b['time'] <=> $a['time']; } );
        foreach( $list as &$e )
            unset( $e['change']['settings'] );
        unset( $e );
        return array( 'path' => $path, 'commits' => array_slice( $list, 0, 40 ) );
    }

    /** change: runs actions on the configuration in memory. Nothing is written until save(). */
    public function change( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $args = $this->queryArgs( $in, $p );
        $type = substr( array_shift( $args ), 5 );
        $args[] = $this->actionsArg( $type, $in['actions'] ?? null, $p );
        $bpArg = $this->bpArg( $p, $in );
        // the change as data (change list of the page; later: the trailers of a git commit) - see
        // todo/config-viewer-panos-style-edit.md
        $note = array( 'time' => time(), 'user' => (string)$user['name'], 'type' => $type, 'args' => $args );
        foreach( $args as $a )
            if( preg_match( '/^(location|template|filter|actions|ruletype|securityprofiletype)=(.*)$/s', $a, $m ) )
                $note[$m[1]] = $m[2];
        if( isset( $in['field'] ) && is_string( $in['field'] ) && preg_match( '/^[a-z][a-z0-9_-]{0,40}$/', $in['field'] ) )
            $note['field'] = $in['field'];
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'change', 'type' => $type, 'args' => array_merge( $args, $bpArg ), 'note' => $note ) );
        return array( 'processed' => count( self::rows( is_array( $r['json'] ?? null ) ? $r['json'] : array() ) ),
            'log' => isset( $r['json']['log'] ) && is_string( $r['json']['log'] ) ? substr( $this->hidePaths( $r['json']['log'] ), 0, 200000 ) : '',
            'status' => $r['status'] ?? null );
    }

    /**
     * undo of one unsaved change (POST …/configs/<cid>/undo, body index = its place in the change list): git takes its
     * commit back on the current state, the worker loads the result again (bin/worker.php viewerUndo). Refused when a
     * later change touched the same objects. A member limited to types / locations may undo only a change he could
     * have made.
     */
    public function undo( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $index = $in['index'] ?? null;
        if( !is_int( $index ) || $index < 0 )
            throw new ViewerException( 'index: the number of the change in the list (from 0)', 400 );
        $files = $this->session( $p, $c, $user );
        $changes = (array)( $this->workerCall( $files, array( 'cmd' => 'status' ), 30 )['status']['changes'] ?? array() );
        $ch = $changes[$index] ?? null;
        if( !is_array( $ch ) || !is_string( $ch['type'] ?? null ) || $ch['type'] === 'undo' )
            throw new ViewerException( 'no change with this number that can be taken back', 404 );
        // a change of the system settings (type=config-section): only without type / location limits
        if( $ch['type'] === 'config-section' )
            self::needUnlimited( $p, 'undo of a change of the system settings' );
        else
        {
            $q = array( 'type' => $ch['type'] );
            foreach( array( 'location', 'template', 'ruletype', 'securityprofiletype' ) as $k )
                if( isset( $ch[$k] ) && is_string( $ch[$k] ) )
                    $q[$k] = $ch[$k];
            $this->queryArgs( $q, $p );
        }
        $r = $this->workerCall( $files, array( 'cmd' => 'undo', 'index' => $index, 'note' => array( 'time' => time(), 'user' => (string)$user['name'] ) ) );
        return array( 'undone' => TRUE, 'unresolved' => array_values( array_filter( (array)( $r['unresolved'] ?? array() ), 'is_string' ) ),
            'warning' => is_string( $r['warning'] ?? null ) ? $r['warning'] : null, 'status' => $r['status'] ?? null );
    }

    /**
     * The locations of a version, for the location choice: Panorama - shared + device groups, firewall - shared + vsys,
     * SCM - containers + snippets (loads the version like a read). A member limited to locations gets only those, and
     * no 'any'. Panorama also: the templates / template stacks with their vsys (network types, template=). Panorama /
     * firewall: 'version' (PAN-OS, e.g. 101 = 10.1).
     */
    public function locations( array $user, $pid, $cid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'locations' ), 120 );
        $list = array();
        foreach( is_array( $r['locations'] ?? null ) ? $r['locations'] : array() as $l )
            if( is_array( $l ) && is_string( $l['name'] ?? null ) && is_string( $l['kind'] ?? null ) )
            {
                $one = array( 'name' => $l['name'], 'kind' => $l['kind'], 'levels' => is_array( $l['levels'] ?? null ) ? array_values( array_filter( $l['levels'], 'is_string' ) ) : array( $l['name'] ) );
                // SCM: the group of the choice (All / Prisma Access folders / containers / …), the list comes in that order
                if( in_array( $l['group'] ?? null, array( 'all', 'prisma-access', 'container', 'on-prem', 'snippet' ), TRUE ) )
                    $one['group'] = $l['group'];
                // the hierarchy of the choice: a child device group / folder / firewall below its parent
                if( is_int( $l['depth'] ?? null ) && $l['depth'] > 0 && $l['depth'] <= 50 && is_string( $l['parent'] ?? null ) )
                {
                    $one['depth'] = $l['depth'];
                    $one['parent'] = $l['parent'];
                }
                $list[] = $one;
            }
        if( $p['scope'] !== null )
        {
            $scope = array_map( 'strtolower', $p['scope'] );
            $list = array_values( array_filter( $list, function( $l ) use ( $scope ) { return in_array( strtolower( $l['name'] ), $scope, TRUE ); } ) );
            // the hierarchy among the locations that are left: a parent outside of the scope is not shown, its child
            // moves up
            $parentOf = array();
            foreach( $list as $l )
                $parentOf[$l['name']] = $l['parent'] ?? null;
            foreach( $list as $i => $l )
            {
                $depth = 0;
                for( $up = $l['parent'] ?? null; $up !== null && array_key_exists( $up, $parentOf ) && $depth < 50; $up = $parentOf[$up] )
                    $depth++;
                unset( $list[$i]['depth'], $list[$i]['parent'] );
                if( $depth > 0 )
                {
                    $list[$i]['depth'] = $depth;
                    $list[$i]['parent'] = $l['parent'];
                }
            }
        }
        // Panorama, network types: templates / template stacks with their vsys (not for a member limited to locations)
        $templates = array();
        if( $p['scope'] === null )
            foreach( is_array( $r['templates'] ?? null ) ? $r['templates'] : array() as $t )
                if( is_array( $t ) && is_string( $t['name'] ?? null ) && in_array( $t['kind'] ?? null, array( 'template', 'template-stack' ), TRUE ) )
                    $templates[] = array( 'name' => $t['name'], 'kind' => $t['kind'],
                        'vsys' => is_array( $t['vsys'] ?? null ) ? array_values( array_filter( $t['vsys'], 'is_string' ) ) : array() );
        return array( 'config' => is_string( $r['config'] ?? null ) ? $r['config'] : 'unknown', 'any' => $p['scope'] === null, 'locations' => $list,
            'templates' => $templates, 'version' => is_int( $r['version'] ?? null ) ? $r['version'] : null, 'ancestor' => !empty( $r['ancestor'] ),
            // the types with predefined objects (UTIL::predefinedTypes): the page offers location "predefined (read only)"
            'predefined' => is_array( $r['predefined'] ?? null ) ? array_values( array_filter( $r['predefined'], 'is_string' ) ) : array() );
    }

    /**
     * System: GET …/configs/<cid>/system?template=<template of Panorama>&location=<SCM folder / snippet / device> - the
     * settings of the configuration (management, system, administrators, authentication, logging, updates) as
     * type=config-section reads them; secrets never. Not for members limited to types / locations (it is the whole
     * device).
     */
    public function system( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        self::needUnlimited( $p, 'the system information' );
        $cmd = array( 'cmd' => 'system' );
        foreach( array( 'template', 'location' ) as $k )
            if( isset( $in[$k] ) && $in[$k] !== '' )
            {
                if( !is_string( $in[$k] ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,200}$/', $in[$k] ) )
                    throw new ViewerException( $k . ': letters, digits, space and . _ - only', 400 );
                $cmd[$k] = $in[$k];
            }
        $r = $this->workerCall( $this->session( $p, $c, $user ), $cmd, 120 );
        if( empty( $r['ok'] ) )
            throw new ViewerException( (string)( $r['error'] ?? 'system information not available' ), 400 );
        unset( $r['ok'] );
        // a section can be changed here: reviewed in action-classes.json ("config-section:<section>") and write permission
        $reviewed = $this->actionClasses()['reviewed'];
        $write = in_array( $p['role'], array( 'write', 'owner' ), TRUE );
        foreach( $r['sections'] as $i => $s )
            $r['sections'][$i]['editable'] = $write && in_array( 'config-section:' . $s['name'], $reviewed, TRUE );
        return $r;
    }

    /**
     * A change of a system setting: POST …/configs/<cid>/system/change - section, action (set / add-member /
     * remove-member / remove-field / delete), entry (entries sections; set on a missing entry creates it), path, value,
     * template (Panorama) / location (SCM). Runs pan-os-php type=config-section on the loaded configuration (the same
     * as the CLI), as one change of the change list (history, undo). Only sections that are reviewed in
     * action-classes.json ("config-section:<section>"); secret fields (password, keys, secrets) never.
     */
    public function systemChange( array $user, $pid, $cid, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        self::needUnlimited( $p, 'a change of the system settings' );
        require_once dirname( __FILE__ ) . '/../../../common/ConfigSection.php';
        $name = $in['section'] ?? '';
        $reg = ConfigSection::registry();
        if( !is_string( $name ) || !isset( $reg[$name] ) )
            throw new ViewerException( 'section: one of type=config-section section=list', 400 );
        if( !in_array( 'config-section:' . $name, $this->actionClasses()['reviewed'], TRUE ) )
            throw new ViewerException( 'section ' . $name . ' can not be changed here (not reviewed in action-classes.json)', 403 );
        $action = $in['action'] ?? '';
        if( !in_array( $action, array( 'set', 'add-member', 'remove-member', 'remove-field', 'delete' ), TRUE ) )
            throw new ViewerException( 'action: set, add-member, remove-member, remove-field or delete', 400 );
        $text = function( $k, $max, $re ) use ( $in ) {
            $v = $in[$k] ?? '';
            if( !is_string( $v ) || strlen( $v ) > $max || preg_match( '/[\x00-\x1F\x7F]/', $v ) || ( $v !== '' && !preg_match( $re, $v ) ) )
                throw new ViewerException( $k . ': not valid', 400 );
            return $v;
        };
        $path = $text( 'path', 300, '/^[A-Za-z0-9_.\-\[\] \/:@]+$/' );
        $value = $text( 'value', 2000, '/^[^\x00-\x1F]*$/' );
        $entry = $text( 'entry', 200, '/^[A-Za-z0-9 _.\-\/:@$]+$/' );
        $template = $text( 'template', 200, '/^[A-Za-z0-9 _.\-]+$/' );
        $location = $text( 'location', 200, '/^[A-Za-z0-9 _.\-]+$/' );
        if( $action !== 'delete' && $path === '' )
            throw new ViewerException( 'path: the field (elements joined by ".", named entries as [name])', 400 );
        if( in_array( $action, array( 'set', 'add-member', 'remove-member' ), TRUE ) && $value === '' )
            throw new ViewerException( 'value: needed for ' . $action, 400 );
        // a secret field is never written from here (its value is not shown either) - nor a masked value
        if( $path !== '' && ConfigSection::isSecret( '', $path ) )
            throw new ViewerException( 'field ' . $path . ' holds a secret - not changed here', 403 );
        if( preg_match( '/^\*\*\* (hidden|encrypted) \*\*\*$/', $value ) || ConfigSection::isSecret( $value ) )
            throw new ViewerException( 'value: a hidden / encrypted value can not be set here', 400 );
        if( $action === 'delete' && $entry === '' )
            throw new ViewerException( 'entry: the entry to delete', 400 );
        // the actions syntax of type=config-section: '/' between actions ('//' = '/')
        $act = $action . ( $path !== '' ? ':' . str_replace( '/', '//', $path ) . ( $value !== '' ? ',' . str_replace( '/', '//', $value ) : '' ) : '' );
        $args = array( 'section=' . $name, 'actions=' . $act );
        if( $entry !== '' )
            $args[] = 'entry=' . $entry;
        if( $template !== '' )
            $args[] = 'template=' . $template;
        if( $location !== '' )
            $args[] = 'location=' . $location;
        $note = array( 'time' => time(), 'user' => (string)$user['name'], 'type' => 'config-section', 'args' => $args, 'section' => $name,
            'actions' => $act ) + ( $entry !== '' ? array( 'filter' => $entry ) : array() ) + ( $template !== '' ? array( 'template' => $template ) : array() )
            + ( $location !== '' ? array( 'location' => $location ) : array() );
        $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'change', 'type' => 'config-section', 'args' => $args, 'note' => $note ) );
        return array( 'log' => isset( $r['json']['log'] ) && is_string( $r['json']['log'] ) ? substr( $this->hidePaths( $r['json']['log'] ), 0, 200000 ) : '',
            'status' => $r['status'] ?? null );
    }
}
