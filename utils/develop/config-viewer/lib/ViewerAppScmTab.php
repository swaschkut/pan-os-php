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
 * the SCM tab (SCM_TAB.md) - egress IP and the Prisma Access pages.
 * Its constants SCM_PA_PAGES / PA_COMPARE_MAX stay in ViewerApp.php (a trait holds no constants before PHP 8.2).
 */
trait ViewerAppScmTab
{
    // ------------------------------------------------------------------ SCM tab (SCM_TAB.md): egress IP

    private static function egressLib(): void
    {
        require_once dirname( __FILE__ ) . '/../../sase/scm/lib/SCMEgressIP.php';
    }

    private function egressDir( array $p ): string
    {
        return $this->projectDir( $p['pid'] ) . '/scm/egress';
    }

    /**
     * the states of the egress IPs of the project (SCM tab): imports (an export / its 92_egress-ip.json / a snapshot)
     * and live reads (runs egress-ip - taken over here when they are done), newest first; the egress-IP keys of the user
     */
    public function scmEgressList( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        $dir = $this->egressDir( $p );
        // live reads that are done: their result into the states of the project (once)
        foreach( $this->q( "SELECT j.*, u.name AS user FROM jobs j LEFT JOIN users u ON u.id = j.user_id WHERE j.project_id = ? AND j.type = 'egress-ip' AND j.state = 'done'",
            array( $p['id'] ) )->fetchAll() as $j )
        {
            $f = $this->jobDir( $p, $j['jid'] ) . '/egress.json';
            if( is_file( $dir . '/' . $j['jid'] . '.json' ) || !is_file( $f ) )
                continue;
            $snap = json_decode( (string)file_get_contents( $f ), TRUE );
            if( !is_array( $snap ) || !isset( $snap['rows'] ) || !is_array( $snap['rows'] ) )
                continue;
            $this->egressStore( $dir, $j['jid'], array( 'source' => 'live', 'user' => (string)$j['user'], 'time' => (int)( $j['finished'] ?? $j['created'] ?? time() ),
                'tsg' => isset( $snap['tsg_id'] ) ? (string)$snap['tsg_id'] : null, 'request' => $snap['request'] ?? null, 'fetched_at' => $snap['fetched_at'] ?? null, 'rows' => $snap['rows'] ) );
        }
        $states = array();
        foreach( glob( $dir . '/*.json' ) ?: array() as $f )
        {
            $s = json_decode( (string)file_get_contents( $f ), TRUE );
            if( !is_array( $s ) )
                continue;
            $states[] = array( 'id' => basename( $f, '.json' ), 'source' => $s['source'] ?? '', 'user' => $s['user'] ?? '', 'time' => (int)( $s['time'] ?? 0 ),
                'tsg' => $s['tsg'] ?? null, 'request' => $s['request'] ?? null, 'fetched_at' => $s['fetched_at'] ?? null, 'name' => $s['name'] ?? null,
                'count' => count( $s['rows'] ?? array() ) );
        }
        usort( $states, function( $a, $b ) { return $b['time'] <=> $a['time'] ?: strcmp( $b['id'], $a['id'] ); } );
        $keys = array();
        if( !isset( $user['token'] ) )
            foreach( $this->keyList( $user ) as $k )
                if( $k['kind'] === 'egressip' && self::bindFits( $p, 'scm', $k['target'] ) )
                    $keys[] = array( 'kid' => $k['kid'], 'target' => $k['target'], 'label' => $k['label'], 'refused' => $this->networkRefusal( 'scm', $k['target'], $user ) );
        self::egressLib();
        return array( 'states' => $states, 'keys' => $keys, 'network' => !empty( $p['network'] ),
            'options' => array( 'servicetype' => SCMEgressIP::SERVICE_TYPES, 'addrtype' => SCMEgressIP::ADDR_TYPES, 'location' => SCMEgressIP::LOCATIONS,
                'env' => SCMEgressIP::ENVIRONMENTS ) );
    }

    private function egressStore( string $dir, string $id, array $state ): void
    {
        if( !is_dir( $dir ) )
            mkdir( $dir, 0700, TRUE );
        $tmp = $dir . '/.' . $id . '.' . getmypid();
        file_put_contents( $tmp, json_encode( $state, JSON_UNESCAPED_SLASHES ) );
        rename( $tmp, $dir . '/' . $id . '.json' );
    }

    /** one state: its rows; with $compare (an older state) the added / removed / changed addresses */
    public function scmEgressGet( array $user, $pid, $id, $compare = null ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        self::egressLib();
        $read = function( $id ) use ( $p ) {
            if( !is_string( $id ) || !preg_match( '/^[0-9a-z]{1,40}$/', $id ) || !is_file( $this->egressDir( $p ) . '/' . $id . '.json' ) )
                throw new ViewerException( 'not found', 404 );
            return json_decode( (string)file_get_contents( $this->egressDir( $p ) . '/' . $id . '.json' ), TRUE );
        };
        $s = $read( $id );
        $out = array( 'id' => $id, 'source' => $s['source'] ?? '', 'tsg' => $s['tsg'] ?? null, 'request' => $s['request'] ?? null, 'fetched_at' => $s['fetched_at'] ?? null,
            'time' => (int)( $s['time'] ?? 0 ), 'rows' => $s['rows'] ?? array() );
        if( $compare !== null && $compare !== '' )
        {
            $o = $read( $compare );
            $out['compare'] = array( 'with' => $compare ) + SCMEgressIP::compare( $o['rows'] ?? array(), $out['rows'] );
        }
        return $out;
    }

    /**
     * an import (SCM tab): the egress IPs of an export (zip of a scm_pa_export.php directory, its
     * infra/92_egress-ip.json) or a snapshot of scm_egress_ip.php save=
     */
    public function scmEgressImport( array $user, $pid, $upload ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        self::egressLib();
        if( !is_array( $upload ) || ( $upload['error'] ?? 1 ) !== 0 || is_array( $upload['tmp_name'] ?? null ) || !is_uploaded_file( (string)$upload['tmp_name'] ) )
            throw new ViewerException( 'file: the egress IPs (92_egress-ip.json of an export, a zip of the export, or a snapshot of scm_egress_ip.php)', 400 );
        if( (int)$upload['size'] > 52428800 )
            throw new ViewerException( 'file: at most 50 MB', 400 );
        $tmp = $this->projectDir( $p['pid'] ) . '/scm/.import-' . bin2hex( random_bytes( 6 ) );
        @mkdir( $tmp, 0700, TRUE );
        try
        {
            $src = (string)$upload['tmp_name'];
            $head = (string)file_get_contents( $src, FALSE, null, 0, 4 );
            if( $head === "PK\x03\x04" )
            {
                // a zip of the export: only its infra/92_egress-ip.json is read (no secrets of the export are kept)
                self::needZip();
                $z = new ZipArchive();
                if( $z->open( $src ) !== TRUE )
                    throw new ViewerException( 'file: the zip can not be read', 400 );
                $found = null;
                for( $i = 0; $i < $z->numFiles; $i++ )
                {
                    $n = (string)$z->getNameIndex( $i );
                    if( preg_match( '#(^|/)infra/92_egress-ip\.json$#', $n ) && strpos( $n, '..' ) === FALSE )
                        $found = $n;
                }
                if( $found === null || ( $z->statName( $found )['size'] ?? 0 ) > 52428800 )
                {
                    $z->close();
                    throw new ViewerException( 'file: the zip has no infra/92_egress-ip.json (export with egressip)', 400 );
                }
                file_put_contents( $tmp . '/egress.json', $z->getFromName( $found ) );
                $z->close();
            }
            else
                copy( $src, $tmp . '/egress.json' );
            try
            {
                $state = SCMEgressIP::fromFile( $tmp . '/egress.json' );
            }
            catch( Exception $e )
            {
                throw new ViewerException( 'file: ' . preg_replace( '#\S*' . preg_quote( $tmp, '#' ) . '\S*#', 'the file', $e->getMessage() ), 400 );
            }
            $raw = json_decode( (string)file_get_contents( $tmp . '/egress.json' ), TRUE );
            if( is_array( $raw ) && isset( $raw['tsg_id'] ) && is_scalar( $raw['tsg_id'] ) && !self::bindFits( $p, 'scm', (string)$raw['tsg_id'] ) )
                throw new ViewerException( 'file: egress IPs of TSG ' . $raw['tsg_id'] . ' - not the SCM tenant of this project', 400 );
            $id = 'i' . time() . bin2hex( random_bytes( 2 ) );
            $this->egressStore( $this->egressDir( $p ), $id, array( 'source' => 'import', 'user' => (string)$user['name'], 'time' => time(),
                'tsg' => is_array( $raw ) && isset( $raw['tsg_id'] ) && is_scalar( $raw['tsg_id'] ) ? (string)$raw['tsg_id'] : null,
                'request' => $state['request'], 'fetched_at' => $state['fetched_at'], 'name' => substr( basename( (string)( $upload['name'] ?? '' ) ), 0, 120 ), 'rows' => $state['rows'] ) );
        }
        finally
        {
            array_map( 'unlink', glob( $tmp . '/*' ) ?: array() );
            @rmdir( $tmp );
        }
        return array( 'id' => $id, 'count' => count( $state['rows'] ) );
    }

    /** a state deleted (write permission) */
    public function scmEgressDelete( array $user, $pid, $id ): void
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        if( !is_string( $id ) || !preg_match( '/^[0-9a-z]{1,40}$/', $id ) || !is_file( $this->egressDir( $p ) . '/' . $id . '.json' ) )
            throw new ViewerException( 'not found', 404 );
        unlink( $this->egressDir( $p ) . '/' . $id . '.json' );
        // a live read stays deleted (not taken over again)
        if( preg_match( '/^[0-9a-f]{32}$/', $id ) )
            @file_put_contents( $this->jobDir( $p, $id ) . '/egress.json', '' );
    }

    // ------------------------------------------------------------------ SCM tab: Prisma Access pages

    /** the pages that show endpoints of $area (a live read of one page gives a state to all of them) */
    private static function scmPaPagesOfArea( string $area ): array
    {
        return array_keys( array_filter( self::SCM_PA_PAGES, function( $d ) use ( $area ) { return $d['area'] === $area; } ) );
    }

    /** the areas of scm_pa_export.php the pages need (read by the SCM import as well) */
    private static function scmPaAreas(): array
    {
        return array_values( array_unique( array_column( self::SCM_PA_PAGES, 'area' ) ) );
    }

    private static function paLib(): void
    {
        require_once dirname( __FILE__ ) . '/../../sase/scm/lib/SCMPrismaAccessCompare.php';
    }

    private function paDir( array $p, string $page ): string
    {
        return $this->projectDir( $p['pid'] ) . '/scm/pa/' . $page;
    }

    /**
     * the export of a run (<jobDir>/scm-export/<TSG>/<time>/) as a state of each of $pages: its manifest (only the
     * endpoints of the page) and their files, as the SCM API gave them (scm_pa_export.php). A page gets a state only
     * when at least one of its endpoints was read. Returns the number of states made.
     */
    private function paCollect( array $p, string $jobDir, string $tsg, string $id, string $source, string $user, int $time, array $pages ): int
    {
        $manifests = glob( $jobDir . '/scm-export/' . $tsg . '/*/manifest.json' ) ?: array();
        if( count( $manifests ) === 0 )
            return 0;
        rsort( $manifests );
        $src = dirname( $manifests[0] );
        $m = json_decode( (string)file_get_contents( $manifests[0] ), TRUE );
        if( !is_array( $m ) || !isset( $m['endpoints'] ) || !is_array( $m['endpoints'] ) )
            return 0;
        $made = 0;
        foreach( $pages as $page )
        {
            $def = self::SCM_PA_PAGES[$page] ?? null;
            $dir = $def !== null ? $this->paDir( $p, $page ) . '/' . $id : null;
            if( $def === null || is_dir( $dir ) )
                continue;
            $eps = array();
            $ok = 0;
            foreach( $m['endpoints'] as $e )
                if( is_array( $e ) && ( $e['area'] ?? '' ) === $def['area'] && ( $def['endpoints'] === null || in_array( $e['name'] ?? '', $def['endpoints'], TRUE ) )
                    && preg_match( '#^' . preg_quote( $def['area'], '#' ) . '/[0-9a-z_.-]+\.json$#', (string)( $e['file'] ?? '' ) ) )
                {
                    $eps[] = $e;
                    if( ( $e['status'] ?? '' ) === 'ok' )
                        $ok++;
                }
            if( $ok === 0 )
                continue;
            $tmp = $this->paDir( $p, $page ) . '/.' . $id . '.' . getmypid();
            @mkdir( $tmp . '/' . $def['area'], 0700, TRUE );
            foreach( $eps as $e )
            {
                $f = $src . '/' . $e['file'];
                if( !is_file( $f ) || is_link( $f ) )
                    continue;
                if( json_decode( (string)file_get_contents( $f ) ) instanceof stdClass )
                    copy( $f, $tmp . '/' . $e['file'] );
            }
            file_put_contents( $tmp . '/manifest.json', json_encode( array( 'format_version' => $m['format_version'] ?? null, 'tool' => $m['tool'] ?? null,
                'areas' => array( $def['area'] ), 'tsg_id' => $tsg, 'created_at' => $m['created_at'] ?? null, 'endpoints' => $eps ), JSON_UNESCAPED_SLASHES ) );
            file_put_contents( $tmp . '/state.json', json_encode( array( 'page' => $page, 'source' => $source, 'user' => $user, 'time' => $time, 'tsg' => $tsg,
                'fetched_at' => $m['created_at'] ?? null ), JSON_UNESCAPED_SLASHES ) );
            rename( $tmp, $dir );
            $made++;
            // flattened once now (the first open of a large list - 75000 entries - would take seconds)
            $st = $this->paState( $p, $page, $id );
            foreach( $st['endpoints'] as $name => $e )
                if( ( $e['status'] ?? '' ) === 'ok' )
                    $this->paFlatData( $st, $name );
        }
        return $made;
    }

    private function paState( array $p, $page, $id ): array
    {
        if( !is_string( $page ) || !isset( self::SCM_PA_PAGES[$page] ) || !is_string( $id ) || !preg_match( '/^[0-9a-z]{1,40}$/', $id )
            || !is_file( $this->paDir( $p, $page ) . '/' . $id . '/state.json' ) )
            throw new ViewerException( 'not found', 404 );
        $dir = $this->paDir( $p, $page ) . '/' . $id;
        $s = (array)json_decode( (string)file_get_contents( $dir . '/state.json' ), TRUE );
        $m = (array)json_decode( (string)file_get_contents( $dir . '/manifest.json' ), TRUE );
        $eps = array();
        foreach( (array)( $m['endpoints'] ?? array() ) as $e )
            $eps[$e['name']] = array( 'status' => $e['status'] ?? null, 'http_code' => $e['http_code'] ?? null, 'error' => $e['error'] ?? null,
                'count' => $e['count'] ?? null, 'file' => $e['file'] ?? null );
        return array( 'id' => $id, 'dir' => $dir, 'source' => $s['source'] ?? '', 'user' => $s['user'] ?? '', 'time' => (int)( $s['time'] ?? 0 ),
            'tsg' => $s['tsg'] ?? null, 'fetched_at' => $s['fetched_at'] ?? null, 'endpoints' => $eps );
    }

    /**
     * the Prisma Access pages and Egress IP from the SCM imports (and reads) the project has done: every run whose
     * export is still there and was not taken yet. Imports before 2.1.63 read only the configuration (area config).
     */
    public function scmPaFromRuns( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        $out = array( 'runs' => 0, 'states' => 0, 'egress' => 0, 'config_only' => 0, 'gone' => 0 );
        foreach( $this->q( "SELECT j.*, u.name AS user FROM jobs j LEFT JOIN users u ON u.id = j.user_id WHERE j.project_id = ? AND j.state = 'done' AND j.type IN ('import', 'scm-pa') ORDER BY j.created",
            array( $p['id'] ) )->fetchAll() as $j )
        {
            $t = self::runTarget( $j );
            if( $t === null || $t[0] !== 'scm' || !self::bindFits( $p, 'scm', $t[1] ) )
                continue;
            $out['runs']++;
            $dir = $this->jobDir( $p, $j['jid'] );
            $manifests = glob( $dir . '/scm-export/' . $t[1] . '/*/manifest.json' ) ?: array();
            if( count( $manifests ) === 0 )
            {
                $out['gone']++;
                continue;
            }
            rsort( $manifests );
            $m = (array)json_decode( (string)file_get_contents( $manifests[0] ), TRUE );
            if( count( array_diff( (array)( $m['areas'] ?? array() ), array( 'config' ) ) ) === 0 )
            {
                $out['config_only']++;
                continue;
            }
            $source = $j['type'] === 'import' ? 'import' : 'live';
            $time = (int)( $j['finished'] ?? $j['created'] );
            $out['states'] += $this->paCollect( $p, $dir, $t[1], $j['jid'], $source, (string)$j['user'], $time, array_keys( self::SCM_PA_PAGES ) );
            if( $this->egressFromExport( $p, $dir, $t[1], $j['jid'], (string)$j['user'], $source === 'import' ? 'SCM import' : 'live' ) )
                $out['egress']++;
        }
        return $out;
    }

    /** the states of a page (newest first), the SCM keys of the user for "Read live" */
    public function scmPaList( array $user, $pid, $page ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        if( !is_string( $page ) || !isset( self::SCM_PA_PAGES[$page] ) )
            throw new ViewerException( 'not found', 404 );
        $states = array();
        foreach( glob( $this->paDir( $p, $page ) . '/*/state.json' ) ?: array() as $f )
        {
            $s = $this->paState( $p, $page, basename( dirname( $f ) ) );
            unset( $s['dir'] );
            $states[] = $s;
        }
        usort( $states, function( $a, $b ) { return $b['time'] <=> $a['time'] ?: strcmp( $b['id'], $a['id'] ); } );
        $keys = array();
        if( !isset( $user['token'] ) )
            foreach( $this->keyList( $user ) as $k )
                if( $k['kind'] === 'scm' && self::bindFits( $p, 'scm', $k['target'] ) )
                    $keys[] = array( 'kid' => $k['kid'], 'target' => $k['target'], 'label' => $k['label'], 'refused' => $this->networkRefusal( 'scm', $k['target'], $user ) );
        return array( 'page' => $page, 'endpoints' => self::SCM_PA_PAGES[$page]['endpoints'], 'states' => $states, 'keys' => $keys, 'network' => !empty( $p['network'] ) );
    }

    /**
     * one state: its endpoints with status, number of entries and size - without their data (a page of Prisma Browser
     * can have 75000 applications): the data of one endpoint with scmPaData, page by page
     */
    public function scmPaGet( array $user, $pid, $page, $id ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        $s = $this->paState( $p, $page, $id );
        foreach( $s['endpoints'] as $name => $e )
        {
            $f = $e['file'] !== null ? $s['dir'] . '/' . $e['file'] : null;
            $s['endpoints'][$name]['bytes'] = $f !== null && is_file( $f ) ? filesize( $f ) : 0;
            unset( $s['endpoints'][$name]['file'] );
        }
        unset( $s['dir'] );
        return $s;
    }

    /** an entry as name / value pairs (as flatPairs of app.js): dotted names, a list of plain values as "a, b" */
    private static function paFlat( $v, string $prefix, array &$out ): void
    {
        if( $v === null )
            return;
        if( $v instanceof stdClass )
        {
            $vars = get_object_vars( $v );
            if( count( $vars ) === 0 && $prefix !== '' )
                $out[$prefix] = '(set)';
            foreach( $vars as $k => $x )
                self::paFlat( $x, $prefix === '' ? (string)$k : $prefix . '.' . $k, $out );
            return;
        }
        if( is_array( $v ) )
        {
            $plain = TRUE;
            foreach( $v as $x )
                if( is_array( $x ) || $x instanceof stdClass )
                    $plain = FALSE;
            if( $plain )
                $out[$prefix] = implode( ', ', array_map( array( 'self', 'paScalar' ), $v ) );
            else
                foreach( $v as $i => $x )
                    self::paFlat( $x, $prefix . '[' . $i . ']', $out );
            return;
        }
        $out[$prefix] = self::paScalar( $v );
    }

    private static function paScalar( $v ): string
    {
        return $v === TRUE ? 'true' : ( $v === FALSE ? 'false' : ( $v === null ? '' : (string)$v ) );
    }

    /**
     * the data of an endpoint flattened once (cache in the folder of the state): an object as pairs, a list as rows
     * (name / value per field) + the columns in the order they first appear
     */
    private function paFlatData( array $s, string $name ): array
    {
        $e = $s['endpoints'][$name] ?? null;
        if( $e === null )
            throw new ViewerException( 'not found', 404 );
        $cache = $s['dir'] . '/cache/' . preg_replace( '/[^a-z0-9_-]/i', '_', $name ) . '.json';
        if( is_file( $cache ) )
        {
            $c = json_decode( (string)file_get_contents( $cache ), TRUE );
            if( is_array( $c ) )
                return $c;
        }
        $f = $e['file'] !== null ? $s['dir'] . '/' . $e['file'] : null;
        $j = $f !== null && is_file( $f ) ? json_decode( (string)file_get_contents( $f ) ) : null;
        $data = $j instanceof stdClass ? ( $j->data ?? null ) : null;
        // one object (a singleton, or a list of one entry without name / value / id): setting / value
        $one = $data instanceof stdClass ? $data : ( is_array( $data ) && count( $data ) === 1 && $data[0] instanceof stdClass
            && !isset( $data[0]->name ) && !isset( $data[0]->value ) && !isset( $data[0]->id ) ? $data[0] : null );
        if( $one !== null )
        {
            $pairs = array();
            self::paFlat( $one, '', $pairs );
            unset( $pairs['id'] );
            $out = array( 'kind' => 'object', 'pairs' => array_map( null, array_keys( $pairs ), array_values( $pairs ) ) );
        }
        else
        {
            $rows = array();
            $cols = array();
            foreach( is_array( $data ) ? $data : array() as $x )
            {
                $r = array();
                if( $x instanceof stdClass || is_array( $x ) )
                    self::paFlat( $x, '', $r );
                else
                    $r['value'] = self::paScalar( $x );
                unset( $r['id'] );
                foreach( $r as $k => $v )
                    $cols[$k] = TRUE;
                $rows[] = $r;
            }
            // the values a column filter offers: columns with at most 50 different values (fewer than the rows)
            $values = array();
            foreach( array_keys( $cols ) as $c )
            {
                $v = array();
                foreach( $rows as $r )
                    if( isset( $r[$c] ) && $r[$c] !== '' && count( $v ) <= 50 )
                        $v[$r[$c]] = TRUE;
                if( count( $v ) > 0 && count( $v ) <= 50 && count( $v ) < count( $rows ) )
                {
                    $values[$c] = array_map( 'strval', array_keys( $v ) );
                    natcasesort( $values[$c] );
                    $values[$c] = array_values( $values[$c] );
                }
            }
            $out = array( 'kind' => 'list', 'columns' => array_keys( $cols ), 'values' => $values, 'rows' => $rows );
        }
        @mkdir( dirname( $cache ), 0700 );
        @file_put_contents( $cache, json_encode( $out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
        return $out;
    }

    /**
     * the data of one endpoint of a state, page by page: $in offset, limit (at most 1000), q (search in every field),
     * f (filter per column: contains, "!text" = without), sort (column), desc. A list returns the rows of the page,
     * the number of all / of the matching rows and the columns; wide entries (more than 10 fields): main = the fields
     * of the first level to show as columns
     */
    public function scmPaData( array $user, $pid, $page, $id, $name, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        $s = $this->paState( $p, $page, $id );
        if( !is_string( $name ) || !isset( $s['endpoints'][$name] ) )
            throw new ViewerException( 'not found', 404 );
        $d = $this->paFlatData( $s, $name );
        if( $d['kind'] === 'object' )
            return $d;
        $low = function( $t ) { return function_exists( 'mb_strtolower' ) ? mb_strtolower( $t ) : strtolower( $t ); };
        $q = $low( trim( (string)( $in['q'] ?? '' ) ) );
        $f = array();
        foreach( (array)( is_string( $in['f'] ?? null ) ? json_decode( $in['f'], TRUE ) : ( $in['f'] ?? array() ) ) as $k => $v )
            if( is_string( $k ) && is_scalar( $v ) && trim( (string)$v ) !== '' )
                $f[$k] = $low( trim( (string)$v ) );
        $rows = $d['rows'];
        if( $q !== '' || count( $f ) > 0 )
            $rows = array_values( array_filter( $rows, function( $r ) use ( $q, $f, $low ) {
                foreach( $f as $k => $v )
                {
                    $x = $low( (string)( $r[$k] ?? '' ) );
                    if( $v[0] === '!' ? ( strlen( $v ) > 1 && strpos( $x, substr( $v, 1 ) ) !== FALSE ) : strpos( $x, $v ) === FALSE )
                        return FALSE;
                }
                return $q === '' || strpos( $low( implode( ' ', $r ) ), $q ) !== FALSE;
            } ) );
        $sort = is_string( $in['sort'] ?? null ) ? $in['sort'] : '';
        if( $sort !== '' )
        {
            $desc = !empty( $in['desc'] ) && $in['desc'] !== 'false' && $in['desc'] !== '0';
            usort( $rows, function( $a, $b ) use ( $sort, $desc ) {
                $c = strnatcasecmp( (string)( $a[$sort] ?? '' ), (string)( $b[$sort] ?? '' ) );
                return $desc ? -$c : $c;
            } );
        }
        $limit = max( 1, min( 1000, (int)( $in['limit'] ?? 100 ) ) );
        $offset = max( 0, (int)( $in['offset'] ?? 0 ) );
        $main = null;
        if( count( $d['columns'] ) > 10 )
        {
            $main = array();
            foreach( $d['columns'] as $c )
                if( strpbrk( $c, '.[' ) === FALSE && count( $main ) < 8 )
                    $main[] = $c;
        }
        $values = array_intersect_key( $d['values'] ?? array(), array_flip( $main ?? $d['columns'] ) );
        return array( 'kind' => 'list', 'total' => count( $d['rows'] ), 'matched' => count( $rows ), 'offset' => $offset, 'limit' => $limit,
            'columns' => $d['columns'], 'main' => $main, 'values' => $values, 'rows' => array_slice( $rows, $offset, $limit ) );
    }

    /**
     * two states compared (left = $old, right = $new): SCMPrismaAccessCompare, the same as scm_pa_compare.php. Without
     * $ep: only the endpoints of the two states (compared one by one when opened); with $ep: that endpoint
     */
    public function scmPaCompare( array $user, $pid, $page, $old, $new, $ep = null ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        $l = $this->paState( $p, $page, $old );
        $r = $this->paState( $p, $page, $new );
        if( $ep === null || $ep === '' )
        {
            $eps = array();
            foreach( array_unique( array_merge( array_keys( $l['endpoints'] ), array_keys( $r['endpoints'] ) ) ) as $n )
                $eps[] = array( 'endpoint' => $n, 'old' => $l['endpoints'][$n]['status'] ?? null, 'new' => $r['endpoints'][$n]['status'] ?? null,
                    'old_count' => $l['endpoints'][$n]['count'] ?? null, 'new_count' => $r['endpoints'][$n]['count'] ?? null );
            return array( 'old' => $old, 'new' => $new, 'endpoints' => $eps );
        }
        if( !is_string( $ep ) || ( !isset( $l['endpoints'][$ep] ) && !isset( $r['endpoints'][$ep] ) ) )
            throw new ViewerException( 'not found', 404 );
        $ls = $l['endpoints'][$ep]['status'] ?? null;
        $rs = $r['endpoints'][$ep]['status'] ?? null;
        if( $ls !== 'ok' || $rs !== 'ok' )
            return array( 'endpoint' => $ep, 'not_comparable' => 'status older: ' . ( $ls ?? 'not read' ) . ', newer: ' . ( $rs ?? 'not read' ) );
        self::paLib();
        $area = self::SCM_PA_PAGES[$page]['area'];
        $meta = SCMPrismaAccessExport::endpointMeta( $area, $ep );
        $load = function( $st ) use ( $ep ) {
            $j = json_decode( (string)file_get_contents( $st['dir'] . '/' . $st['endpoints'][$ep]['file'] ), TRUE );
            return is_array( $j ) && array_key_exists( 'data', $j ) ? $j['data'] : null;
        };
        $c = new SCMPrismaAccessCompare( $l['dir'], $r['dir'] );
        $e = $c->compareEndpoint( array( 'area' => $area, 'container' => null, 'endpoint' => $ep, 'endpoint_key' => $meta['endpoint'] ), $meta, $load( $l ), $load( $r ) );
        $cut = function( array $x ) { return array_slice( $x, 0, self::PA_COMPARE_MAX ); };
        return array( 'endpoint' => $ep, 'singleton' => $e['singleton'], 'key_fields' => $e['key_fields'], 'counts' => $e['counts'],
            'only_left' => $cut( array_column( $e['only_left'], 'key' ) ), 'only_right' => $cut( array_column( $e['only_right'], 'key' ) ),
            'changed' => $cut( array_map( function( $x ) { return array( 'key' => $x['key'], 'changes' => $x['changes'] ); }, $e['changed'] ) ),
            'max' => self::PA_COMPARE_MAX, 'warnings' => $c->warnings );
    }

    public function scmPaDelete( array $user, $pid, $page, $id ): void
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'the SCM tab' );
        self::needScmProject( $p );
        $s = $this->paState( $p, $page, $id );
        foreach( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $s['dir'], FilesystemIterator::SKIP_DOTS ), RecursiveIteratorIterator::CHILD_FIRST ) as $f )
            $f->isDir() ? rmdir( (string)$f ) : unlink( (string)$f );
        rmdir( $s['dir'] );
    }

    /** state of the loaded configuration: unsaved changes, last autosave. Does not start a worker. */
    public function status( array $user, $pid, $cid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        $row = $this->q( 'SELECT sid FROM sessions WHERE project_id = ? AND config_id = ?', array( $p['id'], $c['id'] ) )->fetch();
        if( $row )
        {
            $files = $this->sessionFiles( $this->workDir( $p ), $row['sid'] );
            if( self::workerAlive( $files ) )
                return array( 'loaded' => TRUE ) + (array)( $this->workerCall( $files, array( 'cmd' => 'status' ), 30 )['status'] ?? array() );
        }
        return array( 'loaded' => FALSE, 'dirty' => FALSE, 'changes' => array() );
    }

    /** save: writes the configuration in memory into a NEW version; the loaded configuration continues as that version */
    public function save( array $user, $pid, $cid ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $files = $this->session( $p, $c, $user );
        $file = self::randomId() . '.xml';
        $target = $this->projectDir( $p['pid'] ) . '/' . $file;
        $r = $this->workerCall( $files, array( 'cmd' => 'save', 'file' => $target ) );
        if( empty( $r['saved'] ) )
            return array( 'saved' => FALSE, 'cid' => $c['cid'], 'status' => $r['status'] ?? null );
        if( !is_file( $target ) || !self::isPanosConfig( $target ) )
        {
            @unlink( $target );
            throw new ViewerException( 'saving did not write a configuration', 500 );
        }
        @chmod( $target, 0600 );
        $note = implode( "\n", array_map( array( self::class, 'changeText' ), (array)( $r['changes'] ?? array() ) ) );
        $new = $this->configInsert( $p, $user, $c['name'], $file, (int)$c['id'], substr( $note, 0, 4000 ) );
        $this->q( 'UPDATE configs SET changes = ? WHERE cid = ?', array( json_encode( array_values( (array)( $r['changes'] ?? array() ) ) ), $new['cid'] ) );
        $newId = (int)$this->q( 'SELECT id FROM configs WHERE cid = ?', array( $new['cid'] ) )->fetch()['id'];
        $this->q( 'UPDATE sessions SET config_id = ? WHERE project_id = ? AND config_id = ?', array( $newId, $p['id'], $c['id'] ) );
        return array( 'saved' => TRUE, 'cid' => $new['cid'], 'status' => $r['status'] ?? null );
    }

    /** one step of a playbook per change of the change list (changes as data only; older text lines are skipped) */
    public static function playbookSteps( array $changes ): array
    {
        $steps = array();
        foreach( $changes as $c )
        {
            // an undone change and the undo itself are no steps (the other changes replayed give the same result)
            if( !is_array( $c ) || !is_string( $c['type'] ?? null ) || !is_string( $c['actions'] ?? null ) || $c['actions'] === '' || !empty( $c['undone'] ) || $c['type'] === 'undo' )
                continue;
            $step = array( 'comment' => trim( ( isset( $c['time'] ) ? date( 'Y-m-d H:i T', (int)$c['time'] ) : '' ) . ' ' . (string)( $c['user'] ?? '' )
                . ( isset( $c['field'] ) ? ( $c['field'] === 'multi-edit' ? ' - multi-edit' : ' - field ' . $c['field'] ) : '' ) ), 'type' => $c['type'] );
            foreach( array( 'location', 'template', 'ruletype', 'securityprofiletype', 'filter' ) as $k )
                if( isset( $c[$k] ) && is_string( $c[$k] ) && $c[$k] !== '' )
                    $step[$k] = $k . '=' . $c[$k];
            $step['actions'] = 'actions=' . $c['actions'];
            $steps[] = $step;
        }
        return $steps;
    }

    /**
     * the change list as a pan-os-php playbook (type=playbook): GET …/configs/<cid>/playbook?source=unsaved (the
     * unsaved changes of the loaded version) or source=version (the changes this version was saved from). One step per
     * change: type, location, rule type, filter, actions - and a comment (when, who, field).
     */
    public function playbook( array $user, $pid, $cid, string $source ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $c = $this->configGet( $p, $cid );
        if( $source === 'version' )
            $changes = (array)json_decode( (string)( $this->q( 'SELECT changes FROM configs WHERE id = ?', array( $c['id'] ) )->fetch()['changes'] ?? '' ), TRUE );
        elseif( $source === 'unsaved' )
        {
            $r = $this->workerCall( $this->session( $p, $c, $user ), array( 'cmd' => 'status' ) );
            $changes = (array)( $r['status']['changes'] ?? array() );
        }
        else
            throw new ViewerException( 'source: unsaved or version', 400 );
        $steps = self::playbookSteps( $changes );
        if( count( $steps ) === 0 )
            throw new ViewerException( $source === 'version' ? 'this version was not saved from changes of the viewer' : 'no changes', 400 );
        $pb = array( 'header-comment' => 'changes of the config viewer - project "' . $p['name'] . '", ' . ( $source === 'version' ? 'version ' : 'unsaved changes of version ' )
            . $c['name'] . ' (' . date( 'Y-m-d H:i T', (int)$c['created'] ) . '); exported ' . date( 'Y-m-d H:i T' ) . ' by ' . $user['name'], 'command' => $steps );
        // what the viewer would refuse to run is not exported
        $this->playbookCheck( $pb );
        return $pb;
    }

    /** one line of the change list as text (the note of a saved version): a change is data now, older ones text */
    public static function changeText( $c ): string
    {
        if( !is_array( $c ) )
            return (string)$c;
        if( ( $c['type'] ?? '' ) === 'undo' )
            return 'undo of change ' . ( (int)( $c['index'] ?? -1 ) + 1 ) . ': ' . (string)( $c['undoes'] ?? '' ) . ' [' . ( $c['user'] ?? '?' ) . ']';
        return ( !empty( $c['undone'] ) ? '(undone) ' : '' ) . 'type=' . ( $c['type'] ?? '?' ) . ' ' . implode( ' ', array_map( 'strval', (array)( $c['args'] ?? array() ) ) ) . ' [' . ( $c['user'] ?? '?' ) . ']';
    }

    /** discard: stops the loaded configuration without saving */
    public function discard( array $user, $pid, $cid ): void
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        $c = $this->configGet( $p, $cid );
        $this->sessionStop( $p, (int)$c['id'] );
    }

    public static function rmTree( string $dir ): void
    {
        if( !is_dir( $dir ) || is_link( $dir ) )
            return;
        foreach( scandir( $dir ) as $e )
        {
            if( $e === '.' || $e === '..' )
                continue;
            $path = $dir . '/' . $e;
            if( is_dir( $path ) && !is_link( $path ) )
                self::rmTree( $path );
            else
                @unlink( $path );
        }
        @rmdir( $dir );
    }
}
