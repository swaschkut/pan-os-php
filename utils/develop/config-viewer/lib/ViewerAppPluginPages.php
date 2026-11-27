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
 * the pages of plug-ins (viewer plug-in interface 2): forms, tables and approval steps described as data.
 */
trait ViewerAppPluginPages
{
    // ------------------------------------------------------------------ pages of plug-ins (interface 2)

    /** a page of a plug-in that is switched on (an encrypted package only while licensed) */
    private function pluginPage( $key ): array
    {
        $pg = is_string( $key ) ? ( $this->plugins->pages()[$key] ?? null ) : null;
        if( $pg === null )
            throw new ViewerException( 'not found', 404 );
        $plugin = $this->plugins->plugins[$pg['plugin']] ?? array();
        if( isset( $plugin['package'] ) && !$this->featureOn( $pg['feature'] ) )
            throw new ViewerException( 'not licensed (any more): ' . $pg['feature'], 403 );
        return $pg;
    }

    /** a page of project types: only in a project of one of them */
    private static function pageForProject( array $p, array $pg ): void
    {
        if( count( $pg['types'] ?? array() ) > 0 && !in_array( $p['ptype'] ?? null, $pg['types'], TRUE ) )
            throw new ViewerException( 'not found', 404 );
    }

    private function pluginPageDir( array $p, string $key ): string
    {
        return $this->projectDir( $p['pid'] ) . '/plugin-pages/' . $key;
    }

    /** stored values of every block of a page: block => ['values', 'saved_by', 'saved_at'] */
    private function pluginPageStored( array $p, string $key, array $pg ): array
    {
        $out = array();
        foreach( array_keys( $pg['blocks'] ) as $b )
        {
            $j = json_decode( (string)@file_get_contents( $this->pluginPageDir( $p, $key ) . '/' . $b . '.json' ), TRUE );
            $out[$b] = is_array( $j ) ? $j : array( 'values' => array(), 'saved_by' => null, 'saved_at' => null );
        }
        return $out;
    }

    /** depth of rows() of the plug-in calling rows() of a table (a table can build on another one, not on itself) */
    private $pluginRowsDepth = 0;

    /**
     * what a plug-in may read of a project: the data of one endpoint of the newest state of an SCM tab page; the rows of
     * a table block of the page (with the stored changes)
     */
    private function pluginReader( array $p, ?array $pg = null, array $saved = array() ): callable
    {
        $reader = null;
        $reader = function( string $what, ...$args ) use ( $p, $pg, $saved, &$reader ) {
            if( $what === 'rows' && $pg !== null && count( $args ) === 1 && ( $pg['blocks'][$args[0]]['kind'] ?? null ) === 'table' )
            {
                if( $this->pluginRowsDepth > 3 )
                    throw new ViewerException( 'plug-in: tables build on each other too deep', 500 );
                $this->pluginRowsDepth++;
                try
                {
                    $b = $pg['blocks'][$args[0]];
                    return self::tableMerge( $b, $this->tableSource( $b, new ViewerPluginPage( $saved, $reader ) ), $saved[$args[0]] ?? array() );
                }
                finally
                {
                    $this->pluginRowsDepth--;
                }
            }
            $roles = self::rolesOf( $p );
            if( $what === 'role' && count( $args ) === 1 )
                return $roles[$args[0]] ?? null;
            if( $what !== 'scm-pa' || count( $args ) < 2 || !isset( self::SCM_PA_PAGES[$args[0]] ) )
                return null;
            // a role: only the states of its tenant (not bound yet: none)
            $tsg = null;
            if( ( $args[2] ?? null ) !== null )
            {
                $tsg = $roles[$args[2]]['target'] ?? null;
                if( $tsg === null )
                    return null;
            }
            $newest = null;
            foreach( glob( $this->paDir( $p, $args[0] ) . '/*/state.json' ) ?: array() as $f )
            {
                $s = $this->paState( $p, $args[0], basename( dirname( $f ) ) );
                if( $tsg !== null && (string)$s['tsg'] !== (string)$tsg )
                    continue;
                if( $newest === null || $s['time'] > $newest['time'] )
                    $newest = $s;
            }
            if( $newest === null )
                return null;
            $file = $newest['endpoints'][$args[1]]['file'] ?? null;
            if( $file === null || !is_file( $newest['dir'] . '/' . $file ) )
                return null;
            $j = json_decode( (string)file_get_contents( $newest['dir'] . '/' . $file ), TRUE );
            return is_array( $j ) ? ( $j['data'] ?? null ) : null;
        };
        return $reader;
    }

    /** the rows of a table block from the plug-in: key => row (known columns, scalar values / lists of them) */
    private function tableSource( array $b, ViewerPluginPage $view ): array
    {
        $out = array();
        foreach( (array)( $b['rows'] )( $view ) as $r )
        {
            if( !is_array( $r ) || !isset( $r[$b['key']] ) || !is_scalar( $r[$b['key']] ) || (string)$r[$b['key']] === '' )
                throw new ViewerException( 'plug-in: table ' . $b['name'] . ': every row needs a value in ' . $b['key'], 500 );
            $k = (string)$r[$b['key']];
            if( isset( $out[$k] ) )
                throw new ViewerException( 'plug-in: table ' . $b['name'] . ': ' . $b['key'] . ' ' . $k . ' twice', 500 );
            $row = array();
            foreach( $b['fields'] as $name => $f )
            {
                $v = $r[$name] ?? null;
                $row[$name] = is_scalar( $v ) || $v === null || ( is_array( $v ) && count( array_filter( $v, 'is_scalar' ) ) === count( $v ) ) ? $v : null;
            }
            $out[$k] = $row;
            if( count( $out ) > 5000 )
                throw new ViewerException( 'plug-in: table ' . $b['name'] . ': more than 5000 rows', 500 );
        }
        return $out;
    }

    /** the rows with the stored changes (key => column => value) */
    private static function tableMerge( array $b, array $source, array $changes ): array
    {
        foreach( $source as $k => $row )
            foreach( (array)( $changes[$k] ?? array() ) as $col => $v )
                if( isset( $b['fields'][$col] ) && $b['fields'][$col]['edit'] )
                    $source[$k][$col] = $v;
        return $source;
    }

    /** a table block for the page: columns, rows (key, value as it is now, source of the plug-in), stored changes */
    private function tableBlockPublic( array $b, array $stored, ViewerPluginPage $view ): array
    {
        $rows = array();
        $error = null;
        try
        {
            $source = $this->tableSource( $b, $view );
            foreach( self::tableMerge( $b, $source, $stored['values'] ) as $k => $row )
                $rows[] = array( 'key' => (string)$k, 'value' => $row, 'source' => $source[$k], 'changed' => array_keys( (array)( $stored['values'][$k] ?? array() ) ) );
        }
        catch( Throwable $e )
        {
            $error = 'rows of the plug-in: ' . substr( $e->getMessage(), 0, 300 );
        }
        return array( 'name' => $b['name'], 'kind' => 'table', 'title' => $b['title'], 'text' => $b['text'], 'fields' => array_values( $b['fields'] ), 'key' => $b['key'],
            'rows' => $rows, 'saved_by' => $stored['saved_by'], 'saved_at' => $stored['saved_at'], 'error' => $error );
    }

    /**
     * the state of an approval block: the newest plan (the result file of the newest finished run of its run type), its
     * areas (from the plug-in), the decisions - only those for this run and this content (sha256) of the plan
     */
    private function approvalState( array $p, array $b, array $stored, ViewerPluginPage $view ): array
    {
        $out = array( 'plan' => null, 'areas' => array(), 'complete' => FALSE, 'planner_id' => null, 'file' => null, 'error' => null );
        $j = $this->q( "SELECT j.jid, j.user_id, j.finished, u.name AS by_name FROM jobs j LEFT JOIN users u ON u.id = j.user_id
            WHERE j.project_id = ? AND j.type = ? AND j.state = 'done' ORDER BY j.finished DESC, j.id DESC LIMIT 1", array( $p['id'], $b['run'] ) )->fetch();
        if( $j === FALSE )
            return $out;
        $file = $this->jobDir( $p, $j['jid'] ) . '/' . $b['file'];
        if( !is_file( $file ) )
        {
            $out['error'] = 'the newest run ' . $b['run'] . ' has no ' . $b['file'];
            return $out;
        }
        $content = (string)file_get_contents( $file );
        $hash = hash( 'sha256', $content );
        $out['plan'] = array( 'jid' => $j['jid'], 'by' => $j['by_name'], 'finished' => (int)$j['finished'], 'hash' => substr( $hash, 0, 12 ) );
        $out['planner_id'] = $j['user_id'] !== null ? (int)$j['user_id'] : null;
        $out['file'] = $file;
        $out['hash'] = $hash;
        $valid = ( $stored['values']['jid'] ?? null ) === $j['jid'] && ( $stored['values']['hash'] ?? null ) === $hash;
        $decisions = $valid ? (array)( $stored['values']['decisions'] ?? array() ) : array();
        try
        {
            $seen = array();
            foreach( (array)( $b['areas'] )( json_decode( $content, TRUE ), $view ) as $a )
            {
                if( !is_array( $a ) || !is_string( $a['id'] ?? null ) || !preg_match( '/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,80}$/', $a['id'] ) || isset( $seen[$a['id']] ) )
                    throw new ViewerException( 'every area needs a unique "id"', 500 );
                $seen[$a['id']] = TRUE;
                $d = $decisions[$a['id']] ?? null;
                $out['areas'][] = array( 'id' => $a['id'], 'title' => substr( (string)( $a['title'] ?? $a['id'] ), 0, 120 ), 'summary' => substr( (string)( $a['summary'] ?? '' ), 0, 1000 ),
                    'count' => isset( $a['count'] ) ? (int)$a['count'] : null, 'decision' => $d['decision'] ?? null, 'by' => $d['by'] ?? null, 'at' => $d['at'] ?? null, 'note' => $d['note'] ?? '' );
                if( count( $out['areas'] ) > 500 )
                    throw new ViewerException( 'more than 500 areas', 500 );
            }
        }
        catch( Throwable $e )
        {
            $out['areas'] = array();
            $out['error'] = 'areas of the plug-in: ' . substr( $e->getMessage(), 0, 300 );
            return $out;
        }
        $out['complete'] = count( $out['areas'] ) > 0 && count( array_filter( $out['areas'], function( $a ) { return $a['decision'] !== 'approve'; } ) ) === 0;
        return $out;
    }

    /** an approval block for the page */
    private function approvalBlockPublic( array $p, array $b, array $stored, ViewerPluginPage $view ): array
    {
        $s = $this->approvalState( $p, $b, $stored, $view );
        $runTitle = $this->pluginRuns()[$b['run']]['title'] ?? $b['run'];
        return array( 'name' => $b['name'], 'kind' => 'approval', 'title' => $b['title'], 'text' => $b['text'], 'run' => $b['run'], 'run_title' => $runTitle,
            'plan' => $s['plan'], 'areas' => $s['areas'], 'complete' => $s['complete'], 'four_eyes' => !empty( $p['approval_four_eyes'] ),
            'saved_by' => $stored['saved_by'], 'saved_at' => $stored['saved_at'], 'error' => $s['error'] );
    }

    /**
     * PUT an approval block {decisions: {<area>: {decision: approve|reject|clear, note}}} - write; with four eyes the
     * person who made the plan can not approve. Bound to the plan (run and content): a new plan starts without decisions.
     */
    private function approvalSave( array $user, array $p, string $key, array $pg, array $b, array $in ): array
    {
        $raw = $in['decisions'] ?? null;
        if( !is_array( $raw ) )
            throw new ViewerException( 'decisions: an object area => {decision, note} expected', 400 );
        $stored = $this->pluginPageStored( $p, $key, $pg );
        $saved = array_map( function( $s ) { return $s['values']; }, $stored );
        $s = $this->approvalState( $p, $b, $stored[$b['name']], new ViewerPluginPage( $saved, $this->pluginReader( $p, $pg, $saved ) ) );
        if( $s['plan'] === null || $s['error'] !== null )
            throw new ViewerException( $s['error'] ?? 'there is no plan yet (run ' . $b['run'] . ')', 409 );
        $valid = ( $stored[$b['name']]['values']['jid'] ?? null ) === $s['plan']['jid'] && ( $stored[$b['name']]['values']['hash'] ?? null ) === $s['hash'];
        $decisions = $valid ? (array)( $stored[$b['name']]['values']['decisions'] ?? array() ) : array();
        $ids = array_column( $s['areas'], 'id' );
        $errors = array();
        foreach( $raw as $id => $d )
        {
            $id = (string)$id;
            $decision = is_array( $d ) ? ( $d['decision'] ?? null ) : null;
            $note = is_array( $d ) ? ( $d['note'] ?? '' ) : '';
            if( !in_array( $id, $ids, TRUE ) )
                $errors[$id] = 'not an area of this plan';
            elseif( !in_array( $decision, array( 'approve', 'reject', 'clear' ), TRUE ) )
                $errors[$id] = 'decision: approve, reject or clear';
            elseif( !is_string( $note ) || strlen( $note ) > 300 || preg_match( '/[\x00-\x1f]/', $note ) )
                $errors[$id] = 'note: text of at most 300 characters';
            elseif( $decision === 'approve' && !empty( $p['approval_four_eyes'] ) && $s['planner_id'] === (int)$user['id'] )
                $errors[$id] = 'four eyes: approved by another person than the one who made the plan';
            elseif( $decision === 'clear' )
                unset( $decisions[$id] );
            else
                $decisions[$id] = array( 'decision' => $decision, 'by' => $user['name'], 'at' => time(), 'note' => $note );
        }
        if( count( $errors ) > 0 )
            throw new ViewerFieldException( 'the decisions have errors', $errors );
        $this->pluginBlockStore( $user, $p, $key, $pg, $b, $stored, array( 'jid' => $s['plan']['jid'], 'hash' => $s['hash'], 'decisions' => $decisions ) );
        $stored = $this->pluginPageStored( $p, $key, $pg );
        $saved = array_map( function( $x ) { return $x['values']; }, $stored );
        return $this->approvalBlockPublic( $p, $b, $stored[$b['name']], new ViewerPluginPage( $saved, $this->pluginReader( $p, $pg, $saved ) ) );
    }

    /**
     * a run type with 'approval': refused unless every area of the newest plan is approved; then a copy of exactly that
     * plan (plugin-pages/<page>/approved/<sha256>.json) for the run - %PROJECT%/… of ViewerPluginRun::approved()
     */
    private function approvalGate( array $p, array $plugin ): string
    {
        $key = $plugin['approval']['page'];
        $pg = $this->pluginPage( $key );
        $b = $pg['blocks'][$plugin['approval']['block']];
        $stored = $this->pluginPageStored( $p, $key, $pg );
        $saved = array_map( function( $x ) { return $x['values']; }, $stored );
        $s = $this->approvalState( $p, $b, $stored[$b['name']], new ViewerPluginPage( $saved, $this->pluginReader( $p, $pg, $saved ) ) );
        if( !$s['complete'] )
            throw new ViewerException( 'not approved: every area of the newest plan (' . $b['title'] . ') must be approved first', 409 );
        $dir = $this->pluginPageDir( $p, $key ) . '/approved';
        if( !is_dir( $dir ) )
            mkdir( $dir, 0700, TRUE );
        $name = substr( $s['hash'], 0, 32 ) . '.json';
        if( !is_file( $dir . '/' . $name ) )
        {
            copy( $s['file'], $dir . '/' . $name . '.tmp' );
            @chmod( $dir . '/' . $name . '.tmp', 0600 );
            rename( $dir . '/' . $name . '.tmp', $dir . '/' . $name );
        }
        return '%PROJECT%/plugin-pages/' . $key . '/approved/' . $name;
    }

    /** a block for the page: description (without the callables), stored values, defaults of the plug-in */
    private function pluginBlockPublic( array $b, array $stored, ViewerPluginPage $view, ?array $p = null ): array
    {
        if( $b['kind'] === 'approval' )
            return $this->approvalBlockPublic( $p, $b, $stored, $view );
        if( $b['kind'] === 'table' )
            return $this->tableBlockPublic( $b, $stored, $view );
        $defaults = array();
        $error = null;
        if( $b['defaults'] !== null )
        {
            try
            {
                foreach( (array)( $b['defaults'] )( $view ) as $name => $d )
                {
                    if( !isset( $b['fields'][$name] ) )
                        continue;
                    $d = is_array( $d ) && ( array_key_exists( 'value', $d ) || array_key_exists( 'hint', $d ) ) ? $d : array( 'value' => $d );
                    $value = $d['value'] ?? null;
                    $hint = isset( $d['hint'] ) && is_scalar( $d['hint'] ) ? substr( (string)$d['hint'], 0, 300 ) : null;
                    $defaults[$name] = array( 'value' => is_scalar( $value ) || ( is_array( $value ) && count( array_filter( $value, 'is_scalar' ) ) === count( $value ) ) ? $value : null,
                        'hint' => $hint );
                }
            }
            catch( Throwable $e )
            {
                $error = 'defaults of the plug-in: ' . substr( $e->getMessage(), 0, 300 );
            }
        }
        $fields = array_values( $b['fields'] );
        return array( 'name' => $b['name'], 'kind' => $b['kind'], 'title' => $b['title'], 'text' => $b['text'], 'fields' => $fields,
            'values' => (object)$stored['values'], 'saved_by' => $stored['saved_by'], 'saved_at' => $stored['saved_at'], 'defaults' => (object)$defaults,
            'error' => $error );
    }

    /** GET …/projects/<pid>/pages/<plugin>-<page>: the blocks with their stored values and the defaults of the plug-in */
    public function pluginPageGet( array $user, $pid, $key ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'pages of plug-ins' );
        $pg = $this->pluginPage( $key );
        self::pageForProject( $p, $pg );
        $stored = $this->pluginPageStored( $p, $key, $pg );
        $saved = array_map( function( $s ) { return $s['values']; }, $stored );
        $view = new ViewerPluginPage( $saved, $this->pluginReader( $p, $pg, $saved ) );
        $blocks = array();
        foreach( $pg['blocks'] as $name => $b )
            $blocks[] = $this->pluginBlockPublic( $b, $stored[$name], $view, $p );
        return array( 'key' => $key, 'plugin' => $pg['plugin'], 'title' => $pg['title'], 'text' => $pg['text'], 'blocks' => $blocks,
            'write' => in_array( $p['role'], array( 'owner', 'write' ), TRUE ) );
    }

    /**
     * PUT …/projects/<pid>/pages/<plugin>-<page>/blocks/<block> {values}: every field checked by its type, then by the
     * check of the plug-in; stored with the project (the audit log gets the route, not the values)
     */
    public function pluginPageSave( array $user, $pid, $key, $block, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        self::needUnlimited( $p, 'pages of plug-ins' );
        $pg = $this->pluginPage( $key );
        self::pageForProject( $p, $pg );
        $b = is_string( $block ) ? ( $pg['blocks'][$block] ?? null ) : null;
        if( $b === null )
            throw new ViewerException( 'not found', 404 );
        if( $b['kind'] === 'table' )
            return $this->tableSave( $user, $p, $key, $pg, $b, $in );
        if( $b['kind'] === 'approval' )
            return $this->approvalSave( $user, $p, $key, $pg, $b, $in );
        $raw = $in['values'] ?? null;
        if( !is_array( $raw ) )
            throw new ViewerException( 'values: an object field => value expected', 400 );
        $errors = array();
        foreach( array_keys( $raw ) as $k )
            if( !isset( $b['fields'][$k] ) )
                $errors[(string)$k] = 'not a field of this form';
        $values = array();
        foreach( $b['fields'] as $name => $f )
            try
            {
                $values[$name] = ViewerPlugins::fieldValue( $f, $raw[$name] ?? null );
            }
            catch( Exception $e )
            {
                $errors[$name] = $e->getMessage();
            }
        $stored = $this->pluginPageStored( $p, $key, $pg );
        if( count( $errors ) === 0 && $b['check'] !== null )
        {
            $saved = array_map( function( $s ) { return $s['values']; }, $stored );
            $saved[$block] = $values;
            try
            {
                foreach( (array)( $b['check'] )( $values, new ViewerPluginPage( $saved, $this->pluginReader( $p, $pg, $saved ) ) ) as $k => $msg )
                    if( is_string( $msg ) && $msg !== '' )
                        $errors[isset( $b['fields'][$k] ) ? $k : ''] = substr( $msg, 0, 300 );
            }
            catch( Throwable $e )
            {
                $errors[''] = 'check of the plug-in: ' . substr( $e->getMessage(), 0, 300 );
            }
        }
        if( count( $errors ) > 0 )
            throw new ViewerFieldException( 'the form has errors', $errors );
        return $this->pluginBlockStore( $user, $p, $key, $pg, $b, $stored, $values );
    }

    /** writes the values of a block and returns it as the page shows it */
    private function pluginBlockStore( array $user, array $p, string $key, array $pg, array $b, array $stored, array $values ): array
    {
        $dir = $this->pluginPageDir( $p, $key );
        if( !is_dir( $dir ) )
            mkdir( $dir, 0700, TRUE );
        $doc = array( 'values' => $values, 'saved_by' => $user['name'], 'saved_at' => time() );
        $tmp = $dir . '/' . $b['name'] . '.json.tmp';
        file_put_contents( $tmp, json_encode( $doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
        @chmod( $tmp, 0600 );
        rename( $tmp, $dir . '/' . $b['name'] . '.json' );
        $stored[$b['name']] = $doc;
        $saved = array_map( function( $s ) { return $s['values']; }, $stored );
        return $this->pluginBlockPublic( $b, $doc, new ViewerPluginPage( $saved, $this->pluginReader( $p, $pg, $saved ) ), $p );
    }

    /**
     * a table: {rows: {<key>: {<column>: value}}} - only editable columns of rows the plug-in gives; a value equal to
     * the one of the plug-in removes the change; rows not sent keep their changes. Errors: '<key>/<column>' => message.
     */
    private function tableSave( array $user, array $p, string $key, array $pg, array $b, array $in ): array
    {
        $raw = $in['rows'] ?? null;
        if( !is_array( $raw ) )
            throw new ViewerException( 'rows: an object key => {column: value} expected', 400 );
        $stored = $this->pluginPageStored( $p, $key, $pg );
        $saved = array_map( function( $s ) { return $s['values']; }, $stored );
        $view = new ViewerPluginPage( $saved, $this->pluginReader( $p, $pg, $saved ) );
        try
        {
            $source = $this->tableSource( $b, $view );
        }
        catch( Throwable $e )
        {
            throw new ViewerException( 'rows of the plug-in: ' . $e->getMessage(), 500 );
        }
        $changes = (array)$stored[$b['name']]['values'];
        foreach( array_keys( $changes ) as $k )
            if( !isset( $source[(string)$k] ) )
                unset( $changes[$k] );      // a row the plug-in does not give any more
        $errors = array();
        foreach( $raw as $k => $cols )
        {
            $k = (string)$k;
            if( !isset( $source[$k] ) )
            {
                $errors[$k] = 'not a row of this table';
                continue;
            }
            if( !is_array( $cols ) )
            {
                $errors[$k] = 'an object column => value expected';
                continue;
            }
            foreach( $cols as $col => $v )
            {
                $f = $b['fields'][$col] ?? null;
                if( $f === null || !$f['edit'] )
                {
                    $errors[$k . '/' . $col] = 'not an editable column';
                    continue;
                }
                try
                {
                    $v = ViewerPlugins::fieldValue( $f, $v );
                }
                catch( Exception $e )
                {
                    $errors[$k . '/' . $col] = $e->getMessage();
                    continue;
                }
                try
                {
                    $orig = ViewerPlugins::fieldValue( array( 'required' => FALSE ) + $f, $source[$k][$col] );
                }
                catch( Exception $e )
                {
                    $orig = $source[$k][$col];
                }
                if( $v === $orig )
                    unset( $changes[$k][$col] );
                else
                    $changes[$k][$col] = $v;
                if( isset( $changes[$k] ) && $changes[$k] === array() )
                    unset( $changes[$k] );
            }
        }
        if( count( $errors ) === 0 && $b['check'] !== null )
        {
            $saved[$b['name']] = $changes;
            try
            {
                foreach( (array)( $b['check'] )( self::tableMerge( $b, $source, $changes ), new ViewerPluginPage( $saved, $this->pluginReader( $p, $pg, $saved ) ) ) as $k => $msg )
                {
                    if( is_array( $msg ) )
                    {
                        foreach( $msg as $col => $m )
                            if( is_string( $m ) && $m !== '' )
                                $errors[$k . ( isset( $b['fields'][$col] ) ? '/' . $col : '' )] = substr( $m, 0, 300 );
                    }
                    elseif( is_string( $msg ) && $msg !== '' )
                        $errors[isset( $source[(string)$k] ) ? (string)$k : ''] = substr( $msg, 0, 300 );
                }
            }
            catch( Throwable $e )
            {
                $errors[''] = 'check of the plug-in: ' . substr( $e->getMessage(), 0, 300 );
            }
        }
        if( count( $errors ) > 0 )
            throw new ViewerFieldException( 'the table has errors', $errors );
        return $this->pluginBlockStore( $user, $p, $key, $pg, $b, $stored, $changes );
    }
}
