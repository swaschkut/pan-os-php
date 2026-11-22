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
 * The history of a project on object level (git step 2): one bare repository per project (<project>/history.git),
 * one entry per object (ConfigObjectSplit), written without files or a working tree by `git fast-import`.
 *
 *   refs/viewer/versions/<version>   the state of a saved version (its first commit: the split of the version)
 *   refs/viewer/work/<version>       the unsaved changes on a loaded version: one commit per change, its message
 *                                    carries the change as trailers (Type: Location: Filter: Action: User: …)
 *
 * <version> = the name of the version file without .xml. git is called with GIT_DIR only, no configuration of the
 * user is needed (author / committer are given).
 */
class ViewerGit
{
    const TRAILERS = array( 'type' => 'Type', 'location' => 'Location', 'template' => 'Template', 'ruletype' => 'Ruletype',
        'securityprofiletype' => 'Securityprofiletype', 'filter' => 'Filter', 'actions' => 'Action', 'field' => 'Field', 'user' => 'User',
        'reverts' => 'Reverts', 'run' => 'Run', 'settings' => 'Settings',
        // the first commit of a version (its state when it was first opened - no change)
        'version' => 'Version' );

    private $dir;
    private $git;

    public function __construct( string $dir, string $git = 'git' )
    {
        $this->dir = $dir;
        $this->git = $git;
    }

    public function dir(): string
    {
        return $this->dir;
    }

    /** git there, the repository created when missing; FALSE: no history (the viewer works without) */
    public function ready(): bool
    {
        if( $this->run( array( '--version' ), '', FALSE )[0] !== 0 )
            return FALSE;
        if( !is_file( $this->dir . '/HEAD' ) )
        {
            set_error_handler( function() { return TRUE; } );
            try
            {
                mkdir( $this->dir, 0700, TRUE );
            }
            finally
            {
                restore_error_handler();
            }
            if( $this->run( array( 'init', '-q', '--bare', $this->dir ), '', FALSE )[0] !== 0 )
                return FALSE;
            // no hooks, no background maintenance in the data volume
            foreach( glob( $this->dir . '/hooks/*' ) ?: array() as $h )
                if( is_file( $h ) )
                    unlink( $h );
            $this->run( array( 'config', 'gc.auto', '0' ) );
            $this->run( array( 'config', 'core.logAllRefUpdates', 'false' ) );
        }
        $this->mergeDriver();
        return TRUE;
    }

    /**
     * merge per field (git step 4): every entry (*.xml, _order) is merged by bin/git-merge-entry.php
     * (ConfigObjectMerge) - info/attributes is read by git also in a bare repository (merge-tree of the undo)
     */
    private function mergeDriver(): void
    {
        $attr = "*.xml merge=panos\n_order merge=panos\n";
        set_error_handler( function() { return TRUE; } );
        try
        {
            if( !is_dir( $this->dir . '/info' ) )
                mkdir( $this->dir . '/info', 0700 );
            if( @file_get_contents( $this->dir . '/info/attributes' ) !== $attr )
                file_put_contents( $this->dir . '/info/attributes', $attr );
        }
        finally
        {
            restore_error_handler();
        }
        $php = PHP_BINARY !== '' ? PHP_BINARY : 'php';
        $driver = escapeshellarg( $php ) . ' ' . escapeshellarg( realpath( dirname( __FILE__ ) . '/../bin/git-merge-entry.php' ) ) . ' %O %A %B %P';
        list( $rc, $cur ) = $this->run( array( 'config', '--get', 'merge.panos.driver' ), '', FALSE );
        if( trim( $cur ) !== $driver )
        {
            $this->run( array( 'config', 'merge.panos.name', 'pan-os-php entry per field' ) );
            $this->run( array( 'config', 'merge.panos.driver', $driver ) );
        }
    }

    /** the commit of a ref, null when there is none */
    public function ref( string $ref ): ?string
    {
        list( $rc, $out ) = $this->run( array( 'rev-parse', '-q', '--verify', $ref . '^{commit}' ), '', FALSE );
        $sha = trim( $out );
        return $rc === 0 && preg_match( '/^[0-9a-f]{40,64}$/', $sha ) ? $sha : null;
    }

    public function setRef( string $ref, string $sha ): void
    {
        $this->run( array( 'update-ref', $ref, $sha ) );
    }

    public function deleteRef( string $ref ): void
    {
        if( $this->ref( $ref ) !== null )
            $this->run( array( 'update-ref', '-d', $ref ) );
    }

    /**
     * one commit on $ref: the entries in $put (path => text) written, the paths in $delete removed; $all: the tree is
     * exactly $put (the first commit of a version). Returns the new commit.
     */
    public function commit( string $ref, ?string $parent, array $put, array $delete, string $message, string $user, int $time, bool $all = FALSE ): string
    {
        $name = trim( preg_replace( '/[<>\x00-\x1f]+/', ' ', $user ) );
        if( $name === '' )
            $name = 'config-viewer';
        $email = preg_replace( '/[^A-Za-z0-9._-]+/', '-', $name ) . '@config-viewer';
        $s = 'commit ' . $ref . "\n"
            . 'committer ' . $name . ' <' . $email . '> ' . $time . " +0000\n"
            . 'data ' . strlen( $message ) . "\n" . $message . "\n";
        if( $parent !== null )
            $s .= 'from ' . $parent . "\n";
        if( $all )
            $s .= "deleteall\n";
        foreach( $delete as $p )
            $s .= 'D ' . self::quote( $p ) . "\n";
        foreach( $put as $p => $text )
            $s .= 'M 100644 inline ' . self::quote( $p ) . "\n" . 'data ' . strlen( $text ) . "\n" . $text . "\n";
        $s .= "\ndone\n";
        list( $rc, $out ) = $this->run( array( 'fast-import', '--quiet', '--done', '--force' ), $s, FALSE );
        if( $rc !== 0 )
            throw new Exception( 'git fast-import: ' . substr( trim( $out ), 0, 300 ) );
        $sha = $this->ref( $ref );
        if( $sha === null )
            throw new Exception( 'git: no commit on ' . $ref );
        return $sha;
    }

    /** the message of a change: one line to read, the change as trailers (the playbook / undo read them) */
    public static function message( $note ): string
    {
        if( !is_array( $note ) )
            return self::oneLine( (string)$note ) . "\n";
        if( ( $note['type'] ?? '' ) === 'undo' )
            $head = 'undo: ' . (string)( $note['undoes'] ?? '' );
        else
            $head = trim( ( $note['type'] ?? '' ) . ( isset( $note['ruletype'] ) && $note['ruletype'] !== '' ? '/' . $note['ruletype'] : '' ) . ' '
                . ( $note['location'] ?? '' ) . ' ' . ( $note['filter'] ?? '' ) . ' -> ' . ( $note['actions'] ?? '' ) );
        $m = self::oneLine( substr( $head, 0, 200 ) ) . "\n\n";
        foreach( self::TRAILERS as $k => $t )
            if( isset( $note[$k] ) && is_scalar( $note[$k] ) && (string)$note[$k] !== '' )
                $m .= $t . ': ' . self::oneLine( (string)$note[$k] ) . "\n";
        return $m;
    }

    /** the commits of a ref (that changed $path), newest first: sha, time, user, subject, trailers */
    public function log( string $ref, int $max = 100, ?string $path = null ): array
    {
        if( $this->ref( $ref ) === null )
            return array();
        // with a path: only the commits that changed this entry (a rename: the old name is another entry)
        $args = array( 'log', '-z', '--max-count=' . max( 1, $max ), '--format=%H%x1f%ct%x1f%cn%x1f%B', $ref );
        if( $path !== null )
            $args = array_merge( $args, array( '--', $path ) );
        list( $rc, $out ) = $this->run( $args, '', FALSE );
        $list = array();
        foreach( explode( "\0", $out ) as $rec )
        {
            $f = explode( "\x1f", $rec, 4 );
            if( count( $f ) < 4 )
                continue;
            $lines = explode( "\n", trim( $f[3] ) );
            $tr = array();
            foreach( $lines as $l )
                if( preg_match( '/^([A-Z][a-z]+): (.*)$/', $l, $m ) && in_array( $m[1], self::TRAILERS, TRUE ) )
                    $tr[array_search( $m[1], self::TRAILERS, TRUE )] = $m[2];
            // the lines of a run result (Merged: / Not-merged:) - what the run did per object
            $notes = array_values( array_filter( $lines, function( $l ) { return preg_match( '/^(Merged|Not-merged): /', $l ) === 1; } ) );
            $list[] = array( 'commit' => $f[0], 'time' => (int)$f[1], 'user' => $f[2], 'subject' => $lines[0], 'change' => $tr, 'notes' => $notes );
        }
        return $list;
    }

    /** the paths a commit changed (against its parent): path => A / M / D */
    public function changed( string $sha ): array
    {
        list( $rc, $out ) = $this->run( array( 'diff-tree', '-r', '-z', '--no-commit-id', '--name-status', '--root', $sha ), '', FALSE );
        $f = explode( "\0", rtrim( $out, "\0" ) );
        $list = array();
        for( $i = 0; $i + 1 < count( $f ); $i += 2 )
            $list[$f[$i + 1]] = $f[$i];
        return $list;
    }

    /**
     * the tree of $head with the change of $commit taken back (git revert, in memory: merge-tree with the commit as
     * base and its parent as the other side): array( 'tree' => id or null, 'conflicts' => paths )
     */
    public function revertTree( string $commit, string $head ): array
    {
        $parent = $this->ref( $commit . '^' );
        if( $parent === null )
            throw new Exception( 'the first commit of a version can not be taken back' );
        list( $rc, $out ) = $this->run( array( 'merge-tree', '--write-tree', '--name-only', '--no-messages', '--merge-base=' . $commit, $head, $parent ), '', FALSE );
        $lines = explode( "\n", rtrim( $out, "\n" ) );
        $tree = trim( $lines[0] ?? '' );
        if( !preg_match( '/^[0-9a-f]{40,64}$/', $tree ) || ( $rc !== 0 && $rc !== 1 ) )
            throw new Exception( 'git merge-tree: ' . substr( trim( $out ), 0, 300 ) );
        if( $rc === 0 )
            return array( 'tree' => $tree, 'conflicts' => array() );
        $conflicts = array();
        foreach( array_slice( $lines, 1 ) as $l )
            if( $l !== '' )
                $conflicts[$l] = TRUE;
        return array( 'tree' => null, 'conflicts' => array_keys( $conflicts ) );
    }

    /** the tree of a commit */
    public function tree( string $commitOrTree ): string
    {
        return trim( $this->run( array( 'rev-parse', $commitOrTree . '^{tree}' ) )[1] );
    }

    /** the paths that differ between two trees / commits: path => A / M / D (seen from $a to $b) */
    public function diff( string $a, string $b ): array
    {
        list( $rc, $out ) = $this->run( array( 'diff-tree', '-r', '-z', '--name-status', $a, $b ) );
        $f = explode( "\0", rtrim( $out, "\0" ) );
        $list = array();
        for( $i = 0; $i + 1 < count( $f ); $i += 2 )
            $list[$f[$i + 1]] = $f[$i];
        return $list;
    }

    /** the text of an entry in a commit (null: not there) */
    public function show( string $sha, string $path ): ?string
    {
        list( $rc, $out ) = $this->run( array( 'cat-file', 'blob', $sha . ':' . $path ), '', FALSE );
        return $rc === 0 ? $out : null;
    }

    // ------------------------------------------------------------------------------------------------------------

    public static function oneLine( string $s ): string
    {
        return trim( preg_replace( '/[\x00-\x1f]+/', ' ', $s ) );
    }

    /** a path of fast-import: C style quoted when it starts with a quote (LF can not occur: ConfigObjectSplit::enc) */
    private static function quote( string $p ): string
    {
        return $p !== '' && $p[0] === '"' ? '"' . addcslashes( $p, "\"\\" ) . '"' : $p;
    }

    /**
     * @return array( exit code, stdout (+ stderr when it failed) )
     * PHP warnings of the pipes are answers here (pan-os-php turns every warning into the end of the script, also with @)
     */
    private function run( array $args, string $stdin = '', bool $must = TRUE ): array
    {
        set_error_handler( function() { return TRUE; } );
        try
        {
            return $this->runQuiet( $args, $stdin, $must );
        }
        finally
        {
            restore_error_handler();
        }
    }

    private function runQuiet( array $args, string $stdin, bool $must ): array
    {
        $env = array( 'GIT_DIR' => $this->dir, 'PATH' => getenv( 'PATH' ) ?: '/usr/local/bin:/usr/bin:/bin', 'HOME' => $this->dir,
            'GIT_CONFIG_NOSYSTEM' => '1', 'GIT_TERMINAL_PROMPT' => '0', 'LC_ALL' => 'C' );
        $cmd = array_merge( array( $this->git ), $args );
        $p = proc_open( $cmd, array( 0 => array( 'pipe', 'r' ), 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null, $env );
        if( !is_resource( $p ) )
        {
            if( $must )
                throw new Exception( 'git could not be started' );
            return array( 127, '' );
        }
        // stdin written while stdout is read: a large first commit must not block on a full pipe
        stream_set_blocking( $pipes[0], FALSE );
        stream_set_blocking( $pipes[1], FALSE );
        stream_set_blocking( $pipes[2], FALSE );
        $out = $err = '';
        $pos = 0;
        $len = strlen( $stdin );
        if( $len === 0 )
            fclose( $pipes[0] );
        while( TRUE )
        {
            $r = array( $pipes[1], $pipes[2] );
            $w = $pos < $len ? array( $pipes[0] ) : null;
            $e = null;
            if( @stream_select( $r, $w, $e, 30 ) === FALSE )
                break;
            if( $w )
            {
                $n = @fwrite( $pipes[0], substr( $stdin, $pos, 65536 ) );
                if( $n === FALSE )
                    $pos = $len;
                else
                    $pos += $n;
                if( $pos >= $len )
                    fclose( $pipes[0] );
            }
            foreach( $r as $pipe )
            {
                $chunk = fread( $pipe, 65536 );
                if( $pipe === $pipes[1] )
                    $out .= (string)$chunk;
                else
                    $err .= (string)$chunk;
            }
            if( feof( $pipes[1] ) && feof( $pipes[2] ) )
                break;
        }
        fclose( $pipes[1] );
        fclose( $pipes[2] );
        $rc = proc_close( $p );
        if( $rc !== 0 && $must )
            throw new Exception( 'git ' . $args[0] . ': ' . substr( trim( $err ), 0, 300 ) );
        return array( $rc, $rc === 0 ? $out : $out . $err );
    }
}
