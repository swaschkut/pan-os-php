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
 * Plug-ins of the config viewer (interface version 1). A plug-in adds to the viewer without changing its code:
 *   - run types   POST …/configs/<cid>/<plugin>-<run>/runs: the plug-in builds the pan-os-php arguments of the run
 *   - file kinds  JSON files of a project that its runs use (…/files?kind=<plugin>-<kind>)
 *   - step types  pan-os-php types that a playbook may use in addition
 * The browser page shows the run types with the fields the plug-in declares - a plug-in brings no script for the page.
 *
 * A plug-in is a folder <name>/ with plugin.php, which returns the description as an array (see
 * examples/plugin-example/plugin.php). Folders: <config-viewer>/plugins/ and PANOSPHP_VIEWER_PLUGINS (one folder).
 * A plug-in is PHP code that runs in the web part and the job runner with all their rights: install only what you
 * would install as part of the viewer. What a plug-in may NOT do is decided here, at load time: a description that
 * does not fit is refused as a whole (ViewerPlugins::$errors, shown to admins).
 *
 * 'feature' names the licensed feature the plug-in belongs to (todo/config-viewer-license.md) - checked through
 * ViewerApp::featureOn(); a plug-in without it belongs to basic.
 */
class ViewerPlugins
{
    const API = 1;
    const FIELD_KINDS = '/^(text|location|file:[a-z][a-z0-9-]{0,40})$/';

    /** @var array name => description (checked) */
    public $plugins = array();
    /** @var string[] folder => why it was not loaded */
    public $errors = array();

    public static function load( string $viewerDir ): ViewerPlugins
    {
        $all = new ViewerPlugins();
        $dirs = array( $viewerDir . '/plugins' );
        $extra = (string)getenv( 'PANOSPHP_VIEWER_PLUGINS' );
        if( $extra !== '' )
            $dirs[] = rtrim( $extra, '/' );
        foreach( $dirs as $dir )
            foreach( glob( $dir . '/*/plugin.php' ) ?: array() as $file )
            {
                $folder = basename( dirname( $file ) );
                try
                {
                    $p = self::check( $folder, self::read( $file ) );
                    if( isset( $all->plugins[$p['name']] ) )
                        throw new Exception( 'a plug-in with this name is loaded already' );
                    foreach( array_keys( $p['runs'] ) as $run )
                        if( isset( $all->runs()[$run] ) )
                            throw new Exception( 'run type ' . $run . ' exists already' );
                    $all->plugins[$p['name']] = $p;
                }
                catch( Throwable $e )
                {
                    $all->errors[$folder] = $e->getMessage();
                }
            }
        return $all;
    }

    /** kept apart so that an encrypted plug-in (decrypted in memory) can come in here later */
    private static function read( string $file )
    {
        return ( static function() use ( $file ) { return require $file; } )();
    }

    private static function check( string $folder, $p ): array
    {
        if( !is_array( $p ) )
            throw new Exception( 'plugin.php must return an array' );
        if( ( $p['api'] ?? null ) !== self::API )
            throw new Exception( '"api" must be ' . self::API );
        $name = $p['name'] ?? null;
        if( !is_string( $name ) || !preg_match( '/^[a-z][a-z0-9]{1,30}$/', $name ) || $name !== $folder )
            throw new Exception( '"name": lower case letters and digits, the same as the folder name' );
        $out = array( 'name' => $name, 'api' => self::API, 'version' => self::text( $p['version'] ?? '0', 'version', 40 ), 'title' => self::text( $p['title'] ?? $name, 'title', 80 ),
            'feature' => null, 'runs' => array(), 'kinds' => array(), 'playbookTypes' => array() );
        if( isset( $p['feature'] ) )
        {
            if( !is_string( $p['feature'] ) || !preg_match( '/^[a-z][a-z0-9-]{1,40}$/', $p['feature'] ) )
                throw new Exception( '"feature": lower case letters, digits, -' );
            $out['feature'] = $p['feature'];
        }
        foreach( (array)( $p['kinds'] ?? array() ) as $kind => $k )
        {
            if( !is_string( $kind ) || !preg_match( '/^[a-z][a-z0-9-]{0,30}$/', $kind ) || !is_array( $k ) )
                throw new Exception( 'file kind: lower case name and a description' );
            if( isset( $k['check'] ) && !is_callable( $k['check'] ) )
                throw new Exception( 'file kind ' . $kind . ': "check" must be callable' );
            $out['kinds'][$name . '-' . $kind] = array( 'title' => self::text( $k['title'] ?? $kind, 'title', 80 ), 'check' => $k['check'] ?? null );
        }
        foreach( (array)( $p['runs'] ?? array() ) as $run => $r )
        {
            if( !is_string( $run ) || !preg_match( '/^[a-z][a-z0-9-]{0,30}$/', $run ) || !is_array( $r ) )
                throw new Exception( 'run type: lower case name and a description' );
            if( !isset( $r['tool'] ) || !is_string( $r['tool'] ) || !preg_match( '/^[a-z][a-z-]{0,40}$/', $r['tool'] ) )
                throw new Exception( 'run ' . $run . ': "tool" must be a pan-os-php type' );
            if( !isset( $r['args'] ) || !is_callable( $r['args'] ) )
                throw new Exception( 'run ' . $run . ': "args" must be callable' );
            $fields = array();
            foreach( (array)( $r['fields'] ?? array() ) as $f )
            {
                if( !is_array( $f ) || !isset( $f['name'], $f['kind'] ) || !is_string( $f['name'] ) || !preg_match( '/^[a-z][a-z0-9_]{0,30}$/', $f['name'] )
                    || !is_string( $f['kind'] ) || !preg_match( self::FIELD_KINDS, $f['kind'] ) || in_array( $f['name'], array( 'bp' ), TRUE ) )
                    throw new Exception( 'run ' . $run . ': a field needs "name" and "kind" (text, location, file:<kind>)' );
                $kind = $f['kind'];
                // file:<kind> of this plug-in, or the kinds of the viewer
                if( strpos( $kind, 'file:' ) === 0 && !in_array( substr( $kind, 5 ), array( 'playbook', 'bp' ), TRUE ) )
                {
                    if( !isset( $out['kinds'][$name . '-' . substr( $kind, 5 )] ) )
                        throw new Exception( 'run ' . $run . ': field ' . $f['name'] . ' uses an unknown file kind' );
                    $kind = 'file:' . $name . '-' . substr( $kind, 5 );
                }
                $fields[] = array( 'name' => $f['name'], 'kind' => $kind, 'label' => self::text( $f['label'] ?? $f['name'], 'label', 80 ),
                    'default' => self::text( $f['default'] ?? '', 'default', 200 ), 'required' => !empty( $f['required'] ) );
            }
            $result = $r['result'] ?? null;
            if( $result !== null && ( !is_string( $result ) || !preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]{0,60}\.xml$/', $result ) ) )
                throw new Exception( 'run ' . $run . ': "result" must be a plain .xml file name' );
            $out['runs'][$name . '-' . $run] = array( 'plugin' => $name, 'tool' => $r['tool'], 'title' => self::text( $r['title'] ?? $run, 'title', 80 ), 'fields' => $fields,
                'bp' => !empty( $r['bp'] ), 'result' => $result, 'args' => $r['args'] );
        }
        foreach( (array)( $p['playbookTypes'] ?? array() ) as $t )
        {
            if( !is_string( $t ) || !preg_match( '/^[a-z][a-z-]{0,40}$/', $t ) )
                throw new Exception( '"playbookTypes": pan-os-php type names' );
            $out['playbookTypes'][] = $t;
        }
        return $out;
    }

    private static function text( $v, string $what, int $max ): string
    {
        if( !is_string( $v ) || strlen( $v ) > $max || preg_match( '/[\x00-\x1f]/', $v ) )
            throw new Exception( '"' . $what . '": text of at most ' . $max . ' characters' );
        return $v;
    }

    /** run type => description, of the plug-ins that are switched on */
    public function runs( ?callable $on = null ): array
    {
        $runs = array();
        foreach( $this->plugins as $p )
            if( $on === null || $on( $p ) )
                $runs += $p['runs'];
        return $runs;
    }

    public function kinds( ?callable $on = null ): array
    {
        $kinds = array();
        foreach( $this->plugins as $p )
            if( $on === null || $on( $p ) )
                $kinds += $p['kinds'];
        return $kinds;
    }

    public function playbookTypes( ?callable $on = null ): array
    {
        $types = array();
        foreach( $this->plugins as $p )
            if( $on === null || $on( $p ) )
                $types = array_merge( $types, $p['playbookTypes'] );
        return array_values( array_unique( $types ) );
    }
}

/** what a plug-in gets to build the arguments of a run: checked values and file names, never a path of the server */
class ViewerPluginRun
{
    /** @var array body of the request (not checked) */
    public $in;
    private $file;

    public function __construct( array $in, callable $file )
    {
        $this->in = $in;
        $this->file = $file;
    }

    /** text field: letters, digits, space and . _ - , : / (no quotes, no control characters); '' when not given */
    public function text( string $field, int $max = 200 ): string
    {
        $v = $this->in[$field] ?? '';
        if( !is_string( $v ) || strlen( $v ) > $max || !preg_match( '#^[A-Za-z0-9 _.,:/\-]*$#', $v ) )
            throw new ViewerException( $field . ': letters, digits, space and . _ - , : / only', 400 );
        return $v;
    }

    /** a location name; 'any' when not given */
    public function location( string $field = 'location' ): string
    {
        $v = $this->in[$field] ?? 'any';
        if( !is_string( $v ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,63}$/', $v ) )
            throw new ViewerException( $field . ': letters, digits, space and . _ - only', 400 );
        return $v;
    }

    /** a project file of the given kind, as the run sees it; null when the field is not given */
    public function file( string $field, string $kind ): ?string
    {
        if( !isset( $this->in[$field] ) || $this->in[$field] === '' )
            return null;
        return '%FILES%/' . ( $this->file )( $this->in[$field], $kind )['file'];
    }

    /** the decoded content of a project file (JSON) of the given kind; null when the field is not given */
    public function json( string $field, string $kind )
    {
        if( !isset( $this->in[$field] ) || $this->in[$field] === '' )
            return null;
        return json_decode( (string)file_get_contents( ( $this->file )( $this->in[$field], $kind )['path'] ), TRUE );
    }

    /** a file in the folder of the run (result files) */
    public function out( string $name ): string
    {
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/', $name ) )
            throw new ViewerException( 'plug-in: not a plain file name', 500 );
        return '%JOB%/' . $name;
    }
}
