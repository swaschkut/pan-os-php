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
 * Plug-ins of the config viewer (interface version 1 and 2). A plug-in adds to the viewer without changing its code:
 *   - run types   POST …/configs/<cid>/<plugin>-<run>/runs: the plug-in builds the pan-os-php arguments of the run;
 *                 with 'input' => 'none' the run needs no version (POST …/projects/<pid>/<plugin>-<run>/runs) - e.g.
 *                 a migration, whose input is a project file and whose result becomes the first version
 *   - file kinds  files of a project that its runs use (…/files?kind=<plugin>-<kind>): JSON, or 'format' => 'raw'
 *                 for any other file (a 3rd party configuration), with its own size limit
 *   - step types  pan-os-php types that a playbook may use in addition
 *   - pages       (interface 2) a card of the project with blocks the viewer draws from their description - the
 *                 plug-in brings no script for the page: 'form' (typed fields, values stored with the project,
 *                 defaults / check of the plug-in), 'table' (rows of the plug-in, editable columns - stored are the
 *                 changes per row), 'approval' (the areas of the result of a run - a plan - approved / rejected one by
 *                 one; a run type with 'approval' => '<page>/<block>' starts only when all are approved)
 *   - sensitive   (interface 2) a run field 'secret': a file (e.g. a PSK list of the customer) uploaded only for this
 *                 run - never a project file, never downloadable, removed when the run ends; results the run writes
 *                 into %JOB%/.sensitive/ are downloadable once (then removed), by write members
 *   - project types (interface 2) roles of a project, each bound to its own system (e.g. tenant migration: source
 *                 and target SCM tenant), writing only into the roles marked 'write'; pages can belong to project types
 * A run type can set environment variables for its run ('env', %PLUGIN% = the folder of the plug-in) - so pan-os-php can
 * load files that the plug-in brings (e.g. PANOSPHP_MIGRATION_PARSERS => '%PLUGIN%/parser').
 * The browser page shows the run types with the fields the plug-in declares - a plug-in brings no script for the page.
 *
 * A plug-in is a folder <name>/ with plugin.php, which returns the description as an array (see
 * examples/plugin-example/plugin.php). Folders: <config-viewer>/plugins/ and PANOSPHP_VIEWER_PLUGINS (one folder).
 * A plug-in is PHP code that runs in the web part and the job runner with all their rights: install only what you
 * would install as part of the viewer. What a plug-in may NOT do is decided here, at load time: a description that
 * does not fit is refused as a whole (ViewerPlugins::$errors, shown to admins).
 *
 * 'feature' names the licensed feature the plug-in belongs to (todo/config-viewer-license.md); a plug-in without it
 * belongs to basic.
 *
 * Two forms: a folder <name>/ with plugin.php (the source - development, or a basic plug-in), or an encrypted
 * package <name>.ppp (licensed plug-ins as delivered): loaded only with a licence that holds its feature and the key
 * of its release (lib/misc-classes/PluginPackage.php); its files are read from memory as ppp://<name>/….
 */
class ViewerPlugins
{
    /** the newest interface; plug-ins of interface 1 keep working */
    const API = 2;
    const APIS = array( 1, 2 );
    /** types of the fields of a form block (interface 2) - ViewerPlugins::fieldValue() checks them */
    const FIELD_TYPES = array( 'text', 'int', 'ipv4', 'ipv4-cidr', 'ipv6-cidr', 'asn', 'hostname', 'select', 'bool', 'list' );
    /** types a list may hold */
    const LIST_ITEMS = array( 'text', 'ipv4', 'ipv4-cidr', 'ipv6-cidr', 'hostname' );
    const FIELD_KINDS = '/^(text|location|select|multi|secret|file:[a-z][a-z0-9-]{0,40})$/';
    /** largest size limit a file kind may ask for */
    const KIND_MAX = 209715200;

    /** @var array name => description (checked) */
    public $plugins = array();
    /** @var string[] folder => why it was not loaded */
    public $errors = array();

    /** @var array name => header of packages that were not loaded (not licensed) - shown to admins */
    public $locked = array();

    public static function load( string $viewerDir, ?PluginLicense $licence = null, ?callable $featureOn = null ): ViewerPlugins
    {
        $all = new ViewerPlugins();
        $dirs = array( $viewerDir . '/plugins' );
        $extra = (string)getenv( 'PANOSPHP_VIEWER_PLUGINS' );
        if( $extra !== '' )
            $dirs[] = rtrim( $extra, '/' );
        foreach( $dirs as $dir )
        {
            // encrypted packages
            foreach( glob( $dir . '/*.ppp' ) ?: array() as $pkg )
            {
                $folder = basename( $pkg, '.ppp' );
                try
                {
                    $head = PluginPackage::header( $pkg );
                    if( $head['name'] !== $folder )
                        throw new Exception( 'the file name must be ' . $head['name'] . '.ppp' );
                    if( $licence === null )
                        throw new Exception( 'not licensed: no licence installed' );
                    if( $featureOn !== null && !$featureOn( $head['feature'] ) )
                        throw new Exception( 'not licensed: the licence does not hold the feature ' . $head['feature'] . ', ended, or the clock was set back' );
                    PluginPackage::mount( $pkg, $licence );
                    $p = self::check( $folder, self::read( 'ppp://' . $folder . '/plugin.php' ) );
                    if( $p['feature'] !== $head['feature'] )
                        throw new Exception( 'the feature of the package and of plugin.php differ' );
                    if( isset( $all->plugins[$p['name']] ) )
                        throw new Exception( 'a plug-in with this name is loaded already' );
                    $p['dir'] = 'ppp://' . $folder;
                    $p['builtin'] = FALSE;
                    $p['package'] = (string)realpath( $pkg );
                    foreach( $p['runs'] as $k => $r )
                        $p['runs'][$k] += array( 'dir' => $p['dir'], 'builtin' => FALSE, 'package' => $p['package'] );
                    $all->plugins[$p['name']] = $p;
                }
                catch( Throwable $e )
                {
                    if( isset( $head ) && strpos( $e->getMessage(), 'not licensed' ) === 0 )
                        $all->locked[$folder] = array( 'version' => (string)( $head['version'] ?? '' ), 'feature' => $head['feature'], 'why' => $e->getMessage() );
                    else
                        $all->errors[$folder . '.ppp'] = $e->getMessage();
                }
                unset( $head );
            }
            foreach( glob( $dir . '/*/plugin.php' ) ?: array() as $file )
            {
                $folder = basename( dirname( $file ) );
                try
                {
                    $p = self::check( $folder, self::read( $file ) );
                    // where the plug-in is: for %PLUGIN% in the environment of its runs; 'builtin': shipped in the folder plugins/ of the viewer
                    $p['dir'] = (string)realpath( dirname( $file ) );
                    $p['builtin'] = $dir === $viewerDir . '/plugins';
                    foreach( $p['runs'] as $k => $r )
                        $p['runs'][$k] += array( 'dir' => $p['dir'], 'builtin' => $p['builtin'] );
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
        if( !in_array( $p['api'] ?? null, self::APIS, TRUE ) )
            throw new Exception( '"api" must be ' . implode( ' or ', self::APIS ) );
        $name = $p['name'] ?? null;
        if( !is_string( $name ) || !preg_match( '/^[a-z][a-z0-9]{1,30}$/', $name ) || $name !== $folder )
            throw new Exception( '"name": lower case letters and digits, the same as the folder name' );
        $out = array( 'name' => $name, 'api' => $p['api'], 'version' => self::text( $p['version'] ?? '0', 'version', 40 ), 'title' => self::text( $p['title'] ?? $name, 'title', 80 ),
            'feature' => null, 'runs' => array(), 'kinds' => array(), 'playbookTypes' => array(), 'pages' => array(), 'projectTypes' => array() );
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
            $format = $k['format'] ?? 'json';
            $max = $k['max'] ?? null;
            if( !in_array( $format, array( 'json', 'raw' ), TRUE ) || ( $max !== null && ( !is_int( $max ) || $max < 1 || $max > self::KIND_MAX ) ) )
                throw new Exception( 'file kind ' . $kind . ': "format" json or raw, "max" bytes up to ' . self::KIND_MAX );
            $out['kinds'][$name . '-' . $kind] = array( 'title' => self::text( $k['title'] ?? $kind, 'title', 80 ), 'check' => $k['check'] ?? null, 'format' => $format, 'max' => $max );
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
                    throw new Exception( 'run ' . $run . ': a field needs "name" and "kind" (text, location, select, multi, file:<kind>)' );
                $kind = $f['kind'];
                $options = array();
                if( $kind === 'select' || $kind === 'multi' )
                {
                    foreach( (array)( $f['options'] ?? array() ) as $value => $label )
                    {
                        if( !preg_match( '/^[a-z0-9][a-z0-9_.-]{0,40}$/', (string)$value ) )
                            throw new Exception( 'run ' . $run . ': field ' . $f['name'] . ': option values with lower case letters, digits and . _ -' );
                        $options[(string)$value] = self::text( $label, 'option', 80 );
                    }
                    if( count( $options ) < 1 || count( $options ) > 200 )
                        throw new Exception( 'run ' . $run . ': field ' . $f['name'] . ' needs "options" (value => label)' );
                }
                // file:<kind> of this plug-in, or the kinds of the viewer
                if( strpos( $kind, 'file:' ) === 0 && !in_array( substr( $kind, 5 ), array( 'playbook', 'bp' ), TRUE ) )
                {
                    if( !isset( $out['kinds'][$name . '-' . substr( $kind, 5 )] ) )
                        throw new Exception( 'run ' . $run . ': field ' . $f['name'] . ' uses an unknown file kind' );
                    $kind = 'file:' . $name . '-' . substr( $kind, 5 );
                }
                $fields[] = array( 'name' => $f['name'], 'kind' => $kind, 'label' => self::text( $f['label'] ?? $f['name'], 'label', 80 ),
                    'default' => self::text( $f['default'] ?? '', 'default', 200 ), 'required' => !empty( $f['required'] ), 'options' => $options );
            }
            $result = $r['result'] ?? null;
            if( $result !== null && ( !is_string( $result ) || !preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]{0,60}\.xml$/', $result ) ) )
                throw new Exception( 'run ' . $run . ': "result" must be a plain .xml file name' );
            // environment of the run, e.g. where pan-os-php finds files of the plug-in: %PLUGIN% is the folder of the plug-in
            $env = array();
            foreach( (array)( $r['env'] ?? array() ) as $k => $v )
            {
                if( !is_string( $k ) || !preg_match( '/^PANOSPHP_[A-Z0-9_]{1,40}$/', $k ) || strpos( $k, 'PANOSPHP_VIEWER_' ) === 0
                    || !is_string( $v ) || !preg_match( '#^[A-Za-z0-9_./%-]{1,200}$#', $v ) || strpos( $v, '..' ) !== FALSE )
                    throw new Exception( 'run ' . $run . ': "env" names start with PANOSPHP_ (not PANOSPHP_VIEWER_), values are plain paths / words' );
                $env[$k] = $v;
            }
            $input = $r['input'] ?? 'version';
            if( !in_array( $input, array( 'version', 'none' ), TRUE ) )
                throw new Exception( 'run ' . $run . ': "input" is version or none' );
            if( $input === 'none' && $result === null )
                throw new Exception( 'run ' . $run . ': a run without a version needs "result"' );
            $approval = $r['approval'] ?? null;
            if( $approval !== null && ( !is_string( $approval ) || !preg_match( '#^[a-z][a-z0-9-]{0,30}/[a-z][a-z0-9_-]{0,30}$#', $approval ) ) )
                throw new Exception( 'run ' . $run . ': "approval" must be <page>/<block>' );
            $out['runs'][$name . '-' . $run] = array( 'plugin' => $name, 'feature' => $out['feature'], 'input' => $input, 'tool' => $r['tool'], 'title' => self::text( $r['title'] ?? $run, 'title', 80 ), 'fields' => $fields,
                'bp' => !empty( $r['bp'] ), 'result' => $result, 'args' => $r['args'], 'env' => $env, 'approval' => $approval );
        }
        foreach( (array)( $p['playbookTypes'] ?? array() ) as $t )
        {
            if( !is_string( $t ) || !preg_match( '/^[a-z][a-z-]{0,40}$/', $t ) )
                throw new Exception( '"playbookTypes": pan-os-php type names' );
            $out['playbookTypes'][] = $t;
        }
        if( ( isset( $p['pages'] ) || isset( $p['projectTypes'] ) ) && $p['api'] < 2 )
            throw new Exception( '"pages" / "projectTypes" need "api" 2' );
        foreach( (array)( $p['projectTypes'] ?? array() ) as $type => $t )
            $out['projectTypes'][$name . '-' . $type] = self::checkProjectType( $name, $out['feature'], $type, $t );
        foreach( (array)( $p['pages'] ?? array() ) as $page => $pg )
        {
            $out['pages'][$name . '-' . $page] = self::checkPage( $name, $out['feature'], $page, $pg, $out['runs'] );
            foreach( $out['pages'][$name . '-' . $page]['types'] as $t )
                if( !isset( $out['projectTypes'][$t] ) )
                    throw new Exception( 'page ' . $page . ': project type ' . $t . ' is not one of this plug-in' );
        }
        // a run that needs an approval: the approval block of a page of this plug-in
        foreach( $out['runs'] as $k => $r )
            if( $r['approval'] !== null )
            {
                list( $page, $block ) = explode( '/', $r['approval'] );
                if( ( $out['pages'][$name . '-' . $page]['blocks'][$block]['kind'] ?? null ) !== 'approval' )
                    throw new Exception( 'run ' . $k . ': "approval" ' . $r['approval'] . ' is not an approval block of this plug-in' );
                if( $out['pages'][$name . '-' . $page]['blocks'][$block]['run'] === $k )
                    throw new Exception( 'run ' . $k . ': can not need the approval of its own result' );
                $out['runs'][$k]['approval'] = array( 'page' => $name . '-' . $page, 'block' => $block );
            }
        return $out;
    }

    /** a project type (interface 2): title, roles (name => title, kind panos | scm, write) */
    private static function checkProjectType( string $plugin, ?string $feature, $type, $t ): array
    {
        if( !is_string( $type ) || !preg_match( '/^[a-z][a-z0-9-]{0,30}$/', $type ) || !is_array( $t ) )
            throw new Exception( 'project type: lower case name and a description' );
        $roles = array();
        foreach( (array)( $t['roles'] ?? array() ) as $role => $r )
        {
            if( !is_string( $role ) || !preg_match( '/^[a-z][a-z0-9-]{0,20}$/', $role ) || !is_array( $r ) )
                throw new Exception( 'project type ' . $type . ': role: lower case name and a description' );
            if( !in_array( $r['kind'] ?? null, array( 'panos', 'scm' ), TRUE ) )
                throw new Exception( 'project type ' . $type . ', role ' . $role . ': "kind" panos or scm' );
            $roles[$role] = array( 'name' => $role, 'title' => self::text( $r['title'] ?? $role, 'title', 80 ), 'kind' => $r['kind'], 'write' => !empty( $r['write'] ) );
        }
        if( count( $roles ) < 1 || count( $roles ) > 8 )
            throw new Exception( 'project type ' . $type . ': 1 to 8 roles' );
        return array( 'plugin' => $plugin, 'feature' => $feature, 'type' => $type, 'title' => self::text( $t['title'] ?? $type, 'title', 80 ),
            'text' => self::text( $t['text'] ?? '', 'text', 1000 ), 'roles' => $roles );
    }

    /** a page (interface 2): title, text, blocks */
    private static function checkPage( string $plugin, ?string $feature, $page, $pg, array $runs = array() ): array
    {
        if( !is_string( $page ) || !preg_match( '/^[a-z][a-z0-9-]{0,30}$/', $page ) || !is_array( $pg ) )
            throw new Exception( 'page: lower case name and a description' );
        $blocks = array();
        foreach( (array)( $pg['blocks'] ?? array() ) as $b )
        {
            if( !is_array( $b ) || !is_string( $b['name'] ?? null ) || !preg_match( '/^[a-z][a-z0-9_-]{0,30}$/', $b['name'] ) || isset( $blocks[$b['name']] ) )
                throw new Exception( 'page ' . $page . ': a block needs a "name" (lower case, unique)' );
            $kind = $b['kind'] ?? null;
            if( !in_array( $kind, array( 'form', 'table', 'approval' ), TRUE ) )
                throw new Exception( 'page ' . $page . ', block ' . $b['name'] . ': "kind" must be form, table or approval' );
            foreach( array( 'defaults', 'check', 'rows', 'areas' ) as $c )
                if( isset( $b[$c] ) && !is_callable( $b[$c] ) )
                    throw new Exception( 'page ' . $page . ', block ' . $b['name'] . ': "' . $c . '" must be callable' );
            if( $kind === 'table' )
            {
                $blocks[$b['name']] = self::checkTable( 'page ' . $page . ', block ' . $b['name'], $b );
                continue;
            }
            if( $kind === 'approval' )
            {
                $where = 'page ' . $page . ', block ' . $b['name'];
                $run = $b['run'] ?? null;
                if( !is_string( $run ) || !isset( $runs[$plugin . '-' . $run] ) )
                    throw new Exception( $where . ': "run" must name a run type of this plug-in (its result is the plan)' );
                if( !is_string( $b['file'] ?? null ) || !preg_match( '/^[A-Za-z0-9][A-Za-z0-9._-]{0,60}\.json$/', $b['file'] ) )
                    throw new Exception( $where . ': "file" must be a plain .json file name (the plan the run writes)' );
                if( !isset( $b['areas'] ) )
                    throw new Exception( $where . ': "areas" (callable: the areas of the plan) is needed' );
                $blocks[$b['name']] = array( 'name' => $b['name'], 'kind' => 'approval', 'title' => self::text( $b['title'] ?? $b['name'], 'title', 120 ),
                    'text' => self::text( $b['text'] ?? '', 'text', 1000 ), 'fields' => array(), 'run' => $plugin . '-' . $run, 'file' => $b['file'],
                    'areas' => $b['areas'], 'defaults' => null, 'check' => null );
                continue;
            }
            $fields = array();
            foreach( (array)( $b['fields'] ?? array() ) as $f )
            {
                $f = self::checkField( 'page ' . $page . ', block ' . $b['name'], $f );
                if( isset( $fields[$f['name']] ) )
                    throw new Exception( 'page ' . $page . ', block ' . $b['name'] . ': field ' . $f['name'] . ' twice' );
                $fields[$f['name']] = $f;
            }
            if( count( $fields ) < 1 || count( $fields ) > 200 )
                throw new Exception( 'page ' . $page . ', block ' . $b['name'] . ': 1 to 200 fields' );
            $blocks[$b['name']] = array( 'name' => $b['name'], 'kind' => 'form', 'title' => self::text( $b['title'] ?? $b['name'], 'title', 120 ),
                'text' => self::text( $b['text'] ?? '', 'text', 1000 ), 'fields' => $fields, 'defaults' => $b['defaults'] ?? null, 'check' => $b['check'] ?? null );
        }
        if( count( $blocks ) < 1 || count( $blocks ) > 20 )
            throw new Exception( 'page ' . $page . ': 1 to 20 blocks' );
        // the project types the page belongs to (of this plug-in; none: every project)
        $types = array();
        foreach( (array)( $pg['projectTypes'] ?? array() ) as $t )
        {
            if( !is_string( $t ) || !preg_match( '/^[a-z][a-z0-9-]{0,30}$/', $t ) )
                throw new Exception( 'page ' . $page . ': "projectTypes": names of project types of this plug-in' );
            $types[] = $plugin . '-' . $t;
        }
        return array( 'plugin' => $plugin, 'feature' => $feature, 'page' => $page, 'title' => self::text( $pg['title'] ?? $page, 'title', 80 ),
            'text' => self::text( $pg['text'] ?? '', 'text', 1000 ), 'blocks' => $blocks, 'types' => $types );
    }

    /**
     * a table block: 'columns' (fields; 'edit' => TRUE: editable), 'key' (the column that names a row, not editable),
     * 'rows' (callable: the rows of the plug-in, column => value), 'check' (callable: the rows with the changes)
     */
    private static function checkTable( string $where, array $b ): array
    {
        if( !isset( $b['rows'] ) )
            throw new Exception( $where . ': a table needs "rows" (callable)' );
        $cols = array();
        foreach( (array)( $b['columns'] ?? array() ) as $c )
        {
            $f = self::checkField( $where, $c );
            if( isset( $cols[$f['name']] ) )
                throw new Exception( $where . ': column ' . $f['name'] . ' twice' );
            $f['edit'] = !empty( $c['edit'] );
            $cols[$f['name']] = $f;
        }
        if( count( $cols ) < 1 || count( $cols ) > 50 )
            throw new Exception( $where . ': 1 to 50 columns' );
        $key = $b['key'] ?? null;
        if( !is_string( $key ) || !isset( $cols[$key] ) || $cols[$key]['edit'] )
            throw new Exception( $where . ': "key" must name a column that is not editable' );
        if( count( array_filter( $cols, function( $c ) { return $c['edit']; } ) ) === 0 )
            throw new Exception( $where . ': at least one column with "edit" => TRUE' );
        return array( 'name' => $b['name'], 'kind' => 'table', 'title' => self::text( $b['title'] ?? $b['name'], 'title', 120 ),
            'text' => self::text( $b['text'] ?? '', 'text', 1000 ), 'fields' => $cols, 'key' => $key, 'rows' => $b['rows'], 'defaults' => null, 'check' => $b['check'] ?? null );
    }

    /** a field of a form block: name, type, label, help, required, options (select), min / max (int), max (text), item (list) */
    private static function checkField( string $where, $f ): array
    {
        if( !is_array( $f ) || !is_string( $f['name'] ?? null ) || !preg_match( '/^[a-z][a-z0-9_]{0,40}$/', $f['name'] ) )
            throw new Exception( $where . ': a field needs a "name" (lower case letters, digits, _)' );
        $type = $f['type'] ?? null;
        if( !in_array( $type, self::FIELD_TYPES, TRUE ) )
            throw new Exception( $where . ': field ' . $f['name'] . ': "type" one of ' . implode( ', ', self::FIELD_TYPES ) );
        $out = array( 'name' => $f['name'], 'type' => $type, 'label' => self::text( $f['label'] ?? $f['name'], 'label', 80 ),
            'help' => self::text( $f['help'] ?? '', 'help', 300 ), 'required' => !empty( $f['required'] ) );
        if( $type === 'select' )
        {
            $out['options'] = array();
            foreach( (array)( $f['options'] ?? array() ) as $value => $label )
            {
                if( !preg_match( '/^[a-z0-9][a-z0-9_.-]{0,40}$/', (string)$value ) )
                    throw new Exception( $where . ': field ' . $f['name'] . ': option values with lower case letters, digits and . _ -' );
                $out['options'][(string)$value] = self::text( $label, 'option', 80 );
            }
            if( count( $out['options'] ) < 1 || count( $out['options'] ) > 200 )
                throw new Exception( $where . ': field ' . $f['name'] . ' needs "options" (value => label)' );
        }
        if( $type === 'int' )
            foreach( array( 'min', 'max' ) as $k )
                if( isset( $f[$k] ) )
                {
                    if( !is_int( $f[$k] ) )
                        throw new Exception( $where . ': field ' . $f['name'] . ': "' . $k . '" must be a number' );
                    $out[$k] = $f[$k];
                }
        if( $type === 'text' )
        {
            $max = $f['max'] ?? 200;
            if( !is_int( $max ) || $max < 1 || $max > 2000 )
                throw new Exception( $where . ': field ' . $f['name'] . ': "max" 1 to 2000' );
            $out['max'] = $max;
        }
        if( $type === 'list' )
        {
            $item = $f['item'] ?? 'text';
            if( !in_array( $item, self::LIST_ITEMS, TRUE ) )
                throw new Exception( $where . ': field ' . $f['name'] . ': "item" one of ' . implode( ', ', self::LIST_ITEMS ) );
            $out['item'] = $item;
        }
        return $out;
    }

    /**
     * the value of a field, checked by its type: the stored form (int, bool, normalised address, list), null when
     * empty. Throws Exception (the message names the problem, not the field).
     */
    public static function fieldValue( array $f, $v )
    {
        if( $v === null || $v === '' || $v === array() )
        {
            if( $f['required'] )
                throw new Exception( 'is needed' );
            return $f['type'] === 'bool' ? FALSE : null;
        }
        switch( $f['type'] )
        {
            case 'bool':
                if( is_bool( $v ) )
                    return $v;
                if( in_array( $v, array( 'true', '1', 1 ), TRUE ) )
                    return TRUE;
                if( in_array( $v, array( 'false', '0', 0 ), TRUE ) )
                    return FALSE;
                throw new Exception( 'yes or no' );
            case 'int':
            case 'asn':
                if( is_string( $v ) && preg_match( '/^-?[0-9]{1,19}$/', trim( $v ) ) )
                    $v = (int)trim( $v );
                if( !is_int( $v ) )
                    throw new Exception( 'a number' );
                $min = $f['type'] === 'asn' ? 1 : ( $f['min'] ?? null );
                $max = $f['type'] === 'asn' ? 4294967295 : ( $f['max'] ?? null );
                if( ( $min !== null && $v < $min ) || ( $max !== null && $v > $max ) )
                    throw new Exception( $f['type'] === 'asn' ? 'an AS number (1 to 4294967295)' : 'a number from ' . ( $min ?? '…' ) . ' to ' . ( $max ?? '…' ) );
                return $v;
            case 'select':
                if( !is_string( $v ) || !isset( $f['options'][$v] ) )
                    throw new Exception( 'not one of the options' );
                return $v;
            case 'list':
                if( !is_array( $v ) || count( $v ) > 500 )
                    throw new Exception( 'a list (at most 500 entries)' );
                $out = array();
                foreach( array_values( $v ) as $i => $x )
                {
                    if( $x === '' || $x === null )
                        continue;
                    try
                    {
                        $out[] = self::scalarValue( $f['item'], $x, 200 );
                    }
                    catch( Exception $e )
                    {
                        throw new Exception( 'entry ' . ( $i + 1 ) . ': ' . $e->getMessage() );
                    }
                }
                if( $f['required'] && count( $out ) === 0 )
                    throw new Exception( 'is needed' );
                return $out;
            default:
                return self::scalarValue( $f['type'], $v, $f['max'] ?? 200 );
        }
    }

    /** text / ipv4 / ipv4-cidr / ipv6-cidr / hostname */
    private static function scalarValue( string $type, $v, int $max )
    {
        if( !is_string( $v ) || strlen( $v ) > $max || preg_match( '/[\x00-\x1f]/', $v ) )
            throw new Exception( 'text of at most ' . $max . ' characters' );
        $v = $type === 'text' ? $v : trim( $v );
        switch( $type )
        {
            case 'ipv4':
                if( filter_var( $v, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) === FALSE )
                    throw new Exception( 'an IPv4 address' );
                return $v;
            case 'ipv4-cidr':
                if( !preg_match( '#^([0-9.]+)/([0-9]{1,2})$#', $v, $m ) || filter_var( $m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) === FALSE || (int)$m[2] > 32 )
                    throw new Exception( 'an IPv4 network (a.b.c.d/n)' );
                $len = (int)$m[2];
                $net = long2ip( ip2long( $m[1] ) & ( $len === 0 ? 0 : ( ~0 << ( 32 - $len ) ) & 0xFFFFFFFF ) );
                if( $net !== $m[1] )
                    throw new Exception( 'not the network address of the subnet (' . $net . '/' . $len . ')' );
                return $net . '/' . $len;
            case 'ipv6-cidr':
                if( !preg_match( '#^([0-9a-fA-F:.]+)/([0-9]{1,3})$#', $v, $m ) || filter_var( $m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) === FALSE || (int)$m[2] > 128 )
                    throw new Exception( 'an IPv6 network (x::/n)' );
                $bin = inet_pton( $m[1] );
                $len = (int)$m[2];
                $net = '';
                for( $i = 0; $i < 16; $i++ )
                {
                    $bits = max( 0, min( 8, $len - 8 * $i ) );
                    $net .= chr( ord( $bin[$i] ) & ( ( 0xFF << ( 8 - $bits ) ) & 0xFF ) );
                }
                if( $net !== $bin )
                    throw new Exception( 'not the network address of the subnet (' . inet_ntop( $net ) . '/' . $len . ')' );
                return inet_ntop( $bin ) . '/' . $len;
            case 'hostname':
                if( strlen( $v ) > 253 || !preg_match( '/^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/', $v ) )
                    throw new Exception( 'a host name (letters, digits, -, labels separated by .)' );
                return strtolower( $v );
            default:
                return $v;
        }
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

    /** pages (interface 2) of the plug-ins that are switched on: <plugin>-<page> => description */
    public function pages( ?callable $on = null ): array
    {
        $pages = array();
        foreach( $this->plugins as $p )
            if( $on === null || $on( $p ) )
                $pages += $p['pages'] ?? array();
        return $pages;
    }

    /** project types (interface 2) of the plug-ins that are switched on: <plugin>-<type> => description */
    public function projectTypes( ?callable $on = null ): array
    {
        $types = array();
        foreach( $this->plugins as $p )
            if( $on === null || $on( $p ) )
                $types += $p['projectTypes'] ?? array();
        return $types;
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
    private $fields = array();

    /** the approved plan of a run type with 'approval' (a copy, as it was approved) */
    private $approved;

    public function __construct( array $in, callable $file, array $fields = array(), ?string $approved = null )
    {
        $this->in = $in;
        $this->file = $file;
        $this->approved = $approved;
        foreach( $fields as $f )
            $this->fields[$f['name']] = $f;
    }

    /** the chosen value of a "select" field (one of its options); '' when not given */
    public function choice( string $field ): string
    {
        $v = $this->in[$field] ?? '';
        if( $v === '' )
            return '';
        if( !is_string( $v ) || !isset( $this->fields[$field]['options'][$v] ) )
            throw new ViewerException( $field . ': not one of the options', 400 );
        return $v;
    }

    /** the chosen values of a "multi" field (each one of its options); empty when not given */
    public function choices( string $field ): array
    {
        $v = $this->in[$field] ?? array();
        if( is_string( $v ) )
            $v = $v === '' ? array() : explode( ',', $v );
        if( !is_array( $v ) )
            throw new ViewerException( $field . ': a list of options', 400 );
        foreach( $v as $one )
            if( !is_string( $one ) || !isset( $this->fields[$field]['options'][$one] ) )
                throw new ViewerException( $field . ': not one of the options', 400 );
        return array_values( array_unique( $v ) );
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

    /**
     * a field 'secret': the file uploaded for this run only (POST …/secret-uploads, the token as value) - in the hidden
     * folder of the run, removed when the run ends; null when the field is not given
     */
    public function secret( string $field ): ?string
    {
        if( ( $this->fields[$field]['kind'] ?? null ) !== 'secret' )
            throw new ViewerException( 'plug-in: ' . $field . ' is not a field "secret"', 500 );
        $v = $this->in[$field] ?? '';
        if( $v === '' )
            return null;
        if( !is_string( $v ) || !preg_match( '/^[0-9a-f]{32}$/', $v ) )
            throw new ViewerException( $field . ': the token of an upload (POST …/secret-uploads)', 400 );
        return '%JOB%/.secret/' . $field;
    }

    /** a run type with 'approval': the plan as it was approved (a copy - a newer plan does not change it) */
    public function approved(): string
    {
        if( $this->approved === null )
            throw new ViewerException( 'plug-in: approved() only for a run type with "approval"', 500 );
        return $this->approved;
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

/**
 * what the callables of a page (defaults, check) get: the stored values of the page and read access to the data of the
 * project the viewer has (the SCM tab) - never a path of the server, nothing to write
 */
class ViewerPluginPage
{
    /** @var array block => values (stored) */
    private $saved;
    private $reader;

    public function __construct( array $saved, callable $reader )
    {
        $this->saved = $saved;
        $this->reader = $reader;
    }

    /** the stored values of a block of this page (empty: not saved yet); a table: the changes, key => column => value */
    public function values( string $block ): array
    {
        return $this->saved[$block] ?? array();
    }

    /**
     * a table block of this page as it is now: its rows with the stored changes, key => column => value (null:
     * not a table of this page)
     */
    public function rows( string $block ): ?array
    {
        return ( $this->reader )( 'rows', $block );
    }

    /**
     * the data of one endpoint of the newest state of a page of the SCM tab (Prisma Access: infra, sc, rn, mugw, …),
     * as the SCM API gave it ('data' of the export file); null: no such state / endpoint. $role (a project with a
     * project type): only states of the tenant of that role
     */
    public function scmPa( string $page, string $endpoint, ?string $role = null )
    {
        return ( $this->reader )( 'scm-pa', $page, $endpoint, $role );
    }

    /** a project with a project type: a role and its binding - name, title, kind, write, target (null: not bound yet) */
    public function role( string $role ): ?array
    {
        return ( $this->reader )( 'role', $role );
    }
}
