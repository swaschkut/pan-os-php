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

require_once dirname(__FILE__) . '/../common/ConfigSecrets.php';
require_once dirname(__FILE__) . '/../common/ConfigAnonymizer.php';
require_once dirname(__FILE__) . '/../common/ConfigExcerpt.php';

/**
 * Support files (todo/support-file.md, SupportFile):
 *
 *   type=support-file in=config.xml out=support.tsf [result=after.xml] [report=merger.json] [names=a,b] [rules=no]
 *        [full] [anonymize [ip=keep-private] [mapping=map.json]] [extra=<folder>] [note=text]
 *     makes the support file: environment, the excerpt of the configuration for the names (every copy in every
 *     location, the groups up, the members down, the rules - before and after), the hierarchy, the report, the files of
 *     extra (the config viewer: project, runs, logs), with full the whole configurations. Secrets (passwords, phash,
 *     keys, ...) are always replaced. anonymize: all names / addresses / texts consistently replaced (ConfigAnonymizer,
 *     one mapping for every file); the mapping is written only to mapping= - never into the support file. Encrypted
 *     for the support key (lib/resources/support/keys.json).
 *
 *   type=support-file-read in=support.tsf key=<support key file> out=<folder>
 *     opens it (the key file of the licence tool, support-keygen), checks every file against the manifest, unpacks it
 *     and writes report.html: environment, case, hierarchy, every copy of each name before / after, what to run to
 *     reproduce (config/excerpt-before.xml is a configuration pan-os-php loads).
 */
class SUPPORTFILE__ extends UTIL
{
    const FORMAT = 1;

    public function utilStart()
    {
        $read = $this->utilType === 'support-file-read';
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array( 'niceName' => 'in', 'shortHelp' => $read ? 'the support file (.tsf)' : 'the configuration (XML) of the case', 'argDesc' => '[file]' );
        $this->supportedArguments['out'] = array( 'niceName' => 'out', 'shortHelp' => $read ? 'folder for the content and report.html' : 'the support file (.tsf)', 'argDesc' => '[file|folder]' );
        if( $read )
            $this->supportedArguments['key'] = array( 'niceName' => 'key', 'shortHelp' => 'the support key file (licence tool: support-keygen) - SECRET', 'argDesc' => '[file]' );
        else
        {
            $this->supportedArguments['result'] = array( 'niceName' => 'result', 'shortHelp' => 'the configuration after the run (e.g. out.xml of the merger)', 'argDesc' => '[file]' );
            $this->supportedArguments['report'] = array( 'niceName' => 'report', 'shortHelp' => 'the JSON report of the run (exportjson= of a merger): its names go into the excerpt', 'argDesc' => '[file]' );
            $this->supportedArguments['names'] = array( 'niceName' => 'names', 'shortHelp' => 'object names for the excerpt (comma separated), in addition to the report', 'argDesc' => '[name1,name2]' );
            $this->supportedArguments['rules'] = array( 'niceName' => 'rules', 'shortHelp' => 'the rules that use the names (default yes)', 'argDesc' => 'yes|no' );
            $this->supportedArguments['full'] = array( 'niceName' => 'full', 'shortHelp' => 'the whole configurations as well (in / result)' );
            $this->supportedArguments['anonymize'] = array( 'niceName' => 'anonymize', 'shortHelp' => 'anonymise everything (ConfigAnonymizer): names, addresses, texts - consistent in every file' );
            $this->supportedArguments['ip'] = array( 'niceName' => 'ip', 'shortHelp' => 'with anonymize: remap (default) | keep-private', 'argDesc' => 'remap|keep-private' );
            $this->supportedArguments['mapping'] = array( 'niceName' => 'mapping', 'shortHelp' => 'with anonymize: the mapping original -> pseudonym, SENSITIVE, stays with the customer (never in the support file)', 'argDesc' => '[file.json]' );
            $this->supportedArguments['extra'] = array( 'niceName' => 'extra', 'shortHelp' => 'folder with more files for the support file (viewer: project, runs, logs)', 'argDesc' => '[folder]' );
            $this->supportedArguments['note'] = array( 'niceName' => 'note', 'shortHelp' => 'what the problem is (free text)', 'argDesc' => '[text]' );
        }
        $this->supportedArguments['help'] = array( 'niceName' => 'help', 'shortHelp' => 'this message' );
        $this->supportedArguments['shadow-json'] = array( 'niceName' => 'shadow-json', 'shortHelp' => 'output as JSON' );
        $this->supportedArguments['shadow-nojson'] = array( 'niceName' => 'shadow-nojson', 'shortHelp' => 'output as text' );
        $this->usageMsg = PH::boldText( "USAGE: " ) . ( $read
                ? "pan-os-php type=support-file-read in=support.tsf key=support-<kid>.key out=<folder>\n"
                : "pan-os-php type=support-file in=config.xml out=support.tsf [result=out.xml] [report=merger.json] [names=a,b] [full] [anonymize mapping=map.json] [extra=<folder>] [note=...]\n" );
        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();
        $this->help( PH::$args );
        try
        {
            $read ? $this->read() : $this->create();
        }
        catch( Exception $e )
        {
            derr( $e->getMessage(), null, FALSE );
        }
    }

    // ------------------------------------------------------------------ create

    private function create()
    {
        foreach( array( 'in', 'out' ) as $a )
            if( !isset( PH::$args[$a] ) || PH::$args[$a] === '' )
                $this->display_error_usage_exit( '"' . $a . '" is not set' );
        // the key first: no work without a key to encrypt for
        list( $kid, ) = SupportFile::currentKey();
        $anonymize = isset( PH::$args['anonymize'] );
        $full = isset( PH::$args['full'] );
        $rules = strtolower( (string)( PH::$args['rules'] ?? 'yes' ) ) !== 'no';
        $files = array();   // path in the zip => content
        $notes = array();

        $docs = array( 'before' => $this->loadXml( PH::$args['in'] ) );
        if( isset( PH::$args['result'] ) && PH::$args['result'] !== '' )
            $docs['after'] = $this->loadXml( PH::$args['result'] );

        // names: the report (the problems first), names=
        $report = null;
        $names = array();
        $ruleNames = array();
        if( isset( PH::$args['report'] ) && PH::$args['report'] !== '' )
        {
            $report = json_decode( (string)@file_get_contents( PH::$args['report'] ), TRUE );
            if( !is_array( $report ) )
                throw new Exception( "report '" . PH::$args['report'] . "' is no JSON report" );
            list( $names, $ruleNames, $n ) = self::reportNames( $report );
            if( $n !== '' )
                $notes[] = $n;
        }
        if( isset( PH::$args['names'] ) && PH::$args['names'] !== '' )
            foreach( explode( ',', PH::$args['names'] ) as $n )
                if( trim( $n ) !== '' )
                    $names[trim( $n )] = TRUE;
        $names = array_keys( $names );

        // secrets always out; anonymize: one ConfigAnonymizer for every document (the same pseudonyms everywhere)
        $anon = null;
        if( $anonymize )
        {
            $ip = strtolower( (string)( PH::$args['ip'] ?? 'remap' ) );
            if( !in_array( $ip, array( 'remap', 'keep-private' ), TRUE ) )
                throw new Exception( 'ip=remap|keep-private' );
            $anon = new ConfigAnonymizer( null, array( 'ip' => $ip ) );
        }

        // the excerpt per document (before the anonymisation: the names of the report are the original ones)
        $summary = array();
        foreach( $docs as $which => $doc )
        {
            $ex = new ConfigExcerpt( $doc );
            if( $which === 'before' )
                $files['config/hierarchy.json'] = $ex->hierarchy();
            $sel = $ex->select( $names, $rules );
            foreach( $ruleNames as $rn => $loc )
                $sel = self::addRule( $ex, $doc, $sel, $rn, $loc );
            if( $ex->truncated )
                $notes[] = 'excerpt ' . $which . ': more than ' . ConfigExcerpt::MAX_ENTRIES . ' entries - cut';
            $summary[$which] = array( 'entries' => count( $sel['entries'] ), 'rules' => count( $sel['rules'] ), 'names' => count( $sel['all'] ) );
            $files['config/excerpt-' . $which . '.xml'] = $ex->build( $sel );
        }
        if( $full )
            foreach( $docs as $which => $doc )
                $files['config/full-' . $which . '.xml'] = $doc;

        // secrets / anonymisation of every XML document of the support file
        if( $anon !== null )
        {
            foreach( $files as $p => $d )
                if( $d instanceof DOMDocument )
                    $anon->collectNamesXml( $d );
            foreach( $files as $p => $d )
                if( $d instanceof DOMDocument )
                    $anon->anonymizeXml( $d );
        }
        else
            foreach( $files as $p => $d )
                if( $d instanceof DOMDocument )
                    self::removeSecrets( $d );

        // every copy of each name before / after as data (the reader shows them side by side)
        $objects = array();
        foreach( array( 'before', 'after' ) as $which )
        {
            if( !isset( $files['config/excerpt-' . $which . '.xml'] ) )
                continue;
            $ex = new ConfigExcerpt( $files['config/excerpt-' . $which . '.xml'] );
            foreach( $names as $n )
            {
                $shown = $anon !== null ? ( $anon->names[$n] ?? $n ) : $n;
                foreach( $ex->copies( $shown ) as $c )
                    $objects[$shown][$which][] = array( 'location' => $anon !== null ? ( $anon->names[$c['location']] ?? $c['location'] ) : $c['location'],
                        'store' => $c['store'], 'xml' => $c['element']->ownerDocument->saveXML( $c['element'] ) );
            }
        }
        $files['config/objects.json'] = $objects;

        // the report and the files of extra: anonymised by the mapping (JSON: every string; text: every original),
        // then the leak scan - a file with an original left is not taken
        if( $anon !== null )
            $files['config/hierarchy.json'] = $this->anonJson( $anon, $files['config/hierarchy.json'] );
        if( $report !== null )
            $files['case/report.json'] = $anon !== null ? $this->anonJson( $anon, $report ) : $report;
        if( isset( PH::$args['extra'] ) && PH::$args['extra'] !== '' )
            foreach( $this->extraFiles( PH::$args['extra'] ) as $rel => $text )
            {
                if( $anon !== null )
                {
                    $j = substr( $rel, -5 ) === '.json' ? json_decode( $text, TRUE ) : null;
                    $text = $j !== null ? json_encode( $this->anonJson( $anon, $j ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) : $this->anonText( $anon, $text );
                }
                $files['viewer/' . $rel] = $text;
            }

        // text of every file; leak scan with anonymize
        $texts = array();
        foreach( $files as $p => $d )
            $texts[$p] = $d instanceof DOMDocument ? ( function( $d ) { $d->formatOutput = TRUE; return $d->saveXML(); } )( $d )
                : ( is_array( $d ) ? json_encode( $d, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" : (string)$d );
        $leaks = array();
        if( $anon !== null )
            foreach( $texts as $p => $t )
            {
                $found = $anon->leakScan( $t );
                if( count( $found ) )
                {
                    $leaks[$p] = count( $found );
                    unset( $texts[$p] );
                    $notes[] = $p . ': not taken - ' . count( $found ) . ' original value(s) left after the anonymisation';
                }
            }

        $env = $this->environment();
        $texts['environment.json'] = json_encode( $env, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
        $manifest = array( 'format' => self::FORMAT, 'created' => gmdate( 'Y-m-d\TH:i:s\Z' ), 'kid' => $kid,
            'pan-os-php' => $env['pan-os-php'], 'anonymized' => $anonymize, 'full' => $full, 'rules' => $rules,
            'note' => isset( PH::$args['note'] ) ? substr( (string)PH::$args['note'], 0, 4000 ) : '',
            'names' => $anon !== null ? array_map( function( $n ) use ( $anon ) { return $anon->names[$n] ?? $n; }, $names ) : $names,
            'excerpt' => $summary, 'notes' => $notes, 'files' => array() );
        $texts['README.txt'] = self::readme( $manifest );
        foreach( $texts as $p => $t )
            $manifest['files'][$p] = array( 'size' => strlen( $t ), 'sha256' => hash( 'sha256', $t ) );
        ksort( $manifest['files'] );
        $texts = array( 'manifest.json' => json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" ) + $texts;

        // zip, encrypt, write
        $tmp = tempnam( sys_get_temp_dir(), 'tsf' );
        $zip = new ZipArchive();
        if( $zip->open( $tmp, ZipArchive::OVERWRITE ) !== TRUE )
            throw new Exception( 'can not make the zip' );
        foreach( $texts as $p => $t )
            $zip->addFromString( $p, $t );
        $zip->close();
        $bytes = (string)file_get_contents( $tmp );
        @unlink( $tmp );
        $enc = SupportFile::encrypt( $bytes, $kid );
        if( file_put_contents( PH::$args['out'], $enc ) === FALSE )
            throw new Exception( "can not write '" . PH::$args['out'] . "'" );
        @chmod( PH::$args['out'], 0600 );
        if( $anon !== null && isset( PH::$args['mapping'] ) && PH::$args['mapping'] !== '' )
        {
            file_put_contents( PH::$args['mapping'], json_encode( $anon->mapping(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
            @chmod( PH::$args['mapping'], 0600 );
            PH::print_stdout( " - mapping written to " . PH::$args['mapping'] . " - SENSITIVE: keep it, never send it with the support file" );
        }
        PH::print_stdout( " - support file " . PH::$args['out'] . ": " . count( $texts ) . " files, " . strlen( $enc ) . " bytes, encrypted for the support key " . $kid );
        foreach( $summary as $w => $s )
            PH::print_stdout( "   excerpt " . $w . ": " . $s['entries'] . " entries, " . $s['rules'] . " rules, " . $s['names'] . " names" );
        foreach( $notes as $n )
            PH::print_stdout( "   note: " . $n );
        PH::$JSON_TMP = array( 'file' => basename( PH::$args['out'] ), 'kid' => $kid, 'files' => array_keys( $texts ), 'excerpt' => $summary, 'notes' => $notes, 'anonymized' => $anonymize );
        PH::print_stdout( PH::$JSON_TMP, false, 'support-file' );
    }

    private function loadXml( string $f ): DOMDocument
    {
        if( !is_file( $f ) )
            throw new Exception( "file '" . $f . "' not found" );
        $d = new DOMDocument();
        $d->preserveWhiteSpace = FALSE;
        if( !@$d->load( $f, LIBXML_PARSEHUGE | LIBXML_NONET ) )
            throw new Exception( "file '" . $f . "' is no valid XML" );
        return $d;
    }

    /**
     * the names of a report (object-merger, *-merger, merger-possible-report, rule-merger): the ones not merged / blocked
     * always, merged ones up to 200; rule-merger: rule names (location)
     */
    public static function reportNames( array $r ): array
    {
        $problem = array();
        $merged = array();
        $rules = array();
        $nameOf = function( $x ) {
            if( is_array( $x ) )
                return is_string( $x['name'] ?? null ) ? $x['name'] : null;
            if( is_string( $x ) && preg_match( '/^[^:]*:(.+)$/s', $x, $m ) )
                return preg_replace( '/=content#[0-9a-f]+$|\s*\(.*$/', '', $m[1] );
            return null;
        };
        if( ( $r['type'] ?? '' ) === 'rule-merger' )
        {
            foreach( array_merge( $r['skipped'] ?? array(), $r['merged'] ?? array() ) as $x )
                if( is_string( $x['rule'] ?? null ) )
                    $rules[$x['rule']] = (string)( $x['location'] ?? '' );
            return array( array(), $rules, '' );
        }
        foreach( $r['skipped'] ?? array() as $x )
        {
            foreach( array_merge( array( $x['kept'] ?? null ), (array)( $x['notMergedWith'] ?? array() ) ) as $o )
                if( ( $n = $nameOf( $o ) ) !== null )
                    $problem[$n] = TRUE;
        }
        foreach( $r['findings'] ?? array() as $f )
        {
            $isProblem = !in_array( $f['status'] ?? '', array( 'merge-ok' ), TRUE );
            foreach( array_merge( array( $f['keep'] ?? null ), array_column( (array)( $f['blocked'] ?? array() ), 'copy' ), (array)( $f['notChecked'] ?? array() ),
                (array)( $f['intoParent'] ?? array() ), (array)( $f['copies'] ?? array() ) ) as $o )
                if( ( $n = $nameOf( $o ) ) !== null )
                {
                    if( $isProblem )
                        $problem[$n] = TRUE;
                    else
                        $merged[$n] = TRUE;
                }
        }
        foreach( $r['merged'] ?? array() as $x )
            foreach( array_merge( array( $x['kept'] ?? null ), (array)( $x['removed'] ?? array() ) ) as $o )
                if( ( $n = $nameOf( $o ) ) !== null )
                    $merged[$n] = TRUE;
        $note = '';
        $m = array_diff_key( $merged, $problem );
        if( count( $m ) > 200 )
        {
            $note = count( $m ) . ' merged names in the report - only 200 in the excerpt (names= for more)';
            $m = array_slice( $m, 0, 200, TRUE );
        }
        return array( $problem + $m, array(), $note );
    }

    /** a rule by name (rule-merger) into a selection */
    private static function addRule( ConfigExcerpt $ex, DOMDocument $doc, array $sel, string $name, string $loc ): array
    {
        $x = new DOMXPath( $doc );
        foreach( $ex->locations as $l => $e )
        {
            if( $loc !== '' && $l !== $loc )
                continue;
            foreach( ConfigExcerpt::RULEBASES as $rb )
                foreach( $x->query( $rb . '/*/rules/entry', $e ) as $r )
                    if( $r->getAttribute( 'name' ) === $name )
                    {
                        $sel['entries'][] = array( 'location' => $l, 'store' => $rb, 'element' => $r );
                        $sel['rules'][] = array( 'location' => $l, 'rulebase' => $rb, 'type' => $r->parentNode->parentNode->nodeName, 'name' => $name );
                    }
        }
        return $sel;
    }

    /** without anonymize: every secret (password, phash, keys, PSK, community, ...) replaced - as ConfigAnonymizer does */
    public static function removeSecrets( DOMDocument $doc ): int
    {
        $n = 0;
        $tags = array_flip( ConfigAnonymizer::SECRET_TAGS );
        $x = new DOMXPath( $doc );
        foreach( $x->query( '//*[not(*)]' ) as $e )
        {
            $t = trim( $e->textContent );
            if( $t === '' )
                continue;
            $secret = isset( $tags[$e->nodeName] ) || strpos( $t, '-AQ==' ) === 0 || preg_match( '/^\$[1256y]\$/', $t )
                || ( class_exists( 'ConfigSecrets' ) && defined( 'ConfigSecrets::GCM_PREFIX' ) && strpos( $t, ConfigSecrets::GCM_PREFIX ) === 0 );
            if( $secret )
            {
                $e->nodeValue = '-removed-';
                $n++;
            }
        }
        return $n;
    }

    /** every string of a JSON structure with the pseudonyms of the mapping */
    private function anonJson( ConfigAnonymizer $anon, $data )
    {
        if( is_array( $data ) )
        {
            $out = array();
            foreach( $data as $k => $v )
                $out[is_string( $k ) ? $this->anonText( $anon, $k ) : $k] = $this->anonJson( $anon, $v );
            return $out;
        }
        return is_string( $data ) ? $this->anonText( $anon, $data ) : $data;
    }

    private $pairs = null;

    /** a text with the pseudonyms of the mapping (names, IP addresses, host names, users, serials) - longest first */
    private function anonText( ConfigAnonymizer $anon, string $t ): string
    {
        if( $this->pairs === null )
        {
            $this->pairs = array();
            foreach( $anon->mapping() as $kind => $map )
                foreach( (array)$map as $orig => $pseudo )
                {
                    $orig = (string)$orig;
                    // addresses: the mapping keys them as "<ip>/<prefix>" ("10.1.1.1/" for a host) - in a text the address alone
                    if( $kind === 'ip' && preg_match( '#^([^/]+)/(\d*)$#', $orig, $m ) )
                    {
                        if( $m[2] !== '' )
                            $this->pairs[$orig] = $pseudo . ( strpos( (string)$pseudo, '/' ) === FALSE ? '/' . $m[2] : '' );
                        $orig = $m[1];
                        $pseudo = preg_replace( '#/\d*$#', '', (string)$pseudo );
                    }
                    if( is_string( $pseudo ) && strlen( $orig ) >= 3 && !$anon->isKept( $orig ) )
                        $this->pairs[$orig] = $pseudo;
                }
        }
        return strtr( $t, $this->pairs );
    }

    /** the files of extra= (text, at most 50 MB together; no links, no hidden files) */
    private function extraFiles( string $dir ): array
    {
        $out = array();
        if( !is_dir( $dir ) )
            throw new Exception( "extra '" . $dir . "' is no folder" );
        $total = 0;
        $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
        foreach( $it as $f )
        {
            $rel = substr( $f->getPathname(), strlen( rtrim( $dir, '/' ) ) + 1 );
            if( $f->isLink() || !$f->isFile() || preg_match( '#(^|/)\.#', $rel ) )
                continue;
            $total += $f->getSize();
            if( $total > 52428800 )
                break;
            $out[$rel] = (string)file_get_contents( $f->getPathname() );
        }
        ksort( $out );
        return $out;
    }

    private function environment(): array
    {
        $git = null;
        $head = dirname( __FILE__ ) . '/../../.git/HEAD';
        if( is_file( $head ) )
        {
            $h = trim( (string)file_get_contents( $head ) );
            if( strpos( $h, 'ref: ' ) === 0 && is_file( dirname( $head ) . '/' . substr( $h, 5 ) ) )
                $h = substr( $h, 5 ) . ' ' . trim( (string)file_get_contents( dirname( $head ) . '/' . substr( $h, 5 ) ) );
            $git = $h;
        }
        return array( 'pan-os-php' => PH::frameworkVersion(), 'git' => $git, 'php' => PHP_VERSION, 'os' => php_uname( 's' ) . ' ' . php_uname( 'r' ) . ' ' . php_uname( 'm' ),
            'extensions' => get_loaded_extensions(), 'memory_limit' => ini_get( 'memory_limit' ),
            'container' => is_file( '/.dockerenv' ) || getenv( 'PANOSPHP_VIEWER_CONTAINER' ) ? TRUE : FALSE, 'image' => getenv( 'PANOSPHP_IMAGE' ) ?: null );
    }

    private static function readme( array $m ): string
    {
        return "pan-os-php support file (format " . $m['format'] . ", " . $m['created'] . ")\n\n"
            . "Encrypted for the support of pan-os-php (key " . $m['kid'] . "): only the support can open it.\n\n"
            . "Contains:\n"
            . " - environment.json: versions of pan-os-php, PHP, operating system\n"
            . " - config/: the hierarchy and an excerpt of the configuration for " . count( $m['names'] ) . " object name(s) - every copy in every location,"
            . " the groups that hold them, their members, " . ( $m['rules'] ? "the rules that use them" : "no rules" ) . "; before" . ( isset( $m['excerpt']['after'] ) ? " and after the run" : "" ) . "\n"
            . ( $m['full'] ? " - config/full-*.xml: the whole configuration(s)\n" : "" )
            . " - case/, viewer/: the report of the run, project data, runs and logs of the config viewer (if given)\n\n"
            . "Not contained: passwords, phash, keys and other secrets of the configuration (always replaced), API keys, the key store, licence keys.\n"
            . ( $m['anonymized'] ? "Anonymised: names, addresses and texts are pseudonyms. The mapping stays with you - do not send it.\n" : "Not anonymised.\n" );
    }

    // ------------------------------------------------------------------ read

    private function read()
    {
        foreach( array( 'in', 'key', 'out' ) as $a )
            if( !isset( PH::$args[$a] ) || PH::$args[$a] === '' )
                $this->display_error_usage_exit( '"' . $a . '" is not set' );
        $data = @file_get_contents( PH::$args['in'] );
        if( $data === FALSE || strlen( $data ) > SupportFile::MAX_SIZE )
            throw new Exception( "can not read '" . PH::$args['in'] . "'" );
        $zipBytes = SupportFile::decrypt( $data, (string)@file_get_contents( PH::$args['key'] ) );
        $out = rtrim( PH::$args['out'], '/' );
        if( !is_dir( $out ) && !@mkdir( $out, 0700, TRUE ) )
            throw new Exception( "can not make '" . $out . "'" );
        $tmp = tempnam( sys_get_temp_dir(), 'tsf' );
        file_put_contents( $tmp, $zipBytes );
        $zip = new ZipArchive();
        if( $zip->open( $tmp ) !== TRUE )
        {
            @unlink( $tmp );
            throw new Exception( 'the content is no zip' );
        }
        $files = array();
        for( $i = 0; $i < $zip->numFiles; $i++ )
        {
            $name = (string)$zip->getNameIndex( $i );
            // only plain relative paths (no ../, no absolute path)
            if( $name === '' || $name[0] === '/' || strpos( $name, '..' ) !== FALSE || substr( $name, -1 ) === '/' )
                continue;
            $files[$name] = (string)$zip->getFromIndex( $i );
        }
        $zip->close();
        @unlink( $tmp );
        $manifest = json_decode( $files['manifest.json'] ?? '', TRUE );
        if( !is_array( $manifest ) )
            throw new Exception( 'no manifest.json' );
        $bad = array();
        foreach( $manifest['files'] ?? array() as $p => $info )
            if( !isset( $files[$p] ) || hash( 'sha256', $files[$p] ) !== ( $info['sha256'] ?? '' ) )
                $bad[] = $p;
        foreach( $files as $p => $t )
        {
            $f = $out . '/' . $p;
            if( !is_dir( dirname( $f ) ) )
                @mkdir( dirname( $f ), 0700, TRUE );
            file_put_contents( $f, $t );
        }
        $html = $this->report( $manifest, $files, $bad );
        file_put_contents( $out . '/report.html', $html );
        PH::print_stdout( " - opened: " . count( $files ) . " files (support key " . ( $manifest['kid'] ?? '?' ) . ", made " . ( $manifest['created'] ?? '?' ) . ")"
            . ( $manifest['anonymized'] ?? FALSE ? ", anonymised" : "" ) );
        PH::print_stdout( $bad ? " - CHECK FAILED for: " . implode( ', ', $bad ) : " - every file matches the manifest" );
        PH::print_stdout( " - report: " . $out . "/report.html" );
        if( isset( $files['config/excerpt-before.xml'] ) )
            PH::print_stdout( " - reproduce: pan-os-php type=<merger> in=" . $out . "/config/excerpt-before.xml <settings of the run - see report.html>" );
        PH::$JSON_TMP = array( 'files' => array_keys( $files ), 'bad' => $bad, 'manifest' => $manifest );
        PH::print_stdout( PH::$JSON_TMP, false, 'support-file-read' );
    }

    /** report.html: one page, everything as text (no script) */
    private function report( array $m, array $files, array $bad ): string
    {
        $h = function( $s ) { return htmlspecialchars( (string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8' ); };
        $json = function( $p ) use ( $files ) { return isset( $files[$p] ) ? json_decode( $files[$p], TRUE ) : null; };
        $o = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>support file ' . $h( $m['created'] ?? '' ) . '</title><style>'
            . 'body{font:14px system-ui,sans-serif;margin:24px;max-width:1500px}table{border-collapse:collapse;margin:8px 0}td,th{border:1px solid #ccc;padding:4px 8px;vertical-align:top;text-align:left}'
            . 'pre{background:#f6f6f6;padding:8px;overflow:auto;max-height:420px;white-space:pre-wrap;word-break:break-word;margin:0}.bad{color:#b00}.muted{color:#666}h2{margin-top:28px}.cols{display:grid;grid-template-columns:1fr 1fr;gap:12px}</style></head><body>';
        $o .= '<h1>pan-os-php support file</h1><p>made ' . $h( $m['created'] ?? '' ) . ', support key ' . $h( $m['kid'] ?? '' ) . ', ' . ( $m['anonymized'] ?? FALSE ? 'anonymised' : 'not anonymised' )
            . ( $m['full'] ?? FALSE ? ', with the whole configuration' : '' ) . '</p>';
        $o .= $bad ? '<p class="bad">Check failed (changed or missing): ' . $h( implode( ', ', $bad ) ) . '</p>' : '<p>Every file matches the manifest.</p>';
        if( ( $m['note'] ?? '' ) !== '' )
            $o .= '<h2>Problem (customer)</h2><pre>' . $h( $m['note'] ) . '</pre>';
        foreach( (array)( $m['notes'] ?? array() ) as $n )
            $o .= '<p class="muted">note: ' . $h( $n ) . '</p>';
        $env = $json( 'environment.json' );
        if( is_array( $env ) )
            $o .= '<h2>Environment</h2><table>' . implode( '', array_map( function( $k ) use ( $env, $h ) {
                    return '<tr><th>' . $h( $k ) . '</th><td>' . $h( is_array( $env[$k] ) ? implode( ', ', $env[$k] ) : var_export( $env[$k], TRUE ) ) . '</td></tr>'; }, array_keys( $env ) ) ) . '</table>';
        $run = $json( 'viewer/run.json' );
        if( is_array( $run ) )
        {
            $o .= '<h2>Run</h2><table>';
            foreach( $run as $k => $v )
                $o .= '<tr><th>' . $h( $k ) . '</th><td>' . $h( is_array( $v ) ? implode( ' ', array_map( 'strval', $v ) ) : $v ) . '</td></tr>';
            $o .= '</table>';
            if( is_array( $run['args'] ?? null ) && isset( $files['config/excerpt-before.xml'] ) )
                $o .= '<p>Reproduce:</p><pre>pan-os-php type=' . $h( $run['type'] ?? '?' ) . ' in=config/excerpt-before.xml out=/tmp/repro.xml '
                    . $h( implode( ' ', array_filter( array_map( 'strval', $run['args'] ), function( $a ) { return !preg_match( '/^(in|out|exportjson|exportcsv)=/', $a ); } ) ) ) . '</pre>';
        }
        $hi = $json( 'config/hierarchy.json' );
        if( is_array( $hi ) && isset( $hi['deviceGroups'] ) )
        {
            $children = array();
            foreach( $hi['deviceGroups'] as $dg => $i )
                $children[$i['parent']][] = $dg;
            $tree = function( $p, $d ) use ( &$tree, $children, $hi, $h ) {
                $s = '';
                foreach( $children[$p] ?? array() as $c )
                    $s .= str_repeat( '    ', $d ) . '└ ' . $h( $c ) . ' <span class="muted">(' . (int)$hi['deviceGroups'][$c]['firewalls'] . ' firewalls)</span>' . "\n" . $tree( $c, $d + 1 );
                return $s;
            };
            $o .= '<h2>Hierarchy</h2><pre>shared' . "\n" . $tree( 'shared', 1 ) . '</pre>';
        }
        $objs = $json( 'config/objects.json' );
        if( is_array( $objs ) && $objs )
        {
            $o .= '<h2>Objects (' . count( $objs ) . ')</h2>';
            foreach( $objs as $name => $w )
            {
                $o .= '<h3>' . $h( $name ) . '</h3><div class="cols">';
                foreach( array( 'before', 'after' ) as $which )
                {
                    $o .= '<div><strong>' . $which . '</strong>';
                    foreach( (array)( $w[$which] ?? array() ) as $c )
                        $o .= '<p class="muted">' . $h( $c['location'] . ' / ' . $c['store'] ) . '</p><pre>' . $h( $c['xml'] ) . '</pre>';
                    if( empty( $w[$which] ) )
                        $o .= '<p class="muted">' . ( isset( $files['config/excerpt-' . $which . '.xml'] ) ? 'no copy' : '-' ) . '</p>';
                    $o .= '</div>';
                }
                $o .= '</div>';
            }
        }
        $rep = $json( 'case/report.json' );
        if( is_array( $rep ) )
            $o .= '<h2>Report of the run</h2><pre>' . $h( substr( json_encode( $rep, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ), 0, 200000 ) ) . '</pre>';
        $o .= '<h2>Files</h2><table><tr><th>file</th><th>size</th></tr>';
        foreach( $m['files'] ?? array() as $p => $i )
            $o .= '<tr><td>' . $h( $p ) . '</td><td>' . (int)( $i['size'] ?? 0 ) . '</td></tr>';
        $o .= '</table></body></html>';
        return $o;
    }
}
