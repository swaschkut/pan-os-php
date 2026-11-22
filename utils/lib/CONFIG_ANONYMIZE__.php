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

require_once dirname(__FILE__) . '/../common/ConfigSecrets.php';
require_once dirname(__FILE__) . '/../common/ConfigAnonymizer.php';

/**
 * pan-os-php type=config-anonymize: anonymise Panorama / firewall / SCM configurations, see ConfigAnonymizer and
 * todo/config-anonymize.md.
 *
 *   type=config-anonymize in=customer.xml out=anon.xml [salt=...] [mapping=map.json] [ip=keep-private]
 *   type=config-anonymize in=panorama.xml,fw1.xml,fw2.xml out=<folder>        (one mapping for all files)
 *   type=config-anonymize in=<scm-export folder> out=<folder>                  (SCM export JSON files)
 */
class CONFIG_ANONYMIZE__ extends UTIL
{
    public function utilStart()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input: XML file(s) separated by "," (Panorama / firewall / SCM XML) or an SCM export folder (scm-export://<folder> or <folder>)', 'argDesc' => '[file.xml[,file2.xml]]|[folder]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file (one XML input) or folder (several inputs / SCM export)', 'argDesc' => '[file|folder]');
        $this->supportedArguments['salt'] = array('niceName' => 'salt', 'shortHelp' => 'secret salt: the same salt gives the same pseudonyms (Panorama + firewalls, several runs). Default: random (nothing can be linked). Prefer salt-file', 'argDesc' => '[text]');
        $this->supportedArguments['salt-file'] = array('niceName' => 'salt-file', 'shortHelp' => 'file with the salt (first line)', 'argDesc' => '[filename]');
        $this->supportedArguments['mapping'] = array('niceName' => 'mapping', 'shortHelp' => 'write the mapping original -> pseudonym as JSON - SENSITIVE: keep it with the customer data, never share it with the anonymised config', 'argDesc' => '[file.json]');
        $this->supportedArguments['ip'] = array('niceName' => 'ip', 'shortHelp' => 'remap (default): all addresses mapped prefix preserving (private stays private) | keep-private: RFC1918 / RFC6598 / ULA addresses unchanged', 'argDesc' => 'remap|keep-private');
        $this->supportedArguments['allow-leaks'] = array('niceName' => 'allow-leaks', 'shortHelp' => 'write the output even when the leak scan finds original values in it (default: error, nothing written)');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['shadow-json'] = array('niceName' => 'shadow-json', 'shortHelp' => 'output as JSON');
        $this->supportedArguments['shadow-nojson'] = array('niceName' => 'shadow-nojson', 'shortHelp' => 'output as text');

        $this->usageMsg = PH::boldText("USAGE: ") . "pan-os-php type=config-anonymize in=customer.xml out=anon.xml [salt-file=salt.txt] [mapping=map.json] [ip=keep-private]\n"
            . "       pan-os-php type=config-anonymize in=panorama.xml,fw1.xml out=<folder> salt-file=salt.txt\n"
            . "       pan-os-php type=config-anonymize in=scm-export://<folder> out=<folder>\n";

        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();
        $this->help( PH::$args );
        $this->main();
    }

    public function main()
    {
        if( !isset(PH::$args['in']) || PH::$args['in'] === '' )
            $this->display_error_usage_exit( '"in" is not set' );
        if( !isset(PH::$args['out']) || PH::$args['out'] === '' )
            $this->display_error_usage_exit( '"out" is not set' );

        $salt = null;
        if( isset(PH::$args['salt-file']) )
        {
            $f = PH::$args['salt-file'];
            if( !is_file($f) || !is_readable($f) )
                derr( "salt-file '" . $f . "' not found / not readable", null, FALSE );
            $salt = rtrim( (string)strtok( (string)file_get_contents($f), "\n" ), "\r" );
        }
        elseif( isset(PH::$args['salt']) )
            $salt = (string)PH::$args['salt'];
        if( $salt === null )
            PH::print_stdout( " - no salt given: random salt, the pseudonyms can not be linked to other runs" );

        $ipMode = isset(PH::$args['ip']) ? strtolower(PH::$args['ip']) : 'remap';
        if( !in_array( $ipMode, array( 'remap', 'keep-private' ), TRUE ) )
            derr( "ip=remap|keep-private", null, FALSE );

        $anon = new ConfigAnonymizer( $salt, array( 'ip' => $ipMode ) );

        $in = PH::$args['in'];
        $out = PH::$args['out'];
        if( strpos( $in, 'scm-export://' ) === 0 )
            $in = substr( $in, strlen('scm-export://') );
        if( strpos( $in, 'api://' ) === 0 || strpos( $in, 'scm-api://' ) === 0 )
            derr( "config-anonymize works on files only - download the configuration first (in=file.xml / an SCM export folder)", null, FALSE );

        if( is_dir( $in ) )
            $results = $this->jsonFolder( $anon, rtrim( $in, '/' ), rtrim( $out, '/' ) );
        else
        {
            $files = array_filter( explode( ',', $in ), 'strlen' );
            foreach( $files as $f )
                if( !is_file($f) )
                    derr( "input file '" . $f . "' not found", null, FALSE );
            if( count($files) > 1 && !is_dir($out) && !@mkdir( $out, 0700, TRUE ) )
                derr( "out= must be a folder for several input files", null, FALSE );
            $results = $this->xmlFiles( $anon, $files, $out );
        }

        // leak scan over all outputs
        $leaks = array();
        foreach( $results as $r )
            foreach( $anon->leakScan( $r['text'] ) as $l )
                $leaks[$l][] = basename( $r['out'] );

        PH::print_stdout();
        PH::print_stdout( " - replaced: " . json_encode( $anon->stats ) );
        PH::print_stdout( $anon->stats, false, 'replaced' );

        if( count($leaks) )
        {
            PH::print_stdout( " - LEAK SCAN: " . count($leaks) . " original value(s) still found in the output:" );
            foreach( $leaks as $v => $files )
                PH::print_stdout( "     '" . $v . "' in " . implode( ', ', array_unique($files) ) );
            if( !isset(PH::$args['allow-leaks']) )
                derr( "leak scan failed - nothing written (allow-leaks writes the output anyway)", null, FALSE );
        }
        else
            PH::print_stdout( " - leak scan: no original value found in the output" );

        foreach( $results as $r )
        {
            if( !is_dir( dirname( $r['out'] ) ) )
                @mkdir( dirname( $r['out'] ), 0700, TRUE );
            file_put_contents( $r['out'], $r['text'] );
            PH::print_stdout( " - written: " . $r['out'] );
        }

        if( isset(PH::$args['mapping']) )
        {
            file_put_contents( PH::$args['mapping'], json_encode( $anon->mapping(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) );
            @chmod( PH::$args['mapping'], 0600 );
            PH::print_stdout( " - mapping written to " . PH::$args['mapping'] . " - SENSITIVE: it de-anonymises the output, never share it" );
        }
    }

    /** @return array list of array( out, text ) */
    private function xmlFiles( ConfigAnonymizer $anon, array $files, $out )
    {
        $docs = array();
        foreach( $files as $f )
        {
            $doc = new DOMDocument();
            $doc->preserveWhiteSpace = FALSE;
            if( !@$doc->load( $f, LIBXML_PARSEHUGE ) )
                derr( "input file '" . $f . "' is no valid XML", null, FALSE );
            $docs[$f] = $doc;
        }
        // all names of all files first: one pseudonym per name across Panorama and firewalls
        foreach( $docs as $doc )
            $anon->collectNamesXml( $doc );

        $results = array();
        foreach( $docs as $f => $doc )
        {
            $before = ConfigAnonymizer::structure( $doc );
            $anon->anonymizeXml( $doc );
            $after = ConfigAnonymizer::structure( $doc );
            if( $before !== $after )
                mwarning( "structure of '" . $f . "' changed - please report", null, FALSE );
            else
                PH::print_stdout( " - " . basename($f) . ": structure unchanged (" . array_sum($before) . " elements)" );
            $doc->formatOutput = TRUE;
            $text = $doc->saveXML( $doc->documentElement );
            $target = count($docs) > 1 ? $out . '/' . $this->outName( $anon, basename($f) ) : $out;
            $results[] = array( 'out' => $target, 'text' => $text . "\n" );
        }
        return $results;
    }

    /** output file name: a customer name in the file name is replaced */
    private function outName( ConfigAnonymizer $anon, $name )
    {
        $ext = '';
        if( preg_match( '/^(.*)(\.[a-z0-9]+)$/i', $name, $m ) )
            list( , $name, $ext ) = $m;
        return ( $anon->names[$name] ?? ( $anon->isKept($name) ? $name : 'config-' . substr( md5( $name . microtime() ), 0, 6 ) ) ) . $ext;
    }

    /** SCM export folder: every *.json file; other files are not copied (reports may contain customer data) */
    private function jsonFolder( ConfigAnonymizer $anon, $in, $out )
    {
        $files = array();
        $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $in, FilesystemIterator::SKIP_DOTS ) );
        $skipped = 0;
        foreach( $it as $f )
        {
            if( strtolower( $f->getExtension() ) === 'json' )
                $files[] = $f->getPathname();
            else
                $skipped++;
        }
        sort( $files );
        $data = array();
        foreach( $files as $f )
        {
            $j = json_decode( (string)file_get_contents($f), TRUE );
            if( $j === null && json_last_error() !== JSON_ERROR_NONE )
            {
                mwarning( "'" . $f . "' is no valid JSON - skipped", null, FALSE );
                continue;
            }
            $data[$f] = $j;
            $anon->collectNamesJson( $j );
        }
        $anon->finishNames();

        $results = array();
        foreach( $data as $f => $j )
        {
            $rel = substr( $f, strlen($in) + 1 );
            $parts = explode( '/', $rel );
            foreach( $parts as $i => $p )
            {
                $base = preg_replace( '/\.json$/i', '', $p );
                $mapped = $anon->names[$base] ?? null;
                if( $mapped === null && !$anon->isKept($base) && !preg_match( '/^[0-9a-z_.-]+$/', $base ) )
                    $mapped = 'c-' . substr( hash( 'sha256', $base ), 0, 8 );
                if( $mapped !== null )
                    $parts[$i] = $mapped . ( $base !== $p ? '.json' : '' );
            }
            $text = json_encode( $anon->anonymizeJson( $j ), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
            $results[] = array( 'out' => $out . '/' . implode( '/', $parts ), 'text' => $text . "\n" );
        }
        PH::print_stdout( " - SCM export: " . count($results) . " JSON file(s)" . ( $skipped ? ", " . $skipped . " other file(s) not copied" : '' ) );
        return $results;
    }
}
