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
 * pan-os-php type=config-split - a configuration as one file per object, and back (ConfigObjectSplit):
 *
 *   pan-os-php type=config-split in=<config.xml> out=<folder>              split (the folder must be new or empty)
 *   pan-os-php type=config-split mode=join in=<folder> out=<config.xml>    join
 *   pan-os-php type=config-split mode=check in=<config.xml>                split + join = the same configuration?
 */
class CONFIGSPLIT__
{
    public $result = array();

    function __construct()
    {
        $args = array_change_key_case( PH::$args, CASE_LOWER );
        $mode = isset($args['mode']) ? strtolower( (string)$args['mode'] ) : 'split';
        if( isset($args['help']) || !in_array( $mode, array( 'split', 'join', 'check' ), TRUE ) )
        {
            PH::print_stdout( "pan-os-php type=config-split in=<config.xml> out=<folder>              one file per object (the folder must be new or empty)" );
            PH::print_stdout( "pan-os-php type=config-split mode=join in=<folder> out=<config.xml>    the configuration again" );
            PH::print_stdout( "pan-os-php type=config-split mode=check in=<config.xml>                split + join give the same configuration?" );
            return;
        }
        $in = isset($args['in']) && is_string($args['in']) ? $args['in'] : '';
        $out = isset($args['out']) && is_string($args['out']) ? $args['out'] : '';
        if( $in === '' || ( $mode !== 'check' && $out === '' ) )
            derr( "in= and out= are needed (help: pan-os-php type=config-split help)", null, FALSE );

        if( $mode === 'join' )
        {
            if( !is_dir( $in ) )
                derr( "in= must be a folder made by type=config-split: " . $in, null, FALSE );
            $files = array();
            $base = rtrim( $in, '/' );
            $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ) );
            foreach( $it as $f )
                if( $f->isFile() )
                {
                    $rel = substr( $f->getPathname(), strlen( $base ) + 1 );
                    if( strpos( $rel, '.git/' ) === 0 )
                        continue;
                    $files[$rel] = file_get_contents( $f->getPathname() );
                }
            $doc = ConfigObjectSplit::join( $files );
            file_put_contents( $out, ConfigObjectSplit::canonical( $doc ) );
            $this->result = array( 'files' => count( $files ) );
            PH::print_stdout( " - " . count( $files ) . " files joined into " . $out );
            return;
        }

        $doc = $this->load( $in );
        $t = microtime( TRUE );
        $files = ConfigObjectSplit::split( $doc );
        $objects = 0;
        $stores = array();
        foreach( $files as $p => $x )
            if( $p !== ConfigObjectSplit::REST && substr( $p, -4 ) === '.xml' )
            {
                $objects++;
                $stores[dirname( $p )] = TRUE;
            }
        $this->result = array( 'objects' => $objects, 'stores' => count( $stores ), 'rest_bytes' => strlen( $files[ConfigObjectSplit::REST] ),
            'seconds' => round( microtime( TRUE ) - $t, 3 ) );

        if( $mode === 'check' )
        {
            $same = ConfigObjectSplit::canonical( $doc ) === ConfigObjectSplit::canonical( ConfigObjectSplit::join( $files ) );
            $this->result['same'] = $same;
            PH::print_stdout( " - " . $objects . " objects in " . count( $stores ) . " stores; split + join: " . ( $same ? "the same configuration" : "DIFFERENT" ) );
            if( !$same )
                derr( "split + join do not give the same configuration", null, FALSE );
            return;
        }

        if( file_exists( $out ) && ( !is_dir( $out ) || count( scandir( $out ) ) > 2 ) )
            derr( "out= must be a new or empty folder (an old split would bring back objects deleted since): " . $out, null, FALSE );
        foreach( $files as $p => $x )
        {
            $file = rtrim( $out, '/' ) . '/' . $p;
            if( !is_dir( dirname( $file ) ) )
                mkdir( dirname( $file ), 0777, TRUE );
            file_put_contents( $file, $x );
        }
        PH::print_stdout( " - " . $objects . " objects in " . count( $stores ) . " stores written to " . $out . " (+ " . ConfigObjectSplit::REST . ")" );
    }

    function endOfScript()
    {
    }

    private function load( string $file ): DOMDocument
    {
        if( !is_file( $file ) )
            derr( "in= must be a configuration file: " . $file, null, FALSE );
        $doc = new DOMDocument();
        $prev = libxml_use_internal_errors( TRUE );
        $ok = $doc->load( $file, LIBXML_PARSEHUGE );
        libxml_clear_errors();
        libxml_use_internal_errors( $prev );
        if( !$ok || $doc->documentElement === null || $doc->documentElement->nodeName !== 'config' )
            derr( "in= is no PAN-OS configuration (<config>): " . $file, null, FALSE );
        return $doc;
    }
}
