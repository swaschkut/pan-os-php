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

/**
 * type=master-key: master-key encrypted values of a configuration (utils/README_master-key.md).
 * Step 1: display - XPath of every encrypted value and which master key decrypts it. Values are never printed.
 */
class MASTER_KEY__ extends UTIL
{
    const ACTIONS = array( 'display', 'exporttohtml' );
    const KEY_FILTER = array( 'all', ConfigSecrets::KEY_DEFAULT, ConfigSecrets::KEY_GIVEN, ConfigSecrets::KEY_UNKNOWN );

    public function utilStart()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml or in=api://192.168.1.1', 'argDesc' => '[filename]|[api://IP]');
        $this->supportedArguments['actions'] = array('niceName' => 'actions', 'shortHelp' => 'display (default) | exportToHtml:FILE', 'argDesc' => 'action[:args]');
        $this->supportedArguments['master-key'] = array('niceName' => 'master-key', 'shortHelp' => 'custom master key to test the values that the default master key does not decrypt (prefer master-key-file: the command line is visible in the shell history / process list)', 'argDesc' => '[16 characters]');
        $this->supportedArguments['master-key-file'] = array('niceName' => 'master-key-file', 'shortHelp' => 'file with the custom master key (first line)', 'argDesc' => '[filename]');
        $this->supportedArguments['key'] = array('niceName' => 'key', 'shortHelp' => 'show only the values of one key state: all (default) | default | given | unknown', 'argDesc' => 'all|default|given|unknown');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['shadow-json'] = array('niceName' => 'shadow-json', 'shortHelp' => 'output as JSON');
        $this->supportedArguments['shadow-nojson'] = array('niceName' => 'shadow-nojson', 'shortHelp' => 'output as text');

        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " type=master-key in=config.xml [master-key-file=key.txt] [key=unknown] [actions=display|exportToHtml:FILE]\n"
            . "php " . basename(__FILE__) . " help          : more help messages\n";

        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();
        $this->help( PH::$args );

        // the XML as stored is enough (no object model): fast, and nothing is added to the DOM
        $this->init_arguments();
        $this->main();
    }

    /** the custom master key of master-key-file= / master-key=, or null */
    public static function masterKeyArgument()
    {
        $key = null;
        if( isset(PH::$args['master-key-file']) )
        {
            $f = PH::$args['master-key-file'];
            if( !is_file($f) || !is_readable($f) )
                derr( "master-key-file '" . $f . "' not found / not readable", null, FALSE );
            $lines = preg_split( '/\r?\n/', (string)file_get_contents($f) );
            $key = $lines[0];
        }
        elseif( isset(PH::$args['master-key']) )
            $key = (string)PH::$args['master-key'];
        if( $key === null )
            return null;
        if( $key === '' )
            derr( "the master key is empty", null, FALSE );
        if( strlen($key) != 16 )
            mwarning( "a PAN-OS master key has 16 characters - the given key has " . strlen($key), null, FALSE );
        return $key;
    }

    public function main()
    {
        $actions = array();
        // actions separated by '/', a literal '/' (file path) is written as '//' (as for all pan-os-php actions)
        $raw = str_replace( '//', "\0", isset(PH::$args['actions']) ? PH::$args['actions'] : 'display' );
        foreach( explode( '/', $raw ) as $a )
        {
            if( $a === '' )
                continue;
            $a = str_replace( "\0", '/', $a );
            $p = strpos( $a, ':' );
            $name = strtolower( $p === FALSE ? $a : substr($a, 0, $p) );
            $arg = $p === FALSE ? '' : substr( $a, $p + 1 );
            if( !in_array($name, self::ACTIONS, TRUE) )
                derr( "action '" . $name . "' not supported - supported: display, exportToHtml:FILE", null, FALSE );
            if( $name == 'exporttohtml' && $arg === '' )
                derr( "actions=exportToHtml:FILE needs a file name", null, FALSE );
            $actions[] = array( $name, $arg );
        }

        $filter = isset(PH::$args['key']) ? strtolower(PH::$args['key']) : 'all';
        if( !in_array($filter, self::KEY_FILTER, TRUE) )
            derr( "key=" . implode('|', self::KEY_FILTER), null, FALSE );

        $masterKey = self::masterKeyArgument();
        if( $filter == ConfigSecrets::KEY_GIVEN && $masterKey === null )
            derr( "key=given needs master-key-file= / master-key=", null, FALSE );

        $all = ConfigSecrets::scan( $this->xmlDoc, $masterKey );
        $summary = ConfigSecrets::summary( $all );
        $summary['hashed_values_not_master_key_encrypted'] = ConfigSecrets::countHashes( $this->xmlDoc );
        $summary['custom_master_key_given'] = $masterKey !== null;
        $items = $filter == 'all' ? $all : array_values( array_filter( $all, function( $i ) use ( $filter ) { return $i['key'] === $filter; } ) );

        foreach( $actions as $a )
        {
            if( $a[0] == 'display' )
                $this->display( $items, $summary, $filter );
            else
                $this->exportToHtml( $a[1], $items );
        }

        // JSON (shadow-json): one object per value under 'encrypted_values', the summary under 'summary'
        foreach( $items as $i )
            PH::print_stdout( $i, false, 'encrypted_values' );
        PH::print_stdout( $summary, false, 'summary' );
    }

    private static function formatText( $i )
    {
        if( $i['format'] == ConfigSecrets::FORMAT_CBC )
            return 'AES-256-CBC (version 1)';
        if( $i['format'] == ConfigSecrets::FORMAT_MALFORMED )
            return 'version 1, malformed';
        return 'version ' . $i['version'] . ' - not supported';
    }

    private static function keyText( $i )
    {
        if( $i['key'] == ConfigSecrets::KEY_DEFAULT )
            return 'default master key';
        if( $i['key'] == ConfigSecrets::KEY_GIVEN )
            return 'given master key';
        return $i['format'] == ConfigSecrets::FORMAT_CBC ? 'UNKNOWN (other master key)' : 'not checked';
    }

    private function display( array $items, array $summary, $filter )
    {
        PH::print_stdout();
        PH::print_stdout( "master-key encrypted values" . ( $filter != 'all' ? " (key=" . $filter . ")" : '' ) . " - values are never displayed" );

        $byLocation = array();
        foreach( $items as $i )
            $byLocation[$i['location']][] = $i;
        foreach( $byLocation as $location => $list )
        {
            PH::print_stdout();
            PH::print_stdout( " * " . $location . " (" . count($list) . ")" );
            foreach( $list as $i )
            {
                PH::print_stdout( "   - " . $i['xpath'] );
                PH::print_stdout( "       " . self::formatText($i) . " | key: " . self::keyText($i) . " | " . $i['length'] . " characters" );
            }
        }

        PH::print_stdout();
        PH::print_stdout( "summary: " . $summary['total'] . " encrypted value(s) in the configuration" . ( $filter != 'all' ? ", " . count($items) . " shown" : '' ) );
        $lines = array(
            array( isset($summary['by_key'][ConfigSecrets::KEY_DEFAULT]) ? $summary['by_key'][ConfigSecrets::KEY_DEFAULT] : 0, 'decrypt with the default master key' ),
            array( isset($summary['by_key'][ConfigSecrets::KEY_GIVEN]) ? $summary['by_key'][ConfigSecrets::KEY_GIVEN] : 0, 'decrypt with the given master key' ),
            array( $summary['other_master_key'], 'do NOT decrypt with the default' . ( $summary['custom_master_key_given'] ? ' or the given master key' : ' master key -> custom master key (test it with master-key-file=)' ) ),
            array( isset($summary['by_format'][ConfigSecrets::FORMAT_UNKNOWN]) ? $summary['by_format'][ConfigSecrets::FORMAT_UNKNOWN] : 0, 'in a format version that is not supported (e.g. AES-256-GCM / encryption level 2) - not checked' ),
            array( isset($summary['by_format'][ConfigSecrets::FORMAT_MALFORMED]) ? $summary['by_format'][ConfigSecrets::FORMAT_MALFORMED] : 0, 'malformed (prefix of version 1, but no valid value) - not checked' ),
        );
        foreach( $lines as $l )
            if( $l[0] )
                PH::print_stdout( "   " . str_pad( $l[0], 6, ' ', STR_PAD_LEFT ) . " " . $l[1] );
        if( $summary['hashed_values_not_master_key_encrypted'] )
            PH::print_stdout( "   " . str_pad( $summary['hashed_values_not_master_key_encrypted'], 6, ' ', STR_PAD_LEFT ) . " hashed value(s) (phash) - hashes, independent of the master key" );
        if( count($summary['by_field']) )
        {
            PH::print_stdout();
            PH::print_stdout( "by field:" );
            foreach( $summary['by_field'] as $f => $n )
                PH::print_stdout( "   " . str_pad( $n, 6, ' ', STR_PAD_LEFT ) . " " . $f );
        }
        PH::print_stdout();
    }

    private function exportToHtml( $filename, array $items )
    {
        $esc = function( $t ) { return htmlspecialchars( (string)$t, ENT_QUOTES ); };
        $headers = '<th>location</th><th>field</th><th>format</th><th>key</th><th>length</th><th>xpath</th>';
        $lines = '';
        foreach( $items as $i )
            $lines .= '<tr><td>' . $esc($i['location']) . '</td><td>' . $esc($i['field']) . '</td><td>' . $esc(self::formatText($i)) . '</td><td>'
                . $esc(self::keyText($i)) . '</td><td>' . $esc($i['length']) . '</td><td>' . $esc($i['xpath']) . "</td></tr>\n";
        require_once dirname(__FILE__) . '/ExportToHtmlHelper.php';
        ExportToHtmlHelper::writeHtmlExport( $filename, $headers, $lines );
        PH::print_stdout( " * " . count($items) . " value(s) exported to '" . $filename . "'" );
    }
}
