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
require_once dirname(__FILE__) . '/../common/ConfigSecretsScrub.php';

/**
 * type=master-key: master-key encrypted values of a configuration (utils/README_master-key.md).
 * display - XPath of every encrypted value and which master key decrypts it.
 * rekey - re-encrypt all values: master key of the input (master-key-file=) -> target key (new-master-key-file=,
 * default: the default master key), offline to out=. Values are never printed.
 */
class MASTER_KEY__ extends UTIL
{
    const ACTIONS = array( 'display', 'exporttohtml', 'rekey', 'scrub' );
    const KEY_FILTER = array( 'all', ConfigSecrets::KEY_DEFAULT, ConfigSecrets::KEY_GIVEN, ConfigSecrets::KEY_UNKNOWN );

    public function utilStart()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml or in=api://192.168.1.1', 'argDesc' => '[filename]|[api://IP]');
        $this->supportedArguments['out'] = array('niceName' => 'out', 'shortHelp' => 'output file of actions=rekey', 'argDesc' => '[filename]');
        $this->supportedArguments['actions'] = array('niceName' => 'actions', 'shortHelp' => 'display (default) | exportToHtml:FILE | rekey (re-encrypt all values with the target master key, needs out=)', 'argDesc' => 'action[:args]');
        $this->supportedArguments['new-master-key'] = array('niceName' => 'new-master-key', 'shortHelp' => 'rekey: target master key (default: the PAN-OS default master key); prefer new-master-key-file', 'argDesc' => '[16 characters]');
        $this->supportedArguments['new-master-key-file'] = array('niceName' => 'new-master-key-file', 'shortHelp' => 'rekey: file with the target master key (first line)', 'argDesc' => '[filename]');
        $this->supportedArguments['placeholder'] = array('niceName' => 'placeholder', 'shortHelp' => 'scrub: clear text that replaces every secret (default: ' . ConfigSecretsScrub::DEFAULT_PLACEHOLDER . ')', 'argDesc' => '[text]');
        $this->supportedArguments['allow-partial'] = array('niceName' => 'allow-partial', 'shortHelp' => 'rekey: write out= although some values could not be re-encrypted (they stay unchanged)');
        $this->supportedArguments['master-key'] = array('niceName' => 'master-key', 'shortHelp' => 'custom master key to test the values that the default master key does not decrypt (prefer master-key-file: the command line is visible in the shell history / process list)', 'argDesc' => '[16 characters]');
        $this->supportedArguments['master-key-file'] = array('niceName' => 'master-key-file', 'shortHelp' => 'file with the custom master key (first line)', 'argDesc' => '[filename]');
        $this->supportedArguments['cleartext'] = array('niceName' => 'cleartext', 'shortHelp' => 'display / exportToHtml: show the decrypted value of every secret that the default (public) master key - or the given master key - can read. For a lab; a value encrypted with the public default master key is not a secret');
        $this->supportedArguments['hashes'] = array('niceName' => 'hashes', 'shortHelp' => 'display / exportToHtml: also list the password hashes (phash) with XPath and algorithm - one-way hashes, independent of the master key');
        $this->supportedArguments['key'] = array('niceName' => 'key', 'shortHelp' => 'show only the values of one key state: all (default) | default | given | unknown', 'argDesc' => 'all|default|given|unknown');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
        $this->supportedArguments['shadow-json'] = array('niceName' => 'shadow-json', 'shortHelp' => 'output as JSON');
        $this->supportedArguments['shadow-nojson'] = array('niceName' => 'shadow-nojson', 'shortHelp' => 'output as text');

        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " type=master-key in=config.xml [master-key-file=key.txt] [key=unknown] [actions=display|exportToHtml:FILE]\n"
            . "       pan-os-php type=master-key in=config.xml out=new.xml master-key-file=key.txt [new-master-key-file=new.txt] actions=rekey\n"
            . "       pan-os-php type=master-key in=customer.xml out=lab.xml actions=scrub      (lab copy: secrets replaced by placeholders)\n"
            . "php " . basename(__FILE__) . " help          : more help messages\n";

        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();
        $this->help( PH::$args );

        // the XML as stored is enough (no object model): fast, and nothing is added to the DOM
        $this->init_arguments();
        $this->main();
    }

    /** the master key of <prefix>master-key-file= / <prefix>master-key= (prefix '' = key of the input, 'new-' = target key), or null */
    public static function masterKeyArgument( $prefix = '' )
    {
        $key = null;
        $name = $prefix . 'master-key';
        if( isset(PH::$args[$name . '-file']) )
        {
            $f = PH::$args[$name . '-file'];
            if( !is_file($f) || !is_readable($f) )
                derr( $name . "-file '" . $f . "' not found / not readable", null, FALSE );
            $lines = preg_split( '/\r?\n/', (string)file_get_contents($f) );
            $key = $lines[0];
        }
        elseif( isset(PH::$args[$name]) )
            $key = (string)PH::$args[$name];
        if( $key === null )
            return null;
        if( $key === '' )
            derr( "the master key (" . $name . ") is empty", null, FALSE );
        if( strlen($key) != 16 )
            mwarning( "a PAN-OS master key has 16 characters - the given key (" . $name . ") has " . strlen($key), null, FALSE );
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

        $names = array_map( function( $a ) { return $a[0]; }, $actions );
        foreach( array( 'rekey', 'scrub' ) as $write )
            if( in_array( $write, $names, TRUE ) )
            {
                if( count($actions) != 1 )
                    derr( "actions=" . $write . " can not be combined with other actions (run display on the output afterwards)", null, FALSE );
                if( isset(PH::$args['hashes']) )
                    derr( "hashes is an argument of display / exportToHtml", null, FALSE );
                if( isset(PH::$args['cleartext']) )
                    derr( "cleartext is an argument of display / exportToHtml", null, FALSE );
                if( $write == 'rekey' && isset(PH::$args['placeholder']) )
                    derr( "placeholder is an argument of actions=scrub", null, FALSE );
                if( $write == 'scrub' && $masterKey !== null )
                    derr( "actions=scrub does not need the master key of the input (nothing is decrypted) - remove master-key / master-key-file", null, FALSE );
                if( $write == 'rekey' )
                    $this->rekey( $masterKey );
                else
                    $this->scrub();
                return;
            }
        foreach( array( 'new-master-key', 'new-master-key-file', 'allow-partial', 'placeholder' ) as $arg )
            if( isset(PH::$args[$arg]) )
                derr( $arg . " is an argument of actions=rekey / actions=scrub", null, FALSE );

        $cleartext = isset(PH::$args['cleartext']);
        $all = ConfigSecrets::scan( $this->xmlDoc, $masterKey, $cleartext );
        $summary = ConfigSecrets::summary( $all );
        $summary['hashed_values_not_master_key_encrypted'] = ConfigSecrets::countHashes( $this->xmlDoc );
        $summary['custom_master_key_given'] = $masterKey !== null;
        $items = $filter == 'all' ? $all : array_values( array_filter( $all, function( $i ) use ( $filter ) { return $i['key'] === $filter; } ) );

        $hashes = isset(PH::$args['hashes']) ? ConfigSecrets::scanHashes( $this->xmlDoc ) : null;
        if( $hashes !== null )
        {
            $summary['hash_algorithms'] = array();
            foreach( $hashes as $h )
                $summary['hash_algorithms'][$h['algorithm']] = isset($summary['hash_algorithms'][$h['algorithm']]) ? $summary['hash_algorithms'][$h['algorithm']] + 1 : 1;
        }

        foreach( $actions as $a )
        {
            if( $a[0] == 'display' )
            {
                $this->display( $items, $summary, $filter, $cleartext );
                if( $hashes !== null )
                    $this->displayHashes( $hashes );
            }
            else
                $this->exportToHtml( $a[1], $items, $hashes, $cleartext );
        }
        if( $hashes !== null )
            foreach( $hashes as $h )
                PH::print_stdout( $h, false, 'hashed_values' );

        // JSON (shadow-json): one object per value under 'encrypted_values', the summary under 'summary'
        foreach( $items as $i )
            PH::print_stdout( $i, false, 'encrypted_values' );
        PH::print_stdout( $summary, false, 'summary' );
    }

    /** actions=rekey: all values -> target master key, written to out= */
    private function rekey( $oldKey )
    {
        $newKey = self::masterKeyArgument( 'new-' );
        // the dispatcher sets out=/dev/null when out= is not given
        $out = isset(PH::$args['out']) ? PH::$args['out'] : '';
        if( $out === '' || $out === '/dev/null' )
            derr( "actions=rekey needs out= (the result is written to a file, nothing is sent to a device)", null, FALSE );
        if( $oldKey === null && $newKey === null )
            derr( "actions=rekey: nothing to do - give the master key of the input (master-key-file=) and / or the target key (new-master-key-file=)", null, FALSE );
        if( $oldKey !== null && $oldKey === $newKey )
            derr( "actions=rekey: master key of the input and target master key are the same", null, FALSE );
        $allowPartial = isset(PH::$args['allow-partial']);

        $items = ConfigSecrets::rekey( $this->xmlDoc, $oldKey, $newKey );
        $count = array( ConfigSecrets::REKEYED => 0, ConfigSecrets::ALREADY => 0, ConfigSecrets::FAILED => 0, ConfigSecrets::UNSUPPORTED => 0 );
        foreach( $items as $i )
            $count[$i['status']]++;
        $open = $count[ConfigSecrets::FAILED] + $count[ConfigSecrets::UNSUPPORTED];
        $written = $open == 0 || $allowPartial;
        $target = $newKey === null ? 'default master key' : 'given target master key';

        PH::print_stdout();
        PH::print_stdout( "rekey to the " . $target . " - values are never displayed" );
        $text = array( ConfigSecrets::REKEYED => 're-encrypted', ConfigSecrets::ALREADY => 'already encrypted with the target key - unchanged',
            ConfigSecrets::FAILED => 'NOT re-encrypted: no key decrypts it (other master key) - unchanged', ConfigSecrets::UNSUPPORTED => 'NOT re-encrypted: format not supported / malformed - unchanged' );
        foreach( $items as $i )
        {
            PH::print_stdout( "   - " . $i['xpath'] );
            PH::print_stdout( "       " . $text[$i['status']] . ( $i['from'] !== null ? " (was: " . $i['from'] . " master key)" : '' ) );
            PH::print_stdout( $i, false, 'rekey' );
        }
        PH::print_stdout();
        PH::print_stdout( "summary: " . count($items) . " encrypted value(s)" );
        foreach( $count as $status => $n )
            if( $n )
                PH::print_stdout( "   " . str_pad( $n, 6, ' ', STR_PAD_LEFT ) . " " . $text[$status] );

        $summary = array( 'total' => count($items), 'rekeyed' => $count[ConfigSecrets::REKEYED], 'already_target_key' => $count[ConfigSecrets::ALREADY],
            'failed' => $count[ConfigSecrets::FAILED], 'unsupported' => $count[ConfigSecrets::UNSUPPORTED],
            'target' => $newKey === null ? 'default' : 'given', 'written' => $written, 'out' => $written ? $out : null );
        PH::print_stdout( $summary, false, 'summary' );

        if( !$written )
            derr( $open . " value(s) could not be re-encrypted - out= was NOT written. Use allow-partial to write the file with these values unchanged (they will not work with the target master key).", null, FALSE );

        $xml = &DH::dom_to_xml( $this->xmlDoc->documentElement, 0, TRUE, -1, 2 );
        $dir = pathinfo( $out, PATHINFO_DIRNAME );
        if( !is_dir($dir) )
            mkdir( $dir, 0777, TRUE );
        file_put_contents( $out, $xml );
        PH::print_stdout();
        PH::print_stdout( " * written to '" . $out . "'" );
        if( $open )
            mwarning( $open . " value(s) are unchanged in '" . $out . "' (allow-partial) - they do not decrypt with the target master key", null, FALSE );
        if( $newKey === null )
            PH::print_stdout( " * NOTE: values encrypted with the default master key are as good as clear text (the default key is public) - protect '" . $out . "' like a file with clear text passwords" );
        PH::print_stdout();
    }

    /** actions=scrub: lab copy - every encrypted value replaced by a placeholder / a new certificate, written to out= */
    private function scrub()
    {
        $newKey = self::masterKeyArgument( 'new-' );
        $out = isset(PH::$args['out']) ? PH::$args['out'] : '';
        if( $out === '' || $out === '/dev/null' )
            derr( "actions=scrub needs out= (the result is written to a file, nothing is sent to a device)", null, FALSE );
        $placeholder = isset(PH::$args['placeholder']) ? (string)PH::$args['placeholder'] : ConfigSecretsScrub::DEFAULT_PLACEHOLDER;
        if( $placeholder === '' )
            derr( "placeholder is empty", null, FALSE );
        $allowPartial = isset(PH::$args['allow-partial']);

        $items = ConfigSecretsScrub::scrub( $this->xmlDoc, $placeholder, $newKey );
        $count = array( ConfigSecretsScrub::PLACEHOLDER => 0, ConfigSecretsScrub::CERTIFICATE => 0, ConfigSecretsScrub::CERTIFICATE_CHILD => 0, ConfigSecretsScrub::FAILED => 0 );
        foreach( $items as $i )
            $count[$i['status']]++;
        $written = $count[ConfigSecretsScrub::FAILED] == 0 || $allowPartial;
        $text = array( ConfigSecretsScrub::PLACEHOLDER => 'secret replaced by the placeholder', ConfigSecretsScrub::CERTIFICATE => 'certificate replaced: same name and subject, new key pair',
            ConfigSecretsScrub::CERTIFICATE_CHILD => 'certificate without private key re-issued (its issuer was replaced)', ConfigSecretsScrub::FAILED => 'NOT replaced - unchanged' );

        PH::print_stdout();
        PH::print_stdout( "scrub: lab copy for the " . ( $newKey === null ? 'default master key' : 'given target master key' ) . " - the secrets of the input are replaced, nothing is decrypted" );
        foreach( $items as $i )
        {
            PH::print_stdout( "   - " . $i['xpath'] );
            PH::print_stdout( "       " . $text[$i['status']] . ( $i['detail'] !== '' ? " (" . $i['detail'] . ")" : '' ) );
            PH::print_stdout( $i, false, 'scrub' );
        }
        PH::print_stdout();
        PH::print_stdout( "summary: " . count($items) . " value(s) / certificate(s)" );
        foreach( $count as $status => $n )
            if( $n )
                PH::print_stdout( "   " . str_pad( $n, 6, ' ', STR_PAD_LEFT ) . " " . $text[$status] );
        $summary = array( 'total' => count($items), 'placeholder' => $count[ConfigSecretsScrub::PLACEHOLDER], 'certificate_replaced' => $count[ConfigSecretsScrub::CERTIFICATE],
            'certificate_reissued' => $count[ConfigSecretsScrub::CERTIFICATE_CHILD], 'failed' => $count[ConfigSecretsScrub::FAILED],
            'target' => $newKey === null ? 'default' : 'given', 'written' => $written, 'out' => $written ? $out : null,
            'hashed_values_unchanged' => ConfigSecrets::countHashes( $this->xmlDoc ) );
        PH::print_stdout( $summary, false, 'summary' );

        if( !$written )
            derr( $count[ConfigSecretsScrub::FAILED] . " value(s) could not be replaced - out= was NOT written. Use allow-partial to write the file with these values unchanged (the target device will not be able to read them).", null, FALSE );

        $xml = &DH::dom_to_xml( $this->xmlDoc->documentElement, 0, TRUE, -1, 2 );
        $dir = pathinfo( $out, PATHINFO_DIRNAME );
        if( !is_dir($dir) )
            mkdir( $dir, 0777, TRUE );
        file_put_contents( $out, $xml );
        PH::print_stdout();
        PH::print_stdout( " * written to '" . $out . "'" );
        PH::print_stdout( " * NOTE: lab copy only - the real secrets and private keys are gone (placeholders / new key pairs); VPNs, authentication against servers and certificate trust will not work with it" );
        if( $summary['hashed_values_unchanged'] )
            PH::print_stdout( " * NOTE: " . $summary['hashed_values_unchanged'] . " password hash(es) (phash) are unchanged - after loading, the administrators of the input apply (keep / add an administrator you can log in with)" );
        PH::print_stdout();
    }

    private static function formatText( $i )
    {
        if( $i['format'] == ConfigSecrets::FORMAT_CBC )
            return 'AES-256-CBC (version 1)';
        if( $i['format'] == ConfigSecrets::FORMAT_GCM )
            return 'AES-256-GCM (encryption level 2) - not supported';
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

    /** cleartext for display: inline ['value'] for one line, an indented block for multi-line (e.g. a private key) */
    private static function cleartextText( $i )
    {
        if( !array_key_exists( 'cleartext', $i ) )
            return '';
        if( $i['cleartext'] === null )
            return $i['key'] === ConfigSecrets::KEY_UNKNOWN ? "       cleartext: - (no available master key decrypts this value)\n" : '';
        if( strpos( $i['cleartext'], "\n" ) === FALSE )
            return "       cleartext: ['" . $i['cleartext'] . "']\n";
        return "       cleartext:\n         " . str_replace( "\n", "\n         ", $i['cleartext'] ) . "\n";
    }

    private function display( array $items, array $summary, $filter, $cleartext = FALSE )
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
                if( $cleartext )
                    PH::print_stdout( rtrim( self::cleartextText( $i ), "\n" ) );
            }
        }
        if( $cleartext )
        {
            PH::print_stdout();
            PH::print_stdout( "NOTE: cleartext is shown for values that the default (public) master key or the given master key can read - for a lab only" );
        }

        PH::print_stdout();
        PH::print_stdout( "summary: " . $summary['total'] . " encrypted value(s) in the configuration" . ( $filter != 'all' ? ", " . count($items) . " shown" : '' ) );
        $lines = array(
            array( isset($summary['by_key'][ConfigSecrets::KEY_DEFAULT]) ? $summary['by_key'][ConfigSecrets::KEY_DEFAULT] : 0, 'decrypt with the default master key' ),
            array( isset($summary['by_key'][ConfigSecrets::KEY_GIVEN]) ? $summary['by_key'][ConfigSecrets::KEY_GIVEN] : 0, 'decrypt with the given master key' ),
            array( $summary['other_master_key'], 'do NOT decrypt with the default' . ( $summary['custom_master_key_given'] ? ' or the given master key' : ' master key -> custom master key (test it with master-key-file=)' ) ),
            array( isset($summary['by_format'][ConfigSecrets::FORMAT_GCM]) ? $summary['by_format'][ConfigSecrets::FORMAT_GCM] : 0, 'AES-256-GCM (encryption level 2) - detected, not decrypted / not re-keyed' ),
            array( isset($summary['by_format'][ConfigSecrets::FORMAT_UNKNOWN]) ? $summary['by_format'][ConfigSecrets::FORMAT_UNKNOWN] : 0, 'in another format version that is not supported - not checked' ),
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

    private function displayHashes( array $hashes )
    {
        PH::print_stdout( "password hashes (phash) - one-way hashes, independent of the master key; hashes are never displayed" );
        $byLocation = array();
        foreach( $hashes as $h )
            $byLocation[$h['location']][] = $h;
        foreach( $byLocation as $location => $list )
        {
            PH::print_stdout();
            PH::print_stdout( " * " . $location . " (" . count($list) . ")" );
            foreach( $list as $h )
            {
                PH::print_stdout( "   - " . $h['xpath'] );
                PH::print_stdout( "       " . $h['algorithm'] . ( $h['weak'] ? " - WEAK algorithm, set the password again on a current PAN-OS" : '' ) );
            }
        }
        PH::print_stdout();
    }

    private function exportToHtml( $filename, array $items, $hashes = null, $cleartext = FALSE )
    {
        $esc = function( $t ) { return htmlspecialchars( (string)$t, ENT_QUOTES ); };
        $ct = $cleartext ? '<th>cleartext</th>' : '';
        $headers = '<th>location</th><th>field</th><th>format</th><th>key</th><th>length</th>' . $ct . '<th>xpath</th>';
        $lines = '';
        $ctCell = function( $i ) use ( $esc ) {
            if( !array_key_exists( 'cleartext', $i ) )
                return '<td></td>';
            return '<td>' . ( $i['cleartext'] === null ? '' : '<pre>' . $esc($i['cleartext']) . '</pre>' ) . '</td>';
        };
        foreach( $items as $i )
            $lines .= '<tr><td>' . $esc($i['location']) . '</td><td>' . $esc($i['field']) . '</td><td>' . $esc(self::formatText($i)) . '</td><td>'
                . $esc(self::keyText($i)) . '</td><td>' . $esc($i['length']) . '</td>' . ( $cleartext ? $ctCell($i) : '' ) . '<td>' . $esc($i['xpath']) . "</td></tr>\n";
        if( $hashes !== null )
            foreach( $hashes as $h )
                $lines .= '<tr><td>' . $esc($h['location']) . '</td><td>' . $esc($h['field']) . '</td><td>' . $esc('password hash: ' . $h['algorithm'] . ( $h['weak'] ? ' (weak)' : '' ))
                    . '</td><td>independent of the master key</td><td></td>' . ( $cleartext ? '<td></td>' : '' ) . '<td>' . $esc($h['xpath']) . "</td></tr>\n";
        require_once dirname(__FILE__) . '/ExportToHtmlHelper.php';
        ExportToHtmlHelper::writeHtmlExport( $filename, $headers, $lines );
        PH::print_stdout( " * " . ( count($items) + ( $hashes !== null ? count($hashes) : 0 ) ) . " value(s) exported to '" . $filename . "'" );
    }
}
