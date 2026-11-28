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
 * The text output of type=diff read back as data: one entry per "XPATH: …" with the lines that only file2 has ("+")
 * and the lines that only file1 has ("-"), and the "- FinalResult: PASS | FAIL" line at the end (what
 * type=playbook-validation compare-<a>-<b> checks). Used by the config viewer (diff view of a run, the result of a diff
 * run). Reads the file line by line - a run.log of a large configuration is not loaded at once.
 */
class DiffLog
{
    /**
     * @param string $file the output of type=diff (run.log)
     * @param int $maxEntries entries kept (the rest is counted only)
     * @param int $maxLines lines kept per entry (the rest is counted only)
     * @return array{final:?string,entries:array,count:int,truncated:bool,hash:?string}
     *   entries: xpath, location (shared, device-group <name>, template <name>, vsys <name>, …), kind (path below the
     *   location, e.g. address, pre-rulebase/security/rules), name (the last entry name of the path; '' when the
     *   XPath does not end with an entry), added, removed (number of + / - lines), lines (array of '+…' / '-…'),
     *   lines_cut (lines not kept); hash: fingerprint of all differences (32 hex; the same differences, the same hash)
     */
    public static function read( string $file, int $maxEntries = 5000, int $maxLines = 300 ): array
    {
        $out = array( 'final' => null, 'entries' => array(), 'count' => 0, 'truncated' => FALSE, 'hash' => null );
        $fh = @fopen( $file, 'r' );
        if( $fh === FALSE )
            return $out;
        // the fingerprint of all differences (every XPath and line, also those not kept): the same differences of
        // another diff run have the same hash
        $h = hash_init( 'sha256' );
        $cur = null;
        $flush = function() use ( &$cur, &$out, $maxEntries ) {
            if( $cur === null )
                return;
            $out['count']++;
            if( count( $out['entries'] ) < $maxEntries )
                $out['entries'][] = $cur;
            else
                $out['truncated'] = TRUE;
            $cur = null;
        };
        while( ( $line = fgets( $fh, 1048576 ) ) !== FALSE )
        {
            $line = rtrim( $line, "\r\n" );
            if( preg_match( '/^- FinalResult:\s+(PASS|FAIL)\s*$/', $line, $m ) )
            {
                $flush();
                $out['final'] = $m[1];
                continue;
            }
            if( strpos( $line, 'XPATH: ' ) === 0 )
            {
                $flush();
                $cur = self::entry( substr( $line, 7 ) );
                hash_update( $h, 'X' . substr( $line, 7 ) . "\n" );
                continue;
            }
            // the end of the differences: a line of #, the set commands, the end of the script
            if( $cur !== null && ( $line === '' || preg_match( '/^#{10,}$/', $line ) ) )
            {
                if( $line !== '' )
                    $flush();
                continue;
            }
            if( $cur !== null && ( $line[0] === '+' || $line[0] === '-' ) )
            {
                $cur[$line[0] === '+' ? 'added' : 'removed']++;
                hash_update( $h, $line . "\n" );
                if( count( $cur['lines'] ) < $maxLines )
                    $cur['lines'][] = $line;
                else
                    $cur['lines_cut']++;
            }
        }
        fclose( $fh );
        $flush();
        $out['hash'] = substr( hash_final( $h ), 0, 32 );
        return $out;
    }
    /** "- FinalResult: PASS | FAIL" of the output of type=diff; null: no such line (not finished, failed) */
    public static function finalResult( string $file ): ?string
    {
        $result = null;
        $fh = @fopen( $file, 'r' );
        if( $fh === FALSE )
            return null;
        while( ( $line = fgets( $fh, 1048576 ) ) !== FALSE )
            if( preg_match( '/^- FinalResult:\s+(PASS|FAIL)\s*$/', $line, $m ) )
                $result = $m[1];
        fclose( $fh );
        return $result;
    }

    /** an entry for an XPath: where (location), what (kind), which (name) */
    public static function entry( string $xpath ): array
    {
        $e = array( 'xpath' => $xpath, 'location' => '', 'kind' => '', 'name' => '', 'added' => 0, 'removed' => 0, 'lines' => array(), 'lines_cut' => 0 );
        // the steps of the XPath: name and the value of [@name='…'] (quotes inside a name are not split)
        preg_match_all( "#/([^/\\[]+)(?:\\[@name='((?:[^']|'(?!\\]))*)'\\])?#", $xpath, $m, PREG_SET_ORDER );
        $steps = array_map( function( $x ) { return array( $x[1], $x[2] ?? null ); }, $m );
        if( count( $steps ) && $steps[0][0] === 'config' )
            array_shift( $steps );
        // /config/shared/… | /config/devices/entry[@name='localhost.localdomain']/(device-group|template|template-stack|vsys)/entry[@name='x']/…
        $device = function( array $steps ) {
            // devices/entry[@name='…'] - the device itself (Panorama, firewall)
            return count( $steps ) >= 2 && $steps[0][0] === 'devices' && $steps[1][0] === 'entry' ? array_slice( $steps, 2 ) : null;
        };
        if( count( $steps ) && $steps[0][0] === 'shared' )
        {
            $e['location'] = 'shared';
            array_shift( $steps );
        }
        elseif( ( $below = $device( $steps ) ) !== null )
        {
            $steps = $below;
            if( count( $steps ) >= 2 && in_array( $steps[0][0], array( 'device-group', 'template', 'template-stack', 'vsys' ), TRUE ) && $steps[1][0] === 'entry' && $steps[1][1] !== null )
            {
                $e['location'] = $steps[0][0] . ' ' . $steps[1][1];
                $steps = array_slice( $steps, 2 );
                // a template / template stack has a configuration of its own: config/shared, config/devices/entry/(vsys/entry | network …)
                if( count( $steps ) && $steps[0][0] === 'config' )
                {
                    $steps = array_slice( $steps, 1 );
                    if( count( $steps ) && $steps[0][0] === 'shared' )
                    {
                        $e['location'] .= ' / shared';
                        $steps = array_slice( $steps, 1 );
                    }
                    elseif( ( $below = $device( $steps ) ) !== null )
                    {
                        $steps = $below;
                        if( count( $steps ) >= 2 && $steps[0][0] === 'vsys' && $steps[1][0] === 'entry' && $steps[1][1] !== null )
                        {
                            $e['location'] .= ' / vsys ' . $steps[1][1];
                            $steps = array_slice( $steps, 2 );
                        }
                    }
                }
            }
            else
                $e['location'] = 'device';
        }
        else
            $e['location'] = 'other';
        $last = end( $steps );
        if( $last !== FALSE && $last[0] === 'entry' && $last[1] !== null )
        {
            $e['name'] = $last[1];
            array_pop( $steps );
        }
        // the kind: the names of the steps without entry[@name] (pre-rulebase/security/rules, address, network/interface/…)
        $e['kind'] = implode( '/', array_values( array_filter( array_map( function( $s ) { return $s[0] === 'entry' ? null : $s[0]; }, $steps ) ) ) );
        return $e;
    }
}
