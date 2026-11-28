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
 * Compare of two statistics results of type=stats (actions=display-bpa): which figures differ, which exist in one of
 * them only. One implementation for type=playbook-validation (compare-stats-…) and the config viewer (stats compare
 * of two runs). No dependency on the rest of pan-os-php: plain arrays in, plain arrays out.
 *
 * Both forms of the JSON are read:
 *   shadow-json                  { …, "statistic": [ { "<header>": { <figures> }, … } ] }
 *   json-to-folder / debugapi    [ { "header": "<header>", <figures> }, … ]            (json/debugAPI_string.json)
 */
class StatsCompare
{
    /** the separator of the path of a nested figure, e.g. "percentage / visibility / Logging / value" */
    const PATH = ' / ';

    /**
     * the statistics blocks of a result, by their header (e.g. "Statistics for PanoramaConf 'Panorama full'")
     * @param mixed $json decoded JSON of a stats result
     * @return array<string,array> header => figures (as in the file); empty when it is not a stats result
     */
    public static function blocks( $json ): array
    {
        if( !is_array( $json ) )
            return array();
        if( isset( $json['statistic'] ) && is_array( $json['statistic'] ) )
            $json = $json['statistic'];
        $out = array();
        $add = function( $header, array $block ) use ( &$out ) {
            $header = trim( (string)$header );
            // the same header twice: kept apart by a counter instead of one hiding the other
            $key = $header;
            for( $n = 2; isset( $out[$key] ); $n++ )
                $key = $header . ' #' . $n;
            $out[$key] = $block;
        };
        foreach( $json as $k => $entry )
        {
            if( !is_array( $entry ) )
                continue;
            if( isset( $entry['header'] ) && is_string( $entry['header'] ) )
                $add( $entry['header'], $entry );
            else
                // a group of blocks: header => block (shadow-json), or a list of blocks
                foreach( $entry as $k2 => $block )
                    if( is_array( $block ) )
                        $add( isset( $block['header'] ) && is_string( $block['header'] ) ? $block['header'] : $k2, $block );
        }
        return $out;
    }

    /**
     * the figures of a block as one level: nested ones get the path as name ("percentage / visibility / Logging / value")
     * @return array<string,mixed> name => value (number, text, bool, null)
     */
    public static function flat( array $block, string $prefix = '' ): array
    {
        $out = array();
        foreach( $block as $k => $v )
        {
            $name = $prefix === '' ? (string)$k : $prefix . self::PATH . $k;
            if( is_array( $v ) )
                $out += self::flat( $v, $name );
            else
                $out[$name] = $v;
        }
        return $out;
    }

    /**
     * @param mixed $a decoded JSON of the first stats result ("from")
     * @param mixed $b decoded JSON of the second one ("to")
     * @return array{equal:bool,same:bool,changed:int,only_a:int,only_b:int,blocks:array,blocks_only_a:string[],blocks_only_b:string[],blocks_a:int,blocks_b:int}
     *   equal: no figure that is in both results has another value (what compare-stats of type=playbook-validation
     *          always meant); same: equal and nothing exists in one result only.
     *   blocks: header => array( 'changed' => name => array( 'from', 'to' ), 'only_a' => name => value, 'only_b' => … )
     *           - only blocks with a difference
     */
    public static function compare( $a, $b ): array
    {
        $ba = self::blocks( $a );
        $bb = self::blocks( $b );
        $out = array( 'equal' => TRUE, 'same' => TRUE, 'changed' => 0, 'only_a' => 0, 'only_b' => 0, 'blocks' => array(),
            'blocks_only_a' => array_values( array_diff( array_keys( $ba ), array_keys( $bb ) ) ),
            'blocks_only_b' => array_values( array_diff( array_keys( $bb ), array_keys( $ba ) ) ),
            'blocks_a' => count( $ba ), 'blocks_b' => count( $bb ) );
        foreach( $ba as $header => $block )
        {
            if( !isset( $bb[$header] ) )
                continue;
            $fa = self::flat( $block );
            $fb = self::flat( $bb[$header] );
            $d = array( 'changed' => array(), 'only_a' => array(), 'only_b' => array() );
            foreach( $fa as $name => $value )
            {
                if( !array_key_exists( $name, $fb ) )
                    $d['only_a'][$name] = $value;
                elseif( $value !== $fb[$name] )
                    $d['changed'][$name] = array( 'from' => $value, 'to' => $fb[$name] );
            }
            foreach( $fb as $name => $value )
                if( !array_key_exists( $name, $fa ) )
                    $d['only_b'][$name] = $value;
            $out['changed'] += count( $d['changed'] );
            $out['only_a'] += count( $d['only_a'] );
            $out['only_b'] += count( $d['only_b'] );
            if( count( $d['changed'] ) || count( $d['only_a'] ) || count( $d['only_b'] ) )
                $out['blocks'][$header] = $d;
        }
        $out['equal'] = $out['changed'] === 0;
        $out['same'] = $out['equal'] && $out['only_a'] === 0 && $out['only_b'] === 0 && !count( $out['blocks_only_a'] ) && !count( $out['blocks_only_b'] );
        return $out;
    }
}
