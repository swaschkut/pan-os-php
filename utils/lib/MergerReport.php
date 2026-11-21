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
 * The report of a merger as data (object-merger and the single object mergers, rule-merger, merger-possible-report):
 * the same content as exportCSV=<file.html>, but structured - for the config viewer (tables after a run) and scripts.
 *
 *   exportJSON=<file.json>   writes it to a file
 *   shadow-json              puts it into the JSON output as "merger-report"
 *
 *   { "type": "object-merger", "summary": { … },
 *     "merged":  [ { "objecttype", "key", "kept": {location, name, detail}, "removed": [ {location, name, detail}, … ] } ],
 *     "skipped": [ { "objecttype", "key", "kept": …, "notMergedWith": [ … ], "reason": [ "…" ] } ],
 *     "findings": [ … ]  (merger-possible-report) }
 */
class MergerReport
{
    /** "[DG-Berlin] - web01{value:10.0.0.1/32} (tmp)" → location, name, detail */
    public static function ref( $text ): array
    {
        $text = trim( (string)$text );
        if( preg_match( '/^\[(.*?)\] - (.*?)((?:\s*\{[^{}]*\})*)(\s*\(tmp\))?$/s', $text, $m ) )
            return array( 'location' => $m[1], 'name' => $m[2], 'detail' => trim( $m[3] . ( $m[4] ?? '' ) ), 'text' => $text );
        return array( 'location' => '', 'name' => $text, 'detail' => '', 'text' => $text );
    }

    /** "address: <hash>" (object-merger with several object types) → object type, key */
    private static function key( $index ): array
    {
        $index = (string)$index;
        if( preg_match( '/^([a-z0-9-]+): (.*)$/s', $index, $m ) )
            return array( $m[1], $m[2] );
        return array( '', $index );
    }

    /** from MERGER::$deletedObjects / $skippedObjects (strings "[loc] - name{…}", several joined by "|") */
    public static function fromObjectMerger( string $utilType, array $deleted, array $skipped ): array
    {
        $list = function( $s ) {
            $out = array();
            foreach( explode( '|', (string)$s ) as $x )
                if( trim( $x ) !== '' )
                    $out[] = self::ref( $x );
            return $out;
        };
        $r = array( 'type' => $utilType, 'merged' => array(), 'skipped' => array(), 'summary' => array() );
        foreach( $deleted as $index => $l )
        {
            list( $type, $key ) = self::key( $index );
            $r['merged'][] = array( 'objecttype' => $type, 'key' => $key, 'index' => (string)$index,
                'kept' => isset( $l['kept'] ) ? self::ref( $l['kept'] ) : null, 'removed' => $list( $l['removed'] ?? '' ) );
        }
        foreach( $skipped as $index => $l )
        {
            list( $type, $key ) = self::key( $index );
            $reason = array_values( array_filter( explode( PHP_EOL, (string)( $l['reason'] ?? '' ) ), function( $x ) { return trim( $x ) !== ''; } ) );
            $r['skipped'][] = array( 'objecttype' => $type, 'key' => $key, 'index' => (string)$index,
                'kept' => isset( $l['kept'] ) && $l['kept'] !== '' ? self::ref( $l['kept'] ) : null, 'notMergedWith' => $list( $l['removed'] ?? '' ),
                'reason' => $reason )
                // the effective-policy check as data (MergeSafety::$lastDetail): what the firewalls get before / after
                + ( isset( $l['safety'] ) && is_array( $l['safety'] ) ? array( 'safety' => array_values( $l['safety'] ) ) : array() );
        }
        foreach( array( 'merged', 'skipped' ) as $k )
            foreach( $r[$k] as $e )
            {
                $t = $e['objecttype'] !== '' ? $e['objecttype'] : $utilType;
                if( !isset( $r['summary'][$t] ) )
                    $r['summary'][$t] = array( 'merged' => 0, 'removed' => 0, 'skipped' => 0 );
                if( $k === 'merged' )
                {
                    $r['summary'][$t]['merged']++;
                    $r['summary'][$t]['removed'] += count( $e['removed'] );
                }
                else
                    $r['summary'][$t]['skipped']++;
            }
        return $r;
    }

    /**
     * from RULEMERGER::$deletedObjects / $skippedObjects: rule name => kept / manipulated (fields after / before the
     * merge), removed (name => fields), reason (name => text), skippedreason (deny rule name => fields)
     */
    public static function fromRuleMerger( array $deleted, array $skipped ): array
    {
        $r = array( 'type' => 'rule-merger', 'merged' => array(), 'skipped' => array(), 'summary' => array( 'merged' => 0, 'removed' => 0, 'skipped' => 0 ) );
        $named = function( $list ) {
            $out = array();
            foreach( is_array( $list ) ? $list : array() as $name => $fields )
                $out[] = array( 'name' => (string)$name, 'fields' => is_array( $fields ) ? $fields : array() );
            return $out;
        };
        foreach( $deleted as $name => $l )
        {
            if( empty( $l['removed'] ) )
                continue;
            $after = is_array( $l['kept'] ?? null ) ? $l['kept'] : array();
            $r['merged'][] = array( 'rule' => (string)$name, 'location' => is_string( $after['location'] ?? null ) ? $after['location'] : '',
                'rulebase' => is_string( $after['rulebase'] ?? null ) ? $after['rulebase'] : '',
                'before' => is_array( $l['manipulated'] ?? null ) ? $l['manipulated'] : array(), 'after' => $after, 'removed' => $named( $l['removed'] ) );
            $r['summary']['merged']++;
            $r['summary']['removed'] += count( $l['removed'] );
        }
        foreach( $skipped as $name => $l )
        {
            $kept = is_array( $l['kept'] ?? null ) ? $l['kept'] : array();
            $not = $named( $l['removed'] ?? array() );
            foreach( $not as $i => $n )
                $not[$i]['reason'] = (string)( $l['reason'][$n['name']] ?? '' );
            $r['skipped'][] = array( 'rule' => (string)$name, 'location' => is_string( $kept['location'] ?? null ) ? $kept['location'] : '',
                'rulebase' => is_string( $kept['rulebase'] ?? null ) ? $kept['rulebase'] : '', 'kept' => $kept, 'notMergedWith' => $not,
                'denyRules' => $named( $l['skippedreason'] ?? array() ) );
            $r['summary']['skipped'] += count( $not );
        }
        return $r;
    }

    /** into the JSON output (shadow-json) and / or a file (exportJSON=) */
    public static function write( array $report, $file ): void
    {
        if( PH::$shadow_json )
            PH::$JSON_OUT['merger-report'] = $report;
        if( is_string( $file ) && $file !== '' )
        {
            file_put_contents( $file, json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE ) );
            PH::print_stdout( " - merger report (JSON) written to '" . $file . "'" );
        }
    }

    /** exportJSON= of the arguments (with the project folder like exportCSV) */
    public static function fileArgument( $projectFolder = null )
    {
        if( !isset( PH::$args['exportjson'] ) || !is_string( PH::$args['exportjson'] ) || PH::$args['exportjson'] === '' )
            return null;
        $f = PH::$args['exportjson'];
        return $projectFolder !== null ? $projectFolder . '/' . $f : $f;
    }
}
