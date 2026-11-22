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
 * Three-way merge of one entry of ConfigObjectSplit per field (git step 4) - the merge driver of the history
 * (utils/develop/config-viewer/bin/git-merge-entry.php). Standalone: no other class of pan-os-php needed.
 *
 *   an object / rule / _rest.xml (XML): element by element. Children are matched by a key: <member> by its text (a set:
 *     additions of both sides united, removals taken out), <entry> by its name, every other element by its name and
 *     its place among the elements of that name. A field changed on one side only is taken; changed on both sides to
 *     different values = conflict. Attributes the same way. Removed on one side and changed on the other = conflict.
 *   _order (one key per line): removals of both sides taken out, additions placed after their predecessor of their side.
 *
 * merge() gives the merged text or null (conflict: git keeps it as a conflict).
 */
class ConfigObjectMerge
{
    /** @return string|null the merged text, null = conflict */
    public static function merge( string $base, string $ours, string $theirs, string $path = '' ): ?string
    {
        if( $ours === $theirs || $theirs === $base )
            return $ours;
        if( $ours === $base )
            return $theirs;
        if( basename( $path ) === '_order' )
            return self::mergeOrder( $base, $ours, $theirs );

        $docs = array();
        foreach( array( 'o' => $base, 'a' => $ours, 'b' => $theirs ) as $k => $text )
        {
            $d = new DOMDocument();
            $prev = libxml_use_internal_errors( TRUE );
            $ok = $text !== '' && $d->loadXML( $text, LIBXML_PARSEHUGE );
            libxml_clear_errors();
            libxml_use_internal_errors( $prev );
            if( !$ok || $d->documentElement === null )
                return null;
            self::strip( $d->documentElement );
            $docs[$k] = $d;
        }
        $out = new DOMDocument( '1.0', 'UTF-8' );
        $out->formatOutput = TRUE;
        $m = self::mergeElement( $docs['o']->documentElement, $docs['a']->documentElement, $docs['b']->documentElement, $out );
        if( $m === null )
            return null;
        $out->appendChild( $m );
        // the form of the input: a whole document (_rest.xml, with the declaration) or one entry
        if( strpos( ltrim( $ours ), '<?xml' ) === 0 )
            return $out->saveXML();
        return $out->saveXML( $out->documentElement ) . "\n";
    }

    // ------------------------------------------------------------------------------------------------------------

    private static function mergeOrder( string $base, string $ours, string $theirs ): string
    {
        $lines = function( $t ) { return array_values( array_filter( explode( "\n", $t ), function( $l ) { return $l !== ''; } ) ); };
        $o = $lines( $base );
        $a = $lines( $ours );
        $b = $lines( $theirs );
        $removedB = array_diff( $o, $b );
        $res = array_values( array_filter( $a, function( $k ) use ( $removedB ) { return !in_array( $k, $removedB, TRUE ); } ) );
        // the additions of theirs: after the key before them in theirs (or at the start)
        foreach( $b as $i => $k )
        {
            if( in_array( $k, $o, TRUE ) || in_array( $k, $res, TRUE ) )
                continue;
            $pos = 0;
            for( $j = $i - 1; $j >= 0; $j-- )
                if( ( $p = array_search( $b[$j], $res, TRUE ) ) !== FALSE )
                {
                    $pos = $p + 1;
                    break;
                }
            array_splice( $res, $pos, 0, array( $k ) );
        }
        // a key moved by theirs only (same set, other place): theirs' order for it when ours kept the base order
        if( $a === $o && count( array_diff( $b, $res ) ) === 0 && count( array_diff( $res, $b ) ) === 0 )
            $res = $b;
        return implode( "\n", $res ) . "\n";
    }

    /** whitespace between elements out (an element with element children) */
    private static function strip( DOMElement $el ): void
    {
        $hasEl = FALSE;
        foreach( $el->childNodes as $c )
            if( $c instanceof DOMElement )
                $hasEl = TRUE;
        $rm = array();
        foreach( $el->childNodes as $c )
            if( $c instanceof DOMElement )
                self::strip( $c );
            elseif( $hasEl && $c->nodeType === XML_TEXT_NODE && trim( $c->nodeValue ) === '' )
                $rm[] = $c;
        foreach( $rm as $c )
            $el->removeChild( $c );
    }

    private static function same( ?DOMNode $x, ?DOMNode $y ): bool
    {
        if( $x === null || $y === null )
            return $x === $y;
        return $x->ownerDocument->saveXML( $x ) === $y->ownerDocument->saveXML( $y );
    }

    /** @return DOMElement|null (in $out), null = conflict */
    private static function mergeElement( DOMElement $o, DOMElement $a, DOMElement $b, DOMDocument $out ): ?DOMElement
    {
        if( self::same( $a, $b ) || self::same( $b, $o ) )
            return $out->importNode( $a, TRUE );
        if( self::same( $a, $o ) )
            return $out->importNode( $b, TRUE );
        if( $a->nodeName !== $b->nodeName )
            return null;
        $el = $out->createElement( $a->nodeName );
        // attributes: field by field
        $names = array();
        foreach( array( $o, $a, $b ) as $n )
            foreach( $n->attributes as $at )
                $names[$at->name] = TRUE;
        foreach( array_keys( $names ) as $name )
        {
            $vo = $o->hasAttribute( $name ) ? $o->getAttribute( $name ) : null;
            $va = $a->hasAttribute( $name ) ? $a->getAttribute( $name ) : null;
            $vb = $b->hasAttribute( $name ) ? $b->getAttribute( $name ) : null;
            $v = $va === $vb || $vb === $vo ? $va : ( $va === $vo ? $vb : FALSE );
            if( $v === FALSE )
                return null;
            if( $v !== null )
                $el->setAttribute( $name, $v );
        }
        // a value (text only): changed on both sides to different values
        $ka = self::children( $a );
        $kb = self::children( $b );
        $ko = self::children( $o );
        if( $ka === null || $kb === null || $ko === null )
            return null;
        $keys = array_keys( $ka );
        // the keys of theirs that ours does not have: after the key before them in theirs
        $bKeys = array_keys( $kb );
        foreach( $bKeys as $i => $k )
        {
            if( isset( $ka[$k] ) )
                continue;
            $pos = 0;
            for( $j = $i - 1; $j >= 0; $j-- )
                if( ( $p = array_search( $bKeys[$j], $keys, TRUE ) ) !== FALSE )
                {
                    $pos = $p + 1;
                    break;
                }
            array_splice( $keys, $pos, 0, array( $k ) );
        }
        foreach( $keys as $k )
        {
            $xo = $ko[$k] ?? null;
            $xa = $ka[$k] ?? null;
            $xb = $kb[$k] ?? null;
            if( $xa !== null && $xb !== null )
            {
                if( $xo === null )
                {
                    // added on both sides
                    if( !self::same( $xa, $xb ) )
                        return null;
                    $el->appendChild( $out->importNode( $xa, TRUE ) );
                    continue;
                }
                $m = self::mergeNode( $xo, $xa, $xb, $out );
                if( $m === null )
                    return null;
                $el->appendChild( $m );
            }
            elseif( $xa !== null )
            {
                // only in ours: added by ours, or removed by theirs (allowed when ours did not change it)
                if( $xo === null )
                    $el->appendChild( $out->importNode( $xa, TRUE ) );
                elseif( !self::same( $xa, $xo ) )
                    return null;
            }
            elseif( $xb !== null )
            {
                if( $xo === null )
                    $el->appendChild( $out->importNode( $xb, TRUE ) );
                elseif( !self::same( $xb, $xo ) )
                    return null;
            }
        }
        return $el;
    }

    private static function mergeNode( DOMNode $o, DOMNode $a, DOMNode $b, DOMDocument $out ): ?DOMNode
    {
        if( $a instanceof DOMElement && $b instanceof DOMElement && $o instanceof DOMElement )
            return self::mergeElement( $o, $a, $b, $out );
        if( self::same( $a, $b ) || self::same( $b, $o ) )
            return $out->importNode( $a, TRUE );
        if( self::same( $a, $o ) )
            return $out->importNode( $b, TRUE );
        return null;
    }

    /**
     * the children of an element by key: member = "m:<text>", entry = "e:<name>", other element = "<name>#<n>",
     * text = "#text" (only when it is the only child); null: mixed text and elements (not merged)
     */
    private static function children( DOMElement $el ): ?array
    {
        $list = array();
        $count = array();
        $hasEl = FALSE;
        $hasText = FALSE;
        foreach( $el->childNodes as $c )
        {
            if( $c instanceof DOMElement )
            {
                $hasEl = TRUE;
                if( $c->nodeName === 'member' )
                    $k = 'm:' . $c->textContent;
                elseif( $c->nodeName === 'entry' && $c->hasAttribute( 'name' ) )
                    $k = 'e:' . $c->getAttribute( 'name' );
                else
                {
                    $count[$c->nodeName] = ( $count[$c->nodeName] ?? 0 ) + 1;
                    $k = $c->nodeName . '#' . $count[$c->nodeName];
                }
                if( isset( $list[$k] ) )
                    $k .= '#' . spl_object_id( $c );
                $list[$k] = $c;
            }
            elseif( $c->nodeType === XML_TEXT_NODE || $c->nodeType === XML_CDATA_SECTION_NODE )
            {
                $hasText = TRUE;
                $list['#text'] = $c;
            }
            elseif( $c->nodeType === XML_COMMENT_NODE )
                $list['#comment' . count( $list )] = $c;
        }
        if( $hasEl && $hasText )
            return null;
        return $list;
    }
}
