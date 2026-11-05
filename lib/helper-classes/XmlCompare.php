<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
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

/**
 * Structural comparison of two PAN-OS XML elements, the way type=diff compares configurations:
 *  - children with a name attribute are matched by name (their order does not matter),
 *  - other children are matched by tag name; several unnamed children with the same tag (member lists)
 *    are compared by text content,
 *  - leaves are compared by trimmed text.
 *
 * Used by type=diff (DIFF.php, through hooks that keep its filters and output) and by the mergers
 * (equal(), differences()).
 *
 * Hooks (all optional), see DIFF::compareElements():
 *  'enter'         function($xpath): bool                 FALSE: do not compare this element
 *  'elements'      function($xpath, $el1Elements, $el2Elements)   after the children are grouped by tag
 *  'textDiff'      function($xpath, $el1, $el2)            leaves with different text
 *  'skipMissing'   function($side, $xpath): bool           side 'minus' / 'plus'; TRUE: ignore this missing tag / entry
 *  'namedMissing'  function($side, $node)                  a named entry exists on one side only
 *  'beforeResult'  function($xpath)
 *  'result'        function($xpath, $plus, $minus)          end of one element: entries / tags only on one side
 * Without hooks the differences are collected in $differences.
 */
class XmlCompare
{
    public $hooks = array();

    /** xpath of the children: FALSE = absolute (DH::elementToPanXPath of the first element), TRUE = relative to the compared elements */
    public $relativeXpath = FALSE;

    /** tag names of parents whose named entries are ordered (e.g. 'rules' in vulnerability / spyware profiles) */
    public $orderedParents = array();

    /** collected differences: array( 'xpath' =>, 'type' => 'text'|'plus'|'minus'|'order', 'detail' => string ) */
    public $differences = array();

    public function __construct( array $hooks = array() )
    {
        $this->hooks = $hooks;
    }

    /**
     * TRUE if both elements have the same content. With $ignoreRootName the name attribute of the two
     * compared elements themselves is ignored (e.g. two profiles with different names).
     */
    public static function equal( DOMElement $el1, DOMElement $el2, array $orderedParents = array() ): bool
    {
        return count( self::differences( $el1, $el2, $orderedParents ) ) == 0;
    }

    /** list of differences, xpath relative to the compared elements */
    public static function differences( DOMElement $el1, DOMElement $el2, array $orderedParents = array() ): array
    {
        $cmp = new XmlCompare();
        $cmp->relativeXpath = TRUE;
        $cmp->orderedParents = $orderedParents;
        $cmp->compare( $el1, $el2, '' );
        return $cmp->differences;
    }

    /** one line per difference */
    public static function differencesText( array $differences, $max = 5 ): string
    {
        $lines = array();
        foreach( $differences as $i => $d )
        {
            if( $i >= $max )
            {
                $lines[] = '... ' . ( count($differences) - $max ) . ' more';
                break;
            }
            $lines[] = ( $d['xpath'] === '' ? '/' : $d['xpath'] ) . ' ' . $d['type'] . ': ' . $d['detail'];
        }
        return implode( ' | ', $lines );
    }

    private function hook( $name )
    {
        return isset($this->hooks[$name]) ? $this->hooks[$name] : null;
    }

    private function childXpath( $xpath, DOMElement $node )
    {
        if( !$this->relativeXpath )
            return null;
        $x = $xpath . '/' . $node->tagName;
        if( $node->hasAttribute('name') )
            $x .= "[@name='" . $node->getAttribute('name') . "']";
        return $x;
    }

    public function compare( $el1, $el2, $xpath = null )
    {
        if( $xpath === null )
            $xpath = DH::elementToPanXPath($el1);

        $h = $this->hook('enter');
        if( $h !== null && !$h( $xpath ) )
            return null;

        /** @var DOMElement[][] $el1Elements */
        $el1Elements = array();
        /** @var DOMElement[][] $el2Elements */
        $el2Elements = array();

        /** @var DOMElement[] $plus */
        $plus = array();
        /** @var DOMElement[] $minus */
        $minus = array();

        foreach( $el1->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;
            $el1Elements[$node->tagName][] = $node;
        }

        foreach( $el2->childNodes as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;
            $el2Elements[$node->tagName][] = $node;
        }

        $h = $this->hook('elements');
        if( $h !== null )
            $h( $xpath, $el1Elements, $el2Elements );

        if( count($el1Elements) == 0 && count($el2Elements) == 0 )
        {
            $el1Trim = trim($el1->textContent);
            $el2Trim = trim($el2->textContent);

            if( $el1Trim != $el2Trim )
            {
                $h = $this->hook('textDiff');
                if( $h !== null )
                    $h( $xpath, $el1, $el2 );
                else
                    $this->differences[] = array( 'xpath' => $xpath, 'type' => 'text', 'detail' => "'" . $el1Trim . "' -> '" . $el2Trim . "'" );
            }
            return;
        }

        $skipMissing = $this->hook('skipMissing');

        //
        //  nodes missing entirely in one or the other
        //
        foreach( $el1Elements as $tagName => &$nodeArray1 )
        {
            if( !isset($el2Elements[$tagName]) )
            {
                $fullXpathName = $xpath . "/" . $tagName;

                $continue = ( $skipMissing !== null ) ? $skipMissing( 'minus', $fullXpathName ) : FALSE;
                if( !$continue )
                    foreach( $nodeArray1 as $node )
                    {
                        $continue = false;
                        $attribute = DH::findAttribute('name', $node);
                        if( $attribute !== FALSE && $skipMissing !== null )
                            $continue = $skipMissing( 'minus', $fullXpathName . "[@name='" . $attribute . "']" );

                        if( !$continue )
                            $minus[] = $node;
                    }
                unset($el1Elements[$tagName]);
            }
        }
        foreach( $el2Elements as $tagName => &$nodeArray2 )
        {
            if( !isset($el1Elements[$tagName]) )
            {
                $fullXpathName = $xpath . "/" . $tagName;

                $continue = ( $skipMissing !== null ) ? $skipMissing( 'plus', $fullXpathName ) : FALSE;
                if( !$continue )
                    foreach( $nodeArray2 as $node )
                    {
                        $continue = false;
                        $attribute = DH::findAttribute('name', $node);
                        if( $attribute !== FALSE && $skipMissing !== null )
                            $continue = $skipMissing( 'plus', $fullXpathName . "[@name='" . $attribute . "']" );

                        if( !$continue )
                            $plus[] = $node;
                    }
                unset($el2Elements[$tagName]);
            }
        }

        // conflicting objects
        foreach( $el1Elements as $tagName => &$nodeArray1 )
        {
            $nodeArray2 = &$el2Elements[$tagName];

            $el1BasicNode = null;
            foreach( $nodeArray1 as $nodeIndex => $node )
            {
                if( !$node->hasAttribute('name') )
                {
                    if( $el1BasicNode === null )
                        $el1BasicNode = $node;
                    else
                    {
                        if( is_array($el1BasicNode) )
                            $el1BasicNode[] = $node;
                        else
                        {
                            $el1BasicNode = array($el1BasicNode);
                            $el1BasicNode[] = $node;
                        }
                    }

                    unset($nodeArray1[$nodeIndex]);
                }
            }
            if( $el1BasicNode !== null && count($nodeArray1) > 0 )
                derr('unsupported situation where <node> and <node name=""> were both seen', $el1, false);

            $el2BasicNode = null;
            foreach( $nodeArray2 as $nodeIndex => $node )
            {
                if( !$node->hasAttribute('name') )
                {
                    if( $el2BasicNode === null )
                        $el2BasicNode = $node;
                    else
                    {
                        if( is_array($el2BasicNode) )
                            $el2BasicNode[] = $node;
                        else
                        {
                            $el2BasicNode = array($el2BasicNode);
                            $el2BasicNode[] = $node;
                        }
                    }

                    unset($nodeArray2[$nodeIndex]);
                }
            }
            if( $el2BasicNode !== null && count($nodeArray2) > 0 )
                derr('unsupported situation where <node> and <node name=""> where both seen in same document', $el2, false);

            if( $el1BasicNode === null && $el2BasicNode !== null )
                mwarning('found an issue where file1 has <node> but file2 has <node name="">', null, false);
            if( $el1BasicNode !== null && $el2BasicNode === null )
                mwarning('found an issue where file2 has <node> but file1 has <node name="">', null, false);


            if( $el1BasicNode !== null && $el2BasicNode !== null )
            {
                if( is_object($el1BasicNode) && is_object($el2BasicNode) )
                {
                    $this->compare($el1BasicNode, $el2BasicNode, $this->childXpath( $xpath, $el1BasicNode ));
                }
                else
                {
                    if( is_object($el1BasicNode) )
                        $el1BasicNode = array($el1BasicNode);
                    if( is_object($el2BasicNode) )
                        $el2BasicNode = array($el2BasicNode);

                    $el1ContentSorted = array();
                    $el2ContentSorted = array();

                    foreach( $el1BasicNode as $node )
                    {
                        $nodeContent = $node->textContent;
                        if( isset($el1ContentSorted[$nodeContent]) )
                            mwarning('cannot have <node>'.$nodeContent.'</node> nodes with same content. file1', $el1, false, FALSE);
                        else
                            $el1ContentSorted[$nodeContent] = $node;
                    }
                    foreach( $el2BasicNode as $node )
                    {
                        $nodeContent = $node->textContent;
                        if( isset($el2ContentSorted[$nodeContent]) )
                            mwarning('cannot have <node>'.$nodeContent.'</node> nodes with same content. file2', $el2, false, FALSE);
                        else
                            $el2ContentSorted[$nodeContent] = $node;
                    }

                    foreach( $el1ContentSorted as $content => $node )
                    {
                        if( isset($el2ContentSorted[$content]) )
                            continue;
                        $minus[] = $node;
                    }
                    foreach( $el2ContentSorted as $content => $node )
                    {
                        if( isset($el1ContentSorted[$content]) )
                            continue;
                        $plus[] = $node;
                    }
                }
            }
            elseif( $el1BasicNode !== null && $el2BasicNode === null )
            {
                if( is_object($el1BasicNode) )
                    $minus[] = $el1BasicNode;
                else
                    foreach( $el1BasicNode as $node )
                        $minus[] = $node;
            }
            elseif( $el1BasicNode === null && $el2BasicNode !== null )
            {
                // kept as in type=diff: reported on the 'minus' side
                if( is_object($el2BasicNode) )
                    $minus[] = $el2BasicNode;
                else
                    foreach( $el2BasicNode as $node )
                        $minus[] = $node;
            }
            else
            {
                $el1NameSorted = array();
                $el2NameSorted = array();

                foreach( $nodeArray1 as $nodeIndex => $node )
                {
                    $nodeName = $node->getAttribute('name');
                    if( isset($el1NameSorted[$nodeName]) )
                        mwarning('<node name="' . $nodeName . '"> was found twice in file1', $node, false, FALSE);
                    else
                        $el1NameSorted[$nodeName] = $node;
                }
                foreach( $nodeArray2 as $nodeIndex => $node )
                {
                    $nodeName = $node->getAttribute('name');
                    if( isset($el2NameSorted[$nodeName]) )
                        mwarning('<node name="' . $nodeName . '"> was found twice in file2', $node, false, FALSE);
                    else
                        $el2NameSorted[$nodeName] = $node;
                }

                $namedMissing = $this->hook('namedMissing');
                foreach( $el1NameSorted as $nodeName => $node )
                {
                    if( !isset($el2NameSorted[$nodeName]) )
                    {
                        $minus[] = $node;
                        unset($el1NameSorted[$nodeName]);
                        if( $namedMissing !== null )
                            $namedMissing( 'minus', $node );
                    }
                }
                foreach( $el2NameSorted as $nodeName => $node )
                {
                    if( !isset($el1NameSorted[$nodeName]) )
                    {
                        $plus[] = $node;
                        unset($el2NameSorted[$nodeName]);
                        if( $namedMissing !== null )
                            $namedMissing( 'plus', $node );
                    }
                }

                // order of named entries, only where it matters (and only without hooks, type=diff has its own rule order check)
                if( isset($this->orderedParents[$el1->tagName]) && $this->hook('result') === null )
                {
                    $order1 = array_values( array_intersect( array_keys($el1NameSorted), array_keys($el2NameSorted) ) );
                    $order2 = array_values( array_intersect( array_keys($el2NameSorted), array_keys($el1NameSorted) ) );
                    if( $order1 !== $order2 )
                        $this->differences[] = array( 'xpath' => $xpath, 'type' => 'order', 'detail' => implode(',', $order1) . ' -> ' . implode(',', $order2) );
                }

                foreach( $el1NameSorted as $nodeName => $node1 )
                {
                    $node2 = $el2NameSorted[$nodeName];
                    $this->compare($node1, $node2, $this->childXpath( $xpath, $node1 ));
                }
            }

            unset($el1Elements[$tagName]);
            unset($el2Elements[$tagName]);
        }

        $h = $this->hook('beforeResult');
        if( $h !== null )
            $h( $xpath );

        $h = $this->hook('result');
        if( $h !== null )
            $h( $xpath, $plus, $minus );
        else
        {
            foreach( $plus as $node )
                $this->differences[] = array( 'xpath' => $xpath, 'type' => 'plus', 'detail' => self::nodeText( $node ) );
            foreach( $minus as $node )
                $this->differences[] = array( 'xpath' => $xpath, 'type' => 'minus', 'detail' => self::nodeText( $node ) );
        }
    }

    private static function nodeText( DOMElement $node ): string
    {
        $text = preg_replace( '/\s+/', ' ', DH::dom_to_xml($node, -1, FALSE) );
        if( strlen($text) > 120 )
            $text = substr($text, 0, 117) . '...';
        return trim($text);
    }
}
