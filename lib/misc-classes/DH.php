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

class DH
{
    /**
     * @param DOMNode $a
     * @param $objects
     * @param string $tagName
     * @param bool $showAnyIfZero
     * @param string $valueOfAny
     */
    static function Hosts_to_xmlDom(DOMNode $a, &$objects, $tagName = 'member', $showAnyIfZero = TRUE, $valueOfAny = 'any', $typeObject = TRUE)
    {
        //print_r($a);

        while( $a->hasChildNodes() )
            $a->removeChild($a->childNodes->item(0));

        $c = count($objects);
        if( $c == 0 && $showAnyIfZero == TRUE )
        {
            $tmp = $a->ownerDocument->createElement($tagName);
            $tmp = $a->appendChild($tmp);
            $tmp->appendChild($a->ownerDocument->createTextNode($valueOfAny));
            return;
        }

        foreach( $objects as $o )
        {
            $tmp = $a->ownerDocument->createElement($tagName);
            $tmp = $a->appendChild($tmp);
            if( $typeObject )
                $objName = $o->name();
            else
                $objName = $o;
            $tmp->appendChild($a->ownerDocument->createTextNode($objName));
        }
        //print_r($a);
    }

    static function setDomNodeText(DOMNode $node, $text)
    {
        DH::clearDomNodeChilds($node);
        $node->appendChild($node->ownerDocument->createTextNode($text));
    }

    static function makeElementAsRoot(DOMElement $newRoot, DOMNode $doc)
    {
        $doc->appendChild($newRoot);

        $nodes = array();
        foreach( $doc->childNodes as $node )
        {
            $nodes[] = $node;
        }

        foreach( $nodes as $node )
        {
            if( !$newRoot->isSameNode($node) )
                $doc->removeChild($node);
        }

    }

    static function removeReplaceElement(DOMElement $el, $newName)
    {
        $ret = $el->ownerDocument->createElement($newName);
        $ret = $el->parentNode->replaceChild($ret, $el);

        return $ret;
    }

    static function clearDomNodeChilds(DOMNode $node)
    {
        while( $node->hasChildNodes() )
            $node->removeChild($node->childNodes->item(0));
    }

    /**
     * @param DOMNode $node
     * @return bool|DOMElement
     */
    static function firstChildElement(DOMNode $node)
    {
        foreach( $node->childNodes as $child )
        {
            if( $child->nodeType == XML_ELEMENT_NODE )
                return $child;
        }

        return FALSE;
    }

    /**
     * @param string $tagName
     * @param DOMNode $node
     * @return bool|DOMElement
     * @throws Exception
     */
    static function findFirstElementOrDie($tagName, DOMNode $node)
    {
        $ret = DH::findFirstElement($tagName, $node);

        if( $ret === FALSE )
            derr(' xml element <' . $tagName . '> was not found', $node);

        return $ret;
    }

    /**
     * @param $tagName
     * @param DOMNode $node
     * @return bool|DOMElement
     */
    static function findFirstElement($tagName, DOMNode $node)
    {
        foreach( $node->childNodes as $lnode )
        {
            if( $lnode->nodeType != XML_ELEMENT_NODE )
                continue;
            /** @var DOMElement $lnode */

            if( $lnode->nodeName == $tagName )
                return $lnode;
        }

        return FALSE;
    }

    /**
     * @param $tagName
     * @param DOMNode $node
     * @return bool|DOMElement
     */
    static function findLastElement($tagName, DOMNode $node)
    {
        $foundNode = null;
        foreach( $node->childNodes as $lnode )
        {
            if( $lnode->nodeType != XML_ELEMENT_NODE )
                continue;
            /** @var DOMElement $lnode */

            if( $lnode->nodeName == $tagName )
                $foundNode = $lnode;
        }

        if( $foundNode == null )
            return FALSE;
        else
            return $foundNode;
    }


    static function removeChild(DOMNode $parent, DOMNode $child)
    {
        if( $child->parentNode->isSameNode($parent) )
        {
            $parent->removeChild($child);
        }
    }

    /**
     * @param DOMElement $parent
     * @param string $tagName
     * @param null $withText
     * @return DOMElement
     */
    static function createElement(DOMElement $parent, $tagName, $withText = null)
    {
        $ret = $parent->ownerDocument->createElement($tagName);
        $ret = $parent->appendChild($ret);
        if( $withText !== null )
        {
            $tmp = $parent->ownerDocument->createTextNode($withText);
            $ret->appendChild($tmp);
        }

        return $ret;
    }


    /**
     * @param DOMElement $parent
     * @param string $tagName
     * @param null $withText
     * @return DOMElement
     */
    static function createOrResetElement(DOMElement $parent, $tagName, $withText = null)
    {
        $ret = DH::findFirstElement($tagName, $parent);

        if( $ret === FALSE )
            return DH::createElement($parent, $tagName, $withText);

        DH::clearDomNodeChilds($ret);
        if( $withText !== null )
            DH::setDomNodeText($ret, $withText);

        return $ret;
    }


    /**
     * @param string $tagName
     * @param DOMNode $node
     * @param null|string $withText
     * @return bool|DOMElement
     */
    static function findFirstElementOrCreate($tagName, DOMNode $node, $withText = null)
    {
        $ret = DH::findFirstElement($tagName, $node);

        if( $ret === FALSE )
        {
            return DH::createElement($node, $tagName, $withText);
        }

        return $ret;
    }

    /**
     * @param DOMNode $node
     * @param string $xpath
     * @return int|bool number of nodes deleted or false of XPATH is wrong
     */
    static function removeChildrenElementsMatchingXPath($xpath, DOMNode $node)
    {
        $list = DH::findXPath($xpath, $node);

        if( $list === FALSE )
            return FALSE;

        for( $i = 0; $i < $list->length; $i++ )
        {
            $item = $list->item($i);
            $item->parentNode->removeChild($item);
        }

        return $i;

    }

    /**
     * @param string $tagName
     * @param $value
     * @param DOMNode $node
     * @return DOMNode|bool
     */
    static function findFirstElementByNameAttrOrDie($tagName, $value, DOMNode $node)
    {
        foreach( $node->childNodes as $lnode )
        {
            if( $lnode->nodeName == $tagName )
            {
                $attr = $lnode->attributes->getNamedItem('name');
                if( $attr !== null )
                {
                    if( $attr->nodeValue == $value )
                        return $lnode;
                }
            }
        }

        #derr(' xml element <' . $tagName . ' name="' . $value . '"> was not found');
        return FALSE;
    }

    /**
     * @param string $tagName
     * @param $value
     * @param DOMNode $node
     * @return DOMNode|bool
     */
    static function findFirstElementByNameAttrOrCreate($tagName, $value, DOMNode $node, DOMDocument $xmlDoc1)
    {
        foreach( $node->childNodes as $lnode )
        {
            if( $lnode->nodeName == $tagName )
            {
                $attr = $lnode->attributes->getNamedItem('name');
                if( $attr !== null )
                {
                    if( $attr->nodeValue == $value )
                        return $lnode;
                }
            }
        }

        $entry = $xmlDoc1->createElement($tagName);
        $entry->setAttribute('name', $value);
        $node->appendChild($entry);

        return $entry;
    }

    /**
     * @param string $tagName
     * @param $value
     * @param DOMNode $node
     * @return DOMNode|bool
     */
    static function findFirstElementByNameAttr($tagName, $value, DOMNode $node)
    {
        foreach( $node->childNodes as $lnode )
        {
            if( $lnode->nodeName == $tagName )
            {
                $attr = $lnode->attributes->getNamedItem('name');
                if( $attr !== null )
                {
                    if( $attr->nodeValue == $value )
                        return $lnode;
                }
            }
        }

        return null;
    }

    /**
     * @param string $tagName
     * @param $value
     * @param DOMNode $node
     * @return DOMNode|bool
     */
    static function findFirstElementByValue($tagName, $value, DOMNode $node)
    {
        foreach( $node->childNodes as $lnode )
        {
            if( $lnode->nodeName == $tagName )
            {
                if( $lnode->nodeValue == $value )
                    return $lnode;
            }
        }

        return null;
    }

    /**
     * @param string $attrName
     * @param DOMElement|DOMNode $node
     * @return bool|string
     */
    static function findAttribute($attrName, DOMElement $node)
    {

        $node = $node->getAttributeNode($attrName);

        if( $node === FALSE )
            return FALSE;

        return $node->nodeValue;

    }


    /**
     * @param DOMNodeList $nodeList
     * @param int $indenting
     * @param bool $lineReturn
     * @param int $limitSubLevels
     * @return string
     */
    static function &domlist_to_xml(DOMNodeList $nodeList, $indenting = 0, $lineReturn = TRUE, $limitSubLevels = -1)
    {
        $returnString = '';
        foreach( $nodeList as $node )
        {
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $returnString .= DH::dom_to_xml($node, $indenting, $lineReturn, $limitSubLevels);
        }

        return $returnString;
    }

    /**
     * @param DOMNode $node
     * @param int $indenting
     * @param bool $lineReturn
     * @param int $limitSubLevels
     * @return string
     */
    static function &dom_to_xml(DOMNode $node, $indenting = 0, $lineReturn = TRUE, $limitSubLevels = -1, $indentingIncrement = 1)
    {
        $ind = '';
        $out = '';

        if( $limitSubLevels >= 0 && $limitSubLevels == $indenting )
            return $ind;

        $ind = str_pad('', $indenting, ' ');

        $firstTag = $ind . '<' . $node->nodeName;

        if( get_class($node) != 'DOMDocument' )
            foreach( $node->attributes as $at )
            {
                $firstTag .= ' ' . $at->name . '="' . str_replace(self::$charsToConvert, self::$charsToConvertInto, $at->value) . '"';
            }

        //$firsttag .= '>';

        $c = 0;
        $wroteChildren = FALSE;

        $tmpout = '';

        if( DH::firstChildElement($node) !== FALSE )
        {
            foreach( $node->childNodes as $n )
            {
                if( $n->nodeType != 1 ) continue;

                if( $indenting != -1 )
                    $tmpout .= DH::dom_to_xml($n, $indenting + $indentingIncrement, $lineReturn, $limitSubLevels, $indentingIncrement);
                else
                    $tmpout .= DH::dom_to_xml($n, -1, $lineReturn, $limitSubLevels);
                $wroteChildren = TRUE;
            }
        }


        if( $wroteChildren == FALSE )
        {
            if( DH::firstChildElement($node) !== FALSE || $node->textContent === null || strlen($node->textContent) < 1 )
            {
                $out .= $firstTag . "/>";
                if( $lineReturn )
                    $out .= "\n";
            }
            else
            {
                $out .= $firstTag . '>' . str_replace(self::$charsToConvert, self::$charsToConvertInto, $node->nodeValue) . '</' . $node->nodeName . ">";
                if( $lineReturn )
                    $out .= "\n";
            }
        }
        else
        {
            $out .= $firstTag . ">";
            if( $lineReturn )
                $out .= "\n";

            $out .= $tmpout . $ind . '</' . $node->nodeName . ">";
            if( $lineReturn )
                $out .= "\n";
        }

        return $out;
    }

    static private $charsToConvert = array('&', '>', '<', '"');
    static private $charsToConvertInto = array('&amp;', '&gt;', '&lt;', '&quot;');


    /**
     * @param DOMDocument $xmlDoc
     * @param string $xmlString
     * @return DOMElement
     */
    static public function importXmlStringOrDie(DOMDocument $xmlDoc, $xmlString)
    {
        $newDoc = new DOMDocument();
        if( !$newDoc->loadXML($xmlString, XML_PARSE_BIG_LINES) )
            derr('malformed xml: ' . $xmlString);

        $element = DH::firstChildElement($newDoc);
        if( $element === null or $element === FALSE )
            derr('cannot find first element in :' . $xmlString);

        $element = $xmlDoc->importNode($element, TRUE);

        return $element;

    }


    /**
     * @param DOMNode $element
     * @return string
     */
    static public function elementToPanXPath($element)
    {
        $xpath = '';

        if( $element->nodeType == XML_DOCUMENT_NODE )
            $element = DH::firstChildElement($element);

        if( $element->nodeType == 1 )
        {
            if( $element->hasAttribute('name') )
            {
                $xpath = '/' . $element->tagName . "[@name='{$element->getAttribute('name')}']";
            }
            else
                $xpath = '/' . $element->tagName;

            $parent = $element->parentNode;

            if( $parent === null )
                derr('unsupported node that has no parent (null)');


            if( $parent->nodeType == 9 || $parent->nodeType == 10 )
                return $xpath;

            $xpath = DH::elementToPanXPath($parent) . $xpath;

        }
        else
            derr('unsupported node type=' . $element->nodeType);

        return $xpath;
    }

    /**
     * @param DOMNode $element
     */
    static public function elementToPanSetCommand( $type, $element, $xpath, &$array, $multiVSYS, $debug = false )
    {
        if( $debug )
            if( $multiVSYS === TRUE )
                PH::print_stdout("multivsys enabled");
            elseif( $multiVSYS === FALSE )
                PH::print_stdout("no Multivsys");

        if( $type !== "set" && $type !== "delete" )
            return;

        if( $element->nodeType == XML_DOCUMENT_NODE )
            $element = DH::firstChildElement($element);

        //get xPATH
        #$orig_fullxpath = DH::elementToPanXPath($element);
        $orig_fullxpath = $xpath;

        if( $debug )
            PH::print_stdout( "orig_fullpath|".$orig_fullxpath."|");

        $fullpath = $orig_fullxpath;

        //for template related stuff, do not replace "config network"
        if( strpos( $fullpath, "template" ) === FALSE )
        {
            $replace = "/config";
            $fullpath = str_replace($replace, "", $fullpath);
            $replace = "/devices/entry[@name='localhost.localdomain']";
            $fullpath = str_replace($replace, "", $fullpath);
        }
        else
        {
            $replace = "/config/devices/entry[@name='localhost.localdomain']/template";
            if( strpos( $fullpath, $replace ) !== FALSE )
                $fullpath = str_replace($replace, "/template", $fullpath);

            $replace = "/config/devices/entry[@name='localhost.localdomain']";
            if( strpos( $fullpath, $replace ) !== FALSE )
                $fullpath = str_replace($replace, "/config", $fullpath);
        }


        //if FW - no multivsys - remove it
        if( $multiVSYS === False )
        {
            if($debug)
                PH::print_stdout("remove vsys1 - line 564");
            $replace = "/vsys/entry[@name='vsys1']";
            $fullpath = str_replace($replace, "", $fullpath);
        }

        $fullpath = preg_replace("/(\d+)\/(\d+)/", "$1_$2", $fullpath);
        $fullpath = str_replace("/", " ", $fullpath);
        $fullpath = str_replace("entry[@name='", '"', $fullpath);
        $fullpath = str_replace("']", '"', $fullpath);
        $fullpath = preg_replace("/(\d+)_(\d+)/", "$1/$2", $fullpath);

        $xpath = $type . $fullpath;

        if( $debug )
            PH::print_stdout( "|".$fullpath."|");

        if( strpos( $xpath, " member" ) !== FALSE )
        {
            if( strpos( $xpath, " members member" ) !== FALSE )
                $xpath = str_replace( " members member", " members", $xpath );
            elseif( strpos( $xpath, " members" ) !== FALSE )
            {

            }
            else
                $xpath = str_replace( " member", "", $xpath );
        }

        if( $element->nodeType == XML_ELEMENT_NODE ) //1
        {
            $string = "";
            self::CHILDelementToPanSetCommand( $type, $element, $array, $xpath, $string, $debug);
        }
        else
            derr('unsupported node type=' . $element->nodeType);
    }

    /**
     * @param DOMNode $element
     */
    static public function CHILDelementToPanSetCommand( $type, $element, &$array, $xpath, $string, $debug = false )
    {
        if( $debug )
        {
            print "---------------\n";
            print "0-0\n";
            print "nodename: ".$element->nodeName."\n";
            print "xpath: ".$xpath."\n";
            print "string: ".$string."\n";
        }

        if( $element->nodeType == XML_ELEMENT_NODE )
        {
            if( $debug )
            {
                print "1\n";
            }

            if( $element->nodeName == "entry" )
            {
                if( strpos( $xpath, ' "'.$element->getAttribute('name').'"' ) === FALSE )
                    $string .= ' "' . $element->getAttribute('name').'"';

                if( strpos( $xpath, "delete" ) !== FALSE )
                {
                    $finalstring = $xpath.$string;

                    self::setCommandvalidation( $finalstring, $array, $debug);

                    return;
                }
            }
            else
            {
                if( strpos( $xpath, " ".$element->nodeName ) === FALSE )
                {
                    if( $debug )
                    {
                        print "1-1\n";
                        print "nodename: ".$element->nodeName."\n";
                        print "xpath: ".$xpath."\n";
                        print "string: ".$string."\n";
                    }

                    if( $element->nodeName !== "member" )
                        $string .= " ".$element->nodeName;
                    elseif( strpos( $xpath, " list" ) !== FALSE || strpos( $string, " list" ) !== FALSE )
                    {
                        //validation check - this is needed for custom url
                    }
                    else
                    {
                        if( $debug )
                        {
                            print "1-1\n";
                            print "nodename: ".$element->nodeName."\n";
                            print "xpath: ".$xpath."\n";
                            print "string: ".$string."\n";
                        }

                        if( strpos( $xpath, "delete" ) !== FALSE
                            &&(
                                (
                                    strpos( $xpath, "address-group" ) !== FALSE
                                    && (
                                        strpos( $xpath, "static" ) === FALSE
                                        && strpos( $xpath, "dynamic" ) === FALSE
                                    )
                                )
                                || (
                                    strpos( $xpath, "rule" ) !== FALSE
                                    && (
                                        strpos( $xpath, "source" ) === FALSE
                                        && strpos( $xpath, "destination" ) === FALSE
                                        && strpos( $xpath, "service" ) === FALSE
                                        && strpos( $xpath, "tag" ) === FALSE
                                        && strpos( $xpath, "from" ) === FALSE
                                        && strpos( $xpath, "to" ) === FALSE
                                    )
                                )
                            )
                        )
                        {
                            $finalstring = $xpath.$string;

                            if( $debug )
                            {
                                print "1-2\n";
                                print "finalstring: ".$finalstring."\n";
                            }

                            self::setCommandvalidation( $finalstring, $array, $debug);

                            return;
                        }
                    }
                }
            }


            foreach( $element->childNodes as $childElement )
            {
                #print "xpath: ".$xpath."\n";
                #print "string: ".$string."\n";
                self::CHILDelementToPanSetCommand( $type, $childElement, $array, $xpath, $string, $debug );
            }

            if( $element->hasChildNodes() === FALSE )
            {
                $finalstring = $xpath.$string;

                if( $debug )
                    print "1-3\n";

                self::setCommandvalidation( $finalstring, $array, $debug);
            }
        }
        else
        {
            if( $debug )
                print "2\n";

            if( $element->nodeName == "#text" && strpos( $xpath, "delete" ) !== FALSE )
            {
                if( strpos( $xpath, " local-address ip ipv4" ) !== FALSE || strpos( $xpath, " local-address ip ipv6" ) !== FALSE )
                {
                    if( $debug )
                        print "2-1\n";

                    $finalstring = $xpath;

                    self::setCommandvalidation( $finalstring, $array, $debug);

                    return;
                }
            }

            if( trim($element->nodeValue) !== '')
            {
                if( $debug )
                    print "2-2\n";

                $value = $element->nodeValue;
                if(strstr($value, PHP_EOL))
                    $value = str_replace(PHP_EOL,"^M",$value);

                if( strpos( $element->nodeValue, " " ) !== FALSE )
                    $finalstring =  $xpath.$string.' "'.$value.'"';
                else
                    $finalstring = $xpath.$string.' '.$value;

                if( $debug )
                    print "finalstring: ".$finalstring."\n";

                self::setCommandvalidation( $finalstring, $array, $debug);
            }
        }
    }

    /**
     * @param string $finalstring
     * @param array $array
     **/
    static public function setCommandvalidation( $finalstring, &$array, $debug = false )
    {
        if( strpos($finalstring, "set ") !== FALSE
            && strpos($finalstring, " profiles zone-protection-profile ") !== FALSE
            && strpos($finalstring, " flood ") !== FALSE
        )
        {
            //fixed in DIFF
            //$finalstring = "";
        }

        if( strpos($finalstring, "delete ") !== FALSE
            && (strpos($finalstring, " security rules ") !== FALSE || strpos($finalstring, " default-security-rules rules ") !== FALSE)
            && strpos($finalstring, " log-end no") !== FALSE
        )
        {
            //Problem security rules - log-end no - not allowed
            $finalstring = "";
        }

        if( strpos( $finalstring, "delete" ) !== FALSE
            && strpos( $finalstring, " profile-setting group" ) !== FALSE
        )
        {
            $finalstring = str_replace( " profile-setting group", " profile-setting", $finalstring );
        }


        if( !empty( $finalstring ) )
        {
            if( $debug )
                PH::print_stdout($finalstring);
            $array[] = $finalstring;
        }

    }

    /**
     * @param string $xpathString
     * @param DOMDocument|DOMNode $contextNode
     * @return DOMNode
     */
    static public function findXPathSingleEntryOrDie($xpathString, $contextNode)
    {
        $nodes = DH::findXPath($xpathString, $contextNode);

        if( $nodes === FALSE )
            derr("XPath query evaluation error for '{$xpathString}'");

        if( $nodes->length == 0 )
            derr("no matching node found for xpath '{$xpathString}'", $contextNode);

        if( $nodes->length > 1 )
            derr("more than 1 matching node found for xpath '{$xpathString}'");

        return $nodes->item(0);

    }

    /**
     * @param string $xpathString
     * @param DOMDocument|DOMNode $contextNode
     * @return DOMNode|bool returns FALSE if not found
     */
    static public function findXPathSingleEntry($xpathString, $contextNode)
    {
        $nodes = DH::findXPath($xpathString, $contextNode);

        if( $nodes === FALSE )
            derr("XPath query evaluation error for '{$xpathString}'");

        if( $nodes->length == 0 )
            return FALSE;

        if( $nodes->length > 1 )
            derr("more than 1 matching node found for xpath '{$xpathString}'");

        return $nodes->item(0);
    }


    /**
     * return
     * @param string|array $xpathString
     * @param DOMDocument|DOMNode $contextNode
     * @return DOMNodeList|bool
     */
    static public function findXPath($xpathString, $contextNode)
    {
        if( is_array( $xpathString ) )
            $xpathString = implode( " | ", $xpathString);

        if( $contextNode->nodeType == XML_DOCUMENT_NODE || $contextNode->nodeType == XML_HTML_DOCUMENT_NODE )
        {
            $xpath = new DOMXpath($contextNode);
            $nodes = $xpath->query($xpathString);
        }
        elseif( $contextNode->parentNode->nodeType == XML_DOCUMENT_NODE )
        {
            $xpath = new DOMXpath($contextNode->parentNode);
            $nodes = $xpath->query($xpathString);
        }
        else
        {
            $xpathString = '.' . $xpathString;
            $xpath = new DOMXpath($contextNode->ownerDocument);
            $nodes = $xpath->query($xpathString, $contextNode);
        }

        return $nodes;
    }


    /**
     * @param DOMElement $source
     * @param DOMElement $target
     * @return int
     * @throws Exception
     */
    static public function moveChildElementsToNewParentNode(DOMElement $source, DOMElement $target)
    {
        $sourceOwner = $source->ownerDocument;
        $targetOwner = $target->ownerDocument;

        if( !$sourceOwner->isSameNode($targetOwner) )
            derr('source and target must be part of same XML Document');

        if( $source->nodeType != XML_ELEMENT_NODE )
            derr('source is not an Element type node');

        if( $target->nodeType != XML_ELEMENT_NODE )
            derr('target is not an Element type node');

        $toMove = array();

        foreach( $source->childNodes as $child )
        {
            if( $child->nodeType != XML_ELEMENT_NODE )
                continue;
            $toMove[] = $child;
        }

        foreach( $toMove as $child )
        {
            $target->appendChild($child);
        }

        return count($toMove);

    }


    /**
     * @param DOMElement $source
     * @param DOMElement $target
     * @return int
     * @throws Exception
     */
    static public function copyChildElementsToNewParentNode(DOMElement $source, DOMElement $target)
    {
        $sourceOwner = $source->ownerDocument;
        $targetOwner = $target->ownerDocument;

        $exoCopy = FALSE;

        if( !$sourceOwner->isSameNode($targetOwner) )
        {
            $source = $targetOwner->importNode($source, TRUE);
            $exoCopy = TRUE;
        }

        if( $source->nodeType != XML_ELEMENT_NODE )
            derr('source is not an Element type node');

        if( $target->nodeType != XML_ELEMENT_NODE )
            derr('target is not an Element type node');

        $toMove = array();

        $count = 0;

        $children = array();

        foreach( $source->childNodes as $child )
        {
            if( $child->nodeType != XML_ELEMENT_NODE )
                continue;

            $count++;
            /** @var DOMElement $child */
            $target->appendChild($child->cloneNode(TRUE));
        }

        return count($toMove);
    }

    static public function DEBUGprintDOMDocument( $node )
    {
        if( $node != null )
        {
            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($node, true);
            $newdoc->appendChild($node);

            $lineReturn = TRUE;
            $indentingXmlIncreament = 1;
            $indentingXml = 0;
            $xml = &DH::dom_to_xml($newdoc->documentElement, $indentingXml, $lineReturn, -1, $indentingXmlIncreament);
            print $xml;
            #print $newdoc->saveXML($newdoc->documentElement);
        }

    }

    static public function XMLstringToPrettyDOMDocument( &$string )
    {
        if( !empty($string) )
        {
            $newdoc = new DOMDocument;
            $node = $newdoc->loadXML($string, true);
            #$newdoc->appendChild($node);

            $lineReturn = TRUE;
            $indentingXmlIncreament = 1;
            $indentingXml = 0;
            $xml = &DH::dom_to_xml($newdoc->documentElement, $indentingXml, $lineReturn, -1, $indentingXmlIncreament);
            //print $xml;
            $string = $xml;
        }

    }

    static public function hasChild($p)
    {
        if( $p->hasChildNodes() )
        {
            foreach( $p->childNodes as $c )
            {
                if( $c->nodeType == XML_ELEMENT_NODE )
                    return TRUE;
            }
        }
        return false;
    }

    static public function getXpathDisplay( &$string, $xmlDoc, $xpath, $serial, $entry = false, $actions = "display" )
    {
        $padding = "   ";
        global $jsonArray;

        $string .= "\n";

        $text_contains_search = false;

        PH::$JSON_TMP[$serial]['serial'] = $serial;
        //check Xpath
        $xpathResult = DH::findXPath( $xpath, $xmlDoc);
        $tmp_string = "  * XPATH: " . $xpath;
        $string .= $padding . $tmp_string . "\n";
        //PH::print_stdout( $tmp_string );

        if( strpos($xpath, "[text()") !== FALSE )
            $text_contains_search = true;

        PH::$JSON_TMP[$serial]['xpath'] = $xpath;

        foreach( $xpathResult as $xpath1 )
        {
            if($text_contains_search)
            {
                /** @var DOMElement $xpath1 */
                $string .= "\n";
                //PH::print_stdout();
                $nodePath = $xpath1->getNodePath();

                $tmp_string = "   * XPATH: ".$nodePath;
                $string .= $padding.$tmp_string."\n";
                //PH::print_stdout( $tmp_string );

                $tmpArray = explode("]", $nodePath);
                $tmp_path = "";
                foreach( $tmpArray as $key => $path_tmp )
                {
                    if( strpos($path_tmp, "[") === FALSE )
                        continue;

                    if( !empty($path_tmp) )
                    {
                        $newstring = substr($path_tmp, -7);
                        if( strpos( $newstring, "[" ) !== false )
                            $tmp_path .= $path_tmp."]";

                        $xpathResult = DH::findXPath( $tmp_path, $xmlDoc);
                        if( $xpathResult[0]->hasAttribute('name') )
                        {
                            $tmp_string = "    - "."entry[@name='".$xpathResult[0]->getAttribute('name')."']";
                            $string .= $padding.$tmp_string."\n";
                            //PH::print_stdout( $tmp_string );
                        }
                        else
                        {
                            $tmp_string = "    - ".$xpathResult[0]->nodeName;
                            $string .= $padding.$tmp_string."\n";
                            //PH::print_stdout( $tmp_string );
                        }
                    }
                }
            }

            $newdoc = new DOMDocument;
            $node = $newdoc->importNode($xpath1, true);
            $newdoc->appendChild($node);

            if( $entry === false )
            {
                $lineReturn = TRUE;
                $indentingXmlIncreament = 3;
                $indentingXml = 0;
                $xml = &DH::dom_to_xml($newdoc->documentElement, $indentingXml, $lineReturn, -1, $indentingXmlIncreament);

                $tmp_string = $padding."      * VALUE: ";
                $string .= $padding.$tmp_string."\n";
                //PH::print_stdout( $tmp_string );
                $xml = str_replace( "\n", "\n".$padding."           ", $xml );
                $tmp_string = $padding."           ".$xml;
                $string .= $tmp_string."\n";
                //PH::print_stdout( $xml );
                PH::$JSON_TMP[$serial]['value'] = $xml;
            }
            else
            {
                foreach( $node->childNodes as $child )
                {
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;
                    if( $child->getAttribute('name') !== "" )
                    {
                        $tmp_string = "     - name: ". $child->getAttribute('name');
                        $string .= $padding.$tmp_string."\n";
                        //PH::print_stdout( $tmp_string );
                    }
                }
            }


            if( $actions === "remove" )
            {
                PH::print_stdout("remove xpath!!!");
                $xpath1->parentNode->removeChild($xpath1);
            }

            if( strpos( $actions, 'set-text:' ) !== FALSE )
            {
                $array = explode( ":", $actions );
                if( isset( $array[1] ) )
                {
                    $tmpText = $array[1];
                    PH::print_stdout("set xpath Text: ".$array[1]);
                    $xpath1->textContent = $array[1];

                    DH::DEBUGprintDOMDocument($xpath1);
                }
            }

            if( strpos( $actions, 'manipulate:' ) !== FALSE )
            {
                print_r($jsonArray);
            }

        }


        #if( count($xpathResult) > 0 )
        #    PH::print_stdout($string);
        if( count($xpathResult) == 0 )
            $string = "";
    }

    static public function getXpathDisplayMain( &$string, $xmlDoc, $qualifiedNodeName, $nameattribute, $xpath, $displayXMLnode, $displayAttributeName, $displayXMLlineno, $fullxpath, $displayAPIcommand, $pan, $own_xpath = null )
    {
        $padding = "   ";

        $string .= "\n";

        $nodeList = $xmlDoc->getElementsByTagName($qualifiedNodeName);
        $nodeArray = iterator_to_array($nodeList);

        $templateEntryArray = array();
        foreach( $nodeArray as $item )
        {
            if( $nameattribute !== null )
            {
                $XMLnameAttribute = DH::findAttribute("name", $item);
                if( $XMLnameAttribute === FALSE )
                    continue;

                if( $XMLnameAttribute !== $nameattribute )
                    continue;
            }
            $text = DH::elementToPanXPath($item);
            $replace_template = "/config/devices/entry[@name='localhost.localdomain']/template/";

            if( $xpath !== null && strpos($text, $xpath) === FALSE )
                continue;

            if( strpos($text, $replace_template) !== FALSE )
            {
                $tmpArray['xpath'] = $text;
                $text = str_replace($replace_template, "", $text);

                $templateXpathArray = explode("/", $text);

                $templateName = str_replace("entry[@name='", "", $templateXpathArray[0]);
                $templateName = str_replace("']", "", $templateName);

                $replace = "entry[@name='" . $templateName . "']";
                $text = str_replace($replace, "", $text);

                $tmpArray['text'] = $text;
                $tmpArray['node'] = $item;
                $tmpArray['line'] = $item->getLineNo();

                $templateEntryArray['template'][$templateName][] = $tmpArray;

            }
            else
            {
                $tmpArray['text'] = $text;
                $tmpArray['node'] = $item;
                $tmpArray['line'] = $item->getLineNo();

                $templateEntryArray['misc'][] = $tmpArray;
            }

        }


        if( isset($templateEntryArray['template']) )
        {
            foreach( $templateEntryArray['template'] as $templateName => $templateEntry )
            {
                //$string .= "\n";
                //PH::print_stdout();
                $tmp_string = "TEMPLATE: " . $templateName;
                $string .= $padding.$tmp_string."\n";
                //PH::print_stdout($tmp_string);
                foreach( $templateEntry as $item )
                {
                    $xpath = $item['xpath'];
                    //$string .= "\n";
                    //PH::print_stdout();
                    //PH::print_stdout("---------");
                    if( !$displayXMLnode && !$displayAttributeName )
                    {
                        $tmp_string = "   * XPATH: ".$xpath;
                        $string .= $padding.$tmp_string."\n";
                    }


                    if( $displayXMLlineno )
                    {
                        $tmp_string = "   * line: ".$item['line'];
                        $string .= $padding.$tmp_string."\n";
                    }

                    if( $fullxpath )
                    {
                        $tmp_string = "     |" . $xpath . "|";
                        $string .= $padding.$tmp_string."\n";
                    }


                    if( $displayXMLnode )
                    {
                        $tmp_string = "";
                        DH::getXpathDisplay( $tmp_string, $xmlDoc, $xpath, "test", false, "display");
                        $string .= $tmp_string;
                    }

                    if( $displayAttributeName )
                    {
                        $tmp_string = "";
                        DH::getXpathDisplay( $tmp_string, $xmlDoc, $xpath, "test", true, "display");
                        $string .= $tmp_string;
                    }

                }

                $string .= "\n";
            }
        }

        if( isset($templateEntryArray['misc']) )
        {
            //$tmp_string = "MISC:";
            //$string .= $padding.$tmp_string."\n";
            //PH::print_stdout($tmp_string);

            foreach( $templateEntryArray['misc'] as $miscEntry )
            {
                $xpath = $miscEntry['text'];

                //$string .= "\n";
                //PH::print_stdout();
                //PH::print_stdout("---------");

                if( !$displayXMLnode && !$displayAttributeName )
                {
                    if( $own_xpath !== null )
                    {
                        if( $own_xpath !== $xpath )
                        {
                            $tmp_string = "   * XPATH: ".$xpath ;
                            $string .= $padding.$tmp_string."\n";
                        }
                    }
                    else
                    {
                        $tmp_string = "   * XPATH: ".$xpath ;
                        $string .= $padding.$tmp_string."\n";
                    }
                }

                if( $displayXMLlineno )
                {
                    $tmp_string = "   * line: ".$miscEntry['line'];
                    $string .= $padding.$tmp_string."\n";
                }

                if( $displayXMLnode )
                {
                    $tmp_string = "";
                    DH::getXpathDisplay( $tmp_string, $xmlDoc, $xpath, "test", false, "display");
                    $string .= $tmp_string;
                }
                if( $displayAttributeName )
                {
                    $tmp_string = "";
                    DH::getXpathDisplay( $tmp_string, $xmlDoc, $xpath, "test", true, "display");
                    $string .= $tmp_string;
                }


                if( $displayAPIcommand )
                {
                    $splitXPATH = explode( "/", PH::$JSON_TMP["test"]["xpath"] );
                    array_pop($splitXPATH);
                    $newXpath = "";
                    foreach( $splitXPATH as $entry )
                    {
                        $newXpath .= "/".$entry;
                    }
                    $newXpath = str_replace("//", "/", $newXpath);
                    $newValue = str_replace("\n", "", PH::$JSON_TMP["test"]["value"]);

                    if( $pan->connector !==  null )
                    {
                        $FIREWALL_IP = $pan->connector->apihost;
                        $APIkey = $pan->connector->apikey;
                    }
                    else
                    {
                        $FIREWALL_IP = "{FW-MGMT-IP}\n";
                        $APIkey = "{API-KEY}\n";
                    }


                    $string .= "----------------";
                    $string .= "https://".$FIREWALL_IP."/api/?"."key=".$APIkey."\n&type=config&action=set&xpath=".$newXpath."\n&element=".$newValue ;
                    $string .= "----------------";
                }
            }
        }
    }


    //todo: 20210615 swaschkut
    //merge two XML node // DomDocument
}

