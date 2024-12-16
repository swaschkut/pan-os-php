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

class Sub
{
    public $owner = null;

    public $rulebaseroot;
    public $defaultSecurityRules;
    public $defaultIntraZoneRuleSet = False;
    public $defaultInterZoneRuleSet = False;

    private  $defaultSecurityRules_xml = "<default-security-rules>
                    <rules>
                      <entry name=\"intrazone-default\">
                        <action>allow</action>
                        <log-start>no</log-start>
                        <log-end>no</log-end>
                      </entry>
                      <entry name=\"interzone-default\">
                        <action>deny</action>
                        <log-start>no</log-start>
                        <log-end>no</log-end>
                      </entry>
                    </rules>
                  </default-security-rules>";

    function load_defaultSecurityRule( )
    {

        $finalroot = FALSE;
        $tmproot = DH::findFirstElement('default-security-rules', $this->rulebaseroot);
        if( $tmproot !== FALSE )
        {
            $finalroot = DH::findFirstElement('rules', $tmproot);
            if( $finalroot !== FALSE )
            {
                //Todo: only load if not already loaded earlier
                if( $this->owner === null )
                {

                }
                elseif( get_class($this->owner) == "PanoramaConf" )
                    $finalroot = $this->createPartialDefaultSecurityRule( $finalroot );
                elseif( get_class($this->owner) == "DeviceGroup" )
                {
                    //Todo: not working if empty
                    //$finalroot = $this->createPartialDefaultSecurityRule( $finalroot );
                }
                elseif( get_class($this->owner) == "PANConf" )
                {
                    //Todo: swaschkut 20240320
                    //is it possible to define default security rules at Firewall shared?
                }
                elseif( get_class($this->owner) == "VirtualSystem" )
                {
                    //Todo: not working if empty - need better validation
                    //$finalroot = $this->createPartialDefaultSecurityRule( $finalroot );
                }
            }
        }

        //Todo: check if any of the parentDG has already defaultSec set, if not create it
        if( $tmproot === FALSE )
        {
            if( $this->owner !== null && get_class($this->owner) == "PanoramaConf" )
                $finalroot = $this->createDefaultSecurityRule( );
        }

        return $finalroot;
    }

    function createDefaultSecurityRule( )
    {
        $ownerDocument = $this->rulebaseroot->ownerDocument;

        $newdoc = new DOMDocument;
        $newdoc->loadXML( $this->defaultSecurityRules_xml, XML_PARSE_BIG_LINES);
        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
        $node = $ownerDocument->importNode($node, TRUE);

        $node = $this->rulebaseroot->appendChild($node);

        $ruleNode = DH::findFirstElement('rules', $node);

        return $ruleNode;
    }

    function createPartialDefaultSecurityRule( $originalRuleNode )
    {
        $ownerDocument = $this->rulebaseroot->ownerDocument;

        //todo: swaschkut 20240320
        // this need to be improved, if originalRulenode is empty, there is no need to add it
        if( get_class($this->owner) !== "PanoramaConf" )
        {
            if( $originalRuleNode->hasChildNodes() === FALSE )
                return null;
        }

        $newdoc = new DOMDocument;
        $newdoc->loadXML( $this->defaultSecurityRules_xml, XML_PARSE_BIG_LINES);
        $node = $newdoc->importNode($newdoc->firstChild, TRUE);
        $ruleNode = DH::findFirstElement('rules', $node);

        foreach( $ruleNode->childNodes as $defaultRule )
        {
            /** @var DOMElement $defaultRule */
            if( $defaultRule->nodeType != XML_ELEMENT_NODE )
                continue;

            $newName = DH::findAttribute( 'name', $defaultRule);
            $origName = DH::findFirstElementByNameAttr( "entry", $newName, $originalRuleNode);
            if( $origName === FALSE || $origName === null )
            {
                $node = $ownerDocument->importNode($defaultRule, TRUE);
                $originalRuleNode->appendChild($node);
            }
        }
        return $originalRuleNode;
    }
}

