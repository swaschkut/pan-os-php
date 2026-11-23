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
 * SCM knowledge that does not belong to one tool: used by the import of a Panorama / firewall configuration, by
 * scm_pa_xml_to_change.php (pan-os-php on an SCM export of one tenant) and by the SCM best-practice actions.
 * (The Panorama / firewall import itself belongs to the plug-in scm-migration.)
 */
class SCMCommon
{
    /**
     * sections of security profiles (XML type => paths) the public SCM API does not have - written through the
     * internal UI API (_internal); also: rules with action 'default' (vulnerability / spyware), see stripInternalGaps()
     */
    const INTERNAL_GAPS = array(
        'vulnerability' => array('mica-engine-vulnerability-enabled', 'cloud-inline-analysis'),
        'spyware' => array('mica-engine-spyware-enabled/entry/local-deep-learning'),
        'dns-security' => array('botnet-domains/advanced-dns-security-categories'),
        'virus-and-wildfire-analysis' => array('decoder', 'mlav-engine-filebased-enabled', 'cloud-inline-analysis', 'mica-engine-wildfire-rules'),
    );

    /** XML profile type => SCM resource / internal UI API prefix */
    const INTERNAL_GAP_RESOURCES = array(
        'vulnerability' => 'vulnerability-protection-profiles',
        'spyware' => 'anti-spyware-profiles',
        'dns-security' => 'dns-security-profiles',
        'virus-and-wildfire-analysis' => 'wildfire-anti-virus-profiles',
    );

    /**
     * removes the sections of INTERNAL_GAPS[$type] from the profile entry; rule action 'default': the public API
     * refuses an empty action (live: "action is missing") and has no 'default' -> the whole rules element goes
     * through the internal UI API only
     * @return string[] removed sections (empty: nothing to complete through the internal UI API)
     */
    public static function stripInternalGaps( DOMXPath $xp, DOMElement $prof, $type )
    {
        $removed = array();
        if( $type == 'vulnerability' || $type == 'spyware' )
        {
            if( $xp->query("rules/entry/action/default", $prof)->length > 0 && ($rulesNode = DH::findFirstElement('rules', $prof)) !== FALSE )
            {
                $prof->removeChild($rulesNode);
                $removed['rules (action default)'] = TRUE;
            }
        }
        foreach( isset(self::INTERNAL_GAPS[$type]) ? self::INTERNAL_GAPS[$type] : array() as $path )
            foreach( $xp->query($path, $prof) as $n )
            {
                $n->parentNode->removeChild($n);
                $removed[$path] = TRUE;
            }
        return array_keys($removed);
    }

    /**
     * PAN-OS XML entry -> JSON structure of the internal UI API (/api/config/v9.2): name attribute -> "@name",
     * <entry> children -> {"entry": [...]}, <member> children -> {"member": [...]}, text -> string, empty -> {}
     */
    static public function domToInternal(DOMElement $node, $top = TRUE)
    {
        $out = array();
        if( $node->hasAttribute('name') )
            $out['@name'] = $node->getAttribute('name');
        $children = array();
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                $children[] = $c;
        if( empty($children) && !$node->hasAttribute('name') )
        {
            $text = trim($node->textContent);
            return $text === '' ? new stdClass() : $text;
        }
        $tags = array();
        foreach( $children as $c )
            $tags[$c->tagName][] = $c;
        foreach( $tags as $tag => $list )
        {
            if( $tag == 'entry' || $tag == 'member' )
            {
                $items = array();
                foreach( $list as $c )
                    $items[] = $tag == 'member' ? trim($c->textContent) : self::domToInternal($c, FALSE);
                $out[$tag] = $items;
            }
            else
                $out[$tag] = self::domToInternal($list[0], FALSE);
        }
        return $out;
    }
    /** log types of the match lists added to log forwarding profiles without match list (Strata Logging Service) */
    const SLS_LOG_TYPES = array('traffic', 'threat', 'wildfire', 'url', 'data', 'tunnel', 'auth', 'decryption');
}
