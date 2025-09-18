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

class LogProfile
{
    use AddressCommon;
    use PathableName;
    use XmlConvertible;

    /** @var LogProfileStore|null */
    public $owner = null;

    public $type = null;
    public $type_available = null;

    /**
     * @param string $name
     * @param LogProfileStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->name = $name;
        //before PAN-OS 10.0
        //$this->type_available = array('auth', 'data', 'decryption', 'threat', 'traffic', 'tunnel', 'url', 'wildfire');
        $this->type_available = array('auth', 'data', 'decryption', 'threat', 'traffic', 'tunnel', 'url', 'wildfire');
        //PAN-OS 12.1 and above
        //$this->type_available = array('auth', 'data', 'decryption', 'dns-security', 'threat', 'traffic', 'tunnel', 'url', 'wildfire');
        foreach( $this->type_available as $type )
            $this->type[$type] = array('notSet'=>'--');

        if( $fromXmlTemplate )
        {
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml, XML_PARSE_BIG_LINES);

            $node = DH::findFirstElementOrDie('entry', $doc);

            $rootDoc = $owner->xmlroot->ownerDocument;

            $this->xmlroot = $rootDoc->importNode($node, TRUE);
            $this->load_from_domxml($this->xmlroot);

            $this->setName($name);
        }

        $this->owner = $owner;
    }

    /**
     * @param string $newName
     * @return bool
     */
    public function setName($newName)
    {
        $ret = $this->setRefName($newName);

        if( $this->xmlroot === null )
            return $ret;

        $this->xmlroot->setAttribute('name', $newName);

        return $ret;
    }

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
        $c = findConnectorOrDie($this);
        $xpath = $this->getXPath();

        $this->setName($newName);

        if( $c->isAPI() )
            $c->sendRenameRequest($xpath, $newName);
    }


    /**
     * @return string
     */
    public function &getXPath()
    {
        $str = $this->owner->getLogProfileStoreXPath() . "/entry[@name='" . $this->name . "']";

        return $str;
    }


    public function isTmp()
    {
        if( $this->xmlroot === null )
            return TRUE;
        return FALSE;
    }


    public function load_from_domxml(DOMElement $xml)
    {
        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("LogProfile name not found\n", $xml);


        if( strlen($this->name) < 1 )
            derr("LogProfile name '" . $this->name . "' is not valid.", $xml);


        $tmp_match_list_node = DH::findFirstElement('match-list', $xml);
        if( $tmp_match_list_node !== FALSE )
        {
            foreach( $tmp_match_list_node->childNodes as $node )
            {
                if( $node->nodeType != 1 )
                    continue;
                $name = DH::findAttribute('name', $node);

                $tmp_log_type_node = DH::findFirstElement('log-type', $node);
                $log_type_text = $tmp_log_type_node->textContent;
                unset( $this->type[$log_type_text]['notSet'] );
                $this->type[$log_type_text][$name] = array();
                if( $tmp_log_type_node !== FALSE )
                {
                    $tmp_filter_node = DH::findFirstElement('filter', $node);
                    if( $tmp_filter_node !== FALSE )
                        $this->type[$log_type_text][$name]['filter'] = $tmp_filter_node->textContent;

                    $tmp_send_to_panorama_node = DH::findFirstElement('send-to-panorama', $node);
                    if( $tmp_send_to_panorama_node !== FALSE )
                        $this->type[$log_type_text][$name]['send-to-panorama'] = $tmp_send_to_panorama_node->textContent;

                    $tmp_quarantine_node = DH::findFirstElement('quarantine', $node);
                    if( $tmp_quarantine_node !== FALSE )
                        $this->type[$log_type_text][$name]['quarantine'] = $tmp_quarantine_node->textContent;
                }
            }
        }
        /*
         <entry name="Panorama" loc="shared">
             <match-list loc="shared">
              <entry name="traffic" loc="shared">
               <log-type loc="shared">traffic</log-type>
               <filter loc="shared">All Logs</filter>
               <send-to-panorama loc="shared">yes</send-to-panorama>
               <quarantine loc="shared">no</quarantine>
              </entry>
              <entry name="threat" loc="shared">
               <log-type loc="shared">threat</log-type>
               <filter loc="shared">All Logs</filter>
               <send-to-panorama loc="shared">yes</send-to-panorama>
               <quarantine loc="shared">no</quarantine>
              </entry>
              <entry name="data" loc="shared">
               <log-type loc="shared">data</log-type>
               <filter loc="shared">All Logs</filter>
               <send-to-panorama loc="shared">yes</send-to-panorama>
               <quarantine loc="shared">no</quarantine>
              </entry>
             </match-list>
          </entry>
         */
    }




    static public $templatexml = '<entry name="**temporarynamechangeme**"></entry>';

    public function isLogProfile()
    {
        return TRUE;
    }


    /**
     * @param $otherObject LogProfile
     * @return bool
     */
    public function equals($otherObject)
    {
        if( !$otherObject->isLogProfile() )
            return FALSE;

        if( $otherObject->name != $this->name )
            return FALSE;

        return $this->sameValue($otherObject);
    }

    public function sameValue(LogProfile $otherObject)
    {
        if( $this->isTmp() && !$otherObject->isTmp() )
            return FALSE;

        if( $otherObject->isTmp() && !$this->isTmp() )
            return FALSE;


        return TRUE;
    }

    public function type()
    {
        if( $this->isTmp() )
            return null;


        return $this->type;
    }
    public function url()
    {
        return $this->url;
    }

    public function recurring()
    {
        return $this->recurring;
    }
}

