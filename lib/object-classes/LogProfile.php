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

    /** set by the mergers (type=object-merger) */
    public $ancestor;
    public $childancestor;

    public $type = null;
    public $type_available = null;

    public $enhanced_application_logging = null;

    /**
     * @param string $name
     * @param LogProfileStore|null $owner
     * @param bool $fromXmlTemplate
     */
    public function __construct($name, $owner, $fromXmlTemplate = FALSE)
    {
        $this->name = $name;

        //with 810,910,100,121 there was also gtp,sctp??
        if( isset($owner->owner->version) )
        {
            if( $owner->owner->version < 100 )
                $this->type_available = array('auth', 'data', 'threat', 'traffic', 'tunnel', 'url', 'wildfire');
            elseif( $owner->owner->version >= 100 and $owner->owner->version < 120)
                $this->type_available = array('auth', 'data', 'decryption', 'threat', 'traffic', 'tunnel', 'url', 'wildfire');
            elseif( $owner->owner->version >= 120 )
                $this->type_available = array('auth', 'data', 'decryption', 'dns-security', 'threat', 'traffic', 'tunnel', 'url', 'wildfire');
        }
        else
            $this->type_available = array('auth', 'data', 'decryption', 'dns-security', 'threat', 'traffic', 'tunnel', 'url', 'wildfire');

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


                    $tmp_send_snmptrap_node = DH::findFirstElement('send-snmptrap', $node);
                    if( $tmp_send_snmptrap_node !== FALSE )
                        foreach( $tmp_send_snmptrap_node->childNodes as $node2 )
                        {
                            if ($node2->nodeType != 1)
                                continue;

                            $this->type[$log_type_text][$name]['send-snmptrap'][$node2->textContent] = $node2->textContent;
                        }

                    $tmp_send_email_node = DH::findFirstElement('send-email', $node);
                    if( $tmp_send_email_node !== FALSE )
                        foreach( $tmp_send_email_node->childNodes as $node2 )
                        {
                            if ($node2->nodeType != 1)
                                continue;

                            $this->type[$log_type_text][$name]['send-email'][$node2->textContent] = $node2->textContent;
                        }

                    $tmp_send_syslog_node = DH::findFirstElement('send-syslog', $node);
                    if( $tmp_send_syslog_node !== FALSE )
                        foreach( $tmp_send_syslog_node->childNodes as $node2 )
                        {
                            if ($node2->nodeType != 1)
                                continue;

                            $this->type[$log_type_text][$name]['send-syslog'][$node2->textContent] = $node2->textContent;
                        }

                    $tmp_send_http_node = DH::findFirstElement('send-http', $node);
                    if( $tmp_send_http_node !== FALSE )
                        foreach( $tmp_send_http_node->childNodes as $node2 )
                        {
                            if ($node2->nodeType != 1)
                                continue;

                            $this->type[$log_type_text][$name]['send-http'][$node2->textContent] = $node2->textContent;
                        }
                }
            }
        }

        //          <enhanced-application-logging>yes</enhanced-application-logging>
        $tmp_enhanced_application_logging = DH::findFirstElement('enhanced-application-logging', $xml);
        if( $tmp_enhanced_application_logging !== FALSE )
            $this->enhanced_application_logging = $tmp_enhanced_application_logging->textContent;
        else
        {
            if( $this->owner->owner->version > 81 )
                $this->enhanced_application_logging = "no";
        }

        /*
        //Todo: 20260725
        //additional information needed
        <entry name="default">
          <match-list>
            <entry name="traffic">
              <send-snmptrap>
                <member>1.2.3.4</member>
              </send-snmptrap>
              <send-email>
                <member>4.3.2.1</member>
              </send-email>
              <send-syslog>
                <member>1.2.4.3</member>
              </send-syslog>
              <send-http>
                <member>4.3.1.2</member>
              </send-http>
            </entry>
        ====================
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




    static public $templatexml = '<entry name="**temporarynamechangeme**"><match-list/></entry>';

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

    public function add_log_filter( $logType, $name, $filter = "All Logs", $sendToPanorama = true )
    {
        unset( $this->type[$logType]['notSet'] );
        $this->type[$logType][$name] = array();
        $this->type[$logType][$name]['filter'] = $filter;

        $this->type[$logType][$name]['send_to_panorama'] = $sendToPanorama;

    }

    /**
     * Base XML of the iron-skillet log forwarding profile 'default'
     * (iron-skillet templates/panorama/snippets/log_settings_profiles.xml):
     * every log type sent to Panorama.
     * - 11.2 and later: also decryption
     * - 12.1 and later: also dns-security
     *
     * @param string $version iron-skillet PAN-OS version folder, e.g. "11.1"
     * @return string
     */
    public static function ironSkilletXml( $version )
    {
        if( !in_array( $version, array( '10.0', '10.1', '10.2', '11.0', '11.1', '11.2', '12.1' ), TRUE ) )
        {
            derr( "iron-skillet log forwarding profiles are not available for PAN-OS version '" . $version . "'", null, false );
            return null;
        }

        // match list entry => log type
        $logTypes = array(
            'Traffic_Log_Forwarding' => 'traffic',
            'Threat_Log_Forwarding' => 'threat',
            'Wildfire_Log_Forwarding' => 'wildfire',
            'URL_Log_Forwarding' => 'url',
            'Data_Log_Forwarding' => 'data',
            'Tunnel_Log_Forwarding' => 'tunnel',
            'Auth_Log_Forwarding' => 'auth',
        );
        if( version_compare( $version, '11.2', '>=' ) )
            $logTypes['Decryption_Log_Forwarding'] = 'decryption';
        if( version_compare( $version, '12.1', '>=' ) )
            $logTypes['DNSSecurity_Log_Forwarding'] = 'dns-security';

        $xml = '<root><entry name="default"><match-list>';
        foreach( $logTypes as $name => $logType )
            $xml .= '<entry name="' . $name . '"><log-type>' . $logType . '</log-type><filter>All Logs</filter>'
                . '<send-to-panorama>yes</send-to-panorama></entry>';

        return $xml . '</match-list></entry></root>';
    }
}

