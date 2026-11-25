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
    use ObjectWithDescription;

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
        // set before load_from_domxml() below: it reads the PAN-OS version through the owner
        $this->owner = $owner;

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

        $tmp_description = DH::findFirstElement('description', $xml);
        $this->_description = $tmp_description !== FALSE ? $tmp_description->textContent : null;


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

    // ------------------------------------------------------------------------------------------------- edit (offline)

    const MATCH_SEND = array( 'syslog' => 'send-syslog', 'email' => 'send-email', 'http' => 'send-http', 'snmptrap' => 'send-snmptrap' );

    /** the match list: name => 'log-type', 'filter', 'send-to-panorama', 'quarantine', 'syslog' / 'email' / 'http' / 'snmptrap' (lists) */
    public function matchList(): array
    {
        $out = array();
        $ml = $this->xmlroot === null ? FALSE : DH::findFirstElement( 'match-list', $this->xmlroot );
        if( $ml === FALSE )
            return $out;
        foreach( $ml->childNodes as $e )
        {
            if( $e->nodeType != XML_ELEMENT_NODE )
                continue;
            $m = array();
            foreach( array( 'log-type', 'filter', 'send-to-panorama', 'quarantine' ) as $tag )
            {
                $n = DH::findFirstElement( $tag, $e );
                $m[$tag] = $n === FALSE ? '' : $n->textContent;
            }
            foreach( self::MATCH_SEND as $k => $tag )
            {
                $m[$k] = array();
                $n = DH::findFirstElement( $tag, $e );
                if( $n !== FALSE )
                    foreach( $n->childNodes as $c )
                        if( $c->nodeType == XML_ELEMENT_NODE )
                            $m[$k][] = $c->textContent;
            }
            $out[$e->getAttribute( 'name' )] = $m;
        }
        return $out;
    }

    private function matchNode( string $name ): DOMElement
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        $ml = DH::findFirstElement( 'match-list', $this->xmlroot );
        if( $ml !== FALSE )
            foreach( $ml->childNodes as $e )
                if( $e->nodeType == XML_ELEMENT_NODE && $e->getAttribute( 'name' ) === $name )
                    return $e;
        throw new Exception( "match list entry '" . $name . "' not found" );
    }

    /** read the XML again (the arrays of the match list) */
    private function reloadMatchList(): void
    {
        $this->type = array();
        foreach( $this->type_available ?? array() as $t )
            $this->type[$t] = array( 'notSet' => '--' );
        $this->load_from_domxml( $this->xmlroot );
    }

    private function checkLogType( string $logType ): void
    {
        $ok = array_merge( $this->type_available ?? array(), array( 'gtp', 'sctp' ) );
        if( !in_array( $logType, $ok, TRUE ) )
            throw new Exception( "log type '" . $logType . "': " . implode( ', ', $ok ) );
    }

    static private function checkFilter( string $filter ): void
    {
        if( $filter === '' || strlen( $filter ) > 2047 || preg_match( '/[\x00-\x1F]/', $filter ) )
            throw new Exception( 'filter: 1-2047 characters ("All Logs" or a log filter like (severity geq high))' );
        if( $filter !== 'All Logs' && substr_count( $filter, '(' ) !== substr_count( $filter, ')' ) )
            throw new Exception( "filter '" . $filter . "': the brackets do not match" );
    }

    static private function checkEntryName( string $name ): void
    {
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,30}$/', $name ) )
            throw new Exception( "name '" . $name . "': 1-31 characters, letters, digits, blank, . _ -" );
    }

    /** match-add: a match list entry (log type, filter, send to panorama) */
    public function editMatchAdd( string $name, string $logType, string $filter = 'All Logs', bool $panorama = FALSE ): void
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        self::checkEntryName( $name );
        $this->checkLogType( $logType );
        self::checkFilter( $filter );
        if( isset( $this->matchList()[$name] ) )
            throw new Exception( "match list entry '" . $name . "' exists already" );
        $ml = DH::findFirstElementOrCreate( 'match-list', $this->xmlroot );
        $e = DH::createElement( $ml, 'entry' );
        $e->setAttribute( 'name', $name );
        DH::createElement( $e, 'log-type', $logType );
        DH::createElement( $e, 'filter', $filter );
        DH::createElement( $e, 'send-to-panorama', $panorama ? 'yes' : 'no' );
        $this->reloadMatchList();
    }

    public function editMatchRemove( string $name ): void
    {
        $e = $this->matchNode( $name );
        $e->parentNode->removeChild( $e );
        $this->reloadMatchList();
    }

    /** match-set: one field of an entry - log-type, filter, send-to-panorama (yes / no), quarantine (yes / no) */
    public function editMatchSet( string $name, string $field, string $value ): void
    {
        $e = $this->matchNode( $name );
        if( $field === 'log-type' )
            $this->checkLogType( $value );
        elseif( $field === 'filter' )
            self::checkFilter( $value );
        elseif( in_array( $field, array( 'send-to-panorama', 'quarantine' ), TRUE ) )
        {
            if( !in_array( $value, array( 'yes', 'no' ), TRUE ) )
                throw new Exception( $field . ': yes or no' );
        }
        else
            throw new Exception( "field '" . $field . "': log-type, filter, send-to-panorama, quarantine" );
        $n = DH::findFirstElement( $field, $e );
        if( $n !== FALSE && $n->textContent === $value )
            throw new Exception( $field . ' is ' . $value . ' already' );
        if( $n === FALSE )
            $n = DH::createElement( $e, $field );
        DH::setDomNodeText( $n, $value );
        $this->reloadMatchList();
    }

    /** match-send-add / -remove: a server profile (syslog, email, http, snmptrap) of an entry */
    public function editMatchSend( string $name, string $kind, string $profile, bool $add ): void
    {
        $e = $this->matchNode( $name );
        if( !isset( self::MATCH_SEND[$kind] ) )
            throw new Exception( "kind '" . $kind . "': " . implode( ', ', array_keys( self::MATCH_SEND ) ) );
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/', $profile ) )
            throw new Exception( "server profile '" . $profile . "': a name" );
        $have = $this->matchList()[$name][$kind];
        if( $add && in_array( $profile, $have, TRUE ) )
            throw new Exception( "'" . $profile . "' is set already" );
        if( !$add && !in_array( $profile, $have, TRUE ) )
            throw new Exception( "'" . $profile . "' is not set" );
        $tag = self::MATCH_SEND[$kind];
        $list = DH::findFirstElementOrCreate( $tag, $e );
        if( $add )
            DH::createElement( $list, 'member', $profile );
        else
        {
            foreach( iterator_to_array( $list->childNodes ) as $c )
                if( $c->nodeType == XML_ELEMENT_NODE && $c->textContent === $profile )
                    $list->removeChild( $c );
            if( DH::firstChildElement( $list ) === FALSE )
                $e->removeChild( $list );
        }
        $this->reloadMatchList();
    }

    /** enhanced-application-logging-set: yes / no */
    public function editEnhancedLoggingSet( bool $yes ): void
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        $v = $yes ? 'yes' : 'no';
        $n = DH::findFirstElement( 'enhanced-application-logging', $this->xmlroot );
        if( ( $n === FALSE ? 'no' : $n->textContent ) === $v )
            throw new Exception( 'enhanced application logging is ' . $v . ' already' );
        if( $n === FALSE )
            $n = DH::createElement( $this->xmlroot, 'enhanced-application-logging' );
        DH::setDomNodeText( $n, $v );
        $this->enhanced_application_logging = $v;
    }

    /**
     * name-rename: the profile and every rule / zone that names it (rules and zones keep the name as text)
     * @return int the users updated
     */
    public function editRename( string $newName ): int
    {
        if( $this->isTmp() )
            throw new Exception( 'a tmp object can not be changed' );
        if( !preg_match( '/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,62}$/', $newName ) )
            throw new Exception( "name '" . $newName . "': 1-63 characters, letters, digits, blank, . _ -" );
        if( $newName === $this->name() )
            throw new Exception( 'the name is the same' );
        if( $this->owner->find( $newName ) !== null )
            throw new Exception( "a log forwarding profile '" . $newName . "' exists already" );
        $old = $this->name();
        $users = $this->getReferences();
        $this->setName( $newName );
        $n = 0;
        foreach( $users as $u )
        {
            $current = $u instanceof Zone ? $u->logsetting : ( method_exists( $u, 'logSetting' ) ? $u->logSetting() : null );
            if( $current === $old && method_exists( $u, 'setLogSetting' ) )
            {
                $u->setLogSetting( $newName );
                $n++;
            }
        }
        return $n;
    }

    public function add_log_filter( $logType, $name, $filter = "All Logs", $sendToPanorama = true )
    {
        unset( $this->type[$logType]['notSet'] );
        $this->type[$logType][$name] = array();
        $this->type[$logType][$name]['filter'] = $filter;

        $this->type[$logType][$name]['send_to_panorama'] = $sendToPanorama;

        // the XML as well, so that a saved / pushed profile has the same match list
        if( $this->xmlroot !== null )
        {
            $matchList = DH::findFirstElementOrCreate('match-list', $this->xmlroot);
            foreach( $matchList->childNodes as $existing )
                if( $existing->nodeType == XML_ELEMENT_NODE && $existing->getAttribute('name') === $name )
                {
                    $matchList->removeChild( $existing );
                    break;
                }

            $entry = $this->xmlroot->ownerDocument->createElement('entry');
            $entry->setAttribute('name', $name);
            $entry->appendChild( $this->xmlroot->ownerDocument->createElement('log-type', $logType) );
            $entry->appendChild( $this->xmlroot->ownerDocument->createElement('filter', $filter) );
            $entry->appendChild( $this->xmlroot->ownerDocument->createElement('send-to-panorama', $sendToPanorama ? 'yes' : 'no') );
            $matchList->appendChild( $entry );
        }
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
        // versions: PH::IRONSKILLET_VERSIONS / IRONSKILLET_SNIPPETS (newer PAN-OS: snippet of the newest version below)
        if( ( $version = PH::ironSkilletVersion( $version, 'log forwarding profiles' ) ) === null )
            return null;

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

