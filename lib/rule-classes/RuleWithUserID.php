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


class RuleWithUserID extends Rule
{
    const __UserIDType_Any = 0;
    const __UserIDType_Unknown = 1;
    const __UserIDType_Known = 2;
    const __UserIDType_PreLogon = 3;
    const __UserIDType_Custom = 4;

    static private $__UserIDTypes = array(
        self::__UserIDType_Any => 'any',
        self::__UserIDType_Unknown => 'unknown',
        self::__UserIDType_Known => 'known',
        self::__UserIDType_PreLogon => 'pre-logon',
        self::__UserIDType_Custom => 'custom'
    );

    protected $_userIDType = self::__UserIDType_Any;

    /** @var string[] */
    protected $_users = array();

    function userID_IsAny()
    {
        return ($this->_userIDType == self::__UserIDType_Any);
    }

    function userID_IsUnknown()
    {
        return $this->_userIDType == self::__UserIDType_Unknown;
    }

    function userID_IsKnown()
    {
        return $this->_userIDType == self::__UserIDType_Known;
    }

    function userID_IsPreLogon()
    {
        return $this->_userIDType == self::__UserIDType_PreLogon;
    }

    function userID_IsCustom()
    {
        return $this->_userIDType == self::__UserIDType_Custom;
    }

    /**
     * @return string
     */
    function userID_type()
    {
        return self::$__UserIDTypes[$this->_userIDType];
    }

    function userID_getUsers()
    {
        return $this->_users;
    }

    function userID_Hash()
    {
        $string = implode( ", ", $this->_users );

        return md5( $string );
    }

    function userID_count()
    {
        return count( $this->_users );
    }

    /**
     * For developers only
     */
    function userID_loadUsersFromXml()
    {
        $xml = DH::findFirstElement('source-user', $this->xmlroot);
        if( $xml === FALSE )
            return;

        foreach( $xml->childNodes as $node )
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            $content = strtolower($node->textContent);
            if( strlen($content) == 0 )
                derr('empty username in rule', $node);

            if( $content == 'any' )
                return;
            if( $content == 'unknown' )
            {
                $this->_userIDType = self::__UserIDType_Unknown;
                return;
            }
            if( $content == 'known' )
            {
                $this->_userIDType = self::__UserIDType_Known;
                return;
            }
            if( $content == 'known-user' )
            {
                $this->_userIDType = self::__UserIDType_Known;
                return;
            }
            if( $content == 'pre-logon' )
            {
                $this->_userIDType = self::__UserIDType_PreLogon;
                return;
            }

            $this->_users[] = $content;
        }

        $this->_userIDType = self::__UserIDType_Custom;
    }


    function userID_addUser($newUser)
    {
        $tmpRoot = DH::findFirstElementOrCreate('source-user', $this->xmlroot);

        #$newUser = utf8_encode($newUser);
        $newUser = mb_convert_encoding($newUser, 'UTF-8', 'ISO-8859-1');
        if( in_array($newUser, $this->_users, TRUE) )
            return FALSE;

        $this->_users[] = $newUser;

        DH::Hosts_to_xmlDom($tmpRoot, $this->_users, 'member', FALSE, 'any', FALSE);

        return true;
    }

    function userID_removeUser($newUser)
    {
        $tmpRoot = DH::findFirstElementOrCreate('source-user', $this->xmlroot);

        #$newUser = utf8_encode($newUser);
        $newUser = mb_convert_encoding($newUser, 'UTF-8', 'ISO-8859-1');
        if (($key = array_search($newUser, $this->_users)) !== FALSE) {
            unset($this->_users[$key]);
        }
        else
            return FALSE;

        DH::Hosts_to_xmlDom($tmpRoot, $this->_users, 'member', FALSE, 'any', FALSE);

        return true;
    }

    function userID_setany()
    {
        $tmpRoot = DH::findFirstElementOrCreate('source-user', $this->xmlroot);

        $this->_users = array();

        DH::Hosts_to_xmlDom($tmpRoot, $this->_users, 'member', FALSE, 'any', FALSE);

        return true;
    }

    //Todo:
    function API_userID_addUser($newUser)
    {
        $ret = $this->userID_addUser($newUser);

        if( $ret )
        {
            $xpath = $this->getXPath() . '/source-user';
            $con = findConnectorOrDie($this);

            //$con->sendEditRequest($xpath, '<source-user><member>' . $newUser . '</member></source-user>');
            if( $con->isAPI() )
                $con->sendSetRequest($xpath, "<member>$newUser</member>");
        }

        return $ret;
    }

    function API_userID_removeUser($newUser)
    {
        $ret = $this->userID_removeUser($newUser);

        if( $ret )
        {
            //Todo: continue here how do rewrite this source-user part?
            $xpath = $this->getXPath() . '/source-user';
            $con = findConnectorOrDie($this);


            if( $this->userID_count() < 1 )
            {
                #$con->sendEditRequest($xpath, $this->getXmlText_inline());
                if( $con->isAPI() )
                    $con->sendEditRequest($xpath, '<source-user><member>any</member></source-user>');
                return TRUE;
            }


            $xpath = $xpath . "/member[text()='" . $newUser . "']";
            if( $con->isAPI() )
                $con->sendDeleteRequest($xpath);
        }
        return null;
    }

    function API_userID_setany()
    {
        $ret = $this->userID_setany();

        if( $ret )
        {
            $xpath = $this->getXPath() . '/source-user';
            $con = findConnectorOrDie($this);

            if( $con->isAPI() )
                $con->sendEditRequest($xpath, '<source-user><member>any</member></source-user>');
        }

        return $ret;
    }
}
