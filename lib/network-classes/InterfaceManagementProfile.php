<?php

/**
 * ISC License
 *
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
 * Class InterfaceManagementProfile
 * @property InterfaceManagementProfileStore $owner
 */
class InterfaceManagementProfile
{
    use InterfaceType;
    use XmlConvertible;
    use PathableName;
    use ReferenceableObject;

    public $owner;

    /** @var null|string[]|DOMElement */
    public $typeRoot = null;

    public $type = 'notfound';

    public $enabledServices = array();

    public $permittedIPs = array();



    /**
     * InterfaceManagementProfile constructor.
     * @param string $name
     * @param InterfaceManagementProfileStore $owner
     */
    public function __construct($name, $owner)
    {
        $this->owner = $owner;
        $this->name = $name;
    }

    /**
     * @param DOMElement $xml
     */
    public function load_from_domxml($xml)
    {
        $debug = false;

        $this->xmlroot = $xml;

        $this->name = DH::findAttribute('name', $xml);
        if( $this->name === FALSE )
            derr("InterfaceManagementProfile name not found\n");


        /*
        <entry name="external-web-management">
         <permitted-ip>
          <entry name="185.217.253.59/32"/>
          <entry name="149.40.4.247/32"/>
          <entry name="134.159.167.68/32"/>
          <entry name="124.19.65.164/32"/>
         </permitted-ip>
         <https>yes</https>
         <ssh>yes</ssh>
         <ping>yes</ping>
        </entry>
         */

        $permittedIP_Node = DH::findFirstElement('permitted-ip', $xml);
        if( $permittedIP_Node !== FALSE )
        {
            foreach( $permittedIP_Node->childNodes as $entry_Node )
            {
                if ($entry_Node->nodeType != 1)
                    continue;

                $this->permittedIPs[] = DH::findAttribute('name', $entry_Node);
            }
        }

        foreach( $xml->childNodes as $entry_Node )
        {
            if ($entry_Node->nodeType != 1)
                continue;

            $node_name = $entry_Node->nodeName;
            if( $node_name == 'permitted-ip' )
                continue;

            if( $entry_Node->textContent == "yes" )
                $this->enabledServices[$node_name] = $entry_Node->textContent;
        }
    }

    /**
     * return true if change was successful false if not (duplicate InterfaceManagementProfile name?)
     * @param string $name new name for the InterfaceManagementProfile
     * @return bool
     */
    public function setName($name)
    {
        if( $this->name == $name )
            return TRUE;

        if( preg_match('/[^0-9a-zA-Z_\-\s]/', $name) )
        {
            $name = preg_replace('/[^0-9a-zA-Z_\-\s]/', "", $name);
            PH::print_stdout(  "new name: " . $name );
            #mwarning( 'Name will be replaced with: '.$name."\n" );
        }

        /* TODO: 20180331 finalize needed
        if( isset($this->owner) && $this->owner !== null )
        {
            if( $this->owner->isRuleNameAvailable($name) )
            {
                $oldname = $this->name;
                $this->name = $name;
                $this->owner->ruleWasRenamed($this,$oldname);
            }
            else
                return false;
        }
*/
        if( $this->name != "**temporarynamechangeme**" )
            $this->setRefName($name);

        $this->name = $name;
        $this->xmlroot->setAttribute('name', $name);

        return TRUE;
    }


    public function isInterfaceManagementProfileType()
    {
        return TRUE;
    }

    public function cloneInterfaceManagementProfile($newName)
    {
        $newProfile = $this->owner->newInterfaceManagementProfile($newName);



        return $newProfile;
    }

    static public $templatexml = '<entry name="**temporarynamechangeme**">
<esp>
 ..... add missing stuff
</entry>';

    /*
        static public $templatexml = '<entry name="**temporarynamechangeme**">
    <esp>
      <authentication>
      </authentication>
      <encryption>
      </encryption>
    </esp>
    <lifetime>
    </lifetime>
    <dh-group></dh-group>
    </entry>';
    */
}