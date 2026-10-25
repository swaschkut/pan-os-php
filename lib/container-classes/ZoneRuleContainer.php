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
 * Class ZoneRuleContainer
 * @property SecurityRule|NatRule|PbfRule|CaptivePortalRule|DecryptionRule $owner
 *
 */
class ZoneRuleContainer extends ObjRuleContainer
{
    /** @var null|ZoneStore */
    public $parentCentralStore = null;

    /**
     * zoneName => [ "serial/vsys" => Zone|null ]   (null = Zone dort nicht gefunden)
     * @var array
     */
    public $zonesPerTarget = array();

    public function __construct($owner)
    {
        $this->owner = $owner;
        #$this->name = 'zone';

        //problem with PBF to; as there are no zone possible
        #$this->findParentCentralStore( 'zoneStore' );
    }


    /**
     * add a Zone to this store
     * @param bool $rewritexml
     * @return bool
     */
    public function addZone(Zone $Obj, $rewritexml = TRUE)
    {
        /*
        if( is_string($Obj) )
        {
            $f = $this->parentCentralStore->findOrCreate($Obj);
            if( $f === null )
            {
                derr(": Error : cannot find tag named '".$Obj."'\n");
            }
            return $this->add($f);
        }*/

        $ret = $this->add($Obj);
        if( $ret && $rewritexml )
        {
            $this->rewriteXML();
        }


        return $ret;
    }

    /**
     * add a Zone to this store
     * @param bool $rewritexml
     * @return bool
     */
    public function API_addZone(Zone $Obj, $rewritexml = TRUE)
    {
        if( $this->addZone($Obj, $rewritexml) )
        {
            if( count($this->o) == 1 )
            {
                $this->API_sync();
                return TRUE;
            }
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);
            $con->sendSetRequest($xpath, "<member>".PH::panosphp_htmlspecialchars($Obj->name() )."</member>");

            return TRUE;
        }

        return FALSE;
    }


    /**
     * remove a Zone a Zone to this store. Be careful if you remove last zone as
     * it would become 'any' and won't let you do so.
     * @param bool $rewritexml
     * @param bool $forceAny
     *
     * @return bool  True if Zone was found and removed. False if not found.
     */
    public function removeZone(Zone $Obj, $rewritexml = TRUE, $forceAny = FALSE)
    {
        $count = count($this->o);

        $ret = $this->remove($Obj);

        if( $ret && $count == 1 && !$forceAny )
        {
            derr("you are trying to remove last Zone from a rule which will set it to ANY, please use forceAny=true for object: "
                . $this->toString());
        }

        if( $ret && $rewritexml )
        {
            $this->rewriteXML();
        }
        return $ret;
    }

    /**
     * @param Zone $Obj
     * @param bool $rewritexml
     * @param bool $forceAny
     * @return bool
     */
    public function API_removeZone(Zone $Obj, $rewritexml = TRUE, $forceAny = FALSE)
    {
        if( $this->removeZone($Obj, $rewritexml, $forceAny) )
        {
            $xpath = &$this->getXPath();
            $con = findConnectorOrDie($this);

            if( count($this->o) == 0 )
            {
                $this->API_sync();
                return TRUE;
            }

            $xpath .= "/member[text()='{$Obj->name()}']";
            $con->sendDeleteRequest($xpath);

            return TRUE;
        }

        return FALSE;
    }

    public function setAny()
    {
        $this->removeAll();

        $this->rewriteXML();
    }

    /**
     * @param Zone|string $zone can be Zone object or zone name (string). this is case sensitive
     * @return bool
     */
    public function hasZone($zone, $caseSensitive = TRUE)
    {
        return $this->has($zone, $caseSensitive);
    }


    /**
     * return an array with all Zones in this store
     * @return Zone[]
     */
    public function zones()
    {
        return $this->o;
    }


    /**
     * should only be called from a Rule constructor
     * @ignore
     */
    public function load_from_domxml($xml)
    {
        //PH::print_stdout(  "started to extract '".$this->toString()."' from xml" );
        $this->xmlroot = $xml;
        $i = 0;
        foreach( $xml->childNodes as $node )
        {
            if( $node->nodeType != 1 ) continue;

            if( $i == 0 && strtolower($node->textContent) == 'any' )
            {
                return;
            }

            if( strlen($node->textContent) < 1 )
            {
                derr('this container has members with empty name!', $node);
            }



            if (isset($this->owner->owner->owner) && get_class($this->owner->owner->owner) == 'DeviceGroup')
            {
                //new Code Claude 20261025


                $actualDG   = $this->owner->owner->owner;
                $panorama   = $actualDG->owner;
                $devices    = $actualDG->getDevicesInGroup(true);
                $zoneName   = $node->textContent;
                $representative = null;

                foreach( $devices as $deviceObj )
                {
                    $serial = $deviceObj['serial'];
                    $managedFirewall = $panorama->managedFirewallsStore->find($serial);

                    $stack = null;
                    if( $managedFirewall !== null && !empty($managedFirewall->template_stack) )
                        $stack = $panorama->findTemplateStack($managedFirewall->template_stack);

                    // vsys aus der DG-Zuweisung; ohne Angabe -> vsys1
                    $vsysNames = !empty($deviceObj['vsyslist']) ? array_keys($deviceObj['vsyslist']) : array('vsys1');

                    foreach( $vsysNames as $vsysName )
                    {
                        $zone = ($stack !== null) ? $this->findZoneInStack($stack, $vsysName, $zoneName) : null;
                        $this->zonesPerTarget[$zoneName][$serial.'/'.$vsysName] = $zone;

                        if( $representative === null && $zone !== null )
                            $representative = $zone;
                    }
                }

                // $this->o bekommt weiterhin EIN Objekt pro Name (für Filter, XML, Ausgabe)
                $f = ($representative !== null) ? $representative
                    : $this->parentCentralStore->findOrCreate($zoneName, $this);
                if( !$this->has($f) )
                {
                    $this->o[] = $f;
                    $f->addReference($this);
                }


                /*
                $actualDG = $this->owner->owner->owner;
                $devices =  $actualDG->getDevicesInGroup(true);

                $search_f_TStack = array();
                foreach( $devices as $deviceObj )
                {
                    /* @var ManagedDevice $managedFirewall*/
/*                    $managedFirewall = $this->owner->owner->owner->owner->managedFirewallsStore->find($deviceObj['serial']);

                    if( !empty( $managedFirewall->template_stack ) )
                        $search_f_TStack[] = $managedFirewall->template_stack;
                }

                if( count($search_f_TStack ) > 0 )
                {
                    foreach( $search_f_TStack as $search_f_TStackItem )
                    {
                        $tmp_devicegroup = $this->owner->owner->owner;
                        $tmp_panorama = $tmp_devicegroup->owner;
                        $tmp_TemplateStack = $tmp_panorama->findTemplateStack($search_f_TStackItem);

                        if( $tmp_TemplateStack == null )
                            continue;

                        /* @var TemplateStack $tmp_TemplateStack */
/*                        $tmp_templates = $tmp_TemplateStack->templates;

                        $all = array_merge(array($tmp_TemplateStack), $tmp_templates);

                        $zone_added = false;
                        foreach ($all as $template)
                        {
                            /** @var Template|TemplateStack $template */
/*
                            $all_vsys = $template->deviceConfiguration->getVirtualSystems();
                            foreach ($all_vsys as $vsys)
                            {
                                /** @var VirtualSystem $vsys */
/*
                                $tmp_zone = $vsys->zoneStore->find($node->textContent, $this);
                                if ($tmp_zone !== null)
                                {
                                    #$zone_added = true;
                                    if (!$this->has($tmp_zone))
                                    {
                                        $this->o[] = $tmp_zone;
                                        $tmp_zone->addReference($this);
                                    }
                                }
                            }
                        }

                        #if( !$zone_added )
                            #print "Zone: ".$node->textContent." NOT found \n";

                        //this is needed to get type=rule 'filter=(from has XZY) - back into working mode
                        $f = $this->parentCentralStore->findOrCreate($node->textContent, $this);
                        if (!$this->has($f))
                        {
                            $this->o[] = $f;
                            $f->addReference($this);
                        }

                        //only check the first template-stack - more to check???
                        //YES
                        //Todo:
                        //a parentDG can have a rule with from ZONE -> trust
                        //this parentDG can be used by multiple childDG, so multiple Serial#
                        //these Serial# [manageddevice] can be attached to different multiple TStack
                        //these Tstack can have multiple different Templates
                        //These templates can have multiple vsys
                        //these vsys can have Zones defined in zonestore
                        break;
                    }
                }
                else
                {
                    //if zone is not found in Template / Template-Stack
                    $f = $this->parentCentralStore->findOrCreate($node->textContent, $this);
                    if( !$this->has($f) )
                    {
                        $this->o[] = $f;
                        $f->addReference($this);
                    }
                }
                */
            }
            else
            {
                //if NOT Panorama / Device-Group
                $f = $this->parentCentralStore->findOrCreate($node->textContent, $this);
                if( !$this->has($f) )
                {
                    $this->o[] = $f;
                    $f->addReference($this);
                }
            }


            $i++;
        }
    }


    public function rewriteXML()
    {
        DH::Hosts_to_xmlDom($this->xmlroot, $this->o, 'member', TRUE);
    }

    public function toString_inline()
    {
        if( count($this->o) == 0 )
        {
            $out = '**ANY**';
            return $out;
        }

        $out = parent::toString_inline();
        return $out;
    }


    /**
     * Merge this set of Zones with another one (in paramater). If one of them is 'any'
     * then the result will be 'any'.
     *
     */
    public function merge($other)
    {
        if( count($this->o) == 0 )
            return;

        if( count($other->o) == 0 )
        {
            $this->setAny();
            return;
        }

        foreach( $other->o as $s )
        {
            $this->addZone($s);
        }

    }

    /**
     * To determine if a container has all the zones from another container. Very useful when looking to compare similar rules.
     * @param $other
     * @param $anyIsAcceptable
     * * @param $missingZones
     * @return boolean true if Zones from $other are all in this store
     */
    public function includesContainer(ZoneRuleContainer $other, $anyIsAcceptable = TRUE, &$foundZones = array())
    {
        $tmp_return = TRUE;

        if( !$anyIsAcceptable )
        {
            if( $this->count() == 0 || $other->count() == 0 )
                return FALSE;
        }

        if( $this->count() == 0 )
            return TRUE;

        if( $other->count() == 0 )
            return FALSE;

        $zones = $other->zones();

        foreach( $zones as $zone )
        {
            if( !$this->hasZone($zone) )
                $tmp_return = FALSE;
            else
                $foundZones[] = $zone;

        }
        if( !$tmp_return )
            return FALSE;

        return TRUE;

    }

    public function API_setAny()
    {
        $this->setAny();
        $xpath = &$this->getXPath();
        $con = findConnectorOrDie($this);
        $con->sendDeleteRequest($xpath);
        $con->sendSetRequest($xpath, '<member>any</member>');
    }


    public function &getXPath()
    {
        $str = $this->owner->getXPath() . '/' . $this->name;

        if( $this->owner !== null && $this->owner->isPbfRule() && $this->name == 'from' )
            $str .= '/zone';

        return $str;
    }

    public function copy(ZoneRuleContainer $other)
    {
        if( $other->count() == 0 && $this->count() != 0 )
            $this->removeAll();

        foreach( $other->o as $member )
        {
            $this->addZone($member);
        }
    }

    /**
     * @return bool
     */
    public function isAny()
    {
        return (count($this->o) == 0);
    }


    private function findZoneInStack(TemplateStack $stack, $vsysName, $zoneName)
    {
        // PAN-OS-Precedence: TStack first, than Templates from top to bottom
        $chain = array_merge(array($stack), $stack->templates);

        foreach( $chain as $t )
        {
            /** @var Template|TemplateStack $t */
            $vsys = $t->deviceConfiguration->findVirtualSystem($vsysName);
            if( $vsys === null )
                continue;

            $zone = $vsys->zoneStore->find($zoneName, $this);
            if( $zone !== null )
                return $zone;
        }
        return null;
    }

    public function zonesForAllTargets(Zone $zone)
    {
        $name = $zone->name();
        if( !isset($this->zonesPerTarget[$name]) )
            return array($zone);

        $ret = array();
        foreach( $this->zonesPerTarget[$name] as $target => $z )
        {
            if( $z === null )
                $z = $this->parentCentralStore->findOrCreate($name);   // tmp-Zone
            $ret[$target] = $z;
        }
        return $ret;
    }
}





