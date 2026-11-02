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
     * Zone names loaded from XML on Panorama for which the per serial/vsys reading ('all-targets') is available:
     * zoneName => 'dg' | 'shared'.
     * The reading itself is NOT computed at load: targetsForZone() resolves it on first use, through
     * PanoramaConf::$zoneResolveCache (one result per template-stack / vsys / zone, shared by all rules).
     * Before, every rule stored one entry per zone x firewall x vsys at load (~1 KB each), also for 'to' zones
     * and for every util type, although only 'zone protection all-targets', the '*-all-targets' export columns
     * and the 'targets' filters read them.
     * @var array
     */
    public $perTargetZones = array();

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



            $isDG     = isset($this->owner->owner->owner) && get_class($this->owner->owner->owner) == 'DeviceGroup';
            $isShared = !$isDG && isset($this->owner->owner->owner) && get_class($this->owner->owner->owner) == 'PanoramaConf';

            if( $isDG || $isShared )
            {
                $zoneName   = $node->textContent;

                $actualDG = $isDG ? $this->owner->owner->owner : null;

                // per serial/vsys reading: resolved on first use, see targetsForZone()
                $this->perTargetZones[$zoneName] = $isDG ? 'dg' : 'shared';

                // $this->o keeps the 2.1.60 reading (first template-stack, templates before stack, first vsys
                // holding the name). Used by 'zone protection', 'from-visible', 'from-zone-location', 'from has'.
                // The per-target reading above is only used by 'all.targets' / 'targets' filters,
                // 'zone protection all-targets' and the '*-all-targets' export columns.
                if( $isDG )
                    $this->load_zone_legacy_first_stack($actualDG, $zoneName);
                else
                {
                    // 2.1.60 reading for shared rules: placeholder zone (unchanged)
                    $f = $this->parentCentralStore->findOrCreate($zoneName, $this);
                    if( !$this->has($f) )
                    {
                        $this->o[] = $f;
                        $f->addReference($this);
                    }
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

    /**
     * 2.1.60 zone lookup for $this->o - kept unchanged on purpose (stats 'zone protection', export 'from-visible').
     * first template-stack of the DG firewalls, its templates read before the stack, first vsys holding the name
     */
    private function load_zone_legacy_first_stack(DeviceGroup $actualDG, $zoneName)
    {
        $devices = $actualDG->getDevicesInGroup(true);

        $search_f_TStack = array();
        foreach( $devices as $deviceObj )
        {
            /* @var ManagedDevice $managedFirewall*/
            $managedFirewall = $actualDG->owner->managedFirewallsStore->find($deviceObj['serial']);

            if( !empty( $managedFirewall->template_stack ) )
                $search_f_TStack[] = $managedFirewall->template_stack;
        }

        if( count($search_f_TStack ) > 0 )
        {
            foreach( $search_f_TStack as $search_f_TStackItem )
            {
                $tmp_TemplateStack = $actualDG->owner->findTemplateStack($search_f_TStackItem);

                if( $tmp_TemplateStack == null )
                    continue;

                /* @var TemplateStack $tmp_TemplateStack */
                $tmp_templates = $tmp_TemplateStack->templates;

                $all = array_merge($tmp_templates, array($tmp_TemplateStack));

                foreach ($all as $template)
                {
                    /** @var Template|TemplateStack $template */
                    $all_vsys = $template->deviceConfiguration->getVirtualSystems();
                    foreach ($all_vsys as $vsys)
                    {
                        /** @var VirtualSystem $vsys */
                        $tmp_zone = $vsys->zoneStore->find($zoneName, $this);
                        if ($tmp_zone !== null)
                        {
                            if (!$this->has($tmp_zone))
                            {
                                $this->o[] = $tmp_zone;
                                $tmp_zone->addReference($this);
                            }
                        }
                    }
                }

                //this is needed to get type=rule 'filter=(from has XZY) - back into working mode
                $f = $this->parentCentralStore->findOrCreate($zoneName, $this);
                if (!$this->has($f))
                {
                    $this->o[] = $f;
                    $f->addReference($this);
                }

                //2.1.60 reading: only the first template-stack
                break;
            }
        }
        else
        {
            //if zone is not found in Template / Template-Stack
            $f = $this->parentCentralStore->findOrCreate($zoneName, $this);
            if( !$this->has($f) )
            {
                $this->o[] = $f;
                $f->addReference($this);
            }
        }
    }

    /**
     * shared rules are pushed to every firewall of every device group:
     * union of getDevicesInGroup() of all device groups, vsys lists merged
     */
    private function devicesOfAllDeviceGroups(PanoramaConf $panorama)
    {
        $devices = array();
        foreach( $panorama->getDeviceGroups() as $dg )
        {
            foreach( $dg->getDevicesInGroup(false) as $serial => $d )
            {
                if( !isset($devices[$serial]) )
                    $devices[$serial] = array('serial' => $d['serial'], 'vsyslist' => array());
                if( !empty($d['vsyslist']) )
                    foreach( $d['vsyslist'] as $v )
                        $devices[$serial]['vsyslist'][$v] = $v;
            }
        }
        return $devices;
    }

    /**
     * Per serial/vsys of the rule's device group (incl. child DGs; for shared: every DG) the resolved zone of $zoneName,
     * Target not applied yet. Same order and result as the former load-time computation.
     * The resolution only depends on template-stack, vsys and zone name and is cached on the PanoramaConf,
     * so all rules share one result per combination.
     *
     * @return null|array  "serial/vsys" => array('status' => string, 'zone' => Zone|null, 'candidates' => array)
     *                     null: no per-target reading (not loaded from Panorama XML, or no firewall)
     */
    private function resolveTargets($zoneName)
    {
        if( !isset($this->perTargetZones[$zoneName]) )
            return null;

        if( $this->perTargetZones[$zoneName] == 'dg' )
        {
            $actualDG = $this->owner->owner->owner;
            $panorama = $actualDG->owner;
            $devices  = $actualDG->getDevicesInGroup(true);
        }
        else
        {
            // shared = parent of every top-level device group: union of the firewalls of all device groups
            $panorama = $this->owner->owner->owner;
            if( !isset($panorama->zoneResolveCache['@shared-devices']) )
                $panorama->zoneResolveCache['@shared-devices'] = $this->devicesOfAllDeviceGroups($panorama);
            $devices = $panorama->zoneResolveCache['@shared-devices'];
        }

        if( count($devices) == 0 )
            return null;

        $ret = array();
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
                if( $stack === null )
                {
                    $ret[$serial.'/'.$vsysName] = array('status' => 'missing', 'zone' => null, 'candidates' => array());
                    continue;
                }

                $key = $stack->name()."\0".$vsysName."\0".$zoneName;
                if( !isset($panorama->zoneResolveCache[$key]) )
                    $panorama->zoneResolveCache[$key] = $this->resolveZoneInStack($stack, $vsysName, $zoneName);

                $ret[$serial.'/'.$vsysName] = $panorama->zoneResolveCache[$key];
            }
        }

        return $ret;
    }

    /**
     * Is the rule pushed to this serial/vsys? (rule Target incl. negate; no Target = every DG firewall)
     * a Target entry without vsys covers every vsys of that serial
     */
    private function isDeployedToTarget($serial, $vsysName)
    {
        $rule = $this->owner;
        if( !is_object($rule) || !method_exists($rule, 'target_isAny') || $rule->target_isAny() )
            return TRUE;

        $targets = $rule->targets();
        $inList = isset($targets[$serial]) && ( count($targets[$serial]) == 0 || isset($targets[$serial][$vsysName]) );

        if( $rule->target_isNegated() )
            return !$inList;

        return $inList;
    }

    /**
     * Per serial/vsys the rule is pushed to: the zone this target receives and how it was resolved.
     * Returns null when there is no Panorama/DG per-target data (firewall config, shared, DG without firewalls).
     *
     * @return null|array  "serial/vsys" => array('zone' => Zone, 'status' => string, 'candidates' => array("<tpl>/<vsys>" => Zone))
     *   status: found | protected-all | unprotected-all | ambiguous | missing | no-target
     *   'missing' and 'no-target' carry a tmp zone (zpp is.set == FALSE)
     */
    public function targetsForZone($zoneName)
    {
        $resolved = $this->resolveTargets($zoneName);
        if( $resolved === null )
            return null;

        $ret = array();
        foreach( $resolved as $target => $res )
        {
            $ex = explode('/', $target, 2);
            if( !$this->isDeployedToTarget($ex[0], $ex[1]) )
                continue;

            $status = $res['status'];
            $candidates = $res['candidates'];

            $z = $res['zone'];
            if( $z === null )
                $z = $this->parentCentralStore->findOrCreate($zoneName);   // tmp-Zone

            $ret[$target] = array('zone' => $z, 'status' => $status, 'candidates' => $candidates);
        }

        // DG has firewalls, but the Target excludes all of them: rule is pushed nowhere -> not protected
        if( count($ret) == 0 )
            $ret['---'] = array('zone' => $this->parentCentralStore->findOrCreate($zoneName), 'status' => 'no-target', 'candidates' => array());

        return $ret;
    }

    /**
     * Zones to evaluate for 'all.targets.has.from.query' / 'targets.has.from.query'
     * @return Zone[]
     */
    public function zonesForAllTargets(Zone $zone)
    {
        $targets = $this->targetsForZone($zone->name());
        if( $targets === null )
            return array($zone);

        $ret = array();
        foreach( $targets as $target => $info )
            $ret[$target] = $info['zone'];

        return $ret;
    }

    /**
     * export 'from-visible-all-targets' for one from-zone - same zones as zonesForAllTargets()
     */
    public function visibleAllTargetsString(Zone $zone)
    {
        $targets = $this->targetsForZone($zone->name());
        if( $targets === null )
        {
            if( $zone->isTmp() )
                return '**missing - NOT visible**';
            return $zone->isVisible() ? '**visible**' : '**NOT visible**';
        }

        $missing = FALSE;
        $ambiguous = FALSE;
        $allVisible = TRUE;
        foreach( $targets as $info )
        {
            if( $info['status'] == 'missing' )
                $missing = TRUE;
            elseif( $info['status'] == 'ambiguous' )
                $ambiguous = TRUE;

            if( $info['zone']->isTmp() || !$info['zone']->isVisible() )
                $allVisible = FALSE;
        }

        if( $allVisible )
            return '**visible**';
        if( $missing )
            return '**missing - NOT visible**';
        if( $ambiguous )
            return '**ambiguous - NOT visible**';
        return '**NOT visible**';
    }

    /**
     * export 'from-zone-all-targets' for one from-zone: one entry per serial/vsys
     * @return string[]
     */
    public function zoneAllTargetsStrings(Zone $zone)
    {
        $zppString = function( Zone $z )
        {
            return !empty($z->zoneProtectionProfile) ? $z->zoneProtectionProfile : '---';
        };

        $targets = $this->targetsForZone($zone->name());
        if( $targets === null )
        {
            if( $zone->isTmp() )
                return array('missing');
            return array($zppString($zone));
        }

        $ret = array();
        foreach( $targets as $target => $info )
        {
            if( $info['status'] == 'no-target' )
                $ret[] = 'no target';
            elseif( $info['status'] == 'missing' )
                $ret[] = $target.': missing';
            elseif( $info['status'] == 'ambiguous' )
            {
                $c = array();
                foreach( $info['candidates'] as $loc => $z )
                    $c[] = $loc.' '.$zppString($z);
                $ret[] = $target.': ambiguous ('.implode(', ', $c).')';
            }
            else
            {
                $c = array();
                foreach( $info['candidates'] as $loc => $z )
                    $c[] = $loc.' '.$zppString($z);
                if( count($c) == 0 )
                    $c[] = $zppString($info['zone']);
                $ret[] = $target.': '.implode(', ', $c);
            }
        }
        return $ret;
    }

    /**
     * Resolve the zone a firewall's serial/vsys receives from its template-stack.
     *
     * 1) stack or one of its templates has a vsys named like the DG assignment (vsysN):
     *    zone of the highest level in that vsys (stack > template1 > template2 ...), else 'missing'
     * 2) no vsys of that name (templates with named vsys, e.g. 'D1TSTTFW01'):
     *    all vsys of the chain that hold the zone name (per vsys the highest level wins)
     *      all with ZPP     -> 'protected-all'
     *      none with ZPP    -> 'unprotected-all'
     *      mixed            -> 'ambiguous'  (returns an unprotected zone -> zpp is.set == FALSE)
     *      none holds name  -> 'missing'
     *
     * @return array('status' => string, 'zone' => Zone|null, 'candidates' => array("<tpl>/<vsys>" => Zone))
     */
    private function resolveZoneInStack(TemplateStack $stack, $vsysName, $zoneName)
    {
        $chain = array_merge(array($stack), $stack->templates);

        // 1) firewall's vsys name exists in the chain -> unambiguous
        if( $this->stackHasVsys($chain, $vsysName) )
        {
            foreach( $chain as $t )
            {
                /** @var Template|TemplateStack $t */
                $vsys = $t->deviceConfiguration->findVirtualSystem($vsysName);
                if( $vsys === null )
                    continue;

                $zone = $vsys->zoneStore->find($zoneName, null);
                if( $zone !== null )
                    return array('status' => 'found', 'zone' => $zone,
                        'candidates' => array($t->name().'/'.$vsys->name() => $zone));
            }
            return array('status' => 'missing', 'zone' => null, 'candidates' => array());
        }

        // 2) named vsys: collect per vsys name the zone of the highest level
        $perVsys = array();
        foreach( $chain as $t )
        {
            foreach( $t->deviceConfiguration->getVirtualSystems() as $vsys )
            {
                /** @var VirtualSystem $vsys */
                if( isset($perVsys[$vsys->name()]) )
                    continue;

                $zone = $vsys->zoneStore->find($zoneName, null);
                if( $zone !== null )
                    $perVsys[$vsys->name()] = array('loc' => $t->name().'/'.$vsys->name(), 'zone' => $zone);
            }
        }

        if( count($perVsys) == 0 )
            return array('status' => 'missing', 'zone' => null, 'candidates' => array());

        $with = array();
        $without = array();
        foreach( $perVsys as $c )
        {
            if( !empty($c['zone']->zoneProtectionProfile) )
                $with[$c['loc']] = $c['zone'];
            else
                $without[$c['loc']] = $c['zone'];
        }

        if( count($without) == 0 )
            return array('status' => 'protected-all', 'zone' => reset($with), 'candidates' => $with);

        if( count($with) == 0 )
            return array('status' => 'unprotected-all', 'zone' => reset($without), 'candidates' => $without);

        // mixed: return an unprotected zone so that 'zpp is.set' evaluates FALSE
        return array('status' => 'ambiguous', 'zone' => reset($without), 'candidates' => $with + $without);
    }

    /**
     * @param Template[]|TemplateStack[] $chain
     */
    private function stackHasVsys(array $chain, $vsysName)
    {
        foreach( $chain as $t )
            if( $t->deviceConfiguration->findVirtualSystem($vsysName) !== null )
                return TRUE;

        return FALSE;
    }
}





