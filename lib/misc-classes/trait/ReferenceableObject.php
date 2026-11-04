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

trait ReferenceableObject
{

    protected $name;
    public $refrules = array();
    protected $refcomphash = null;

    /**
     * @param string $newName
     * @param bool $skip_name_unicity_check
     * @return bool
     * @throws Exception
     */
    protected function setRefName($newName, $skip_name_unicity_check = FALSE)
    {
        if( !is_string($newName) )
            derr('$newName must be a string');

        if( $this->name == $newName )
            return FALSE;

        $oldName = $this->name;
        $this->name = $newName;

        $this->broadcastMyNameChange($oldName);

        return TRUE;
    }

    public function addReference($ref)
    {
        if( $ref === null )
            return;

        // integer key: same identity as spl_object_hash(), without a 32 character string per reference
        $serial = spl_object_id($ref);

        if( isset($this->refrules[$serial]) )
            return;

        $this->refrules[$serial] = $ref;
        $this->refcomphash = null;
    }

    public function removeReference($ref)
    {
        if( $ref === null )
            return;

        $serial = spl_object_id($ref);

        if( isset($this->refrules[$serial]) )
        {
            unset($this->refrules[$serial]);
            $this->refcomphash = null;
            return;
        }

        mwarning('tried to unreference an object that is not referenced:' . $this->toString() . '  against  ' . $ref->toString(), null, False);
    }

    public function broadcastMyNameChange($oldname)
    {

        foreach( $this->refrules as $ref )
        {
            #print get_class($ref)."\n";
            $ref->referencedObjectRenamed($this, $oldname);
        }

        if( $this->owner !== null )
        {
            $this->owner->referencedObjectRenamed($this, $oldname);
        }
    }

    public function replaceMeGlobally($newobject, $apimode=false)
    {
        foreach( $this->refrules as $o )
        {
            if( $apimode )
                $o->API_replaceReferencedObject($this, $newobject);
            else
                $o->replaceReferencedObject($this, $newobject);
        }
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = FALSE, $outputPadding = '', $skipIfConflict = FALSE)
    {
        derr('not implemented yet');
    }

    /**
     * @param $objectToAdd Service|ServiceGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function API_addObjectWhereIamUsed($objectToAdd, $displayOutput = FALSE, $outputPadding = '', $skipIfConflict = FALSE)
    {
        derr('not implemented yet');
    }


    public function countReferences()
    {
        return count($this->refrules);
    }

    public function countLocationReferences()
    {
        $refLocationcounter = array();
        $this->getReferencesLocation($refLocationcounter);
        return count($refLocationcounter);
    }

    public function display_references($indent = 0)
    {
        $strpad = str_pad('', $indent);
        PH::print_stdout( $strpad . "* Displaying referencers for " . $this->toString() );
        foreach( $this->refrules as $o )
        {
            PH::print_stdout( $strpad . '  - ' . $o->toString() );
        }

        // Panorama same-name / override: what the firewalls actually use
        $info = $this->getSameNameOverrideInfo();
        if( $info['mode'] != 'panorama' && $info['mode'] != 'scm' )
            return;
        if( count($info['usedVia']) == 0 && count($info['overriddenIn']) == 0 && $info['shadowedBy'] === null && count($info['shadows']) == 0 )
            return;

        $precedence = $info['precedence'] ? 'yes' : 'no';
        PH::print_stdout( $strpad . "  * same-name override (ancestor-objects-take-precedence: " . $precedence . ")" );
        foreach( $info['usedVia'] as $entry )
            PH::print_stdout( $strpad . "    - used on firewalls via: " . $entry['ref']->toString() . "  [names " . $entry['via']->toString() . "]" );
        if( count($info['overriddenIn']) > 0 )
            PH::print_stdout( $strpad . "    - NOT used on firewalls of DG: " . implode(', ', $info['overriddenIn']) . "  [own same-name copy wins]" );
        if( $info['shadowedBy'] !== null )
            PH::print_stdout( $strpad . "    - shadowed: firewalls use " . $info['shadowedBy']->toString() . " instead" );
        if( count($info['shadows']) > 0 )
            PH::print_stdout( $strpad . "    - replaces the same-name copy on firewalls of DG: " . implode(', ', $info['shadows']) );
    }

    /**
     * @return SecurityRule[]
     */
    public function findAssociatedSecurityRules()
    {
        return $this->findAssociatedRule_byType('SecurityRule');
    }

    /**
     * @param string $type
     * @return Rule[]
     */
    public function findAssociatedRule_byType($type)
    {
        $ret = array();

        foreach( $this->refrules as $cur )
        {
            if( isset($cur->owner) && $cur->owner !== null )
            {
                $class = get_class($cur->owner);

                if( $class == $type )
                {
                    if( !in_array($cur->owner, $ret, TRUE) )
                    {
                        $ret[] = $cur->owner;
                    }
                }

            }
        }

        return $ret;
    }


    public function generateRefHashComp($force = FALSE)
    {
        if( $this->refcomphash !== null && !$force )
            return;

        $fasthashcomp = 'ReferenceableObject';

        $tmpa = $this->refrules;

        usort($tmpa, "__CmpObjMemID");

        foreach( $tmpa as $o )
        {
            $fasthashcomp .= '.*/' . spl_object_hash($o);
        }

        $this->refcomphash = md5($fasthashcomp, TRUE);

    }

    public function getRefHashComp()
    {
        $this->generateRefHashComp();
        return $this->refcomphash;
    }

    public function getReferences()
    {
        return $this->refrules;
    }

    public function getReferencesRecursive( $references = array() )
    {
        //Todo: problem if same objects groups are available multiple times with different members;
        //check location or something, no clue yet 20211115
        if( get_class( $this ) == "Address" || get_class( $this ) == "AddressGroup" )
        {
            foreach( $this->refrules as $reference )
            {
                if( get_class( $reference ) == "Address" || get_class( $reference ) == "AddressGroup" )
                {
                    $recursiveReferences = $reference->getReferencesRecursive();
                    // keys are object ids: union keeps every object once (array_merge would renumber them)
                    $references = $references + $recursiveReferences;
                }
            }
            $references = $references + $this->refrules;
        }

        return $references;
    }

    public function getReferencesLocation( &$counter_array = array() )
    {
        $location_array = array();
        foreach( $this->refrules as $cur )
        {
            #print "--------------\n";
            #print get_class( $cur)."\n";
            #print $cur->name()."\n";
            if( isset($cur->owner->owner->owner->owner) && get_class( $cur->owner->owner->owner->owner ) == "PanoramaConf" )
            {
                //Panorama - Rule
                if( isset($cur->owner->owner->owner) && $cur->owner->owner->owner !== null && method_exists($cur->owner->owner->owner,'name') )
                {
                    if( $cur->owner->owner->owner->name() !== "" )
                        $tmp_name = $cur->owner->owner->owner->name();
                    else
                        $tmp_name = "shared";

                    #print "pan | ".$cur->owner->owner->owner->name()."\n";
                    $location_array[$tmp_name] = $tmp_name;
                    if( isset($counter_array[$tmp_name]))
                        $counter_array[$tmp_name] += 1;
                    else
                        $counter_array[$tmp_name] = 1;
                }
            }
            elseif( isset($cur->owner->owner->owner) && get_class( $cur->owner->owner->owner ) == "PanoramaConf" )
            {
                #Panorama - AddressGroup
                if( isset($cur->owner->owner) && $cur->owner->owner !== null && method_exists($cur->owner->owner,'name') )
                {
                    if( get_class($cur->owner->owner) !== "PanoramaConf"
                        && get_class($cur->owner->owner) !== "DeviceGroup"
                        && get_class($cur->owner->owner) !== "PANConf"
                        && get_class($cur->owner->owner) !== "VirtualSystem"
                        && get_class($cur->owner->owner) !== "Container"
                        && get_class($cur->owner->owner) !== "DeviceCloud"
                        && get_class($cur->owner->owner) !== "DeviceOnPrem"
                        && get_class($cur->owner->owner) !== "Snippet"
                    )
                    {
                        $tmp_name = "shared";
                    }
                    else
                    {
                        if ($cur->owner->owner->name() !== "")
                            $tmp_name = $cur->owner->owner->name();
                        else
                            $tmp_name = "shared";
                    }
                    #print "pan-fw | ".$cur->owner->owner->name()."\n";
                    $location_array[$tmp_name] = $tmp_name;
                    if( isset($counter_array[$tmp_name]))
                        $counter_array[$tmp_name] += 1;
                    else
                        $counter_array[$tmp_name] = 1;
                }
            }
            else
            {
                //possible to be on FW?????
                if( isset($cur->owner->owner->owner) && $cur->owner->owner->owner !== null && method_exists($cur->owner->owner->owner,'name') && $cur->owner->owner->owner->name() !== "")
                {
                    if( get_class($cur->owner->owner->owner) !== "PanoramaConf"
                        && get_class($cur->owner->owner->owner) !== "DeviceGroup"
                        && get_class($cur->owner->owner->owner) !== "PANConf"
                        && get_class($cur->owner->owner->owner) !== "VirtualSystem"
                        && get_class($cur->owner->owner->owner) !== "Container"
                        && get_class($cur->owner->owner->owner) !== "DeviceCloud"
                        && get_class($cur->owner->owner->owner) !== "DeviceOnPrem"
                        && get_class($cur->owner->owner->owner) !== "Snippet"
                    )
                    {
                        $tmp_name = "shared";
                    }
                    else
                    {
                        if( $cur->owner->owner->owner->name() !== "" )
                            $tmp_name = $cur->owner->owner->owner->name();
                        else
                            $tmp_name = "shared";
                    }


                    #print "fw-pan | ".$cur->owner->owner->owner->name()."\n";
                    $location_array[$tmp_name] = $tmp_name;
                    if( isset($counter_array[$tmp_name]))
                        $counter_array[$tmp_name] += 1;
                    else
                        $counter_array[$tmp_name] = 1;
                }
                //Firewall
                elseif( isset($cur->owner->owner) && $cur->owner->owner !== null && method_exists($cur->owner->owner,'name') )
                {
                    if( get_class($cur->owner->owner) !== "PanoramaConf"
                        && get_class($cur->owner->owner) !== "DeviceGroup"
                        && get_class($cur->owner->owner) !== "PANConf"
                        && get_class($cur->owner->owner) !== "VirtualSystem"
                        && get_class($cur->owner->owner) !== "Container"
                        && get_class($cur->owner->owner) !== "DeviceCloud"
                        && get_class($cur->owner->owner) !== "DeviceOnPrem"
                        && get_class($cur->owner->owner) !== "Snippet"
                    )
                    {
                        $tmp_name = "shared";
                    }
                    else
                    {
                        if ($cur->owner->owner->name() !== "")
                            $tmp_name = $cur->owner->owner->name();
                        else
                            $tmp_name = "shared";
                    }

                    #print "fw | ".$cur->owner->owner->name()."\n";
                    $location_array[$tmp_name] = $tmp_name;
                    if( isset($counter_array[$tmp_name]))
                        $counter_array[$tmp_name] += 1;
                    else
                        $counter_array[$tmp_name] = 1;
                }
            }


            if( get_class( $cur ) == "AddressGroup" || get_class( $cur ) == "ServiceGroup"  )
            {
                //why is this needed
                    ##print $cur->name()."\n";
                #$recursive_loc_array = $cur->getReferencesLocation( );
                    ##print_r( $recursive_loc_array );
                #$location_array = array_merge( $location_array, $recursive_loc_array );
            }
        }
        #print_r($location_array);
        return $location_array;
    }

    public function getReferencesLocationType( &$counter_array = array() )
    {
        $location_array = array();
        foreach( $this->refrules as $cur )
        {
            $debug = false;
            if( $debug )
            {
                print "--------------\n";
                print get_class( $cur)."\n";
                print $cur->name()."\n";
                if( isset($cur->owner->owner->owner->owner))
                    print "owner:". get_class( $cur->owner->owner->owner->owner )."\n";
            }
            if( isset($cur->owner->owner->owner->owner) && get_class( $cur->owner->owner->owner->owner ) == "PanoramaConf" )
            {
                //Panorama - Rule
                if( isset($cur->owner->owner->owner) && $cur->owner->owner->owner !== null
                    && method_exists($cur->owner->owner->owner,'name') && $cur->owner->owner->owner->name() !== "")
                {
                    if( $debug )
                        print "pan | ".$cur->owner->owner->owner->name()."\n";
                    $getClassName = get_class($cur->owner->owner->owner);
                    $location_array[ $getClassName] = $getClassName;
                    if( isset($counter_array[ $getClassName ]))
                        $counter_array[ $getClassName ] += 1;
                    else
                        $counter_array[ $getClassName ] = 1;
                }
            }
            elseif( isset($cur->owner->owner->owner->owner) && ( get_class( $cur->owner->owner->owner->owner ) == "TemplateStack" || get_class( $cur->owner->owner->owner->owner ) == "Template" ) )
            {
                //Panorama - Rule
                if( isset($cur->owner->owner->owner->owner) && $cur->owner->owner->owner->owner !== null
                    && method_exists($cur->owner->owner->owner->owner,'name') && $cur->owner->owner->owner->owner->name() !== "")
                {
                    if( $debug )
                        print "pan | ".$cur->owner->owner->owner->name()."\n";
                    $getClassName = get_class($cur->owner->owner->owner->owner);
                    $location_array[ $getClassName] = $getClassName;
                    if( isset($counter_array[ $getClassName ]))
                        $counter_array[ $getClassName ] += 1;
                    else
                        $counter_array[ $getClassName ] = 1;
                }
            }
            elseif( isset($cur->owner->owner->owner) && get_class( $cur->owner->owner->owner ) == "PanoramaConf" )
            {
                #Panorama - AddressGroup
                if( isset($cur->owner->owner) && $cur->owner->owner !== null && method_exists($cur->owner->owner,'name') && $cur->owner->owner->name() !== "")
                {
                    if( $debug )
                        print "pan-fw | ".$cur->owner->owner->name()."\n";
                    $getClassName = get_class($cur->owner->owner);
                    $location_array[ $getClassName ] = $getClassName;
                    if( isset($counter_array[ $getClassName ]))
                        $counter_array[ $getClassName ] += 1;
                    else
                        $counter_array[ $getClassName ] = 1;
                }
            }
            else
            {
                //possible to be on FW?????
                if( isset($cur->owner->owner->owner) && $cur->owner->owner->owner !== null
                    && method_exists($cur->owner->owner->owner,'name') && $cur->owner->owner->owner->name() !== "")
                {
                    if( $debug )
                        print "fw-pan | ".$cur->owner->owner->owner->name()."\n";
                    $getClassName = get_class($cur->owner->owner->owner);
                    $location_array[ $getClassName ] = $getClassName;
                    if( isset($counter_array[ $getClassName ]))
                        $counter_array[ $getClassName ] += 1;
                    else
                        $counter_array[ $getClassName ] = 1;
                }
                //Firewall
                elseif( isset($cur->owner->owner) && $cur->owner->owner !== null && method_exists($cur->owner->owner,'name') && $cur->owner->owner->name() !== "")
                {
                    if( $debug )
                        print "fw | ".$cur->owner->owner->name()."\n";
                    $getClassName = get_class($cur->owner->owner);
                    $location_array[ $getClassName ] = $getClassName;
                    if( isset($counter_array[ $getClassName ]))
                        $counter_array[ $getClassName ] += 1;
                    else
                        $counter_array[ $getClassName ] = 1;
                }
            }


            if( get_class( $cur ) == "AddressGroup" || get_class( $cur ) == "ServiceGroup"  )
            {
                //why is this needed
                ##print $cur->name()."\n";
                #$recursive_loc_array = $cur->getReferencesLocation( );
                ##print_r( $recursive_loc_array );
                #$location_array = array_merge( $location_array, $recursive_loc_array );
            }
        }
        #print_r($location_array);
        return $location_array;
    }

    public function getReferencesStore()
    {
        $store_array = array();
        foreach( $this->refrules as $cur )
        {
            if( isset($cur->owner->owner) && $cur->owner->owner !== null )
            {
                $class = get_class($cur->owner->owner);
                if( $class == "PanoramaConf" || $class == "PANConf"
                    || $class == "DeviceGroup" || $class == "VirtualSystem"
                    || $class == "BuckbeakConf" || $class == "FawkesConf"
                    || $class == "Container" || $class == "DeviceCloud" || $class == "DeviceOnPrem" || $class == "Snippet"
                )
                    $class = get_class($cur->owner);
                $class = strtolower($class);
                $store_array[$class] = $class;
            }
        }
        return $store_array;
    }

    /**
     * @param string $value
     */
    public function ReferencesStoreValidation($value)
    {
        $store_array = array();
        $store_array['addressstore'] = FALSE;
        $store_array['servicestore'] = FALSE;
        $store_array['rulestore'] = FALSE;
        $store_array['securityprofilegroupstore'] = FALSE;

        $store_array['logicalrouterstore'] = FALSE;
        $store_array['virtualrouterstore'] = FALSE;
        $store_array['ethernetifstore'] = FALSE;
        $store_array['tunnelifstore'] = FALSE;
        $store_array['gpgatewaystore'] = FALSE;
        $store_array['gpportalstore'] = FALSE;
        $store_array['ikegatewaystore'] = FALSE;
        $store_array['gretunnelstore'] = FALSE;
        $store_array['loopbackifstore'] = FALSE;
        $store_array['vlanifstore'] = FALSE;
        $store_array['zonestore'] = FALSE;


        if( !array_key_exists($value, $store_array) )
        {
            $store_string = "";
            $first = TRUE;
            foreach( array_keys($store_array) as $storeName )
            {
                if( $first )
                {
                    $store_string .= "'" . $storeName . "'";
                    $first = FALSE;
                }
                else
                    $store_string .= ", '" . $storeName . "'";
            }

            derr("this is not a store name: '" . $value . "' | possible names: " . $store_string . "\n");
        }
    }

    public function getReferencesType()
    {
        $type_array = array();
        foreach( $this->refrules as $cur )
        {
            if( isset($cur->owner) && $cur->owner !== null )
            {
                if( get_class($cur) == "URLProfile" )
                    $class = get_class($cur);
                else
                    $class = get_class($cur->owner);
                $class = strtolower($class);
                $type_array[$class] = $class;
            }

        }
        return $type_array;
    }

    /**
     * @param string $value
     */
    public function ReferencesTypeValidation($value)
    {
        $type_array = array();
        $type_array['address'] = FALSE;
        $type_array['addressgroup'] = FALSE;
        $type_array['service'] = FALSE;
        $type_array['servicegroup'] = FALSE;
        $type_array['securityrule'] = FALSE;
        $type_array['natrule'] = FALSE;
        $type_array['decryptionrule'] = FALSE;
        $type_array['appoverriderule'] = FALSE;
        $type_array['captiveportalrule'] = FALSE;
        $type_array['authenticationrule'] = FALSE;
        $type_array['pbfrule'] = FALSE;
        $type_array['qosrule'] = FALSE;
        $type_array['dosrule'] = FALSE;

        $type_array['urlprofile'] = FALSE;

        if( !array_key_exists($value, $type_array) )
        {
            $type_string = "";
            $first = TRUE;
            foreach( array_keys($type_array) as $typeName )
            {
                if( $first )
                {
                    $type_string .= "'" . $typeName . "'";
                    $first = FALSE;
                }
                else
                    $type_string .= ", '" . $typeName . "'";
            }

            derr("this is not a type name: '" . $value . "' | possible names: " . $type_string . "\n");
        }
    }

    /**
     * @param string $className
     * @return array
     */
    public function & findReferencesWithClass($className)
    {
        $ret = array();

        foreach( $this->refrules as $reference )
        {
            if( get_class($reference) == $className )
                $ret[] = $reference;
        }

        return $ret;
    }

    /**
     * @param string $className
     * @return array
     */
    public function & findReferencesWithOwnerClass($className)
    {
        $ret = array();

        foreach( $this->refrules as $reference )
        {
            if( get_class($reference->owner) == $className )
                $ret[] = $reference;
        }

        return $ret;
    }

    public function name()
    {
        return $this->name;
    }

    /**
     * Returns the location an object (or a referencer such as a rule, rule container or group) lives in:
     * DeviceGroup, PanoramaConf (Shared), VirtualSystem, PANConf, or an SCM container type.
     * Returns null if no such owner is found.
     */
    public static function findLocationOwner($object)
    {
        $locationClasses = array('DeviceGroup', 'PanoramaConf', 'VirtualSystem', 'PANConf',
            'Container', 'DeviceCloud', 'DeviceOnPrem', 'Snippet', 'FawkesConf', 'BuckbeakConf');

        $cur = $object;
        for( $i = 0; $i < 25 && $cur !== null && is_object($cur); $i++ )
        {
            if( in_array(get_class($cur), $locationClasses, TRUE) )
                return $cur;
            $cur = isset($cur->owner) ? $cur->owner : null;
        }

        return null;
    }

    /**
     * Same-name / override check, Panorama view.
     *
     * Panorama pushes ONE object per name to a firewall. When Shared / ancestor device groups and a
     * descendant device group hold objects with the same name, the setting
     * "deviceconfig setting management ancestor-objects-take-precedence" decides which one:
     *
     * off (default): the descendant's copy wins. A rule in D's ancestor chain naming the ancestor copy
     *   uses D's copy on D's firewalls. -> D's copy is used when an ancestor copy (any level up to
     *   Shared, not just the nearest) is referenced by something located in D's ancestor chain.
     *   Referencers in other branches do not count.
     *
     * yes: the highest ancestor's copy wins. Rules of a descendant naming its own copy use the
     *   ancestor's copy on the firewalls. -> this copy is used when it is the highest copy and a
     *   same-name copy in a descendant device group is referenced. A copy shadowed by an ancestor copy
     *   is never used via override.
     *
     * Firewall (vsys / shared): no override across levels -> FALSE.
     * SCM (Container / DeviceCloud / DeviceOnPrem / Snippet): previous behaviour (nearest copy up).
     * Referencers that are groups count conservatively, without checking whether the group is in use.
     */
    public function isUsedViaSameNameOverride(): bool
    {
        $info = $this->getSameNameOverrideInfo();
        return count($info['usedVia']) > 0;
    }

    /**
     * Same-name / override analysis of this object, Panorama view. Returns:
     *  'mode'         => 'firewall' | 'scm' | 'panorama'
     *  'precedence'   => bool, ancestor-objects-take-precedence
     *  'usedVia'      => list of array('ref' => referencer, 'via' => same-name copy it names):
     *                    referencers that make THIS object used on firewalls without referencing it directly
     *  'overriddenIn' => list of descendant DeviceGroup names holding their own same-name copy,
     *                    precedence off: their firewalls use their own copy, not this one
     *  'shadowedBy'   => precedence yes: the highest ancestor copy that firewalls use instead of this one
     *  'shadows'      => precedence yes, this is the highest copy: descendant DeviceGroup names whose copy it replaces
     */
    public function getSameNameOverrideInfo(): array
    {
        $info = array( 'mode' => null, 'precedence' => FALSE, 'usedVia' => array(),
            'overriddenIn' => array(), 'shadowedBy' => null, 'shadows' => array(),
            'ancestorCopies' => array(), 'descendantCopies' => array() );

        if( !isset($this->owner) || !is_object($this->owner) )
            return $info;

        $location = self::findLocationOwner($this);
        if( $location === null )
            return $info;

        $locationClass = get_class($location);

        if( $locationClass == 'VirtualSystem' || $locationClass == 'PANConf' )
        {
            $info['mode'] = 'firewall';
            // structural only (has.same-name.other.level): same-name copy in the firewall's shared
            if( isset($this->owner->parentCentralStore) && $this->owner->parentCentralStore !== null )
            {
                $found = $this->owner->parentCentralStore->find($this->name(), null, FALSE);
                if( $found !== null && $found !== $this )
                    $info['ancestorCopies'][] = $found;
            }
            return $info;
        }

        if( $locationClass != 'DeviceGroup' && $locationClass != 'PanoramaConf' )
        {
            // SCM: keep previous behaviour
            $info['mode'] = 'scm';
            if( isset($this->owner->parentCentralStore) && $this->owner->parentCentralStore !== null )
            {
                $tmp_obj = $this->owner->parentCentralStore->find($this->name(), null, TRUE);
                if( $tmp_obj !== null && $tmp_obj !== $this )
                {
                    $info['ancestorCopies'][] = $tmp_obj;
                    foreach( $tmp_obj->getReferences() as $ref )
                        $info['usedVia'][] = array('ref' => $ref, 'via' => $tmp_obj);
                }
            }
            return $info;
        }

        $info['mode'] = 'panorama';
        $panorama = ($locationClass == 'PanoramaConf') ? $location : $location->owner;
        $info['precedence'] = is_object($panorama) && method_exists($panorama, 'ancestorObjectsTakePrecedence')
            && $panorama->ancestorObjectsTakePrecedence();

        // same-name copies above (nearest first)
        $ancestorCopies = array();
        if( isset($this->owner->parentCentralStore) )
            for( $store = $this->owner->parentCentralStore; $store !== null; $store = (isset($store->parentCentralStore) ? $store->parentCentralStore : null) )
            {
                $found = $store->find($this->name(), null, FALSE);
                if( $found !== null && $found !== $this )
                    $ancestorCopies[] = $found;
            }

        // same-name copies in descendant device groups
        $descendantCopies = array();
        $storeProperty = null;
        foreach( get_object_vars($location) as $key => $value )
            if( $value === $this->owner )
            {
                $storeProperty = $key;
                break;
            }
        if( $storeProperty !== null )
        {
            $descendants = ($locationClass == 'PanoramaConf') ? $location->getDeviceGroups() : $location->childDeviceGroups(TRUE);
            foreach( $descendants as $dg )
            {
                if( !isset($dg->$storeProperty) || $dg->$storeProperty === null )
                    continue;
                $found = $dg->$storeProperty->find($this->name(), null, FALSE);
                if( $found !== null && $found !== $this )
                    $descendantCopies[$dg->name()] = $found;
            }
        }

        $info['ancestorCopies'] = $ancestorCopies;
        $info['descendantCopies'] = $descendantCopies;

        if( !$info['precedence'] )
        {
            // descendant copy wins
            $info['overriddenIn'] = array_keys($descendantCopies);

            if( $locationClass == 'PanoramaConf' )
                return $info;   // Shared has no ancestor

            /** @var DeviceGroup $location */
            $chain = array();
            for( $dg = $location->parentDeviceGroup; $dg !== null; $dg = $dg->parentDeviceGroup )
                $chain[spl_object_id($dg)] = TRUE;
            $chain[spl_object_id($panorama)] = TRUE;

            foreach( $ancestorCopies as $ancestorObj )
                foreach( $ancestorObj->getReferences() as $ref )
                {
                    // a referencer in this DG's ancestor chain reaches this DG's firewalls (groups count conservatively)
                    $refLocation = self::findLocationOwner($ref);
                    if( $refLocation !== null && isset($chain[spl_object_id($refLocation)]) )
                        $info['usedVia'][] = array('ref' => $ref, 'via' => $ancestorObj);
                }

            return $info;
        }

        // ancestor copy wins: references were rebound to the highest copy at load time
        if( count($ancestorCopies) > 0 )
        {
            $info['shadowedBy'] = end($ancestorCopies);
            return $info;
        }

        $info['shadows'] = array_keys($descendantCopies);
        foreach( $descendantCopies as $descendantObj )
            foreach( $descendantObj->getReferences() as $ref )
                $info['usedVia'][] = array('ref' => $ref, 'via' => $descendantObj);

        return $info;
    }

    /**
     * Same-name status across device-group levels; ancestor-objects-take-precedence is evaluated here,
     * so callers do not need to know the flag:
     *  'isOverriding'           this copy is pushed instead of a same-name copy on another level
     *  'isOverridden'           a same-name copy on another level is pushed instead of this copy
     *  'overridesUpperLevel'    this copy wins over a same-name copy in Shared / an ancestor (only possible with flag no)
     *  'overriddenAtLowerLevel' a same-name copy in a descendant wins over this copy (only possible with flag no)
     *  'sameNameOtherLevel'     a same-name copy exists on another level, whichever wins
     * Firewall: all FALSE. SCM: only the upper-level check, as before.
     */
    public function getSameNameLevelStatus(): array
    {
        $info = $this->getSameNameOverrideInfo();

        $status = array( 'isOverriding' => FALSE, 'isOverridden' => FALSE,
            'overridesUpperLevel' => FALSE, 'overriddenAtLowerLevel' => FALSE, 'sameNameOtherLevel' => FALSE );

        $hasUpper = count($info['ancestorCopies']) > 0;
        $hasLower = count($info['descendantCopies']) > 0;
        $status['sameNameOtherLevel'] = $hasUpper || $hasLower;

        if( $info['mode'] == 'scm' )
        {
            $status['overridesUpperLevel'] = $hasUpper;
            $status['isOverriding'] = $hasUpper;
            return $status;
        }
        if( $info['mode'] != 'panorama' )
            return $status;

        if( $info['precedence'] )
        {
            // highest copy wins
            $status['isOverridden'] = $hasUpper;
            $status['isOverriding'] = !$hasUpper && $hasLower;
        }
        else
        {
            // lowest copy wins; a middle copy overrides the upper one and is overridden by the lower one
            $status['overridesUpperLevel'] = $hasUpper;
            $status['overriddenAtLowerLevel'] = $hasLower;
            $status['isOverriding'] = $hasUpper;
            $status['isOverridden'] = $hasLower;
        }

        return $status;
    }

    /**
     * Unused = no direct reference AND not used via a same-name copy in an ancestor (Panorama view).
     * Valid for all object types.
     */
    public function objectIsUnused(): ?bool
    {
        if( $this->countReferences() > 0 )
            return FALSE;

        return !$this->isUsedViaSameNameOverride();
    }

    /**
     * Like objectIsUnused(), and additionally an object whose only referencers are groups
     * that are themselves unused (recursively) is unused.
     */
    public function objectIsUnusedRecursive(): ?bool
    {
        $className = "";

        if( get_class($this) == 'Service' || get_class($this) == 'ServiceGroup' )
            $className = 'ServiceGroup';
        elseif( get_class($this) == 'Address' || get_class($this) == 'AddressGroup' )
            $className = 'AddressGroup';
        elseif( get_class($this) == 'AntiVirusProfile'
            || get_class($this) == 'AntiSpywareProfile'
            || get_class($this) == 'DataFilteringProfile'
            || get_class($this) == 'DNSSecurityProfile'
            || get_class($this) == 'FileBlockingProfile'
            || get_class($this) == 'URLProfile'
            || get_class($this) == 'VirusAndWildfireProfile'
            || get_class($this) == 'VulnerabilityProfile'
            || get_class($this) == 'WildfireProfile'
            || get_class($this) == 'SecurityProfileGroup'
        )
            $className = 'SecurityProfileGroup';
        elseif( get_class($this) == 'App' || get_class($this) == 'AppFilter' || get_class($this) == 'AppGroup')
            $className = 'AppGroup';
        else
            return null;

        if( $this->countReferences() == 0 )
            return !$this->isUsedViaSameNameOverride();

        $groups = $this->findReferencesWithClass($className);

        if( count($groups) != $this->countReferences() )
            return FALSE;

        foreach( $groups as $group )
        {
            if( $group === $this )
                continue;
            if( !$group->objectIsUnusedRecursive() )
                return FALSE;
        }

        return TRUE;
    }
}
