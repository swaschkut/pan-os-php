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
 * Generic object merger.
 *
 * One merging flow for every object type; what differs per type is described by a "merge spec"
 * (an array of values and closures, see the *MergeSpec() methods at the end of this file).
 *
 * Flow per location (identical to the former tag_merging() / custom_url_category_merging()):
 *  1. hash tables: child device groups, own location, upper levels
 *  2. drop hashes with a single entry
 *  3. child device groups -> own location (create the picked object here if needed, replace, delete)
 *  4. own location (and ancestors with allowMergingWithUpperLevel): replace, delete or skip
 *  5. statistics; logging for exportCSV through deletedObject() / skippedObject()
 *
 * Spec keys:
 *  label, objectTxt, pluralTxt, storeProp, ancestorTypeLabel, differentValueTxt     strings
 *  valueAlgs                      dupAlgorithm values that use 'hash'
 *  listObjects(store)             objects of one store
 *  eligible(object)               object takes part (value algorithms)
 *  hash(object)                   hash for the value algorithms
 *  whereUsedHash(object)|null     hash for 'whereused' (null: not supported)
 *  eligibleWhereUsed(object)      object takes part ('whereused', before the reference check)
 *  lookupName(picked)             name used to find / create the picked object in the target store
 *  childConflict(other, picked)   TRUE: a same-name object at child level blocks the creation
 *  skipReason(picked, other)      reason string for exportCSV, or null
 *  createCopy(store, picked, name) creates the picked object in the target store, returns it
 *  createdHashKey(created)        hash key under which the created object is added
 *  allowExistingMismatch()        TRUE: a different existing object does not block the merge
 *  valueText(object)              value shown in skip messages
 *  remove(object)                 removes the object (API or offline)
 *  ancestorTypeOk(ancestor)       the ancestor is of the right type
 *  ancestorMergeable(ancestor)    with allowMergingWithUpperLevel: the ancestor can take the object
 *  beforeAncestorCompare(object, ancestor)   called before the ancestor value comparison
 *  ancestorValueText(ancestor)    "color: '..'" / "Value: '..'" in ancestor messages
 *  ancestorDiffReason(ancestor, object)|null  prints the difference and returns a reason (or null)
 *  errorValueText(object, ancestor)          value part of the "|->ERROR ancestor" text
 */
trait MergerEngine
{
    function genericObjectMerging( array $spec )
    {
        $objectTxt = $spec['objectTxt'];
        $pluralTxt = $spec['pluralTxt'];

        foreach( $this->location_array as $tmp_location )
        {
            $store = null;
            $findLocation = null;
            $parentStore = null;
            $childDeviceGroups = null;
            $this->locationSettings( $tmp_location, $spec['label'], $store, $findLocation, $parentStore, $childDeviceGroups );

            //
            // Building a hash table of all objects with same value
            //
            if( $this->upperLevelSearch )
                $objectsToSearchThrough = $store->nestedPointOfView();
            else
                $objectsToSearchThrough = $spec['listObjects']( $store );

            $nestedQueries = null;
            $hashMap = array();
            $child_hashMap = array();
            $child_NamehashMap = array();
            $upperHashMap = array();
            if( in_array( $this->dupAlg, $spec['valueAlgs'], TRUE ) )
            {
                //todo: childDG/childDG to parentDG merge is always done; should it not combined to upperLevelSearch value?
                foreach( $childDeviceGroups as $dg )
                {
                    /** @var DeviceGroup $dg */
                    $storeProp = $spec['storeProp'];
                    foreach( $spec['listObjects']( $dg->$storeProp ) as $object )
                    {
                        if( !$spec['eligible']( $object ) )
                            continue;

                        if( $this->excludeFilter !== null && $this->excludeFilter->matchSingleObject(array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
                            continue;

                        $value = $spec['hash']( $object );

                        $child_hashMap[$value][] = $object;
                        $child_NamehashMap[$object->name()][] = $object;
                    }
                }

                foreach( $objectsToSearchThrough as $object )
                {
                    if( !$spec['eligible']( $object ) )
                        continue;

                    if( $this->excludeFilter !== null && $this->excludeFilter->matchSingleObject(array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
                        continue;

                    $value = $spec['hash']( $object );

                    if( $object->owner === $store )
                    {
                        $hashMap[$value][] = $object;
                        if( $parentStore !== null )
                            $object->ancestor = self::findAncestor( $parentStore, $object, $spec['storeProp'] );
                    }
                    else
                        $upperHashMap[$value][] = $object;
                }
            }
            elseif( $this->dupAlg == 'whereused' && $spec['whereUsedHash'] !== null )
                foreach( $objectsToSearchThrough as $object )
                {
                    if( !$spec['eligibleWhereUsed']( $object ) )
                        continue;

                    if( $object->countReferences() == 0 )
                        continue;

                    if( $this->excludeFilter !== null && $this->excludeFilter->matchSingleObject(array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
                        continue;

                    $value = $spec['whereUsedHash']( $object );
                    if( $object->owner === $store )
                    {
                        $hashMap[$value][] = $object;
                        if( $parentStore !== null )
                            $object->ancestor = self::findAncestor( $parentStore, $object, $spec['storeProp'] );
                    }
                    else
                        $upperHashMap[$value][] = $object;
                }
            else derr("unsupported use case");

            //
            // Hashes with single entries have no duplicate, let's remove them
            //
            $countConcernedObjects = 0;
            self::removeSingleEntries( $hashMap, $child_hashMap, $upperHashMap, $countConcernedObjects);

            $countConcernedChildObjects = 0;
            self::removeSingleEntries( $child_hashMap, $hashMap, $upperHashMap, $countConcernedChildObjects);


            PH::print_stdout( " - found " . count($hashMap) . " duplicates values totalling {$countConcernedObjects} {$objectTxt} objects which are duplicate" );

            PH::print_stdout( " - found " . count($child_hashMap) . " duplicates childDG values totalling {$countConcernedChildObjects} {$objectTxt} objects which are duplicate" );


            PH::print_stdout( "\n\nNow going after each duplicates for a replacement" );

            //
            // child device groups -> this location
            //
            $countChildRemoved = 0;
            $countChildCreated = 0;
            foreach( $child_hashMap as $index => &$hash )
            {
                PH::print_stdout();
                PH::print_stdout( " - value '{$index}'" );

                $pickedObject = $this->PickObject( $hash);

                $tmp_DG_name = $store->owner->name();
                if( $tmp_DG_name == "" )
                    $tmp_DG_name = 'shared';

                $tmpPickedName = $spec['lookupName']( $pickedObject );
                $tmp_object = $store->find( $tmpPickedName );
                if( $tmp_object == null )
                {
                    if( isset( $child_NamehashMap[ $pickedObject->name() ] ) )
                    {
                        $exit = false;
                        $exitObject = null;
                        foreach( $child_NamehashMap[ $pickedObject->name() ] as $obj )
                        {
                            if( $spec['childConflict']( $obj, $pickedObject ) )
                            {
                                $exit = true;
                                $exitObject = $obj;
                            }
                        }

                        if( $exit )
                        {
                            $stringSkippedReason = $spec['skipReason']( $pickedObject, $exitObject );
                            PH::print_stdout( "   * SKIP: no creation of object in DG: '".$tmp_DG_name."' as object with same name '{$exitObject->name()}' and different value exist at childDG level" );
                            if( $stringSkippedReason === null )
                                $this->skippedObject( $index, $pickedObject, $exitObject);
                            else
                                $this->skippedObject( $index, $pickedObject, $exitObject, $stringSkippedReason);
                            continue;
                        }
                    }
                    PH::print_stdout( "   * create object in DG: '".$tmp_DG_name."' : '".$tmpPickedName."'" );

                    if( $this->action === "merge" )
                    {
                        $tmp_object = $spec['createCopy']( $store, $pickedObject, $tmpPickedName );

                        $value = $spec['createdHashKey']( $tmp_object );
                        $hashMap[$value][] = $tmp_object;
                    }
                    else
                        $tmp_object = "[".$tmp_DG_name."] - ".$pickedObject->name()." {new}";

                    $countChildCreated++;
                }
                else
                {
                    if( $tmp_object->equals( $pickedObject ) )
                    {
                        PH::print_stdout( "   * keeping object '{$tmp_object->_PANC_shortName()}'" );
                    }
                    else
                    {
                        if( !$spec['allowExistingMismatch']() )
                        {
                            $stringSkippedReason = $spec['skipReason']( $pickedObject, $tmp_object );
                            PH::print_stdout( "    - SKIP: object name '{$pickedObject->_PANC_shortName()}' [with value '" . $spec['valueText']( $pickedObject ) . "'] is not IDENTICAL to object name: '{$tmp_object->_PANC_shortName()}' [with value '" . $spec['valueText']( $tmp_object ) . "'] " );
                            if( $stringSkippedReason === null )
                                $this->skippedObject( $index, $pickedObject, $tmp_object);
                            else
                                $this->skippedObject( $index, $pickedObject, $tmp_object, $stringSkippedReason);
                            continue;
                        }
                    }
                }


                // Merging loop finally!
                foreach( $hash as $objectIndex => $object )
                {
                    PH::print_stdout("    - replacing '{$object->_PANC_shortName()}' ...");
                    if( $this->action === "merge" )
                        $object->replaceMeGlobally($tmp_object, $this->apiMode);

                    PH::print_stdout("    - deleting '{$object->_PANC_shortName()}'");
                    self::deletedObject( $index, $tmp_object, $object);

                    if( $this->action === "merge" )
                        $spec['remove']( $object );

                    $countChildRemoved++;
                }
            }

            if( count( $child_hashMap ) >0 )
                PH::print_stdout( "\n\nDuplicates ChildDG removal is now done. Number of objects after cleanup: '{$store->count()}' (removed/created {$countChildRemoved}/{$countChildCreated} {$pluralTxt})\n" );

            //
            // this location (and its ancestors with allowMergingWithUpperLevel)
            //
            $countRemoved = 0;
            foreach( $hashMap as $index => &$hash )
            {
                PH::print_stdout();
                PH::print_stdout( " - name '{$index}'" );

                $pickedObject = $this->hashMapPickfilter( $upperHashMap, $index, $hash );

                // Merging loop finally!
                foreach( $hash as $objectIndex => $object )
                {
                    if( isset($object->ancestor) )
                    {
                        $ancestor = $object->ancestor;
                        $ancestor_different_value = "";

                        if( !$spec['ancestorTypeOk']( $ancestor ) )
                        {
                            PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' has one ancestor which is not {$spec['ancestorTypeLabel']} object");
                            continue;
                        }

                        if( $this->upperLevelSearch && $spec['ancestorMergeable']( $ancestor ) )
                        {
                            $spec['beforeAncestorCompare']( $object, $ancestor );

                            if( $object->sameValue($ancestor) || $this->dupAlg == 'samename' )
                            {
                                if( $this->dupAlg == 'identical' )
                                    if( $pickedObject->name() != $ancestor->name() )
                                    {
                                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' is not IDENTICAL to object name from upperlevel '{$pickedObject->_PANC_shortName()}' ");
                                        continue;
                                    }

                                $text = "    - object '{$object->name()}' merged with its ancestor, deleting: " . $object->_PANC_shortName();
                                self::deletedObject( $index, $ancestor, $object);

                                if( $this->action === "merge" )
                                {
                                    $object->replaceMeGlobally($ancestor, $this->apiMode);
                                    $spec['remove']( $object );
                                }

                                PH::print_stdout($text);

                                $text = "         ancestor name: '{$ancestor->name()}' DG: ";
                                if( $ancestor->owner->owner->name() == "" ) $text .= "'shared'";
                                else $text .= "'{$ancestor->owner->owner->name()}'";
                                $text .= "  " . $spec['ancestorValueText']( $ancestor ) . " ";
                                PH::print_stdout($text);

                                if( $pickedObject === $object )
                                    $pickedObject = $ancestor;

                                $countRemoved++;

                                if( $this->mergeCountLimit !== FALSE && $countRemoved >= $this->mergeCountLimit )
                                {
                                    PH::print_stdout("\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACHED mergeCountLimit ({$this->mergeCountLimit})");
                                    break 2;
                                }

                                continue;
                            }
                            else
                                $ancestor_different_value = $spec['differentValueTxt'];

                            if( $this->addMissingObjects )
                                continue;
                        }

                        PH::print_stdout("    - object '{$object->name()}' cannot be merged because it has an ancestor " . $ancestor_different_value . "");
                        $tmp_skippedReason = $spec['ancestorDiffReason']( $ancestor, $object );

                        $text = "         ancestor name: '{$ancestor->name()}' DG: ";
                        if( $ancestor->owner->owner->name() == "" ) $text .= "'shared'";
                        else $text .= "'{$ancestor->owner->owner->name()}'";
                        $text .= "  " . $spec['ancestorValueText']( $ancestor ) . " ";
                        PH::print_stdout($text);
                        if( $tmp_skippedReason !== null )
                            $this->skippedObject( $index, $object, $ancestor, $tmp_skippedReason);

                        if( $this->upperLevelSearch )
                        {
                            $tmpstring = "|->ERROR ancestor: '" . $object->_PANC_shortName() . "  " . $spec['errorValueText']( $object, $ancestor ) . " "."' cannot be merged. | ".$text;
                            $this->skippedObject( $index, $object, $ancestor, $tmpstring);
                        }
                        else
                            $tmpstring = "|-> ancestor: '" . $object->_PANC_shortName() . "' you did not allow to merged";
                        self::deletedObjectSetRemoved( $index, $tmpstring );

                        continue;
                    }

                    if( $object === $pickedObject )
                        continue;

                    if( $this->dupAlg != 'identical' )
                    {
                        PH::print_stdout("    - replacing '{$object->_PANC_shortName()}' ...");
                        if( $this->action === "merge" )
                            $object->replaceMeGlobally($pickedObject, $this->apiMode);

                        PH::print_stdout("    - deleting '{$object->_PANC_shortName()}'");
                        self::deletedObject( $index, $pickedObject, $object);

                        if( $this->action === "merge" )
                            $spec['remove']( $object );

                        $countRemoved++;

                        if( $this->mergeCountLimit !== FALSE && $countRemoved >= $this->mergeCountLimit )
                        {
                            PH::print_stdout("\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACHED mergeCountLimit ({$this->mergeCountLimit})");
                            break 2;
                        }
                    }
                    else
                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' is not IDENTICAL");
                }

            }

            PH::print_stdout( "\n\nDuplicates removal is now done. Number of objects after cleanup: '{$store->count()}' (removed {$countRemoved} {$pluralTxt})\n" );

        }
    }

    // ------------------------------------------------------------------------------------------
    // merge specs
    // ------------------------------------------------------------------------------------------

    function tagMergeSpec(): array
    {
        return array(
            'label' => "Tag",
            'objectTxt' => "tag",
            'pluralTxt' => "tags",
            'storeProp' => "tagStore",
            'ancestorTypeLabel' => "TAG",
            'differentValueTxt' => "with different color",
            'valueAlgs' => array('samecolor', 'identical', 'samename'),

            'listObjects' => function( $store ) {
                return $store->tags();
            },
            'eligible' => function( $object ) {
                return $object->isTag() && !$object->isTmp();
            },
            // samecolor: tags with the same color are merged, whatever their name; tags without a color
            //            are never merged by color (they keep a hash of their own name)
            // identical / samename: tags are compared by name; the color decides through sameValue() / equals()
            'hash' => function( $object ) {
                if( $this->dupAlg == 'samecolor' )
                {
                    $color = $object->getColor();
                    if( $color !== '' && $color !== 'none' )
                        return 'color:' . $color;
                    return 'name:' . $object->name();
                }
                return $object->name();
            },
            'eligibleWhereUsed' => function( $object ) {
                return $object->isTag() && !$object->isTmp();
            },
            'whereUsedHash' => function( $object ) {
                return $object->getRefHashComp() . $object->name();
            },

            'lookupName' => function( $picked ) {
                $name = $picked->name();
                TAG::revertreplaceNamewith($name);
                return $name;
            },
            'childConflict' => function( $other, $picked ) {
                //Todo: validate if this is correct; expectation is not same color swaschkut 20230525
                return !$other->sameValue($picked) && $this->dupAlg !== 'samename';
            },
            'skipReason' => function( $picked, $other ) {
                return null;
            },
            'createCopy' => function( $store, $picked, $name ) {
                /** @var TagStore $store */
                $created = $store->createTag( $name );
                $created->setColor( $picked->getColor() );
                if( $this->apiMode )
                    $created->API_sync();
                return $created;
            },
            'createdHashKey' => function( $created ) {
                $name = $created->name();
                TAG::replaceNamewith($name);
                return $name;
            },
            'allowExistingMismatch' => function() {
                return FALSE;
            },
            'valueText' => function( $object ) {
                return $object->getColor();
            },
            'remove' => function( $object ) {
                if( $this->apiMode )
                    $object->owner->API_removeTag($object);
                else
                    $object->owner->removeTag($object);
            },

            'ancestorTypeOk' => function( $ancestor ) {
                return $ancestor->isTag();
            },
            'ancestorMergeable' => function( $ancestor ) {
                return !$ancestor->isTmp();
            },
            'beforeAncestorCompare' => function( $object, $ancestor ) {
            },
            'ancestorValueText' => function( $ancestor ) {
                return "color: '{$ancestor->getColor()}'";
            },
            'ancestorDiffReason' => function( $ancestor, $object ) {
                return null;
            },
            'errorValueText' => function( $object, $ancestor ) {
                return "color: '{$object->getColor()}'";
            },
        );
    }

    function customUrlCategoryMergeSpec(): array
    {
        $objectClass = "customURLProfile";

        return array(
            'label' => "Custom-Url-Category",
            'objectTxt' => "custome-url-category",
            'pluralTxt' => "custome-url-category",
            'storeProp' => "customURLProfileStore",
            'ancestorTypeLabel' => "custome-url-category",
            'differentValueTxt' => "with different value",
            'valueAlgs' => array('samevalue', 'identical', 'samename'),

            'listObjects' => function( $store ) {
                /** @var SecurityProfileStore $store */
                return $store->getAll();
            },
            'eligible' => function( $object ) use ( $objectClass ) {
                return get_class($object) === $objectClass;
            },
            'hash' => function( $object ) {
                $value = '';
                foreach( $object->getmembers() as $member )
                    $value .= './.' . $member;
                return $value;
            },
            // 'whereused' is not offered for custom URL categories (see merger_arguments())
            'eligibleWhereUsed' => null,
            'whereUsedHash' => null,

            'lookupName' => function( $picked ) {
                return $picked->name();
            },
            'childConflict' => function( $other, $picked ) {
                return !$this->addMissingObjects && !$other->sameValue($picked);
            },
            'skipReason' => function( $picked, $other ) {
                return $picked->displayValueDiff($other, 7, true);
            },
            'createCopy' => function( $store, $picked, $name ) {
                $created = $store->newCustomSecurityProfileURL( $name );
                foreach( $picked->getmembers() as $member )
                    $created->addMember( $member );
                if( $this->apiMode )
                    $created->API_sync();
                return $created;
            },
            'createdHashKey' => function( $created ) {
                return $created->name();
            },
            'allowExistingMismatch' => function() {
                return $this->addMissingObjects;
            },
            'valueText' => function( $object ) {
                return implode("./.", $object->getmembers());
            },
            'remove' => function( $object ) {
                if( $this->apiMode )
                    $object->owner->API_removeSecurityProfile($object);
                else
                    $object->owner->removeSecurityProfile($object);
            },

            'ancestorTypeOk' => function( $ancestor ) use ( $objectClass ) {
                return get_class($ancestor) === $objectClass;
            },
            'ancestorMergeable' => function( $ancestor ) use ( $objectClass ) {
                return get_class($ancestor) === $objectClass;
            },
            'beforeAncestorCompare' => function( $object, $ancestor ) {
                if( $this->addMissingObjects && !$object->sameValue($ancestor) )
                    $this->customURLcategoryGetValueDiff( $ancestor, $object, true );
            },
            'ancestorValueText' => function( $ancestor ) {
                return "Value: '" . implode("./.", $ancestor->getmembers()) . "'";
            },
            'ancestorDiffReason' => function( $ancestor, $object ) {
                $ancestor->displayValueDiff( $object, 7);
                return $ancestor->displayValueDiff( $object, 7, true);
            },
            'errorValueText' => function( $object, $ancestor ) {
                return "value: '" . implode("./.", $ancestor->getmembers()) . "'";
            },
        );
    }
}
