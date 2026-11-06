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
    /** hash maps of the location being merged, for spec hooks (e.g. address_service_hash_map_check) */
    public $mergeCtx = array();

    /** @var MergeSafety|null effective-policy check of the running merger (address / service objects and groups) */
    public $mergeSafety = null;

    private function startMergeSafety( string $storeProp )
    {
        $this->mergeSafety = MergeSafety::supports( $storeProp ) ? new MergeSafety( $this->pan, $storeProp, (bool)$this->addMissingObjects ) : null;
    }

    /**
     * TRUE (and the skip is printed / logged for exportCSV) when the effective-policy check refused an operation.
     * $reason: result of a MergeSafety check (null: allowed)
     */
    private function mergeSafetyBlocks( $reason, $index, $kept, $removed ): bool
    {
        if( $reason === null )
            return FALSE;

        PH::print_stdout( "    - SKIP: '{$removed->_PANC_shortName()}' not merged, " . $reason );
        $this->skippedObject( $index, $kept, $removed, $reason );
        return TRUE;
    }

    /** spec hook or null */
    private function mergeHook( array $spec, string $key )
    {
        return ( isset($spec[$key]) && $spec[$key] !== null ) ? $spec[$key] : null;
    }

    function genericObjectMerging( array $spec )
    {
        $objectTxt = $spec['objectTxt'];
        $pluralTxt = $spec['pluralTxt'];

        $hashCheck = $this->mergeHook($spec, 'hashCheck');
        $storeCount = function( $store ) use ( $spec ) {
            $h = $this->mergeHook($spec, 'storeCount');
            return $h !== null ? $h( $store ) : $store->count();
        };
        $check = function( $index, $object ) use ( $hashCheck ) {
            return $hashCheck === null || $hashCheck( $index, $object );
        };

        $this->startMergeSafety( $spec['storeProp'] );
        $safety = $this->mergeSafety;

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

            $withChildAncestor = !empty($spec['childAncestor']);

            $nestedQueries = null;
            $hashMap = array();
            $NamehashMap = array();
            $child_hashMap = array();
            $child_NamehashMap = array();
            $upperHashMap = array();
            $upper_NamehashMap = array();

            $addOwn = function( $object, $value ) use ( &$hashMap, &$NamehashMap, &$upperHashMap, &$upper_NamehashMap, $store, $parentStore, &$childDeviceGroups, $spec, $withChildAncestor ) {
                if( $object->owner === $store )
                {
                    $hashMap[$value][] = $object;
                    $NamehashMap[$object->name()][] = $object;
                    if( $parentStore !== null )
                        $object->ancestor = self::findAncestor( $parentStore, $object, $spec['storeProp'] );
                    if( $withChildAncestor )
                        $object->childancestor = self::findChildAncestor( $childDeviceGroups, $object, $spec['storeProp'] );
                }
                else
                {
                    $upperHashMap[$value][] = $object;
                    $upper_NamehashMap[$object->name()][] = $object;
                }
            };

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

                    $addOwn( $object, $spec['hash']( $object ) );
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

                    $addOwn( $object, $spec['whereUsedHash']( $object ) );
                }
            else derr("unsupported use case");

            //
            // Hashes with single entries have no duplicate, let's remove them
            //
            $countConcernedObjects = 0;
            self::removeSingleEntries( $hashMap, $child_hashMap, $upperHashMap, $countConcernedObjects);

            $countConcernedChildObjects = 0;
            self::removeSingleEntries( $child_hashMap, $hashMap, $upperHashMap, $countConcernedChildObjects);

            $this->mergeCtx = array( 'NamehashMap' => &$NamehashMap, 'upper_NamehashMap' => &$upper_NamehashMap, 'child_NamehashMap' => &$child_NamehashMap );


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

                if( !$check( $index, $pickedObject ) )
                    continue;

                $tmp_DG_name = $store->owner->name();
                if( $tmp_DG_name == "" )
                    $tmp_DG_name = 'shared';

                $tmpPickedName = $spec['lookupName']( $pickedObject );
                $tmp_object = $store->find( $tmpPickedName );
                $createAllowed = $this->mergeHook($spec, 'createAllowed');
                if( $tmp_object == null && $createAllowed !== null && !$createAllowed() )
                {
                    continue;
                }
                elseif( $tmp_object == null )
                {
                    if( isset( $child_NamehashMap[ $pickedObject->name() ] ) )
                    {
                        $conflictHook = $this->mergeHook($spec, 'childConflictObject');
                        $exitObject = null;
                        if( $conflictHook !== null )
                            $exitObject = $conflictHook( $child_NamehashMap[ $pickedObject->name() ], $pickedObject );
                        else
                        {
                            foreach( $child_NamehashMap[ $pickedObject->name() ] as $obj )
                            {
                                if( $spec['childConflict']( $obj, $pickedObject ) )
                                    $exitObject = $obj;
                            }
                        }

                        if( $exitObject !== null )
                        {
                            $stringSkippedReason = $spec['skipReason']( $pickedObject, $exitObject );
                            $messageHook = $this->mergeHook($spec, 'childConflictMessage');
                            if( $messageHook !== null )
                                PH::print_stdout( $messageHook( $tmp_DG_name, $exitObject ) );
                            else
                                PH::print_stdout( "   * SKIP: no creation of object in DG: '".$tmp_DG_name."' as object with same name '{$exitObject->name()}' and different value exist at childDG level" );
                            if( $stringSkippedReason === null )
                                $this->skippedObject( $index, $pickedObject, $exitObject);
                            else
                                $this->skippedObject( $index, $pickedObject, $exitObject, $stringSkippedReason);
                            continue;
                        }
                    }
                    if( $safety !== null && $this->mergeSafetyBlocks( $safety->checkPlace( $pickedObject, $store ), $index, $pickedObject, $pickedObject ) )
                        continue;

                    $suffixHook = $this->mergeHook($spec, 'createMessageSuffix');
                    PH::print_stdout( "   * create object in DG: '".$tmp_DG_name."' : '".$tmpPickedName."'" . ( $suffixHook !== null ? $suffixHook( $pickedObject ) : "" ) );

                    if( $this->action === "merge" )
                    {
                        $tmp_object = $spec['createCopy']( $store, $pickedObject, $tmpPickedName );

                        $value = $spec['createdHashKey']( $tmp_object );
                        $hashMap[$value][] = $tmp_object;
                        if( !empty($spec['createdAddToNameMap']) )
                            $NamehashMap[$tmp_object->name()][] = $tmp_object;
                    }
                    else
                        $tmp_object = "[".$tmp_DG_name."] - ".$pickedObject->name()." {new}";

                    $countChildCreated++;
                }
                else
                {
                    $keepHook = $this->mergeHook($spec, 'existingKeep');
                    $keep = $keepHook !== null ? $keepHook( $tmp_object, $pickedObject ) : $tmp_object->equals( $pickedObject );
                    if( $keep )
                    {
                        PH::print_stdout( "   * keeping object '{$tmp_object->_PANC_shortName()}'" );
                    }
                    else
                    {
                        if( !$spec['allowExistingMismatch']() )
                        {
                            $reasonHook = $this->mergeHook($spec, 'existingSkipReason');
                            $stringSkippedReason = $reasonHook !== null ? $reasonHook( $pickedObject, $tmp_object ) : $spec['skipReason']( $pickedObject, $tmp_object );
                            $skipMessageHook = $this->mergeHook($spec, 'existingSkipMessage');
                            if( $skipMessageHook !== null )
                                PH::print_stdout( $skipMessageHook( $pickedObject, $tmp_object ) );
                            else
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
                $beforeReplace = $this->mergeHook($spec, 'childBeforeReplace');
                $replaceHook = $this->mergeHook($spec, 'replace');
                foreach( $hash as $objectIndex => $object )
                {
                    if( $beforeReplace !== null && !$beforeReplace( $index, $object, $tmp_object, $pickedObject ) )
                        continue;

                    if( $safety !== null )
                    {
                        // without actions=merge the created object exists only as text: simulate it
                        if( is_object($tmp_object) )
                            $reason = $safety->checkReplace( $object, $tmp_object );
                        else
                            $reason = $safety->checkReplace( $object, $pickedObject, MergeSafety::placeOverlay( $pickedObject, $store ) );
                        if( $this->mergeSafetyBlocks( $reason, $index, is_object($tmp_object) ? $tmp_object : $pickedObject, $object ) )
                            continue;
                    }

                    PH::print_stdout("    - replacing '{$object->_PANC_shortName()}' ...");
                    $success = true;
                    if( $this->action === "merge" )
                    {
                        if( $replaceHook !== null )
                            $success = $replaceHook( $object, $tmp_object );
                        else
                            $object->replaceMeGlobally($tmp_object, $this->apiMode);
                    }

                    if( $success )
                    {
                        PH::print_stdout("    - deleting '{$object->_PANC_shortName()}'");
                        self::deletedObject( $index, $tmp_object, $object);

                        if( $this->action === "merge" )
                            $spec['remove']( $object );

                        $countChildRemoved++;
                    }
                }
            }

            if( count( $child_hashMap ) >0 )
            {
                $tmpCount = $storeCount( $store );
                PH::print_stdout( "\n\nDuplicates ChildDG removal is now done. Number of objects after cleanup: '{$tmpCount}' (removed/created {$countChildRemoved}/{$countChildCreated} {$pluralTxt})\n" );
            }

            //
            // this location (and its ancestors with allowMergingWithUpperLevel)
            //
            $mainIndexLabel = isset($spec['mainIndexLabel']) ? $spec['mainIndexLabel'] : 'name';
            $countRemoved = 0;
            $whereUsedPhase = $this->mergeHook($spec, 'whereUsedMainPhase');
            if( $this->dupAlg == 'whereused' && $whereUsedPhase !== null )
                $countRemoved = $whereUsedPhase( $hashMap );
            else
            foreach( $hashMap as $index => &$hash )
            {
                PH::print_stdout();
                PH::print_stdout( " - {$mainIndexLabel} '{$index}'" );

                $pickedObject = $this->hashMapPickfilter( $upperHashMap, $index, $hash );

                if( !$check( $index, $pickedObject ) )
                    continue;

                // Merging loop finally!
                foreach( $hash as $objectIndex => $object )
                {
                    if( !$check( $index, $object ) )
                        continue;

                    if( isset($object->ancestor) )
                    {
                        $ancestor = $object->ancestor;
                        $ancestor_different_value = "";

                        if( !$spec['ancestorTypeOk']( $ancestor ) )
                        {
                            $typeSkipHook = $this->mergeHook($spec, 'ancestorTypeSkip');
                            if( $typeSkipHook !== null )
                                $typeSkipHook( $index, $object, $ancestor );
                            else
                                PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' has one ancestor which is not {$spec['ancestorTypeLabel']} object");
                            continue;
                        }

                        if( $this->upperLevelSearch && $spec['ancestorMergeable']( $ancestor ) )
                        {
                            $spec['beforeAncestorCompare']( $object, $ancestor );

                            $sameValueHook = $this->mergeHook($spec, 'ancestorSameValue');
                            $sameValue = $sameValueHook !== null ? $sameValueHook( $object, $ancestor ) : ( $object->sameValue($ancestor) || $this->dupAlg == 'samename' );
                            if( $sameValue )
                            {
                                $preMergeHook = $this->mergeHook($spec, 'ancestorPreMerge');
                                if( $preMergeHook !== null )
                                {
                                    if( !$preMergeHook( $index, $object, $ancestor, $pickedObject ) )
                                        continue;
                                }
                                elseif( $this->dupAlg == 'identical' )
                                    if( $pickedObject->name() != $ancestor->name() )
                                    {
                                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' is not IDENTICAL to object name from upperlevel '{$pickedObject->_PANC_shortName()}' ");
                                        continue;
                                    }

                                if( $safety !== null && $this->mergeSafetyBlocks( $safety->checkReplace( $object, $ancestor ), $index, $ancestor, $object ) )
                                    continue;

                                $mergedTextHook = $this->mergeHook($spec, 'ancestorMergedText');
                                if( $mergedTextHook !== null )
                                    $text = $mergedTextHook( $object, $ancestor );
                                else
                                    $text = "    - object '{$object->name()}' merged with its ancestor, deleting: " . $object->_PANC_shortName();
                                self::deletedObject( $index, $ancestor, $object);

                                if( $this->action === "merge" )
                                {
                                    $replaceAncestorHook = $this->mergeHook($spec, 'replaceWithAncestor');
                                    if( $replaceAncestorHook !== null )
                                        $replaceAncestorHook( $object, $ancestor );
                                    else
                                        $object->replaceMeGlobally($ancestor, $this->apiMode);
                                    $removeAncestorHook = $this->mergeHook($spec, 'removeAfterAncestorMerge');
                                    if( $removeAncestorHook !== null )
                                        $removeAncestorHook( $object );
                                    else
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

                                if( !isset($spec['limitAfterAncestorMerge']) || $spec['limitAfterAncestorMerge'] )
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

                        $cannotHook = $this->mergeHook($spec, 'cannotMergeMessage');
                        if( $cannotHook !== null )
                            PH::print_stdout( $cannotHook( $object, $ancestor, $ancestor_different_value ) );
                        else
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
                            $errorHook = $this->mergeHook($spec, 'upperErrorString');
                            if( $errorHook !== null )
                                $tmpstring = $errorHook( $object, $ancestor, $ancestor_different_value, $text );
                            else
                                $tmpstring = "|->ERROR ancestor: '" . $object->_PANC_shortName() . "  " . $spec['errorValueText']( $object, $ancestor ) . " "."' cannot be merged. | ".$text;
                            $this->skippedObject( $index, $object, $ancestor, $tmpstring);
                            if( !empty($spec['breakAfterUpperError']) )
                                break;
                        }
                        else
                            $tmpstring = "|-> ancestor: '" . $object->_PANC_shortName() . "' you did not allow to merged";
                        self::deletedObjectSetRemoved( $index, $tmpstring );

                        continue;
                    }

                    $beforePickedHook = $this->mergeHook($spec, 'beforePickedCheck');
                    if( $beforePickedHook !== null && !$beforePickedHook( $index, $object, $pickedObject ) )
                        continue;

                    if( $object === $pickedObject )
                        continue;

                    if( $this->dupAlg != 'identical' || !empty($spec['mergeIntoPickedAllAlgs']) )
                    {
                        if( $safety !== null && $this->mergeSafetyBlocks( $safety->checkReplace( $object, $pickedObject ), $index, $pickedObject, $object ) )
                            continue;

                        $intoPickedHook = $this->mergeHook($spec, 'mergeIntoPicked');
                        if( $intoPickedHook !== null )
                        {
                            $removed = $intoPickedHook( $index, $object, $pickedObject );
                            if( $removed === null )
                                continue;
                            $countRemoved += $removed;
                        }
                        else
                        {
                            PH::print_stdout("    - replacing '{$object->_PANC_shortName()}' ...");
                            if( $this->action === "merge" )
                                $object->replaceMeGlobally($pickedObject, $this->apiMode);

                            PH::print_stdout("    - deleting '{$object->_PANC_shortName()}'");
                            self::deletedObject( $index, $pickedObject, $object);

                            if( $this->action === "merge" )
                                $spec['remove']( $object );

                            $countRemoved++;
                        }

                        if( $this->mergeCountLimit !== FALSE && $countRemoved >= $this->mergeCountLimit )
                        {
                            PH::print_stdout("\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACHED mergeCountLimit ({$this->mergeCountLimit})");
                            break 2;
                        }
                    }
                    else
                    {
                        $notIdenticalHook = $this->mergeHook($spec, 'notIdenticalMessage');
                        if( $notIdenticalHook !== null )
                            PH::print_stdout( $notIdenticalHook( $object ) );
                        else
                            PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' is not IDENTICAL");
                    }
                }

            }

            $tmpCount = $storeCount( $store );
            PH::print_stdout( "\n\nDuplicates removal is now done. Number of objects after cleanup: '{$tmpCount}' (removed {$countRemoved} {$pluralTxt})\n" );

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

    /**
     * type=securityprofile-merger profiletype=...
     *  samename (default): same profile name across the device-group hierarchy, merged only with the same content
     *  samevalue:          same content, also with different names
     * Content = profile XML compared like type=diff (XmlCompare), the profile name is ignored;
     * in vulnerability / spyware profiles the order of the rules counts.
     */
    function securityProfileMergeSpec( string $profileType, string $storeProp ): array
    {
        $ordered = array( 'rules' => TRUE );
        $content = function( $object ) use ( $ordered ) {
            return XmlCompare::canonical( $object->xmlroot, $ordered );
        };
        $sameContent = function( $a, $b ) use ( $content ) {
            return $content( $a ) === $content( $b );
        };
        $diffText = function( $a, $b ) use ( $ordered ) {
            return "different content: " . XmlCompare::differencesText( XmlCompare::differences( $a->xmlroot, $b->xmlroot, $ordered ) );
        };
        $short = function( $object ) use ( $content ) {
            return "content#" . substr( md5( $content( $object ) ), 0, 8 );
        };
        $sameClass = function( $object, $store ) {
            return is_object($object) && isset($object->xmlroot) && $object->xmlroot !== null && get_class($object) === $store->type;
        };

        return array(
            'label' => "SecurityProfile-" . $profileType,
            'objectTxt' => "security-profile",
            'pluralTxt' => "security-profiles",
            'storeProp' => $storeProp,
            'ancestorTypeLabel' => "security-profile '" . $profileType . "'",
            'differentValueTxt' => "with different content",
            'valueAlgs' => array( 'samename', 'samevalue' ),

            'listObjects' => function( $store ) {
                /** @var SecurityProfileStore $store */
                return $store->getAll();
            },
            'eligible' => function( $object ) use ( $sameClass ) {
                return $sameClass( $object, $object->owner );
            },
            'hash' => function( $object ) use ( $content ) {
                if( $this->dupAlg == 'samevalue' )
                    return md5( $content( $object ) );
                return $object->name();
            },
            'mainIndexLabel' => 'value',
            'eligibleWhereUsed' => null,
            'whereUsedHash' => null,

            'lookupName' => function( $picked ) {
                return $picked->name();
            },
            // same name at child level with other content: no creation
            'childConflict' => function( $other, $picked ) use ( $sameContent ) {
                return !$sameContent( $other, $picked );
            },
            'skipReason' => function( $picked, $other ) use ( $diffText ) {
                return $diffText( $picked, $other );
            },
            'createCopy' => function( $store, $picked, $name ) {
                /** @var SecurityProfileStore $store */
                $created = $store->cloneSecurityProfile( $picked, $name );
                if( $this->apiMode && method_exists($created, 'API_sync') )
                    $created->API_sync();
                return $created;
            },
            'createdHashKey' => function( $created ) use ( $content ) {
                if( $this->dupAlg == 'samevalue' )
                    return md5( $content( $created ) );
                return $created->name();
            },
            'existingKeep' => function( $existing, $picked ) use ( $sameContent ) {
                return $sameContent( $existing, $picked );
            },
            'allowExistingMismatch' => function() {
                return FALSE;
            },
            'valueText' => function( $object ) use ( $short ) {
                return $short( $object );
            },
            // child copies with other content than the kept object are not replaced
            'childBeforeReplace' => function( $index, $object, $target, $picked ) use ( $sameContent, $diffText ) {
                $compareWith = is_object($target) ? $target : $picked;
                if( $object === $compareWith || $sameContent( $object, $compareWith ) )
                    return TRUE;
                PH::print_stdout( "    - SKIP: '{$object->_PANC_shortName()}' has " . $diffText( $compareWith, $object ) );
                $this->skippedObject( $index, $compareWith, $object, $diffText( $compareWith, $object ) );
                return FALSE;
            },
            'remove' => function( $object ) {
                if( $this->apiMode )
                    $object->owner->API_removeSecurityProfile( $object );
                else
                    $object->owner->removeSecurityProfile( $object );
            },

            'ancestorTypeOk' => function( $ancestor ) use ( $sameClass ) {
                return $sameClass( $ancestor, $ancestor->owner );
            },
            'ancestorMergeable' => function( $ancestor ) use ( $sameClass ) {
                return $sameClass( $ancestor, $ancestor->owner );
            },
            'beforeAncestorCompare' => function( $object, $ancestor ) {
            },
            'ancestorSameValue' => function( $object, $ancestor ) use ( $sameContent ) {
                return $sameContent( $object, $ancestor );
            },
            'ancestorValueText' => function( $ancestor ) use ( $short ) {
                return $short( $ancestor );
            },
            'ancestorDiffReason' => function( $ancestor, $object ) use ( $diffText, $sameContent ) {
                if( $sameContent( $ancestor, $object ) )
                    $reason = "same content as the ancestor, merging with upper level not allowed (allowMergingWithUpperLevel)";
                else
                    $reason = $diffText( $ancestor, $object );
                PH::print_stdout( "         " . $reason );
                return $reason;
            },
            'errorValueText' => function( $object, $ancestor ) use ( $short ) {
                return $short( $ancestor );
            },
            // own location: only objects with the same content as the kept one
            'beforePickedCheck' => function( $index, $object, $picked ) use ( $sameContent, $diffText ) {
                if( $object === $picked || $sameContent( $object, $picked ) )
                    return TRUE;
                PH::print_stdout( "    - SKIP: '{$object->_PANC_shortName()}' has " . $diffText( $picked, $object ) );
                $this->skippedObject( $index, $picked, $object, $diffText( $picked, $object ) );
                return FALSE;
            },
        );
    }

    function addressMergeSpec(): array
    {
        $hashCheck = function( $index, $object ) {
            return $this->address_service_hash_map_check( $index, $object, $this->mergeCtx['NamehashMap'], $this->mergeCtx['upper_NamehashMap'], $this->mergeCtx['child_NamehashMap'], true, true, true );
        };
        // TRUE = merging must not happen ("|| is needed, to not change the existing traffic flow")
        $tagBlocks = function( $object, $other, $index ) {
            if( $object->tags->count() > 0 || $other->tags->count() > 0 )
            {
                if( $this->address_tag_DAG_check( $object, $other, $index) )
                    return TRUE;
            }
            if( $object->tags->count() + $other->tags->count() > $object->tagLimit )
            {
                if( $this->address_tag_merge_check( $object, $other, $index) )
                    return TRUE;
            }
            return FALSE;
        };
        // same-name object with a different value? TRUE / FALSE, or null = no decision (keep the previous one);
        // m32: /32 host objects with the same IP may be merged
        $differentValue = function( $obj, $pickedObject ) {
            /** @var Address $obj */
            /** @var Address $pickedObject */
            if( (!$obj->isType_FQDN() && !$pickedObject->isType_FQDN()) && $obj->getNetworkMask() == '32' && $pickedObject->getNetworkMask() == '32' )
                return !( $this->allowMergingObjectWith_m32 && ($obj->getNetworkValue() == $pickedObject->getNetworkValue()) );
            if( $obj->value() !== $pickedObject->value() )
                return TRUE;
            if( $obj->getNetworkMask() !== $pickedObject->getNetworkMask() )
                return TRUE;
            return null;
        };

        return array(
            'label' => "Address",
            'objectTxt' => "address",
            'pluralTxt' => "addresses",
            'storeProp' => "addressStore",
            'ancestorTypeLabel' => "address",
            'differentValueTxt' => "with different value",
            'valueAlgs' => array('sameaddress', 'identical'),
            'childAncestor' => TRUE,
            'mainIndexLabel' => 'value',
            'breakAfterUpperError' => TRUE,

            'listObjects' => function( $store ) {
                /** @var AddressStore $store */
                return $store->addressANDtmpIPObjects();
            },
            'eligible' => function( $object ) {
                return $object->isAddress() && ( $this->mergermodeghost || !$object->isTmpAddr() );
            },
            'hash' => function( $object ) {
                return $this->address_get_value_string( $object );
            },
            'eligibleWhereUsed' => function( $object ) {
                return $object->isAddress();
            },
            'whereUsedHash' => function( $object ) {
                return $this->address_get_value_string( $object );
            },
            'hashCheck' => $hashCheck,
            'storeCount' => function( $store ) {
                return $store->countAddresses();
            },

            // ---- child device groups -> this location
            'lookupName' => function( $picked ) {
                return $picked->name();
            },
            'createAllowed' => function() {
                return $this->dupAlg != 'identical';
            },
            'childConflict' => null,
            'childConflictObject' => function( $sameNameObjects, $pickedObject ) use ( $differentValue ) {
                $exit = FALSE;
                $exitObject = null;
                foreach( $sameNameObjects as $obj )
                {
                    if( $obj === $pickedObject )
                        continue;

                    $decision = $differentValue( $obj, $pickedObject );
                    if( $decision !== null )
                    {
                        $exit = $decision;
                        if( $exit )
                            $exitObject = $obj;
                    }

                    if( !$exit && isset($obj->owner->parentCentralStore) )
                    {
                        $tmp_obj = $obj->owner->parentCentralStore->find( $pickedObject->name(), null, true );
                        if( $tmp_obj !== null )
                        {
                            $decision = $differentValue( $tmp_obj, $pickedObject );
                            if( $decision !== null )
                            {
                                $exit = $decision;
                                if( $exit )
                                    $exitObject = $tmp_obj;
                            }
                        }
                    }
                }
                return $exit ? $exitObject : null;
            },
            'childConflictMessage' => function( $dgName, $exitObject ) {
                return "   * SKIP: no creation of object in DG: '" . $dgName . "' as object with same name '{$exitObject->name()}' and different value '{$exitObject->value()}' exist at childDG/parentDG level";
            },
            'skipReason' => function( $picked, $other ) {
                return "object with different value exist at childDG/parentDG level";
            },
            'createMessageSuffix' => function( $picked ) {
                return " type: " . $picked->type();
            },
            'createCopy' => function( $store, $picked, $name ) {
                /** @var AddressStore $store */
                if( $this->apiMode )
                    return $store->API_newAddress($name, $picked->type(), $picked->value(), $picked->description());
                return $store->newAddress($name, $picked->type(), $picked->value(), $picked->description());
            },
            'createdHashKey' => function( $created ) {
                return $this->address_get_value_string( $created );
            },
            'existingKeep' => function( $existing, $picked ) {
                /** @var Address $existing */
                if( $existing->isAddress() && $picked->isAddress() && $existing->type() === $picked->type() && $existing->value() === $picked->value() )
                    return TRUE;
                if( $existing->isAddress() && $picked->isAddress() && $existing->getNetworkValue() == $picked->getNetworkValue() )
                    return $this->address_get_value_string($existing) === $this->address_get_value_string($picked);
                return FALSE;
            },
            'allowExistingMismatch' => function() {
                return FALSE;
            },
            'existingSkipReason' => function( $picked, $existing ) {
                return "not identical";
            },
            'existingSkipMessage' => function( $pickedObject, $tmp_address ) {
                $string = "    - SKIP: object name '{$pickedObject->_PANC_shortName()}'";
                if( $pickedObject->isAddress() )
                    $string .= " [with value '{$pickedObject->value()}']";
                else
                    $string .= " [AdressGroup]";
                $string .= " is not IDENTICAL to object name: '{$tmp_address->_PANC_shortName()}'";
                if( $tmp_address->isAddress() )
                    $string .= " [with value '{$tmp_address->value()}']";
                else
                    $string .= " [AdressGroup]";
                return $string;
            },
            'valueText' => function( $object ) {
                return $object->value();
            },
            'childBeforeReplace' => function( $index, $object, $tmp_address ) use ( $hashCheck, $tagBlocks ) {
                /** @var Address $object */
                if( $tmp_address === null )
                    return FALSE;
                if( $object->isTmpAddr() )
                    return FALSE;
                if( !$hashCheck( $index, $object ) )
                    return FALSE;

                if( $this->dupAlg == 'identical' )
                    if( $object->name() != $tmp_address->name() )
                    {
                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' [with value '{$object->value()}'] is not IDENTICAL to object name from upperlevel '{$tmp_address->_PANC_shortName()}' [with value '{$tmp_address->value()}'] ");
                        $this->skippedObject( $index, $tmp_address, $object, "not identical");
                        return FALSE;
                    }

                return !$tagBlocks( $object, $tmp_address, $index );
            },
            'replace' => function( $object, $target ) {
                $success = $object->__replaceWhereIamUsed($this->apiMode, $target, TRUE, 5);
                $object->merge_tag_description_to($target, $this->apiMode);
                return $success;
            },
            'remove' => function( $object ) {
                if( $this->apiMode )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);
            },

            // ---- this location and its ancestors
            'ancestorTypeOk' => function( $ancestor ) {
                return $ancestor->isAddress();
            },
            'ancestorTypeSkip' => function( $index, $object, $ancestor ) {
                PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' as one ancestor is of type addressgroup");
                $this->skippedObject( $index, $object, $ancestor, "ancestor of type addressgroup");
            },
            'ancestorMergeable' => function( $ancestor ) {
                return !$ancestor->isGroup() && ($ancestor->isType_ipNetmask() || $ancestor->isType_ipRange() || $ancestor->isType_FQDN() || $ancestor->isTmpAddr() );
            },
            'beforeAncestorCompare' => function( $object, $ancestor ) {
            },
            'ancestorSameValue' => function( $object, $ancestor ) {
                return $object->getIP4Mapping()->equals($ancestor->getIP4Mapping()) || ($object->isType_FQDN() && $ancestor->isType_FQDN()) && ($object->value() == $ancestor->value());
            },
            'ancestorPreMerge' => function( $index, $object, $ancestor, $pickedObject ) use ( $tagBlocks ) {
                if( $this->address_get_value_string($pickedObject) != $this->address_get_value_string($ancestor) )
                {
                    PH::print_stdout("    - SKIP: object name '{$ancestor->_PANC_shortName()}' [with value '{$ancestor->value()}'] is not matching to object name from upperlevel '{$pickedObject->_PANC_shortName()}' [with value '{$pickedObject->value()}'] ");
                    $this->skippedObject( $index, $pickedObject, $ancestor, "not matching to object name from upperlevel");
                    return FALSE;
                }

                if( $this->dupAlg == 'identical' )
                    if( $pickedObject->name() != $ancestor->name() )
                    {
                        PH::print_stdout("    - SKIP: object name '{$ancestor->_PANC_shortName()}' [with value '{$ancestor->value()}'] is not IDENTICAL to object name from upperlevel '{$pickedObject->_PANC_shortName()}' [with value '{$pickedObject->value()}'] ");
                        $this->skippedObject( $index, $pickedObject, $ancestor, "not IDENTICAL to object name from upperlevel");
                        return FALSE;
                    }

                if( $tagBlocks( $pickedObject, $ancestor, $index ) )
                    return FALSE;

                if( $this->action === "merge" )
                    $object->merge_tag_description_to($ancestor, $this->apiMode);

                return TRUE;
            },
            'ancestorMergedText' => function( $object, $ancestor ) {
                if( isset($ancestor->owner) )
                {
                    $tmp_ancestor_DGname = $ancestor->owner->owner->name();
                    if( $tmp_ancestor_DGname === "" )
                        $tmp_ancestor_DGname = "shared";
                }
                else
                    $tmp_ancestor_DGname = "shared";

                return "    - object '{$object->name()}' DG: '" . $object->owner->owner->name() . "' merged with its ancestor at DG: '" . $tmp_ancestor_DGname . "', deleting: " . $object->_PANC_shortName();
            },
            'replaceWithAncestor' => function( $object, $ancestor ) {
                $object->replaceMeGlobally($ancestor);
            },
            'ancestorValueText' => function( $ancestor ) {
                return "value: '{$ancestor->value()}'";
            },
            'cannotMergeMessage' => function( $object, $ancestor, $differentValueTxt ) {
                return "    - object '{$object->name()}' '{$ancestor->type()}' cannot be merged because it has an ancestor " . $differentValueTxt . "";
            },
            'ancestorDiffReason' => function( $ancestor, $object ) {
                return null;
            },
            'upperErrorString' => function( $object, $ancestor, $differentValueTxt, $text ) {
                return "|->ERROR object '{$object->name()}' '{$ancestor->type()}' cannot be merged because it has an ancestor " . $differentValueTxt . " | ".$text;
            },
            'errorValueText' => null,
            'mergeIntoPicked' => function( $index, $object, $pickedObject ) use ( $tagBlocks ) {
                if( $pickedObject->isType_TMP() )
                    return null;

                if( $tagBlocks( $object, $pickedObject, $index ) )
                    return null;

                PH::print_stdout("    - replacing '{$object->_PANC_shortName()}' ...");

                PH::print_stdout("    - deleting '{$object->_PANC_shortName()}'");
                self::deletedObject($index, $pickedObject, $object);

                $removed = 0;
                if( $this->action === "merge" )
                {
                    $success = $object->__replaceWhereIamUsed($this->apiMode, $pickedObject, TRUE, 5);

                    $object->merge_tag_description_to($pickedObject, $this->apiMode);

                    if( $success )
                    {
                        if( $object->owner !== null )
                        {
                            if( $this->apiMode )
                                $object->owner->API_remove($object);
                            else
                                $object->owner->remove($object);

                            $removed = 1;
                        }
                    }
                }
                return $removed;
            },
            'notIdenticalMessage' => function( $object ) {
                return "    - SKIP: object name '{$object->_PANC_shortName()}' [with value '{$object->value()}'] is not IDENTICAL";
            },
        );
    }

    function serviceMergeSpec(): array
    {
        $hashCheck = function( $index, $object ) {
            return $this->address_service_hash_map_check( $index, $object, $this->mergeCtx['NamehashMap'], $this->mergeCtx['upper_NamehashMap'], $this->mergeCtx['child_NamehashMap'], true, true, true );
        };
        $differs = function( $obj, $pickedObject ) {
            /** @var Service $obj */
            return !$obj->dstPortMapping()->equals($pickedObject->dstPortMapping())
                || !$obj->srcPortMapping()->equals($pickedObject->srcPortMapping())
                || $obj->getOverride() != $pickedObject->getOverride()
                || $obj->protocol() != $pickedObject->protocol();
        };
        $removeWithTrue = function( $object ) {
            if( $this->apiMode )
                $object->owner->API_remove($object, TRUE);
            else
                $object->owner->remove($object, TRUE);
        };
        $ancestorText = function( $ancestor ) {
            $text = "         ancestor name: '{$ancestor->name()}' DG: ";
            if( $ancestor->owner->owner->name() == "" ) $text .= "'shared'";
            else $text .= "'{$ancestor->owner->owner->name()}'";
            $text .=  "  value: '{$ancestor->protocol()}/{$ancestor->getDestPort()}' ";
            return $text;
        };

        return array(
            'label' => "Service",
            'objectTxt' => "service",
            'pluralTxt' => "services",
            'storeProp' => "serviceStore",
            'ancestorTypeLabel' => "service",
            'differentValueTxt' => "",
            'valueAlgs' => array('sameports', 'samedstsrcports', 'identical'),
            'childAncestor' => TRUE,
            'mainIndexLabel' => 'value',
            'createdAddToNameMap' => TRUE,
            'limitAfterAncestorMerge' => FALSE,
            'mergeIntoPickedAllAlgs' => TRUE,

            'listObjects' => function( $store ) {
                /** @var ServiceStore $store */
                return $store->serviceObjects();
            },
            'eligible' => function( $object ) {
                return $object->isService() && !$object->isTmpSrv();
            },
            // all value algorithms hash the destination ports; the rest is decided by servicePickedObjectValidation()
            'hash' => function( $object ) {
                return $object->dstPortMapping()->mappingToText();
            },
            'eligibleWhereUsed' => function( $object ) {
                return $object->isService() && !$object->isTmpSrv();
            },
            'whereUsedHash' => function( $object ) {
                return $object->getRefHashComp() . $object->protocol();
            },
            'hashCheck' => $hashCheck,
            'storeCount' => function( $store ) {
                return $store->countServices();
            },

            // ---- child device groups -> this location
            'lookupName' => function( $picked ) {
                return $picked->name();
            },
            'createAllowed' => function() {
                return $this->dupAlg != 'identical';
            },
            'childConflict' => null,
            'childConflictObject' => function( $sameNameObjects, $pickedObject ) use ( $differs ) {
                $exit = FALSE;
                $exitObject = null;
                foreach( $sameNameObjects as $obj )
                {
                    if( $differs( $obj, $pickedObject ) )
                    {
                        $exit = TRUE;
                        $exitObject = $obj;
                    }

                    if( isset($obj->owner->parentCentralStore) )
                    {
                        $tmp_obj = $obj->owner->parentCentralStore->find( $pickedObject->name(), null, true );
                        if( $tmp_obj !== null && $differs( $tmp_obj, $pickedObject ) )
                        {
                            $exit = TRUE;
                            $exitObject = $tmp_obj;
                        }
                    }
                }
                return $exit ? $exitObject : null;
            },
            'childConflictMessage' => function( $dgName, $exitObject ) {
                return "   * SKIP: no creation of object in DG: '".$dgName."' as object with same name '{$exitObject->name()}' and different value '{$exitObject->dstPortMapping()->mappingToText()}' exist at childDG level";
            },
            'skipReason' => function( $picked, $other ) {
                return "different value";
            },
            'createCopy' => function( $store, $picked, $name ) {
                /** @var ServiceStore $store */
                if( $this->apiMode )
                    return $store->API_newService($name, $picked->protocol(), $picked->getDestPort(), $picked->description(), $picked->getSourcePort());
                return $store->newService($name, $picked->protocol(), $picked->getDestPort(), $picked->description(), $picked->getSourcePort());
            },
            'createdHashKey' => function( $created ) {
                return $created->dstPortMapping()->mappingToText();
            },
            'allowExistingMismatch' => function() {
                return FALSE;
            },
            'existingSkipReason' => function( $picked, $existing ) {
                return "not identical";
            },
            'existingSkipMessage' => function( $pickedObject, $tmp_service ) {
                $string = "    - SKIP: object name '{$pickedObject->_PANC_shortName()}'\n";
                if( $pickedObject->isService() )
                {
                    /* @var Service $pickedObject */
                    $string .= "            [protocol '{$pickedObject->protocol()}']";
                    $string .= " [with dport value '{$pickedObject->getDestPort()}']";
                    if( $pickedObject->getTimeout() != '' )
                        $string .= " [timeout '{$pickedObject->getTimeout()}']";
                    if( $pickedObject->getHalfcloseTimeout() != '' )
                        $string .= " [HalfcloseTimeout '{$pickedObject->getHalfcloseTimeout()}']";
                    if( $pickedObject->getTimewaitTimeout() != '' )
                        $string .= " [TimewaitTimeout '{$pickedObject->getTimewaitTimeout()}']";
                    if( !empty($pickedObject->getSourcePort()) )
                        $string .= " [with sport value '{$pickedObject->getSourcePort()}']\n";
                    else
                        $string .= "\n";
                }
                else
                    $string .= " [ServiceGroup] ";

                $string .= "       is not IDENTICAL to object name: '{$tmp_service->_PANC_shortName()}'\n";

                if( $tmp_service->isService() )
                {
                    $string .= "            [protocol '{$tmp_service->protocol()}']";
                    $string .= " [with dport value '{$tmp_service->getDestPort()}']";
                    if( $pickedObject->getTimeout() != '' )
                        $string .= " [timeout '{$pickedObject->getTimeout()}']";
                    if( $pickedObject->getHalfcloseTimeout() != '' )
                        $string .= " [HalfcloseTimeout '{$pickedObject->getHalfcloseTimeout()}']";
                    if( $pickedObject->getTimewaitTimeout() != '' )
                        $string .= " [TimewaitTimeout '{$pickedObject->getTimewaitTimeout()}']";
                    if( !empty($tmp_service->getSourcePort()) )
                        $string .= " [with sport value '{$tmp_service->getSourcePort()}']\n";
                    else
                        $string .= "\n";
                }
                else
                    $string .= " [ServiceGroup] ";

                return $string;
            },
            'valueText' => function( $object ) {
                return $object->getDestPort();
            },
            'childBeforeReplace' => function( $index, $object, $tmp_service, $pickedObject ) use ( $hashCheck, $differs ) {
                if( $tmp_service === null )
                    return FALSE;

                if( !$hashCheck( $index, $object ) )
                    return FALSE;

                //validate if object with same name at upperlevel has same type / value
                //if not it can be a problem if the upperlevel obejct is used in an upperlevel addressgroup and this address-group is used at same level as $object is located
                $upper_NamehashMap = $this->mergeCtx['upper_NamehashMap'];
                if( isset( $upper_NamehashMap[$pickedObject->name()] ) )
                {
                    $skip2 = FALSE;
                    $skip3 = FALSE;
                    $skippedOBJ = null;

                    foreach( $upper_NamehashMap[$pickedObject->name()] as $key => $overridenOBJ )
                    {
                        if( !$overridenOBJ->isService() )
                        {
                            $skip2 = TRUE;
                            $skippedOBJ = $overridenOBJ;
                            break;
                        }
                        if( $differs( $object, $overridenOBJ ) )
                        {
                            $skip3 = TRUE;
                            $skippedOBJ = $overridenOBJ;
                            break;
                        }
                    }

                    if( $skip2 )
                    {
                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' as one ancestor is of type addressgroup");
                        $this->skippedObject( $index, $object, $skippedOBJ, "ancestor of type addressgroup");
                        return FALSE;
                    }
                    if( $skip3 )
                    {
                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' as one ancestor has same name, but different value");
                        $this->skippedObject( $index, $object, $skippedOBJ, " ancestor has same name, but different value");
                        return FALSE;
                    }
                }

                if( $this->dupAlg == 'identical' )
                    if( $object->name() != $tmp_service->name() )
                    {
                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' is not IDENTICAL to object name from upperlevel '{$tmp_service->_PANC_shortName()}'");
                        $this->skippedObject( $index, $tmp_service, $object);
                        return FALSE;
                    }

                return !$this->servicePickedObjectValidation( $index, $object, $tmp_service );
            },
            'replace' => function( $object, $target ) {
                return $object->__replaceWhereIamUsed($this->apiMode, $target, TRUE, 5);
            },
            'remove' => function( $object ) {
                if( $this->apiMode )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);
            },

            // ---- this location and its ancestors
            'ancestorTypeOk' => function( $ancestor ) {
                return $ancestor->isService();
            },
            'ancestorTypeSkip' => function( $index, $object, $ancestor ) {
                PH::print_stdout( "    - SKIP: object name '{$object->_PANC_shortName()}' as one ancestor is of type servicegroup" );
                $this->skippedObject( $index, $object, $ancestor);
            },
            'ancestorMergeable' => function( $ancestor ) {
                return !$ancestor->isGroup() && !$ancestor->isTmpSrv();
            },
            'beforeAncestorCompare' => function( $object, $ancestor ) {
            },
            'ancestorSameValue' => function( $object, $ancestor ) {
                return $object->dstPortMapping()->equals($ancestor->dstPortMapping());
            },
            'ancestorPreMerge' => function( $index, $object, $ancestor, $pickedObject ) {
                if( $this->servicePickedObjectValidation( $index, $object, $ancestor ) )
                    return FALSE;

                if( $this->dupAlg == 'identical' )
                    if( $object->name() != $ancestor->name() )
                    {
                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' is not IDENTICAL to object name from upperlevel '{$ancestor->_PANC_shortName()}'");
                        $this->skippedObject( $index, $ancestor, $object);
                        return FALSE;
                    }
                return TRUE;
            },
            'replaceWithAncestor' => function( $object, $ancestor ) {
                $object->replaceMeGlobally($ancestor);
            },
            'removeAfterAncestorMerge' => $removeWithTrue,
            'ancestorValueText' => function( $ancestor ) {
                return "value: '{$ancestor->protocol()}/{$ancestor->getDestPort()}'";
            },
            'cannotMergeMessage' => function( $object, $ancestor, $differentValueTxt ) {
                return "    - object '{$object->name()}' cannot be merged because it has an ancestor";
            },
            'ancestorDiffReason' => function( $ancestor, $object ) {
                return null;
            },
            'upperErrorString' => function( $object, $ancestor, $differentValueTxt, $text ) {
                return "|->ERROR ancestor: '" . $object->_PANC_shortName() . "' cannot be merged. | ".$text;
            },
            'errorValueText' => null,
            'beforePickedCheck' => function( $index, $object, $pickedObject ) {
                return !$this->servicePickedObjectValidation( $index, $object, $pickedObject );
            },
            'mergeIntoPicked' => function( $index, $object, $pickedObject ) use ( $removeWithTrue ) {
                if( $this->dupAlg == 'identical' )
                    if( $object->name() != $pickedObject->name() )
                    {
                        PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' is not IDENTICAL to object name from upperlevel '{$pickedObject->_PANC_shortName()}'");
                        $this->skippedObject( $index, $pickedObject, $object);
                        return null;
                    }

                PH::print_stdout("    - replacing '{$object->_PANC_shortName()}' ...");
                $success = true;
                if( $this->action === "merge" )
                    $success = $object->__replaceWhereIamUsed($this->apiMode, $pickedObject, TRUE, 5);

                if( $success )
                {
                    PH::print_stdout("    - deleting '{$object->_PANC_shortName()}'");
                    self::deletedObject($index, $pickedObject, $object);
                    if( $this->action === "merge" )
                        $removeWithTrue( $object );
                    return 1;
                }
                return 0;
            },

            // ---- 'whereused': merge the ports of all services used at exactly the same places
            'whereUsedMainPhase' => function( &$hashMap ) use ( $hashCheck, $ancestorText ) {
                $countRemoved = 0;
                foreach( $hashMap as $index => &$hash )
                {
                    PH::print_stdout();

                    $setList = array();
                    foreach( $hash as $object )
                        $setList[] = PH::getLocationString($object->owner->owner) . '/' . $object->name();
                    PH::print_stdout( " - duplicate set : '" . PH::list_to_string($setList) . "'" );

                    $pickedObject = $this->PickObject( $hash);

                    if( !$hashCheck( $index, $pickedObject ) )
                        continue;

                    PH::print_stdout( "   * keeping object '{$pickedObject->_PANC_shortName()}'" );

                    foreach( $hash as $object )
                    {
                        /** @var Service $object */
                        if( !$hashCheck( $index, $object ) )
                            continue;

                        if( isset($object->ancestor) )
                        {
                            $ancestor = $object->ancestor;
                            PH::print_stdout( "    - object '{$object->name()}' cannot be merged because it has an ancestor" );

                            $text = $ancestorText( $ancestor );
                            PH::print_stdout( $text );

                            if( $this->upperLevelSearch )
                            {
                                $tmpstring = "|->ERROR ancestor: '" . $object->_PANC_shortName() . "' cannot be merged. | ".$text ;
                                $this->skippedObject( $index, $object, $ancestor, $tmpstring);
                            }
                            else
                                $tmpstring = "|-> ancestor: '" . $object->_PANC_shortName() . "' you did not allow to merged";
                            self::deletedObjectSetRemoved( $index, $tmpstring );

                            continue;
                        }

                        if( $object === $pickedObject )
                            continue;

                        if( $this->mergeSafety !== null && $this->mergeSafetyBlocks( $this->mergeSafety->checkWhereUsedServiceMerge( $object, $pickedObject ), $index, $pickedObject, $object ) )
                            continue;

                        $localMapping = $object->dstPortMapping();
                        PH::print_stdout( "    - adding the following ports to first service: " . $localMapping->mappingToText() . "" );
                        if( $this->action === "merge" )
                        {
                            $localMapping->mergeWithMapping($pickedObject->dstPortMapping());

                            if( $pickedObject->isTcp() )
                                $tmp_string = str_replace("tcp/", "", $localMapping->tcpMappingToText());
                            else
                                $tmp_string = str_replace("udp/", "", $localMapping->udpMappingToText());

                            if( $this->apiMode )
                            {
                                $pickedObject->API_setDestPort( $tmp_string );
                                PH::print_stdout("    - removing '{$object->name()}' from places where it's used:");
                                $object->API_removeWhereIamUsed(TRUE, 7);
                                $object->owner->API_remove($object);
                            }
                            else
                            {
                                $pickedObject->setDestPort( $tmp_string );
                                PH::print_stdout("    - removing '{$object->name()}' from places where it's used:");
                                $object->removeWhereIamUsed(TRUE, 7);
                                $object->owner->remove($object);
                            }
                            $countRemoved++;
                        }

                        if( $this->mergeCountLimit !== FALSE && $countRemoved >= $this->mergeCountLimit )
                        {
                            PH::print_stdout( "\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACH mergeCountLimit ({$this->mergeCountLimit})" );
                            break 2;
                        }
                    }
                    PH::print_stdout( "   * final mapping for service '{$pickedObject->name()}': {$pickedObject->getDestPort()}" );

                    PH::print_stdout();
                }
                return $countRemoved;
            },
        );
    }


    /*
     * ------------------------------------------------------------------------------------------
     * Group merger (address-group, service-group)
     *
     * Groups are merged differently from plain objects: a group from a child device group is
     * moved (not copied) to the target location, its members are checked there, and with
     * dupAlgorithm=whereused the members of the duplicates are merged into the picked group.
     *
     * Flow per location (identical to the former addressgroup_merging() / servicegroup_merging()):
     *  1. hash tables: child device groups, own location, upper levels
     *  2. drop hashes with a single entry
     *  3. child device groups -> own location (move the picked group here if needed, replace, delete)
     *  4. own location (and ancestors with allowMergingWithUpperLevel): replace, delete or skip
     *
     * Group spec keys:
     *  locationType, storeProp, childDoneLabel           strings
     *  hashGenerator()                returns the hash closure for $this->dupAlg (derr if unsupported)
     *  listGroups(store)              groups of one store
     *  eligible(object)               object takes part
     *  mainSkip(object, store, childDeviceGroups)       TRUE: ignore this object (own / upper level)
     *  childPhase                     FALSE: child device group duplicates are not processed
     *  checkParent(hash)              TRUE: the picked group can not be moved
     *  moveMessage(dgName, picked)    "move object to DG" line
     *  memberCheck(index, picked, store, dgName)        TRUE: a member blocks the move
     *  targetNotGroup(index, picked, target)            prints / logs: existing object is no group
     *  targetMismatch(index, picked, target, pickedValue, targetValue)
     *                                 existing group has another value; TRUE: skip this hash
     *  childPhaseChildAncestorCheck   TRUE: check childancestor in the child merge loop as well
     *  valueDiff(ancestor, object, display)              FALSE: skip ("was delete earlier")
     *  ancestorNonGroupSkip           TRUE: an ancestor that is no group is skipped right away
     *  ancestorMergeable(ancestor)    the object can be merged into its ancestor
     *  ancestorMergedText(object, dgName)
     *  removeAfterAncestorMerge(object)
     *  ancestorNotMerged(index, object, ancestor, dgName)  TRUE: skip this object
     *  notIdenticalReason, notIdenticalPickedReason     exportCSV reasons
     *  reportWithoutMerge             TRUE: "deleting" is reported without actions=merge as well
     *  countGroups(store)
     */
    function genericGroupMerging( array $g )
    {
        $this->startMergeSafety( $g['storeProp'] );
        $safety = $this->mergeSafety;

        foreach( $this->location_array as $tmp_location )
        {
            $store = null;
            $findLocation = null;
            $parentStore = null;
            $childDeviceGroups = null;
            $this->locationSettings( $tmp_location, $g['locationType'], $store, $findLocation, $parentStore, $childDeviceGroups);

            $hashGenerator = $g['hashGenerator']();

            //
            // Building a hash table of all group objects with same value
            //
            if( $this->upperLevelSearch )
                $objectsToSearchThrough = $store->nestedPointOfView();
            else
                $objectsToSearchThrough = $g['listGroups']( $store );

            $hashMap = array();
            $child_hashMap = array();
            $upperHashMap = array();

            //todo: childDG/childDG to parentDG merge is always done; should it not combined to upperLevelSearch value?
            foreach( $childDeviceGroups as $dg )
            {
                /** @var DeviceGroup $dg */
                foreach( $g['listGroups']( $dg->{$g['storeProp']} ) as $object )
                {
                    if( !$g['eligible']( $object ) )
                        continue;

                    if( $this->excludeFilter !== null && $this->excludeFilter->matchSingleObject(array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
                        continue;

                    $value = $hashGenerator($object);
                    if( $value === null )
                        continue;

                    $child_hashMap[$value][] = $object;
                }
            }
            if( !$g['childPhase'] )
                $child_hashMap = array();

            foreach( $objectsToSearchThrough as $object )
            {
                if( !$g['eligible']( $object ) )
                    continue;

                if( $this->excludeFilter !== null && $this->excludeFilter->matchSingleObject(array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
                    continue;

                if( $g['mainSkip']( $object, $store, $childDeviceGroups ) )
                    continue;

                $value = $hashGenerator($object);
                if( $value === null )
                    continue;

                if( $object->owner === $store )
                {
                    $hashMap[$value][] = $object;
                    if( $parentStore !== null )
                        $object->ancestor = self::findAncestor( $parentStore, $object, $g['storeProp']);

                    $object->childancestor = self::findChildAncestor( $childDeviceGroups, $object, $g['storeProp']);
                }
                else
                    $upperHashMap[$value][] = $object;
            }

            //
            // Hashes with single entries have no duplicate, let's remove them
            //
            $countConcernedObjects = 0;
            foreach( $hashMap as $index => &$hash )
            {
                if( count($hash) == 1 && !isset($upperHashMap[$index]) && !isset(reset($hash)->ancestor) )
                    unset($hashMap[$index]);
                else
                    $countConcernedObjects += count($hash);
            }
            unset($hash);
            $countConcernedChildObjects = 0;
            foreach( $child_hashMap as $index => &$hash )
            {
                if( count($hash) == 1 && !isset($upperHashMap[$index]) && !isset(reset($hash)->ancestor) )
                    unset($child_hashMap[$index]);
                else
                    $countConcernedChildObjects += count($hash);
            }
            unset($hash);

            PH::print_stdout( " - found " . count($hashMap) . " duplicate values totalling {$countConcernedObjects} groups which are duplicate" );

            PH::print_stdout( " - found " . count($child_hashMap) . " duplicates childDG values totalling {$countConcernedChildObjects} groups which are duplicate" );


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

                $pickedObject = $this->PickObject( $hash );

                $tmp_DG_name = $store->owner->name();
                if( $tmp_DG_name == "" )
                    $tmp_DG_name = 'shared';

                $target = $store->find( $pickedObject->name() );
                if( $target == null && $this->dupAlg != "identical" )
                {
                    PH::print_stdout( $g['moveMessage']( $tmp_DG_name, $pickedObject ) );

                    if( $g['checkParent']( $hash ) )
                    {
                        PH::print_stdout("     this object can not be created" );
                        continue;
                    }

                    if( $g['memberCheck']( $index, $pickedObject, $store, $tmp_DG_name ) )
                        continue;

                    if( $safety !== null && $this->mergeSafetyBlocks( $safety->checkMove( $pickedObject, $store ), $index, $pickedObject, $pickedObject ) )
                        continue;

                    if( $this->action === "merge" )
                    {
                        self::deletedObject($index, $pickedObject, $pickedObject);
                        if( isset($g['moveObject']) )
                            $g['moveObject']( $pickedObject, $store );
                        elseif( $this->apiMode )
                        {
                            $oldXpath = $pickedObject->getXPath();
                            $pickedObject->owner->remove($pickedObject);
                            $store->add($pickedObject);
                            $pickedObject->API_sync();
                            $this->pan->connector->sendDeleteRequest($oldXpath);
                        }
                        else
                        {
                            $pickedObject->owner->remove($pickedObject);
                            $store->add($pickedObject);
                        }
                        $target = $store->find( $pickedObject->name() );
                        $value = $hashGenerator($target);
                        $hashMap[$value][] = $target;
                    }

                    $countChildCreated++;
                }
                elseif( $target === null )
                    continue;
                else
                {
                    if( !$this->groupIsGroup( $g, $target ) )
                    {
                        $g['targetNotGroup']( $index, $pickedObject, $target );
                        continue;
                    }

                    $pickedObject_value = $hashGenerator($pickedObject);
                    $target_value = $hashGenerator($target);

                    if( $pickedObject_value == $target_value )
                        PH::print_stdout( "   * keeping object '{$target->_PANC_shortName()}'" );
                    elseif( $g['targetMismatch']( $index, $pickedObject, $target, $pickedObject_value, $target_value ) )
                        continue;
                    elseif( $this->action === "merge" && $hashGenerator($pickedObject) != $hashGenerator($target) )
                    {
                        // missing members could not be added: merging would change the group content
                        PH::print_stdout( "    - SKIP: object name '{$pickedObject->_PANC_shortName()}' still differs from '{$target->_PANC_shortName()}' after adding the missing members" );
                        $this->skippedObject( $index, $pickedObject, $target, 'still different after adding missing members');
                        continue;
                    }
                }


                // Merging loop finally!
                foreach( $hash as $objectIndex => $object )
                {
                    if( $target === null )
                        continue;

                    if( $g['childPhaseChildAncestorCheck'] )
                    {
                        $check = $this->groupChildAncestorCheck( $g, $index, $object );
                        if( $check === 'break' )
                            break;
                        if( $check === 'continue' )
                            continue;
                    }

                    if( $this->dupAlg == 'identical' )
                        if( $object->name() != $target->name() )
                        {
                            PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' is not IDENTICAL to object name from upperlevel '{$target->_PANC_shortName()}'");
                            $this->skippedObject( $index, $target, $object, $g['notIdenticalReason']);
                            continue;
                        }

                    if( $object !== $target )
                    {
                        if( $safety !== null && $this->mergeSafetyBlocks( $safety->checkReplace( $object, $target ), $index, $target, $object ) )
                            continue;

                        PH::print_stdout("    - group '{$object->name()}' DG: '" . $object->owner->owner->name() . "' merged with its ancestor at DG: '" . $target->owner->owner->name() . "', deleting: " . $object->_PANC_shortName());
                        self::deletedObject($index, $target, $object);
                        PH::print_stdout("    - replacing '{$object->_PANC_shortName()}' ...");
                        if( $this->action === "merge" )
                        {
                            $success = $this->groupReplace( $g, $object, $target );

                            if( $success )
                            {
                                $this->groupRemove( $g, $object );

                                $countChildRemoved++;
                            }
                        }
                    }
                }
            }
            if( count( $child_hashMap ) > 0 )
            {
                $tmpCount = $g['countGroups']( $store );
                PH::print_stdout( "\n\nDuplicates ChildDG removal is now done. Number of objects after cleanup: '{$tmpCount}' (removed/created {$countChildRemoved}/{$countChildCreated} {$g['childDoneLabel']})\n" );
            }

            //
            // this location (and upper levels)
            //
            $countRemoved = 0;
            foreach( $hashMap as $index => &$hash )
            {
                PH::print_stdout();
                PH::print_stdout( " - value '{$index}'" );

                if( $g['printDuplicateSet'] )
                {
                    $setList = array();
                    foreach( $hash as $object )
                        $setList[] = PH::getLocationString($object->owner->owner) . '/' . $object->name();
                    PH::print_stdout(" - duplicate set : '" . PH::list_to_string($setList) . "'");
                }

                $pickedObject = $this->hashMapPickfilter( $upperHashMap, $index, $hash );

                // Merging loop finally!
                foreach( $hash as $object )
                {
                    if( isset($object->ancestor) )
                    {
                        $ancestor = $object->ancestor;

                        if( $g['ancestorNonGroupSkip'] && !$ancestor->isGroup() )
                        {
                            PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' as one ancestor is of type: ". get_class( $ancestor )." '{$ancestor->_PANC_shortName()}' value: ".$ancestor->value());
                            $this->skippedObject( $index, $object, $ancestor, 'ancestor of type: '.get_class( $ancestor ));
                            continue;
                        }

                        if( $g['ancestorMergeable']( $ancestor ) )
                        {
                            if( $this->dupAlg == 'identical' )
                                if( $object->name() != $ancestor->name() )
                                {
                                    PH::print_stdout("    - SKIP: object name '{$ancestor->_PANC_shortName()}' is not IDENTICAL to object name from upperlevel '{$object->_PANC_shortName()}'");
                                    $this->skippedObject( $index, $object, $ancestor, $g['notIdenticalReason']);
                                    continue;
                                }

                            if( $hashGenerator($object) != $hashGenerator($ancestor) )
                            {
                                if( $g['valueDiff']( $ancestor, $object, true ) === FALSE )
                                {
                                    PH::print_stdout("    - SKIP: object name '{$ancestor->_PANC_shortName()}' was delete earlier. upperlevel '{$object->_PANC_shortName()}'");
                                    $this->skippedObject( $index, $object, $ancestor, 'was delete earlier');
                                    continue;
                                }
                            }

                            if( $hashGenerator($object) == $hashGenerator($ancestor) )
                            {
                                if( $this->dupAlg == 'samename' )
                                {
                                    if( $g['valueDiff']( $ancestor, $object, false ) === FALSE )
                                    {
                                        PH::print_stdout("    - SKIP: object name '{$ancestor->_PANC_shortName()}' was delete earlier. upperlevel '{$object->_PANC_shortName()}'");
                                        $this->skippedObject( $index, $object, $ancestor, 'was delete earlier');
                                        continue;
                                    }
                                }

                                if( $safety !== null && $this->mergeSafetyBlocks( $safety->checkReplace( $object, $ancestor ), $index, $ancestor, $object ) )
                                    continue;

                                $tmp_ancestor_DGname = $this->groupOwnerDGName( $ancestor );

                                $text = $g['ancestorMergedText']( $object, $tmp_ancestor_DGname );
                                self::deletedObject($index, $ancestor, $object);
                                if( $this->action === "merge" )
                                {
                                    $object->replaceMeGlobally($ancestor);
                                    $g['removeAfterAncestorMerge']( $object );
                                }

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
                        }

                        $tmp_ancestor_DGname = $this->groupOwnerDGName( $ancestor );

                        if( $g['ancestorNotMerged']( $index, $object, $ancestor, $tmp_ancestor_DGname ) )
                            continue;
                    }

                    $check = $this->groupChildAncestorCheck( $g, $index, $object );
                    if( $check === 'break' )
                        break;
                    if( $check === 'continue' )
                        continue;

                    if( $object === $pickedObject )
                        continue;

                    if( $this->dupAlg == 'whereused' )
                    {
                        if( $safety !== null && $this->mergeSafetyBlocks( $safety->checkWhereUsedGroupMerge( $object, $pickedObject ), $index, $pickedObject, $object ) )
                            continue;

                        PH::print_stdout("    - merging '{$object->name()}' members into '{$pickedObject->name()}': ");
                        foreach( $object->members() as $member )
                        {
                            $text = "     - adding member '{$member->name()}'... ";
                            if( $this->action === "merge" )
                            {
                                if( $this->apiMode )
                                    $pickedObject->API_addMember($member);
                                else
                                    $pickedObject->addMember($member);
                            }
                            PH::print_stdout($text);
                        }
                        PH::print_stdout("    - now removing '{$object->name()} from where it's used");
                        $text = "    - deleting '{$object->name()}'... ";
                        self::deletedObject($index, $pickedObject, $object);
                        if( $this->action === "merge" )
                        {
                            if( $this->apiMode )
                            {
                                $object->API_removeWhereIamUsed(TRUE, 6);
                                $object->owner->API_remove($object);
                            }
                            else
                            {
                                $object->removeWhereIamUsed(TRUE, 6);
                                $object->owner->remove($object);
                            }
                        }
                        PH::print_stdout($text);
                    }
                    else
                    {
                        if( $this->dupAlg == 'identical' )
                            if( $object->name() != $pickedObject->name() )
                            {
                                PH::print_stdout("    - SKIP: object name '{$pickedObject->_PANC_shortName()}' is not IDENTICAL to object name from upperlevel '{$object->_PANC_shortName()}'");
                                $this->skippedObject( $index, $object, $pickedObject, $g['notIdenticalPickedReason']);
                                continue;
                            }

                        if( $safety !== null && $this->mergeSafetyBlocks( $safety->checkReplace( $object, $pickedObject ), $index, $pickedObject, $object ) )
                            continue;

                        PH::print_stdout("    - replacing '{$object->_PANC_shortName()}' ...");
                        $success = $g['reportWithoutMerge'];
                        if( $this->action === "merge" )
                            $success = $this->groupReplace( $g, $object, $pickedObject );

                        if( $success )
                        {
                            PH::print_stdout("    - deleting '{$object->_PANC_shortName()}'");
                            self::deletedObject($index, $pickedObject, $object);
                            if( $this->action === "merge" )
                                $this->groupRemove( $g, $object );
                        }
                    }

                    $countRemoved++;

                    if( $this->mergeCountLimit !== FALSE && $countRemoved >= $this->mergeCountLimit )
                    {
                        PH::print_stdout("\n *** STOPPING MERGE OPERATIONS NOW SINCE WE REACHED mergeCountLimit ({$this->mergeCountLimit})");
                        break 2;
                    }
                }
            }

            $tmpCount = $g['countGroups']( $store );
            PH::print_stdout( "\n\nDuplicates removal is now done. Number of objects after cleanup: '{$tmpCount}' (removed {$countRemoved} groups)\n" );
        }
    }

    /** the object is a group of the merged type (spec hook 'isGroup', default $object->isGroup()) */
    private function groupIsGroup( array $g, $object ): bool
    {
        if( isset($g['isGroup']) )
            return $g['isGroup']( $object );
        return $object->isGroup();
    }

    /** replaces $object by $target where it is used (spec hook 'replaceObject'); returns success */
    private function groupReplace( array $g, $object, $target )
    {
        if( isset($g['replaceObject']) )
            return $g['replaceObject']( $object, $target );
        return $object->__replaceWhereIamUsed($this->apiMode, $target, TRUE, 5);
    }

    /** removes a merged group (spec hook 'removeObject') */
    private function groupRemove( array $g, $object )
    {
        if( isset($g['removeObject']) )
        {
            $g['removeObject']( $object );
            return;
        }
        if( $this->apiMode )
            //true flag needed for nested groups in a specific constellation
            $object->owner->API_remove($object, TRUE);
        else
            $object->owner->remove($object, TRUE);
    }

    /** DG name of an object's owner, "shared" for shared / no owner */
    private function groupOwnerDGName( $object )
    {
        if( isset($object->owner) )
        {
            $name = $object->owner->owner->name();
            if( $name === "" )
                $name = "shared";
        }
        else
            $name = "shared";

        return $name;
    }

    /**
     * A group with a same-name object in a child device group can not be merged.
     * Returns 'break', 'continue' or null (no childancestor).
     */
    private function groupChildAncestorCheck( array $g, $index, $object )
    {
        if( !isset( $object->childancestor ) )
            return null;

        $childancestor = $object->childancestor;
        if( $childancestor === null )
            return null;

        if( !$this->groupIsGroup( $g, $childancestor ) )
        {
            PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' as one ancestor is of type: ". get_class( $childancestor )." '{$childancestor->_PANC_shortName()}' value: ".$childancestor->value());
            $this->skippedObject( $index, $object, $childancestor, 'childancestor of type: '.get_class( $childancestor ));
            return 'break';
        }

        //Todo check ip4mapping of $childancestor and $object
        if( $g['valueDiff']( $childancestor, $object, true ) === FALSE )
        {
            //if delete earlier, why not replacing this reference???
            PH::print_stdout("    - SKIP: object name '{$childancestor->_PANC_shortName()}' was delete earlier. upperlevel '{$object->_PANC_shortName()}'");
            $this->skippedObject( $index, $object, $childancestor, 'was delete earlier');
            return 'continue';
        }

        $tmp_ancestor_DGname = $this->groupOwnerDGName( $childancestor );

        PH::print_stdout("    - group '{$object->name()}' cannot be merged because it has an ancestor at DG: ".$tmp_ancestor_DGname );
        PH::print_stdout( "    - ancestor type: ".get_class( $childancestor ) );
        $this->skippedObject( $index, $object, $childancestor, 'childancestor at DG: '.$tmp_ancestor_DGname);

        return 'break';
    }

    /**
     * type=securityprofilegroup-merger
     *  samemembers (default): per profile type the same profile name
     *  samevalue:             per profile type the same profile content (profile names may differ)
     * A group is moved to / merged into a parent location only if every profile name it uses resolves there to
     * a profile with the same content; MergeSafety checks the content each firewall receives.
     */
    function securityProfileGroupMergeSpec(): array
    {
        $typeStores = array(
            'virus' => 'AntiVirusProfileStore', 'spyware' => 'AntiSpywareProfileStore', 'vulnerability' => 'VulnerabilityProfileStore',
            'file-blocking' => 'FileBlockingProfileStore', 'wildfire-analysis' => 'WildfireProfileStore', 'url-filtering' => 'URLProfileStore',
            'data-filtering' => 'DataFilteringProfileStore' );
        $ordered = array( 'rules' => TRUE );

        // type => profile object (or name if no object exists)
        $slots = function( $spg ) {
            $ret = array();
            foreach( $spg->secprofProfiles_obj as $type => $profile )
                if( is_object($profile) || ( $profile !== null && $profile !== '' ) )
                    $ret[$type] = $profile;
            foreach( $spg->secprofiles as $type => $name )
                if( !isset($ret[$type]) && $name !== null && $name !== '' )
                    $ret[$type] = $name;
            ksort($ret);
            return $ret;
        };
        $slotName = function( $profile ) {
            return is_object($profile) ? $profile->name() : (string)$profile;
        };
        $profileContent = function( $profile ) use ( $slotName, $ordered ) {
            if( is_object($profile) && isset($profile->xmlroot) && $profile->xmlroot !== null )
                return md5( XmlCompare::canonical( $profile->xmlroot, $ordered ) );
            return 'name:' . $slotName( $profile );
        };
        $slotsText = function( $spg ) use ( $slots, $slotName ) {
            $parts = array();
            foreach( $slots( $spg ) as $type => $profile )
                $parts[] = $type . ':' . $slotName( $profile );
            return implode( ',', $parts );
        };
        $slotsDiff = function( $a, $b ) use ( $slots, $slotName, $profileContent ) {
            $sa = $slots( $a );
            $sb = $slots( $b );
            $diff = array();
            foreach( array_unique( array_merge( array_keys($sa), array_keys($sb) ) ) as $type )
            {
                $na = isset($sa[$type]) ? $slotName( $sa[$type] ) : '-';
                $nb = isset($sb[$type]) ? $slotName( $sb[$type] ) : '-';
                if( $na !== $nb )
                    $diff[] = $type . ": '" . $na . "' -> '" . $nb . "'";
                elseif( isset($sa[$type]) && $profileContent( $sa[$type] ) !== $profileContent( $sb[$type] ) )
                    $diff[] = $type . ": '" . $na . "' different content";
            }
            return implode( ' | ', $diff );
        };
        $remove = function( $object ) {
            if( $this->apiMode )
                $object->owner->API_removeSecurityProfileGroup( $object );
            else
                $object->owner->removeSecurityProfileGroup( $object );
        };

        return array(
            'locationType' => "SecurityProfileGroup",
            'storeProp' => "securityProfileGroupStore",
            'childDoneLabel' => "securityprofilegroups",
            'childPhase' => TRUE,
            'childPhaseChildAncestorCheck' => TRUE,
            'printDuplicateSet' => TRUE,
            'ancestorNonGroupSkip' => FALSE,
            'reportWithoutMerge' => FALSE,
            'notIdenticalReason' => "not identical",
            'notIdenticalPickedReason' => "not identical",

            'hashGenerator' => function () use ( $slots, $slotName, $profileContent ) {
                if( $this->dupAlg == 'samemembers' || $this->dupAlg == 'identical' )
                    return function ($object) use ( $slots, $slotName ) {
                        $value = '';
                        foreach( $slots( $object ) as $type => $profile )
                            $value .= './.' . $type . ':' . $slotName( $profile );
                        return $value;
                    };
                elseif( $this->dupAlg == 'samevalue' )
                    return function ($object) use ( $slots, $profileContent ) {
                        $value = '';
                        foreach( $slots( $object ) as $type => $profile )
                            $value .= './.' . $type . ':' . $profileContent( $profile );
                        return md5( $value );
                    };
                else
                    derr("unsupported dupAlgorithm");
            },
            'listGroups' => function ($store) {
                return $store->securityProfileGroups();
            },
            'eligible' => function ($object) {
                return $object instanceof SecurityProfileGroup;
            },
            'isGroup' => function ($object) {
                return $object instanceof SecurityProfileGroup;
            },
            'mainSkip' => function ($object, $store, $childDeviceGroups) {
                return FALSE;
            },
            'checkParent' => function ($hash) use ( $slotsDiff ) {
                foreach( $hash as $picked )
                {
                    $dg = $picked->owner->owner;
                    if( !isset($dg->parentDeviceGroup) || $dg->parentDeviceGroup === null )
                        continue;
                    $parentCopy = $dg->parentDeviceGroup->securityProfileGroupStore->find( $picked->name(), null, TRUE );
                    if( $parentCopy !== null && $slotsDiff( $picked, $parentCopy ) !== '' )
                    {
                        PH::print_stdout( "   * SKIPPED : a group named '{$picked->name()}' with other profiles exists in an upper level: " . $slotsDiff( $picked, $parentCopy ) );
                        return TRUE;
                    }
                }
                return FALSE;
            },
            'moveMessage' => function ($tmp_DG_name, $pickedObject) {
                return "   * move object to DG: '" . $tmp_DG_name . "' : '" . $pickedObject->name() . "' from DG: '".$pickedObject->owner->owner->name()."'";
            },
            // every profile name must resolve in the target location to a profile with the same content
            'memberCheck' => function ($index, $pickedObject, $store, $tmp_DG_name) use ( $slots, $slotName, $typeStores, $ordered ) {
                $targetLocation = $store->owner;
                foreach( $slots( $pickedObject ) as $type => $profile )
                {
                    if( !is_object($profile) || !isset($typeStores[$type]) )
                        continue;
                    $prop = $typeStores[$type];
                    if( !isset($targetLocation->$prop) || $targetLocation->$prop === null )
                        continue;
                    $found = $targetLocation->$prop->find( $profile->name() );
                    if( $found === null )
                    {
                        $reason = "profile {$type} '{$profile->name()}' does not exist in target location '{$tmp_DG_name}'";
                        PH::print_stdout( "   * SKIPPED : " . $reason );
                        $this->skippedObject( $index, $pickedObject, $profile, $reason );
                        return TRUE;
                    }
                    if( $found !== $profile && isset($found->xmlroot) && isset($profile->xmlroot)
                        && XmlCompare::canonical( $found->xmlroot, $ordered ) !== XmlCompare::canonical( $profile->xmlroot, $ordered ) )
                    {
                        $reason = "profile {$type} '{$profile->name()}' has other content in target location '{$tmp_DG_name}': "
                            . XmlCompare::differencesText( XmlCompare::differences( $found->xmlroot, $profile->xmlroot, $ordered ) );
                        PH::print_stdout( "   * SKIPPED : " . $reason );
                        $this->skippedObject( $index, $pickedObject, $found, $reason );
                        return TRUE;
                    }
                }
                return FALSE;
            },
            // the moved group uses the profiles of its new location (same content, see memberCheck)
            'moveObject' => function ($pickedObject, $store) use ( $slots, $typeStores ) {
                $oldXpath = $pickedObject->getXPath();
                $pickedObject->owner->removeSecurityProfileGroup( $pickedObject );
                $store->addSecurityProfileGroup( $pickedObject );

                $targetLocation = $store->owner;
                foreach( $slots( $pickedObject ) as $type => $profile )
                {
                    if( !is_object($profile) || !isset($typeStores[$type]) )
                        continue;
                    $prop = $typeStores[$type];
                    $found = $targetLocation->$prop->find( $profile->name() );
                    if( $found === null || $found === $profile )
                        continue;
                    $profile->removeReference( $pickedObject );
                    $found->addReference( $pickedObject );
                    $pickedObject->secprofProfiles_obj[$type] = $found;
                }

                if( $this->apiMode )
                {
                    $pickedObject->API_sync();
                    $this->pan->connector->sendDeleteRequest( $oldXpath );
                }
            },
            'replaceObject' => function ($object, $target) {
                $object->replaceMeGlobally( $target, $this->apiMode );
                return TRUE;
            },
            'removeObject' => $remove,
            'targetNotGroup' => function ($index, $pickedObject, $target) {
                PH::print_stdout( "    - SKIP: object name '{$pickedObject->_PANC_shortName()}' can not be merged with object name: '{$target->_PANC_shortName()}' of type ".get_class($target) );
                $this->skippedObject( $index, $pickedObject, $target, "object type is not security-profile-group");
            },
            'targetMismatch' => function ($index, $pickedObject, $target, $pickedObject_value, $target_value) use ( $slotsDiff ) {
                $reason = $slotsDiff( $target, $pickedObject );
                PH::print_stdout( "    - SKIP: object name '{$pickedObject->_PANC_shortName()}' is not IDENTICAL to object name: '{$target->_PANC_shortName()}': " . $reason );
                $this->skippedObject( $index, $pickedObject, $target, "not identical: " . $reason );
                return TRUE;
            },
            'valueDiff' => function ($ancestor, $object, $display) use ( $slotsDiff ) {
                if( $display )
                    PH::print_stdout( "       - differences to ancestor: " . $slotsDiff( $ancestor, $object ) );
                return null;
            },
            'ancestorMergeable' => function ($ancestor) {
                return $this->upperLevelSearch && $ancestor instanceof SecurityProfileGroup;
            },
            'ancestorMergedText' => function ($object, $tmp_ancestor_DGname) {
                return "    - group '{$object->name()}' DG: '" . $object->owner->owner->name() . "' merged with its ancestor at DG: '" . $tmp_ancestor_DGname . "', deleting: " . $object->_PANC_shortName();
            },
            'replaceWithAncestor' => null,
            'removeAfterAncestorMerge' => $remove,
            'ancestorNotMerged' => function ($index, $object, $ancestor, $tmp_ancestor_DGname) use ( $slotsDiff ) {
                $reason = $slotsDiff( $ancestor, $object );
                PH::print_stdout("    - group '{$object->name()}' cannot be merged because it has an ancestor at DG: ".$tmp_ancestor_DGname . ( $reason !== '' ? " (" . $reason . ")" : " (merging with upper level not allowed)" ) );
                $this->skippedObject( $index, $object, $ancestor, $reason !== '' ? "ancestor at DG: " . $tmp_ancestor_DGname . ": " . $reason : "ancestor at DG: " . $tmp_ancestor_DGname . " same profiles, allowMergingWithUpperLevel not set" );
                return TRUE;
            },
            'countGroups' => function ($store) {
                return $store->count();
            },
        );
    }

    function addressGroupMergeSpec(): array
    {
        return array(
            'locationType' => "AddressGroup",
            'storeProp' => "addressStore",
            'childDoneLabel' => "addressgroups",
            'childPhase' => TRUE,
            'childPhaseChildAncestorCheck' => TRUE,
            'printDuplicateSet' => FALSE,
            'ancestorNonGroupSkip' => TRUE,
            'reportWithoutMerge' => FALSE,
            'notIdenticalReason' => 'name is not IDENTICAL',
            'notIdenticalPickedReason' => 'object name not IDENTICAL',

            'hashGenerator' => function () {
                if( $this->dupAlg == 'samemembers' || $this->dupAlg == 'identical' )
                    return function ($object) {
                        /** @var AddressGroup $object */
                        $value = '';
                        $members = $object->members();
                        usort($members, '__CmpObjName');
                        foreach( $members as $member )
                            $value .= './.' . $member->name();
                        return $value;
                    };
                elseif( $this->dupAlg == 'sameip4mapping' )
                    return function ($object) {
                        /** @var AddressGroup $object */
                        $mapping = $object->getFullMapping();
                        // IPv4 only: groups with IPv6 content are not compared
                        // (the maps hold both families, IPv6 entries are recognised by their text)
                        foreach( $mapping['ip4']->getMapArray() as $entry )
                            if( isset($entry['network']) && strpos($entry['network'], ':') !== FALSE )
                                return null;
                        $value = $mapping['ip4']->dumpToString();
                        if( count($mapping['unresolved']) > 0 )
                        {
                            ksort($mapping['unresolved']);
                            $value .= '//unresolved:/';
                            foreach( $mapping['unresolved'] as $unresolvedEntry )
                                $value .= $unresolvedEntry->name() . '.%.';
                        }
                        return $value;
                    };
                elseif( $this->dupAlg == 'whereused' )
                    return function ($object) {
                        if( $object->countReferences() == 0 )
                            return null;
                        /** @var AddressGroup $object */
                        return $object->getRefHashComp() . '//dynamic:' . boolYesNo($object->isDynamic());
                    };
                elseif( $this->dupAlg == 'samename' )
                    return function ($object) {
                        /** @var AddressGroup $object */
                        return $object->name();
                    };
                else
                    derr("unsupported dupAlgorithm");
            },
            'listGroups' => function ($store) {
                return $store->addressGroups();
            },
            'eligible' => function ($object) {
                return $object->isGroup() && !$object->isDynamic();
            },
            'mainSkip' => function ($object, $store, $childDeviceGroups) {
                return FALSE;
            },
            'checkParent' => function ($hash) {
                return $this->checkParentPickObject( $hash );
            },
            'moveMessage' => function ($tmp_DG_name, $pickedObject) {
                return "   * move object to DG: '".$tmp_DG_name."' : '".$pickedObject->name()."'";
            },
            'memberCheck' => function ($index, $pickedObject, $store, $tmp_DG_name) {
                foreach( $pickedObject->members() as $memberObject )
                {
                    /** @var Address|AddressGroup $memberObject */
                    $memberFound = $store->find($memberObject->name());
                    if( $memberFound === null )
                    {
                        if( $this->addMissingObjects )
                        {
                            if( $this->mergeSafety !== null && $this->mergeSafetyBlocks( $this->mergeSafety->checkMove( $memberObject, $store ), $index, $pickedObject, $memberObject ) )
                                return TRUE;

                            PH::print_stdout("      - object: " . $memberObject->name() . " from DG: '" . $memberObject->owner->owner->name() . "' move to: '" . $tmp_DG_name . "'");
                            if( $this->action === "merge" )
                            {
                                self::deletedObject($index, $pickedObject, $pickedObject);
                                /** @var AddressStore $store */
                                if( $this->apiMode )
                                {
                                    $oldXpath = $memberObject->getXPath();
                                    $memberObject->owner->remove($memberObject);
                                    $store->add($memberObject);
                                    $memberObject->API_sync();
                                    $this->pan->connector->sendDeleteRequest($oldXpath);
                                }
                                else
                                {
                                    $memberObject->owner->remove($memberObject);
                                    $store->add($memberObject);
                                }
                            }
                        }
                        else
                        {
                            PH::print_stdout("   * SKIPPED : this group has an object named '{$memberObject->name()} that does not exist in target location '{$tmp_DG_name}'");
                            $this->skippedObject( $index, $pickedObject, $memberObject, "this group has an object named '{$memberObject->name()} that does not exist in target location '{$tmp_DG_name}'" );
                            return TRUE;
                        }
                    }
                    else
                    {
                        /** @var Address|AddressGroup $memberFound */
                        if( $memberFound->isAddress() && $memberObject->isAddress() )
                        {
                            if( $memberFound->value() !== $memberObject->value() )
                            {
                                PH::print_stdout("   * SKIPPED : this group has an object named '{$memberObject->name()} that does exist in target location '{$tmp_DG_name}' with different value");
                                $this->skippedObject( $index, $memberFound, $memberObject, "this group has an object named '{$memberObject->name()} that does exist in target location '{$tmp_DG_name}' with different value" );
                                return TRUE;
                            }
                        }
                        elseif( $memberFound->isGroup() && $memberObject->isGroup() )
                        {
                            $diff = $memberObject->getValueDiff($memberFound);
                            if( count($diff['minus']) != 0 || count($diff['plus']) != 0 )
                            {
                                PH::print_stdout("   * SKIPPED : this group has different member ship compare to upperlevel");
                                $this->skippedObject( $index, $memberFound, $memberObject, "this group has different member ship compare to upperlevel" );
                                return TRUE;
                            }
                        }
                        else
                        {
                            PH::print_stdout("   * SKIPPED : this group has an object named '{$memberObject->name()} that does exist in target location '{$tmp_DG_name}' with different object type");
                            $this->skippedObject( $index, $memberFound, $memberObject, "this group has an object named '{$memberObject->name()} that does not exist in target location '{$tmp_DG_name}'" );
                            return TRUE;
                        }
                    }
                }
                return FALSE;
            },
            'targetNotGroup' => function ($index, $pickedObject, $target) {
                PH::print_stdout( "    - SKIP: object name '{$pickedObject->_PANC_shortName()}' of type ".get_class($pickedObject)." can not be merged with object name: '{$target->_PANC_shortName()}' of type ".get_class($target). " value: ".$target->value() );
                $this->skippedObject( $index, $pickedObject, $target, get_class($pickedObject)." can not be merged with ".get_class($target));
            },
            'targetMismatch' => function ($index, $pickedObject, $target, $pickedObject_value, $target_value) {
                if( $this->addMissingObjects )
                {
                    // the existing group in the target location takes the missing members
                    if( $this->addressgroupGetValueDiff($target, $pickedObject, true) === FALSE )
                    {
                        PH::print_stdout("    - SKIP: object name '{$target->_PANC_shortName()}' was delete earlier. upperlevel '{$pickedObject->_PANC_shortName()}'");
                        $this->skippedObject( $index, $pickedObject, $target, 'was delete earlier');
                        return TRUE;
                    }
                    return FALSE;
                }

                $stringSkippedReason = $pickedObject->displayValueDiff($target, 7, true);
                PH::print_stdout( "    - SKIP: object name '{$pickedObject->_PANC_shortName()}' [with value '{$pickedObject_value}'] is not IDENTICAL to object name: '{$target->_PANC_shortName()}' [with value '{$target_value}']" );
                $this->skippedObject( $index, $pickedObject, $target, $stringSkippedReason);
                return TRUE;
            },
            'valueDiff' => function ($ancestor, $object, $display) {
                return $this->addressgroupGetValueDiff($ancestor, $object, $display);
            },
            'ancestorMergeable' => function ($ancestor) {
                return $this->upperLevelSearch && $ancestor->isGroup() && !$ancestor->isDynamic() && $this->dupAlg != 'whereused';
            },
            'ancestorMergedText' => function ($object, $tmp_ancestor_DGname) {
                return "    - group '{$object->name()}' DG: '" . $object->owner->owner->name() . "' merged with its ancestor at DG: '" . $tmp_ancestor_DGname . "', deleting: " . $object->_PANC_shortName();
            },
            'removeAfterAncestorMerge' => function ($object) {
                if( $this->apiMode )
                    $object->owner->API_remove($object, TRUE);
                else
                    $object->owner->remove($object, TRUE);
            },
            'ancestorNotMerged' => function ($index, $object, $ancestor, $tmp_ancestor_DGname) {
                if( $this->addMissingObjects )
                    return FALSE;

                PH::print_stdout("    - group '{$object->name()}' cannot be merged because it has an ancestor at DG: ".$tmp_ancestor_DGname );
                PH::print_stdout( "    - ancestor type: ".get_class( $ancestor ) );
                $this->skippedObject( $index, $object, $ancestor, 'ancestor at DG: '.$tmp_ancestor_DGname);
                return TRUE;
            },
            'countGroups' => function ($store) {
                return $store->countAddressGroups();
            },
        );
    }

    function serviceGroupMergeSpec(): array
    {
        return array(
            'locationType' => "ServiceGroup",
            'storeProp' => "serviceStore",
            'childDoneLabel' => "servicegroups",
            'childPhase' => TRUE,
            'childPhaseChildAncestorCheck' => TRUE,
            'printDuplicateSet' => TRUE,
            'ancestorNonGroupSkip' => FALSE,
            'reportWithoutMerge' => TRUE,
            'notIdenticalReason' => "not identical",
            'notIdenticalPickedReason' => "not identical",

            'hashGenerator' => function () {
                if( $this->dupAlg == 'samemembers' || $this->dupAlg == 'identical' )
                    return function ($object) {
                        /** @var ServiceGroup $object */
                        $value = '';
                        $members = $object->members();
                        usort($members, '__CmpObjName');
                        foreach( $members as $member )
                            $value .= './.' . $member->name();
                        return $value;
                    };
                elseif( $this->dupAlg == 'sameportmapping' )
                    return function ($object) {
                        /** @var ServiceGroup $object */
                        $mapping = $object->dstPortMapping();
                        $value = $mapping->mappingToText();
                        if( count($mapping->unresolved) > 0 )
                        {
                            ksort($mapping->unresolved);
                            $value .= '//unresolved:/';
                            foreach( $mapping->unresolved as $unresolvedEntry )
                                $value .= $unresolvedEntry->name() . '.%.';
                        }
                        return $value;
                    };
                elseif( $this->dupAlg == 'whereused' )
                    return function ($object) {
                        if( $object->countReferences() == 0 )
                            return null;
                        /** @var ServiceGroup $object */
                        return $object->getRefHashComp();
                    };
                else
                    derr("unsupported dupAlgorithm");
            },
            'listGroups' => function ($store) {
                return $store->serviceGroups();
            },
            'eligible' => function ($object) {
                return $object->isGroup();
            },
            'mainSkip' => function ($object, $store, $childDeviceGroups) {
                // Object with descendants in lower device groups should be excluded
                if( $this->pan->isPanorama() )
                {
                    foreach( $childDeviceGroups as $dg )
                    {
                        if( $dg->serviceStore->find($object->name(), null, FALSE) !== null )
                            return TRUE;
                    }
                }
                return FALSE;
            },
            'checkParent' => function ($hash) {
                return $this->checkParentPickObject( $hash, 'serviceStore' );
            },
            'moveMessage' => function ($tmp_DG_name, $pickedObject) {
                return "   * move object to DG: '" . $tmp_DG_name . "' : '" . $pickedObject->name() . "' from DG: '".$pickedObject->owner->owner->name()."'";
            },
            'memberCheck' => function ($index, $pickedObject, $store, $tmp_DG_name) {
                $skip = FALSE;
                foreach( $pickedObject->members() as $memberObject )
                {
                    $memberFound = $store->find($memberObject->name());
                    if( $memberFound === null )
                    {
                        PH::print_stdout("   * SKIPPED : this group has an object named '{$memberObject->name()} that does not exist in target location '{$tmp_DG_name}'");
                        $this->skippedObject( $index, $pickedObject, $memberObject, "this group has an object named '{$memberObject->name()} that does not exist in target location '{$tmp_DG_name}'" );
                        return TRUE;
                    }

                    /** @var Service|ServiceGroup $memberFound */
                    if( $memberFound->isService() && $memberObject->isService() )
                    {
                        if( $memberFound->getDestPort() !== $memberObject->getDestPort() || $memberFound->getSourcePort() !== $memberObject->getSourcePort() || $memberFound->protocol() !== $memberObject->protocol() )
                        {
                            PH::print_stdout("   * SKIPPED : this group has an object named '{$memberObject->name()} that does exist in target location '{$tmp_DG_name}' with different value or protocol");
                            $this->skippedObject( $index, $pickedObject, $memberObject, "this group has an object named '{$memberObject->name()} that does exist in target location '{$tmp_DG_name}' with different value or protocol" );
                            return TRUE;
                        }
                    }
                    elseif( $memberFound->isGroup() && $memberObject->isGroup() )
                    {
                        $diff = $memberObject->getValueDiff($memberFound);
                        if( count($diff['minus']) != 0 || count($diff['plus']) != 0 )
                        {
                            PH::print_stdout("   * SKIPPED : this group has different member ship compare to upperlevel");
                            $this->skippedObject( $index, $pickedObject, $memberObject, "this group has different member ship compare to upperlevel" );
                            $skip = TRUE;
                        }
                    }
                    else
                    {
                        PH::print_stdout("   * SKIPPED : this group has an object named '{$memberObject->name()} that does exist in target location '{$tmp_DG_name}' with different object type");
                        $this->skippedObject( $index, $pickedObject, $memberObject, "this group has an object named '{$memberObject->name()} that does exist in target location '{$tmp_DG_name}' with different object type" );
                        return TRUE;
                    }
                }
                return $skip;
            },
            'targetNotGroup' => function ($index, $pickedObject, $target) {
                PH::print_stdout( "    - SKIP: object name '{$pickedObject->_PANC_shortName()}' of type ".get_class($pickedObject)." can not be merged with object name: '{$target->_PANC_shortName()}' of type ".get_class($target) );
                $this->skippedObject( $index, $pickedObject, $target, "object type is not service-group");
            },
            'targetMismatch' => function ($index, $pickedObject, $target, $pickedObject_value, $target_value) {
                PH::print_stdout( "    - SKIP: object name '{$pickedObject->_PANC_shortName()}' [with value '{$pickedObject_value}'] is not IDENTICAL to object name: '{$target->_PANC_shortName()}' [with value '{$target_value}']" );
                $this->skippedObject( $index, $pickedObject, $target, "not identical");
                return TRUE;
            },
            'valueDiff' => function ($ancestor, $object, $display) {
                // returns nothing: never "was delete earlier"
                return $this->servicegroupGetValueDiff($ancestor, $object, $display);
            },
            'ancestorMergeable' => function ($ancestor) {
                return $this->upperLevelSearch && $ancestor->isGroup();
            },
            'ancestorMergedText' => function ($object, $tmp_ancestor_DGname) {
                return "    - group '{$object->name()}' DG: '" . $object->owner->owner->name() . "' merged with its ancestor at DG: '" . $tmp_ancestor_DGname . "', deleting: " . $object->_PANC_shortName();
            },
            'removeAfterAncestorMerge' => function ($object) {
                if( $this->apiMode )
                    $object->owner->API_remove($object);
                else
                    $object->owner->remove($object);
            },
            'ancestorNotMerged' => function ($index, $object, $ancestor, $tmp_ancestor_DGname) {
                PH::print_stdout("    - group '{$object->name()}' cannot be merged because it has an ancestor at DG: ".$tmp_ancestor_DGname );
                PH::print_stdout( "    - ancestor type: ".get_class( $ancestor ) );
                $this->skippedObject( $index, $object, $ancestor, "ancestor type: ".get_class( $ancestor ));
                return TRUE;
            },
            'countGroups' => function ($store) {
                return $store->countServiceGroups();
            },
        );
    }

    // ------------------------------------------------------------------------------------------
    // helpers used by the merge specs (moved from MERGER.php)
    // ------------------------------------------------------------------------------------------

    // ---- picking the object to keep

    function hashMapPickfilter( $upperHashMap, $index, &$hash)
    {
        $pickedObject = null;
        if( $this->dupAlg == 'identical' )
            $this->pickFilter = 'identical';

        if( $this->pickFilter !== null )
        {
            if( isset($upperHashMap[$index]) )
            {
                $hashArray = $upperHashMap[$index];
                $printString = "   * using object from upper level : ";
            }
            else
            {
                $hashArray = $hash;
                $printString = "   * keeping object : ";
            }

            foreach( $hashArray as $object )
            {
                if( $this->dupAlg == 'identical' )
                {
                    if( get_class($object->owner->owner) !== "PanoramaConf" && $object->owner->owner->parentDeviceGroup !== null)
                    {
                        $pickedObject = $this->parentSameNameObject( $object );
                        if( $pickedObject !== null )
                            break;
                    }
                }
                elseif( $this->pickFilter->matchSingleObject(array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
                {
                    $pickedObject = $object;
                    break;
                }
            }

            if( $pickedObject === null )
            {
                if( isset($upperHashMap[$index]) )
                {
                    $hashArray = $hash;
                    $printString = "   * keeping object :";

                    foreach( $hashArray as $object )
                    {
                        if( $this->dupAlg == 'identical' )
                        {
                            if( get_class($object->owner->owner) !== "PanoramaConf" && $object->owner->owner->parentDeviceGroup !== null)
                            {
                                $pickedObject = $this->parentSameNameObject( $object );
                                if( $pickedObject !== null )
                                    break;
                            }
                        }
                        elseif( $this->pickFilter->matchSingleObject(array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
                        {
                            $pickedObject = $object;
                            break;
                        }
                    }
                }
                if( $pickedObject === null )
                    $pickedObject = reset($hash);
            }

            PH::print_stdout($printString . "'{$pickedObject->_PANC_shortName()}'");
        }
        else
        {
            if( isset($upperHashMap[$index]) )
            {
                $pickedObject = reset($upperHashMap[$index]);
                /** @var Address $pickedObject */
                if( get_class($pickedObject) === "Address" && $pickedObject->isType_TMP() )
                {
                    $pickedObject = reset($hash);
                    PH::print_stdout( "   * keeping object '{$pickedObject->_PANC_shortName()}'" );
                }
                else
                    PH::print_stdout( "   * using object from upper level : '{$pickedObject->_PANC_shortName()}'" );
            }
            else
            {
                $pickedObject = reset($hash);
                PH::print_stdout( "   * keeping object '{$pickedObject->_PANC_shortName()}'" );
            }
        }

        return $pickedObject;
    }

    /**
     * dupAlgorithm=identical: address / address-group with the same name in the parent device group.
     * Other object types: null (the former lookup in the addressStore could pick an address
     * for a service, service-group or tag with the same name).
     */
    private function parentSameNameObject( $object )
    {
        if( !($object->owner instanceof AddressStore) )
            return null;

        return $object->owner->owner->parentDeviceGroup->addressStore->find( $object->name() );
    }

    function PickObject(&$hash)
    {
        $pickedObject = null;
        if( $this->pickFilter !== null )
        {
            foreach( $hash as $object )
            {
                if( $this->dupAlg == 'identical' )
                {
                    if( get_class($object->owner->owner) !== "PanoramaConf" && $object->owner->owner->parentDeviceGroup !== null)
                    {
                        $pickedObject = $this->parentSameNameObject( $object );
                        if( $pickedObject !== null )
                            break;
                    }
                }
                elseif( $this->pickFilter->matchSingleObject(array('object' => $object, 'nestedQueries' => &$nestedQueries)) )
                {
                    $pickedObject = $object;
                    break;
                }
            }
            if( $pickedObject === null )
                $pickedObject = reset($hash);
            if( get_class($pickedObject) == "Address" && $pickedObject->isType_TMP() )
                $pickedObject = reset($hash);
        }
        else
            $pickedObject = reset($hash);

        return $pickedObject;
    }

    /**
     * Child-device-group phase of the group mergers: TRUE if one group of $hash can not be moved up,
     * because the parent device group already holds an object with the same name and a different
     * value, membership or object type.
     */
    function checkParentPickObject( $hash, $storeProp = 'addressStore' )
    {
        $isService = ( $storeProp === 'serviceStore' );
        $break = False;
        foreach( $hash as $pickedObject )
        {
            /** @var DeviceGroup $pickedObject_DG */
            $pickedObject_DG = $pickedObject->owner->owner;
            if( $pickedObject_DG->parentDeviceGroup !== null )
            {
                $tmp_DG_name = $pickedObject_DG->parentDeviceGroup->name();

                $nextFindObject = $pickedObject_DG->parentDeviceGroup->$storeProp->find( $pickedObject->name(), null, True );
                if( $nextFindObject !== null )
                {
                    if( $isService && $pickedObject->isService() && $nextFindObject->isService() )
                    {
                        if( $pickedObject->getDestPort() !== $nextFindObject->getDestPort() || $pickedObject->getSourcePort() !== $nextFindObject->getSourcePort() || $pickedObject->protocol() !== $nextFindObject->protocol() )
                        {
                            PH::print_stdout("   * SKIPPED : this group has an object named '{$pickedObject->name()} that does exist in target location '{$tmp_DG_name}' with different value or protocol");
                            $break = TRUE;
                        }
                    }
                    elseif( !$isService && $pickedObject->isAddress() && $nextFindObject->isAddress() )
                    {
                        if( $pickedObject->value() !== $nextFindObject->value() )
                        {
                            PH::print_stdout("   * SKIPPED : this group has an object named '{$pickedObject->name()} that does exist in target location '{$tmp_DG_name}' with different value");
                            $break = TRUE;
                        }
                    }
                    elseif( $pickedObject->isGroup() && $nextFindObject->isGroup() )
                    {
                        //todo 20230518 check deeper if this group group part must be validate more
                        $diff = $pickedObject->getValueDiff($nextFindObject);
                        if( count($diff['minus']) != 0 || count($diff['plus']) != 0 )
                        {
                            if( $isService )
                                PH::print_stdout("   * SKIPPED : this group has different member ship compare to upperlevel");
                            else
                                PH::print_stdout("   * SKIPPED : this group has different membership compare to upperlevel");
                            $break = TRUE;
                        }
                    }
                    else
                    {
                        PH::print_stdout("   * SKIPPED : this group has an object named '{$pickedObject->name()} that does exist in target location '{$tmp_DG_name}' with different object type");
                        $break = TRUE;
                    }
                }
            }
        }
        return $break;
    }

    // ---- address / address-group

    function address_service_hash_map_check( $index, $object, $NamehashMap, $upper_NamehashMap, $child_NamehashMap, $checkNamehashMap = false, $checkUpperhashMap = false, $checkChildhashMap = false )
    {
        $array_hashMap = array( "name"=>$NamehashMap, "upper"=>$upper_NamehashMap, "child"=>$child_NamehashMap );
        foreach( $array_hashMap as $key => $MainHashMap )
        {
            if( $key == "name" && !$checkNamehashMap )
                continue;
            elseif( $key == "upper" && !$checkUpperhashMap )
                continue;
            elseif( $key == "child" && !$checkChildhashMap )
                continue;


            if( isset($MainHashMap[$object->name()]) )
            {
                $skip2 = FALSE;
                $skip3 = FALSE;
                $skippedOBJ = null;

                $tmp_string_obj_type = "";
                foreach( $MainHashMap[$object->name()] as $key => $overridenOBJ )
                {
                    if( get_class($object) == "Address" )
                    {
                        if (!$overridenOBJ->isAddress())
                        {
                            $skip2 = TRUE;
                            $tmp_string_obj_type = "addressgroup";
                            $skippedOBJ = $overridenOBJ;
                            break;
                        }
                        if( $this->allowMergingObjectWith_m32 && ($overridenOBJ->getNetworkMask() == '32' && $object->getNetworkMask() == '32') )
                        {
                            if( $overridenOBJ->getNetworkValue() !== $object->getNetworkValue())
                            {
                                $skip3 = TRUE;
                                $skippedOBJ = $overridenOBJ;
                                break;
                            }
                        }
                        elseif ($overridenOBJ->value() !== $object->value())
                        {
                            $skip3 = TRUE;
                            $skippedOBJ = $overridenOBJ;
                            break;
                        }
                    }
                    elseif( get_class($object) == "Service" )
                    {
                        if (!$overridenOBJ->isService())
                        {
                            $skip2 = TRUE;
                            $tmp_string_obj_type = "servicegroup";
                            $skippedOBJ = $overridenOBJ;
                            break;
                        }
                        if( $overridenOBJ->getDestPort() !== $object->getDestPort() || $overridenOBJ->getSourcePort() !== $object->getSourcePort() || $overridenOBJ->protocol() !== $object->protocol() )
                        {
                            $skip3 = TRUE;
                            $skippedOBJ = $overridenOBJ;
                            break;
                        }
                    }
                }

                if ($skip2)
                {

                    PH::print_stdout("    - SKIP: object name '{$object->_PANC_shortName()}' as one ancestor is of type ".$tmp_string_obj_type);
                    $this->skippedObject($index, $object, $skippedOBJ, "ancestor of type ".$tmp_string_obj_type);

                    return FALSE;//continue
                }
                if ($skip3)
                {
                    PH::print_stdout("    - SKIP3: object name '{$object->_PANC_shortName()}' as one ancestor has same name, but different value");
                    $this->skippedObject($index, $object, $skippedOBJ, " ancestor has same name, but different value");
                    return FALSE;//continue
                }
            }
        }

        return TRUE;
    }

    function address_tag_DAG_check( $pickedObject, $ancestor, $index)
    {
        /** @var Address $pickedObject */
        $pickedObjReferences = $pickedObject->refrules;

        $pickedObjPartOfDAG = false;
        foreach( $pickedObjReferences as $objReference)
        {
            /** @var AddressGroup $objReference */
            if( get_class($objReference) == "AddressGroup" && $objReference->isDynamic() )
            {
                $pickedObjPartOfDAG = true;
                break;
            }
        }

        $ancestorRef = $ancestor->refrules;
        $ancestorPartOfDAG = false;
        foreach( $ancestorRef as $objReference)
        {
            /** @var AddressGroup $objReference */
            if( get_class($objReference) == "AddressGroup" && $objReference->isDynamic() )
            {
                $ancestorPartOfDAG = true;
                break;
            }
        }

        if( $pickedObjPartOfDAG || $ancestorPartOfDAG )
        {
            /** @var Address $pickedObject */
            /** @var Address $ancestor */
            foreach( $pickedObject->tags->getAll() as $objTag )
            {
                if( !$ancestor->tags->hasTag($objTag) )
                {
                    //todo: check if both objects are at same level
                    if( $pickedObject->owner->owner !== $ancestor->owner->owner )
                    {
                        if( is_object($objTag) )
                            $tmp_string = "    - SKIP1: '{$pickedObject->_PANC_shortName()}' [has a tag '{$objTag->name()}'] which is not part of address object: ".$ancestor->_PANC_shortName();
                        else
                            $tmp_string = "    - SKIP1: '{$pickedObject->_PANC_shortName()}' [has a tag '{$objTag}'] which is not part of address object: ".$ancestor->_PANC_shortName();
                        PH::print_stdout( $tmp_string );
                        $this->skippedObject( $index, $pickedObject, $ancestor, $tmp_string );

                        return true;
                    }
                }
            }
            foreach( $ancestor->tags->getAll() as $objTag )
            {
                if( !$pickedObject->tags->hasTag($objTag) )
                {
                    if( $pickedObject->owner->owner !== $ancestor->owner->owner )
                    {
                        #if (is_object($objTag))
                        #    $tmp_string = "    - SKIP2: '{$ancestor->_PANC_shortName()}' [has a tag '{$objTag->name()}'] which is not part of address object: " . $pickedObject->_PANC_shortName();
                        #else
                        #    $tmp_string = "    - SKIP2: '{$ancestor->_PANC_shortName()}' [has a tag '{$objTag}'] which is not part of address object: " . $pickedObject->_PANC_shortName();
                        #PH::print_stdout($tmp_string);
                        #$this->skippedObject($index, $pickedObject, $ancestor, $tmp_string);

                        #return true;
                    }
                }
            }
        }

        return false;
    }

    function address_tag_merge_check( $pickedObject, $ancestor, $index)
    {
        $arrayPicked = array();
        foreach( $pickedObject->tags->getAll() as $key => $tagObj )
            $arrayPicked[] = $tagObj->name();

        $arrayAncestor = array();
        foreach( $ancestor->tags->getAll() as $key => $tagObj )
            $arrayAncestor[] = $tagObj->name();

        $mergeArray = array_unique( array_merge($arrayPicked, $arrayAncestor) );

        if( count($mergeArray) > $pickedObject->tagLimit )
        {
            PH::print_stdout( "    - SKIP: tag count of name '{$ancestor->_PANC_shortName()}' [with value '{$ancestor->value()}'] added with object name from upperlevel '{$pickedObject->_PANC_shortName()}' [with value '{$pickedObject->value()}'] exceed PAN-OS limit ".$pickedObject->tagLimit." with unique tag count: ".count($mergeArray) );
            $this->skippedObject( $index, $pickedObject, $ancestor, "tag object count exceed PAN-OS limit ".$pickedObject->tagLimit." with unique tag count: ".count($mergeArray) );

            return true;
        }

        return false;
    }

    function address_get_value_string( $object )
    {
        /** @var Address $object */
        $value = $object->value();
        #if( ($object->isType_ipNetmask() || $object->isType_TMP() ) && strpos($object->value(), '/32') !== FALSE )
        #    $value = substr($value, 0, strlen($value) - 3);
        if( ($object->isType_ipNetmask() || $object->isType_TMP() ) && strpos($object->value(), '/') == FALSE )
            $value = $value . "/32";

        if( $object->type() === "tmp" )
            $value = "ip-netmask" . '-' . $value;
        else
            $value = $object->type() . '-' . $value;

        return $value;
    }

    function addressgroupGetValueDiff( $ancestor, $object, $display = false)
    {
        if( $display )
            $ancestor->displayValueDiff($object, 7);

        if( $this->addMissingObjects )
        {
            $diff = $ancestor->getValueDiff($object);
            if( count($diff['minus']) != 0 )
            {
                $store = $ancestor->owner;
                if( $store !== null )
                {
                    foreach( $diff['minus'] as $d )
                    {
                        /** @var Address|AddressGroup $d */

                        if( $store->find($d->name()) !== null )
                        {
                            $text = "      - adding objects to group: ";
                            $text .= $d->name();
                            PH::print_stdout($text);
                            if( $this->action === "merge" )
                            {
                                if( $this->apiMode )
                                    $ancestor->API_addMember($d);
                                else
                                    $ancestor->addMember($d);
                            }
                        }
                        else
                        {
                            #PH::print_stdout("      - object not found: " . $d->name() . "");
                            if( $this->mergeSafety !== null )
                            {
                                $reason = $this->mergeSafety->checkMove( $d, $store );
                                if( $reason !== null )
                                {
                                    PH::print_stdout( "      - SKIP: object '{$d->name()}' not moved to '" . $store->owner->_PANC_shortName() . "', " . $reason );
                                    continue;
                                }
                            }
                            $text = "      - adding object: ";
                            $text .= $d->name();
                            $text .= " from DG '".$d->owner->owner->_PANC_shortName()."' to '".$store->owner->_PANC_shortName()."'";
                            $text .= " to group";
                            PH::print_stdout($text);
                            if( $this->action === "merge" )
                            {
                                /** @var AddressStore $store */
                                if( $this->apiMode )
                                {
                                    $oldXpath = $d->getXPath();
                                    $d->owner->remove($d);
                                    $store->add($d);
                                    $d->API_sync();
                                    $this->pan->connector->sendDeleteRequest($oldXpath);
                                    $ancestor->API_addMember($d);
                                }
                                else
                                {
                                    $d->owner->remove($d);
                                    $store->add($d);
                                    $ancestor->addMember($d);
                                }
                            }
                        }
                    }
                }
                else
                {
                    mwarning( "store of ".get_class($ancestor)." object: ".$object->name(). " is null. minus", null, FALSE );
                    return FALSE;
                }
            }


            if( count($diff['plus']) != 0 )
            {
                $store = $ancestor->owner;
                if( $store !== null )
                {
                    foreach( $diff['plus'] as $d )
                    {
                        /** @var Address|AddressGroup $d */
                        //TMP usage to clean DG level ADDRESSgroup up
                        $object->addMember($d);
                    }
                }
                else
                {
                    mwarning( "store of ".get_class($ancestor)." object: ".$object->name(). " is null. plus", null, FALSE );
                    return FALSE;
                }
            }
        }

        return TRUE;
    }

    // ---- service / service-group

    function servicePickedObjectValidation( $index, $object, $pickedObject )
    {
        /** @var Service $object */
        /** @var Service $pickedObject */

        $skipped = false;
        if( $object->protocol() != $pickedObject->protocol() )
        {
            $text = "    - object '{$object->name()}' cannot be merged because of different service protocol";
            $text .="  object protocol value: " . $object->protocol() . " | pickedObject protocol value: " . $pickedObject->protocol();
            PH::print_stdout( $text );
            $this->skippedObject( $index, $object, $pickedObject);
            $skipped = true;
        }
        elseif( !$object->srcPortMapping()->equals($pickedObject->srcPortMapping()) && $this->dupAlg == 'samedstsrcports' )
        {
            $text = "    - object '{$object->name()}' cannot be merged because of different SRC port information";
            $text .= "  object value: " . $object->srcPortMapping()->mappingToText() . " | pickedObject value: " . $pickedObject->srcPortMapping()->mappingToText();
            PH::print_stdout( $text );
            $this->skippedObject( $index, $object, $pickedObject);
            $skipped = true;
        }
        elseif( $object->getOverride() != $pickedObject->getOverride() )
        {
            $text = "    - object '{$object->name()}' cannot be merged because of different timeout Override information";
            $text .="  object timeout value: " . $object->getOverride() . " | pickedObject timeout value: " . $pickedObject->getOverride();
            PH::print_stdout( $text );
            $this->skippedObject( $index, $object, $pickedObject);
            $skipped = true;
        }

        return $skipped;
    }

    function servicegroupGetValueDiff( $ancestor, $object, $display = false)
    {
        /* @var ServiceGroup $ancestor */
        if( $display )
            $ancestor->displayValueDiff($object, 7);

        if( $this->addMissingObjects )
        {
            $diff = $ancestor->getValueDiff($object);

            if( count($diff['minus']) != 0 )
                foreach( $diff['minus'] as $d )
                {
                    /** @var Service|ServiceGroup $d */

                    if( $ancestor->owner->find($d->name()) !== null )
                    {
                        PH::print_stdout("      - adding objects to group: " . $d->name() . "");
                        if( $this->action === "merge" )
                        {
                            if( $this->apiMode )
                                $ancestor->API_addMember($d);
                            else
                                $ancestor->addMember($d);
                        }
                    }
                    else
                    {
                        PH::print_stdout("      - object not found: " . $d->name() . "");
                    }
                }

            if( count($diff['plus']) != 0 )
                foreach( $diff['plus'] as $d )
                {
                    /** @var Service|ServiceGroup $d */
                    //TMP usage to clean DG level SERVICEgroup up
                    if( $this->action === "merge" )
                        $object->addMember($d);
                }
        }
    }

    // ---- custom URL category

    /**
     * @param customURLProfile $ancestor
     * @param customURLProfile $object
     */
    function customURLcategoryGetValueDiff( $ancestor, $object, $display = false)
    {
        if( $display )
            $ancestor->displayValueDiff($object, 7);

        if( $this->addMissingObjects )
        {
            $diff = $ancestor->getValueDiff($object);

            if( count($diff['minus']) != 0 )
                foreach( $diff['minus'] as $d )
                {
                    /** @var string $d */

                    PH::print_stdout("      - adding objects to group: " . $d . "");
                    if( $this->action === "merge" )
                    {
                        if( $this->apiMode )
                        {
                            //
                            mwarning("API mode not implemented yet");
                            #$ancestor->API_addMember($d);
                        }
                        else
                            $ancestor->addMember($d);
                    }
                }

            if( count($diff['plus']) != 0 )
                foreach( $diff['plus'] as $d )
                {
                    /** @var Service|ServiceGroup $d */
                    //TMP usage to clean DG level customURLcategory up
                    if( $this->action === "merge" )
                        $object->addMember($d);
                }
        }
    }
}
