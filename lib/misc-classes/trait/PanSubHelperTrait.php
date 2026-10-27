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

trait PanSubHelperTrait
{

    /**
     * Object store classes whose lookups (find / findOrCreate with $nested) continue in the
     * store of the same name on the parent (DeviceGroup, Container, ...).
     */
    public static function inheritableStoreClasses(): array
    {
        return array(
            'AddressStore', 'ServiceStore', 'TagStore', 'AppStore', 'ScheduleStore',
            'EDLStore', 'LogProfileStore', 'ZoneStore',
            'SecurityProfileGroupStore', 'SecurityProfileStore'
        );
    }

    /**
     * Links every inheritable object store owned by this sub to the store of the same name on $parent.
     * The set of stores is taken from the objects themselves instead of a hand-written list, so a store
     * added to a class later is linked automatically and every code path (load from XML, create*())
     * links exactly the same stores.
     * A store is only linked when the parent has a store of the same name and class
     * (e.g. DeviceGroup has no zoneStore, so zones are never linked between DeviceGroups).
     *
     * @param DeviceGroup|Container|PanoramaConf|BuckbeakConf|FawkesConf $parent
     */
    public function linkStoresToParent( $parent ): void
    {
        if( $parent === null )
            return;

        $storeClasses = self::inheritableStoreClasses();
        foreach( get_object_vars($this) as $property => $store )
        {
            if( !is_object($store) || !in_array(get_class($store), $storeClasses, TRUE) )
                continue;
            if( !isset($store->owner) || $store->owner !== $this )
                continue;
            if( !isset($parent->$property) || !is_object($parent->$property) || get_class($parent->$property) !== get_class($store) )
                continue;

            $store->parentCentralStore = $parent->$property;
        }
    }

    public function isPanorama()
    {
        FALSE;
    }

    public function isFirewall(): void
    {
        FALSE;
    }

    public function isVirtualSystem(): void
    {
        FALSE;
    }

    public function isDeviceGroup(): void
    {
        FALSE;
    }

    public function isTemplate(): void
    {
        FALSE;
    }

    public function isFawkes(): void
    {
        FALSE;
    }

    public function isBuckbeak(): void
    {
        FALSE;
    }

    public function isContainer(): void
    {
        FALSE;
    }

    public function isDeviceCloud(): void
    {
        FALSE;
    }

    public function isDeviceOnPrem(): void
    {
        FALSE;
    }

    public function isSnippet(): void
    {
        FALSE;
    }

    public function isManagedDevice(): void
    {
        FALSE;
    }
}
