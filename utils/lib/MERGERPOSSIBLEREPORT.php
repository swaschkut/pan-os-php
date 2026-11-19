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
 * type=merger-possible-report
 *
 * Read-only report over all locations (shared, device groups, templates, template stacks, vsys;
 * SCM: folders, devices and snippets):
 * which objects exist more than once
 *   - same name, same value       -> duplicate, merge candidate
 *   - same name, different value  -> conflict; "overlapping" when one copy can hide the other
 *                                    (parent / child device group, same template stack, shared / vsys)
 *   - same value, different names -> duplicate under another name
 * With mergecheck: for the object types the mergers check (address, service, their groups,
 * security profiles, security profile groups) MergeSafety tells whether replacing each copy by the
 * copy in the highest location would change what a firewall receives.
 *
 * The configuration is not changed.
 */
class MERGERPOSSIBLEREPORT extends MERGER
{
    /** objecttype => definition */
    public $reportTypes = array();

    /** collected findings, for exportCSV */
    public $findings = array();

    /** objecttype => counters */
    public $summary = array();

    public $mergeCheck = FALSE;

    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "pan-os-php type=merger-possible-report in=inputfile.xml [objecttype=any|address,service,...] [mergecheck] [exportCSV=report.html]";

        $this->defineReportTypes();

        $this->supportedArguments['objecttype'] = array('niceName' => 'ObjectType',
            'shortHelp' => "object type(s) to report, comma separated; default any",
            'argDesc' => 'any|' . implode('|', array_keys($this->reportTypes)));
        $this->supportedArguments['mergecheck'] = array('niceName' => 'MergeCheck',
            'shortHelp' => "for address / service / their groups / EDL / applications (custom, filter, group) / schedule / log forwarding and decryption profiles / security profiles / security profile groups: check with the effective-policy check whether a merge into the copy in the highest location would change what a firewall receives (slower)");
        $this->supportedArguments['exportcsv'] = array('niceName' => 'exportCSV',
            'shortHelp' => 'write the findings as HTML table', 'argDesc' => 'report.html');

        $this->prepareSupportedArgumentsArray();
        PH::processCliArgs();
        $this->arg_validation();

        if( isset(PH::$args['exportcsv']) )
        {
            $this->exportcsv = TRUE;
            $this->exportcsvFile = PH::$args['exportcsv'];
        }
        if( isset(PH::$args['mergecheck']) )
            $this->mergeCheck = TRUE;

        $this->help(PH::$args);
        $this->inDebugapiArgument();
        $this->inputValidation();
        $this->location_provided();
        $this->load_config();

        // security profile types: only those this configuration has (Panorama / firewall or SCM)
        $presentProfileTypes = $this->profileTypesOfConfig();
        foreach( MERGER::$securityProfileMergerStores as $profileType => $storeProp )
            if( !in_array( $profileType, $presentProfileTypes, TRUE ) )
                unset( $this->reportTypes['securityprofile-' . $profileType] );

        $types = array_keys($this->reportTypes);
        if( isset(PH::$args['objecttype']) && strtolower(PH::$args['objecttype']) !== 'any' )
        {
            $types = array();
            foreach( explode(',', strtolower(PH::$args['objecttype'])) as $t )
            {
                $t = trim($t);
                if( !isset($this->reportTypes[$t]) )
                    $this->display_error_usage_exit("unsupported objecttype '" . $t . "' - supported: any|" . implode('|', array_keys($this->reportTypes)));
                $types[] = $t;
            }
        }

        foreach( $types as $type )
            $this->reportType( $type );

        $this->printSummary();

        if( $this->exportcsv )
            $this->exportReportHtml();
    }

    // ------------------------------------------------------------------------------------------
    // object types
    // ------------------------------------------------------------------------------------------

    private function defineReportTypes()
    {
        $strip = function( $object ) {
            return $this->canonicalValue( $object->xmlroot );
        };
        $all = function( $store ) {
            return $store->getAll();
        };
        $members = function( $object ) {
            $names = array();
            foreach( $object->members() as $m )
                $names[] = $m->name();
            sort($names, SORT_STRING);
            return 'members:' . implode(',', $names);
        };

        $this->reportTypes['address'] = array( 'scope' => 'dg', 'store' => 'addressStore', 'safety' => 'addressStore',
            'list' => function( $s ) { return $s->addressObjects(); },
            'eligible' => function( $o ) { return !$o->isTmpAddr(); },
            'value' => function( $o ) {
                $value = $o->value();
                if( $o->isType_ipNetmask() && strpos($value, '/') === FALSE )
                    $value .= '/32';
                return $o->type() . '-' . $value;
            } );
        $this->reportTypes['addressgroup'] = array( 'scope' => 'dg', 'store' => 'addressStore', 'safety' => 'addressStore',
            'list' => function( $s ) { return $s->addressGroups(); },
            'eligible' => function( $o ) { return $o->isGroup(); },
            'value' => function( $o ) use ( $members, $strip ) {
                if( $o->isDynamic() )
                    return 'dynamic:' . $strip( $o );
                return $members( $o );
            } );
        $this->reportTypes['service'] = array( 'scope' => 'dg', 'store' => 'serviceStore', 'safety' => 'serviceStore',
            'list' => function( $s ) { return $s->serviceObjects(); },
            'eligible' => function( $o ) { return !$o->isTmpSrv(); },
            'value' => $strip );
        $this->reportTypes['servicegroup'] = array( 'scope' => 'dg', 'store' => 'serviceStore', 'safety' => 'serviceStore',
            'list' => function( $s ) { return $s->serviceGroups(); },
            'eligible' => function( $o ) { return $o->isGroup(); },
            'value' => $members );
        $this->reportTypes['tag'] = array( 'scope' => 'dg', 'store' => 'tagStore',
            'list' => function( $s ) { return $s->tags(); },
            'eligible' => function( $o ) { return !$o->isTmp(); },
            'value' => function( $o ) { return 'color:' . $o->getColor(); } );
        $this->reportTypes['custom-url-category'] = array( 'scope' => 'dg', 'store' => 'customURLProfileStore',
            'list' => $all, 'eligible' => null, 'value' => $strip );
        foreach( MERGER::$securityProfileMergerStores as $profileType => $storeProp )
            $this->reportTypes['securityprofile-' . $profileType] = array( 'scope' => 'dg', 'store' => $storeProp, 'safety' => $storeProp,
                'list' => $all, 'eligible' => null, 'value' => $strip );
        $this->reportTypes['securityprofilegroup'] = array( 'scope' => 'dg', 'store' => 'securityProfileGroupStore', 'safety' => 'securityProfileGroupStore',
            'list' => function( $s ) { return $s->securityProfileGroups(); },
            'eligible' => null,
            'value' => function( $o ) {
                $slots = array();
                foreach( $o->secprofProfiles_obj as $t => $p )
                    if( is_object($p) || ( $p !== null && $p !== '' ) )
                        $slots[$t] = is_object($p) ? $p->name() : (string)$p;
                foreach( $o->secprofiles as $t => $n )
                    if( !isset($slots[$t]) && $n !== null && $n !== '' )
                        $slots[$t] = (string)$n;
                ksort($slots);
                $parts = array();
                foreach( $slots as $t => $n )
                    $parts[] = $t . ':' . $n;
                return 'profiles:' . implode(',', $parts);
            } );
        $this->reportTypes['decryption-profile'] = array( 'scope' => 'dg', 'store' => 'DecryptionProfileStore', 'safety' => 'DecryptionProfileStore', 'list' => $all, 'eligible' => null, 'value' => $strip );
        $this->reportTypes['hip-object'] = array( 'scope' => 'dg', 'store' => 'HipObjectsProfileStore', 'list' => $all, 'eligible' => null, 'value' => $strip );
        $this->reportTypes['hip-profile'] = array( 'scope' => 'dg', 'store' => 'HipProfilesProfileStore', 'list' => $all, 'eligible' => null, 'value' => $strip );
        $this->reportTypes['schedule'] = array( 'scope' => 'dg', 'store' => 'scheduleStore', 'safety' => 'scheduleStore', 'list' => $all, 'eligible' => null, 'value' => $strip );
        $this->reportTypes['edl'] = array( 'scope' => 'dg', 'store' => 'EDLStore', 'safety' => 'EDLStore', 'list' => $all,
            'eligible' => function( $o ) { return !$o->isTmp() && strpos( (string)$o->type(), 'predefined' ) !== 0; },
            // descriptions (also inside <type><ip>…) ignored, as in the EDL merger
            'value' => function( $o ) { return $this->canonicalValue( MERGER::xmlWithoutTags( $o->xmlroot, array( 'description' ) ) ); } );
        $this->reportTypes['log-profile'] = array( 'scope' => 'dg', 'store' => 'LogProfileStore', 'safety' => 'LogProfileStore', 'list' => $all, 'eligible' => null, 'value' => $strip );
        $this->reportTypes['application-group'] = array( 'scope' => 'dg', 'store' => 'appStore', 'safety' => 'appStore', 'list' => $all,
            'eligible' => function( $o ) { return !$o->isTmp() && !$o->isPredefined() && $o->isApplicationGroup(); },
            'value' => function( $o ) use ( $strip ) { return $strip( $o ); } );
        $this->reportTypes['application-filter'] = array( 'scope' => 'dg', 'store' => 'appStore', 'safety' => 'appStore', 'list' => $all,
            'eligible' => function( $o ) { return !$o->isTmp() && !$o->isPredefined() && $o->isApplicationFilter(); },
            'value' => $strip );
        $this->reportTypes['application-custom'] = array( 'scope' => 'dg', 'store' => 'appStore', 'safety' => 'appStore', 'list' => $all,
            'eligible' => function( $o ) { return !$o->isTmp() && !$o->isPredefined() && $o->isApplicationCustom(); },
            'value' => $strip );

        $this->reportTypes['certificate'] = array( 'scope' => 'template', 'store' => 'certificateStore', 'list' => $all, 'eligible' => null,
            'value' => function( $o ) {
                return $this->certificateValue( $o );
            },
            'info' => function( $o ) {
                $cn = DH::findFirstElement('common-name', $o->xmlroot);
                $exp = DH::findFirstElement('not-valid-after', $o->xmlroot);
                $pk = DH::findFirstElement('private-key', $o->xmlroot);
                return ( $cn !== FALSE ? 'CN=' . $cn->textContent : '' ) . ( $exp !== FALSE ? ' until ' . $exp->textContent : '' ) . ( $pk !== FALSE ? ' [private key]' : '' );
            } );
        $this->reportTypes['certificate-profile'] = array( 'scope' => 'template', 'store' => 'certificateProfileStore', 'list' => $all, 'eligible' => null,
            'value' => function( $o, $l ) {
                // CA certificates are compared by their content, not by their names
                $clone = $o->xmlroot->cloneNode(TRUE);
                $ca = DH::findFirstElement('CA', $clone);
                if( $ca !== FALSE )
                    foreach( $ca->childNodes as $entry )
                        if( $entry->nodeType == XML_ELEMENT_NODE && $entry->nodeName == 'entry' )
                            $entry->setAttribute( 'name', $this->certificateFingerprint( $entry->getAttribute('name'), $l ) );
                return $this->canonicalValue( $clone );
            },
            'info' => function( $o ) {
                return 'CA: ' . implode( ',', $o->caCertificateNames() );
            } );
        $this->reportTypes['ssl-tls-service-profile'] = array( 'scope' => 'template', 'store' => 'SSL_TLSServiceProfileStore', 'list' => $all, 'eligible' => null,
            'value' => function( $o, $l ) {
                // the certificate is compared by its content, not by its name
                $clone = $o->xmlroot->cloneNode(TRUE);
                $c = DH::findFirstElement('certificate', $clone);
                if( $c !== FALSE )
                    $c->textContent = $this->certificateFingerprint( $c->textContent, $l );
                return $this->canonicalValue( $clone );
            } );
    }

    /** the certificate itself, never the private key */
    public function certificateValue( $certificate )
    {
        $pub = DH::findFirstElement('public-key', $certificate->xmlroot);
        if( $pub !== FALSE && trim($pub->textContent) !== '' )
            return 'cert:' . md5( preg_replace('/\s+/', '', $pub->textContent) );
        return 'cert-xml:' . md5( $this->canonicalValue( $certificate->xmlroot, array( 'private-key' ) ) );
    }

    /**
     * certificate name as seen from a template location -> its content
     * vsys: own certificates, then the template / stack (a stack also its templates in stack order)
     */
    public function certificateFingerprint( $name, array $l )
    {
        $stores = array();
        if( $this->isScmReport() )
        {
            // SCM: folder / device / snippet chain, a snippet also uses 'All'
            foreach( PH::scmObjectLevels( $l['loc'] ) as $level )
                if( isset($level->certificateStore) && $level->certificateStore !== null )
                    $stores[] = $level->certificateStore;
        }
        elseif( count( PH::templateScopeLevels( $l['loc'] ) ) > 0 )
        {
            // template / template stack: stack vsys, stack shared, then each template of the stack (vsys, shared)
            foreach( PH::templateScopeLevels( $l['loc'] ) as $level )
                if( isset($level->certificateStore) && $level->certificateStore !== null )
                    $stores[] = $level->certificateStore;
        }
        else
        {
            if( isset($l['loc']->certificateStore) )
                $stores[] = $l['loc']->certificateStore;
            // firewall vsys: then shared
            if( $l['loc'] instanceof VirtualSystem && isset($l['loc']->owner->certificateStore) )
                $stores[] = $l['loc']->owner->certificateStore;
        }
        foreach( $stores as $store )
            foreach( $store->getAll() as $c )
                if( $c->name() === $name )
                    return $this->certificateValue( $c );

        return 'unresolved:' . $name;
    }

    /** canonical content without name, description and tags (XmlCompare semantics) */
    public function canonicalValue( $xml, array $ignore = array() )
    {
        if( $xml === null || $xml === FALSE )
            return '';
        $clone = $xml->cloneNode(TRUE);
        $ignore = array_merge( array( 'description', 'tag' ), $ignore );
        $remove = array();
        foreach( $clone->childNodes as $child )
            if( $child->nodeType == XML_ELEMENT_NODE && in_array($child->tagName, $ignore, TRUE) )
                $remove[] = $child;
        foreach( $remove as $child )
            $clone->removeChild($child);
        return XmlCompare::canonical( $clone, array( 'rules' => TRUE ) );
    }

    // ------------------------------------------------------------------------------------------
    // locations
    // ------------------------------------------------------------------------------------------

    /** array of array( 'label' =>, 'loc' => location object holding the store ) */
    private function reportLocations( $scope )
    {
        $ret = array();
        $pan = $this->pan;

        // SCM has no templates: every folder, device and snippet can hold every object type
        if( $this->isScmReport() )
            return $this->scmReportLocations();

        if( $scope == 'dg' )
        {
            if( $pan->isPanorama() )
            {
                $ret[] = array( 'label' => 'shared', 'loc' => $pan );
                foreach( $pan->getDeviceGroups() as $dg )
                    $ret[] = array( 'label' => $dg->name(), 'loc' => $dg );
            }
            elseif( $pan->isFirewall() )
            {
                $ret[] = array( 'label' => 'shared', 'loc' => $pan );
                foreach( $pan->getVirtualSystems() as $vsys )
                    $ret[] = array( 'label' => $vsys->name(), 'loc' => $vsys );
            }
            return $ret;
        }

        // template scope
        if( $pan->isPanorama() )
        {
            // Panorama's own shared certificates are not pushed to firewalls
            foreach( $pan->getTemplates() as $template )
            {
                $ret[] = array( 'label' => 'template:' . $template->name(), 'loc' => $template, 'template' => $template );
                foreach( $template->deviceConfiguration->getVirtualSystems() as $vsys )
                    $ret[] = array( 'label' => 'template:' . $template->name() . '/' . $vsys->name(), 'loc' => $vsys, 'template' => $template );
            }
            foreach( $pan->getTemplatesStacks() as $stack )
            {
                $ret[] = array( 'label' => 'template-stack:' . $stack->name(), 'loc' => $stack, 'template' => $stack );
                foreach( $stack->deviceConfiguration->getVirtualSystems() as $vsys )
                    $ret[] = array( 'label' => 'template-stack:' . $stack->name() . '/' . $vsys->name(), 'loc' => $vsys, 'template' => $stack );
            }
        }
        elseif( $pan->isFirewall() )
        {
            $ret[] = array( 'label' => 'shared', 'loc' => $pan );
            foreach( $pan->getVirtualSystems() as $vsys )
                $ret[] = array( 'label' => $vsys->name(), 'loc' => $vsys );
        }
        return $ret;
    }

    private function isScmReport()
    {
        return $this->pan->isFawkes() || $this->pan->isBuckbeak();
    }

    /** SCM: folders, cloud and on-prem devices, snippets (predefined-snippet left out, it cannot be changed) */
    private function scmReportLocations()
    {
        $ret = array();
        $pan = $this->pan;
        foreach( $pan->getContainers() as $sub )
            $ret[] = array( 'label' => $sub->name(), 'loc' => $sub );
        foreach( $pan->getDeviceClouds() as $sub )
            $ret[] = array( 'label' => $sub->name(), 'loc' => $sub );
        foreach( $pan->getDeviceOnPrems() as $sub )
            $ret[] = array( 'label' => $sub->name(), 'loc' => $sub );
        foreach( $pan->getSnippets() as $sub )
            if( $sub->name() !== 'predefined-snippet' )
                $ret[] = array( 'label' => 'snippet:' . $sub->name(), 'loc' => $sub );
        return $ret;
    }

    /** cache: SCM location id => locations its names are looked up in */
    private $scmLevelsCache = array();

    private function scmLevels( $loc )
    {
        $id = spl_object_id( $loc );
        if( !isset($this->scmLevelsCache[$id]) )
            $this->scmLevelsCache[$id] = PH::scmObjectLevels( $loc );
        return $this->scmLevelsCache[$id];
    }

    /** one copy can hide the other on a firewall */
    private function overlapping( array $a, array $b, $scope )
    {
        $la = $a['loc'];
        $lb = $b['loc'];

        // SCM: both copies are in the lookup chain of one folder, device or snippet
        if( $this->isScmReport() )
        {
            foreach( $this->scmReportLocations() as $view )
            {
                $levels = $this->scmLevels( $view['loc'] );
                if( in_array( $la, $levels, TRUE ) && in_array( $lb, $levels, TRUE ) )
                    return TRUE;
            }
            return FALSE;
        }

        if( $scope == 'dg' )
        {
            if( $la instanceof PanoramaConf || $lb instanceof PanoramaConf || $la instanceof PANConf || $lb instanceof PANConf )
                return TRUE;
            if( $la instanceof DeviceGroup && $lb instanceof DeviceGroup )
                return $this->isParentDG( $la, $lb ) || $this->isParentDG( $lb, $la );
            return FALSE;
        }

        // template scope: both used by one template stack
        if( !isset($a['template']) || !isset($b['template']) )
            return ( $la instanceof PANConf || $lb instanceof PANConf );
        if( $a['template'] === $b['template'] )
            return TRUE;
        foreach( $this->pan->getTemplatesStacks() as $stack )
        {
            $members = array_merge( array( $stack ), $stack->templates );
            if( in_array( $a['template'], $members, TRUE ) && in_array( $b['template'], $members, TRUE ) )
                return TRUE;
        }
        return FALSE;
    }

    private function isParentDG( DeviceGroup $parent, DeviceGroup $child )
    {
        $cur = $child->parentDeviceGroup;
        while( $cur !== null )
        {
            if( $cur === $parent )
                return TRUE;
            $cur = $cur->parentDeviceGroup;
        }
        return FALSE;
    }

    /** depth of a location: shared 0, device group 1 + parent depth */
    private function depth( $loc )
    {
        // SCM: 'All' 0, folder / device 1 + parent depth; a snippet copy is never the one kept
        // while a folder copy exists
        if( $loc instanceof Snippet )
            return 1000;
        if( $loc instanceof Container || $loc instanceof DeviceCloud || $loc instanceof DeviceOnPrem )
        {
            $d = 0;
            for( $cur = $loc->parentContainer; $cur !== null; $cur = $cur->parentContainer )
                $d++;
            return $d;
        }

        if( !( $loc instanceof DeviceGroup ) )
            return 0;
        $d = 1;
        $cur = $loc->parentDeviceGroup;
        while( $cur !== null )
        {
            $d++;
            $cur = $cur->parentDeviceGroup;
        }
        return $d;
    }

    // ------------------------------------------------------------------------------------------
    // report
    // ------------------------------------------------------------------------------------------

    private function reportType( $type )
    {
        $def = $this->reportTypes[$type];
        $storeProp = $def['store'];

        $entries = array();
        foreach( $this->reportLocations( $def['scope'] ) as $l )
        {
            $loc = $l['loc'];
            if( !isset($loc->$storeProp) || $loc->$storeProp === null )
                continue;
            foreach( $def['list']( $loc->$storeProp ) as $object )
            {
                if( !is_object($object) || $object->owner !== $loc->$storeProp )
                    continue;
                if( $def['eligible'] !== null && !$def['eligible']( $object ) )
                    continue;
                $value = $def['value']( $object, $l );
                $entries[] = $l + array( 'object' => $object, 'name' => $object->name(), 'value' => $value,
                    'info' => isset($def['info']) ? $def['info']( $object ) : '' );
            }
        }

        $byName = array();
        $byValue = array();
        foreach( $entries as $i => $e )
        {
            $byName[$e['name']][] = $i;
            $byValue[$e['value']][] = $i;
        }

        $sum = array( 'objects' => count($entries), 'same-name-same-value' => 0, 'same-name-different-value' => 0,
            'overlapping-conflicts' => 0, 'same-value-different-names' => 0, 'merge-ok' => 0, 'merge-blocked' => 0 );

        PH::print_stdout();
        PH::print_stdout( "######################## objecttype: {$type} ({$sum['objects']} objects) ########################" );

        foreach( $byName as $name => $idx )
        {
            if( count($idx) < 2 )
                continue;
            $values = array();
            foreach( $idx as $i )
                $values[$entries[$i]['value']] = TRUE;

            if( count($values) == 1 )
            {
                $sum['same-name-same-value']++;
                $this->addFinding( $type, 'same name, same value', $name, FALSE, $idx, $entries, $def, $sum );
            }
            else
            {
                $sum['same-name-different-value']++;
                $overlap = FALSE;
                foreach( $idx as $a )
                    foreach( $idx as $b )
                        if( $a < $b && $entries[$a]['value'] !== $entries[$b]['value'] && $this->overlapping( $entries[$a], $entries[$b], $def['scope'] ) )
                            $overlap = TRUE;
                if( $overlap )
                    $sum['overlapping-conflicts']++;
                $this->addFinding( $type, 'same name, different value', $name, $overlap, $idx, $entries, $def, $sum );
            }
        }

        foreach( $byValue as $value => $idx )
        {
            $names = array();
            foreach( $idx as $i )
                $names[$entries[$i]['name']] = TRUE;
            if( count($names) < 2 )
                continue;
            $sum['same-value-different-names']++;
            $this->addFinding( $type, 'same value, different names', implode(',', array_keys($names)), FALSE, $idx, $entries, $def, $sum );
        }

        PH::print_stdout( " - same name, same value: {$sum['same-name-same-value']} | same name, different value: {$sum['same-name-different-value']} ({$sum['overlapping-conflicts']} overlapping) | same value, different names: {$sum['same-value-different-names']}"
            . ( $this->mergeCheck && isset($def['safety']) ? " | merge check: {$sum['merge-ok']} ok, {$sum['merge-blocked']} would change the policy" : "" ) );

        $this->summary[$type] = $sum;
    }

    private function addFinding( $type, $kind, $key, $overlap, array $idx, array $entries, array $def, array &$sum )
    {
        $copies = array();
        foreach( $idx as $i )
        {
            $e = $entries[$i];
            $copies[] = $e['label'] . ':' . $e['name'] . '=' . $this->shortValue( $e['value'] ) . ( $e['info'] !== '' ? ' (' . trim($e['info']) . ')' : '' );
        }

        $check = '';
        if( $this->mergeCheck && isset($def['safety']) && $kind !== 'same name, different value' )
            $check = $this->mergeCheckText( $idx, $entries, $def, $sum );

        PH::print_stdout( "   * [{$kind}]" . ( $overlap ? " [overlapping]" : "" ) . " '{$key}': " . implode(' | ', $copies) . ( $check !== '' ? " -> " . $check : "" ) );

        $this->findings[] = array( 'type' => $type, 'kind' => $kind, 'key' => $key, 'overlap' => $overlap ? 'yes' : '',
            'copies' => $copies, 'check' => $check );
    }

    /** MergeSafety: replace every copy by the copy in the highest location */
    private function mergeCheckText( array $idx, array $entries, array $def, array &$sum )
    {
        $keep = null;
        foreach( $idx as $i )
            if( $keep === null || $this->depth( $entries[$i]['loc'] ) < $this->depth( $entries[$keep]['loc'] ) )
                $keep = $i;

        $safety = new MergeSafety( $this->pan, $def['safety'], FALSE );
        $ok = 0;
        $blocked = array();
        $notVisible = array();
        foreach( $idx as $i )
        {
            if( $i === $keep )
                continue;
            if( !$this->visibleFrom( $entries[$keep]['loc'], $entries[$i]['loc'] ) )
            {
                $notVisible[] = $entries[$i]['label'] . ':' . $entries[$i]['name'];
                continue;
            }
            $reason = $safety->checkReplace( $entries[$i]['object'], $entries[$keep]['object'] );
            if( $reason === null )
                $ok++;
            else
                $blocked[] = $entries[$i]['label'] . ':' . $entries[$i]['name'] . ' (' . $reason . ')';
        }
        $sum['merge-ok'] += $ok;
        $sum['merge-blocked'] += count($blocked);

        $text = "keep " . $entries[$keep]['label'] . ':' . $entries[$keep]['name'] . ", " . $ok . " ok";
        if( count($blocked) > 0 )
            $text .= ", " . count($blocked) . " would change the policy: " . implode('; ', $blocked);
        if( count($notVisible) > 0 )
            $text .= ", not checked (kept copy not visible there, needs a copy in a common parent): " . implode('; ', $notVisible);
        return $text;
    }

    /** an object in $keepLoc can be used from $otherLoc */
    private function visibleFrom( $keepLoc, $otherLoc )
    {
        // SCM: the kept copy is in the lookup chain of the other copy's location
        // (parent folders, their snippets; a snippet also uses 'All')
        if( $this->isScmReport() )
            return $keepLoc === $otherLoc || in_array( $keepLoc, $this->scmLevels( $otherLoc ), TRUE );

        if( $keepLoc === $otherLoc || $keepLoc instanceof PanoramaConf || $keepLoc instanceof PANConf )
            return TRUE;
        if( $keepLoc instanceof DeviceGroup && $otherLoc instanceof DeviceGroup )
            return $this->isParentDG( $keepLoc, $otherLoc );
        return FALSE;
    }

    private function shortValue( $value )
    {
        if( strlen($value) <= 60 )
            return $value;
        return 'content#' . substr( md5($value), 0, 8 );
    }

    private function printSummary()
    {
        PH::print_stdout();
        PH::print_stdout( "######################## summary ########################" );
        foreach( $this->summary as $type => $s )
        {
            if( $s['objects'] == 0 )
                continue;
            PH::print_stdout( sprintf( " - %-34s objects %5d | same name+value %4d | same name, other value %4d (%d overlapping) | same value, other name %4d%s",
                $type, $s['objects'], $s['same-name-same-value'], $s['same-name-different-value'], $s['overlapping-conflicts'], $s['same-value-different-names'],
                $this->mergeCheck && isset($this->reportTypes[$type]['safety']) ? sprintf( " | merge ok %d / would change policy %d", $s['merge-ok'], $s['merge-blocked'] ) : "" ) );
        }
    }

    private function exportReportHtml()
    {
        $esc = function( $t ) { return htmlspecialchars( (string)$t, ENT_QUOTES ); };
        $html = "<html><head><meta charset=\"utf-8\"><title>merger-possible-report</title>"
            . "<style>body{font-family:sans-serif;font-size:13px}table{border-collapse:collapse}td,th{border:1px solid #999;padding:3px 6px;vertical-align:top}th{background:#eee}</style></head><body>";
        $html .= "<h2>Summary</h2><table><tr><th>object type</th><th>objects</th><th>same name, same value</th><th>same name, different value</th><th>overlapping</th><th>same value, different names</th><th>merge ok</th><th>would change policy</th></tr>";
        foreach( $this->summary as $type => $s )
            $html .= "<tr><td>" . $esc($type) . "</td><td>{$s['objects']}</td><td>{$s['same-name-same-value']}</td><td>{$s['same-name-different-value']}</td><td>{$s['overlapping-conflicts']}</td><td>{$s['same-value-different-names']}</td><td>"
                . ( $this->mergeCheck && isset($this->reportTypes[$type]['safety']) ? $s['merge-ok'] : '' ) . "</td><td>"
                . ( $this->mergeCheck && isset($this->reportTypes[$type]['safety']) ? $s['merge-blocked'] : '' ) . "</td></tr>";
        $html .= "</table><h2>Findings</h2><table><tr><th>object type</th><th>finding</th><th>name / names</th><th>overlapping</th><th>copies (location:name=value)</th><th>merge check</th></tr>";
        foreach( $this->findings as $f )
            $html .= "<tr><td>" . $esc($f['type']) . "</td><td>" . $esc($f['kind']) . "</td><td>" . $esc($f['key']) . "</td><td>" . $esc($f['overlap']) . "</td><td>"
                . implode('<br>', array_map($esc, $f['copies'])) . "</td><td>" . $esc($f['check']) . "</td></tr>";
        $html .= "</table></body></html>";

        file_put_contents( $this->exportcsvFile, $html );
        PH::print_stdout( " - report written to '" . $this->exportcsvFile . "'" );
    }
}
