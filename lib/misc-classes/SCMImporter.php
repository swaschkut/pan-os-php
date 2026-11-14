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
 * Puts a Panorama or firewall configuration into an SCM configuration (XML as written by in=scm-api://).
 * type=scm-changes then turns the result into SCM API requests (folders and snippets first).
 *
 * Panorama
 *   shared                  -> container All, or a snippet attached to All
 *   device-group            -> folder below the firewall folder (ngfw-shared); the DG hierarchy is kept
 *   template                -> snippet
 *   template-stack (own)    -> snippet
 *   managed firewall        -> device below the folder of its device-group; snippets attached in the order
 *                              template-stack, then its templates in stack order (the top snippet wins in SCM,
 *                              as the stack wins over its templates in Panorama)
 *
 * Firewall
 *   shared + one vsys       -> a new folder below the firewall folder, or a snippet
 *
 * Objects whose name already exists at the target are not copied (the existing one stays), with a warning.
 */
class SCMImporter
{
    const FIREWALL_FOLDER = "ngfw-shared";

    /** folder levels below the firewall folder - the same limit as device-group levels below shared in Panorama */
    const MAX_FOLDER_DEPTH = 4;

    /** paths that are the same below a Panorama device-group / shared / vsys and an SCM folder / snippet */
    static public $objectPaths = array(
        'tag', 'address', 'address-group', 'service', 'service-group', 'schedule',
        'log-settings/profiles',
        'profiles/custom-url-category', 'profiles/spyware', 'profiles/vulnerability', 'profiles/url-filtering',
        'profiles/file-blocking', 'profiles/dns-security', 'profiles/virus-and-wildfire-analysis',
        'profile-group',
    );

    /** configuration that exists in Panorama / PAN-OS but is not imported; reported with the number of entries */
    static public $notImported = array(
        'external-list' => 'external dynamic lists',
        'application' => 'custom applications',
        'application-group' => 'application groups',
        'application-filter' => 'application filters',
        'profiles/virus' => 'antivirus profiles (SCM: wildfire-anti-virus-profiles, combined with WildFire)',
        'profiles/wildfire-analysis' => 'WildFire profiles (SCM: wildfire-anti-virus-profiles, combined with antivirus)',
        'profiles/data-filtering' => 'data filtering profiles',
        'profiles/decryption' => 'decryption profiles',
        'pre-rulebase/nat/rules' => 'NAT pre-rules', 'post-rulebase/nat/rules' => 'NAT post-rules',
        'rulebase/nat/rules' => 'NAT rules',
        'pre-rulebase/decryption/rules' => 'decryption pre-rules', 'post-rulebase/decryption/rules' => 'decryption post-rules',
        'rulebase/decryption/rules' => 'decryption rules',
        'pre-rulebase/application-override/rules' => 'application override pre-rules',
        'rulebase/application-override/rules' => 'application override rules',
        'pre-rulebase/pbf/rules' => 'PBF pre-rules', 'rulebase/pbf/rules' => 'PBF rules',
        'pre-rulebase/qos/rules' => 'QoS pre-rules', 'rulebase/qos/rules' => 'QoS rules',
        'pre-rulebase/authentication/rules' => 'authentication pre-rules', 'rulebase/authentication/rules' => 'authentication rules',
    );

    /** zone protection profile: PAN-OS field => SCM field (same setting, other name) */
    static public $zppFieldNames = array(
        'discard-ip-spoof' => 'spoofed-ip-discard',
        'discard-ip-frag' => 'fragmented-traffic-discard',
        'discard-strict-source-routing' => 'strict-source-routing-discard',
        'discard-loose-source-routing' => 'loose-source-routing-discard',
        'discard-security' => 'security-discard',
        'discard-timestamp' => 'timestamp-discard',
        'discard-record-route' => 'record-route-discard',
        'discard-stream-id' => 'stream-id-discard',
        'discard-unknown-option' => 'unknown-option-discard',
        'discard-malformed-option' => 'malformed-option-discard',
        'discard-overlapping-tcp-segment-mismatch' => 'mismatched-overlapping-tcp-segment-discard',
        'discard-tcp-split-handshake' => 'tcp-handshake-discard',
        'discard-tcp-syn-with-data' => 'tcp-syn-with-data-discard',
        'discard-tcp-synack-with-data' => 'tcp-synack-with-data-discard',
        'discard-icmp-ping-zero-id' => 'icmp-ping-zero-id-discard',
        'discard-icmp-frag' => 'icmp-frag-discard',
        'discard-icmp-large-packet' => 'icmp-large-packet-discard',
        'discard-icmp-error' => 'discard-icmp-embedded-error',
        'remove-tcp-timestamp' => 'tcp-timestamp-strip',
        'tcp-reject-non-syn' => 'reject-non-syn-tcp',
        'strip-mptcp-option' => 'mptcp-option-strip',
        'strip-tcp-fast-open-and-data' => 'tcp-fast-open-and-data-strip',
    );

    /** @var BuckbeakConf */
    public $scm;
    public $warnings = array();
    public $summary = array();

    public $keepZoneInterfaces = FALSE;
    /** zones: interfaces as SCM interface variables ($ethernet1_1, $ethernet1_2-1 …) - the interfaces themselves are
     *  created by the caller (scm_pa_panorama_to_change.php) in the snippet of the template */
    public $interfaceVariables = FALSE;

    /** PAN-OS interface name -> SCM interface variable: ethernet1/1 -> $ethernet1_1, ethernet1/2.1 -> $ethernet1_2-1 */
    static public function interfaceVariable($name)
    {
        $name = trim($name);
        if( $name === '' || $name[0] == '$' )
            return $name;
        // ethernet / aggregate sub interfaces: SCM requires "<parent>.<unit>" (live: '$ethernet1_2-1' is invalid)
        if( preg_match('/^(ethernet\d+\/\d+(?:\/\d+)?|ae\d+)\.(\d+)$/', $name, $m) )
            return '$' . str_replace('/', '_', $m[1]) . '.' . $m[2];
        return '$' . str_replace(array('/', '.'), array('_', '-'), $name);
    }

    /** snippet created for a template ('template') / template-stack ('stack'); null if none */
    public function snippetNameOf($kind, $name)
    {
        return isset($this->snippetNames[$kind . "|" . $name]) ? $this->snippetNames[$kind . "|" . $name] : null;
    }
    public $firewallFolder = self::FIREWALL_FOLDER;

    /** Panorama: 'all' (default), 'device-groups' (shared + device-groups only: no templates, stacks, firewalls) or
     *  'templates' (shared + device-groups + templates / template-stacks as snippets, attached to the device-group
     *  folders: per firewall of the device-group its template-stack, then the stack's templates; no firewalls) */
    public $panoramaScope = 'all';
    /** Panorama: folder (below the firewall folder) that holds the device-group tree; null = the firewall folder */
    public $dgParentFolder = null;
    /** Panorama: only these device-groups (their parents are imported as well); null = all */
    public $deviceGroupFilter = null;
    /** Panorama, scope device-groups: create the zones used by the security rules of a device-group in its folder
     *  (definition from the templates, interfaces removed; not created again below a folder that has it already) */
    public $zonesFromRules = FALSE;

    /** Panorama: prepare security profiles for SCM before the import (SCM rules take profile groups only, SCM combines
     *  antivirus + WildFire, DNS security is its own profile): see prepareSecurityProfiles() */
    public $scmProfiles = FALSE;
    /** custom applications are created by the caller (scm_pa_panorama_to_change.php) - not reported as not imported */
    public $customApplicationsElsewhere = FALSE;

    /** device-groups not imported because the folder level would exceed MAX_FOLDER_DEPTH */
    public $depthErrors = array();

    /** group tags removed from rules (reported once) */
    public $groupTags = array();

    /** "type|name" => name of the snippet created for it */
    private $snippetNames = array();

    public function __construct(BuckbeakConf $scm)
    {
        $this->scm = $scm;
    }

    // ------------------------------------------------------------------------------------------------
    // Panorama
    // ------------------------------------------------------------------------------------------------

    /**
     * @param PanoramaConf $pano
     * @param string $sharedMode 'snippet' (default), 'global', 'folder' (into the device-group parent folder) or 'skip'
     * @param string $sharedSnippet name of the snippet for shared
     */
    public function importPanorama(PanoramaConf $pano, $sharedMode = 'snippet', $sharedSnippet = 'Panorama-Shared')
    {
        $xp = new DOMXPath($pano->xmldoc);
        $all = $this->scm->findContainer("All");
        $fwFolder = $this->ensureFirewallFolder();

        if( $this->scmProfiles )
            $this->prepareSecurityProfiles($pano);

        // folder that holds the device-group tree
        $dgRoot = $fwFolder;
        if( $this->dgParentFolder !== null && $this->dgParentFolder !== $fwFolder->name() )
        {
            $dgRoot = $this->scm->findContainer($this->dgParentFolder);
            if( $dgRoot === null )
                $dgRoot = $this->scm->createContainer($this->validName($this->dgParentFolder, "device-group parent folder"), $fwFolder->name());
        }

        // shared
        $shared = $xp->query("/config/shared")->item(0);
        if( $sharedMode == 'skip' )
        {
            if( $shared !== null )
                $this->reportSkippedShared($shared);
            $shared = null;
        }
        if( $shared !== null )
        {
            if( $sharedMode == 'global' )
                $target = $all;
            elseif( $sharedMode == 'folder' )
                $target = $dgRoot;
            else
            {
                $target = $this->ensureSnippet($this->validName($sharedSnippet, "shared snippet"), "shared");
                $all->addSnippet($target);
            }
            $this->copyScope($shared, $target, "Panorama shared", TRUE);
            $sharedRules = (new DOMXPath($shared->ownerDocument))->query("pre-rulebase/security/rules/entry|post-rulebase/security/rules/entry", $shared)->length;
            if( $sharedRules > 0 && $sharedMode == 'global' )
                $this->warnings[] = "Panorama shared: " . $sharedRules . " security rule(s) copied to folder 'All' - they apply to Prisma Access as well";
            if( $this->zonesFromRules && $sharedMode == 'folder' )
                $this->addRuleZones($pano, $target, $dgRoot === $fwFolder ? "All" : $fwFolder->name(), "Panorama shared");
        }

        // device-groups, parents first
        $dgFolders = array();
        $pending = $pano->deviceGroups;
        if( $this->deviceGroupFilter !== null )
        {
            $wanted = array();
            foreach( $this->deviceGroupFilter as $name )
            {
                $dg = $pano->findDeviceGroup($name);
                if( $dg === null )
                {
                    $this->warnings[] = "device-group '" . $name . "' not found";
                    continue;
                }
                for( $d = $dg; $d !== null; $d = $d->parentDeviceGroup )
                    $wanted[$d->name()] = TRUE;
            }
            $pending = array_filter($pending, function($dg) use ($wanted){ return isset($wanted[$dg->name()]); });
        }
        while( !empty($pending) )
        {
            $progress = FALSE;
            foreach( $pending as $i => $dg )
            {
                /** @var DeviceGroup $dg */
                $parentDG = $dg->parentDeviceGroup;
                if( $parentDG !== null && !isset($dgFolders[$parentDG->name()]) )
                    continue;
                $parentName = $parentDG === null ? $dgRoot->name() : $dgFolders[$parentDG->name()]->name();
                $parentDepth = $this->folderDepth($parentName);
                if( $parentDepth !== null && $parentDepth + 1 > self::MAX_FOLDER_DEPTH )
                {
                    $this->depthErrors[] = "device-group '" . $dg->name() . "': folder level " . ($parentDepth + 1) . " below '" . $this->firewallFolder
                        . "' (max. " . self::MAX_FOLDER_DEPTH . ") - not imported" . ( $dgRoot !== $fwFolder ? "; dg-parent '" . $dgRoot->name() . "' uses " . $this->folderDepth($dgRoot->name()) . " level(s)" : "" );
                    unset($pending[$i]);
                    $progress = TRUE;
                    continue;
                }
                $folder = $this->ensureFolder($this->validName($dg->name(), "device-group"), $parentName);
                $dgFolders[$dg->name()] = $folder;
                $this->copyScope($dg->xmlroot, $folder, "device-group '" . $dg->name() . "'", TRUE);
                unset($pending[$i]);
                $progress = TRUE;
            }
            if( !$progress )
            {
                foreach( $pending as $dg )
                    $this->warnings[] = "device-group '" . $dg->name() . "': its parent cannot be resolved, not imported";
                break;
            }
        }
        $this->summary['folders'] = count($dgFolders);

        if( $this->panoramaScope == 'device-groups' )
        {
            $this->addZonesOfRules($pano, $dgFolders);
            $this->summary['skipped'] = array( 'templates' => count($pano->templates), 'template-stacks' => count($pano->templatestacks),
                'firewalls' => count($pano->managedFirewallsStore->getAll()) );
            return;
        }

        // templates and template-stacks
        foreach( $pano->templates as $template )
        {
            /** @var Template $template */
            $snippet = $this->ensureSnippet($this->validName($template->name(), "template"), "template|" . $template->name());
            $config = DH::findFirstElement('config', $template->xmlroot);
            if( $config !== FALSE )
                $this->copyNetworkScope($config, $snippet, "template '" . $template->name() . "'");
            if( empty($this->stacksOfTemplate($pano, $template)) )
                $this->warnings[] = "template '" . $template->name() . "' is in no template-stack: its snippet is created but not attached";
        }
        foreach( $pano->templatestacks as $stack )
        {
            /** @var TemplateStack $stack */
            $name = $stack->name();
            if( $this->scm->findSnippet($name) !== null && !isset($this->snippetNames["stack|" . $name]) )
                $name = $name . "-stack";
            $snippet = $this->ensureSnippet($this->validName($name, "template-stack"), "stack|" . $stack->name());
            $config = DH::findFirstElement('config', $stack->xmlroot);
            if( $config !== FALSE )
                $this->copyNetworkScope($config, $snippet, "template-stack '" . $stack->name() . "'");
        }
        $this->summary['snippets'] = count($this->snippetNames);

        if( $this->panoramaScope == 'templates' )
        {
            $this->attachStacksToFolders($pano, $dgFolders);
            $this->addZonesOfRules($pano, $dgFolders);
            $this->summary['skipped'] = array( 'firewalls' => count($pano->managedFirewallsStore->getAll()) );
            return;
        }

        // managed firewalls
        $devices = 0;
        foreach( $pano->managedFirewallsStore->getAll() as $fw )
        {
            /** @var ManagedDevice $fw */
            $serial = $fw->name();
            $dgs = array_keys($fw->getDeviceGroup());
            if( count($dgs) > 0 && isset($dgFolders[$dgs[0]]) )
                $folder = $dgFolders[$dgs[0]];
            else
            {
                $folder = $fwFolder;
                $this->warnings[] = "firewall " . $serial . " is in no device-group: attached to folder '" . $fwFolder->name() . "'";
            }
            if( $folder !== $fwFolder && $this->hasChildFolder($folder) )
                $this->warnings[] = "firewall " . $serial . ": its folder '" . $folder->name() . "' has sub-folders (device-group with child device-groups)";

            $snippets = array();
            $stack = null;
            if( !empty($fw->template_stack) )
                $stack = $pano->findTemplateStack($fw->template_stack);
            if( $stack !== null )
            {
                $snippets[] = $this->snippetNames["stack|" . $stack->name()];
                foreach( $stack->templates as $t )
                    $snippets[] = $this->snippetNames["template|" . $t->name()];
            }
            elseif( !empty($fw->template_stack) )
                $this->warnings[] = "firewall " . $serial . ": template-stack '" . $fw->template_stack . "' not found";
            else
                $this->warnings[] = "firewall " . $serial . " is in no template-stack: no snippets attached";

            $this->ensureDevice($serial, $folder->name(), $snippets);
            $devices++;
        }
        $this->summary['devices'] = $devices;
    }

    /**
     * device-group folder <- snippets of the template-stacks of its firewalls: stack, then its templates (stack order);
     * the first snippet is the top one (wins in SCM, as the stack wins over its templates in Panorama)
     */
    private function attachStacksToFolders(PanoramaConf $pano, array $dgFolders)
    {
        $stacksOfDG = array();
        foreach( $pano->managedFirewallsStore->getAll() as $fw )
        {
            /** @var ManagedDevice $fw */
            $dgs = array_keys($fw->getDeviceGroup());
            if( count($dgs) == 0 || !isset($dgFolders[$dgs[0]]) )
                continue;
            if( empty($fw->template_stack) )
            {
                $this->warnings[] = "firewall " . $fw->name() . " (device-group '" . $dgs[0] . "') is in no template-stack";
                continue;
            }
            $stack = $pano->findTemplateStack($fw->template_stack);
            if( $stack === null )
            {
                $this->warnings[] = "firewall " . $fw->name() . ": template-stack '" . $fw->template_stack . "' not found";
                continue;
            }
            $stacksOfDG[$dgs[0]][$stack->name()] = $stack;
        }
        $this->summary['folder_snippets'] = array();
        foreach( $stacksOfDG as $dgName => $stacks )
        {
            $folder = $dgFolders[$dgName];
            if( count($stacks) > 1 )
                $this->warnings[] = "device-group '" . $dgName . "': its firewalls use " . count($stacks) . " template-stacks (" . implode(", ", array_keys($stacks))
                    . ") - the snippets of all are attached in this order, the first wins";
            foreach( $stacks as $stack )
            {
                $names = array( $this->snippetNames["stack|" . $stack->name()] );
                foreach( $stack->templates as $t )
                    $names[] = $this->snippetNames["template|" . $t->name()];
                foreach( $names as $n )
                {
                    $folder->addSnippet($this->scm->findSnippet($n));
                    $this->summary['folder_snippets'][$folder->name()][] = $n;
                }
            }
        }
        foreach( $dgFolders as $dgName => $folder )
            if( !isset($stacksOfDG[$dgName]) && !$this->hasChildFolder($folder) )
                $this->warnings[] = "device-group '" . $dgName . "': no firewall with a template-stack - no snippets attached";
    }

    /** zones of the rules of every device-group folder (zonesFromRules), parents first */
    private function addZonesOfRules(PanoramaConf $pano, array $dgFolders)
    {
        if( !$this->zonesFromRules )
            return;
        foreach( $dgFolders as $dgName => $folder )
        {
            $pn = DH::findFirstElement('parent', $folder->xmlroot);
            $this->addRuleZones($pano, $folder, $pn === FALSE ? null : $pn->textContent, "device-group '" . $dgName . "'");
        }
    }

    /** folder name => zone names created in it (zones from rules) */
    private $ruleZones = array();
    /** zone name => definition in a template / template-stack (first found) */
    private $templateZones = null;

    /**
     * zones of the security rules of $folder (from / to, not 'any') that are not in the folder or one of its parents yet:
     * created in $folder with the definition of the templates (interfaces removed) or as empty layer3 zone
     */
    private function addRuleZones(PanoramaConf $pano, $folder, $parentName, $label)
    {
        if( $this->templateZones === null )
        {
            $this->templateZones = array();
            $xp = new DOMXPath($pano->xmldoc);
            foreach( array('template', 'template-stack') as $kind )
                foreach( $xp->query("/config/devices/entry/" . $kind . "/entry/config/devices/entry/vsys/entry/zone/entry") as $z )
                    if( !isset($this->templateZones[$z->getAttribute('name')]) )
                        $this->templateZones[$z->getAttribute('name')] = $z;
        }

        $xp = new DOMXPath($folder->xmlroot->ownerDocument);
        $used = array();
        foreach( array('pre-rulebase', 'post-rulebase') as $rb )
            foreach( $xp->query($rb . "/security/rules/entry/from/member|" . $rb . "/security/rules/entry/to/member", $folder->xmlroot) as $m )
            {
                $z = trim($m->textContent);
                if( $z !== '' && $z !== 'any' )
                    $used[$z] = TRUE;
            }
        if( empty($used) )
            return;

        // zones of the parent folders and of the snippets attached to the folder or its parents
        // (created by this import or existing in the SCM configuration)
        $inherited = array();
        $sxp = new DOMXPath($folder->xmlroot->ownerDocument);
        foreach( $sxp->query("snippets/member", $folder->xmlroot) as $m )
            if( ($sn = $this->scm->findSnippet(trim($m->textContent))) !== null )
                foreach( $sxp->query("zone/entry", $sn->xmlroot) as $z )
                    $inherited[$z->getAttribute('name')] = TRUE;
        for( $p = $parentName, $guard = 0; $p !== null && $guard < 20; $guard++ )
        {
            foreach( $this->ruleZones[$p] ?? array() as $z => $x )
                $inherited[$z] = TRUE;
            $c = $this->scm->findContainer($p);
            if( $c === null )
                break;
            foreach( $xp->query("zone/entry", $c->xmlroot) as $z )
                $inherited[$z->getAttribute('name')] = TRUE;
            foreach( $sxp->query("snippets/member", $c->xmlroot) as $m )
                if( ($sn = $this->scm->findSnippet(trim($m->textContent))) !== null )
                    foreach( $sxp->query("zone/entry", $sn->xmlroot) as $z )
                        $inherited[$z->getAttribute('name')] = TRUE;
            $pn = DH::findFirstElement('parent', $c->xmlroot);
            $p = $pn === FALSE ? null : $pn->textContent;
        }

        $parent = $this->ensurePath($folder->xmlroot, 'zone');
        $existing = array();
        foreach( $xp->query("entry", $parent) as $e )
            $existing[$e->getAttribute('name')] = TRUE;
        $created = array();
        $empty = array();
        foreach( array_keys($used) as $z )
        {
            if( isset($inherited[$z]) || isset($existing[$z]) )
                continue;
            if( isset($this->templateZones[$z]) )
                $new = $parent->ownerDocument->importNode($this->templateZones[$z], TRUE);
            else
            {
                $new = $parent->ownerDocument->createElement('entry');
                $new->setAttribute('name', $z);
                DH::createElement( DH::createElement($new, 'network'), 'layer3' );
                $empty[] = $z;
            }
            $this->currentDest = $folder;
            $this->cleanEntry($new, 'zones', $label);
            if( !isset($this->templateZones[$z]) )
                $this->addPlaceholder('zones', $z, "placeholder: zone used by rules, not in a template - empty layer3 zone");
            $parent->appendChild($new);
            $this->ruleZones[$folder->name()][$z] = TRUE;
            $created[] = $z;
        }
        if( !empty($created) )
        {
            $this->summary['objects']['zones'] = ($this->summary['objects']['zones'] ?? 0) + count($created);
            $this->warnings[] = $label . ": zones of its rules created in folder '" . $folder->name() . "': " . implode(", ", $created)
                . ( !empty($empty) ? " (not in a template, created as empty layer3 zone: " . implode(", ", $empty) . ")" : "" );
        }
    }

    /** folder levels below the firewall folder (firewall folder = 0); null if it is not below it */
    public function folderDepth($name)
    {
        $depth = 0;
        for( $guard = 0; $guard < 20; $guard++ )
        {
            if( $name === $this->firewallFolder )
                return $depth;
            $c = $this->scm->findContainer($name);
            if( $c === null )
                return null;
            $p = DH::findFirstElement('parent', $c->xmlroot);
            if( $p === FALSE )
                return null;
            $name = $p->textContent;
            $depth++;
        }
        return null;
    }

    private function reportSkippedShared(DOMElement $shared)
    {
        $n = 0;
        foreach( array_merge(self::$objectPaths, array('pre-rulebase/security/rules', 'post-rulebase/security/rules')) as $rel )
            $n += (new DOMXPath($shared->ownerDocument))->query($rel . "/entry", $shared)->length;
        if( $n > 0 )
            $this->warnings[] = "Panorama shared: " . $n . " object(s) / rule(s) not imported (shared=skip) - device-group objects / rules that use them fail";
    }

    // ------------------------------------------------------------------------------------------------
    // security profiles for SCM (Panorama source XML is changed in memory, before it is copied)
    // ------------------------------------------------------------------------------------------------

    /**
     * 1) security rules with single profiles -> profile group: the same as the rule action securityProfile-replace-by-Group
     *    (existing group with the same profiles, else a new one secProfGroupN in the scope of the rule)
     * 2) profile groups: virus + wildfire-analysis -> one virus-and-wildfire-analysis profile in the scope of the group
     *    (name: the antivirus or WildFire profile name, both: <AV>_<WF>) - WildFire rules, antivirus threat / MLAV
     *    exceptions and packet capture; decoder actions and inline ML of the antivirus profile are not part of the
     *    public SCM API (warning)
     * 3) spyware profiles with botnet-domains -> DNS security profile with the same name (botnet-domains moved there);
     *    profile groups with such a spyware profile get it as dns-security
     */
    private function prepareSecurityProfiles(PanoramaConf $pano)
    {
        $scopes = array( array('label' => "Panorama shared", 'store' => $pano, 'dg' => null, 'node' => DH::findFirstElement('shared', $pano->xmlroot)) );
        foreach( $pano->deviceGroups as $dg )
            $scopes[] = array('label' => "device-group '" . $dg->name() . "'", 'store' => $dg, 'dg' => $dg, 'node' => $dg->xmlroot);

        // 1) rules with single profiles -> group
        $replaced = 0;
        foreach( $scopes as $sc )
        {
            if( $sc['node'] === FALSE || $sc['node'] === null || !isset($sc['store']->securityRules) || $sc['store']->securityRules === null )
                continue;
            foreach( $sc['store']->securityRules->rules() as $rule )
            {
                if( !$rule->isSecurityRule() || $rule->securityProfileIsBlank() || $rule->securityProfileType() == "group" )
                    continue;
                $store = $rule->owner->owner->securityProfileGroupStore;
                if( $store->xmlroot === null )
                {
                    $node = DH::findFirstElementOrCreate('profile-group', $rule->owner->owner->xmlroot);
                    $store->load_securityprofile_groups_from_domxml($node);
                }
                $profiles = $rule->securityProfiles();
                // also the profile groups of the parent device-groups / shared (same profile objects only)
                $group = $store->findByHash( $store->calculateHash($profiles), TRUE, $rule->securityProfiles_obj() );
                if( $group === null )
                    $group = $store->createSecurityProfileGroup_based_Profile( $profiles, $rule->securityProfiles_obj() );
                $rule->setSecurityProfileGroup( $group->name() );
                $replaced++;
                $this->spgCreated[$sc['label']][$group->name()][] = $rule->name();
            }
        }
        foreach( $this->spgCreated as $label => $groups )
            foreach( $groups as $g => $rules )
                $this->warnings[] = $label . ": rules with single security profiles use profile group '" . $g . "' (SCM rules take profile groups only): " . implode(", ", $rules);
        $this->summary['rules_profiles_to_group'] = $replaced;

        $xp = new DOMXPath($pano->xmldoc);

        // 0) references are never removed: a profile a group refers to that is not in the configuration is created in
        //    the scope of the group - copy of the PAN-OS predefined profile, else an empty placeholder (both listed)
        foreach( $scopes as $sc )
        {
            if( $sc['node'] === FALSE || $sc['node'] === null )
                continue;
            foreach( $xp->query("profile-group/entry", $sc['node']) as $grp )
                foreach( array('spyware', 'vulnerability', 'url-filtering', 'file-blocking') as $type )
                {
                    $m = $this->groupMember($grp, $type);
                    if( $m === null || $this->findProfile($pano, $sc['dg'], $type, $m) !== null )
                        continue;
                    $parent = DH::findFirstElementOrCreate($type, DH::findFirstElementOrCreate('profiles', $sc['node']));
                    $pre = $this->predefinedProfile($type, $m);
                    if( $pre !== null )
                    {
                        $new = $pano->xmldoc->importNode($pre, TRUE);
                        $this->markPlaceholder($new, "copy of the PAN-OS predefined " . $type . " profile '" . $m . "' (referenced by profile group '" . $grp->getAttribute('name') . "')");
                    }
                    else
                    {
                        $new = $pano->xmldoc->createElement('entry');
                        $new->setAttribute('name', $m);
                        $this->markPlaceholder($new, "placeholder: " . $type . " profile '" . $m . "' is not in the configuration and not PAN-OS predefined - content unknown (referenced by profile group '" . $grp->getAttribute('name') . "')");
                    }
                    $parent->appendChild($new);
                    $this->warnings[] = $sc['label'] . ": " . $type . " profile '" . $m . "' referenced by profile group '" . $grp->getAttribute('name') . "' created " . ( $pre !== null ? "as copy of the PAN-OS predefined profile" : "as placeholder" );
                }
            // log forwarding profiles without match list: SCM requires one - placeholder match list (forwards nothing, as before)
            foreach( $xp->query("log-settings/profiles/entry", $sc['node']) as $lfp )
                if( $xp->query("match-list/entry", $lfp)->length == 0 )
                {
                    $ml = DH::findFirstElementOrCreate('match-list', $lfp);
                    $e = DH::createElement($ml, 'entry');
                    $e->setAttribute('name', 'pan-os-php-placeholder');
                    DH::createElement($e, 'log-type', 'traffic');
                    DH::createElement($e, 'filter', 'All Logs');
                    $this->markPlaceholder($lfp, "log forwarding profile without match list (SCM requires one): placeholder match list 'pan-os-php-placeholder' (traffic, All Logs, no destination - forwards nothing)");
                }
        }

        // 3) spyware -> spyware + DNS security (per spyware profile, in its scope)
        $dnsCreated = array();
        foreach( $scopes as $sc )
        {
            if( $sc['node'] === FALSE || $sc['node'] === null )
                continue;
            foreach( $xp->query("profiles/spyware/entry", $sc['node']) as $sp )
            {
                $botnet = DH::findFirstElement('botnet-domains', $sp);
                if( $botnet === FALSE )
                    continue;
                $name = $sp->getAttribute('name');
                $dnsParent = DH::findFirstElementOrCreate('dns-security', DH::findFirstElementOrCreate('profiles', $sc['node']));
                $exists = $xp->query("entry[@name='" . $name . "']", $dnsParent)->length > 0;
                if( !$exists )
                {
                    $dns = $pano->xmldoc->createElement('entry');
                    $dns->setAttribute('name', $name);
                    $dnsParent->appendChild($dns);
                    $dns->appendChild($botnet);     // moved
                    $dnsCreated[$sc['label']][] = $name;
                }
                else
                    $sp->removeChild($botnet);
            }
        }
        foreach( $dnsCreated as $label => $names )
            $this->warnings[] = $label . ": DNS security of spyware profiles moved to DNS security profiles with the same name: " . implode(", ", $names);

        // 2) + 3) profile groups
        $vawCreated = array();
        foreach( $scopes as $sc )
        {
            if( $sc['node'] === FALSE || $sc['node'] === null )
                continue;
            foreach( $xp->query("profile-group/entry", $sc['node']) as $grp )
            {
                $av = $this->groupMember($grp, 'virus');
                $wf = $this->groupMember($grp, 'wildfire-analysis');
                if( $av !== null || $wf !== null )
                {
                    $name = $av !== null && $wf !== null ? $av . "_" . $wf : ( $av !== null ? $av : $wf );
                    $this->ensureVirusAndWildfire($pano, $sc, $name, $av, $wf, $vawCreated);
                    foreach( array('virus', 'wildfire-analysis') as $tag )
                        if( ($n = DH::findFirstElement($tag, $grp)) !== FALSE )
                            $grp->removeChild($n);
                    DH::createElement( DH::findFirstElementOrCreate('virus-and-wildfire-analysis', $grp), 'member', $name );
                }
                // data filtering profiles are not imported (SCM: enterprise DLP)
                // data filtering: the reference stays - SCM has no API to create the profile (enterprise DLP), the
                // generator lists the group (and what uses it) as not importable
                $spy = $this->groupMember($grp, 'spyware');
                if( $spy !== null && DH::findFirstElement('dns-security', $grp) === FALSE
                    && $this->findProfile($pano, $sc['dg'], 'dns-security', $spy) !== null )
                    DH::createElement( DH::findFirstElementOrCreate('dns-security', $grp), 'member', $spy );
            }
        }
        foreach( $vawCreated as $label => $names )
            $this->warnings[] = $label . ": antivirus / WildFire profiles of profile groups combined into virus-and-wildfire-analysis profiles: " . implode(", ", $names);

        // 4) public SCM API: rule action 'default' = empty action (as the public API returns it); sections the public
        //    API does not have are removed from the public request. The complete profile (PAN-OS structure) is kept for
        //    the internal UI API (multiConfigure edit, written by scm_pa_change.php after the public create)
        $gaps = array(
            'vulnerability' => array('mica-engine-vulnerability-enabled', 'cloud-inline-analysis'),
            'spyware' => array('mica-engine-spyware-enabled/entry/local-deep-learning'),
            'dns-security' => array('botnet-domains/advanced-dns-security-categories'),
            'virus-and-wildfire-analysis' => array('decoder', 'mlav-engine-filebased-enabled', 'cloud-inline-analysis', 'mica-engine-wildfire-rules'),
        );
        foreach( $scopes as $sc )
        {
            if( $sc['node'] === FALSE || $sc['node'] === null )
                continue;
            foreach( $gaps as $type => $paths )
                foreach( $xp->query("profiles/" . $type . "/entry", $sc['node']) as $prof )
                {
                    // DNS sinkhole: SCM (public and internal API, live 2026-11-14) only knows the keywords
                    // pan-sinkhole-default-ip / 127.0.0.1 and ::1 - the Palo Alto Networks sinkhole of PAN-OS
                    // (sinkhole.paloaltonetworks.com / 2600:5200::1) is the keyword pan-sinkhole-default-ip / ::1
                    $customSinkhole = array();
                    if( $type == 'dns-security' && ($sk = $xp->query("botnet-domains/sinkhole", $prof)->item(0)) !== null )
                        foreach( array( 'ipv4-address' => array('pan-sinkhole-default-ip', array('127.0.0.1', 'pan-sinkhole-default-ip'), array('sinkhole.paloaltonetworks.com')),
                                        'ipv6-address' => array('::1', array('::1'), array('2600:5200::1')) ) as $tag => $def )
                        {
                            $v = $xp->query($tag, $sk)->item(0);
                            if( $v === null )
                            {
                                DH::createElement($sk, $tag, $def[0]);
                                continue;
                            }
                            $val = trim($v->textContent);
                            if( in_array($val, $def[1], TRUE) )
                                continue;
                            if( !in_array($val, $def[2], TRUE) )
                                $customSinkhole[] = $tag . " " . $val;
                            else
                                $this->markIncomplete($prof, "DNS sinkhole " . $tag . " '" . $val . "' written as SCM keyword '" . $def[0] . "' (same Palo Alto Networks sinkhole)");
                            $v->textContent = $def[0];
                        }
                    foreach( $customSinkhole as $cs )
                        $this->markIncomplete($prof, "DNS sinkhole " . $cs . ": SCM only knows pan-sinkhole-default-ip / 127.0.0.1 / ::1 - set to the default sinkhole, check the profile");
                    $orig = $prof->cloneNode(TRUE);
                    $defaults = 0;
                    $removed = array();
                    // rule action 'default': the public API refuses an empty action (live: "action is missing") and
                    // has no 'default' -> the rules are sent through the internal UI API only
                    if( $type == 'vulnerability' || $type == 'spyware' )
                    {
                        $defaults = $xp->query("rules/entry/action/default", $prof)->length;
                        if( $defaults > 0 && ($rulesNode = DH::findFirstElement('rules', $prof)) !== FALSE )
                        {
                            $prof->removeChild($rulesNode);
                            $removed['rules (action default)'] = TRUE;
                        }
                    }
                    foreach( $paths as $path )
                        foreach( $xp->query($path, $prof) as $n )
                        {
                            $n->parentNode->removeChild($n);
                            $removed[$path] = TRUE;
                        }
                    if( empty($removed) && $defaults == 0 )
                        continue;
                    $prof->setAttribute(self::INTERNAL_ATTR, json_encode( array('prefix' => "profiles/" . $type,
                        'entry' => self::domToInternal($orig)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ));
                    // complete through the internal UI API (_internal) - not 'incomplete'
                    if( !empty($removed) )
                        $this->apiGaps[$sc['label'] . "|" . $type . "|" . implode(", ", array_keys($removed))][] = $prof->getAttribute('name');
                }
        }
        foreach( $this->apiGaps as $k => $names )
        {
            list($label, $type, $paths) = explode("|", $k, 3);
            $this->warnings[] = $label . ": " . $type . " profiles " . implode(", ", $names) . ": " . $paths . " not in the public SCM API - internal UI API";
        }

    }

    const INCOMPLETE_ATTR = 'pan-os-php-scm-incomplete';
    const INTERNAL_ATTR = 'pan-os-php-scm-internal';

    /** profiles to complete through the internal UI API: resource, name, scope_type, scope, prefix, entry (PAN-OS JSON) */
    public $internal = array();

    /**
     * PAN-OS XML entry -> JSON structure of the internal UI API (/api/config/v9.2): name attribute -> "@name",
     * <entry> children -> {"entry": [...]}, <member> children -> {"member": [...]}, text -> string, empty -> {}
     */
    static public function domToInternal(DOMElement $node, $top = TRUE)
    {
        $out = array();
        if( $node->hasAttribute('name') )
            $out['@name'] = $node->getAttribute('name');
        $children = array();
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                $children[] = $c;
        if( empty($children) && !$node->hasAttribute('name') )
        {
            $text = trim($node->textContent);
            return $text === '' ? new stdClass() : $text;
        }
        $tags = array();
        foreach( $children as $c )
            $tags[$c->tagName][] = $c;
        foreach( $tags as $tag => $list )
        {
            if( $tag == 'entry' || $tag == 'member' )
            {
                $items = array();
                foreach( $list as $c )
                    $items[] = $tag == 'member' ? trim($c->textContent) : self::domToInternal($c, FALSE);
                $out[$tag] = $items;
            }
            else
                $out[$tag] = self::domToInternal($list[0], FALSE);
        }
        return $out;
    }
    const INCOMPLETE_SEP = ' || ';

    /**
     * objects imported without part of their content / references: list of
     * ['resource' => , 'name' => , 'scope_type' => folder|snippet, 'scope' => , 'missing' => [..]]
     */
    public $incomplete = array();
    /** SCM container / snippet the entries are copied to (for $incomplete) */
    private $currentDest = null;

    private function addIncomplete($resource, $name, $what)
    {
        $d = $this->currentDest;
        $type = $d instanceof Snippet ? 'snippet' : 'folder';
        $scope = $d !== null ? $d->name() : null;
        $k = $resource . "|" . $type . "|" . $scope . "|" . $name;
        if( !isset($this->incomplete[$k]) )
            $this->incomplete[$k] = array( 'resource' => $resource, 'name' => $name, 'scope_type' => $type, 'scope' => $scope, 'missing' => array() );
        if( !in_array($what, $this->incomplete[$k]['missing'], TRUE) )
            $this->incomplete[$k]['missing'][] = $what;
    }

    const PLACEHOLDER_ATTR = 'pan-os-php-scm-placeholder';

    /** objects created because something refers to them, without (or with not original) content:
     *  ['resource', 'name', 'scope_type', 'scope', 'content' => [..]] */
    public $placeholders = array();

    private function addPlaceholder($resource, $name, $what)
    {
        $d = $this->currentDest;
        $k = $resource . "|" . ( $d instanceof Snippet ? 'snippet' : 'folder' ) . "|" . ( $d !== null ? $d->name() : '' ) . "|" . $name;
        if( !isset($this->placeholders[$k]) )
            $this->placeholders[$k] = array( 'resource' => $resource, 'name' => $name, 'scope_type' => $d instanceof Snippet ? 'snippet' : 'folder',
                'scope' => $d !== null ? $d->name() : null, 'content' => array() );
        $this->placeholders[$k]['content'][] = $what;
    }

    private function markPlaceholder(DOMElement $entry, $what)
    {
        $cur = $entry->getAttribute(self::PLACEHOLDER_ATTR);
        $entry->setAttribute(self::PLACEHOLDER_ATTR, $cur === '' ? $what : $cur . self::INCOMPLETE_SEP . $what);
    }

    /** marks a Panorama entry: this content is not imported (recorded per object when the entry is copied) */
    private function markIncomplete(DOMElement $entry, $what)
    {
        $cur = $entry->getAttribute(self::INCOMPLETE_ATTR);
        $entry->setAttribute(self::INCOMPLETE_ATTR, $cur === '' ? $what : $cur . self::INCOMPLETE_SEP . $what);
    }

    /** public API gaps removed from profiles, reported */
    public $apiGaps = array();


    /** rules -> profile group created / used, per scope (reported) */
    private $spgCreated = array();

    private function groupMember(DOMElement $grp, $tag)
    {
        $n = DH::findFirstElement($tag, $grp);
        if( $n === FALSE )
            return null;
        foreach( $n->childNodes as $m )
            if( $m->nodeType == XML_ELEMENT_NODE && trim($m->textContent) !== '' )
                return trim($m->textContent);
        return null;
    }

    /** profile entry of a type, searched in the device-group, its parents, then shared; null if not found (predefined) */
    private function findProfile(PanoramaConf $pano, $dg, $type, $name)
    {
        $xp = new DOMXPath($pano->xmldoc);
        $q = "profiles/" . $type . "/entry[@name=" . $this->xpathLiteral($name) . "]";
        for( $d = $dg; $d !== null; $d = $d->parentDeviceGroup )
            if( ($n = $xp->query($q, $d->xmlroot)->item(0)) !== null )
                return $n;
        $shared = DH::findFirstElement('shared', $pano->xmlroot);
        if( $shared !== FALSE && ($n = $xp->query($q, $shared)->item(0)) !== null )
            return $n;
        return null;
    }

    private $predefinedDoc = null;

    /** PAN-OS predefined profile (lib/object-classes/predefined.xml: virus / wildfire-analysis / spyware / vulnerability /
     *  url-filtering / file-blocking 'default', 'strict', 'basic file blocking' …); null if there is none */
    public function predefinedProfile($type, $name)
    {
        if( $this->predefinedDoc === null )
        {
            $this->predefinedDoc = new DOMDocument();
            $this->predefinedDoc->load(dirname(__FILE__) . "/../object-classes/predefined.xml", XML_PARSE_BIG_LINES);
        }
        $xp = new DOMXPath($this->predefinedDoc);
        foreach( $xp->query("//" . $type . "/entry[@name=" . $this->xpathLiteral($name) . "]") as $n )
            if( $n->parentNode->parentNode !== null && in_array($n->parentNode->parentNode->nodeName, array('profiles', 'predefined'), TRUE)
                || DH::findFirstElement('rules', $n) !== FALSE || DH::findFirstElement('decoder', $n) !== FALSE || $type == 'file-blocking' || $type == 'url-filtering' )
                return $n;
        return null;
    }

    private function xpathLiteral($s)
    {
        if( strpos($s, "'") === FALSE )
            return "'" . $s . "'";
        return 'concat("' . str_replace('"', '", \'"\', "', $s) . '")';
    }

    private function ensureVirusAndWildfire(PanoramaConf $pano, array $sc, $name, $av, $wf, array &$created)
    {
        $parent = DH::findFirstElementOrCreate('virus-and-wildfire-analysis', DH::findFirstElementOrCreate('profiles', $sc['node']));
        foreach( $parent->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->getAttribute('name') === $name )
                return;
        $doc = $pano->xmldoc;
        $entry = $doc->createElement('entry');
        $entry->setAttribute('name', $name);

        $wfNode = $wf !== null ? $this->findProfile($pano, $sc['dg'], 'wildfire-analysis', $wf) : null;
        if( $wf !== null && $wfNode === null && ($pre = $this->predefinedProfile('wildfire-analysis', $wf)) !== null )
        {
            $wfNode = $pre;
            $this->markPlaceholder($entry, "WildFire part: copy of the PAN-OS predefined WildFire profile '" . $wf . "'");
        }
        $rules = $wfNode !== null ? DH::findFirstElement('rules', $wfNode) : FALSE;
        if( $rules !== FALSE )
            $entry->appendChild($doc->importNode($rules, TRUE));
        elseif( $wf !== null && $wfNode === null )
        {
            // no WildFire profile in the group (or the predefined 'default'): forward all file types of all applications
            $r = DH::createElement( DH::createElement($entry, 'rules'), 'entry' );
            $r->setAttribute('name', 'default');
            DH::createElement( DH::createElement($r, 'application'), 'member', 'any' );
            DH::createElement( DH::createElement($r, 'file-type'), 'member', 'any' );
            DH::createElement($r, 'direction', 'both');
            DH::createElement($r, 'analysis', 'public-cloud');
            $this->warnings[] = $sc['label'] . ": WildFire profile '" . $wf . "' not in the configuration - '" . $name . "' uses the default rule (any / any / both / public-cloud)";
            $this->markPlaceholder($entry, "WildFire profile '" . $wf . "' not in the configuration and not PAN-OS predefined - content unknown, default rule any / any / both / public-cloud");
        }

        $avNode = $av !== null ? $this->findProfile($pano, $sc['dg'], 'virus', $av) : null;
        if( $av !== null && $avNode === null && ($pre = $this->predefinedProfile('virus', $av)) !== null )
        {
            $avNode = $pre;
            $this->markPlaceholder($entry, "antivirus part: copy of the PAN-OS predefined antivirus profile '" . $av . "'");
        }
        if( $avNode !== null )
        {
            // sections of the SCM virus-and-wildfire-analysis profile (internal UI API structure, HAR 2026-11-14);
            // decoder / inline ML / inline cloud analysis are completed through the internal UI API (step 4)
            foreach( array('decoder', 'mlav-engine-filebased-enabled', 'cloud-inline-analysis', 'mica-engine-wildfire-rules',
                         'threat-exception', 'mlav-exception', 'packet-capture') as $tag )
                if( ($n = DH::findFirstElement($tag, $avNode)) !== FALSE )
                    $entry->appendChild($doc->importNode($n, TRUE));
            if( DH::findFirstElement('application', $avNode) !== FALSE )
            {
                $this->warnings[] = $sc['label'] . ": '" . $name . "': application exceptions of antivirus profile '" . $av . "' not imported";
                $this->markIncomplete($entry, "application exceptions of antivirus profile '" . $av . "' not imported (no SCM field known)");
            }
        }
        elseif( $av !== null )
        {
            $this->warnings[] = $sc['label'] . ": antivirus profile '" . $av . "' not in the configuration - '" . $name . "' without antivirus part";
            $this->markPlaceholder($entry, "antivirus profile '" . $av . "' not in the configuration and not PAN-OS predefined - content unknown");
        }

        $parent->appendChild($entry);
        $created[$sc['label']][] = $name;
    }

    private function stacksOfTemplate(PanoramaConf $pano, $template)
    {
        $stacks = array();
        foreach( $pano->templatestacks as $stack )
            foreach( $stack->templates as $t )
                if( $t === $template )
                    $stacks[] = $stack;
        return $stacks;
    }

    // ------------------------------------------------------------------------------------------------
    // firewall
    // ------------------------------------------------------------------------------------------------

    /**
     * @param DOMDocument $doc PAN-OS firewall configuration
     * @param string $target 'folder' or 'snippet'
     * @param string|null $name name of the folder / snippet (default: hostname)
     * @param string $vsys
     * @param string|null $serial with a folder: the firewall is attached to it as a device
     */
    public function importFirewall(DOMDocument $doc, $target, $name = null, $vsys = 'vsys1', $serial = null)
    {
        $xp = new DOMXPath($doc);
        $base = "/config/devices/entry[@name='localhost.localdomain']";

        if( $name === null )
        {
            $host = $xp->query($base . "/deviceconfig/system/hostname")->item(0);
            $name = $host !== null && trim($host->textContent) !== "" ? trim($host->textContent) : "firewall";
        }
        $name = $this->validName($name, $target);

        $vsysNode = $xp->query($base . "/vsys/entry[@name='" . $vsys . "']")->item(0);
        if( $vsysNode === null )
            derr("vsys '" . $vsys . "' not found in the firewall configuration", null, FALSE);
        $others = array();
        foreach( $xp->query($base . "/vsys/entry") as $v )
            if( $v->getAttribute('name') !== $vsys )
                $others[] = $v->getAttribute('name');
        if( !empty($others) )
            $this->warnings[] = "multi-vsys firewall: only " . $vsys . " is imported, not " . implode(", ", $others);

        if( $target == 'folder' )
            $scope = $this->ensureFolder($name, $this->ensureFirewallFolder()->name());
        else
            $scope = $this->ensureSnippet($name, "firewall");

        // vsys first: in PAN-OS a vsys object hides a shared object of the same name
        $this->copyScope($vsysNode, $scope, $vsys, FALSE);
        $this->copyZones($vsysNode, $scope, $vsys);
        $shared = $xp->query("/config/shared")->item(0);
        if( $shared !== null )
            $this->copyScope($shared, $scope, "shared", FALSE);
        $deviceNode = $xp->query($base)->item(0);
        if( $deviceNode !== null )
            $this->copyZPP($deviceNode, $scope, "network");

        if( $serial !== null )
        {
            if( $target == 'folder' )
                $this->ensureDevice($serial, $scope->name(), array());
            else
                $this->warnings[] = "serial " . $serial . " ignored: a snippet has no devices";
        }
        $this->summary[$target == 'folder' ? 'folders' : 'snippets'] = 1;
    }

    // ------------------------------------------------------------------------------------------------
    // copy
    // ------------------------------------------------------------------------------------------------

    /**
     * objects and security rules of a Panorama shared / device-group (rulebase pre / post)
     * or of a firewall vsys / shared (rulebase -> pre-rulebase)
     */
    private function copyScope(DOMElement $src, $dest, $label, $panorama)
    {
        foreach( self::$objectPaths as $rel )
            $this->copyEntries($src, $rel, $dest, $rel, $label);

        if( $panorama )
        {
            $this->copyEntries($src, 'pre-rulebase/security/rules', $dest, 'pre-rulebase/security/rules', $label);
            $this->copyEntries($src, 'post-rulebase/security/rules', $dest, 'post-rulebase/security/rules', $label);
        }
        else
            $this->copyEntries($src, 'rulebase/security/rules', $dest, 'pre-rulebase/security/rules', $label);

        $this->reportNotImported($src, $label);
    }

    /** template / template-stack <config>: zones and objects of vsys1, shared objects, zone protection profiles */
    private function copyNetworkScope(DOMElement $config, $dest, $label)
    {
        $xp = new DOMXPath($config->ownerDocument);
        foreach( $xp->query("devices/entry/vsys/entry", $config) as $vsys )
        {
            /** @var DOMElement $vsys */
            if( $vsys->getAttribute('name') !== 'vsys1' )
            {
                $this->warnings[] = $label . ": only vsys1 is imported, not " . $vsys->getAttribute('name');
                continue;
            }
            $this->copyZones($vsys, $dest, $label);
            foreach( self::$objectPaths as $rel )
                $this->copyEntries($vsys, $rel, $dest, $rel, $label);
        }
        $shared = DH::findFirstElement('shared', $config);
        if( $shared !== FALSE )
            foreach( self::$objectPaths as $rel )
                $this->copyEntries($shared, $rel, $dest, $rel, $label . " shared");
        foreach( $xp->query("devices/entry", $config) as $dev )
            $this->copyZPP($dev, $dest, $label);
    }

    private function copyZones(DOMElement $vsys, $dest, $label)
    {
        $this->copyEntries($vsys, 'zone', $dest, 'zone', $label);
    }

    private function copyZPP(DOMElement $deviceEntry, $dest, $label)
    {
        $this->copyEntries($deviceEntry, 'network/profiles/zone-protection-profile', $dest,
            'devices/entry/network/profiles/zone-protection-profiles', $label);
    }

    private function copyEntries(DOMElement $src, $srcRel, $dest, $destRel, $label)
    {
        $xp = new DOMXPath($src->ownerDocument);
        $nodes = $xp->query($srcRel . "/entry", $src);
        if( $nodes->length == 0 )
            return 0;

        $parent = $this->ensurePath($dest->xmlroot, $destRel);
        $existing = array();
        foreach( $parent->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE && $c->tagName == 'entry' )
                $existing[$c->getAttribute('name')] = TRUE;

        $resource = SCMChangeGenerator::$resourcePaths[$destRel] ?? $destRel;
        $copied = 0;
        $skipped = array();
        foreach( $nodes as $node )
        {
            /** @var DOMElement $node */
            $name = $node->getAttribute('name');
            if( isset($existing[$name]) )
            {
                $skipped[] = $name;
                continue;
            }
            $new = $parent->ownerDocument->importNode($node, TRUE);
            $this->currentDest = $dest;
            $this->cleanEntry($new, $resource, $label);
            $parent->appendChild($new);
            $existing[$name] = TRUE;
            $copied++;
        }
        if( !empty($skipped) )
            $this->warnings[] = $label . ": " . $resource . " already in " . $this->scopeLabel($dest) . ", not copied: " . implode(", ", $skipped);

        $this->summary['objects'][$resource] = ($this->summary['objects'][$resource] ?? 0) + $copied;
        return $copied;
    }

    /**
     * PAN-OS fields without an SCM counterpart that carry no configuration of their own are removed,
     * so they do not mark the request for review. Anything else stays and is checked by type=scm-changes.
     */
    private function cleanEntry(DOMElement $entry, $resource, $label)
    {
        // Panorama / PAN-OS uuids are not SCM ids
        $this->removeUuids($entry);

        // complete profile for the internal UI API (prepareSecurityProfiles)
        if( $entry->hasAttribute(self::INTERNAL_ATTR) )
        {
            $d = $this->currentDest;
            $in = json_decode($entry->getAttribute(self::INTERNAL_ATTR), TRUE);
            $this->internal[] = array( 'resource' => $resource, 'name' => $entry->getAttribute('name'),
                'scope_type' => $d instanceof Snippet ? 'snippet' : 'folder', 'scope' => $d !== null ? $d->name() : null,
                'prefix' => $in['prefix'], 'entry' => $in['entry'] );
            $entry->removeAttribute(self::INTERNAL_ATTR);
        }

        if( $entry->hasAttribute(self::PLACEHOLDER_ATTR) )
        {
            $d = $this->currentDest;
            $k = $resource . "|" . ( $d instanceof Snippet ? 'snippet' : 'folder' ) . "|" . ( $d !== null ? $d->name() : '' ) . "|" . $entry->getAttribute('name');
            $this->placeholders[$k] = array( 'resource' => $resource, 'name' => $entry->getAttribute('name'),
                'scope_type' => $d instanceof Snippet ? 'snippet' : 'folder', 'scope' => $d !== null ? $d->name() : null,
                'content' => explode(self::INCOMPLETE_SEP, $entry->getAttribute(self::PLACEHOLDER_ATTR)) );
            $entry->removeAttribute(self::PLACEHOLDER_ATTR);
        }

        // content removed while the profiles were prepared for SCM (prepareSecurityProfiles)
        if( $entry->hasAttribute(self::INCOMPLETE_ATTR) )
        {
            foreach( explode(self::INCOMPLETE_SEP, $entry->getAttribute(self::INCOMPLETE_ATTR)) as $what )
                $this->addIncomplete($resource, $entry->getAttribute('name'), $what);
            $entry->removeAttribute(self::INCOMPLETE_ATTR);
        }

        if( $resource == 'security-rules' )
        {
            $target = DH::findFirstElement('target', $entry);
            if( $target !== FALSE )
            {
                $devices = DH::findFirstElement('devices', $target);
                $hasDevices = $devices !== FALSE && DH::firstChildElement($devices) !== FALSE;
                $negate = DH::findFirstElement('negate', $target);
                $negated = $negate !== FALSE && trim($negate->textContent) == 'yes';
                if( !$hasDevices && !$negated )
                    $entry->removeChild($target);
                else
                {
                    $this->warnings[] = $label . ": rule '" . $entry->getAttribute('name') . "' has a target (firewalls); SCM rules have no target";
                    $this->addIncomplete($resource, $entry->getAttribute('name'), "target (firewalls) - SCM rules have no target, review");
                }
            }
            // <profile-setting><group/></profile-setting>: no profile (PAN-OS) - SCM refuses an empty group
            $ps = DH::findFirstElement('profile-setting', $entry);
            if( $ps !== FALSE )
            {
                $hasMember = FALSE;
                foreach( $ps->getElementsByTagName('member') as $m )
                    if( trim($m->textContent) !== '' )
                        $hasMember = TRUE;
                if( !$hasMember )
                    $entry->removeChild($ps);
            }
            // display grouping of the rule list, no SCM field
            $groupTag = DH::findFirstElement('group-tag', $entry);
            if( $groupTag !== FALSE )
            {
                $this->groupTags[trim($groupTag->textContent)] = TRUE;
                $this->addIncomplete($resource, $entry->getAttribute('name'), "group_tag '" . trim($groupTag->textContent) . "' not imported (no SCM field)");
                $entry->removeChild($groupTag);
            }
            // SaaS user / tenant lists with only 'any' are the PAN-OS default (no condition)
            foreach( array('saas-user-list', 'saas-tenant-list') as $tag )
            {
                $node = DH::findFirstElement($tag, $entry);
                if( $node === FALSE )
                    continue;
                $members = array();
                foreach( $node->childNodes as $m )
                    if( $m->nodeType == XML_ELEMENT_NODE )
                        $members[] = trim($m->textContent);
                if( empty($members) || $members == array('any') )
                    $entry->removeChild($node);
            }

            $ruleType = DH::findFirstElement('rule-type', $entry);
            if( $ruleType !== FALSE && trim($ruleType->textContent) == 'universal' )
                $entry->removeChild($ruleType);

            // PAN-OS before 10.0: <hip-profiles> is the source HIP of the rule ('any' = no condition)
            $hip = DH::findFirstElement('hip-profiles', $entry);
            if( $hip !== FALSE )
            {
                $members = array();
                foreach( $hip->childNodes as $m )
                    if( $m->nodeType == XML_ELEMENT_NODE )
                        $members[] = trim($m->textContent);
                if( empty($members) || $members == array('any') || DH::findFirstElement('source-hip', $entry) !== FALSE )
                    $entry->removeChild($hip);
                else
                {
                    $sourceHip = $entry->ownerDocument->createElement('source-hip');
                    foreach( $members as $name )
                        DH::createElement($sourceHip, 'member', $name);
                    $entry->replaceChild($sourceHip, $hip);
                }
            }
        }

        if( $resource == 'zone-protection-profiles' )
        {
            foreach( iterator_to_array($entry->childNodes) as $c )
            {
                if( $c->nodeType != XML_ELEMENT_NODE || !isset(self::$zppFieldNames[$c->tagName]) )
                    continue;
                $renamed = $entry->ownerDocument->createElement(self::$zppFieldNames[$c->tagName]);
                foreach( iterator_to_array($c->childNodes) as $cc )
                    $renamed->appendChild($cc);
                $entry->replaceChild($renamed, $c);
            }
        }

        // custom URL category without entries: SCM refuses an empty list - placeholder entry empty.empty (as the SCM UI accepts it, HAR 2026-11-14)
        if( $resource == 'url-categories' )
        {
            $type = DH::findFirstElement('type', $entry);
            $isList = $type === FALSE || trim($type->textContent) == 'URL List';
            $list = DH::findFirstElement('list', $entry);
            $members = $list === FALSE ? 0 : $list->getElementsByTagName('member')->length;
            if( $isList && $members == 0 )
            {
                if( $list === FALSE )
                    $list = DH::createElement($entry, 'list');
                DH::createElement($list, 'member', 'empty.empty');
                $this->addPlaceholder($resource, $entry->getAttribute('name'), "custom URL category without entries (SCM refuses an empty list): placeholder entry 'empty.empty'");
            }
        }

        if( $resource == 'zones' && $this->interfaceVariables )
        {
            $network = DH::findFirstElement('network', $entry);
            if( $network !== FALSE )
                foreach( array('layer3', 'layer2', 'virtual-wire', 'tap', 'tunnel', 'external') as $type )
                {
                    $node = DH::findFirstElement($type, $network);
                    if( $node === FALSE )
                        continue;
                    foreach( $node->childNodes as $m )
                        if( $m->nodeType == XML_ELEMENT_NODE )
                            $m->nodeValue = self::interfaceVariable($m->textContent);
                }
        }
        elseif( $resource == 'zones' && !$this->keepZoneInterfaces )
        {
            $network = DH::findFirstElement('network', $entry);
            if( $network !== FALSE )
            {
                $removed = array();
                foreach( array('layer3', 'layer2', 'virtual-wire', 'tap', 'tunnel', 'external') as $type )
                {
                    $node = DH::findFirstElement($type, $network);
                    if( $node === FALSE )
                        continue;
                    foreach( iterator_to_array($node->childNodes) as $m )
                        if( $m->nodeType == XML_ELEMENT_NODE )
                        {
                            $removed[] = $m->textContent;
                            $node->removeChild($m);
                        }
                }
                if( !empty($removed) )
                {
                    $this->warnings[] = $label . ": zone '" . $entry->getAttribute('name') . "' interfaces not imported: " . implode(", ", $removed);
                    $this->addIncomplete($resource, $entry->getAttribute('name'), "interfaces not imported: " . implode(", ", $removed) . " (device variables per firewall - next step)");
                }
            }
        }
    }

    private function removeUuids(DOMElement $node)
    {
        if( $node->hasAttribute('uuid') )
            $node->removeAttribute('uuid');
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                $this->removeUuids($c);
    }

    private function reportNotImported(DOMElement $src, $label)
    {
        $xp = new DOMXPath($src->ownerDocument);
        $parts = array();
        foreach( self::$notImported as $rel => $what )
        {
            if( $this->scmProfiles && in_array($rel, array('profiles/virus', 'profiles/wildfire-analysis'), TRUE) )
                continue;
            if( $this->customApplicationsElsewhere && $rel == 'application' )
                continue;
            $n = $xp->query($rel . "/entry", $src)->length;
            if( $n > 0 )
                $parts[] = $n . " " . $what;
        }
        if( !empty($parts) )
            $this->warnings[] = $label . ": not imported: " . implode(", ", $parts);
    }

    // ------------------------------------------------------------------------------------------------
    // folders / snippets / devices
    // ------------------------------------------------------------------------------------------------

    private function ensureFirewallFolder()
    {
        $folder = $this->scm->findContainer($this->firewallFolder);
        if( $folder === null )
            $folder = $this->scm->createContainer($this->firewallFolder, "All");
        return $folder;
    }

    private function ensureFolder($name, $parent)
    {
        $folder = $this->scm->findContainer($name);
        if( $folder !== null )
        {
            $this->warnings[] = "folder '" . $name . "' exists in SCM already: objects are added to it, existing names are kept";
            return $folder;
        }
        if( $this->scm->findSnippet($name) !== null )
            $this->warnings[] = "folder '" . $name . "' has the name of a snippet";
        return $this->scm->createContainer($name, $parent);
    }

    private function ensureSnippet($name, $key)
    {
        $snippet = $this->scm->findSnippet($name);
        if( $snippet !== null )
            $this->warnings[] = "snippet '" . $name . "' exists in SCM already: objects are added to it, existing names are kept";
        else
            $snippet = $this->scm->createSnippet($name);
        $this->snippetNames[$key] = $snippet->name();
        return $snippet;
    }

    private function ensureDevice($serial, $folderName, array $snippetNames)
    {
        $device = $this->scm->findDeviceOnPrem($serial);
        if( $device === null )
            $device = $this->scm->createDeviceOnPrem($serial, $folderName);
        else
        {
            $this->warnings[] = "device " . $serial . " exists in SCM already: folder set to '" . $folderName . "'";
            $parentNode = DH::findFirstElementOrCreate('parent', $device->xmlroot);
            DH::setDomNodeText($parentNode, $folderName);
        }
        foreach( $snippetNames as $s )
            $device->addSnippet($this->scm->findSnippet($s));
        return $device;
    }

    private function hasChildFolder(Container $folder)
    {
        foreach( $this->scm->getContainers() as $c )
        {
            $p = DH::findFirstElement('parent', $c->xmlroot);
            if( $p !== FALSE && $p->textContent === $folder->name() )
                return TRUE;
        }
        return FALSE;
    }

    /** SCM folder / snippet names: [a-zA-Z0-9 ._-], at most 64 characters */
    private function validName($name, $what)
    {
        $valid = preg_replace('/[^a-zA-Z0-9 ._\-]/', '_', $name);
        if( strlen($valid) > 64 )
            $valid = substr($valid, 0, 64);
        if( $valid !== $name )
            $this->warnings[] = $what . " '" . $name . "' is named '" . $valid . "' in SCM (allowed: letters, digits, space . _ -, at most 64 characters)";
        return $valid;
    }

    private function scopeLabel($scope)
    {
        return strtolower(get_class($scope) == 'Container' ? 'folder' : get_class($scope)) . " '" . $scope->name() . "'";
    }

    /** create the path below an SCM folder / snippet entry; "entry" steps without name use the first entry */
    private function ensurePath(DOMElement $root, $rel)
    {
        $node = $root;
        foreach( explode('/', $rel) as $step )
        {
            $found = FALSE;
            foreach( $node->childNodes as $c )
                if( $c->nodeType == XML_ELEMENT_NODE && $c->tagName == $step )
                {
                    $found = $c;
                    break;
                }
            if( $found === FALSE )
            {
                $found = $node->ownerDocument->createElement($step);
                $node->appendChild($found);
            }
            $node = $found;
        }
        return $node;
    }
}
