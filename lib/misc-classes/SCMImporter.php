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
    public $firewallFolder = self::FIREWALL_FOLDER;

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
     * @param string $sharedMode 'snippet' (default) or 'global'
     * @param string $sharedSnippet name of the snippet for shared
     */
    public function importPanorama(PanoramaConf $pano, $sharedMode = 'snippet', $sharedSnippet = 'Panorama-Shared')
    {
        $xp = new DOMXPath($pano->xmldoc);
        $all = $this->scm->findContainer("All");
        $fwFolder = $this->ensureFirewallFolder();

        // shared
        $shared = $xp->query("/config/shared")->item(0);
        if( $shared !== null )
        {
            if( $sharedMode == 'global' )
                $target = $all;
            else
            {
                $target = $this->ensureSnippet($this->validName($sharedSnippet, "shared snippet"), "shared");
                $all->addSnippet($target);
            }
            $this->copyScope($shared, $target, "Panorama shared", TRUE);
        }

        // device-groups, parents first
        $dgFolders = array();
        $pending = $pano->deviceGroups;
        while( !empty($pending) )
        {
            $progress = FALSE;
            foreach( $pending as $i => $dg )
            {
                /** @var DeviceGroup $dg */
                $parentDG = $dg->parentDeviceGroup;
                if( $parentDG !== null && !isset($dgFolders[$parentDG->name()]) )
                    continue;
                $parentName = $parentDG === null ? $fwFolder->name() : $dgFolders[$parentDG->name()]->name();
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
                    $this->warnings[] = $label . ": rule '" . $entry->getAttribute('name') . "' has a target (firewalls); SCM rules have no target";
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

        if( $resource == 'zones' && !$this->keepZoneInterfaces )
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
                    $this->warnings[] = $label . ": zone '" . $entry->getAttribute('name') . "' interfaces not imported: " . implode(", ", $removed);
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
