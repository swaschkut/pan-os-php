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
 * Translates the difference between two SCM configurations (XML as written by pan-os-php for in=scm-api://)
 * into Strata Cloud Manager API requests.
 *
 * The XML is the original download (file1) and the same configuration after pan-os-php changed it (file2),
 * e.g. by a playbook. For every object that was added, changed or deleted, one request is produced:
 *
 *   POST   <path>          new object, full body incl. folder / snippet / device
 *   PUT    <path>/<id>     changed object, "merge": true, body holds only the changed top-level fields
 *   DELETE <path>/<id>     deleted object
 *
 * A PUT in SCM replaces the whole object, while the XML does not hold every field SCM returns
 * (e.g. the description of security profiles is not imported). The sender therefore reads the live
 * object (GET <path>/<id>), applies the changed fields of "body" (null removes a field) and sends that.
 *
 * Bodies are built and checked against the official SCM OpenAPI request schema
 * (lib/resources/scm/scm-ngfw-config-schema.json). A field the schema does not know is not sent;
 * if such a field carries configuration, the request is marked "review": true with a warning,
 * because sending it without that field would not do what the change intended.
 */
class SCMChangeGenerator
{
    const FORMAT = "pan-os-php-scm-changes";
    const VERSION = 1;

    /** XML path below a folder / snippet / device entry => SCM resource */
    static public $resourcePaths = array(
        'tag' => 'tags',
        'address' => 'addresses',
        'address-group' => 'address-groups',
        'service' => 'services',
        'service-group' => 'service-groups',
        'schedule' => 'schedules',
        'log-settings/profiles' => 'log-forwarding-profiles',
        'profiles/custom-url-category' => 'url-categories',
        'profiles/spyware' => 'anti-spyware-profiles',
        'profiles/vulnerability' => 'vulnerability-protection-profiles',
        'profiles/virus-and-wildfire-analysis' => 'wildfire-anti-virus-profiles',
        'profiles/url-filtering' => 'url-access-profiles',
        'profiles/file-blocking' => 'file-blocking-profiles',
        'profiles/dns-security' => 'dns-security-profiles',
        'profile-group' => 'profile-groups',
        'devices/entry/network/profiles/zone-protection-profiles' => 'zone-protection-profiles',
        'devices/entry/network/profiles/zone-protection-profile' => 'zone-protection-profiles',
        'zone' => 'zones',
        'pre-rulebase/security/rules' => 'security-rules',
        'post-rulebase/security/rules' => 'security-rules',
    );

    /** PAN-OS paths that exist in the XML but have no SCM resource of their own */
    static public $unsupportedPaths = array(
        'profiles/virus' => 'SCM combines antivirus and WildFire in wildfire-anti-virus-profiles',
        'profiles/wildfire-analysis' => 'SCM combines antivirus and WildFire in wildfire-anti-virus-profiles',
    );

    /** order of POST / PUT (referenced objects first); DELETE runs in reverse order */
    static public $resourceRank = array(
        'tags' => 10, 'addresses' => 20, 'address-groups' => 30, 'services' => 40, 'service-groups' => 50,
        'schedules' => 55, 'log-forwarding-profiles' => 60, 'url-categories' => 65,
        'anti-spyware-profiles' => 70, 'vulnerability-protection-profiles' => 70, 'wildfire-anti-virus-profiles' => 70,
        'url-access-profiles' => 70, 'file-blocking-profiles' => 70, 'dns-security-profiles' => 70,
        'profile-groups' => 80, 'zone-protection-profiles' => 85, 'zones' => 90, 'security-rules' => 100,
    );

    /** XML children pan-os-php writes by default that have no SCM field and carry no configuration of their own */
    static public $ignoredFields = array(
        'security-rules' => array('option'),
    );

    /** fields of a body that name other objects; used to order requests and to pass on "review" */
    static public $references = array(
        'profile-groups' => array(
            'spyware' => 'anti-spyware-profiles', 'vulnerability' => 'vulnerability-protection-profiles',
            'virus_and_wildfire_analysis' => 'wildfire-anti-virus-profiles', 'url_filtering' => 'url-access-profiles',
            'file_blocking' => 'file-blocking-profiles', 'dns_security' => 'dns-security-profiles'),
        'security-rules' => array('profile_setting.group' => 'profile-groups', 'log_setting' => 'log-forwarding-profiles'),
        'zones' => array('network.zone_protection_profile' => 'zone-protection-profiles', 'network.log_setting' => 'log-forwarding-profiles'),
        'url-access-profiles' => array('alert' => 'url-categories', 'allow' => 'url-categories', 'block' => 'url-categories',
            'continue' => 'url-categories'),
    );

    public $schema = array();
    public $schemaSource = "";
    public $apiBase = "https://api.strata.paloaltonetworks.com";

    public $requests = array();
    public $warnings = array();
    /** resource => name => TRUE, every object of file2 in any folder / snippet / device */
    public $existing = array();
    public $file1 = null;
    public $file2 = null;

    public function __construct($schemaFile = null)
    {
        if( $schemaFile === null )
            $schemaFile = dirname(__FILE__) . "/../resources/scm/scm-ngfw-config-schema.json";

        $data = json_decode(file_get_contents($schemaFile), TRUE);
        if( !is_array($data) || !isset($data['resources']) )
            derr("SCM schema file '" . $schemaFile . "' could not be read", null, FALSE);

        $this->schema = $data['resources'];
        $this->schemaSource = $data['source'] ?? "";
        if( isset($data['api_base']) )
            $this->apiBase = $data['api_base'];
    }

    // ------------------------------------------------------------------------------------------------
    // main
    // ------------------------------------------------------------------------------------------------

    /**
     * @param DOMDocument $orig configuration as downloaded from SCM (file1)
     * @param DOMDocument $new same configuration after the changes (file2)
     * @return array change document, see toJSON()
     */
    public function run(DOMDocument $orig, DOMDocument $new)
    {
        $this->requests = array();
        $this->warnings = array();

        $origScopes = $this->collectScopes($orig);
        $newScopes = $this->collectScopes($new);

        $origObjects = array();
        $newObjects = array();
        foreach( $origScopes as $key => $scope )
            $origObjects += $this->collectObjects($scope);
        foreach( $newScopes as $key => $scope )
            $newObjects += $this->collectObjects($scope);

        $this->existing = array();
        foreach( $newObjects as $obj )
            $this->existing[$obj['resource']][$obj['name']] = TRUE;

        // an object is the same object when its SCM id matches (renamed objects), otherwise when its name matches
        $origByUuid = array();
        foreach( $origObjects as $key => $obj )
            if( $obj['uuid'] !== null )
                $origByUuid[$obj['resource'] . "|" . $obj['uuid']] = $key;

        $matched = array();
        foreach( $newObjects as $key => $obj )
        {
            $origKey = null;
            if( $obj['uuid'] !== null && isset($origByUuid[$obj['resource'] . "|" . $obj['uuid']]) )
                $origKey = $origByUuid[$obj['resource'] . "|" . $obj['uuid']];
            elseif( isset($origObjects[$key]) && !isset($matched[$key]) )
                $origKey = $key;

            if( $origKey === null || isset($matched[$origKey]) )
                $this->addCreate($obj);
            else
            {
                $matched[$origKey] = TRUE;
                $this->addUpdate($origObjects[$origKey], $obj);
            }
        }
        foreach( $origObjects as $key => $obj )
        {
            if( !isset($matched[$key]) )
                $this->addDelete($obj);
        }

        foreach( $newScopes as $key => $scope )
        {
            if( isset($origScopes[$key]) )
                $this->checkUntranslatedChanges($origScopes[$key], $scope);
            else
                $this->warnings[] = "new " . $scope['scope_type'] . " '" . $scope['scope'] . "': creating folders, snippets or devices is not supported, its objects are sent";
        }
        foreach( $origScopes as $key => $scope )
            if( !isset($newScopes[$key]) )
                $this->warnings[] = $scope['scope_type'] . " '" . $scope['scope'] . "' was removed: deleting folders, snippets or devices is not supported";

        $this->sortRequests();
        $this->resolveDependencies();

        return $this->result();
    }

    public function result()
    {
        $summary = array('POST' => 0, 'PUT' => 0, 'DELETE' => 0, 'review' => 0);
        foreach( $this->requests as $r )
        {
            $summary[$r['method']]++;
            if( $r['review'] )
                $summary['review']++;
        }

        return array(
            'format' => self::FORMAT,
            'version' => self::VERSION,
            'generated' => date('c'),
            'generator' => "pan-os-php " . PH::frameworkVersion() . " type=scm-changes",
            'source' => array('file1' => $this->file1, 'file2' => $this->file2),
            'api_base' => $this->apiBase,
            'schema_source' => $this->schemaSource,
            'notes' => array(
                "PUT requests carry \"merge\": true: GET the object, apply the fields of body (null removes a field), PUT the result.",
                "Requests with \"review\": true could not be translated completely; see their warnings.",
                "Changes go to the SCM candidate configuration; pushing it is a separate step.",
            ),
            'summary' => $summary,
            'warnings' => $this->warnings,
            'requests' => array_values($this->requests),
        );
    }

    public function toJSON()
    {
        return json_encode($this->result(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    }

    // ------------------------------------------------------------------------------------------------
    // collect folders / snippets / devices and their objects
    // ------------------------------------------------------------------------------------------------

    private function collectScopes(DOMDocument $doc)
    {
        $xp = new DOMXPath($doc);
        $base = "/config/devices/entry[@name='localhost.localdomain']";
        $scopes = array();
        $types = array(
            'folder' => "container/entry",
            'snippet' => "snippet/entry",
            'device' => "device/on-prem/entry|$base/device/cloud/entry",
        );
        foreach( $types as $scopeType => $rel )
        {
            $nodes = $xp->query("$base/" . $rel);
            foreach( $nodes as $node )
            {
                /** @var DOMElement $node */
                $name = $node->getAttribute('name');
                $scopes[$scopeType . "|" . $name] = array(
                    'scope_type' => $scopeType, 'scope' => $name, 'node' => $node, 'xpath' => $this->xpathOf($node));
            }
        }
        return $scopes;
    }

    private function collectObjects(array $scope)
    {
        $objects = array();
        $xp = new DOMXPath($scope['node']->ownerDocument);
        foreach( self::$resourcePaths as $rel => $resource )
        {
            foreach( $xp->query($rel . "/entry", $scope['node']) as $node )
            {
                /** @var DOMElement $node */
                $name = $node->getAttribute('name');
                $position = null;
                if( $resource == 'security-rules' )
                    $position = strpos($rel, 'post-') === 0 ? 'post' : 'pre';

                // one name per resource and location (pre and post rules share the name space)
                $key = $scope['scope_type'] . "|" . $scope['scope'] . "|" . $resource . "|" . $name;
                $objects[$key] = array(
                    'resource' => $resource,
                    'name' => $name,
                    'scope_type' => $scope['scope_type'],
                    'scope' => $scope['scope'],
                    'position' => $position,
                    'uuid' => $node->hasAttribute('uuid') ? $node->getAttribute('uuid') : null,
                    'node' => $node,
                    'xpath' => $this->xpathOf($node),
                );
            }
        }
        return $objects;
    }

    /**
     * Changes inside a folder / snippet / device that are not part of an object of a known resource
     * cannot be sent; report them so they are not lost silently.
     */
    private function checkUntranslatedChanges(array $origScope, array $newScope)
    {
        $a = $this->stripObjects($origScope['node']);
        $b = $this->stripObjects($newScope['node']);

        $childrenA = $this->childMap($a);
        $childrenB = $this->childMap($b);
        $tags = array_unique(array_merge(array_keys($childrenA), array_keys($childrenB)));
        sort($tags);
        foreach( $tags as $tag )
        {
            $ca = $childrenA[$tag] ?? "";
            $cb = $childrenB[$tag] ?? "";
            if( $ca === $cb )
                continue;

            $reason = "";
            foreach( self::$unsupportedPaths as $rel => $why )
                if( strpos($rel, $tag . "/") === 0 || $rel === $tag )
                    $reason = " (" . $why . ")";

            $this->warnings[] = $newScope['scope_type'] . " '" . $newScope['scope'] . "': changes below <" . $tag . "> are not translated to SCM API requests" . $reason;
        }
    }

    private function stripObjects(DOMElement $scopeNode)
    {
        $doc = new DOMDocument();
        $clone = $doc->importNode($scopeNode, TRUE);
        $doc->appendChild($clone);
        $xp = new DOMXPath($doc);
        foreach( array_keys(self::$resourcePaths) as $rel )
            foreach( $xp->query("/entry/" . $rel . "/entry") as $n )
                $n->parentNode->removeChild($n);
        $this->removeEmptyElements($clone);
        return $clone;
    }

    /** containers left empty once the objects are taken out (e.g. <profile-group/>) are no change */
    private function removeEmptyElements(DOMElement $node)
    {
        for( $i = $node->childNodes->length - 1; $i >= 0; $i-- )
        {
            $c = $node->childNodes->item($i);
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            $this->removeEmptyElements($c);
            if( $c->attributes->length == 0 && trim($c->textContent) === "" && !$this->hasElementChild($c) )
                $node->removeChild($c);
        }
    }

    private function hasElementChild(DOMElement $node)
    {
        foreach( $node->childNodes as $c )
            if( $c->nodeType == XML_ELEMENT_NODE )
                return TRUE;
        return FALSE;
    }

    private function childMap(DOMElement $node)
    {
        $map = array();
        foreach( $node->childNodes as $c )
        {
            if( $c->nodeType != XML_ELEMENT_NODE )
                continue;
            if( $c->tagName == 'snippets' )
            {
                // attached snippets as a set; pan-os-php attaches predefined-snippet itself when it loads the XML
                $names = array();
                foreach( $c->childNodes as $m )
                    if( $m->nodeType == XML_ELEMENT_NODE && $m->textContent !== 'predefined-snippet' )
                        $names[$m->textContent] = TRUE;
                ksort($names);
                if( !empty($names) )
                    $map['snippets'] = implode(",", array_keys($names));
                continue;
            }
            $map[$c->tagName] = ($map[$c->tagName] ?? "") . $this->canonical($c);
        }
        return $map;
    }

    // ------------------------------------------------------------------------------------------------
    // requests
    // ------------------------------------------------------------------------------------------------

    private function newRequest($method, array $obj)
    {
        $res = $this->schema[$obj['resource']];
        $lookup = array('name' => $obj['name'], $obj['scope_type'] => $obj['scope']);
        if( $obj['position'] !== null )
            $lookup['position'] = $obj['position'];

        return array(
            'seq' => 0,
            'method' => $method,
            'path' => $method == 'POST' ? $res['path'] : $res['path'] . "/" . ($obj['uuid'] ?? "{id}"),
            'id' => $method == 'POST' ? null : $obj['uuid'],
            'query' => new stdClass(),
            'merge' => FALSE,
            'body' => new stdClass(),
            'before' => null,
            'object' => array(
                'resource' => $obj['resource'],
                'name' => $obj['name'],
                'scope_type' => $obj['scope_type'],
                'scope' => $obj['scope'],
                'position' => $obj['position'],
                'xpath' => $obj['xpath'],
            ),
            'lookup' => $lookup,
            'depends_on' => array(),
            'review' => FALSE,
            'warnings' => array(),
        );
    }

    private function addCreate(array $obj)
    {
        $r = $this->newRequest('POST', $obj);
        $dropped = array();
        $body = $this->toBody($obj, $dropped);
        unset($body['id']);

        $ordered = array('name' => $obj['name'], $obj['scope_type'] => $obj['scope']);
        foreach( $body as $k => $v )
            if( !isset($ordered[$k]) )
                $ordered[$k] = $v;
        $r['body'] = $ordered;

        if( $obj['resource'] == 'security-rules' )
            $r['query'] = array('position' => $obj['position']);

        $this->addDroppedWarnings($r, $dropped, TRUE);
        $this->checkScope($r, $obj);
        $this->requests[] = $r;
    }

    private function addUpdate(array $old, array $new)
    {
        $droppedOld = array();
        $droppedNew = array();
        $a = $this->toBody($old, $droppedOld);
        $b = $this->toBody($new, $droppedNew);

        $changed = array();
        $before = array();
        if( $old['name'] !== $new['name'] )
        {
            $changed['name'] = $new['name'];
            $before['name'] = $old['name'];
        }
        $keys = array_unique(array_merge(array_keys($a), array_keys($b)));
        foreach( $keys as $k )
        {
            if( in_array($k, array('id', 'name', 'folder', 'snippet', 'device')) )
                continue;
            $va = array_key_exists($k, $a) ? json_encode($a[$k]) : null;
            $vb = array_key_exists($k, $b) ? json_encode($b[$k]) : null;
            if( $va === $vb )
                continue;
            $changed[$k] = array_key_exists($k, $b) ? $b[$k] : null;
            $before[$k] = array_key_exists($k, $a) ? $a[$k] : null;
        }

        // dropped fields only matter where they changed
        $droppedChanged = array_diff($droppedNew, $droppedOld);

        if( empty($changed) && empty($droppedChanged) )
        {
            if( $this->canonical($old['node']) !== $this->canonical($new['node']) )
                $this->warnings[] = $new['resource'] . " '" . $new['name'] . "' (" . $new['scope_type'] . " '" . $new['scope'] . "'): changed only in fields SCM does not have, no request";
            return;
        }

        $r = $this->newRequest('PUT', $new);
        $r['merge'] = TRUE;
        $r['body'] = empty($changed) ? new stdClass() : $changed;
        $r['before'] = empty($before) ? new stdClass() : $before;

        if( $new['uuid'] === null )
            $r['warnings'][] = "no SCM id in the XML: resolve the object by name (see lookup)";
        if( $old['uuid'] !== null && $new['uuid'] !== null && $old['uuid'] !== $new['uuid'] )
            $r['warnings'][] = "SCM id differs between file1 (" . $old['uuid'] . ") and file2 (" . $new['uuid'] . ")";
        if( $old['position'] !== $new['position'] )
            $r['warnings'][] = "rule moved from " . $old['position'] . " to " . $new['position'] . " rulebase: moving rules is not translated";

        $this->addDroppedWarnings($r, $droppedChanged, TRUE);
        if( empty($changed) )
        {
            $r['review'] = TRUE;
            $r['warnings'][] = "all changed fields are unknown to SCM";
        }
        $this->checkScope($r, $new);
        $this->requests[] = $r;
    }

    private function addDelete(array $obj)
    {
        $r = $this->newRequest('DELETE', $obj);
        $r['body'] = null;
        if( $obj['uuid'] === null )
            $r['warnings'][] = "no SCM id in the XML: resolve the object by name (see lookup)";
        $this->checkScope($r, $obj);
        $this->requests[] = $r;
    }

    private function addDroppedWarnings(array &$r, array $dropped, $review)
    {
        if( empty($dropped) )
            return;
        $dropped = array_values(array_unique($dropped));
        $r['warnings'][] = "not sent, unknown to the SCM schema of " . $r['object']['resource'] . ": " . implode(", ", $dropped);
        if( $review )
            $r['review'] = TRUE;
    }

    private function checkScope(array &$r, array $obj)
    {
        if( $obj['scope_type'] == 'snippet' && $obj['scope'] == 'predefined-snippet' )
        {
            $r['review'] = TRUE;
            $r['warnings'][] = "object of the predefined snippet: it cannot be changed through the API";
        }
    }

    private function sortRequests()
    {
        $methodRank = array('POST' => 1, 'PUT' => 2, 'DELETE' => 3);
        usort($this->requests, function ($x, $y) use ($methodRank) {
            $m = $methodRank[$x['method']] <=> $methodRank[$y['method']];
            if( $m !== 0 )
                return $m;
            $rx = self::$resourceRank[$x['object']['resource']] ?? 999;
            $ry = self::$resourceRank[$y['object']['resource']] ?? 999;
            $r = ($x['method'] == 'DELETE') ? ($ry <=> $rx) : ($rx <=> $ry);
            if( $r !== 0 )
                return $r;
            return strcmp($x['object']['scope'] . "|" . $x['object']['name'], $y['object']['scope'] . "|" . $y['object']['name']);
        });
        foreach( $this->requests as $i => &$req )
            $req['seq'] = $i + 1;
    }

    /**
     * A request that names an object created in this change set depends on that POST.
     * If the POST needs review, the dependent request needs it too: it would fail or reference nothing.
     */
    private function resolveDependencies()
    {
        $created = array();
        foreach( $this->requests as $req )
            if( $req['method'] == 'POST' )
                $created[$req['object']['resource'] . "|" . $req['object']['name']][] = $req['seq'];

        $changed = TRUE;
        while( $changed )
        {
            $changed = FALSE;
            foreach( $this->requests as &$req )
            {
                if( $req['method'] == 'DELETE' || !isset(self::$references[$req['object']['resource']]) )
                    continue;
                $body = is_array($req['body']) ? $req['body'] : array();
                foreach( self::$references[$req['object']['resource']] as $field => $targetResource )
                {
                    foreach( $this->namesAt($body, $field) as $refName )
                    {
                        $k = $targetResource . "|" . $refName;
                        if( !isset($created[$k]) )
                        {
                            if( !isset($this->existing[$targetResource][$refName]) && $this->isChangedReference($req, $field, $refName) )
                            {
                                $msg = "references " . $targetResource . " '" . $refName . "', which is not in the configuration";
                                if( !in_array($msg, $req['warnings']) )
                                {
                                    $req['warnings'][] = $msg;
                                    if( !$req['review'] )
                                    {
                                        $req['review'] = TRUE;
                                        $changed = TRUE;
                                    }
                                }
                            }
                            continue;
                        }
                        foreach( $created[$k] as $seq )
                        {
                            if( !in_array($seq, $req['depends_on']) && $seq != $req['seq'] )
                                $req['depends_on'][] = $seq;
                            $dep = $this->requests[$seq - 1];
                            if( $dep['review'] && !$req['review'] )
                            {
                                $req['review'] = TRUE;
                                $req['warnings'][] = "depends on request " . $seq . " (" . $targetResource . " '" . $refName . "'), which needs review";
                                $changed = TRUE;
                            }
                        }
                    }
                }
                sort($req['depends_on']);
            }
            unset($req);
        }
    }

    /**
     * Predefined objects (e.g. url categories) are not objects of the configuration; only a name
     * the change adds is checked, a name that was referenced before was accepted by SCM already.
     */
    private function isChangedReference(array $req, $field, $refName)
    {
        if( $req['method'] == 'POST' )
            return !in_array($field, array('alert', 'allow', 'block', 'continue'));
        $before = is_array($req['before']) ? $req['before'] : array();
        return !in_array($refName, $this->namesAt($before, $field));
    }

    private function namesAt(array $body, $field)
    {
        $v = $body;
        foreach( explode('.', $field) as $part )
        {
            if( !is_array($v) || !array_key_exists($part, $v) )
                return array();
            $v = $v[$part];
        }
        if( is_string($v) )
            return array($v);
        if( is_array($v) )
            return array_values(array_filter($v, 'is_string'));
        return array();
    }

    // ------------------------------------------------------------------------------------------------
    // XML -> SCM JSON
    // ------------------------------------------------------------------------------------------------

    /**
     * @param array $obj
     * @param array $dropped XML paths not sent because the SCM schema does not know them
     * @return array body without folder / snippet / device
     */
    public function toBody(array $obj, array &$dropped)
    {
        $schema = $this->schema[$obj['resource']]['schema'];
        $ignored = self::$ignoredFields[$obj['resource']] ?? array();
        $body = $this->convertElement($obj['node'], $schema, "", $dropped, $ignored);
        if( !is_array($body) )
            $body = array();
        $body = array('name' => $obj['name']) + $body;
        return $body;
    }

    private function convertElement(DOMElement $node, array $schema, $path, array &$dropped, array $ignored = array())
    {
        $type = $schema['type'] ?? 'any';

        if( $type == 'object' )
        {
            $out = array();
            foreach( $node->childNodes as $child )
            {
                if( $child->nodeType != XML_ELEMENT_NODE )
                    continue;
                /** @var DOMElement $child */
                if( $path === "" && in_array($child->tagName, $ignored) )
                    continue;

                $key = str_replace('-', '_', $child->tagName);
                if( !isset($schema['properties'][$key]) )
                {
                    $dropped[] = ltrim($path . "/" . $child->tagName, "/");
                    continue;
                }
                $out[$key] = $this->convertElement($child, $schema['properties'][$key], $path . "/" . $child->tagName, $dropped);
            }
            if( empty($out) )
                return new stdClass();
            return $out;
        }

        if( $type == 'array' )
        {
            $items = $schema['items'] ?? array('type' => 'string');
            $out = array();
            if( ($items['type'] ?? 'any') == 'object' )
            {
                foreach( $node->childNodes as $child )
                {
                    if( $child->nodeType != XML_ELEMENT_NODE )
                        continue;
                    if( $child->tagName != 'entry' )
                    {
                        $dropped[] = ltrim($path . "/" . $child->tagName, "/");
                        continue;
                    }
                    $entry = array();
                    if( $child->hasAttribute('name') )
                        $entry['name'] = $child->getAttribute('name');
                    $converted = $this->convertElement($child, $items, $path . "/entry", $dropped);
                    if( is_array($converted) )
                        $entry += $converted;
                    $out[] = $entry;
                }
                return $out;
            }

            $members = 0;
            foreach( $node->childNodes as $child )
            {
                if( $child->nodeType != XML_ELEMENT_NODE )
                    continue;
                $members++;
                $out[] = $this->convertScalar($child->textContent, $items);
            }
            if( $members == 0 && trim($node->textContent) !== "" )
                $out[] = $this->convertScalar(trim($node->textContent), $items);
            return $out;
        }

        // scalar
        foreach( $node->childNodes as $child )
            if( $child->nodeType == XML_ELEMENT_NODE )
            {
                // SCM expects a value, the XML has a structure: keep its first element name (e.g. <mode><ip-user/></mode>)
                if( isset($schema['enum']) && in_array($child->tagName, $schema['enum']) )
                    return $child->tagName;
                $dropped[] = ltrim($path . "/" . $child->tagName, "/");
                return null;
            }
        return $this->convertScalar($node->textContent, $schema);
    }

    private function convertScalar($text, array $schema)
    {
        $text = trim($text);
        $type = $schema['type'] ?? 'any';
        if( $type == 'boolean' )
        {
            if( $text === 'yes' || $text === 'true' )
                return TRUE;
            if( $text === 'no' || $text === 'false' )
                return FALSE;
        }
        if( $type == 'integer' && is_numeric($text) )
            return (int)$text;
        if( $type == 'number' && is_numeric($text) )
            return $text + 0;
        return $text;
    }

    // ------------------------------------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------------------------------------

    private function canonical(DOMElement $node)
    {
        $doc = new DOMDocument();
        $doc->preserveWhiteSpace = FALSE;
        $clone = $doc->importNode($node, TRUE);
        $doc->appendChild($clone);
        $this->removeWhitespace($clone);
        return $clone->C14N();
    }

    private function removeWhitespace(DOMNode $node)
    {
        for( $i = $node->childNodes->length - 1; $i >= 0; $i-- )
        {
            $c = $node->childNodes->item($i);
            if( $c->nodeType == XML_TEXT_NODE && trim($c->textContent) === "" && $node->childNodes->length > 1 )
                $node->removeChild($c);
            elseif( $c->nodeType == XML_ELEMENT_NODE )
                $this->removeWhitespace($c);
        }
    }

    private function xpathOf(DOMElement $node)
    {
        $parts = array();
        $n = $node;
        while( $n !== null && $n->nodeType == XML_ELEMENT_NODE )
        {
            /** @var DOMElement $n */
            $p = $n->tagName;
            if( $n->hasAttribute('name') )
                $p .= "[@name='" . $n->getAttribute('name') . "']";
            $parts[] = $p;
            $n = $n->parentNode;
        }
        return "/" . implode("/", array_reverse($parts));
    }
}
