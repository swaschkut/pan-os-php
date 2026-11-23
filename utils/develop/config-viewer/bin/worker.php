<?php
/**
 * ISC License
 *
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
 * config-viewer worker: loads ONE configuration once and keeps it in memory (UTIL::$sharedConfig). Started by
 * bin/service.php on request of ViewerApp::session(), never by a user. Requests arrive on a unix socket inside the project folder, one JSON line
 * per connection:
 *   references type, args, name -> who uses the objects of that name (in a forked child)
 *   locations                 -> the locations of the loaded configuration (device groups / vsys / containers, snippets)
 *   read    type, args        -> runs in a forked child (a failing run / exit() can not hurt the loaded configuration)
 *   change  type, args, note  -> tried in a forked child first; only when that worked it runs on the real memory
 *   save    file              -> writes the memory to a new file (only when there are unsaved changes)
 *   status / close
 * Unsaved changes are written to the autosave file every <autosave> minutes and when the worker stops.
 *
 * Not started on its own: bin/service.php forks and includes this file.
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
// included by bin/service.php in a forked child, with the (validated) parameters in $viewerWorker
if( !isset( $viewerWorker ) || !is_array( $viewerWorker ) )
{
    fwrite( STDERR, "config-viewer worker: started by bin/service.php only\n" );
    exit( 2 );
}
$configFile = $viewerWorker['config'];
$sockFile = $viewerWorker['sock'];
$pidFile = $viewerWorker['pid'];
$logFile = $viewerWorker['log'];
$autosaveFile = $viewerWorker['autosave'];
$autosaveSec = max( 60, (int)$viewerWorker['autosaveMin'] * 60 );
$idleSec = max( 60, (int)$viewerWorker['idleMin'] * 60 );

posix_setsid();
ini_set( 'error_log', $logFile );
ini_set( 'log_errors', '1' );
ini_set( 'display_errors', '0' );
// whatever pan-os-php prints outside of a captured run is dropped
ob_start( function( $buffer ) { return ''; }, 4096 );
// written apart and renamed: the web part must never see the file without the process id in it
file_put_contents( $pidFile . '.tmp', (string)getmypid(), LOCK_EX );
chmod( $pidFile . '.tmp', 0600 );
rename( $pidFile . '.tmp', $pidFile );

$GLOBALS['viewerIsChild'] = FALSE;
$GLOBALS['viewerState'] = array( 'dirty' => FALSE, 'changes' => array(), 'saved' => null, 'autosaved' => null, 'loaded' => time() );

/**
 * The pan-os-php framework turns every PHP warning into a fatal error (also with @). The worker's own file and
 * socket calls must not stop it, e.g. a select() interrupted by a finished child.
 */
function viewerQuiet( callable $fn )
{
    set_error_handler( function() { return TRUE; } );
    try
    {
        return $fn();
    }
    finally
    {
        restore_error_handler();
    }
}

function viewerUnlink( $file )
{
    viewerQuiet( function() use ( $file ) { if( file_exists( $file ) ) unlink( $file ); } );
}

function viewerLog( $text )
{
    global $logFile;
    viewerQuiet( function() use ( $logFile, $text ) { file_put_contents( $logFile, date( 'c' ) . ' ' . $text . "\n", FILE_APPEND ); } );
}

function viewerStatus()
{
    $s = $GLOBALS['viewerState'];
    $h = $GLOBALS['viewerHistory'] ?? array();
    return array( 'dirty' => $s['dirty'], 'changes' => $s['changes'], 'saved' => $s['saved'], 'autosaved' => $s['autosaved'], 'loaded' => $s['loaded'],
        'history' => array( 'on' => isset( $h['git'] ), 'head' => $h['head'] ?? null, 'commits' => $h['commits'] ?? 0, 'error' => $h['error'] ?? null ) );
}

/**
 * the locations of the loaded configuration, for the location choice of the page: Panorama - shared and every device
 * group; firewall - shared and every vsys (and shared gateway); SCM - every container (folder) and snippet
 */
function viewerLocations()
{
    $pan = UTIL::$sharedConfig['pan'] ?? null;
    $out = array();
    // 'levels': the locations whose objects a firewall of this location gets, nearest first (the effective view)
    $add = function( $kind, $list ) use ( &$out, $pan ) {
        foreach( is_array( $list ) ? $list : array() as $o )
            if( is_object( $o ) && method_exists( $o, 'name' ) && is_string( $o->name() ) && $o->name() !== '' )
                $out[] = array( 'name' => $o->name(), 'kind' => $kind, 'levels' => viewerLevels( $pan, $o ) );
    };
    if( $pan instanceof PanoramaConf )
    {
        $out[] = array( 'name' => 'shared', 'kind' => 'shared', 'levels' => array( 'shared' ) );
        $add( 'device-group', $pan->getDeviceGroups() );
        return array( 'config' => 'panorama', 'locations' => $out, 'ancestor' => $pan->ancestorObjectsTakePrecedence() );
    }
    if( $pan instanceof PANConf )
    {
        $out[] = array( 'name' => 'shared', 'kind' => 'shared', 'levels' => array( 'shared' ) );
        $add( 'vsys', $pan->getVirtualSystems() );
        $add( 'shared-gateway', $pan->getSharedGateways() );
        return array( 'config' => 'firewall', 'locations' => $out, 'ancestor' => FALSE );
    }
    if( $pan instanceof BuckbeakConf || $pan instanceof FawkesConf )
    {
        $add( 'container', $pan->getContainers() );
        $add( 'snippet', $pan->getSnippets() );
        return array( 'config' => 'scm', 'locations' => $out, 'ancestor' => FALSE );
    }
    return array( 'config' => 'unknown', 'locations' => $out, 'ancestor' => FALSE );
}

/**
 * system information: every config section of utils/common/config_sections.json that applies to this configuration
 * (Panorama, firewall, a template of Panorama, an SCM folder / snippet / device) - read with the methods of
 * type=config-section (ConfigSection), the same as the CLI shows; secrets never (ConfigSection::flatten)
 */
function viewerSystem( ?string $template, ?string $at ): array
{
    $pan = UTIL::$sharedConfig['pan'] ?? null;
    if( !is_object( $pan ) )
        throw new Exception( 'no configuration loaded' );
    $isScm = $pan instanceof BuckbeakConf || $pan instanceof FawkesConf;
    $isPanorama = $pan instanceof PanoramaConf;
    if( $template !== null && ( !$isPanorama || $pan->findTemplate( $template ) === null ) )
        throw new Exception( 'template ' . $template . ' not found' );
    $scope = ConfigSection::scopeOf( $isPanorama, $template, $isScm );
    $scmRoot = null;
    $choices = array();
    if( $isScm )
    {
        $at = $at ?? 'All';
        $sub = null;
        foreach( array( 'findContainer', 'findDeviceCloud', 'findDeviceOnPrem', 'findSnippet' ) as $f )
            if( $sub === null && method_exists( $pan, $f ) )
                $sub = $pan->$f( $at );
        if( $sub === null )
            throw new Exception( 'folder / snippet / device ' . $at . ' not found' );
        $scmRoot = $sub->xmlroot;
        foreach( array( 'getContainers', 'getDeviceClouds', 'getDeviceOnPrems', 'getSnippets' ) as $f )
            if( method_exists( $pan, $f ) )
                foreach( $pan->$f() as $o )
                    $choices[] = $o->name();
    }
    elseif( $isPanorama )
        foreach( $pan->getTemplates() as $t )
            $choices[] = $t->name();
    $names = $isPanorama && $template === null ? ConfigSection::panoramaNames( $pan->xmldoc ) : array();
    $sections = array();
    foreach( ConfigSection::registry() as $name => $def )
    {
        if( !in_array( $scope, $def['scope'], TRUE ) )
            continue;
        $section = ConfigSection::section( $name );
        $container = ConfigSection::container( $pan->xmldoc, $section, $template, FALSE, $scope, $scmRoot );
        $entries = array();
        foreach( ConfigSection::sectionEntries( $section, $container ) as $en => $e )
            $entries[] = array( 'name' => (string)$en, 'fields' => ConfigSection::flatten( $e ), 'members' => ConfigSection::memberPaths( $e ),
                'references' => count( $names ) && !empty( $def['references'] ) ? ConfigSection::references( $e, $names ) : array() );
        $sections[] = array( 'name' => $name, 'group' => $def['group'] ?? 'Other', 'description' => $def['description'] ?? '',
            'kind' => $def['kind'] ?? 'entries', 'path' => $isScm ? ConfigSection::pathOf( $section, 'scm' ) : ConfigSection::xpath( $section, $template, $scope ),
            'entries' => $entries );
    }
    return array( 'config' => $isScm ? 'scm' : ( $isPanorama ? 'panorama' : 'firewall' ), 'scope' => $scope, 'template' => $template,
        'location' => $isScm ? $at : null, 'choices' => $choices,
        'ancestor' => $isPanorama ? $pan->ancestorObjectsTakePrecedence() : null, 'sections' => $sections );
}

/**
 * same name on other levels, per object of the read (Panorama device groups / shared, SCM folders): with the method of
 * pan-os-php (ReferenceableObject::getSameNameOverrideInfo / getSameNameLevelStatus - the filters is.overriden,
 * is.overriding): rowKey => array( 'overrides' => locations of the copies it hides, 'overridden' => locations of the
 * copies that hide it ) - only objects with a copy on another level
 */
function viewerOverride( $util ): array
{
    $out = array();
    $locOf = function( $o ) { $l = PH::getLocationString( $o ); return is_string( $l ) ? $l : '?'; };
    foreach( is_array( $util->objectsToProcess ?? null ) ? $util->objectsToProcess : array() as $set )
        foreach( viewerSetObjects( $set ) as $o )
        {
            if( !is_object( $o ) || !method_exists( $o, 'getSameNameOverrideInfo' ) || !method_exists( $o, 'name' ) )
                continue;
            try { $info = $o->getSameNameOverrideInfo(); } catch( Throwable $e ) { continue; }
            $up = array_map( $locOf, $info['ancestorCopies'] ?? array() );
            $down = array_keys( $info['descendantCopies'] ?? array() );
            if( !count( $up ) && !count( $down ) )
                continue;
            if( ( $info['mode'] ?? null ) === 'panorama' && !empty( $info['precedence'] ) )
                // ancestor precedence: the highest copy wins
                $row = array( 'overrides' => count( $up ) ? array() : $down, 'overridden' => count( $up ) ? array( end( $up ) ) : array() );
            else
                // the nearest copy wins (default; SCM)
                $row = array( 'overrides' => $up, 'overridden' => $down );
            $out[viewerRowKey( $o )] = $row;
        }
    return $out;
}

/**
 * the effective view: for each object of the read, the object a firewall of $at gets for its name - with the lookup
 * of pan-os-php itself (the store of the location, nested: an EDL before an address / group / region of the same
 * name, then the parents, SCM snippets, predefined objects; Panorama "ancestor objects take precedence":
 * PH::resolveNameForFirewalls). rowKey => 'used' | array( 'by' => location, 'class' => class of the winner )
 */
function viewerEffective( $util, string $at ): array
{
    $pan = UTIL::$sharedConfig['pan'] ?? null;
    if( !is_object( $pan ) )
        return array();
    $loc = null;
    if( $at === 'shared' )
        $loc = $pan;
    else
        foreach( array( 'findDeviceGroup', 'findVirtualSystem', 'findContainer', 'findDeviceCloud', 'findDeviceOnPrem', 'findSnippet' ) as $f )
            if( $loc === null && method_exists( $pan, $f ) )
                $loc = $pan->$f( $at );
    if( $loc === null )
        return array();
    $ancestor = $pan instanceof PanoramaConf && $pan->ancestorObjectsTakePrecedence();
    $stores = array( 'Address' => 'addressStore', 'AddressGroup' => 'addressStore', 'Region' => 'addressStore', 'EDL' => 'addressStore',
        'Service' => 'serviceStore', 'ServiceGroup' => 'serviceStore', 'Tag' => 'tagStore' );
    $out = array();
    foreach( is_array( $util->objectsToProcess ?? null ) ? $util->objectsToProcess : array() as $set )
        foreach( viewerSetObjects( $set ) as $o )
        {
            if( !is_object( $o ) || !method_exists( $o, 'name' ) )
                continue;
            $prop = $stores[get_class( $o )] ?? null;
            $win = null;
            if( $prop !== null && isset( $loc->$prop ) && is_object( $loc->$prop ) )
                $win = $ancestor && method_exists( 'PH', 'resolveNameForFirewalls' ) ? PH::resolveNameForFirewalls( $prop, $o->name(), $loc )
                    : $loc->$prop->find( $o->name() );
            if( $win === null )
                continue;
            $wl = PH::getLocationString( $win );
            $out[viewerRowKey( $o )] = $win === $o ? 'used' : array( 'by' => is_string( $wl ) ? $wl : '?', 'class' => get_class( $win ) );
        }
    return $out;
}

/**
 * the locations a firewall of $o gets objects from, nearest first - which copy of a name it gets:
 *   Panorama: the device group, its parents, shared (the nearest copy wins; with "ancestor objects take precedence"
 *             the highest one)
 *   firewall: the vsys, shared
 *   SCM:      the folder, its snippets (the first attached wins), the parent folder, its snippets, … up to All (and its
 *             snippets: predefined ones too) - the nearest wins (SCM has no ancestor precedence)
 */
function viewerLevels( $pan, $o ): array
{
    // the levels of pan-os-php itself (PH::firewallResolutionLevels - the same as the filters is.overriden.for and the
    // device level), nearest first; a Panorama / firewall configuration is "shared"
    $list = array();
    foreach( PH::firewallResolutionLevels( $o ) as $l )
        $list[] = $l instanceof PanoramaConf || $l instanceof PANConf ? 'shared' : $l->name();
    return array_values( array_unique( $list ) );
}

/** the viewer type (and rule type / profile type) of a pan-os-php object, null for others (interface, vsys, …) */
function viewerTypeOf( $o )
{
    static $rules = array( 'SecurityRule' => 'security', 'NatRule' => 'nat', 'DecryptionRule' => 'decryption', 'AppOverrideRule' => 'appoverride',
        'CaptivePortalRule' => 'captiveportal', 'AuthenticationRule' => 'authentication', 'PbfRule' => 'pbf', 'QoSRule' => 'qos', 'DoSRule' => 'dos',
        'TunnelInspectionRule' => 'tunnelinspection', 'DefaultSecurityRule' => 'defaultsecurity', 'NetworkPacketBrokerRule' => 'networkpacketbroker',
        'SDWanRule' => 'sdwan' );
    // profiles: the types of the page (ViewerApp::SPCLASSES - SCM: virus-and-wildfire-analysis, before 'virus')
    $profiles = ViewerApp::SPCLASSES;
    static $plain = array( 'Address' => 'address', 'AddressGroup' => 'address', 'Region' => 'address', 'Service' => 'service', 'ServiceGroup' => 'service',
        'Tag' => 'tag', 'Zone' => 'zone', 'Schedule' => 'schedule', 'SecurityProfileGroup' => 'securityprofilegroup', 'App' => 'application',
        'AppGroup' => 'application', 'AppFilter' => 'application', 'AppCustom' => 'application', 'EDL' => 'edl', 'LogProfile' => 'log-profile',
        // network / device objects that use other objects (certificates, profiles, interfaces, …) - so a reference names
        // them and the page can open them
        'Certificate' => 'certificate', 'CertificateProfile' => 'certificate-profile', 'SSL_TLSServiceProfile' => 'ssl-tls-service-profile',
        'IKEGateway' => 'ike-gateway', 'IkeCryptoProfil' => 'ike-profile', 'IPSecCryptoProfil' => 'ipsec-profile', 'IPsecTunnel' => 'ipsec-tunnel',
        'GreTunnel' => 'gre-tunnel', 'GPGateway' => 'gp-gateway', 'GPPortal' => 'gp-portal', 'GPGatewayTunnel' => 'gpgateway-tunnel',
        'InterfaceManagementProfile' => 'interface-management-profile', 'ZoneProtectionProfile' => 'zone-protection-profile',
        'EthernetInterface' => 'interface', 'AggregateEthernetInterface' => 'interface', 'LoopbackInterface' => 'interface', 'TunnelInterface' => 'interface',
        'VlanInterface' => 'interface', 'VirtualWire' => 'virtualwire', 'VirtualRouter' => 'routing', 'LogicalRouter' => 'routing',
        'StaticRoute' => 'static-route', 'DHCP' => 'dhcp', 'Threat' => 'threat', 'DNSPolicy' => 'dns-rule' );
    static $devices = array( 'DeviceGroup' => 'devicegroup', 'Template' => 'template', 'TemplateStack' => 'templatestack', 'ManagedDevice' => 'manageddevice',
        'LogCollector' => 'logcollector', 'LogCollectorGroup' => 'logcollectorgroup',
        // SCM: folders (containers), cloud / on-prem devices, snippets
        'Container' => 'container', 'DeviceCloud' => 'devicecloud', 'DeviceOnPrem' => 'deviceonprem', 'Snippet' => 'snippet' );
    $c = get_class( $o );
    if( $o instanceof ThreatPolicy )
        return array( 'type' => 'threat-rule' );
    if( isset( $devices[$c] ) )
        return array( 'type' => 'device', 'devicetype' => $devices[$c] );
    if( isset( $rules[$c] ) )
        return array( 'type' => 'rule', 'ruletype' => $rules[$c] );
    if( isset( $profiles[$c] ) )
        return array( 'type' => 'securityprofile', 'securityprofiletype' => $profiles[$c] );
    if( isset( $plain[$c] ) )
        return array( 'type' => $plain[$c] );
    return null;
}

/** the objects that use $o (a rule, group, profile group, …), each once, with the fields it uses $o in */
function viewerUsers( $o )
{
    $refs = array();
    foreach( isset( $o->refrules ) && is_array( $o->refrules ) ? $o->refrules : array() as $ref )
    {
        // from the reference up to the object that uses it: a rule / group / profile group …; a "…Container" on
        // the way is the field (AddressRuleContainer:source)
        $field = null;
        $user = null;
        $first = null;
        // a use of a certificate / certificate profile (CertificateUsage): the user is the object the field belongs to
        // (SSL/TLS service profile, IKE gateway, GlobalProtect portal / gateway, …), the field its path; without such
        // an object (management, SSL decryption settings, …) the field itself
        if( $ref instanceof CertificateReference )
        {
            $field = $ref->field;
            $owner = $ref->owner;
            $isLocation = !is_object( $owner ) || $owner instanceof PANConf || $owner instanceof PanoramaConf || $owner instanceof Template
                || $owner instanceof TemplateStack || $owner instanceof VirtualSystem || $owner instanceof DeviceGroup
                || $owner instanceof Container || $owner instanceof DeviceCloud || $owner instanceof DeviceOnPrem || $owner instanceof Snippet;
            if( !$isLocation )
                $ref = $owner;
        }
        for( $x = $ref, $i = 0; is_object( $x ) && $i < 8; $x = $x->owner ?? null, $i++ )
        {
            if( $first === null && method_exists( $x, 'name' ) && !preg_match( '/Store$/', get_class( $x ) ) )
                $first = $x;
            if( $field === null && preg_match( '/Container$/', get_class( $x ) ) && !$x instanceof Container && method_exists( $x, 'name' ) && is_string( $x->name() ) && $x->name() !== '' )
                $field = $x->name();
            $tx = viewerTypeOf( $x );
            if( $tx !== null )
            {
                // a device (device group, container, …) is the user only when it is the reference itself - not the
                // location of an object without a list in the viewer (then: that object)
                if( $tx['type'] === 'device' && $first !== null && $first !== $x )
                    break;
                $user = $x;
                break;
            }
        }
        $user = $user ?? $first;
        if( !is_object( $user ) )
            continue;
        $t = viewerTypeOf( $user );
        // location and template as the rows of the page name them (viewerRowKey): the shared part of a template is
        // location shared + template; a device is in "shared"; a DNS rule / threat rule has its security profile
        list( $loc, $tpl ) = explode( '|', viewerRowKey( $user ), 3 );
        if( ( $t['type'] ?? null ) === 'device' )
            $loc = 'shared';
        $profile = ( $user instanceof DNSPolicy || $user instanceof ThreatPolicy ) && is_object( $user->owner ?? null ) ? $user->owner->name() : null;
        $row = array( 'type' => $t['type'] ?? null, 'ruletype' => $t['ruletype'] ?? null, 'securityprofiletype' => $t['securityprofiletype'] ?? null,
            'devicetype' => $t['devicetype'] ?? null, 'location' => $loc !== '' ? $loc : null, 'template' => $tpl !== '' ? $tpl : null, 'profile' => $profile,
            'name' => method_exists( $user, 'name' ) ? (string)$user->name() : '', 'class' => get_class( $user ),
            'rulebase' => method_exists( $user, 'isPostRule' ) && $t !== null && $t['type'] === 'rule' ? ( $user->isPostRule() ? 'post' : 'pre' ) : null );
        $key = $row['class'] . '|' . $row['location'] . '|' . $row['template'] . '|' . $row['profile'] . '|' . $row['name'];
        if( !isset( $refs[$key] ) )
            $refs[$key] = $row + array( 'fields' => array() );
        if( $field !== null && !in_array( $field, $refs[$key]['fields'], TRUE ) )
            $refs[$key]['fields'][] = $field;
    }
    return array_values( $refs );
}

/**
 * the objects of one set of a utility (objectsToProcess): 'objects' (addresses, services, tags, zones, devices, ...) or
 * 'rules' - RULEUTIL and also SECURITYPROFILEUTIL / PROFILEUTIL keep theirs there. Before only 'objects' was read: rules
 * and security profiles had no XML / history in the window, no count of references ("?") and no references.
 */
/**
 * the key of an object as the rows of the viewer name it (ViewerApp::rows): "location|template|name" - the shared part
 * of a template has location "shared" (pan-os-php: location = the template); a DNS rule / threat rule "…|profile/name"
 */
function viewerRowKey( $o ): string
{
    $loc = PH::getLocationString( $o );
    $loc = is_string( $loc ) ? $loc : '';
    $tpl = PH::findTemplateOwner( $o );
    $tpl = is_object( $tpl ) && method_exists( $tpl, 'name' ) ? (string)$tpl->name() : '';
    if( $tpl !== '' && $loc === $tpl )
        $loc = 'shared';
    // a device (device group, template, template stack, managed firewall): the page lists it in "shared" - before, a
    // device group / template stack had its own name as location here: no count of references ("?") and no XML
    $t = viewerTypeOf( $o );
    if( ( $t['type'] ?? null ) === 'device' )
        $loc = 'shared';
    return $loc . '|' . $tpl . '|' . PH::jsonObjectKey( $o );
}

/**
 * the path of an object in the history (ConfigObjectSplit): its entry; a device group - the list of its firewalls
 * (<devices>, …/device-group/<name>/devices/_order: one line per firewall), its objects have their own history
 */
function viewerHistoryPath( $o ): ?string
{
    if( $o instanceof DeviceGroup && $o->xmlroot instanceof DOMElement )
        return ConfigObjectSplit::path( $o->xmlroot ) . '/devices/' . ConfigObjectSplit::ORDER;
    return ConfigObjectSplit::entryPath( $o->xmlroot );
}

function viewerSetObjects( $set ): array
{
    if( !is_array( $set ) )
        return array();
    if( is_array( $set['objects'] ?? null ) )
        return $set['objects'];
    return is_array( $set['rules'] ?? null ) ? $set['rules'] : array();
}

/**
 * who uses the objects named $name of a type (in the location of $args): every object found, with its references -
 * the referencing object (type, rule type, location, name, pre / post) and the field (source, destination, member, …)
 */
function viewerReferences( $type, array $args, $name, $profile = null )
{
    global $configFile;
    // the run only selects the objects of the location (no object has this name, so nothing is shown)
    $argv = array_merge( array( 'config-viewer', 'in=' . $configFile, 'shadow-json' ), $args, array( 'actions=display', 'filter=(name eq config-viewer-load)' ) );
    PH::resetCliArgs( $argv );
    PH::$JSON_OUT = array();
    PH::$JSON_TMP = array();
    PH::$JSON_OUTlog = '';
    ob_start();
    $util = PH::callPANOSPHP( $type, $argv, count( $argv ), 'config-viewer' );
    ob_end_clean();
    $out = array();
    foreach( is_array( $util->objectsToProcess ?? null ) ? $util->objectsToProcess : array() as $set )
        foreach( viewerSetObjects( $set ) as $o )
        {
            if( !is_object( $o ) || !method_exists( $o, 'name' ) || $o->name() !== $name )
                continue;
            if( $profile !== null && PH::jsonObjectKey( $o ) !== $profile . '/' . $name )
                continue;
            $refs = viewerUsers( $o );
            $loc = PH::getLocationString( $o );
            $out[] = array( 'location' => is_string( $loc ) ? $loc : null, 'class' => get_class( $o ), 'references' => $refs );
        }
    return $out;
}

// ---- history on object level (git step 2, lib/ViewerGit.php): one commit per change on refs/viewer/work/<version>

/** the repository of the project and the first commit of the loaded version (when it has none yet) */
function viewerHistoryStart( string $configFile ): void
{
    $GLOBALS['viewerHistory'] = array( 'commits' => 0 );
    $h = &$GLOBALS['viewerHistory'];
    if( getenv( 'PANOSPHP_VIEWER_GIT' ) === '0' )
    {
        $h['error'] = 'switched off (PANOSPHP_VIEWER_GIT=0)';
        return;
    }
    try
    {
        $git = new ViewerGit( dirname( $configFile ) . '/history.git' );
        if( !$git->ready() )
        {
            $h['error'] = 'git is not available';
            return;
        }
        $key = basename( $configFile, '.xml' );
        $t = microtime( TRUE );
        $state = ConfigObjectSplit::state( UTIL::$sharedConfig['pan']->xmldoc );
        $head = $git->ref( 'refs/viewer/versions/' . $key );
        if( $head === null )
            $head = $git->commit( 'refs/viewer/versions/' . $key, null, ConfigObjectSplit::files( $state ), array(),
                "version " . $key . "\n\nVersion: " . $key . "\n", 'config-viewer', time(), TRUE );
        // a loaded version starts without unsaved changes: its work ref begins at the version again
        $git->setRef( 'refs/viewer/work/' . $key, $head );
        $h += array( 'git' => $git, 'key' => $key, 'head' => $head, 'state' => $state );
        viewerLog( sprintf( 'history: %s, %d objects, %.2f s', substr( $head, 0, 12 ), count( $state['entries'] ), microtime( TRUE ) - $t ) );
    }
    catch( Throwable $e )
    {
        $h = array( 'commits' => 0, 'error' => $e->getMessage() );
        viewerLog( 'history: ' . $e->getMessage() );
    }
}

/** after a change on the memory: the objects that differ as one commit (the change as its message); its id or null */
function viewerHistoryCommit( $note ): ?string
{
    $h = &$GLOBALS['viewerHistory'];
    if( !isset( $h['git'] ) )
        return null;
    try
    {
        $state = ConfigObjectSplit::state( UTIL::$sharedConfig['pan']->xmldoc );
        $c = ConfigObjectSplit::changes( $h['state'], $state );
        $user = is_array( $note ) ? (string)( $note['user'] ?? '' ) : '';
        $time = is_array( $note ) && is_int( $note['time'] ?? null ) ? $note['time'] : time();
        $h['head'] = $h['git']->commit( 'refs/viewer/work/' . $h['key'], $h['head'], $c['put'], $c['delete'], ViewerGit::message( $note ), $user, $time );
        $h['state'] = $state;
        $h['commits']++;
        return $h['head'];
    }
    catch( Throwable $e )
    {
        // the history can not follow any more: switched off for this worker, the changes themselves go on
        viewerLog( 'history: ' . $e->getMessage() );
        $h = array( 'commits' => $h['commits'] ?? 0, 'error' => 'stopped: ' . $e->getMessage() );
        return null;
    }
}

/** the objects of the loaded configuration that are used but not there (pan-os-php: tmp objects): "location type name" */
function viewerUnresolved(): array
{
    $pan = UTIL::$sharedConfig['pan'] ?? null;
    $locs = array( 'shared' => $pan );
    foreach( array( 'getDeviceGroups', 'getVirtualSystems', 'getSharedGateways', 'getContainers', 'getSnippets' ) as $m )
        if( is_object( $pan ) && method_exists( $pan, $m ) )
            foreach( (array)$pan->$m() as $l )
                if( is_object( $l ) && method_exists( $l, 'name' ) )
                    $locs[$l->name()] = $l;
    $out = array();
    foreach( $locs as $name => $l )
        foreach( array( 'addressStore' => 'address', 'serviceStore' => 'service', 'tagStore' => 'tag' ) as $store => $type )
            if( is_object( $l ) && isset( $l->$store ) && is_object( $l->$store ) && method_exists( $l->$store, 'all' ) )
                foreach( $l->$store->all() as $o )
                    if( ( method_exists( $o, 'isTmpAddr' ) && $o->isTmpAddr() ) || ( method_exists( $o, 'isTmpSrv' ) && $o->isTmpSrv() )
                        || ( $o instanceof Tag && $o->isTmp() ) )
                        $out[] = $name . ' ' . $type . ' ' . $o->name();
    sort( $out );
    return array_values( array_unique( $out ) );
}

/**
 * undo of one unsaved change (git step 3): git takes its commit back on the current state (merge-tree, in memory);
 * the configuration of that tree is loaded by pan-os-php again (no object of the old memory is kept), the result is
 * one more commit ("undo: …", Reverts: <commit>). Refused when a later change touched the same lines of an object.
 * @return array( 'ok' => TRUE, 'unresolved' => objects used but not there any more ) or ok FALSE + error
 */
function viewerUndo( int $index, array $note ): array
{
    global $configFile;
    $h = &$GLOBALS['viewerHistory'];
    $changes = &$GLOBALS['viewerState']['changes'];
    if( !isset( $h['git'] ) )
        return array( 'ok' => FALSE, 'error' => 'undo needs the history (git) of the version: ' . ( $h['error'] ?? 'off' ) );
    $c = $changes[$index] ?? null;
    if( !is_array( $c ) || !is_string( $c['commit'] ?? null ) || ( $c['type'] ?? '' ) === 'undo' )
        return array( 'ok' => FALSE, 'error' => 'this change can not be taken back (no commit of it)' );
    if( !empty( $c['undone'] ) )
        return array( 'ok' => FALSE, 'error' => 'this change is taken back already' );
    $git = $h['git'];
    $r = $git->revertTree( $c['commit'], $h['head'] );
    if( $r['tree'] === null )
        return array( 'ok' => FALSE, 'error' => 'a later change touched the same objects: ' . implode( ', ', array_slice( $r['conflicts'], 0, 10 ) )
            . ' - take the later change back first', 'conflicts' => $r['conflicts'] );
    $tree = $r['tree'];
    // the configuration of the tree: the entries of the memory, the ones the undo touches from the tree
    $files = ConfigObjectSplit::files( $h['state'] );
    foreach( $git->diff( $h['head'], $tree ) as $path => $st )
    {
        if( $st === 'D' )
            unset( $files[$path] );
        else
        {
            $text = $git->show( $tree, $path );
            if( $text === null )
                return array( 'ok' => FALSE, 'error' => 'git: ' . $path . ' not readable' );
            $files[$path] = $text;
        }
    }
    $before = viewerUnresolved();
    $doc = ConfigObjectSplit::join( $files );
    $old = UTIL::$sharedConfig;
    UTIL::$sharedConfig = array( 'xmlDoc' => $doc, 'pan' => null );
    $load = viewerDecode( viewerRun( 'tag', array( 'location=any', 'actions=display', 'filter=(name eq config-viewer-load)' ) ) );
    if( !$load['ok'] || UTIL::$sharedConfig['pan'] === null )
    {
        UTIL::$sharedConfig = $old;
        return array( 'ok' => FALSE, 'error' => 'the configuration after the undo could not be loaded: ' . ( $load['error'] ?? '' ) );
    }
    unset( $old );
    gc_collect_cycles();
    $unresolved = array_values( array_diff( viewerUnresolved(), $before ) );

    $note['type'] = 'undo';
    $note['undoes'] = trim( ( $c['type'] ?? '' ) . ' ' . ( $c['location'] ?? '' ) . ' ' . ( $c['filter'] ?? '' ) . ' -> ' . ( $c['actions'] ?? '' ) );
    $note['reverts'] = $c['commit'];
    $note['index'] = $index;
    $sha = viewerHistoryCommit( $note );
    $warning = null;
    if( $sha !== null && $git->tree( $sha ) !== $tree )
    {
        // pan-os-php loaded the configuration a little differently (e.g. it creates a tag that is used but missing):
        // the commit holds what is in memory - said with the entries
        $diff = array();
        foreach( $git->diff( $tree, $sha ) as $path => $st )
            $diff[] = ( $st === 'A' ? 'added ' : ( $st === 'D' ? 'removed ' : 'changed ' ) ) . $path;
        $warning = 'pan-os-php changed the configuration when it loaded it after the undo: ' . implode( ', ', array_slice( $diff, 0, 10 ) );
        viewerLog( 'undo: ' . $warning );
    }
    $changes[$index]['undone'] = TRUE;
    $entry = array( 'time' => $note['time'] ?? time(), 'user' => $note['user'] ?? '', 'type' => 'undo', 'undoes' => $note['undoes'], 'index' => $index );
    if( $sha !== null )
        $entry['commit'] = $sha;
    $changes[] = $entry;
    $GLOBALS['viewerState']['dirty'] = TRUE;
    return array( 'ok' => TRUE, 'unresolved' => $unresolved, 'warning' => $warning );
}

/** saved as a new version: it is the state of the last commit */
function viewerHistorySaved( string $newFile ): void
{
    $h = &$GLOBALS['viewerHistory'];
    if( !isset( $h['git'] ) )
        return;
    try
    {
        $key = basename( $newFile, '.xml' );
        $h['git']->setRef( 'refs/viewer/versions/' . $key, $h['head'] );
        $h['git']->setRef( 'refs/viewer/work/' . $key, $h['head'] );
        $h['git']->deleteRef( 'refs/viewer/work/' . $h['key'] );
        $h['key'] = $key;
        $h['commits'] = 0;
    }
    catch( Throwable $e )
    {
        viewerLog( 'history: ' . $e->getMessage() );
        $h = array( 'commits' => 0, 'error' => 'stopped: ' . $e->getMessage() );
    }
}

/** the unsaved changes discarded */
function viewerHistoryDiscard(): void
{
    $h = $GLOBALS['viewerHistory'] ?? array();
    if( isset( $h['git'] ) )
        try { $h['git']->deleteRef( 'refs/viewer/work/' . $h['key'] ); } catch( Throwable $e ) { }
}

function viewerWrite( $path )
{
    $tmp = $path . '.tmp';
    UTIL::$sharedConfig['pan']->save_to_file( $tmp, FALSE );
    if( !is_file( $tmp ) || filesize( $tmp ) < 10 )
        return FALSE;
    return viewerQuiet( function() use ( $tmp, $path ) { chmod( $tmp, 0600 ); return rename( $tmp, $path ); } );
}

/** one pan-os-php run on the configuration in memory; returns the JSON output as text */
function viewerRun( $type, array $args )
{
    global $configFile;
    // 'x-computed' is no pan-os-php argument: the API object model also gets its computed values (_panosphp)
    ApiObjectModel::$withComputed = in_array( 'x-computed', $args, TRUE );
    // 'x-refcount': count the users of every object of the read ("location|name" => number, $GLOBALS['viewerRefcounts'])
    $refcount = in_array( 'x-refcount', $args, TRUE );
    // 'x-xml': the XML of every object of the read and its entry in the history ("location|template|name" => path, xml)
    $withXml = in_array( 'x-xml', $args, TRUE );
    $args = array_values( array_diff( $args, array( 'x-computed', 'x-refcount', 'x-xml' ) ) );
    // 'x-override': same name on other levels (pan-os-php getSameNameOverrideInfo - as the filters is.overriden /
    // is.overriding and the object-merger): which copies an object overrides, where it is overridden
    $override = in_array( 'x-override', $args, TRUE );
    $args = array_values( array_diff( $args, array( 'x-override' ) ) );
    // 'x-effective=<location>': which copy of each name a firewall of this location gets (effective view)
    $effectiveAt = null;
    foreach( $args as $i => $a )
        if( strpos( $a, 'x-effective=' ) === 0 )
        {
            $effectiveAt = substr( $a, 12 );
            unset( $args[$i] );
        }
    $args = array_values( $args );
    // 'x-bp=<file>' is no pan-os-php argument either: the BP JSON of the project for this one run (checks, computed
    // verdicts, alert-only-set / best-practice-set). Only a file of the folder "files" of this project; afterwards the
    // BP JSON the configuration was loaded with is used again.
    $bp = null;
    foreach( $args as $i => $a )
        if( strpos( $a, 'x-bp=' ) === 0 )
        {
            $bp = substr( $a, 5 );
            unset( $args[$i] );
        }
    $args = array_values( $args );
    // the BP JSON the configuration was loaded with: taken when it is first replaced (the load has set it by then)
    static $defaultBp = null;
    if( $bp !== null )
    {
        if( $defaultBp === null )
            $defaultBp = array( PH::$shadow_bp_jsonfilename );
        if( !preg_match( '#^' . preg_quote( dirname( $configFile ) . '/files/', '#' ) . '[0-9a-f]{32}\.json$#', $bp ) || !is_file( $bp ) )
            return json_encode( array( 'error' => 'BP JSON file of the project not found' ) );
        PH::$shadow_bp_jsonfilename = $bp;
        PH::$shadow_bp_jsonfile = null;
    }
    $argv = array_merge( array( 'config-viewer', 'in=' . $configFile, 'shadow-json' ), $args );
    $argc = count( $argv );
    PH::resetCliArgs( $argv );
    PH::$JSON_OUT = array();
    PH::$JSON_TMP = array();
    PH::$JSON_OUTlog = '';
    ob_start();
    $util = PH::callPANOSPHP( $type, $argv, $argc, 'config-viewer' );
    if( $refcount )
    {
        $GLOBALS['viewerRefcounts'] = array();
        foreach( is_array( $util->objectsToProcess ?? null ) ? $util->objectsToProcess : array() as $set )
            foreach( viewerSetObjects( $set ) as $o )
                if( is_object( $o ) && isset( $o->refrules ) && method_exists( $o, 'name' ) )
                    // "location|template|name" - a DNS rule / threat rule "…|profile/name" (PH::jsonObjectKey)
                    $GLOBALS['viewerRefcounts'][viewerRowKey( $o )] = count( viewerUsers( $o ) );
    }
    if( $effectiveAt !== null )
        $GLOBALS['viewerEffective'] = viewerEffective( $util, $effectiveAt );
    if( $override )
        $GLOBALS['viewerOverride'] = viewerOverride( $util );
    if( $withXml )
    {
        // only the object of the window: objectsToProcess holds every object of the location (the filter is applied
        // by the actions) - before, the first 20 of the location were taken: an object further back (e.g. an address
        // group after the addresses) had no XML, and every read paid the paths of 20 objects (ConfigObjectSplit::
        // entryPath walks the whole document - about 1 s on a big configuration)
        $xmlName = null;
        foreach( $args as $a )
            if( preg_match( '/^filter=\(name eq (.+)\)$/s', $a, $m ) )
                $xmlName = $m[1];
        $GLOBALS['viewerXml'] = array();
        foreach( is_array( $util->objectsToProcess ?? null ) ? $util->objectsToProcess : array() as $set )
            foreach( viewerSetObjects( $set ) as $o )
                if( is_object( $o ) && isset( $o->xmlroot ) && $o->xmlroot instanceof DOMElement && method_exists( $o, 'name' )
                    && ( $xmlName === null ? count( $GLOBALS['viewerXml'] ) < 20 : $o->name() === $xmlName ) && count( $GLOBALS['viewerXml'] ) < 50 )
                {
                    $GLOBALS['viewerXml'][viewerRowKey( $o )] = array( 'path' => viewerHistoryPath( $o ),
                        'xml' => substr( ConfigObjectSplit::canonical( $o->xmlroot ), 0, 200000 ) );
                }
    }
    unset( $util );
    $out = (string)ob_get_clean();
    if( $bp !== null )
    {
        PH::$shadow_bp_jsonfilename = $defaultBp[0];
        PH::$shadow_bp_jsonfile = null;
    }
    return $out;
}

function viewerDecode( $out )
{
    $start = strpos( $out, '{' );
    $json = $start === FALSE ? null : json_decode( substr( $out, $start ), TRUE );
    if( is_array( $json ) && !isset( $json['error'] ) )
        return array( 'ok' => TRUE, 'json' => $json );
    $msg = '';
    if( is_array( $json ) )
        $msg = is_string( $json['error'] ) ? $json['error'] : json_encode( $json['error'] );
    elseif( preg_match( '/\*\*ERROR\*\*\s*(.+)/', $out, $m ) )
        $msg = $m[1];
    return array( 'ok' => FALSE, 'error' => trim( $msg ) !== '' ? trim( $msg ) : 'pan-os-php stopped with an error - check the syntax of filter / actions' );
}

function viewerSend( $conn, array $answer )
{
    viewerQuiet( function() use ( $conn, $answer ) {
        if( is_resource( $conn ) )
        {
            fwrite( $conn, json_encode( $answer, JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE ) );
            fclose( $conn );
        }
    } );
}

/**
 * Runs in a forked child and never returns. The answer is sent from a shutdown function, so an exit() inside
 * pan-os-php still gives an answer. $send = FALSE: only the exit code tells whether the run worked (trial of a change).
 */
function viewerChild( $conn, $type, array $args, $send )
{
    $GLOBALS['viewerIsChild'] = TRUE;
    pcntl_alarm( 600 );
    $done = FALSE;
    register_shutdown_function( function() use ( $conn, $send, &$done ) {
        $out = '';
        while( ob_get_level() > 0 )
            $out = (string)ob_get_clean() . $out;
        $r = viewerDecode( $out );
        if( isset( $GLOBALS['viewerRefcounts'] ) && $r['ok'] )
            $r['refcounts'] = $GLOBALS['viewerRefcounts'];
        if( isset( $GLOBALS['viewerEffective'] ) && $r['ok'] )
            $r['effective'] = $GLOBALS['viewerEffective'];
        if( isset( $GLOBALS['viewerOverride'] ) && $r['ok'] )
            $r['override'] = $GLOBALS['viewerOverride'];
        if( isset( $GLOBALS['viewerXml'] ) && $r['ok'] )
            $r['xml'] = $GLOBALS['viewerXml'];
        if( !$done && $r['ok'] )
            $r = array( 'ok' => FALSE, 'error' => 'the run stopped' );
        if( $send || !$r['ok'] )
            viewerSend( $conn, $r + array( 'status' => viewerStatus() ) );
        posix_kill( getmypid(), $r['ok'] ? SIGUSR1 : SIGKILL );
    } );
    try
    {
        ob_start();
        print viewerRun( $type, $args );
        $done = TRUE;
    }
    catch( Throwable $e )
    {
        while( ob_get_level() > 0 )
            ob_end_clean();
        ob_start();
        print json_encode( array( 'error' => $e->getMessage() ) );
    }
    exit( 0 );
}

register_shutdown_function( function() use ( $sockFile, $pidFile, $autosaveFile ) {
    if( $GLOBALS['viewerIsChild'] )
        return;
    // the worker stops: unsaved changes go to the autosave file, the viewer turns it into a version
    if( $GLOBALS['viewerState']['dirty'] && isset( UTIL::$sharedConfig['pan'] ) && UTIL::$sharedConfig['pan'] !== null )
    {
        try { viewerWrite( $autosaveFile ); } catch( Throwable $e ) { }
    }
    viewerUnlink( $sockFile );
    viewerUnlink( $pidFile );
} );

$repo = dirname( __FILE__ ) . '/../../../..';
require_once $repo . '/lib/pan_php_framework.php';
require_once $repo . '/utils/lib/UTIL.php';
require_once dirname( __FILE__ ) . '/../lib/ViewerGit.php';
require_once $repo . '/utils/common/ConfigSection.php';

// ---- load once
$doc = new DOMDocument();
if( !$doc->load( $configFile, XML_PARSE_BIG_LINES | LIBXML_NONET ) )
{
    viewerLog( 'configuration can not be read' );
    exit( 5 );
}
UTIL::$sharedConfig = array( 'xmlDoc' => $doc, 'pan' => null );
// location=any: an SCM configuration has no 'shared' (its containers are 'All', folders, snippets)
$first = viewerDecode( viewerRun( 'tag', array( 'location=any', 'actions=display', 'filter=(name eq config-viewer-load)' ) ) );
if( !$first['ok'] || UTIL::$sharedConfig['pan'] === null )
{
    viewerLog( 'configuration can not be loaded: ' . ( $first['error'] ?? '' ) );
    exit( 6 );
}
viewerHistoryStart( $configFile );

viewerUnlink( $sockFile );
$old = umask( 0177 );
$server = viewerQuiet( function() use ( $sockFile, &$errstr ) { return stream_socket_server( 'unix://' . $sockFile, $errno, $errstr ); } );
umask( $old );
if( !$server )
{
    viewerLog( 'socket: ' . $errstr );
    exit( 7 );
}
pcntl_signal( SIGUSR1, SIG_DFL );
// a stopped worker (kill, shutdown of the server) still writes its unsaved changes to the autosave file
pcntl_async_signals( TRUE );
foreach( array( SIGTERM, SIGINT, SIGHUP ) as $sig )
    pcntl_signal( $sig, function() { if( !$GLOBALS['viewerIsChild'] ) exit( 0 ); posix_kill( getmypid(), SIGKILL ); } );
$lastUsed = time();
$lastAutosave = time();
$trials = array();

while( TRUE )
{
    // reap finished children
    while( ( $done = pcntl_waitpid( -1, $st, WNOHANG ) ) > 0 )
        unset( $trials[$done] );

    $read = array( $server );
    $write = null;
    $except = null;
    $n = viewerQuiet( function() use ( &$read, &$write, &$except ) { return stream_select( $read, $write, $except, 15 ); } );

    if( $GLOBALS['viewerState']['dirty'] && time() - $lastAutosave >= $autosaveSec )
    {
        try
        {
            if( viewerWrite( $autosaveFile ) )
                $GLOBALS['viewerState']['autosaved'] = time();
        }
        catch( Throwable $e ) { viewerLog( 'autosave failed: ' . $e->getMessage() ); }
        $lastAutosave = time();
    }
    if( time() - $lastUsed > $idleSec )
        exit( 0 );
    if( $n === FALSE || $n === 0 )
        continue;

    $conn = viewerQuiet( function() use ( $server ) { return stream_socket_accept( $server, 5 ); } );
    if( !$conn )
        continue;
    stream_set_timeout( $conn, 10 );
    $cmd = json_decode( (string)viewerQuiet( function() use ( $conn ) { return fgets( $conn, 1048576 ); } ), TRUE );
    if( !is_array( $cmd ) || !isset( $cmd['cmd'] ) )
    {
        viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad request' ) );
        continue;
    }
    $lastUsed = time();
    $type = isset( $cmd['type'] ) && is_string( $cmd['type'] ) ? $cmd['type'] : '';
    $args = isset( $cmd['args'] ) && is_array( $cmd['args'] ) ? array_values( array_filter( $cmd['args'], 'is_string' ) ) : array();

    if( $cmd['cmd'] === 'status' )
        viewerSend( $conn, array( 'ok' => TRUE, 'status' => viewerStatus() ) );
    elseif( $cmd['cmd'] === 'references' )
    {
        // in a child, like a read: whatever pan-os-php does on the way can not hurt the loaded configuration
        $name = isset( $cmd['name'] ) && is_string( $cmd['name'] ) ? $cmd['name'] : '';
        // a DNS rule / threat rule: the one of this security profile (the same name is in several profiles)
        $profile = isset( $cmd['profile'] ) && is_string( $cmd['profile'] ) && $cmd['profile'] !== '' ? $cmd['profile'] : null;
        $child = pcntl_fork();
        if( $child === 0 )
        {
            fclose( $server );
            $GLOBALS['viewerIsChild'] = TRUE;
            pcntl_alarm( 300 );
            $sent = FALSE;
            register_shutdown_function( function() use ( $conn, &$sent ) {
                while( ob_get_level() > 0 )
                    ob_end_clean();
                if( !$sent )
                    viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'the references could not be read' ) );
                posix_kill( getmypid(), SIGKILL );
            } );
            try { $r = array( 'ok' => TRUE, 'objects' => viewerReferences( $type, $args, $name, $profile ) ); }
            catch( Throwable $e ) { $r = array( 'ok' => FALSE, 'error' => 'references: ' . $e->getMessage() ); }
            while( ob_get_level() > 0 )
                ob_end_clean();
            viewerSend( $conn, $r );
            $sent = TRUE;
            exit( 0 );
        }
        viewerQuiet( function() use ( $conn ) { fclose( $conn ); } );
        if( $child < 0 )
            viewerLog( 'fork failed' );
    }
    elseif( $cmd['cmd'] === 'system' )
    {
        $tpl = isset( $cmd['template'] ) && is_string( $cmd['template'] ) && $cmd['template'] !== '' ? $cmd['template'] : null;
        $at = isset( $cmd['location'] ) && is_string( $cmd['location'] ) && $cmd['location'] !== '' ? $cmd['location'] : null;
        try { $r = array( 'ok' => TRUE ) + viewerSystem( $tpl, $at ); } catch( Throwable $e ) { $r = array( 'ok' => FALSE, 'error' => 'system: ' . $e->getMessage() ); }
        viewerSend( $conn, $r );
    }
    elseif( $cmd['cmd'] === 'locations' )
    {
        try { $r = array( 'ok' => TRUE ) + viewerLocations(); } catch( Throwable $e ) { $r = array( 'ok' => FALSE, 'error' => 'locations: ' . $e->getMessage() ); }
        viewerSend( $conn, $r );
    }
    elseif( $cmd['cmd'] === 'close' )
    {
        $GLOBALS['viewerState']['dirty'] = FALSE; // discard
        viewerHistoryDiscard();
        viewerUnlink( $autosaveFile );
        viewerSend( $conn, array( 'ok' => TRUE ) );
        exit( 0 );
    }
    elseif( $cmd['cmd'] === 'read' )
    {
        $child = pcntl_fork();
        if( $child === 0 )
        {
            fclose( $server );
            viewerChild( $conn, $type, $args, TRUE );
        }
        viewerQuiet( function() use ( $conn ) { fclose( $conn ); } );
        if( $child < 0 )
            viewerLog( 'fork failed' );
    }
    elseif( $cmd['cmd'] === 'change' )
    {
        // 1. trial in a child: a failing action must not stop or half-change the loaded configuration
        $child = pcntl_fork();
        if( $child === 0 )
        {
            fclose( $server );
            viewerChild( $conn, $type, $args, FALSE );
        }
        if( $child < 0 )
        {
            viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'fork failed' ) );
            continue;
        }
        pcntl_waitpid( $child, $st );
        if( !( pcntl_wifsignaled( $st ) && pcntl_wtermsig( $st ) === SIGUSR1 ) )
        {
            viewerQuiet( function() use ( $conn ) { fclose( $conn ); } ); // the child sent the error already
            continue;
        }
        // 2. the real run on the memory
        try
        {
            $r = viewerDecode( viewerRun( $type, $args ) );
        }
        catch( Throwable $e )
        {
            $r = array( 'ok' => FALSE, 'error' => $e->getMessage() );
        }
        if( $r['ok'] )
        {
            if( !$GLOBALS['viewerState']['dirty'] )
                $lastAutosave = time();
            $GLOBALS['viewerState']['dirty'] = TRUE;
            // the change as data (ViewerApp::change): time, user, type, location, filter, actions, field; text from older viewers
            $note = $cmd['note'] ?? $type;
            if( is_array( $note ) )
            {
                $clean = array();
                foreach( array( 'time', 'user', 'type', 'location', 'template', 'filter', 'actions', 'ruletype', 'securityprofiletype', 'field', 'section' ) as $k )
                    if( isset( $note[$k] ) && is_scalar( $note[$k] ) )
                        $clean[$k] = is_string( $note[$k] ) ? substr( $note[$k], 0, 2000 ) : $note[$k];
                $clean['args'] = array_slice( array_map( function( $a ) { return substr( (string)$a, 0, 2000 ); }, array_filter( (array)( $note['args'] ?? array() ), 'is_scalar' ) ), 0, 10 );
                $note = $clean;
            }
            else
                $note = substr( (string)$note, 0, 500 );
            $sha = viewerHistoryCommit( $note );
            if( is_array( $note ) && $sha !== null )
                $note['commit'] = $sha;
            $GLOBALS['viewerState']['changes'][] = $note;
        }
        viewerSend( $conn, $r + array( 'status' => viewerStatus() ) );
    }
    elseif( $cmd['cmd'] === 'undo' )
    {
        $note = array();
        foreach( array( 'time', 'user' ) as $k )
            if( isset( $cmd['note'][$k] ) && is_scalar( $cmd['note'][$k] ) )
                $note[$k] = is_string( $cmd['note'][$k] ) ? substr( $cmd['note'][$k], 0, 200 ) : $cmd['note'][$k];
        try { $r = viewerUndo( is_int( $cmd['index'] ?? null ) ? $cmd['index'] : -1, $note ); }
        catch( Throwable $e ) { $r = array( 'ok' => FALSE, 'error' => 'undo: ' . $e->getMessage() ); }
        viewerSend( $conn, $r + array( 'status' => viewerStatus() ) );
    }
    elseif( $cmd['cmd'] === 'save' )
    {
        $file = isset( $cmd['file'] ) && is_string( $cmd['file'] ) ? $cmd['file'] : '';
        // only into the folder of this project, only a new *.xml file
        if( !$GLOBALS['viewerState']['dirty'] )
            viewerSend( $conn, array( 'ok' => TRUE, 'saved' => FALSE, 'status' => viewerStatus() ) );
        elseif( dirname( $file ) !== dirname( $configFile ) || !preg_match( '/^[0-9a-f]{32}\.xml$/', basename( $file ) ) || file_exists( $file ) )
            viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad target' ) );
        else
        {
            try { $ok = viewerWrite( $file ); } catch( Throwable $e ) { $ok = FALSE; viewerLog( 'save failed: ' . $e->getMessage() ); }
            if( !$ok )
                viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'the configuration could not be written' ) );
            else
            {
                $changes = $GLOBALS['viewerState']['changes'];
                $GLOBALS['viewerState']['dirty'] = FALSE;
                $GLOBALS['viewerState']['changes'] = array();
                $GLOBALS['viewerState']['saved'] = time();
                viewerUnlink( $autosaveFile );
                viewerHistorySaved( $file );
                $configFile = $file;
                viewerSend( $conn, array( 'ok' => TRUE, 'saved' => TRUE, 'changes' => $changes, 'status' => viewerStatus() ) );
            }
        }
    }
    else
        viewerSend( $conn, array( 'ok' => FALSE, 'error' => 'bad request' ) );
}
