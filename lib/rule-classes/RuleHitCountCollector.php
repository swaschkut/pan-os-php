<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
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
 * Security rule hit count of every firewall / vsys a rule is pushed to, with as few API calls as possible.
 *
 * Every firewall/vsys is asked ONCE per rulebase for all of its rules
 *   <show><rule-hit-count><vsys><vsys-name><entry name="VSYS"><rule-base><entry name="security"><rules><all/>
 * and the answer is cached for the whole run. Panorama is asked once for its connected firewalls
 * (hostname, PAN-OS version, HA state). For an export of N rules over F firewall/vsys this means
 * 1 + F API calls instead of 4 * N.
 *
 * Which firewalls belong to a rule:
 *   DeviceGroup rule      all firewalls/vsys of the DeviceGroup and its child DeviceGroups
 *   shared rule           all firewalls/vsys of all DeviceGroups
 *   VSYS rule (firewall)  the firewall itself
 *
 * Aggregation over the firewalls (rule usage data is not synced between HA peers, every firewall counts its own traffic):
 *   hit-count                                sum
 *   last-hit / last-reset / rule-modification latest
 *   first-hit / rule-creation                earliest (0 = never / unknown is ignored)
 *   latest                                   'yes' only if every firewall reports 'yes'
 */
class RuleHitCountCollector
{
    const STATUS_OK = 'ok';
    const STATUS_NOT_CONNECTED = 'not connected';
    const STATUS_RULE_NOT_FOUND = 'rule not on device';
    const STATUS_NO_DATA = 'no hit-count data';

    /** @var array  [connectorKey][serial/vsys/rulebase] => [ruleName => values] | null (no data) */
    private static $hitCache = array();

    /** @var array  [connectorKey] => panorama_getConnectedFirewallsSerials() */
    private static $connectedCache = array();

    /** @var int  number of API calls sent by this class, for tests / shadow-apicalls output */
    public static $apiCalls = 0;

    private static $fields = array( 'latest', 'hit-count', 'last-hit-timestamp', 'last-reset-timestamp', 'first-hit-timestamp',
        'rule-creation-timestamp', 'rule-modification-timestamp' );

    public static function supports( Rule $rule ): bool
    {
        if( self::ruleBaseOf($rule) === null )
            return FALSE;

        $system = $rule->owner->owner;

        return $system->isDeviceGroup() || $system->isPanorama() || $system->isVirtualSystem();
    }

    /**
     * firewall rulebase name: security rules and the default security rules (intrazone-default / interzone-default)
     */
    private static function ruleBaseOf( Rule $rule ): ?string
    {
        $nature = $rule->ruleNature();
        if( $nature === 'security' || $nature === 'defaultSecurity' )
            return 'security';
        return null;
    }

    public static function reset(): void
    {
        self::$hitCache = array();
        self::$connectedCache = array();
        self::$apiCalls = 0;
    }

    /**
     * @return array|null  same keys / formats as Rule::API_showRuleHitCount():
     *                     latest, hit-count, last-hit, last-reset, first-hit, rule-creation, rule-modification
     *                     plus 'per-device' => [serial/vsys => hostname, serial, vsys, ha-state, sw-version, status, hit-count, last-hit, ...]
     *                     null if the rule type / location is not supported
     */
    public static function forRule( Rule $rule ): ?array
    {
        if( !self::supports($rule) )
            return null;

        $system = $rule->owner->owner;
        $connector = findConnectorOrDie($rule);
        $ruleBase = self::ruleBaseOf($rule);

        $perDevice = array();
        foreach( self::devicesOf($system, $connector) as $device )
        {
            foreach( $device['vsyslist'] as $vsys )
            {
                $deviceKey = $device['serial'].'/'.$vsys;
                $line = array(
                    'hostname' => $device['hostname'],
                    'serial' => $device['serial'],
                    'vsys' => $vsys,
                    'ha-state' => $device['ha-state'],
                    'sw-version' => $device['sw-version'],
                    'status' => self::STATUS_OK );

                if( !$device['connected'] )
                    $line['status'] = self::STATUS_NOT_CONNECTED;
                else
                {
                    $rules = self::hitCountOf( $device['connector'], $connector, $device['serial'], $vsys, $ruleBase, $device['version'] );
                    if( $rules === null )
                        $line['status'] = self::STATUS_NO_DATA;
                    elseif( !isset($rules[$rule->name()]) )
                        $line['status'] = self::STATUS_RULE_NOT_FOUND;
                    else
                        $line['values'] = $rules[$rule->name()];
                }

                $perDevice[$deviceKey] = $line;
            }
        }

        return self::aggregate( $perDevice );
    }

    /**
     * Structured text, one line per firewall/vsys, used for the 'hit-count per firewall' export column.
     * @return string[]
     */
    public static function perDeviceLines( array $hitCountArray ): array
    {
        if( !isset($hitCountArray['per-device']) )
            return array();

        $lines = array();
        foreach( $hitCountArray['per-device'] as $deviceName => $device )
        {
            if( !isset($device['status']) )
            {
                //Rule::API_showRuleHitCount() format (non-security rules): key 'DG/serial/vsys', hit-count, last-hit, first-hit
                $lines[] = $deviceName.' | hits: '.$device['hit-count'].' | last-hit: '.$device['last-hit'].' | first-hit: '.$device['first-hit'];
                continue;
            }

            $name = $device['hostname'];
            if( $device['hostname'] !== $device['serial'] )
                $name .= ' ('.$device['serial'].')';
            $name .= ' / '.$device['vsys'];
            if( $device['ha-state'] !== '' )
                $name .= ' [HA '.$device['ha-state'].']';

            if( $device['status'] !== self::STATUS_OK )
            {
                $lines[] = $name.' | '.$device['status'];
                continue;
            }

            $text = $name.' | hits: '.$device['hit-count'].' | last-hit: '.$device['last-hit'].' | first-hit: '.$device['first-hit'];
            if( $device['last-reset'] !== '0' )
                $text .= ' | last-reset: '.$device['last-reset'];
            $text .= ' | created: '.$device['rule-creation'].' | modified: '.$device['rule-modification'];
            $lines[] = $text;
        }

        return $lines;
    }

    private static function aggregate( array $perDevice ): array
    {
        $aggregated = array( 'latest' => null, 'hit-count' => 0,
            'last-hit-timestamp' => 0, 'last-reset-timestamp' => 0, 'first-hit-timestamp' => 0,
            'rule-creation-timestamp' => 0, 'rule-modification-timestamp' => 0 );
        $found = array();

        foreach( $perDevice as $deviceKey => $device )
        {
            $values = isset($device['values']) ? $device['values'] : array();
            unset($perDevice[$deviceKey]['values']);

            foreach( $values as $field => $value )
                $found[$field] = TRUE;

            if( isset($values['latest']) )
                $aggregated['latest'] = ( $aggregated['latest'] === 'no' || $values['latest'] !== 'yes' ) ? 'no' : 'yes';
            if( isset($values['hit-count']) )
                $aggregated['hit-count'] += (int)$values['hit-count'];
            foreach( array('last-hit-timestamp', 'last-reset-timestamp', 'rule-modification-timestamp') as $latestField )
            {
                if( isset($values[$latestField]) )
                    $aggregated[$latestField] = max( $aggregated[$latestField], (int)$values[$latestField] );
            }
            foreach( array('first-hit-timestamp', 'rule-creation-timestamp') as $earliestField )
            {
                if( isset($values[$earliestField]) && (int)$values[$earliestField] > 0
                    && ($aggregated[$earliestField] == 0 || (int)$values[$earliestField] < $aggregated[$earliestField]) )
                    $aggregated[$earliestField] = (int)$values[$earliestField];
            }

            if( $device['status'] === self::STATUS_OK )
            {
                $perDevice[$deviceKey]['hit-count'] = isset($values['hit-count']) ? (string)(int)$values['hit-count'] : '';
                $perDevice[$deviceKey]['last-hit'] = self::date( $values, 'last-hit-timestamp' );
                $perDevice[$deviceKey]['last-reset'] = self::date( $values, 'last-reset-timestamp' );
                $perDevice[$deviceKey]['first-hit'] = self::date( $values, 'first-hit-timestamp' );
                $perDevice[$deviceKey]['rule-creation'] = self::date( $values, 'rule-creation-timestamp' );
                $perDevice[$deviceKey]['rule-modification'] = self::date( $values, 'rule-modification-timestamp' );
            }
        }

        $result = array();
        if( isset($found['latest']) )
            $result['latest'] = $aggregated['latest'];
        if( isset($found['hit-count']) )
            $result['hit-count'] = (string)$aggregated['hit-count'];
        foreach( array('last-hit', 'last-reset', 'first-hit', 'rule-creation', 'rule-modification') as $key )
        {
            if( isset($found[$key.'-timestamp']) )
                $result[$key] = self::date( $aggregated, $key.'-timestamp' );
        }
        $result['per-device'] = $perDevice;

        return $result;
    }

    private static function date( array $values, $field ): string
    {
        if( !isset($values[$field]) || (int)$values[$field] == 0 )
            return "0";
        return date( 'Y-m-d H:i:s', (int)$values[$field] );
    }

    /**
     * @return array[]  serial => [serial, hostname, vsyslist, connected, connector, version, sw-version, ha-state]
     */
    private static function devicesOf( $system, PanAPIConnector $connector ): array
    {
        if( $system->isVirtualSystem() )
        {
            if( empty($connector->info_serial) || empty($connector->info_PANOS_version_int) )
            {
                $connector->refreshSystemInfos();
                self::$apiCalls++;
            }

            $serial = $connector->info_serial;
            return array( $serial => array( 'serial' => $serial, 'hostname' => (string)$connector->info_hostname,
                'vsyslist' => array( $system->name() => $system->name() ), 'connected' => TRUE, 'connector' => $connector,
                'version' => (int)$connector->info_PANOS_version_int, 'sw-version' => (string)$connector->info_PANOS_version, 'ha-state' => '' ) );
        }

        if( $system->isDeviceGroup() )
            $devices = $system->getDevicesInGroup(TRUE);
        else
        {
            //shared: pushed to every firewall of every DeviceGroup
            $devices = array();
            foreach( $system->getDeviceGroups() as $deviceGroup )
            {
                foreach( $deviceGroup->getDevicesInGroup(FALSE) as $serial => $device )
                {
                    if( !isset($devices[$serial]) )
                        $devices[$serial] = $device;
                    else
                        $devices[$serial]['vsyslist'] = $devices[$serial]['vsyslist'] + $device['vsyslist'];
                }
            }
        }
        ksort($devices);

        $panorama = $system->isDeviceGroup() ? $system->owner : $system;
        $connected = self::connectedFirewalls( $connector, $panorama );

        $result = array();
        foreach( $devices as $device )
        {
            $serial = $device['serial'];
            $vsyslist = $device['vsyslist'];
            if( count($vsyslist) == 0 )
                $vsyslist = array( 'vsys1' => 'vsys1' );
            ksort($vsyslist);

            $info = isset($connected[$serial]) ? $connected[$serial] : null;
            $swVersion = ($info !== null && isset($info['sw-version'])) ? $info['sw-version'] : '';

            $result[$serial] = array(
                'serial' => $serial,
                'hostname' => ($info !== null && isset($info['hostname'])) ? $info['hostname'] : $serial,
                'vsyslist' => $vsyslist,
                'connected' => $info !== null,
                'connector' => null,
                'version' => self::versionInt( $swVersion ),
                'sw-version' => $swVersion,
                'ha-state' => ($info !== null && isset($info['ha-state'])) ? $info['ha-state'] : '' );
        }

        return $result;
    }

    private static function connectedFirewalls( PanAPIConnector $connector, $panorama ): array
    {
        $key = spl_object_hash($connector);
        if( !isset(self::$connectedCache[$key]) )
        {
            //PanoramaConf already asked Panorama while loading the config in API mode
            if( isset($panorama->managedFirewallsSerialsModel) && is_array($panorama->managedFirewallsSerialsModel)
                && count($panorama->managedFirewallsSerialsModel) > 0 )
            {
                self::$connectedCache[$key] = $panorama->managedFirewallsSerialsModel;
                return self::$connectedCache[$key];
            }

            self::$connectedCache[$key] = $connector->panorama_getConnectedFirewallsSerials();
            self::$apiCalls++;
        }

        return self::$connectedCache[$key];
    }

    private static function versionInt( $swVersion ): int
    {
        if( !preg_match('/^(\d+)\.(\d+)/', $swVersion, $matches) )
            return 0;
        return (int)$matches[1] * 10 + (int)$matches[2];
    }

    /**
     * Hit count of all rules of one firewall/vsys and rulebase - one API call, cached.
     * @return array|null  ruleName => values ; null if the firewall cannot deliver hit-count data (PAN-OS < 8.1)
     */
    private static function hitCountOf( $deviceConnector, PanAPIConnector $connector, $serial, $vsys, $ruleBase, $version ): ?array
    {
        $cacheKey = $serial.'/'.$vsys.'/'.$ruleBase;
        $connectorKey = spl_object_hash($connector);
        if( isset(self::$hitCache[$connectorKey]) && array_key_exists($cacheKey, self::$hitCache[$connectorKey]) )
            return self::$hitCache[$connectorKey][$cacheKey];

        if( $version > 0 && $version < 81 )
        {
            PH::print_stdout( "   - firewall/vsys '".$serial."/".$vsys."' runs PAN-OS < 8.1: no hit-count data" );
            self::$hitCache[$connectorKey][$cacheKey] = null;
            return null;
        }

        if( $deviceConnector === null )
        {
            $deviceConnector = $connector->cloneForPanoramaManagedDevice($serial);
            $deviceConnector->setShowApiCalls($connector->showApiCalls);
        }

        $apiCmd = '<show><rule-hit-count><vsys><vsys-name><entry%20name="' . $vsys . '"><rule-base><entry%20name="' . $ruleBase . '"><rules>';
        $apiCmd .= '<all></all>';
        $apiCmd .= '</rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>';

        $apiResult = $deviceConnector->sendCmdRequest($apiCmd);
        self::$apiCalls++;

        $rules = array();
        $rulesXml = DH::findXPath('/result/rule-hit-count/vsys/entry/rule-base/entry/rules/entry', $apiResult);
        for( $i = 0; $i < $rulesXml->length; $i++ )
        {
            $ruleNode = $rulesXml->item($i);
            $values = array();
            foreach( $ruleNode->childNodes as $node )
            {
                if( $node->nodeType == XML_ELEMENT_NODE && in_array($node->nodeName, self::$fields, TRUE) )
                    $values[$node->nodeName] = $node->nodeName === 'latest' ? $node->textContent : (int)$node->textContent;
            }
            $rules[$ruleNode->getAttribute('name')] = $values;
        }

        if( $connector->showApiCalls )
            PH::print_stdout( "rule hit-count '".$ruleBase."' of firewall/vsys '".$serial."/".$vsys."': ".count($rules)." rules" );

        self::$hitCache[$connectorKey][$cacheKey] = $rules;

        return $rules;
    }
}
