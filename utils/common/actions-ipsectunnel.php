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

IPsectunnelCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( IPsectunnelCallContext $context )
    {
        $object = $context->object;


        $text = $context->padding." - "."Tunnel: " . str_pad($object->name(), 25) . " - IKE Gateway: " . $object->gateway;
        $text .= " - interface: " . $object->interface . " - proposal: " . $object->proposal;
        $text .= " -disabled: " . $object->disabled;
        PH::print_stdout($text);

        foreach( $object->proxyIdList() as $proxyId )
        {
            $text = $context->padding."   - Name: " . $proxyId['name'] . " - ";
            $text .= "local: " . $proxyId['local'] . " - ";
            $text .= "remote: " . $proxyId['remote'] . " - ";
            $text .= "protocol: " . $proxyId['protocol']['type'] . " - ";
            $text .= "local-port: " . $proxyId['protocol']['localport'] . " - ";
            $text .= "remote-port: " . $proxyId['protocol']['remoteport'] . " - ";
            $text .= "type: " . $proxyId['type'];
            PH::print_stdout($text);
        }


        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
        }

        PH::print_stdout();
    },

);

IPsectunnelCallContext::$supportedActions[] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (IPsectunnelCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (IPsectunnelCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (IPsectunnelCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $lines = '';


        $addWhereUsed = FALSE;
        $addUsedInLocation = FALSE;

        $optionalFields = &$context->arguments['additionalFields'];

        if( isset($optionalFields['WhereUsed']) )
            $addWhereUsed = TRUE;

        if( isset($optionalFields['UsedInLocation']) )
            $addUsedInLocation = TRUE;


        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th>';

        $headers .= '<th>gateway</th><th>interface</th><th>proposal</th><th>disabled</th><th>proxyID</th>';

        if( $addWhereUsed )
            $headers .= '<th>where used</th>';
        if( $addUsedInLocation )
            $headers .= '<th>location used</th>';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var IPsecTunnel $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction( (string)$count );

                #$lines .= $context->encloseFunction(PH::getLocationString($object));
                if( get_class($object->owner->owner) == "PANConf" )
                {
                    // $object->owner->owner is the PANConf (deviceConfiguration) of a template / template stack: the template
                    // (stack) name is its owner (before: compared the PANConf with "Template", so the column was always "---")
                    if( isset($object->owner->owner->owner)
                        && ( $object->owner->owner->owner instanceof Template || $object->owner->owner->owner instanceof TemplateStack )
                    )
                    {
                        $lines .= $context->encloseFunction($object->owner->owner->owner->name());

                        $tmp_vsys = $object->owner->owner->network->findVsysInterfaceOwner($object->name());
                        if( $tmp_vsys !==  null )
                            $lines .= $context->encloseFunction($tmp_vsys->name());
                        else
                            $lines .= $context->encloseFunction(get_class($object->owner->owner));
                    }
                    else
                    {
                        $lines .= $context->encloseFunction("---");

                        $tmp_vsys = $object->owner->owner->network->findVsysInterfaceOwner($object->name());
                        if( $tmp_vsys !==  null )
                            $lines .= $context->encloseFunction($tmp_vsys->name());
                        else
                        {
                            #$lines .= $context->encloseFunction($object->owner->owner->name());
                            $lines .= $context->encloseFunction(get_class($object->owner->owner));
                        }
                    }
                }
                // not a firewall / template (e.g. SCM folder, snippet, device): both cells all the same, so the columns stay in place
                else
                    $lines .= $context->encloseTemplateLocationOther( $object );

                $lines .= $context->encloseFunction($object->name());

                $lines .= $context->encloseFunction($object->gateway);

                $lines .= $context->encloseFunction($object->interface);

                $lines .= $context->encloseFunction($object->proposal);

                $lines .= $context->encloseFunction($object->disabled);

                $tmp_array = array();
                foreach( $object->proxyIdList() as $proxyId )
                {
                    $text = " - " . $proxyId['name'] . " - ";
                    $text .= "local: " . $proxyId['local'] . " - ";
                    $text .= "remote: " . $proxyId['remote'] . " - ";
                    $text .= "protocol: " . $proxyId['protocol']['type'] . " - ";
                    $text .= "local-port: " . $proxyId['protocol']['localport'] . " - ";
                    $text .= "remote-port: " . $proxyId['protocol']['remoteport'] . " - ";
                    $text .= "type: " . $proxyId['type'];
                    $tmp_array[] = $text;
                }
                $lines .= $context->encloseFunction($tmp_array);


                if( $addWhereUsed )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                        $refTextArray[] = $ref->_PANC_shortName();

                    $lines .= $context->encloseFunction($refTextArray);
                }
                if( $addUsedInLocation )
                {
                    $refTextArray = array();
                    foreach( $object->getReferences() as $ref )
                    {
                        $location = PH::getLocationString($object->owner);
                        $refTextArray[$location] = $location;
                    }

                    $lines .= $context->encloseFunction($refTextArray);
                }

                $lines .= "</tr>\n";
            }
        }

        require_once dirname(__FILE__) . '/../lib/ExportToHtmlHelper.php';
        ExportToHtmlHelper::writeHtmlExport($filename, $headers, $lines);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'),
        'additionalFields' =>
            array('type' => 'pipeSeparatedList',
                'subtype' => 'string',
                'default' => '*NONE*',
                'choices' => array('WhereUsed', 'UsedInLocation'),
                'help' =>
                    "pipe(|) separated list of additional field to include in the report. The following is available:\n" .
                    "  - WhereUsed : list places where object is used (rules, groups ...)\n" .
                    "  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n")
    )
);
IPsectunnelCallContext::$supportedActions[] = array_merge(IPsectunnelCallContext::$supportedActions[array_key_last(IPsectunnelCallContext::$supportedActions)], array('name' => 'exportToHtml'));

// ---- changes (offline: an XML file / the config viewer) - one edit… method of the class each (NetworkObjectEdit)

IPsectunnelCallContext::$supportedActions['ike-gateway-set'] = array(
    'name' => 'ike-gateway-Set',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editIkeGateway( $a['gateway'] );
            return "IKE gateway '" . $a['gateway'] . "'";
        } );
    },
    'args' => array( 'gateway' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'IKE gateway - must exist in the location of the tunnel or above it',
);

IPsectunnelCallContext::$supportedActions['ipsec-crypto-profile-set'] = array(
    'name' => 'ipsec-crypto-profile-Set',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editIpsecCryptoProfile( $a['profile'] );
            return "IPsec crypto profile '" . $a['profile'] . "'";
        } );
    },
    'args' => array( 'profile' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'IPsec crypto profile - must exist in the location of the tunnel or above it',
);

IPsectunnelCallContext::$supportedActions['tunnel-interface-set'] = array(
    'name' => 'tunnel-interface-Set',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $found = $o->editTunnelInterface( $a['interface'] );
            return "tunnel interface '" . $a['interface'] . "'" . ( $found ? "" : " (no interface of this name in the location or above it)" );
        } );
    },
    'args' => array( 'interface' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'tunnel interface',
);

IPsectunnelCallContext::$supportedActions['anti-replay-set'] = array(
    'name' => 'anti-replay-Set',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editFlag( 'anti-replay', $a['enable'] );
            return "anti replay " . ( $a['enable'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'enable' => array( 'type' => 'bool', 'default' => '*nodefault*' ) ),
    'help' => 'anti replay',
);

IPsectunnelCallContext::$supportedActions['copy-tos-set'] = array(
    'name' => 'copy-tos-Set',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editFlag( 'copy-tos', $a['enable'] );
            return "copy TOS header " . ( $a['enable'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'enable' => array( 'type' => 'bool', 'default' => '*nodefault*' ) ),
    'help' => 'copy TOS header',
);

IPsectunnelCallContext::$supportedActions['disabled-set'] = array(
    'name' => 'disabled-Set',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editFlag( 'disabled', $a['disabled'] );
            return "disabled " . ( $a['disabled'] ? 'yes' : 'no' );
        } );
    },
    'args' => array( 'disabled' => array( 'type' => 'bool', 'default' => '*nodefault*' ) ),
    'help' => 'disable the tunnel',
);

IPsectunnelCallContext::$supportedActions['tunnel-monitor-set'] = array(
    'name' => 'tunnel-monitor-Set',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editTunnelMonitor( $a['enable'], $a['destination-ip'] );
            return "tunnel monitor " . ( $a['enable'] ? "yes, destination " . $a['destination-ip'] : 'no' );
        } );
    },
    'args' => array( 'enable' => array( 'type' => 'bool', 'default' => '*nodefault*' ), 'destination-ip' => array( 'type' => 'string', 'default' => '' ) ),
    'help' => 'tunnel monitor (with a destination IP)',
);

IPsectunnelCallContext::$supportedActions['proxy-id-add'] = array(
    'name' => 'proxy-id-Add',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editProxyIdAdd( $a['name'], $a['local'], $a['remote'] );
            return "proxy ID '" . $a['name'] . "' " . $a['local'] . " -> " . $a['remote'];
        } );
    },
    'args' => array( 'name' => array( 'type' => 'string', 'default' => '*nodefault*' ), 'local' => array( 'type' => 'string', 'default' => '*nodefault*' ), 'remote' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'add a proxy ID (protocol any)',
);

IPsectunnelCallContext::$supportedActions['proxy-id-remove'] = array(
    'name' => 'proxy-id-Remove',
    'MainFunction' => function ( IPsectunnelCallContext $context ) {
        $context->runEdit( function ( $o, $a ) {
            $o->editProxyIdRemove( $a['name'] );
            return "proxy ID '" . $a['name'] . "' removed";
        } );
    },
    'args' => array( 'name' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => 'remove a proxy ID',
);
