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


// <editor-fold desc=" ***** common actions *****" defaultstate="collapsed" >
//
// Actions with the same definition for several object types. Each is written once and registered for every listed
// type through CallContext::registerAction() (like RQuery::registerFilter in filters-Common.php). A type-specific
// action of the same name in actions-<type>.php wins for that type.
//
// A refused change is SKIPPED with the reason (not an error): a run over many objects goes on; the config viewer
// shows a SKIPPED of its change as an error at the field.

/** $group is $needle or holds it, also through a member group (adding $group to $needle would be a loop) */
function commonGroupContains( $group, $needle ): bool
{
    if( $group === $needle )
        return TRUE;
    if( !$group->isGroup() )
        return FALSE;
    foreach( $group->members() as $m )
        if( commonGroupContains( $m, $needle ) )
            return TRUE;
    return FALSE;
}

/** a static group (address group, service group) - else SKIPPED, FALSE */
function commonStaticGroup( CallContext $context ): bool
{
    $object = $context->object;
    if( !$object->isGroup() )
    {
        PH::ACTIONstatus( $context, "SKIPPED", "because object is not a group" );
        return FALSE;
    }
    if( method_exists( $object, 'isDynamic' ) && $object->isDynamic() )
    {
        PH::ACTIONstatus( $context, "SKIPPED", "because the group is dynamic - its filter selects the members" );
        return FALSE;
    }
    return TRUE;
}

CallContext::registerAction( array( 'AddressCallContext', 'ServiceCallContext' ), array(
    'name' => 'add-member',
    'MainFunction' => function (CallContext $context) {
        $object = $context->object;
        $name = trim( $context->arguments['membername'] );
        if( !commonStaticGroup( $context ) )
            return;

        // the location of the group or above it
        $member = $object->owner->find( $name );
        if( $member === null )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because object '" . $name . "' not found in the location of the group or above it" );
            return;
        }
        if( $object->has( $member ) )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because '" . $name . "' is already a member of this group" );
            return;
        }
        if( commonGroupContains( $member, $object ) )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because '" . $name . "' is the group itself or holds it - that would be a loop" );
            return;
        }
        if( method_exists( $member, 'isType_ipWildcard' ) && $member->isType_ipWildcard() )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because a wildcard address object can not be a member of an address group" );
            return;
        }

        if( $context->isAPI )
            $object->API_addMember( $member );
        else
            $object->addMember( $member );
        PH::ACTIONlog( $context, "member '" . $name . "' added" );
    },
    'args' => array(
        'membername' => array( 'type' => 'string', 'default' => '*nodefault*' )
    ),
    'help' => "adds an object / group of the location of the group or above it to a static address / service group.\n" .
        "Example: 'actions=add-member:h-10.0.0.1'"
) );

CallContext::registerAction( array( 'AddressCallContext', 'ServiceCallContext' ), array(
    'name' => 'remove-member',
    'MainFunction' => function (CallContext $context) {
        $object = $context->object;
        $name = trim( $context->arguments['membername'] );
        if( !commonStaticGroup( $context ) )
            return;

        $member = null;
        foreach( $object->members() as $m )
            if( $m->name() === $name )
                $member = $m;
        if( $member === null )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because '" . $name . "' is not a member of this group" );
            return;
        }
        if( count( $object->members() ) === 1 )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because '" . $name . "' is the last member - a group needs one (delete the group instead)" );
            return;
        }

        if( $context->isAPI )
            $object->API_removeMember( $member );
        else
            $object->removeMember( $member );
        PH::ACTIONlog( $context, "member '" . $name . "' removed" );
    },
    'args' => array(
        'membername' => array( 'type' => 'string', 'default' => '*nodefault*' )
    ),
    'help' => "removes a member of a static address / service group (not the last one).\n" .
        "Example: 'actions=remove-member:h-10.0.0.1'"
) );

CallContext::registerAction( array( 'AddressCallContext', 'ServiceCallContext', 'RuleCallContext', 'SecurityProfileCallContext' ), array(
    'name' => 'description-set',
    'MainFunction' => function (CallContext $context) {
        $object = $context->object;
        if( !method_exists( $object, 'setDescription' ) )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because this object has no description" );
            return;
        }
        // the aliases: $$comma$$ $$colon$$ $$forwardslash$$ $$pipe$$ (they separate the arguments / actions)
        $text = PH::textAliases( (string)$context->arguments['description'] );
        if( $text === '*nodefault*' )
            $text = '';
        $root = PH::findRootObjectOrDie( $object->owner );
        $max = isset( $root->version ) && $root->version < 71 ? 253 : 1020;
        if( strlen( $text ) > $max )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because the description is longer than " . $max . " characters" );
            return;
        }
        if( $text === $object->description() )
        {
            PH::ACTIONstatus( $context, "SKIPPED", "because the description is the same" );
            return;
        }
        if( $context->isAPI )
            $object->API_setDescription( $text );
        else
            $object->setDescription( $text );
        PH::ACTIONlog( $context, $text === '' ? "description removed" : "description set" );
    },
    'args' => array(
        'description' => array( 'type' => 'string', 'default' => '',
            'help' => "the new description (empty: removed); , : / | written as \$\$comma\$\$ \$\$colon\$\$ \$\$forwardslash\$\$ \$\$pipe\$\$" )
    ),
    'help' => "sets (replaces) the description of an address, service, rule or security profile; empty: removed.\n" .
        "Example: 'actions=description-set:web servers\$\$comma\$\$ DMZ'"
) );

// ---- interfaces of a router / zone: the objects bring editInterfaceAdd / editInterfaceRemove (RouterObjectEdit,
// Zone); a refused change is SKIPPED with the reason (CallContext::runEdit)

CallContext::registerAction( array( 'RoutingCallContext', 'ZoneCallContext' ), array(
    'name' => 'interface-add',
    'MainFunction' => function (CallContext $context) {
        $context->runEdit( function( $o, $a ) {
            if( !method_exists( $o, 'editInterfaceAdd' ) )
                throw new Exception( "this object has no interfaces to add" );
            $o->editInterfaceAdd( $a['interface'] );
            return "interface '" . trim( $a['interface'] ) . "' added";
        } );
    },
    'args' => array( 'interface' => array( 'type' => 'string', 'default' => '*nodefault*',
        'help' => "an interface of the location or above it ('/' written as '//'); a zone: of its type, imported into its vsys, in no other zone; a router: in no other router" ) ),
    'help' => "adds an interface to a virtual / logical router or a zone. Example: 'actions=interface-add:ethernet1//2'"
) );

CallContext::registerAction( array( 'RoutingCallContext', 'ZoneCallContext' ), array(
    'name' => 'interface-remove',
    'MainFunction' => function (CallContext $context) {
        $context->runEdit( function( $o, $a ) {
            if( !method_exists( $o, 'editInterfaceRemove' ) )
                throw new Exception( "this object has no interfaces to remove" );
            $o->editInterfaceRemove( $a['interface'] );
            return "interface '" . trim( $a['interface'] ) . "' removed";
        } );
    },
    'args' => array( 'interface' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => "removes an interface from a virtual / logical router or a zone. Example: 'actions=interface-remove:ethernet1//2'"
) );

// ---- name-rename of the network objects: NetworkObjectEdit::editRename - the object, the index of its store and
// every user that names it (IKE gateway -> IKE crypto profile, IPsec tunnel -> IKE gateway / IPsec crypto profile,
// interface -> interface management profile, zone -> zone protection profile, static route -> next virtual router).
// A type with its own name-rename (zone, interface, address, ...) keeps it.

CallContext::registerAction( array( 'IKEgatewayCallContext', 'IKEprofileCallContext', 'IPsecprofileCallContext', 'IPsectunnelCallContext',
    'RoutingCallContext', 'StaticRouteCallContext', 'GREtunnelCallContext', 'InterfaceManagementProfileCallContext', 'ZoneProtectionProfileCallContext',
    'VirtualWireCallContext', 'GPPortalCallContext', 'GPGatewayCallContext', 'GPGatewaytunnelCallContext' ), array(
    'name' => 'name-rename',
    'MainFunction' => function (CallContext $context) {
        $context->runEdit( function( $o, $a ) {
            if( !method_exists( $o, 'editRename' ) )
                throw new Exception( "this object can not be renamed here" );
            $old = $o->name();
            $o->editRename( $a['newname'] );
            return "renamed '" . $old . "' -> '" . $o->name() . "' (users updated: " . count( $o->getReferences() ) . ")";
        } );
    },
    'args' => array( 'newname' => array( 'type' => 'string', 'default' => '*nodefault*' ) ),
    'help' => "renames a network object and updates every object that names it. Example: 'actions=name-rename:ike-aes256'"
) );

// </editor-fold>
