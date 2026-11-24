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

// </editor-fold>
