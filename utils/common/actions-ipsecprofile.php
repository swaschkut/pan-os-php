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

IPsecprofileCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( IPsecprofileCallContext $context )
    {
        $object = $context->object;
        //PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );

        PH::print_stdout( $context->padding. " - protocol: " . $object->ipsecProtocol );
        $text = $context->padding."      encryption: " . $object->encryption . " - authentication: " . $object->authentication . " - dhgroup: " . $object->dhgroup;

        if( $object->lifetime_seconds != "" )
            $text .= " - lifetime: " . $object->lifetime_seconds . " seconds";
        elseif( $object->lifetime_minutes != "" )
            $text .= " - lifetime: " . $object->lifetime_minutes . " minutes";
        elseif( $object->lifetime_hours != "" )
            $text .= " - lifetime: " . $object->lifetime_hours . " hours";
        elseif( $object->lifetime_days != "" )
            $text .= " - lifetime: " . $object->lifetime_days . " days";


        if( $object->lifesize_kb != "" )
            $text .= " - lifesize: " . $object->lifesize_kb . " kb";
        elseif( $object->lifesize_mb != "" )
            $text .= " - lifesize: " . $object->lifesize_mb . " mb";
        elseif( $object->lifesize_gb != "" )
            $text .= " - lifesize: " . $object->lifesize_gb . " gb";
        elseif( $object->lifesize_tb != "" )
            $text .= " - lifesize: " . $object->lifesize_tb . " tb";

        PH::print_stdout($text);


        if( PH::$shadow_displayxmlnode )
        {
            PH::print_stdout(  "" );
            DH::DEBUGprintDOMDocument($context->object->xmlroot);
            PH::print_stdout();
        }

    },

);