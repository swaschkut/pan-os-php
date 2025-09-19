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


LogProfileCallContext::$supportedActions['displayreferences'] = array(
    'name' => 'displayReferences',
    'MainFunction' => function (LogProfileCallContext $context) {
        $object = $context->object;

        $object->display_references(7);
    },
);

LogProfileCallContext::$supportedActions['display'] = array(
    'name' => 'display',
    'MainFunction' => function (LogProfileCallContext $context) {
        /** @var LogProfile $object */
        $object = $context->object;
        $tmp_txt = "     * " . get_class($object) . " '{$object->name()}'   ";


        if( !empty( $object->type() ) )
        {
            foreach( $object->type() as $key => $name )
            {
                if( isset($name['notSet']))
                {
                    $tmp_txt = "       - ".str_pad( $key, 12 );
                    $tmp_txt .= " | NOT SET";
                }
                else
                {
                    foreach ($name as $name_key => $type)
                    {
                        $tmp_txt = "       - " . str_pad($key, 12)." | ".str_pad($name_key, 12)."";
                        foreach ($type as $type_key => $type_value)
                        {
                            $tmp_txt .= " |" . $type_key . "->" . $type_value;
                        }
                    }
                }
                PH::print_stdout($tmp_txt);
            }
        }

    },
);

