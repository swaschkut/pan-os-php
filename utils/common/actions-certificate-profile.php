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

CertificateProfileCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( CertificateProfileCallContext $context )
    {
        /** @var CertificateProfile $object */
        $object = $context->object;
        $name = $object->name();

        PH::print_stdout("     * ".get_class($object)." '{$name}'" );
        PH::$JSON_TMP['sub']['object'][$name]['name'] = $name;

        foreach( CertificateProfileCallContext::caResolution($object) as $caName => $where )
        {
            $details = $object->caCertificates[$caName];
            $text = "        - CA: '{$caName}' (" . $where . ")";
            foreach( $details as $key => $value )
                $text .= " {$key}: '{$value}'";
            PH::print_stdout( $text );
            PH::$JSON_TMP['sub']['object'][$name]['ca'][$caName] = array_merge( array( 'certificate' => $where ), $details );
        }

        foreach( $object->usernameField as $key => $value )
        {
            PH::print_stdout( "        - username-field: {$key} {$value}" );
            PH::$JSON_TMP['sub']['object'][$name]['username-field'][$key] = $value;
        }

        if( $object->domain !== null && $object->domain !== '' )
        {
            PH::print_stdout( "        - domain: '{$object->domain}'" );
            PH::$JSON_TMP['sub']['object'][$name]['domain'] = $object->domain;
        }

        foreach( $object->settings as $key => $value )
        {
            PH::print_stdout( "        - {$key}: {$value}" );
            PH::$JSON_TMP['sub']['object'][$name]['settings'][$key] = $value;
        }
    },
);


CertificateProfileCallContext::$supportedActions['exportToExcel'] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (CertificateProfileCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (CertificateProfileCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (CertificateProfileCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;

        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th><th>CA certificates</th><th>username-field</th><th>domain</th><th>settings</th>';

        $lines = '';
        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                /** @var CertificateProfile $object */
                $count++;

                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction((string)$count);
                $lines .= $context->encloseFunction(CertificateProfileCallContext::templateName($object));
                $lines .= $context->encloseFunction(CertificateProfileCallContext::locationName($object));
                $lines .= $context->encloseFunction($object->name());

                $ca = array();
                foreach( CertificateProfileCallContext::caResolution($object) as $caName => $where )
                    $ca[] = $caName . ' (' . $where . ')';
                $lines .= $context->encloseFunction($ca);

                $username = array();
                foreach( $object->usernameField as $key => $value )
                    $username[] = $key . ' ' . $value;
                $lines .= $context->encloseFunction(implode(' ', $username));

                $lines .= $context->encloseFunction((string)$object->domain);

                $settings = array();
                foreach( $object->settings as $key => $value )
                    $settings[] = $key . ': ' . $value;
                $lines .= $context->encloseFunction($settings);

                $lines .= "</tr>\n";
            }
        }

        require_once dirname(__FILE__) . '/../lib/ExportToHtmlHelper.php';
        ExportToHtmlHelper::writeHtmlExport($filename, $headers, $lines);
    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'))
);
CertificateProfileCallContext::$supportedActions['exportToHtml'] = array_merge(CertificateProfileCallContext::$supportedActions['exportToExcel'], array('name' => 'exportToHtml'));
