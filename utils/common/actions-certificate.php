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



CertificateCallContext::$supportedActions['display'] = Array(
    'name' => 'display',
    'MainFunction' => function ( CertificateCallContext $context )
    {
        $object = $context->object;
        PH::print_stdout("     * ".get_class($object)." '{$object->name()}'" );
        PH::$JSON_TMP['sub']['object'][$object->name()]['name'] = $object->name();

        $algorithm = "";
        $privateKey = "";
        $privateKeyLen = "";


        $notValidbefore = "";
        $notValidafter = "";

        $publicKeyLen = "";
        $publicKeyAlgorithm = "";
        $publicKeyHash = "";

        $privateKeyLen = "";
        $privateKeyAlgorithm = "";
        $privateKeyHash = "";

        if( $object->algorithm != null )
            $algorithm = "Algorithm: ".$object->algorithm;

        if( $object->notValidbefore != null )
            $notValidbefore = " | not Valid before: ".$object->notValidbefore;
        if( $object->notValidafter != null )
            $notValidafter = "after: ".$object->notValidafter;

        if( $object->privateKey != null )
        {
            $privateKey = $object->privateKey;
            $privateKeyLen = "       - "."privateKey length: ".$object->privateKeyLen;
            $privateKeyAlgorithm = " | algorithm: ".$object->privateKeyAlgorithm;
            $privateKeyHash = " |  hash: ".$object->privateKeyHash;
        }

        if( $object->publicKey != null )
        {
            $publicKey = $object->publicKey;
            $publicKeyLen = "       - "."publicKey length: ".$object->publicKeyLen;
            $publicKeyAlgorithm = " | algorithm: ".$object->publicKeyAlgorithm;
            $publicKeyHash = " |  hash: ".$object->publicKeyHash;
        }
        //not-valid-before
        //not-valid-after

        $subject = "---";
        if( isset($object->publicKeyDetailArray['subject'] ) )
        {
            $input = $object->publicKeyDetailArray['subject'];
            $subject = implode(', ', array_map(
                function ($v, $k) {
                    if(is_array($v)){
                        return $k.'[]='.implode('&'.$k.'[]=', $v);
                    }else{
                        return $k.'='.$v;
                    }
                },
                $input,
                array_keys($input)
            ));
        }

        $issuer = "---";
        if( isset($object->publicKeyDetailArray['issuer'] ) )
        {
            $input = $object->publicKeyDetailArray['issuer'];
            $issuer = implode(', ', array_map(
                function ($v, $k) {
                    if(is_array($v)){
                        return $k.'[]='.implode('&'.$k.'[]=', $v);
                    }else{
                        return $k.'='.$v;
                    }
                },
                $input,
                array_keys($input)
            ));
        }


        $CA = "---";
        if( isset($object->publicKeyDetailArray['extensions']['basicConstraints'] ) )
        {
            if( strpos( $object->publicKeyDetailArray['extensions']['basicConstraints'], "CA:TRUE" ) !== FALSE )
                $CA = "Yes";
            else
                $CA = "No";
        }


        PH::print_stdout( "       - ".$algorithm.$notValidbefore." - ".$notValidafter );
        PH::print_stdout( );
        #PH::print_stdout( $privateKeyLen.$privateKeyAlgorithm.$privateKeyHash );
        PH::print_stdout( $publicKeyLen.$publicKeyAlgorithm.$publicKeyHash );

        PH::print_stdout( "       - Subject: ".$subject );
        PH::print_stdout( "       - Issuer:  ".$issuer );
        PH::print_stdout( "       - CA: ".$CA );

        #print_r( $object->publicKeyDetailArray );
    },
);


CertificateCallContext::$supportedActions['exportToExcel'] = array(
    'name' => 'exportToExcel',
    'MainFunction' => function (CertificateCallContext $context) {
        $object = $context->object;
        $context->objectList[] = $object;
    },
    'GlobalInitFunction' => function (CertificateCallContext $context) {
        $context->objectList = array();
    },
    'GlobalFinishFunction' => function (CertificateCallContext $context) {
        $args = &$context->arguments;
        $filename = $args['filename'];

        if( isset( $_SERVER['REQUEST_METHOD'] ) )
            $filename = "project/html/".$filename;



        $headers = '<th>ID</th><th>template</th><th>location</th><th>name</th>';
        $headers .= '<th>Algorithm</th><th>not Valid before</th><th>not Valid after</th>';
        $headers .= '<th>Subject</th><th>Issuer</th><th>CA</th>';



        $lines = '';

        $count = 0;
        if( isset($context->objectList) )
        {
            foreach( $context->objectList as $object )
            {
                $count++;

                /** @var DHCP $object */
                if( $count % 2 == 1 )
                    $lines .= "<tr>\n";
                else
                    $lines .= "<tr bgcolor=\"#DDDDDD\">";

                $lines .= $context->encloseFunction((string)$count);

                if( isset($object->owner->owner->owner) && get_class($object->owner->owner->owner) == "PANConf" )
                {
                    if( isset($object->owner->owner->owner->owner) && $object->owner->owner->owner->owner !== null && (get_class($object->owner->owner->owner->owner) == "Template" || get_class($context->subSystem->owner) == "TemplateStack" ) )
                    {
                        $lines .= $context->encloseFunction($object->owner->owner->owner->owner->name());
                        if( $object->owner->owner->name() == "certificateStore" )
                            $lines .= $context->encloseFunction("shared");
                        else
                            $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                    else
                    {
                        $lines .= $context->encloseFunction("---");
                        if( $object->owner->owner->name() == "certificateStore" )
                            $lines .= $context->encloseFunction("shared");
                        else
                            $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                }
                elseif( isset($object->owner->owner) && $object->owner->owner !== null && (get_class($object->owner->owner) == "Template" || get_class($context->subSystem->owner) == "TemplateStack" ) )
                {
                    if( isset($object->owner->owner->owner) && $object->owner->owner->owner !== null && (get_class($object->owner->owner->owner) == "Template" || get_class($context->subSystem->owner) == "TemplateStack" ) )
                    {
                        $lines .= $context->encloseFunction($object->owner->owner->owner->name());
                        if( $object->owner->owner->name() == "certificateStore" )
                            $lines .= $context->encloseFunction("shared");
                        else
                            $lines .= $context->encloseFunction($object->owner->owner->name());
                    }
                    else
                    {
                        $lines .= $context->encloseFunction($object->owner->owner->name());
                        if( $object->owner->name() == "certificateStore" )
                            $lines .= $context->encloseFunction("shared");
                        else
                            $lines .= $context->encloseFunction($object->owner->name());
                    }

                }
                else
                {
                    $lines .= $context->encloseFunction($object->owner->owner->name());
                    if( $object->owner->name() == "certificateStore" )
                        $lines .= $context->encloseFunction("shared");
                    else
                        $lines .= $context->encloseFunction($object->owner->name());
                }


                $lines .= $context->encloseFunction($object->name());

                $algorithm = "";
                if( $object->algorithm != null )
                    $algorithm = $object->algorithm;
                $lines .= $context->encloseFunction($algorithm);

                $notValidbefore = "";
                if( $object->notValidbefore != null )
                    $notValidbefore = $object->notValidbefore;
                $lines .= $context->encloseFunction($notValidbefore);

                $notValidafter = "";
                if( $object->notValidafter != null )
                    $notValidafter = $object->notValidafter;
                $lines .= $context->encloseFunction($notValidafter);

                $subject = "";
                if( isset($object->publicKeyDetailArray['subject'] ) )
                {
                    $input = $object->publicKeyDetailArray['subject'];
                    $subject = implode(', ', array_map(
                        function ($v, $k) {
                            if(is_array($v)){
                                return $k.'[]='.implode('&'.$k.'[]=', $v);
                            }else{
                                return $k.'='.$v;
                            }
                        },
                        $input,
                        array_keys($input)
                    ));
                }
                $lines .= $context->encloseFunction($subject);

                $issuer = "";
                if( isset($object->publicKeyDetailArray['issuer'] ) )
                {
                    $input = $object->publicKeyDetailArray['issuer'];
                    $issuer = implode(', ', array_map(
                        function ($v, $k) {
                            if(is_array($v)){
                                return $k.'[]='.implode('&'.$k.'[]=', $v);
                            }else{
                                return $k.'='.$v;
                            }
                        },
                        $input,
                        array_keys($input)
                    ));
                }
                $lines .= $context->encloseFunction($issuer);


                $CA = "";
                if( isset($object->publicKeyDetailArray['extensions']['basicConstraints'] ) )
                {
                    if( strpos( $object->publicKeyDetailArray['extensions']['basicConstraints'], "CA:TRUE" ) !== FALSE )
                        $CA = "Yes";
                    else
                        $CA = "No";
                }
                $lines .= $context->encloseFunction($CA);


                $lines .= "</tr>\n";

            }
        }

        $content = file_get_contents(dirname(__FILE__) . '/html/export-template.html');
        $content = str_replace('%TableHeaders%', $headers, $content);

        $content = str_replace('%lines%', $lines, $content);

        $jscontent = file_get_contents(dirname(__FILE__) . '/html/jquery.min.js');
        $jscontent .= "\n";
        $jscontent .= file_get_contents(dirname(__FILE__) . '/html/jquery.stickytableheaders.min.js');
        $jscontent .= "\n\$('table').stickyTableHeaders();\n";

        $content = str_replace('%JSCONTENT%', $jscontent, $content);

        file_put_contents($filename, $content);

    },
    'args' => array('filename' => array('type' => 'string', 'default' => '*nodefault*'))
);