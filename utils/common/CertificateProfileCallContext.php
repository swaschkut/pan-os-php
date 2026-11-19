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

class CertificateProfileCallContext extends CallContext
{
    /** @var  CertificateProfile */
    public $object;

    public static $commonActionFunctions = Array();
    public static $supportedActions = Array();

    static public function prepareSupportedActions()
    {
        $tmpArgs = Array();
        foreach( self::$supportedActions as &$arg )
        {
            $tmpArgs[strtolower($arg['name'])] = $arg;
        }
        ksort($tmpArgs);
        self::$supportedActions = $tmpArgs;
    }

    /**
     * template / template stack name, '---' outside Panorama templates
     * @param CertificateProfile $object
     * @return string
     */
    static public function templateName( $object )
    {
        $cur = $object->owner;
        while( $cur !== null )
        {
            if( $cur instanceof Template || $cur instanceof TemplateStack )
                return $cur->name();
            $cur = isset($cur->owner) ? $cur->owner : null;
        }
        return '---';
    }

    /**
     * 'shared' or the vsys name
     * @param CertificateProfile $object
     * @return string
     */
    static public function locationName( $object )
    {
        if( isset($object->owner->owner) && $object->owner->owner instanceof VirtualSystem )
            return $object->owner->owner->name();
        return 'shared';
    }

    /**
     * CA name => location of the certificate found for it, or 'unresolved'
     * @param CertificateProfile $object
     * @return string[]
     */
    static public function caResolution( $object )
    {
        $ret = array();
        foreach( $object->caCertificateNames() as $caName )
        {
            $certificate = $object->findCertificate($caName);
            if( $certificate === null )
                $ret[$caName] = 'unresolved';
            else
            {
                $loc = $certificate->owner->owner;
                if( $loc instanceof VirtualSystem )
                    $ret[$caName] = $loc->name();
                elseif( $loc instanceof Template || $loc instanceof TemplateStack )
                    $ret[$caName] = $loc->name() . '/shared';
                else
                    $ret[$caName] = 'shared';
            }
        }
        return $ret;
    }
}
require_once  "actions-certificate-profile.php";
CertificateProfileCallContext::prepareSupportedActions();
