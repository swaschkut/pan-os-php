<?php
/**
 * ISC License
 *
 * Copyright (c) 2026, Sven Waschkut - pan-os-php@waschkut.net
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

/*
 * Read-only check of the iron-skillet URL filtering profiles built by URLProfile::ironSkilletXml():
 * for every iron-skillet version, which predefined URL categories (lib/object-classes/predefined.xml,
 * <pan-url-categories>) 'Outbound-URL' and 'Alert-Only-URL' do not list, in site access
 * (alert + block) and in credential enforcement, and which listed categories are not predefined.
 *
 * The categories live in URLProfile::ironSkilletCategories(); this script changes nothing.
 *
 * usage: php url_categories_check.php [predefined.xml]
 */

require_once dirname(__FILE__) . '/../../../lib/pan_php_framework.php';

$predefinedFile = isset( $argv[1] ) ? $argv[1] : dirname(__FILE__) . '/../../../lib/object-classes/predefined.xml';

$doc = new DOMDocument();
if( !$doc->load( $predefinedFile, XML_PARSE_BIG_LINES ) )
    derr( "cannot load predefined file: " . $predefinedFile, null, false );

$xpath = new DOMXPath( $doc );
$predefined = array();
foreach( $xpath->query( '/predefined/pan-url-categories/entry' ) as $entry )
    $predefined[] = $entry->getAttribute( 'name' );
print "predefined URL categories: " . count( $predefined ) . " (" . $predefinedFile . ")\n\n";

// custom URL categories created by sp_spg-create-*-bp, not predefined
$customCategories = array( 'Block', 'Allow' );

$versions = array( '8.1', '9.1', '10.0', '10.1', '10.2', '11.0', '11.1', '11.2', '12.1' );
$profiles = array( 'Outbound-URL', 'Alert-Only-URL' );

$complete = 0;
foreach( $versions as $version )
{
    $profileDoc = new DOMDocument();
    $profileDoc->loadXML( URLProfile::ironSkilletXml( $version ) );
    $profileXpath = new DOMXPath( $profileDoc );

    $lines = array();
    foreach( $profiles as $profile )
    {
        $sections = array(
            'site access' => "/root/entry[@name='$profile']/*[self::alert or self::block or self::allow]/member",
            'credential enforcement' => "/root/entry[@name='$profile']/credential-enforcement/*[self::alert or self::block or self::allow]/member",
        );
        foreach( $sections as $section => $query )
        {
            $listed = array();
            foreach( $profileXpath->query( $query ) as $member )
                $listed[] = $member->textContent;

            $missing = array_diff( $predefined, $listed );
            $unknown = array_diff( $listed, $predefined, $customCategories );

            if( count( $missing ) > 0 )
                $lines[] = "  $profile $section: not listed (" . count( $missing ) . "): " . implode( ', ', $missing );
            if( count( $unknown ) > 0 )
                $lines[] = "  $profile $section: not predefined (" . count( $unknown ) . "): " . implode( ', ', $unknown );
        }
    }

    if( count( $lines ) == 0 )
    {
        $complete++;
        print "iron-skillet $version: every predefined category listed\n";
    }
    else
        print "iron-skillet $version:\n" . implode( "\n", $lines ) . "\n";
}

print "\n" . $complete . " of " . count( $versions ) . " versions list every predefined URL category\n";
