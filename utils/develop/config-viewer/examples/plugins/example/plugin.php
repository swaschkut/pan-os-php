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


/**
 * Example plug-in for the config viewer (interface version 1, lib/ViewerPlugins.php). Not active here: copy the folder
 * "example" into <config-viewer>/plugins/ or point PANOSPHP_VIEWER_PLUGINS to the folder that holds it.
 *
 * It adds:
 *   run type  example-export     addresses of a location as HTML (a read: result file only)
 *   run type  example-tag-rules  adds the tags of a "tag list" file to the security rules; the changed configuration
 *                                can be taken as a new version
 *   file kind example-taglist    JSON: [ "tag-a", "tag-b" ]
 */
return array(
    'api' => 1,
    'name' => 'example',
    'title' => 'Example plug-in',
    'version' => '1.0',
    // 'feature' => 'example',      // a licensed feature (todo/config-viewer-license.md); without it: basic

    'kinds' => array(
        'taglist' => array(
            'title' => 'tag list (JSON)',
            // gets the decoded JSON; returns what is wrong with it, or nothing
            'check' => function( $json ) {
                if( !is_array( $json ) || count( $json ) < 1 || count( $json ) > 20 )
                    return 'tag list: 1 to 20 tag names';
                foreach( $json as $tag )
                    if( !is_string( $tag ) || !preg_match( '/^[A-Za-z0-9_.-]{1,63}$/', $tag ) )
                        return 'tag list: tag names with letters, digits and . _ - only';
            } ),
    ),

    'runs' => array(
        'export' => array(
            'title' => 'Example: addresses as HTML',
            'tool' => 'address',                                   // pan-os-php type=address
            'fields' => array(
                array( 'name' => 'location', 'kind' => 'location', 'label' => 'Location', 'default' => 'any' ),
            ),
            // ViewerPluginRun $run: checked values only. in= is set by the viewer (the version of the run).
            'args' => function( ViewerPluginRun $run ) {
                return array( 'location=' . $run->location(), 'actions=exportToExcel:addresses.html' );
            } ),

        'tag-rules' => array(
            'title' => 'Example: tag the security rules',
            'tool' => 'rule',
            'bp' => FALSE,                                         // TRUE: the run takes a BP JSON of the project
            'result' => 'out.xml',                                 // result configuration: "Result as new version"
            'fields' => array(
                array( 'name' => 'tags', 'kind' => 'file:taglist', 'label' => 'Tag list', 'required' => TRUE ),
                array( 'name' => 'location', 'kind' => 'location', 'label' => 'Location', 'default' => 'any' ),
            ),
            'args' => function( ViewerPluginRun $run ) {
                $actions = array();
                foreach( $run->json( 'tags', 'example-taglist' ) as $tag )
                    $actions[] = 'tag-Add-Force:' . $tag;
                return array( 'location=' . $run->location(), 'actions=' . implode( '/', $actions ), 'out=' . $run->out( 'out.xml' ) );
            } ),
    ),

    // pan-os-php types a playbook may use in addition to the ones of the viewer
    'playbookTypes' => array(),
);
