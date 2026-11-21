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
 * config-viewer: the editors of pan-os-php (utils/common/html/editor) for the page - editor.php?e=playbook|bp.
 *
 * The editors use inline scripts; the page of the viewer allows none. So they are served here, with their scripts
 * inlined, under a policy of their own: a sandbox (an origin of their own - no cookies, no API, no access to the page),
 * no network at all, only embedded by the viewer. They get the file and give the result back with postMessage; the
 * viewer stores the result as a new project file (checked like an upload). Nothing of a project is in this answer.
 */
$editors = array(
    // the actions / filters of the playbook editor: util_action_filter.json of this pan-os-php (instead of its copy json_array.js)
    'playbook' => array( 'dir' => 'playbook', 'html' => 'playbook-editor.html', 'scripts' => array( 'json_array.js' => 'util_action_filter' ) ),
    'bp' => array( 'dir' => 'bp_setting', 'html' => 'bp_setting-editor.html', 'scripts' => array( 'd3.v7.min.js' => null, 'validation.js' => null ) ),
);
$e = isset( $_GET['e'] ) && is_string( $_GET['e'] ) ? $_GET['e'] : '';
if( !isset( $editors[$e] ) || PHP_SAPI === 'cli' )
{
    http_response_code( 404 );
    exit;
}
$repo = dirname( __FILE__ ) . '/../../..';
$dir = $repo . '/utils/common/html/editor/' . $editors[$e]['dir'];
$html = @file_get_contents( $dir . '/' . $editors[$e]['html'] );
if( !is_string( $html ) )
{
    http_response_code( 404 );
    exit;
}
foreach( $editors[$e]['scripts'] as $name => $from )
{
    if( $from === 'util_action_filter' )
        $code = 'var subjectObject = ' . (string)@file_get_contents( $repo . '/utils/lib/util_action_filter.json' ) . ';';
    else
        $code = (string)@file_get_contents( $dir . '/' . $name );
    // a script is never ended early by its own text
    $code = str_ireplace( '</script', '<\/script', $code );
    $html = str_replace( '<script src="' . $name . '"></script>', '<script>' . $code . '</script>', $html );
}
header( 'Content-Type: text/html; charset=utf-8' );
header( "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:; connect-src 'none'; "
    . "form-action 'none'; base-uri 'none'; frame-ancestors 'self'; sandbox allow-scripts" );
header( 'X-Content-Type-Options: nosniff' );
header( 'Referrer-Policy: no-referrer' );
header( 'Cache-Control: no-store' );
print $html;
