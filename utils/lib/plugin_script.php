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
 * Runs a script of an encrypted plug-in package (ppp://<name>/…) - PH::runSCMScript starts it for such a script: a new
 * PHP process can not open ppp:// itself. The framework mounts the packages of the run (PANOSPHP_PLUGIN_PACKAGES +
 * PANOSPHP_LICENSE, PluginPackage::bootFromEnv), then the script runs as if it was started directly.
 *
 *   php utils/lib/plugin_script.php ppp://<name>/<script>.php <arguments of the script>
 */
set_include_path( dirname(__FILE__) . '/../../' . PATH_SEPARATOR . get_include_path() );
require_once "lib/pan_php_framework.php";

$pluginScript = isset( $argv[1] ) ? (string)$argv[1] : '';
if( strpos( $pluginScript, 'ppp://' ) !== 0 || !is_file( $pluginScript ) )
{
    fwrite( STDERR, "plugin_script.php: not a script of a mounted plug-in package (licence / PANOSPHP_PLUGIN_PACKAGES): " . $pluginScript . "\n" );
    exit( 1 );
}
$argv = array_merge( array( $pluginScript ), array_slice( $argv, 2 ) );
$argc = count( $argv );
$_SERVER['argv'] = $argv;
$_SERVER['argc'] = $argc;
require $pluginScript;
