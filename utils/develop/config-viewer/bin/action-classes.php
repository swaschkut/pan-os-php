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
 * Builds action-classes.json: the risk class of every pan-os-php action (allow list per action of the config-viewer).
 *
 *   php bin/action-classes.php            writes ../action-classes.json (keeps "reviewed" and "override" of the file)
 *   php bin/action-classes.php check      exit 1 when the file is not up to date (new / removed actions)
 *
 * Class of an action, from its arguments (utils/lib/util_action_filter.json) and its source (utils/common/actions-*.php):
 *   read         shows objects, changes nothing                       (display…)
 *   change       changes the configuration in memory only
 *   writes-file  writes a file; "file_arg" = position of the file name argument (null: fixed name in the working directory)
 *   reads-file   reads a file of the server (…-from-file, …)
 *   network      reaches another system or handles keys (DNS lookup, LDAP, …-fastapi, upload-…, authkey, system-…)
 *
 * The config-viewer offers 'read' and 'change' for interactive changes and also 'writes-file' in a playbook run (plain
 * file name, folder of the run); 'reads-file' and 'network' are never offered. A type can be changed only when it is
 * listed in "reviewed" - set by a person after reading the classes of that type. "override" corrects single actions
 * ( "<type>": { "<action>": { "class": … } } ) and survives a rebuild.
 */
if( PHP_SAPI !== 'cli' )
{
    http_response_code( 404 );
    exit;
}
$repo = realpath( dirname(__FILE__) . '/../../../..' );
$target = dirname(__FILE__) . '/../action-classes.json';
$def = json_decode( (string)file_get_contents( $repo . '/utils/lib/util_action_filter.json' ), TRUE );
if( !is_array( $def ) )
{
    fwrite( STDERR, "util_action_filter.json can not be read\n" );
    exit( 2 );
}
$old = is_file( $target ) ? json_decode( (string)file_get_contents( $target ), TRUE ) : null;
$reviewed = is_array( $old['reviewed'] ?? null ) ? $old['reviewed'] : array( 'address', 'service', 'tag', 'rule', 'zone', 'schedule', 'securityprofile', 'securityprofilegroup' );
$override = is_array( $old['override'] ?? null ) ? $old['override'] : array();

// source of every action: "<file key without dashes>" => "<action>" => code
$source = array();
foreach( glob( $repo . '/utils/common/actions-*.php' ) as $file )
{
    $key = str_replace( '-', '', substr( basename( $file ), 8, -4 ) );
    foreach( preg_split( '/\n(?=[A-Za-z]+CallContext::\$supportedActions\[)/', (string)file_get_contents( $file ) ) as $i => $block )
        if( $i > 0 && preg_match( "/'name'\s*=>\s*'([^']+)'/", $block, $m ) )
            $source[$key][strtolower( $m[1] )] = $block;
}

$fileArg = '/^(filename|file|csvfilename|panorama_file|exporttoexcel)$/i';
$secretArg = '/authkey|master-key|ldapserver|password/i';
$networkName = '/-fastapi$|reverse-dns|^upload-|ldap|^authkey|^system-|^decommission$|-for-fqdn$|geoip/';
$networkSource = '/gethostby|dns_get_record|curl_|fsockopen|stream_socket_client|RUNSSH|ssh2_/';
$writeSource = '/file_put_contents|fopen\s*\(|fwrite\s*\(|save_to_file/';

$types = array();
foreach( $def as $type => $d )
{
    if( !is_array( $d ) || !isset( $d['action'] ) || !is_array( $d['action'] ) || count( $d['action'] ) == 0 )
        continue;
    $src = $source[str_replace( '-', '', $type )] ?? array();
    foreach( $d['action'] as $name => $a )
    {
        $name = strtolower( (string)$name );
        $args = array_keys( (array)( $a['args'] ?? array() ) );
        $code = $src[$name] ?? '';
        $fileAt = null;
        $secret = FALSE;
        foreach( $args as $i => $arg )
        {
            if( $fileAt === null && preg_match( $fileArg, (string)$arg ) )
                $fileAt = $i;
            if( preg_match( $secretArg, (string)$arg ) )
                $secret = TRUE;
        }
        if( $secret || preg_match( $networkName, $name ) || preg_match( $networkSource, $code ) )
            $entry = array( 'class' => 'network' );
        elseif( $fileAt !== null && ( preg_match( '/from-file/', $name ) || !( preg_match( '/^export|^display/', $name ) || preg_match( $writeSource, $code ) ) ) )
            $entry = array( 'class' => 'reads-file' );
        elseif( $fileAt !== null )
            $entry = array( 'class' => 'writes-file', 'file_arg' => $fileAt );
        elseif( preg_match( '/^export/', $name ) || preg_match( $writeSource, $code ) )
            $entry = array( 'class' => 'writes-file', 'file_arg' => null );
        elseif( preg_match( '/^display/', $name ) )
            $entry = array( 'class' => 'read' );
        else
            $entry = array( 'class' => 'change' );
        if( isset( $override[$type][$name] ) && is_array( $override[$type][$name] ) )
            $entry = $override[$type][$name];
        $types[$type][$name] = $entry;
    }
    ksort( $types[$type] );
}
ksort( $types );
$out = array(
    '_about' => 'risk class per pan-os-php action - built by bin/action-classes.php (see there); "reviewed": types a person has checked, only these can be changed in the config-viewer; "override": corrections that survive a rebuild',
    'reviewed' => array_values( $reviewed ),
    'override' => (object)$override,
    'types' => $types,
);
$json = json_encode( $out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";

if( ( $argv[1] ?? '' ) === 'check' )
{
    if( !is_file( $target ) || file_get_contents( $target ) !== $json )
    {
        fwrite( STDERR, "action-classes.json is not up to date - run: php bin/action-classes.php\n" );
        exit( 1 );
    }
    print "action-classes.json is up to date\n";
    exit( 0 );
}
file_put_contents( $target, $json );
$count = array();
foreach( $types as $t )
    foreach( $t as $e )
        $count[$e['class']] = ( $count[$e['class']] ?? 0 ) + 1;
ksort( $count );
print "action-classes.json: " . count( $types ) . " types";
foreach( $count as $c => $n )
    print ", " . $n . " " . $c;
print "\n";
