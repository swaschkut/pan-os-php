<?php
/**
 * ISC License
 *
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

/**
 * in=scm-export://<export folder>
 *
 * Offline variant of in=scm-api://: the SCM configuration is read from a folder written by scm_pa_export.php
 * (config/01_folders.json, config/02_snippets.json, config/folders|snippets|devices/<container>/NN_<type>.json)
 * instead of the SCM API. The JSON -> XML translation is the one of PanSCMAPIConnector (importConfig), so every
 * pan-os-php utility that works with scm-api:// works with the export. Nothing is ever sent: the result is written
 * with out=<file.xml>; scm_pa_xml_to_change.php turns the difference into a change file for scm_pa_change.php.
 *
 * Security profiles (vulnerability, virus-and-wildfire, anti-spyware, DNS security): complete from the internal UI
 * API answers of the export (config/internal/<type>.json) when present, else the public fields only.
 */
class PanSCMExportConnector extends PanSCMAPIConnector
{
    /** @var string export folder (the one holding manifest.json) */
    public $exportDir;

    /** @var array manifest.json of the export */
    public $manifest = array();

    /** @var array [kind][container][type] => file */
    private $files = array();

    public function __construct( $dir )
    {
        $dir = self::resolveDir( $dir );
        if( !is_dir($dir) || !is_file($dir . "/manifest.json") )
            derr( "scm-export://: '" . $dir . "' is no scm_pa_export.php folder (manifest.json missing)", null, FALSE );
        $this->exportDir = $dir;
        $this->manifest = json_decode(file_get_contents($dir . "/manifest.json"), TRUE);
        if( !is_array($this->manifest) )
            derr( "scm-export://: manifest.json of '" . $dir . "' is not readable", null, FALSE );
        $tsg = isset($this->manifest['tsg_id']) ? (string)$this->manifest['tsg_id'] : "export";

        parent::__construct( $tsg );

        // offline: no internal UI API lookups
        PH::$shadow_scm_no_internal_api = TRUE;

        foreach( array('folders' => 'folder', 'snippets' => 'snippet', 'devices' => 'device') as $sub => $kind )
            foreach( glob($dir . "/config/" . $sub . "/*", GLOB_ONLYDIR) as $cDir )
                foreach( glob($cDir . "/*.json") as $f )
                {
                    // NN_<type>.json / NN_<type>-pre.json / NN_<type>-post.json
                    $t = preg_replace('/^\d+_/', '', basename($f, ".json"));
                    $this->files[$kind][basename($cDir)][$t] = $f;
                }
    }

    /**
     * scm_pa_export.php writes <outdir>/<TSG>/<timestamp>/: the folder itself, <outdir>/<TSG> (newest export with a
     * config area) or <outdir> with one TSG are accepted
     */
    public static function resolveDir( $dir )
    {
        $dir = rtrim($dir, "/");
        for( $i = 0; $i < 2 && is_dir($dir) && !is_file($dir . "/manifest.json"); $i++ )
        {
            $subs = array();
            foreach( glob($dir . "/*", GLOB_ONLYDIR) as $d )
                if( is_file($d . "/manifest.json") ? is_dir($d . "/config") : count(glob($d . "/*/manifest.json")) > 0 )
                    $subs[] = $d;
            if( count($subs) == 0 )
                break;
            sort($subs);    // timestamps sort chronologically
            $dir = end($subs);
        }
        return $dir;
    }

    /** UTIL types whose SCM types together cover everything the loader knows */
    // order: referenced types first (log forwarding / zone protection profiles, tags) - the objects that refer to
    // them get their references while loading
    const ALL_UTIL_TYPES = array( 'log-profile', 'zone-protection-profile', 'tag', 'application', 'upload', 'rule',
        'schedule', 'zone', 'securityprofile', 'securityprofilegroup', 'address', 'service', 'device' );

    /**
     * the whole export into a BuckbeakConf (all containers, all types the loader knows) - e.g. as the original for
     * scm_pa_xml_to_change.php. $utilTypes: restrict to these UTIL types.
     * @return string[] loaded containers
     */
    public function loadAll( BuckbeakConf $pan, $utilTypes = null )
    {
        $folders = PanSCMAPIConnector::$folderArray;
        $folders = array_merge( $folders, $this->getSnippetsavailable($pan) );
        $folders = array_merge( $folders, $this->getFolderavailable($pan) );
        $folders = array_values(array_unique($folders));
        $loaded = array();
        foreach( $folders as $folder )
        {
            if( $folder === "Shared" )
                $sub = $pan->findContainer("Prisma Access");
            else
            {
                $sub = $pan->findContainer($folder);
                if( $sub === null )
                    $sub = $pan->findSnippet($folder);
                if( $sub === null )
                    $sub = $pan->findDeviceCloud($folder);
                if( $sub === null )
                    $sub = $pan->findDeviceOnPrem($folder);
            }
            if( $sub === null )
                continue;
            foreach( $utilTypes === null ? self::ALL_UTIL_TYPES : $utilTypes as $ut )
                $this->loadSCMConfig( $folder, $sub, $ut );
            // one entry per container (the static folder list and the folder answer overlap)
            $loaded[get_class($sub) . "|" . $sub->name()] = $sub->name();
        }
        return array_values($loaded);
    }

    /** @var array type => uuid => internal UI API entry (config/internal/<type>.json), FALSE = not in the export */
    private $internalEntries = array();

    /**
     * security profiles: complete entry of the internal UI API from the export (config/internal/<type>.json, written
     * by scm_pa_export.php) - decoder, inline ML, inline cloud analysis, rule action default, advanced DNS; matched
     * by @uuid = id, independent of the folder being loaded (snippet profiles as well). Without the file: public
     * fields only.
     */
    protected function SCM_API_internal_profile_lookup( $type, $uuid )
    {
        $index = $this->internalIndex( $type );
        return ( $index !== FALSE && isset($index[$uuid]) ) ? $index[$uuid] : null;
    }

    /** @return array|false uuid => entry, FALSE: the export has no internal answer of this type */
    public function internalIndex( $type )
    {
        if( !array_key_exists($type, $this->internalEntries) )
        {
            $this->internalEntries[$type] = FALSE;
            $f = $this->exportDir . "/config/internal/" . $type . ".json";
            if( isset(self::INTERNAL_PROFILE_TYPES[$type]) && is_file($f) )
            {
                $j = json_decode(file_get_contents($f), TRUE);
                if( is_array($j) && isset($j['data']) && is_array($j['data']) )
                {
                    $this->internalEntries[$type] = array();
                    foreach( $j['data'] as $e )
                        if( is_array($e) && isset($e['@uuid']) )
                            $this->internalEntries[$type][$e['@uuid']] = $e;
                }
            }
        }
        return $this->internalEntries[$type];
    }

    /** export folders do not need credentials */
    public function findOrCreateConnectorFromHost( $TSGid )
    {
        return $this;
    }

    public function getAccessToken()
    {
        derr( "scm-export:// works offline - no SCM API access", null, FALSE );
    }

    private function readFile( $file )
    {
        $json = json_decode(file_get_contents($file), TRUE);
        if( !is_array($json) )
            return null;
        if( !isset($json['data']) || !is_array($json['data']) )
            return null;
        return array( 'data' => $json['data'], 'total' => count($json['data']), 'limit' => count($json['data']) + 1, 'offset' => 0 );
    }

    /** folders / snippets of the export */
    function getResourceSetup( $type = null, $foldertype = "folder", $folderName = null, $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1 )
    {
        $map = array( 'folders' => '01_folders.json', 'snippets' => '02_snippets.json', 'devices' => '03_devices.json' );
        if( !isset($map[$type]) || !is_file($this->exportDir . "/config/" . $map[$type]) )
            return array( 'data' => array() );
        $r = $this->readFile( $this->exportDir . "/config/" . $map[$type] );
        return $r === null ? array( 'data' => array() ) : $r;
    }

    /** objects of one type and container from the export */
    function getResource( $type = null, $foldertype = "folder", $folderName = null, $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1 )
    {
        if( $type === null || $folderName === null )
            return null;
        $kind = $foldertype == "snippet" ? "snippet" : ( $foldertype == "device" ? "device" : "folder" );
        $key = strpos($type, "-rules") !== FALSE ? $type . "-" . $prePost : $type;
        if( !isset($this->files[$kind][$folderName][$key]) )
        {
            // rule files without pre / post split (snippet rules)
            if( strpos($type, "-rules") !== FALSE && $prePost == "pre" && isset($this->files[$kind][$folderName][$type]) )
                $key = $type;
            else
                return null;
        }
        PH::print_stdout( "       - " . $type . ( strpos($type, "-rules") !== FALSE ? " (" . $prePost . ")" : "" ) . " - " . $foldertype . " - " . $folderName . " [export]" );
        return $this->readFile( $this->files[$kind][$folderName][$key] );
    }

    function getNetworkResource( $type = "zones", $foldertype = "folder", $folderName = "Prisma Access", $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1 )
    {
        return $this->getResource( $type, $foldertype, $folderName, $limit, $prePost, $offset, $runtime );
    }

    function getResourceURL( $url_config, $type = null, $foldertype = "folder", $folder = null, $limit = 200, $prePost = "pre", $offset = 0, $runtime = 1 )
    {
        return $this->getResource( $type, $foldertype, $folder, $limit, $prePost, $offset, $runtime );
    }

    function curl_request_SCM( $url )
    {
        derr( "scm-export:// works offline - no SCM API request (" . $url . ")", null, FALSE );
    }

    public function sendSCMAPIRequest( $requestMethod, $url, $body = false, $exitOnError = TRUE )
    {
        derr( "scm-export:// works offline - nothing is sent (" . $requestMethod . " " . $url . "); write the result with out= and use scm_pa_xml_to_change.php", null, FALSE );
    }

    public function sendCreateRequest( $element )
    {
        $this->sendSCMAPIRequest( "POST", "(create)" );
    }

    public function sendPUTRequest( $element )
    {
        $this->sendSCMAPIRequest( "PUT", "(update)" );
    }

    public function sendDELETERequest( $object )
    {
        $this->sendSCMAPIRequest( "DELETE", "(delete)" );
    }
}
