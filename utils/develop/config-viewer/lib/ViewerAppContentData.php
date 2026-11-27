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
 * Part of ViewerApp (trait: the same class - $this, private methods and self:: are those of ViewerApp):
 * the App-ID database (predefined.xml) and the MaxMind data of the installation / of a project.
 */
trait ViewerAppContentData
{
    // ------------------------------------------------------------------ App-ID database / MaxMind data

    /**
     * environment of a run of project $pid for the App-ID database and MaxMind data (pan-os-php: PANOSPHP_PREDEFINED_XML,
     * PANOSPHP_GEOIP_DIR): the App-ID database of the project, else the one of the installation; MaxMind of the
     * installation. Nothing set = the data shipped in the image.
     */
    private function dataEnv( string $pid ): array
    {
        $env = array();
        if( is_file( $this->dataDir . '/projects/' . $pid . '/predefined.xml' ) )
            $env['PANOSPHP_PREDEFINED_XML'] = '%PROJECT%/predefined.xml';
        elseif( is_file( $this->dataDir . '/central/predefined.xml' ) )
            $env['PANOSPHP_PREDEFINED_XML'] = '%CENTRAL%/predefined.xml';
        if( is_file( $this->dataDir . '/central/geoip/data/RegionCCipv4.json' ) )
            $env['PANOSPHP_GEOIP_DIR'] = '%CENTRAL%/geoip';
        return $env;
    }

    /** %JOB% / %PROJECT% / %CENTRAL% of an environment of a run as paths of this computer (run without a container) */
    private function resolveEnv( array $env, string $pid, string $jobDir ): array
    {
        foreach( $env as $k => $v )
            $env[$k] = str_replace( array( '%JOB%', '%PROJECT%', '%CENTRAL%' ), array( $jobDir, $this->dataDir . '/projects/' . $pid, $this->dataDir . '/central' ), $v );
        return $env;
    }

    /** the App-ID version of a predefined.xml (<predefined><application-version>), null when it is no predefined.xml */
    private static function predefinedVersion( string $file ): ?string
    {
        $r = new XMLReader();
        if( !is_file( $file ) || !@$r->open( $file, null, LIBXML_NONET | LIBXML_PARSEHUGE ) )
            return null;
        $version = null;
        $depth = 0;
        while( @$r->read() )
        {
            if( $r->nodeType == XMLReader::DOC_TYPE )
                break;
            if( $r->nodeType != XMLReader::ELEMENT )
                continue;
            if( $r->depth === 0 && $r->name !== 'predefined' )
                break;
            if( $r->depth === 1 && $r->name === 'application-version' )
            {
                $version = trim( (string)$r->readString() );
                break;
            }
        }
        $r->close();
        return $version !== null && preg_match( '/^[0-9]{1,6}-[0-9]{1,6}$/', $version ) ? $version : null;
    }

    private function dataMeta( string $file ): ?array
    {
        $m = json_decode( (string)@file_get_contents( $file ), TRUE );
        return is_array( $m ) ? $m : null;
    }

    /** puts a predefined.xml in place (installation: central/, project: projects/<pid>/) with its description */
    private function appidInstall( string $from, string $targetDir, string $source, string $user ): array
    {
        $version = self::predefinedVersion( $from );
        if( $version === null )
            throw new ViewerException( 'no App-ID database: a predefined.xml (<predefined> with <application-version>) is needed', 400 );
        $tmp = $targetDir . '/predefined.xml.' . getmypid() . '.tmp';
        if( !copy( $from, $tmp ) )
            throw new ViewerException( 'the App-ID database can not be stored', 500 );
        @chmod( $tmp, 0600 );
        if( is_file( $targetDir . '/predefined.xml' ) )
            @rename( $targetDir . '/predefined.xml', $targetDir . '/predefined.prev.xml' );
        rename( $tmp, $targetDir . '/predefined.xml' );
        $meta = array( 'version' => $version, 'source' => $source, 'user' => $user, 'time' => time(), 'size' => filesize( $targetDir . '/predefined.xml' ) );
        file_put_contents( $targetDir . '/predefined.json', json_encode( $meta ) );
        return $meta;
    }

    /** MaxMind data from the folder of a run (geoip/data/RegionCCipv4.json, …) into central/geoip */
    private function geoipInstall( string $fromDir, string $source, string $user ): array
    {
        $files = array();
        foreach( array( 'RegionCCipv4.json', 'RegionCCipv6.json' ) as $f )
        {
            $c = @file_get_contents( $fromDir . '/data/' . $f );
            if( !is_string( $c ) || !is_array( json_decode( $c, TRUE ) ) )
                throw new ViewerException( 'the MaxMind data was not created (see run.log)' );
            $files[$f] = $c;
        }
        $dir = $this->dataDir . '/central/geoip';
        $tmp = $dir . '.' . getmypid() . '.tmp';
        self::rmTree( $tmp );
        mkdir( $tmp . '/data', 0700, TRUE );
        foreach( $files as $f => $c )
            file_put_contents( $tmp . '/data/' . $f, $c );
        $meta = array( 'source' => $source, 'user' => $user, 'time' => time(), 'countries' => count( (array)json_decode( $files['RegionCCipv4.json'], TRUE ) ) );
        file_put_contents( $tmp . '/geoip.json', json_encode( $meta ) );
        self::rmTree( $dir . '.prev' );
        if( is_dir( $dir ) )
            rename( $dir, $dir . '.prev' );
        rename( $tmp, $dir );
        return $meta;
    }

    /** App-ID of the image (lib/object-classes/predefined.xml) */
    private function imageAppidVersion(): ?string
    {
        return self::predefinedVersion( $this->repoDir . '/lib/object-classes/predefined.xml' );
    }

    /** the App-ID database / MaxMind data of the installation (administrator) and their runs */
    public function centralInfo( array $user ): array
    {
        if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        $c = $this->dataDir . '/central';
        $runs = array();
        $sys = $this->q( 'SELECT id FROM projects WHERE pid = ?', array( self::SYSTEM_PID ) )->fetch();
        if( $sys )
            $runs = $this->jobList( $user, self::SYSTEM_PID );
        return array( 'pid' => self::SYSTEM_PID, 'image' => array( 'version' => $this->imageAppidVersion() ),
            'appid' => is_file( $c . '/predefined.xml' ) ? $this->dataMeta( $c . '/predefined.json' ) : null,
            'geoip' => is_file( $c . '/geoip/data/RegionCCipv4.json' ) ? $this->dataMeta( $c . '/geoip/geoip.json' ) : null,
            'runs' => $runs );
    }

    /** the project of the installation-wide runs (made on first use, owned by the first administrator who needs it) */
    public function systemProject( array $user ): array
    {
        if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        if( !$this->q( 'SELECT 1 FROM projects WHERE pid = ?', array( self::SYSTEM_PID ) )->fetch() )
        {
            $this->q( 'INSERT INTO projects (pid, name, owner_id, created) VALUES (?,?,?,?)', array( self::SYSTEM_PID, '#installation', $user['id'], time() ) );
            @mkdir( $this->projectDir( self::SYSTEM_PID ), 0700, TRUE );
        }
        return $this->projectGet( $user, self::SYSTEM_PID, 'owner' );
    }

    /** an uploaded App-ID database (predefined.xml): installation ($pid null, administrator) or project (write) */
    public function appidUpload( array $user, ?string $pid, ?array $upload ): array
    {
        if( $pid === null )
        {
            if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
                throw new ViewerException( 'not found', 404 );
            $dir = $this->dataDir . '/central';
        }
        else
        {
            $p = $this->projectGet( $user, $pid, 'write' );
            self::needUnlimited( $p, 'the App-ID database' );
            $dir = $this->projectDir( $p['pid'] );
        }
        if( $upload === null || ( $upload['error'] ?? 1 ) !== UPLOAD_ERR_OK || !is_uploaded_file( $upload['tmp_name'] ) )
            throw new ViewerException( 'file: a predefined.xml', 400 );
        return $this->appidInstall( $upload['tmp_name'], $dir, 'upload ' . substr( basename( (string)( $upload['name'] ?? '' ) ), 0, 80 ), $user['name'] );
    }

    /** back to the App-ID database of the image (installation) / of the installation (project) */
    public function appidReset( array $user, ?string $pid ): void
    {
        if( $pid === null )
        {
            if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
                throw new ViewerException( 'not found', 404 );
            $dir = $this->dataDir . '/central';
        }
        else
            $dir = $this->projectDir( $this->projectGet( $user, $pid, 'write' )['pid'] );
        foreach( array( 'predefined.xml', 'predefined.json', 'predefined.prev.xml' ) as $f )
            @unlink( $dir . '/' . $f );
    }

    /** the App-ID database a project uses: its own, the one of the installation, or the one of the image */
    public function appidInfo( array $user, string $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        $own = $this->projectDir( $p['pid'] ) . '/predefined.xml';
        $central = $this->dataDir . '/central/predefined.xml';
        if( is_file( $own ) )
            return array( 'from' => 'project', 'meta' => $this->dataMeta( $this->projectDir( $p['pid'] ) . '/predefined.json' ) );
        if( is_file( $central ) )
            return array( 'from' => 'installation', 'meta' => $this->dataMeta( $this->dataDir . '/central/predefined.json' ) );
        return array( 'from' => 'image', 'meta' => array( 'version' => $this->imageAppidVersion() ) );
    }

    /** the PHP extension zip (ZipArchive) on the server: a clear error instead of "Class ZipArchive not found" */
    public static function needZip(): void
    {
        if( !class_exists( 'ZipArchive' ) )
            throw new ViewerException( 'the PHP extension zip is missing on the server (php' . PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION
                . '-zip / docker-php-ext-install zip) - a zip can not be read; JSON files can still be imported', 500 );
    }

    /** MaxMind data from an uploaded GeoLite2-Country-CSV zip (air gap): a run without network makes the data */
    public function geoipUpload( array $user, ?array $upload ): array
    {
        $p = $this->systemProject( $user );
        if( $upload === null || ( $upload['error'] ?? 1 ) !== UPLOAD_ERR_OK || !is_uploaded_file( $upload['tmp_name'] ) )
            throw new ViewerException( 'file: the GeoLite2-Country-CSV zip of MaxMind', 400 );
        self::needZip();
        $zip = new ZipArchive();
        $ok = $zip->open( $upload['tmp_name'] ) === TRUE;
        $names = array();
        for( $i = 0; $ok && $i < $zip->numFiles; $i++ )
            $names[] = (string)$zip->getNameIndex( $i );
        if( $ok )
            $zip->close();
        if( !$ok || count( preg_grep( '#^GeoLite2-Country-CSV_[0-9]{8}/GeoLite2-Country-Blocks-IPv4\.csv$#', $names ) ) !== 1
            || count( preg_grep( '#(^/|\.\./|^\.\.)#', $names ) ) > 0 )
            throw new ViewerException( 'file: the GeoLite2-Country-CSV zip of MaxMind (folder GeoLite2-Country-CSV_<date> with the CSV files)', 400 );
        $jid = self::randomId();
        $dir = $this->jobDir( $p, $jid );
        mkdir( $dir, 0700, TRUE );
        move_uploaded_file( $upload['tmp_name'], $dir . '/GeoLite2-Country-CSV-upload.zip' );
        $this->q( 'INSERT INTO jobs (jid, project_id, config_id, user_id, type, args, state, created) VALUES (?,?,?,?,?,?,?,?)',
            array( $jid, $p['id'], 0, $user['id'], 'geoip', json_encode( array( 'x-geoip-zip=upload' ) ), 'queued', time() ) );
        return $this->jobGet( $user, self::SYSTEM_PID, $jid );
    }

    public function geoipReset( array $user ): void
    {
        if( empty( $user['is_admin'] ) || isset( $user['token'] ) )
            throw new ViewerException( 'not found', 404 );
        self::rmTree( $this->dataDir . '/central/geoip' );
        self::rmTree( $this->dataDir . '/central/geoip.prev' );
    }
}
