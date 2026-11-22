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
 * Encrypted plug-in packages (<name>.ppp) - todo/config-viewer-license.md, decision 6.
 *
 * A package holds the files of a plug-in (plugin.php, parsers, …) encrypted with XChaCha20-Poly1305 (PHP sodium). The
 * key is in the licence of the customer (PluginLicense::packageKey); a new key for every release. Decrypted files stay
 * in memory and are read through the stream wrapper ppp://<name>/<path> - require / include / is_file work on them,
 * nothing is written to disk.
 *
 * Format:  line 1  "PANOSPHP-PLUGIN 1"
 *          line 2  header JSON: name, version, feature, kid, nonce (base64) - authenticated as associated data
 *          line 3  base64 of the cipher text of JSON {"files": {"<path>": "<base64 content>", …}}
 *
 * In a run of pan-os-php: PANOSPHP_PLUGIN_PACKAGES (paths, separated by ":") + PANOSPHP_LICENSE (the licence text) -
 * bootFromEnv() mounts them at start (lib/pan_php_framework.php).
 */
class PluginPackage
{
    const MAGIC = 'PANOSPHP-PLUGIN 1';

    /** @var array name => array( path => content ) of the mounted packages */
    public static $files = array();
    /** @var array name => header */
    public static $headers = array();

    /** the header of a package file, without decrypting it */
    public static function header( string $file ): array
    {
        $fh = @fopen( $file, 'r' );
        if( $fh === FALSE )
            throw new Exception( 'plug-in package: can not be read' );
        $magic = rtrim( (string)fgets( $fh ), "\r\n" );
        $head = json_decode( rtrim( (string)fgets( $fh, 65536 ), "\r\n" ), TRUE );
        fclose( $fh );
        if( $magic !== self::MAGIC || !is_array( $head ) || !preg_match( '/^[a-z][a-z0-9]{1,30}$/', (string)( $head['name'] ?? '' ) )
            || !is_string( $head['kid'] ?? null ) || !is_string( $head['nonce'] ?? null ) || !is_string( $head['feature'] ?? null ) )
            throw new Exception( 'plug-in package: not a package of pan-os-php' );
        return $head;
    }

    /**
     * decrypt a package into memory and make it readable as ppp://<name>/…
     * @return array the header
     * @throws Exception not licensed (no licence, ended, feature missing, key of this release missing) or damaged
     */
    public static function mount( string $file, ?PluginLicense $licence ): array
    {
        $head = self::header( $file );
        if( $licence === null )
            throw new Exception( 'not licensed: no licence installed' );
        if( !$licence->usable() )
            throw new Exception( 'not licensed: the licence ended on ' . $licence->data['valid_until'] );
        if( !in_array( $head['feature'], $licence->data['features'], TRUE ) )
            throw new Exception( 'not licensed: the licence does not hold the feature ' . $head['feature'] );
        $key = $licence->packageKey( $head['kid'] );
        if( $key === null )
            throw new Exception( 'not licensed: the licence does not hold the key of this release (' . preg_replace( '/[^A-Za-z0-9._-]/', '', (string)( $head['version'] ?? '' ) ) . ') - a renewed licence is needed' );
        $lines = explode( "\n", (string)file_get_contents( $file ), 4 );
        $nonce = base64_decode( $head['nonce'], TRUE );
        $cipher = base64_decode( trim( $lines[2] ?? '' ), TRUE );
        $plain = ( $nonce === FALSE || $cipher === FALSE ) ? FALSE
            : sodium_crypto_aead_xchacha20poly1305_ietf_decrypt( $cipher, rtrim( $lines[1], "\r" ), $nonce, $key );
        sodium_memzero( $key );
        $j = $plain === FALSE ? null : json_decode( $plain, TRUE );
        if( !is_array( $j ) || !is_array( $j['files'] ?? null ) )
            throw new Exception( 'plug-in package: damaged or changed' );
        $files = array();
        foreach( $j['files'] as $path => $b64 )
            if( is_string( $path ) && preg_match( '#^[A-Za-z0-9_][A-Za-z0-9_./-]*$#', $path ) && strpos( $path, '..' ) === FALSE )
                $files[$path] = (string)base64_decode( (string)$b64 );
        self::register();
        self::$files[$head['name']] = $files;
        self::$headers[$head['name']] = $head;
        return $head;
    }

    public static function register(): void
    {
        if( !in_array( 'ppp', stream_get_wrappers(), TRUE ) )
            stream_wrapper_register( 'ppp', 'PluginPackageStream' );
    }

    /** in a run: mount what PANOSPHP_PLUGIN_PACKAGES names, with the licence in PANOSPHP_LICENSE */
    public static function bootFromEnv(): void
    {
        $list = (string)getenv( 'PANOSPHP_PLUGIN_PACKAGES' );
        if( $list === '' )
            return;
        $licence = null;
        try
        {
            $licence = PluginLicense::parse( (string)getenv( 'PANOSPHP_LICENSE' ) );
        }
        catch( Exception $e )
        {
            fwrite( STDERR, "pan-os-php: " . $e->getMessage() . "\n" );
        }
        foreach( explode( ':', $list ) as $file )
            if( $file !== '' )
            {
                try
                {
                    self::mount( $file, $licence );
                }
                catch( Exception $e )
                {
                    fwrite( STDERR, "pan-os-php: plug-in package " . basename( $file ) . ": " . $e->getMessage() . "\n" );
                }
            }
    }

    /** the content of ppp://<name>/<path>, or null */
    public static function content( string $url ): ?string
    {
        if( !preg_match( '#^ppp://([a-z][a-z0-9]{1,30})/(.+)$#', $url, $m ) )
            return null;
        $path = preg_replace( '#/+#', '/', $m[2] );
        // "a/b/../c": the parsers build paths with dirname()
        $parts = array();
        foreach( explode( '/', $path ) as $p )
        {
            if( $p === '..' )
                array_pop( $parts );
            elseif( $p !== '.' && $p !== '' )
                $parts[] = $p;
        }
        return self::$files[$m[1]][implode( '/', $parts )] ?? null;
    }

    public static function isDir( string $url ): bool
    {
        if( !preg_match( '#^ppp://([a-z][a-z0-9]{1,30})(/.*)?$#', rtrim( $url, '/' ), $m ) || !isset( self::$files[$m[1]] ) )
            return FALSE;
        $prefix = trim( $m[2] ?? '', '/' );
        if( $prefix === '' )
            return TRUE;
        foreach( array_keys( self::$files[$m[1]] ) as $p )
            if( strpos( $p, $prefix . '/' ) === 0 )
                return TRUE;
        return FALSE;
    }
}

/** stream wrapper ppp:// - read only */
class PluginPackageStream
{
    public $context;
    private $data = '';
    private $pos = 0;

    public function stream_open( $path, $mode, $options, &$opened )
    {
        if( strpbrk( $mode, 'waxc+' ) !== FALSE )
            return FALSE;
        $c = PluginPackage::content( $path );
        if( $c === null )
            return FALSE;
        $this->data = $c;
        $this->pos = 0;
        return TRUE;
    }

    public function stream_read( $count )
    {
        $r = substr( $this->data, $this->pos, $count );
        $this->pos += strlen( $r );
        return $r;
    }

    public function stream_eof()
    {
        return $this->pos >= strlen( $this->data );
    }

    public function stream_tell()
    {
        return $this->pos;
    }

    public function stream_seek( $offset, $whence )
    {
        $len = strlen( $this->data );
        $new = $whence === SEEK_SET ? $offset : ( $whence === SEEK_CUR ? $this->pos + $offset : $len + $offset );
        if( $new < 0 || $new > $len )
            return FALSE;
        $this->pos = $new;
        return TRUE;
    }

    public function stream_stat()
    {
        return self::stat( strlen( $this->data ), FALSE );
    }

    public function stream_set_option( $option, $arg1, $arg2 )
    {
        return FALSE;
    }

    public function stream_close()
    {
        $this->data = '';
    }

    public function url_stat( $path, $flags )
    {
        $c = PluginPackage::content( $path );
        if( $c !== null )
            return self::stat( strlen( $c ), FALSE );
        if( PluginPackage::isDir( $path ) )
            return self::stat( 0, TRUE );
        return FALSE;
    }

    private static function stat( int $size, bool $dir ): array
    {
        $mode = $dir ? 0040555 : 0100444;
        return array( 'dev' => 0, 'ino' => 0, 'mode' => $mode, 'nlink' => 1, 'uid' => 0, 'gid' => 0, 'rdev' => 0, 'size' => $size,
            'atime' => 0, 'mtime' => 0, 'ctime' => 0, 'blksize' => -1, 'blocks' => -1 );
    }
}
