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
 * One container per run (todo/config-viewer-api.md, decision 2). Used by bin/jobs.php only - the web part never
 * starts a container and needs no access to the container runtime.
 *
 * The call is built here from fixed parts; from the job come only: project id, job id, version file name (all
 * checked against [0-9a-f]{32}) and the pan-os-php arguments, which run inside the container:
 *   - no network, read-only root file system, no capabilities, no new privileges, limits for memory / CPU / processes
 *   - the project folder read-only at /project (version files, playbooks, BP JSON), the folder of the run
 *     read-write at /job (working directory, result files) - nothing else of the data directory, no other project
 *
 * Environment:
 *   PANOSPHP_VIEWER_CONTAINER         docker | podman (empty: no container, a run is a process of the job runner)
 *   PANOSPHP_VIEWER_CONTAINER_IMAGE   image with pan-os-php (same version as the viewer), e.g. swaschkut/pan-os-php:develop
 *   PANOSPHP_VIEWER_CONTAINER_DATA    where the runtime finds the data directory: an absolute path on the host of
 *                                     the runtime, or the name of the volume that holds it (job runner in a container).
 *                                     Default: PANOSPHP_VIEWER_DATA as the job runner sees it (job runner on the host).
 *   PANOSPHP_VIEWER_CONTAINER_TOOL    pan-os-php.php in the image (default /tools/pan-os-php/utils/pan-os-php.php)
 *   PANOSPHP_VIEWER_CONTAINER_MEMORY  default 2g      PANOSPHP_VIEWER_CONTAINER_CPUS  default 2
 *   PANOSPHP_VIEWER_CONTAINER_USER    uid:gid in the container (default: the one of the job runner)
 *   PANOSPHP_VIEWER_CONTAINER_PLUGINS absolute path on the host of the runtime of the folder that holds plug-ins which
 *                                     are not in the image (a run of such a plug-in gets its folder read-only at /plugin)
 */
class ViewerContainer
{
    public string $program, $image, $data, $tool, $memory, $cpus, $user, $label, $plugins;

    /** null when PANOSPHP_VIEWER_CONTAINER is not set */
    public static function fromEnv( string $dataDir ): ?ViewerContainer
    {
        $program = (string)getenv( 'PANOSPHP_VIEWER_CONTAINER' );
        if( $program === '' )
            return null;
        if( $program !== 'docker' && $program !== 'podman' )
            throw new Exception( 'PANOSPHP_VIEWER_CONTAINER must be docker or podman' );
        $c = new ViewerContainer();
        $c->program = $program;
        $c->image = (string)getenv( 'PANOSPHP_VIEWER_CONTAINER_IMAGE' );
        if( !preg_match( '#^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,254}$#', $c->image ) )
            throw new Exception( 'PANOSPHP_VIEWER_CONTAINER_IMAGE must be set to the pan-os-php image' );
        $c->data = rtrim( (string)( getenv( 'PANOSPHP_VIEWER_CONTAINER_DATA' ) ?: $dataDir ), '/' );
        if( !preg_match( '#^(/[A-Za-z0-9._ /-]+|[A-Za-z0-9][A-Za-z0-9_.-]*)$#', $c->data ) || strpos( $c->data, '..' ) !== FALSE )
            throw new Exception( 'PANOSPHP_VIEWER_CONTAINER_DATA must be an absolute path or a volume name' );
        // plug-ins that are not part of the image: where the runtime finds the folder that holds them (absolute path on its host)
        $c->plugins = rtrim( (string)getenv( 'PANOSPHP_VIEWER_CONTAINER_PLUGINS' ), '/' );
        if( $c->plugins !== '' && ( !preg_match( '#^/[A-Za-z0-9._ /-]+$#', $c->plugins ) || strpos( $c->plugins, '..' ) !== FALSE ) )
            throw new Exception( 'PANOSPHP_VIEWER_CONTAINER_PLUGINS must be an absolute path' );
        $c->tool = (string)( getenv( 'PANOSPHP_VIEWER_CONTAINER_TOOL' ) ?: '/tools/pan-os-php/utils/pan-os-php.php' );
        $c->memory = (string)( getenv( 'PANOSPHP_VIEWER_CONTAINER_MEMORY' ) ?: '2g' );
        $c->cpus = (string)( getenv( 'PANOSPHP_VIEWER_CONTAINER_CPUS' ) ?: '2' );
        $c->user = (string)( getenv( 'PANOSPHP_VIEWER_CONTAINER_USER' ) ?: ( function_exists( 'posix_getuid' ) ? posix_getuid() . ':' . posix_getgid() : '' ) );
        if( !preg_match( '#^/[A-Za-z0-9._/-]+\.php$#', $c->tool ) || !preg_match( '/^[0-9]+[bkmg]?$/', $c->memory ) || !preg_match( '/^[0-9]+(\.[0-9]+)?$/', $c->cpus )
            || !preg_match( '/^([0-9]+:[0-9]+)?$/', $c->user ) )
            throw new Exception( 'PANOSPHP_VIEWER_CONTAINER_TOOL / _MEMORY / _CPUS / _USER: not a valid value' );
        // the containers of this installation (clean up after a stop of the job runner)
        $c->label = 'panosphp-viewer=' . substr( hash( 'sha256', $dataDir ), 0, 16 );
        return $c;
    }

    public static function name( string $jid ): string
    {
        return 'panosphp-run-' . $jid;
    }

    private function mount( string $sub, string $target, bool $readOnly ): string
    {
        if( $this->data[0] === '/' )
            $m = 'type=bind,src=' . $this->data . '/' . $sub . ',dst=' . $target;
        else
            $m = 'type=volume,src=' . $this->data . ',dst=' . $target . ',volume-subpath=' . $sub;
        return $m . ( $readOnly ? ',readonly' : '' );
    }

    /**
     * @param array $job from ViewerApp::runnerTake(): pid, jid, file, tool (pan-os-php type; default: type), rawArgs (with %FILES% / %JOB%)
     * @return string[] argument array for proc_open (no shell)
     */
    public function runCommand( array $job ): array
    {
        foreach( array( 'pid', 'jid' ) as $k )
            if( !preg_match( '/^[0-9a-f]{32}$/', (string)$job[$k] ) )
                throw new Exception( 'container: invalid ' . $k );
        if( ( $job['file'] !== null && !preg_match( '/^[0-9a-f]{32}\.xml$/', (string)$job['file'] ) ) || !preg_match( '/^[a-z-]+$/', (string)( $job['tool'] ?? $job['type'] ) ) )
            throw new Exception( 'container: invalid job' );
        $args = array();
        foreach( $job['rawArgs'] as $a )
            $args[] = str_replace( array( '%FILES%', '%JOB%' ), array( '/project/files', '/job' ), $a );

        $cmd = array( $this->program, 'run', '--rm', '--name', self::name( $job['jid'] ), '--label', $this->label,
            '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '256', '--memory', $this->memory, '--cpus', $this->cpus,
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=256m',
            '--mount', $this->mount( 'projects/' . $job['pid'], '/project', TRUE ),
            '--mount', $this->mount( 'projects/' . $job['pid'] . '/jobs/' . $job['jid'], '/job', FALSE ),
            '--workdir', '/job', '--env', 'HOME=/job', '--env', 'TMPDIR=/job', '--env', 'PANOSPHP_LOG_DIR=/job/log' );
        // a run type of a plug-in that needs its files: the folder of the plug-in read-only at /plugin (a plug-in shipped in
        // the image is there already)
        if( !empty( $job['pluginPackage'] ) )
        {
            // an encrypted plug-in: the package file read-only, the licence as environment; the run decrypts in memory
            if( !preg_match( '/^[a-z][a-z0-9]{1,30}$/', (string)( $job['plugin'] ?? '' ) ) || !preg_match( '#^[A-Za-z0-9+/=: _.-]{40,20000}$#', (string)( $job['licence'] ?? '' ) ) )
                throw new Exception( 'container: invalid plug-in package' );
            if( $this->plugins === '' )
                throw new Exception( 'PANOSPHP_VIEWER_CONTAINER_PLUGINS is not set (the folder of the plug-ins on the host)' );
            array_push( $cmd, '--mount', 'type=bind,src=' . $this->plugins . '/' . $job['plugin'] . '.ppp,dst=/plugins/' . $job['plugin'] . '.ppp,readonly',
                '--env', 'PANOSPHP_PLUGIN_PACKAGES=/plugins/' . $job['plugin'] . '.ppp', '--env', 'PANOSPHP_LICENSE=' . $job['licence'] );
            foreach( $job['rawEnv'] ?? array() as $k => $v )
                if( preg_match( '/^PANOSPHP_[A-Z0-9_]{1,40}$/', (string)$k ) && strpos( (string)$k, 'PANOSPHP_VIEWER_' ) !== 0 )
                    array_push( $cmd, '--env', $k . '=' . str_replace( '%PLUGIN%', 'ppp://' . $job['plugin'], (string)$v ) );
        }
        elseif( count( $job['rawEnv'] ?? array() ) )
        {
            if( !preg_match( '/^[a-z][a-z0-9]{1,30}$/', (string)( $job['plugin'] ?? '' ) ) )
                throw new Exception( 'container: invalid plug-in' );
            if( !empty( $job['pluginBuiltin'] ) )
                $where = dirname( $this->tool ) . '/develop/config-viewer/plugins/' . $job['plugin'];
            else
            {
                if( $this->plugins === '' )
                    throw new Exception( 'PANOSPHP_VIEWER_CONTAINER_PLUGINS is not set (the folder of the plug-ins on the host)' );
                array_push( $cmd, '--mount', 'type=bind,src=' . $this->plugins . '/' . $job['plugin'] . ',dst=/plugin,readonly' );
                $where = '/plugin';
            }
            foreach( $job['rawEnv'] as $k => $v )
                if( preg_match( '/^PANOSPHP_[A-Z0-9_]{1,40}$/', (string)$k ) && strpos( (string)$k, 'PANOSPHP_VIEWER_' ) !== 0 )
                    array_push( $cmd, '--env', $k . '=' . str_replace( '%PLUGIN%', $where, (string)$v ) );
        }
        if( $this->user !== '' )
            array_push( $cmd, '--user', $this->user );
        array_push( $cmd, '--entrypoint', 'php', $this->image, $this->tool, 'type=' . ( $job['tool'] ?? $job['type'] ) );
        // a run type of a plug-in without a version has no in=
        if( $job['file'] !== null )
            $cmd[] = 'in=/project/' . $job['file'];
        return array_merge( $cmd, $args );
    }

    /** stop the container of a run (cancel, time limit, delete) */
    public function kill( string $jid ): void
    {
        if( preg_match( '/^[0-9a-f]{32}$/', $jid ) )
            self::quiet( array( $this->program, 'rm', '--force', self::name( $jid ) ) );
    }

    /** containers left from a stopped job runner */
    public function cleanup(): void
    {
        $out = self::quiet( array( $this->program, 'ps', '--all', '--quiet', '--filter', 'label=' . $this->label ) );
        foreach( preg_split( '/\s+/', trim( $out ), -1, PREG_SPLIT_NO_EMPTY ) as $id )
            if( preg_match( '/^[0-9a-f]{6,64}$/', $id ) )
                self::quiet( array( $this->program, 'rm', '--force', $id ) );
    }

    /** is the runtime reachable ? - error text or null */
    public function check(): ?string
    {
        $p = @proc_open( array( $this->program, 'version' ), array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'file', '/dev/null', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes );
        if( !is_resource( $p ) )
            return $this->program . ' can not be started';
        $err = trim( (string)stream_get_contents( $pipes[2] ) );
        return proc_close( $p ) === 0 ? null : ( $err !== '' ? $err : $this->program . ' version failed' );
    }

    private static function quiet( array $cmd ): string
    {
        $p = @proc_open( $cmd, array( 0 => array( 'file', '/dev/null', 'r' ), 1 => array( 'pipe', 'w' ), 2 => array( 'file', '/dev/null', 'w' ) ), $pipes );
        if( !is_resource( $p ) )
            return '';
        $out = (string)stream_get_contents( $pipes[1] );
        proc_close( $p );
        return $out;
    }
}
