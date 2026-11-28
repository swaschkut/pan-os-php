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
 * jobs (runs of pan-os-php with result files): create a run with its checked arguments, list, result files.
 */
trait ViewerAppJobs
{
    // ------------------------------------------------------------------ jobs: create a run, its arguments, list, result files

    public function jobCreate( array $user, $pid, $cid, $type, array $in ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        if( !is_string( $type ) || !in_array( $type, $this->jobTypes(), TRUE ) )
            throw new ViewerException( 'not found', 404 );
        $plugin = $this->pluginRuns()[$type] ?? null;
        // a run works on the whole configuration
        self::needUnlimited( $p, 'a ' . $type . ' run' );
        // a run type of a plug-in with 'input' => 'none' has no version (its input is a project file); an import neither
        $noVersion = ( $plugin !== null && $plugin['input'] === 'none' ) || in_array( $type, array( 'import', 'appid', 'geoip', 'ldap', 'ldap-discover', 'egress-ip', 'scm-pa' ), TRUE )
            // the PSK list: of a version and / or (with an SCM key) of the firewalls managed by SCM
            || ( $type === 'psk-list' && $cid === null );
        // the project of the installation-wide runs has only App-ID / MaxMind runs; MaxMind is installation-wide only
        if( ( $p['pid'] === self::SYSTEM_PID && !in_array( $type, array( 'appid', 'geoip' ), TRUE ) ) || ( $type === 'geoip' && $p['pid'] !== self::SYSTEM_PID ) )
            throw new ViewerException( 'not found', 404 );
        if( $noVersion !== ( $cid === null ) )
            throw new ViewerException( 'not found', 404 );
        $c = $noVersion ? array( 'id' => 0 ) : $this->configGet( $p, $cid );

        $args = array();
        if( $type === 'import' )
        {
            // the configuration of a firewall / Panorama (XML API) or an SCM tenant, read only, with an API key of this
            // user; becomes a new version. Needs: network for runs (administrator), network of this project (owner),
            // the target allowed by the lists of the administrator, write permission.
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)( $in['kid'] ?? '' ), $user['id'] ) )->fetch();
            if( !$k || !in_array( $k['kind'], array( 'panos', 'scm' ), TRUE ) )
                throw new ViewerException( 'kid: one of your API keys of a firewall / Panorama or an SCM tenant (Account, My API keys)', 400 );
            // the order of the reasons: installation, project, target
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( $k['kind'], $k['target'], $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->networkRefusal( $k['kind'], $k['target'], $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            $source = $in['source'] ?? 'candidate';
            if( !in_array( $source, array( 'candidate', 'running' ), TRUE ) || ( $k['kind'] === 'scm' && $source !== 'candidate' ) )
                throw new ViewerException( 'source: candidate or running (PAN-OS)', 400 );
            // only references here - the runner builds the steps and the key store of the run when it starts
            $role = self::bindRole( $p, $k['kind'], $k['target'], $in['role'] ?? null );
            // one import of a project at a time (a second click while the first is queued / running)
            $busy = $this->q( "SELECT jid FROM jobs WHERE project_id = ? AND type = 'import' AND state IN ('queued', 'running') ORDER BY id LIMIT 1", array( $p['id'] ) )->fetch();
            if( $busy )
                throw new ViewerException( 'an import of this project is already queued / running (run ' . substr( $busy['jid'], 0, 8 ) . ') - see Runs and project files', 409 );
            $args = array( 'x-import-key=' . $k['kid'], 'x-import-target=' . $k['kind'] . ':' . $k['target'], 'x-import-source=' . $source );
            if( $role !== null )
                $args[] = 'x-role=' . $role;
            // SCM: the scope of the import - given with the import (chosen the first time / changed by the owner) or the
            // one of the project; fixed in the arguments of the run
            if( $k['kind'] === 'scm' )
            {
                if( isset( $in['scope'] ) )
                {
                    $given = self::scopeCheck( $in['scope'] );
                    if( $given !== self::scopeOf( $p ) )
                    {
                        if( self::scopeOf( $p ) !== null && $p['role'] !== 'owner' )
                            throw new ViewerException( 'not allowed: the scope of the SCM import is changed by the owner', 403 );
                        $this->q( 'UPDATE projects SET import_scope = ? WHERE id = ?', array( json_encode( $given ), $p['id'] ) );
                    }
                    $scope = $given;
                }
                else
                    $scope = self::scopeOf( $p );
                $args[] = 'x-import-areas=' . implode( ',', array_merge( array( 'config' ), self::scopeAreas( $scope ) ) );
                $args[] = 'x-import-egress=' . ( $scope === null || !empty( $scope['egress'] ) ? 'yes' : 'no' );
                if( $scope !== null && count( $scope['config_scope'] ?? array() ) > 0 )
                    $args[] = 'x-import-cscope=' . implode( ',', $scope['config_scope'] );
            }
        }
        if( $type === 'egress-ip' )
        {
            // SCM tab: the egress IPs of a Prisma Access tenant, live with the egress-IP API key of this user (key store
            // kind egress IP, target = TSG). Network as for an import of the tenant (tsg:<TSG> on the allow list).
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)( $in['kid'] ?? '' ), $user['id'] ) )->fetch();
            if( !$k || $k['kind'] !== 'egressip' )
                throw new ViewerException( 'kid: one of your egress-IP API keys (Account, My API keys, kind egress IP)', 400 );
            $role = self::bindRole( $p, 'scm', $k['target'], $in['role'] ?? null );
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( 'scm', $k['target'], $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->networkRefusal( 'scm', $k['target'], $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            self::egressLib();
            try
            {
                $req = SCMEgressIP::request( null, array( 'servicetype' => (string)( $in['servicetype'] ?? 'all' ), 'addrtype' => (string)( $in['addrtype'] ?? 'all' ),
                    'location' => (string)( $in['location'] ?? 'all' ) ) );
            }
            catch( Exception $e )
            {
                throw new ViewerException( $e->getMessage(), 400 );
            }
            $env = (string)( $in['env'] ?? 'prod8' );
            if( !SCMEgressIP::validEnv( $env ) )
                throw new ViewerException( 'env: prod8 (default), prod6, prod (older tenants) or another prod<N>', 400 );
            $args = array( 'x-egress-key=' . $k['kid'], 'x-egress-target=egressip:' . $k['target'], 'servicetype=' . $req['serviceType'],
                'addrtype=' . $req['addrType'], 'location=' . $req['location'], 'env=' . $env );
            if( $role !== null )
                $args[] = 'x-role=' . $role;
        }
        if( $type === 'scm-pa' )
        {
            // SCM tab, Prisma Access (Infrastructure, …) read live: scm_pa_export.php of the area of the page with the
            // SCM key of this user (key store kind SCM, target = TSG), read only. Network as for an import of the tenant.
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $page = (string)( $in['page'] ?? '' );
            if( $page !== 'all' && !isset( self::SCM_PA_PAGES[$page] ) )
                throw new ViewerException( 'page: all | ' . implode( ' | ', array_keys( self::SCM_PA_PAGES ) ), 400 );
            $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)( $in['kid'] ?? '' ), $user['id'] ) )->fetch();
            if( !$k || $k['kind'] !== 'scm' )
                throw new ViewerException( 'kid: one of your SCM keys (Account, My API keys, kind SCM)', 400 );
            $role = self::bindRole( $p, 'scm', $k['target'], $in['role'] ?? null );
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( 'scm', $k['target'], $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->networkRefusal( 'scm', $k['target'], $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            $args = array( 'x-scmpa-key=' . $k['kid'], 'x-scmpa-target=scm:' . $k['target'], 'x-scmpa-page=' . $page );
            if( $role !== null )
                $args[] = 'x-role=' . $role;
        }
        if( $type === 'psk-list' )
        {
            // the IKE gateways and pre-shared keys (type=scm-ngfw-psk-list): of this version (offline) and / or, with an SCM
            // key of this user, of the firewalls managed by the SCM tenant (newest local configuration, read only) - then
            // both compared by the SHA-1 of the pre-shared key. The PSK lists (clear text) are sensitive results:
            // downloadable once. Write permission, not with an API token.
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $kid = (string)( $in['kid'] ?? '' );
            if( $kid === '' && $cid === null )
                throw new ViewerException( 'a version and / or kid (one of your SCM keys) is needed', 400 );
            if( $kid !== '' )
            {
                $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( $kid, $user['id'] ) )->fetch();
                if( !$k || $k['kind'] !== 'scm' )
                    throw new ViewerException( 'kid: one of your SCM keys (Account, My API keys, kind SCM)', 400 );
                $role = self::bindRole( $p, 'scm', $k['target'], $in['role'] ?? null );
                if( !$this->networkGet()['enabled'] )
                    throw new ViewerException( (string)$this->networkRefusal( 'scm', $k['target'], $user ), 403 );
                if( empty( $p['network'] ) )
                    throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
                if( ( $why = $this->networkRefusal( 'scm', $k['target'], $user ) ) !== null )
                    throw new ViewerException( $why, 403 );
                $args = array( 'x-psk-key=' . $k['kid'], 'x-psk-target=scm:' . $k['target'] );
                if( $role !== null )
                    $args[] = 'x-role=' . $role;
            }
        }
        if( $type === 'ldap-discover' )
        {
            // help for a first LDAP query: the domain controllers of an AD domain (DNS SRV) and the base DN (RootDSE of
            // the first that answers - anonymous, no password, no key). Network as for an import; the allow list must
            // cover the hosts of the domain (e.g. *.example.local) - only servers in the domain are asked.
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $domain = strtolower( trim( (string)( $in['domain'] ?? '' ) ) );
            if( strlen( $domain ) > 253 || !preg_match( '/^([a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/', $domain ) )
                throw new ViewerException( 'domain: the DNS name of the AD domain, e.g. example.local', 400 );
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( 'panos', 'dc.' . $domain, $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( $this->networkRefusal( 'panos', $domain, $user ) !== null && ( $why = $this->networkRefusal( 'panos', 'dc.' . $domain, $user ) ) !== null )
                throw new ViewerException( $why . ' - the administrator puts *.' . $domain . ' on the allow list', 403 );
            $args = array( 'x-ldap-discover-target=' . $domain, 'mode=discover', 'domain=' . $domain, 'out=%JOB%/ldap.json' );
            if( isset( $in['ldaps'] ) && ( $in['ldaps'] === FALSE || $in['ldaps'] === 'no' || $in['ldaps'] === 'false' ) )
                $args[] = 'ldaps=no';
        }
        if( $type === 'ldap' || $type === 'ldap-users' )
        {
            // an LDAP query of the user (type=ldap-query) or the users of the security rules of this version
            // (type=rule actions=user-check-ldap: show the ones that do not exist any more, or remove them - a result
            // configuration). The password: the user's key store entry ldap_user<bind user>. Network as for an import.
            $this->projectGet( $user, $pid, 'write' );
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $qr = $this->q( 'SELECT * FROM ldap_queries WHERE qid = ? AND user_id = ?', array( (string)( $in['qid'] ?? '' ), $user['id'] ) )->fetch();
            if( !$qr )
                throw new ViewerException( 'qid: one of your saved LDAP queries', 400 );
            $k = $this->q( "SELECT * FROM user_keys WHERE user_id = ? AND kind = 'ldap' AND target = ?", array( $user['id'], strtolower( $qr['bind_user'] ) ) )->fetch();
            if( !$k )
                throw new ViewerException( 'no LDAP account ' . $qr['bind_user'] . ' under Account, My API keys (kind LDAP account: bind user + password)', 400 );
            $q = self::ldapQueryCheck( array( 'name' => $qr['name'], 'server' => $qr['server'], 'domain' => $qr['domain'] ?? '', 'ldaps' => (int)( $qr['ldaps'] ?? 1 ), 'bind_user' => $qr['bind_user'], 'base_dn' => $qr['base_dn'],
                'attribute' => $qr['attribute'], 'mode' => $type === 'ldap' ? $qr['mode'] : 'validation', 'users' => $qr['users'], 'group' => $qr['grp'], 'transitive' => $qr['transitive'] ) );
            // automatic server: the target is the domain (auto:<domain>) - the allow list must cover its hosts
            $target = $q['server'] === '' ? 'auto:' . $q['domain'] : $q['host'];
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->ldapRefusal( $target, $user ), 403 );
            if( empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->ldapRefusal( $target, $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            $args = array( 'x-' . $type . '-key=' . $k['kid'], 'x-' . $type . '-target=' . $target );
            if( $type === 'ldap' )
            {
                if( $q['mode'] === 'validation' && $q['users'] === '' )
                    throw new ViewerException( 'the query has no users to check', 400 );
                array_push( $args, 'mode=' . $q['mode'], 'ldapServer=' . ( $q['server'] === '' ? 'auto' : $q['server'] ), 'ldapUser=' . $q['bind_user'], 'dn=' . $q['base_dn'], 'filtercriteria=' . $q['attribute'] );
                if( $q['server'] === '' )
                {
                    $args[] = 'domain=' . $q['domain'];
                    if( !$q['ldaps'] )
                        $args[] = 'ldaps=no';
                }
                if( $q['users'] !== '' )
                    $args[] = 'users=' . $q['users'];
                if( $q['grp'] !== '' )
                    $args[] = 'group=' . $q['grp'];
                if( $q['transitive'] )
                    $args[] = 'transitive=yes';
                array_push( $args, 'out=%JOB%/ldap.json', 'csv=%JOB%/ldap.csv' );
            }
            else
            {
                $remove = ( $in['action'] ?? 'show' ) === 'remove';
                // the arguments of the action (separated by ',', no ':' / '/'): show|remove, bind user, server as
                // ldaps%host[%port], base DN (';' instead of ','), attribute, existentUser
                if( preg_match( '#[:/]#', $q['bind_user'] . $q['base_dn'] ) )
                    throw new ViewerException( 'bind user and base DN: no ":" or "/" for the check of the rules', 400 );
                if( $q['server'] === '' )
                    // automatic: auto%<domain> (LDAPS) / auto-ldap%<domain>
                    $server = ( $q['ldaps'] ? 'auto' : 'auto-ldap' ) . '%' . $q['domain'];
                else
                {
                    preg_match( '#^(ldaps?)://([^:]+)(?::([0-9]+))?$#', $q['server'], $s );
                    $server = $s[1] . '%' . $s[2] . ( isset( $s[3] ) ? '%' . $s[3] : '' );
                }
                $args[] = 'location=any';
                $args[] = 'actions=user-check-ldap:' . ( $remove ? 'remove' : 'show' ) . ',' . $q['bind_user'] . ',' . $server . ',' . str_replace( ',', ';', $q['base_dn'] ) . ',' . $q['attribute'] . ',false';
                if( $remove )
                    $args[] = 'out=%JOB%/out.xml';
            }
        }
        if( $type === 'appid' || $type === 'geoip' )
        {
            // App-ID database from a firewall / Panorama (type=download-predefined, read only): for the installation
            // (administrator, project of the installation) or for one project (write); MaxMind GeoLite2 (installation):
            // download with the maxmind-licensekey of the administrator, or an uploaded zip (geoipUpload)
            if( isset( $user['token'] ) )
                throw new ViewerException( 'not allowed with an API token', 403 );
            $central = $p['pid'] === self::SYSTEM_PID;
            if( !$central )
                $this->projectGet( $user, $pid, 'write' );
            $k = $this->q( 'SELECT * FROM user_keys WHERE kid = ? AND user_id = ?', array( (string)( $in['kid'] ?? '' ), $user['id'] ) )->fetch();
            $want = $type === 'appid' ? 'panos' : 'named';
            if( !$k || $k['kind'] !== $want || ( $type === 'geoip' && $k['target'] !== 'maxmind-licensekey' ) )
                throw new ViewerException( 'kid: ' . ( $type === 'appid' ? 'one of your API keys of a firewall / Panorama' : 'your maxmind-licensekey' ) . ' (Account, My API keys)', 400 );
            $host = $type === 'appid' ? $k['target'] : self::MAXMIND_HOST;
            if( !$this->networkGet()['enabled'] )
                throw new ViewerException( (string)$this->networkRefusal( 'panos', $host, $user ), 403 );
            if( !$central && empty( $p['network'] ) )
                throw new ViewerException( 'network is off for this project (the owner turns it on)', 403 );
            if( ( $why = $this->networkRefusal( 'panos', $host, $user ) ) !== null )
                throw new ViewerException( $why, 403 );
            $args = array( 'x-' . $type . '-key=' . $k['kid'], 'x-' . $type . '-target=' . $host );
        }
        if( in_array( $type, array( 'object-merger', 'rule-merger', 'merger-possible-report' ), TRUE ) )
            $args = $this->mergerArgs( $user, $pid, $type, $in );
        // another pan-os-php image for a built-in run (stats, playbook): by its name in the list of the installation, as
        // for a run type of a plug-in with a field of kind "image" - e.g. the same playbook with an older release
        if( in_array( $type, self::RUN_IMAGE_TYPES, TRUE ) )
        {
            $image = $in['image'] ?? '';
            if( $image !== '' && ( !is_string( $image ) || !in_array( $image, $this->runImages(), TRUE ) ) )
                throw new ViewerException( 'image: one of the images of this installation (' . ( implode( ', ', $this->runImages() ) ?: 'none is set up' ) . ') or empty', 400 );
        }
        if( $type === 'stats' )
        {
            $location = $in['location'] ?? 'any';
            if( !is_string( $location ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,63}$/', $location ) )
                throw new ViewerException( 'location: letters, digits, space and . _ - only', 400 );
            $args = array( 'location=' . $location, 'actions=display-bpa', 'json-to-folder', 'debugapi' );
        }
        if( $type === 'diff' )
        {
            // two versions of the project: this one (file1, the original) and 'other' (file2, the newer one); no in= -
            // with in= type=diff compares inside one file. Set commands from file1 to file2 on request.
            // … or the result configurations of two finished runs of the project (run1 = file1, run2 = file2), e.g. the
            // same playbook on the same version with two pan-os-php images - without making versions of the results.
            // The version of the request is the one run1 ran on.
            if( isset( $in['run1'] ) || isset( $in['run2'] ) )
            {
                $r1 = $this->jobResultArg( $p, $in['run1'] ?? null, 'run1' );
                $r2 = $this->jobResultArg( $p, $in['run2'] ?? null, 'run2' );
                if( $r1['job']['jid'] === $r2['job']['jid'] )
                    throw new ViewerException( 'diff: choose two different runs', 400 );
                if( (int)$r1['job']['config_id'] !== (int)$c['id'] )
                    throw new ViewerException( 'diff: the version of the request is the one run1 ran on', 400 );
                $args = array( 'file1=' . $r1['arg'], 'file2=' . $r2['arg'] );
            }
            else
            {
                $other = $this->configGet( $p, $in['other'] ?? null );
                if( (int)$other['id'] === (int)$c['id'] )
                    throw new ViewerException( 'diff: choose two different versions', 400 );
                $args = array( 'file1=%PROJECT%/' . $c['file'], 'file2=%PROJECT%/' . $other['file'] );
            }
            // with outputformatset type=diff prints only the set commands - display-xpath-and-xmlnode keeps the XML
            // differences ( XPATH + / - ) in run.log as well, as without set commands
            if( !empty( $in['setcommands'] ) )
            {
                $args[] = 'outputformatset=set-commands.txt';
                $args[] = 'display-xpath-and-xmlnode';
            }
            if( !empty( $in['noruleordercheck'] ) )
                $args[] = 'noruleordercheck';
            // filter: an XPath of the configuration (never a file - type=diff reads a filter that is a file name)
            $xf = $in['xpath'] ?? '';
            if( $xf !== '' && $xf !== null )
            {
                if( !is_string( $xf ) || strlen( $xf ) > 2000 || preg_match( '/[\x00-\x1F\x7F]|\.\./', $xf )
                    || !preg_match( '#^/(config|policy|template|template-stack|cloud_services|device-group)(/|\[|$)#', $xf ) )
                    throw new ViewerException( 'diff: xpath - an XPath of the configuration, e.g. /config/devices/entry[@name=\'localhost.localdomain\']/device-group', 400 );
                $args[] = 'filter=' . $xf;
            }
        }
        if( $type === 'playbook' )
        {
            // a playbook file of the project or a predefined one (turned on by an administrator), checked again now
            // (PLAYBOOK_* rules); the stage files, the set commands and the result configuration stay in the folder of the run
            $predefined = $in['predefined'] ?? null;
            if( $predefined !== null && $predefined !== '' )
            {
                if( isset( $in['playbook'] ) && $in['playbook'] !== '' )
                    throw new ViewerException( 'playbook or predefined - not both', 400 );
                if( !self::playbookName( $predefined ) || !in_array( $predefined, array_column( $this->playbooksPredefined(), 'name' ), TRUE ) )
                    throw new ViewerException( 'predefined playbook not offered here (an administrator turns them on)', 400 );
                $this->playbookCheck( json_decode( (string)file_get_contents( $this->playbookDir() . '/' . $predefined ), TRUE ) );
                $json = 'json=$$playbook$$/' . $predefined;
            }
            else
            {
                $pb = $this->fileGet( $p, $in['playbook'] ?? null, 'playbook' );
                $this->playbookCheck( json_decode( (string)file_get_contents( $pb['path'] ), TRUE ) );
                $json = 'json=%FILES%/' . $pb['file'];
            }
            $meta = array( 'playbook' => isset( $pb ) ? $pb['fid'] : 'predefined:' . $predefined, 'then' => null, 'bp' => null );
            // "then": a second playbook file of the project whose steps run after the first, in the same run (e.g. the
            // stats and the security profile overviews of the result). Both are checked; the run gets one playbook -
            // the first with the steps of the second appended - written into its folder when it is queued (playbook.json)
            $then = $in['then'] ?? null;
            if( $then !== null && $then !== '' )
            {
                $tf = $this->fileGet( $p, $then, 'playbook' );
                $meta['then'] = $tf['fid'];
                $tj = json_decode( (string)file_get_contents( $tf['path'] ), TRUE );
                $this->playbookCheck( $tj );
                $fj = json_decode( (string)file_get_contents( isset( $pb ) ? $pb['path'] : $this->playbookDir() . '/' . $predefined ), TRUE );
                $fj['command'] = array_merge( array_values( $fj['command'] ), array_values( $tj['command'] ) );
                $this->playbookCheck( $fj );
                $playbookJoined = json_encode( $fj, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
                $json = 'json=%JOB%/playbook.json';
            }
            $args = array_merge( array( $json, 'out=%JOB%/out.xml', 'stagename=stage/step-', 'outputformatset=set-commands.txt' ), self::playbookOptions( $in ) );
        }
        if( $plugin !== null )
        {
            // a run type of a plug-in: it builds the arguments from checked values (ViewerPluginRun); in= is always
            // the version, files only from this project, results only in the folder of the run
            foreach( $plugin['fields'] as $f )
                if( $f['required'] && ( !isset( $in[$f['name']] ) || $in[$f['name']] === '' || $in[$f['name']] === array() ) )
                    throw new ViewerException( $f['name'] . ' is needed', 400 );
            // a run that needs an approval: only with every area of the newest plan approved - it gets a copy of that plan
            $approved = ( $plugin['approval'] ?? null ) !== null ? $this->approvalGate( $p, $plugin ) : null;
            $run = new ViewerPluginRun( $in, function( $fid, $kind ) use ( $p ) { return $this->fileGet( $p, $fid, $kind ); }, $plugin['fields'], $approved );
            $args = ( $plugin['args'] )( $run );
            if( !is_array( $args ) )
                throw new ViewerException( 'plug-in: no arguments', 500 );
            foreach( $args as $a )
                if( !is_string( $a ) || strlen( $a ) > 4000 || preg_match( '/[\x00-\x1f]/', $a ) || preg_match( '/^(in|type|projectfolder)=/i', $a )
                    || ( preg_match( '/^out=/i', $a ) && strpos( $a, 'out=%JOB%/' ) !== 0 ) )
                    throw new ViewerException( 'plug-in: an argument is not allowed', 500 );
            $args = array_values( $args );
            if( !$plugin['bp'] )
                unset( $in['bp'] );
            // another image for this run: one of the names of the installation (a request never names an image itself)
            if( ( $plugin['imageField'] ?? null ) !== null )
            {
                $image = $in[$plugin['imageField']] ?? '';
                if( $image !== '' && ( !is_string( $image ) || !in_array( $image, $this->runImages(), TRUE ) ) )
                    throw new ViewerException( $plugin['imageField'] . ': one of the images of this installation (' . ( implode( ', ', $this->runImages() ) ?: 'none is set up' ) . ') or empty', 400 );
            }
        }
        // the BP JSON of the project instead of the one shipped with pan-os-php
        if( isset( $in['bp'] ) )
        {
            $args[] = 'shadow-bpjsonfile=%FILES%/' . $this->fileGet( $p, $in['bp'], 'bp' )['file'];
            if( isset( $meta ) )
                $meta['bp'] = $in['bp'];
        }
        $open = (int)$this->q( "SELECT COUNT(*) AS c FROM jobs WHERE project_id = ? AND state IN ('queued','running')", array( $p['id'] ) )->fetch()['c'];
        if( $open >= self::JOB_QUEUE_MAX )
            throw new ViewerException( 'too many open runs in this project - wait for them or cancel one', 429 );
        $jid = self::randomId();
        // sensitive files of the run (fields 'secret' of a plug-in): moved from the upload into the hidden folder of the
        // run before it can start; removed when the run ends (runnerFinish)
        if( $plugin !== null )
            $this->secretMove( $user, $p, $plugin, $in, $jid );
        // a support file: what goes in is put next to the run now (hidden folder .support of the run)
        if( $type === 'support-file' )
            $args = $this->supportStage( $user, $p, $c, $jid, $in );
        // a playbook run with "then": the joined playbook is a file of the run
        if( isset( $playbookJoined ) )
        {
            $dir = $this->jobDir( $p, $jid );
            if( ( !is_dir( $dir ) && !@mkdir( $dir, 0700, TRUE ) ) || file_put_contents( $dir . '/playbook.json', $playbookJoined ) === FALSE )
                throw new ViewerException( 'the playbook of the run can not be stored', 500 );
            @chmod( $dir . '/playbook.json', 0600 );
        }
        $this->q( 'INSERT INTO jobs (jid, project_id, config_id, user_id, type, args, state, created, image, meta) VALUES (?,?,?,?,?,?,?,?,?,?)',
            array( $jid, $p['id'], $c['id'], $user['id'], $type, json_encode( $args ), 'queued', time(), ( $image ?? '' ) !== '' ? $image : null, isset( $meta ) ? json_encode( $meta ) : null ) );
        return $this->jobGet( $user, $pid, $jid );
    }

    /**
     * a support file (todo/support-file.md): pan-os-php type=support-file on the version, with - in the hidden folder
     * .support of the run - the files of the viewer for it: the case (a run of the project: its settings, report,
     * result, run.log), project and versions, the last runs, the audit of the project, the browser errors the page
     * collected, the environment of the viewer. Never in it: API keys, the key store, passwords, sessions, licence keys,
     * other projects. Options: names (objects for the excerpt), rules, full (the whole configuration), anonymize (the
     * mapping is a file of the run - for the customer only, never in the support file), note.
     */
    private function supportStage( array $user, array $p, array $c, string $jid, array $in ): array
    {
        $this->projectGet( $user, $p['pid'], 'write' );
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        if( !class_exists( 'SupportFile' ) )
            require_once $this->repoDir . '/lib/misc-classes/SupportFile.php';
        try
        {
            SupportFile::currentKey();
        }
        catch( Exception $e )
        {
            throw new ViewerException( $e->getMessage(), 400 );
        }
        $stage = $this->jobDir( $p, $jid ) . '/.support';
        if( !is_dir( $stage . '/extra' ) && !@mkdir( $stage . '/extra', 0700, TRUE ) )
            throw new ViewerException( 'the folder of the run can not be created', 500 );
        $put = function( string $name, $data ) use ( $stage ) {
            file_put_contents( $stage . '/extra/' . $name, is_string( $data ) ? $data : json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) . "\n" );
        };
        $args = array( 'out=%JOB%/support.tsf', 'extra=%JOB%/.support/extra' );
        // the case: a run of this project on this version
        if( isset( $in['run'] ) && $in['run'] !== '' && $in['run'] !== null )
        {
            $r = $this->jobRow( $p, $in['run'] );
            if( (int)$r['config_id'] !== (int)$c['id'] )
                throw new ViewerException( 'run: a run on this version', 400 );
            $rdir = $this->jobDir( $p, $r['jid'] );
            $put( 'run.json', array( 'jid' => $r['jid'], 'type' => $r['type'], 'args' => array_values( array_filter( (array)json_decode( $r['args'], TRUE ), function( $a ) {
                    return is_string( $a ) && strpos( $a, 'x-' ) !== 0; } ) ), 'state' => $r['state'], 'error' => $r['error'], 'created' => (int)$r['created'],
                'started' => $r['started'] !== null ? (int)$r['started'] : null, 'finished' => $r['finished'] !== null ? (int)$r['finished'] : null ) );
            foreach( glob( $rdir . '/run*.log' ) ?: array() as $f )
                if( is_file( $f ) && !is_link( $f ) && filesize( $f ) < 50000000 )
                    $put( basename( $f ), $this->hidePaths( (string)file_get_contents( $f ) ) );
            foreach( array( 'merger.json' => 'report', 'out.xml' => 'result' ) as $f => $arg )
                if( is_file( $rdir . '/' . $f ) && !is_link( $rdir . '/' . $f ) && copy( $rdir . '/' . $f, $stage . '/' . $f ) )
                    $args[] = $arg . '=%JOB%/.support/' . $f;
        }
        // project, versions, last runs, audit of the project - without the names of other users
        // anonymised: no names of the project / the versions (often the name of the customer)
        $anonymous = !empty( $in['anonymize'] ) && $in['anonymize'] !== 'false';
        $vn = 0;
        $put( 'project.json', array( 'name' => $anonymous ? 'project' : $p['name'], 'pid' => $p['pid'], 'created' => (int)( $p['created'] ?? 0 ),
            'versions' => array_map( function( $v ) use ( $anonymous, &$vn ) { $vn++; return array( 'name' => $anonymous ? 'version-' . $vn : $v['name'], 'size' => (int)( $v['size'] ?? 0 ),
                    'note' => $anonymous ? '' : ( $v['note'] ?? '' ), 'created' => (int)( $v['created'] ?? 0 ), 'cid' => $v['cid'] ); },
                $this->q( 'SELECT * FROM configs WHERE project_id = ? ORDER BY id', array( $p['id'] ) )->fetchAll() ),
            'version' => array( 'name' => $anonymous ? '' : ( $c['name'] ?? '' ), 'cid' => $c['cid'] ?? '' ) ) );
        $put( 'runs.json', array_map( function( $j ) { return array( 'jid' => $j['jid'], 'type' => $j['type'], 'state' => $j['state'], 'error' => $j['error'],
                'created' => (int)$j['created'], 'started' => $j['started'] !== null ? (int)$j['started'] : null, 'finished' => $j['finished'] !== null ? (int)$j['finished'] : null,
                'args' => array_values( array_filter( (array)json_decode( $j['args'], TRUE ), function( $a ) { return is_string( $a ) && strpos( $a, 'x-' ) !== 0; } ) ) ); },
            $this->q( 'SELECT * FROM jobs WHERE project_id = ? ORDER BY id DESC LIMIT 50', array( $p['id'] ) )->fetchAll() ) );
        $put( 'audit.json', array_map( function( $a ) { return array( 'ts' => (int)$a['ts'], 'method' => $a['method'], 'route' => $a['route'], 'status' => (int)$a['status'],
                'detail' => $a['detail'] !== null ? json_decode( $a['detail'], TRUE ) : null ); },
            $this->q( 'SELECT ts, method, route, status, detail FROM audit WHERE pid = ? ORDER BY id DESC LIMIT 300', array( $p['pid'] ) )->fetchAll() ) );
        // the viewer: version, settings (no host lists), licence (summary), the browser of the user
        $net = $this->networkGet();
        $browser = array_slice( array_values( array_filter( (array)( $in['browser'] ?? array() ), 'is_array' ) ), 0, 200 );
        $put( 'viewer.json', array( 'git' => trim( (string)@shell_exec( 'git -C ' . escapeshellarg( $this->repoDir ) . ' log -1 --format=%H%x20%cs 2>/dev/null' ) ) ?: null,
            'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'container' => getenv( 'PANOSPHP_VIEWER_CONTAINER' ) ?: null,
            'network' => array( 'enabled' => $net['enabled'], 'users' => $net['users'], 'conntest' => $net['conntest'], 'allow' => count( $net['allow'] ), 'deny' => count( $net['deny'] ) ),
            'userAgent' => substr( (string)( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 300 ) ) );
        if( $browser )
            $put( 'browser.json', array_map( function( $b ) { return array_map( function( $v ) { return is_scalar( $v ) ? substr( (string)$v, 0, 2000 ) : null; }, array_slice( $b, 0, 10, TRUE ) ); }, $browser ) );
        // options
        $names = trim( (string)( $in['names'] ?? '' ) );
        if( $names !== '' )
        {
            if( strlen( $names ) > 20000 || preg_match( '/[\x00-\x1f]/', $names ) )
                throw new ViewerException( 'names: object names, comma separated', 400 );
            $args[] = 'names=' . $names;
        }
        if( isset( $in['rules'] ) && ( $in['rules'] === FALSE || $in['rules'] === 'false' ) )
            $args[] = 'rules=no';
        if( !empty( $in['full'] ) && $in['full'] !== 'false' )
            $args[] = 'full';
        if( !empty( $in['anonymize'] ) && $in['anonymize'] !== 'false' )
        {
            array_push( $args, 'anonymize', 'mapping=%JOB%/mapping-SENSITIVE.json' );
            if( ( $in['ip'] ?? '' ) === 'keep-private' )
                $args[] = 'ip=keep-private';
        }
        $note = trim( (string)( $in['note'] ?? '' ) );
        if( $note !== '' )
            $args[] = 'note=' . substr( preg_replace( '/[\x00-\x1f]+/', ' ', $note ), 0, 4000 );
        return $args;
    }

    /**
     * the arguments of a merger run (Merger tab): object-merger / rule-merger on a copy of the version - the result
     * configuration out.xml (Result as new version), the report as exportJSON (merger.json: the tables of the page) and
     * exportCSV (merger.html, skipped-merger.html: download); merger-possible-report only reports (read). Every value
     * from a fixed list or checked; filters are pan-os-php filters (one argument each, no shell).
     */
    private function mergerArgs( array $user, $pid, string $type, array $in ): array
    {
        if( $type !== 'merger-possible-report' )
            $this->projectGet( $user, $pid, 'write' );
        $bool = function( $k ) use ( $in ) { $v = $in[$k] ?? FALSE; return $v === TRUE || $v === 'yes' || $v === 'true' || $v === 1 || $v === '1'; };
        $location = $in['location'] ?? 'any';
        if( $location === '' || $location === null )
            $location = 'any';
        if( !is_string( $location ) || !preg_match( '/^[A-Za-z0-9 _.\-]{1,63}(,[A-Za-z0-9 _.\-]{1,63}){0,49}$/', $location ) )
            throw new ViewerException( 'location: any, or location names (, separated) with letters, digits, space and . _ -', 400 );
        $filter = function( $k ) use ( $in ) {
            $v = $in[$k] ?? '';
            if( $v === '' || $v === null )
                return null;
            if( !is_string( $v ) || strlen( $v ) > 2000 || preg_match( '/[\x00-\x1F\x7F]/', $v ) || !preg_match( '/^[!(]/', trim( $v ) ) )
                throw new ViewerException( $k . ': a pan-os-php filter, e.g. (name regex /^H-/)', 400 );
            return trim( $v );
        };
        $types = function( array $allowed ) use ( $in ) {
            $v = $in['objecttype'] ?? 'any';
            $list = is_array( $v ) ? $v : explode( ',', (string)$v );
            $list = array_values( array_unique( array_filter( array_map( 'trim', $list ), 'strlen' ) ) );
            if( count( $list ) === 0 || in_array( 'any', $list, TRUE ) )
                return 'any';
            foreach( $list as $t )
                if( !in_array( $t, $allowed, TRUE ) && !( $allowed === array() && preg_match( '/^[a-z0-9-]{1,60}$/', $t ) ) )
                    throw new ViewerException( 'objecttype: any or ' . implode( ', ', $allowed ), 400 );
            return implode( ',', $list );
        };
        $report = array( 'exportjson=merger.json', 'exportcsv=merger.html' );
        if( $type === 'merger-possible-report' )
        {
            // the report types of pan-os-php (address, service, …, securityprofile-<type>): checked by the report
            // over all locations (the report has no location choice)
            $args = array( 'objecttype=' . $types( array() ) );
            if( $bool( 'mergecheck' ) )
                $args[] = 'mergecheck';
            return array_merge( $args, $report );
        }
        $args = array( 'location=' . $location, 'out=%JOB%/out.xml' );
        if( $type === 'object-merger' )
        {
            $args[] = 'objecttype=' . $types( self::MERGER_OBJECTTYPES );
            $dup = $in['dupalgorithm'] ?? '';
            if( $dup !== '' && $dup !== null )
            {
                if( !in_array( $dup, self::MERGER_DUPALGORITHMS, TRUE ) )
                    throw new ViewerException( 'DupAlgorithm: ' . implode( ', ', self::MERGER_DUPALGORITHMS ), 400 );
                $args[] = 'DupAlgorithm=' . $dup;
            }
            $limit = $in['mergecountlimit'] ?? '';
            if( $limit !== '' && $limit !== null )
            {
                if( !preg_match( '/^[0-9]{1,6}$/', (string)$limit ) )
                    throw new ViewerException( 'mergecountlimit: a number', 400 );
                $args[] = 'mergecountlimit=' . (int)$limit;
            }
            foreach( array( 'pickfilter' => 'pickFilter', 'excludefilter' => 'excludeFilter' ) as $k => $name )
                if( ( $f = $filter( $k ) ) !== null )
                    $args[] = $name . '=' . $f;
            if( $bool( 'allowmergingwithupperlevel' ) )
                $args[] = 'allowMergingWithUpperLevel';
            return array_merge( $args, $report );
        }
        // rule-merger
        $method = $in['method'] ?? 'matchFromToSrcDstApp';
        if( !in_array( $method, self::RULEMERGER_METHODS, TRUE ) )
            throw new ViewerException( 'method: ' . implode( ', ', self::RULEMERGER_METHODS ), 400 );
        $args[] = 'method=' . $method;
        $rb = $in['rulebase'] ?? 'pre';
        if( !in_array( $rb, array( 'pre', 'post' ), TRUE ) )
            throw new ViewerException( 'rulebase: pre or post (Panorama)', 400 );
        $args[] = $rb === 'post' ? 'panoramaPostRules' : 'panoramaPreRules';
        foreach( array( 'mergedenyrules' => 'mergeDenyRules', 'stopmergingifdenyseen' => 'stopMergingIfDenySeen', 'mergeadjacentonly' => 'mergeAdjacentOnly' ) as $k => $name )
            if( isset( $in[$k] ) )
                $args[] = $name . '=' . ( $bool( $k ) ? 'yes' : 'no' );
        if( ( $f = $filter( 'filter' ) ) !== null )
            $args[] = 'filter=' . $f;
        $add = $in['additionalmatch'] ?? array();
        $add = is_array( $add ) ? $add : array_filter( explode( ',', (string)$add ), 'strlen' );
        foreach( $add as $a )
            if( !in_array( $a, self::RULEMERGER_ADDITIONAL, TRUE ) )
                throw new ViewerException( 'additionalMatch: ' . implode( ', ', self::RULEMERGER_ADDITIONAL ), 400 );
        if( count( $add ) )
            $args[] = 'additionalMatch=' . implode( ',', array_values( array_unique( $add ) ) );
        return array_merge( $args, $report );
    }

    /**
     * an SCM import again from its export: only the conversion (type=scm-export-xml) on the JSON the run has already
     * downloaded - no network, no key. A failed import (the conversion failed), or a done one (a newer pan-os-php
     * converts more, e.g. the IKE / IPsec objects). The run is queued again (its run.log stays as run-<n>.log); when it
     * is done the configuration becomes a new version, as after an import (a done one: the Prisma Access states and
     * egress IPs of the run are not taken over a second time).
     */
    public function jobConvert( array $user, $pid, $jid ): array
    {
        $p = $this->projectGet( $user, $pid, 'write' );
        if( isset( $user['token'] ) )
            throw new ViewerException( 'not allowed with an API token', 403 );
        $j = $this->jobRow( $p, $jid );
        $args = (array)json_decode( $j['args'], TRUE );
        $tsg = null;
        foreach( $args as $a )
            if( is_string( $a ) && preg_match( '/^x-import-target=scm:([0-9]{1,20})$/', $a, $m ) )
                $tsg = $m[1];
        if( $j['type'] !== 'import' || $tsg === null )
            throw new ViewerException( 'only an SCM import can be converted again', 400 );
        if( !in_array( $j['state'], array( 'failed', 'done' ), TRUE ) )
            throw new ViewerException( 'only a finished import can be converted again (state: ' . $j['state'] . ')', 409 );
        $busy = $this->q( "SELECT jid FROM jobs WHERE project_id = ? AND type = 'import' AND state IN ('queued', 'running') ORDER BY id LIMIT 1", array( $p['id'] ) )->fetch();
        if( $busy )
            throw new ViewerException( 'an import of this project is already queued / running (run ' . substr( $busy['jid'], 0, 8 ) . ')', 409 );
        $dir = $this->jobDir( $p, $j['jid'] );
        $export = $dir . '/scm-export/' . $tsg;
        if( !is_dir( $export ) || is_link( $export ) || count( glob( $export . '/*/manifest.json' ) ?: array() ) === 0 )
            throw new ViewerException( 'the run has no complete SCM export to convert (the download did not finish) - import again', 409 );
        // the log of the attempt before
        for( $n = 1; is_file( $dir . '/run-' . $n . '.log' ) && $n < 100; $n++ );
        if( is_file( $dir . '/run.log' ) )
            @rename( $dir . '/run.log', $dir . '/run-' . $n . '.log' );
        @unlink( $dir . '/out.xml' );
        $again = $j['state'] === 'done' || in_array( 'x-import-again=yes', $args, TRUE );
        $args = array_values( array_filter( $args, function( $a ) { return $a !== 'x-import-resume=convert' && $a !== 'x-import-again=yes'; } ) );
        $args[] = 'x-import-resume=convert';
        // a done import converted again: its version, Prisma Access states and egress IPs exist already
        if( $again )
            $args[] = 'x-import-again=yes';
        if( $this->q( "UPDATE jobs SET state = 'queued', args = ?, error = NULL, reason = NULL, started = NULL, finished = NULL WHERE id = ? AND state = ?",
            array( json_encode( $args ), $j['id'], $j['state'] ) )->rowCount() === 0 )
            throw new ViewerException( 'the run changed - try again', 409 );
        return $this->jobGet( $user, $pid, $j['jid'] );
    }

    private function jobRow( array $project, $jid ): array
    {
        $j = is_string( $jid ) && preg_match( '/^[0-9a-f]{32}$/', $jid )
            ? $this->q( 'SELECT j.*, u.name AS user, c.cid FROM jobs j LEFT JOIN users u ON u.id = j.user_id LEFT JOIN configs c ON c.id = j.config_id
                WHERE j.jid = ? AND j.project_id = ?', array( $jid, $project['id'] ) )->fetch() : FALSE;
        if( !$j )
            throw new ViewerException( 'not found', 404 );
        return $j;
    }

    private static function jobPublic( array $j ): array
    {
        return array( 'jid' => $j['jid'], 'type' => $j['type'], 'cid' => $j['cid'], 'args' => json_decode( $j['args'], TRUE ), 'state' => $j['state'], 'user' => $j['user'],
            'created' => (int)$j['created'], 'started' => $j['started'] !== null ? (int)$j['started'] : null,
            'finished' => $j['finished'] !== null ? (int)$j['finished'] : null, 'error' => $j['error'], 'reason' => $j['reason'] ?? null,
            // the image the run asked for by name (null: the image of the viewer)
            'image' => $j['image'] ?? null );
    }

    /** result files of a job: names relative to the folder of the job */
    private function jobFiles( array $project, string $jid ): array
    {
        $dir = $this->jobDir( $project, $jid );
        $files = array();
        if( is_dir( $dir ) )
        {
            $it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ) );
            foreach( $it as $f )
                // never a hidden file (the key store of an import: .panconfkeystore)
                if( $f->isFile() && !$f->isLink() && !preg_match( '#(^|/)\.#', substr( $f->getPathname(), strlen( $dir ) + 1 ) ) )
                    $files[] = array( 'name' => substr( $f->getPathname(), strlen( $dir ) + 1 ), 'size' => $f->getSize() );
            usort( $files, function( $a, $b ) { return strcmp( $a['name'], $b['name'] ); } );
        }
        return $files;
    }

    public function jobList( array $user, $pid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'the list of runs' );
        $rows = $this->q( 'SELECT j.*, u.name AS user, c.cid FROM jobs j LEFT JOIN users u ON u.id = j.user_id LEFT JOIN configs c ON c.id = j.config_id
            WHERE j.project_id = ? ORDER BY j.id DESC LIMIT 200', array( $p['id'] ) )->fetchAll();
        // has_stats: the run has figures to compare (stats compare) - a stats run, or a playbook run with a stats step;
        // has_result: it has a result configuration (a diff between the results of two runs)
        return array_map( function( $j ) use ( $p ) { return self::jobPublic( $j ) + $this->jobHas( $p, $j ); }, $rows );
    }

    /** what a finished run has for the compares: a stats result, a result configuration */
    private function jobHas( array $p, array $j ): array
    {
        if( $j['state'] !== 'done' )
            return array( 'has_stats' => FALSE, 'has_result' => FALSE );
        $dir = $this->jobDir( $p, $j['jid'] );
        $result = $this->jobResultName( $j );
        // saved: the version of this project that was made from the result of the run (null: none / deleted again)
        $v = $this->jobVersion( $p, $j );
        return array( 'has_stats' => is_file( $dir . '/' . self::STATS_RESULT_FILE ), 'has_result' => $result !== null && is_file( $dir . '/' . $result ),
            'saved' => $v !== null ? $v['cid'] : null );
    }

    /**
     * the version of the project that "Result as new version" made from this run (the newest one that still exists).
     * Versions made before the column from_run existed are found by their note ("<type> run <first 8 of the run id>…").
     */
    private function jobVersion( array $p, array $j ): ?array
    {
        $v = $this->q( "SELECT cid, name FROM configs WHERE project_id = ? AND ( from_run = ? OR ( from_run IS NULL AND ( note = ? OR note LIKE ? ) ) ) ORDER BY id DESC LIMIT 1",
            array( $p['id'], $j['jid'], $j['type'] . ' run ' . substr( $j['jid'], 0, 8 ), $j['type'] . ' run ' . substr( $j['jid'], 0, 8 ) . ',%' ) )->fetch();
        return $v ? array( 'cid' => $v['cid'], 'name' => $v['name'] ) : null;
    }

    /** the name of the result configuration of a run type (playbook runs write out.xml; a run type of a plug-in names its own); null: none */
    private function jobResultName( array $j ): ?string
    {
        return in_array( $j['type'], array( 'playbook', 'ldap-users', 'object-merger', 'rule-merger' ), TRUE ) ? 'out.xml' : ( $this->pluginRuns()[$j['type']]['result'] ?? null );
    }

    /** a finished run of the project with a result configuration: its file as a run sees it ( %PROJECT%/jobs/<run>/<file> ) */
    private function jobResultArg( array $p, $jid, string $what ): array
    {
        $j = $this->jobRow( $p, $jid );
        $result = $this->jobResultName( $j );
        $file = $this->jobDir( $p, $j['jid'] ) . '/' . ( $result ?? 'out.xml' );
        if( $j['state'] !== 'done' || $result === null || !is_file( $file ) || is_link( $file ) || !self::isPanosConfig( $file ) )
            throw new ViewerException( 'diff: ' . $what . ' - a finished run of this project with a result configuration', 409 );
        return array( 'job' => $j, 'arg' => '%PROJECT%/jobs/' . $j['jid'] . '/' . $result );
    }

    public function jobGet( array $user, $pid, $jid ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'a run' );
        $j = $this->jobRow( $p, $jid );
        $done = in_array( $j['state'], array( 'done', 'failed' ), TRUE );
        return self::jobPublic( $j ) + $this->jobHas( $p, $j ) + array( 'files' => $done ? $this->jobFiles( $p, $j['jid'] ) : array(),
            // sensitive results: downloadable once by write members (not with a token)
            'sensitive' => $done && $p['role'] !== 'read' && !isset( $user['token'] ) ? $this->sensitiveFiles( $p, $j ) : array() );
    }

    /** @return array 'name', 'content' of one result file; server paths are replaced in the content */
    public function jobFile( array $user, $pid, $jid, string $name ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'a run' );
        $j = $this->jobRow( $p, $jid );
        if( !in_array( $j['state'], array( 'done', 'failed' ), TRUE ) )
            throw new ViewerException( 'the run is not finished', 409 );
        foreach( $this->jobFiles( $p, $j['jid'] ) as $f )
            if( $f['name'] === $name )
            {
                if( $f['size'] > self::JOB_FILE_MAX )
                    throw new ViewerException( 'file too large', 413 );
                // the name comes from the list of the folder, never from the request
                return array( 'name' => basename( $f['name'] ), 'content' => $this->hidePaths( (string)file_get_contents( $this->jobDir( $p, $j['jid'] ) . '/' . $f['name'] ) ) );
            }
        throw new ViewerException( 'not found', 404 );
    }

    /** the result file of a stats run with its figures (type=stats … json-to-folder debugapi) */
    const STATS_RESULT_FILE = 'json/debugAPI_string.json';

    /** a finished stats run of the project with what tells it apart from another one: version, note of the version, image */
    private function statsRun( array $p, $jid ): array
    {
        $j = $this->jobRow( $p, $jid );
        // a stats run, or a run that made the stats on the way (a playbook with a stats step: the figures of its result)
        if( $j['state'] !== 'done' )
            throw new ViewerException( 'stats compare: a finished run with a stats result', 409 );
        $c = $j['config_id'] !== null ? $this->q( 'SELECT name, note FROM configs WHERE id = ?', array( $j['config_id'] ) )->fetch() : FALSE;
        $file = $this->jobDir( $p, $j['jid'] ) . '/' . self::STATS_RESULT_FILE;
        if( !is_file( $file ) || is_link( $file ) || filesize( $file ) > self::JOB_FILE_MAX )
            throw new ViewerException( 'stats compare: the run has no stats result (' . self::STATS_RESULT_FILE . ')', 409 );
        $json = json_decode( (string)file_get_contents( $file ), TRUE );
        if( !is_array( $json ) )
            throw new ViewerException( 'stats compare: the stats result of the run can not be read', 409 );
        return array( 'run' => self::jobPublic( $j ) + array( 'version' => $c ? $c['name'] : null, 'note' => $c ? $c['note'] : null ), 'json' => $json );
    }

    /**
     * Compare of the figures of two stats runs of a project (e.g. the result of the same playbook with two pan-os-php
     * images): StatsCompare - the code of type=playbook-validation compare-stats-…, plus what exists in one of them only.
     * @return array a, b (the runs), and the result of StatsCompare::compare()
     */
    public function jobStatsCompare( array $user, $pid, $jid, $other ): array
    {
        $p = $this->projectGet( $user, $pid, 'read' );
        self::needUnlimited( $p, 'a run' );
        $a = $this->statsRun( $p, $jid );
        $b = $this->statsRun( $p, $other );
        if( $a['run']['jid'] === $b['run']['jid'] )
            throw new ViewerException( 'stats compare: choose two different runs', 400 );
        $r = StatsCompare::compare( $a['json'], $b['json'] );
        // lists of names stay objects in JSON also when they are empty
        foreach( $r['blocks'] as $header => $d )
            foreach( $d as $k => $v )
                $r['blocks'][$header][$k] = (object)$v;
        $r['blocks'] = (object)$r['blocks'];
        // visibility not 100 % in A or B, with the value of both (compare-stats-not-100 of type=playbook-validation)
        return array( 'a' => $a['run'], 'b' => $b['run'], 'not_full' => StatsCompare::notFullBoth( $a['json'], $b['json'] ),
            'not_full_excluded' => StatsCompare::NOT_FULL_EXCLUDE ) + $r;
    }
}
