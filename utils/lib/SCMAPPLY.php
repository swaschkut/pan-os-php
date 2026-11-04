<?php
/**
 * ISC License
 *
 * Copyright (c) 2014-2018, Palo Alto Networks Inc.
 * Copyright (c) 2019, Palo Alto Networks Inc.
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
 * type=scm-apply
 *
 * Sends the requests of a type=scm-changes file to Strata Cloud Manager, in the order of "seq".
 *
 *  - POST    body as written
 *  - PUT     "merge": true -> GET the live object, apply the fields of body (null removes a field), PUT the result
 *  - DELETE  as written
 *  - a request without id is resolved through its "lookup" (GET ?name=...&folder=...);
 *    "skip_if_missing": true (devices, which cannot be created) is skipped when the object is not in SCM
 *  - "merge_lists": {"snippets": "keep-others"}: the listed snippets go on top in this order,
 *    snippets the live folder / device has besides them stay below
 *  - "review": true requests are skipped unless include-review is given
 *  - a request whose dependency did not succeed is skipped
 *  - by default the run stops at the first failed request (continue-on-error to go on)
 *
 * The changes land in the SCM candidate configuration; nothing is pushed.
 * Every request and its result are written to a result file (default: <changes>.result.json).
 */
class SCMAPPLY extends UTIL
{
    public $changesFile = null;
    public $resultFile = null;
    public $tsg = null;
    public $dryRun = FALSE;
    public $includeReview = FALSE;
    public $continueOnError = FALSE;
    public $fromSeq = 1;

    /** @var PanSCMAPIConnector */
    public $scm = null;
    public $apiBase = null;
    private $curl = null;

    public function utilStart()
    {
        $this->usageMsg = PH::boldText('USAGE: ') . "\n" .
            "  - php " . basename(__FILE__) . " type=scm-apply changes=changes.json tsg=TSG_ID [dry-run]\n" .
            "\n" .
            "  changes            file written by type=scm-changes\n" .
            "  tsg                TSG ID of the tenant; client_id / client_secret come from ~/.panconfkeystore\n" .
            "                     (the same entry in=scm-api://TSG_ID uses; asked for and stored when missing)\n" .
            "  dry-run            print what would be sent, no connection to SCM\n" .
            "  include-review     also send requests marked \"review\": true\n" .
            "  continue-on-error  do not stop at the first failed request (its dependents are skipped)\n" .
            "  from=SEQ           start at request SEQ (e.g. to resume a run)\n" .
            "  result=FILE        result file (default: <changes>.result.json)\n" .
            "\n" .
            "  Changes go to the candidate configuration. Push them in SCM afterwards.\n";

        PH::processCliArgs();

        if( isset(PH::$args['help']) )
        {
            PH::print_stdout($this->usageMsg);
            exit(0);
        }

        $this->main();
    }

    public function supportedArguments()
    {
        $this->supportedArguments = array();
        $this->supportedArguments['changes'] = array('niceName' => 'changes', 'shortHelp' => 'file written by type=scm-changes', 'argDesc' => '[filename]');
        $this->supportedArguments['tsg'] = array('niceName' => 'tsg', 'shortHelp' => 'TSG ID of the tenant', 'argDesc' => '[TSG_ID]');
        $this->supportedArguments['dry-run'] = array('niceName' => 'dry-run', 'shortHelp' => 'print what would be sent');
        $this->supportedArguments['include-review'] = array('niceName' => 'include-review', 'shortHelp' => 'also send requests marked review');
        $this->supportedArguments['continue-on-error'] = array('niceName' => 'continue-on-error', 'shortHelp' => 'do not stop at the first failed request');
        $this->supportedArguments['from'] = array('niceName' => 'from', 'shortHelp' => 'start at request SEQ', 'argDesc' => '[SEQ]');
        $this->supportedArguments['result'] = array('niceName' => 'result', 'shortHelp' => 'result file', 'argDesc' => '[filename]');
        $this->supportedArguments['apiurl'] = array('niceName' => 'apiurl', 'shortHelp' => 'testing only: other API base URL', 'argDesc' => '[url]');
        $this->supportedArguments['tokenurl'] = array('niceName' => 'tokenurl', 'shortHelp' => 'testing only: other token URL', 'argDesc' => '[url]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'debugapi', 'shortHelp' => 'print every request and response');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
    }

    public function main()
    {
        if( !isset(PH::$args['changes']) )
            $this->display_error_usage_exit('"changes" is required');
        $this->changesFile = PH::$args['changes'];
        $this->dryRun = isset(PH::$args['dry-run']);
        $this->includeReview = isset(PH::$args['include-review']);
        $this->continueOnError = isset(PH::$args['continue-on-error']);
        $this->debugAPI = isset(PH::$args['debugapi']);
        if( isset(PH::$args['from']) )
            $this->fromSeq = (int)PH::$args['from'];
        $this->resultFile = PH::$args['result'] ?? preg_replace('/\.json$/', '', $this->changesFile) . ".result.json";

        if( !file_exists($this->changesFile) )
            derr("file '" . $this->changesFile . "' not found", null, FALSE);
        $changes = json_decode(file_get_contents($this->changesFile), TRUE);
        if( !is_array($changes) || ($changes['format'] ?? '') !== SCMChangeGenerator::FORMAT )
            derr("'" . $this->changesFile . "' is not a type=scm-changes file", null, FALSE);
        if( (int)$changes['version'] > SCMChangeGenerator::VERSION )
            derr("'" . $this->changesFile . "' has version " . $changes['version'] . ", this pan-os-php reads up to " . SCMChangeGenerator::VERSION, null, FALSE);

        $this->apiBase = rtrim(PH::$args['apiurl'] ?? $changes['api_base'], "/");

        if( !$this->dryRun )
        {
            if( !isset(PH::$args['tsg']) )
                $this->display_error_usage_exit('"tsg" is required (or use dry-run)');
            $this->tsg = PH::$args['tsg'];

            PanAPIConnector::loadConnectorsFromUserHome();
            $this->scm = new PanSCMAPIConnector($this->tsg);
            $this->scm->findOrCreateConnectorFromHost($this->tsg);
            if( isset(PH::$args['tokenurl']) )
                $this->scm->url_token = PH::$args['tokenurl'];
            if( !isset(PH::$args['apiurl']) && $this->scm->url_api !== "https://api.strata.paloaltonetworks.com" )
                $this->apiBase = $this->scm->url_api;
            $this->scm->getAccessToken();
        }

        $results = $this->apply($changes['requests']);

        $out = array(
            'changes' => $this->changesFile,
            'tsg' => $this->tsg,
            'api_base' => $this->apiBase,
            'dry_run' => $this->dryRun,
            'started' => date('c', (int)$this->runStartTime),
            'finished' => date('c'),
            'summary' => $this->summary($results),
            'results' => $results,
        );
        file_put_contents($this->resultFile, json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");

        PH::print_stdout();
        $s = $out['summary'];
        $line = " * " . ($this->dryRun ? "dry-run: " : "") . "ok " . $s['ok'] . ", failed " . $s['failed']
            . ", skipped (review) " . $s['skipped-review'] . ", skipped (dependency) " . $s['skipped-dependency']
            . ", not run " . $s['not-run'] . ($s['skipped-missing'] > 0 ? ", not in SCM " . $s['skipped-missing'] : "")
            . ($s['skipped-from'] > 0 ? ", before from= " . $s['skipped-from'] : "");
        PH::print_stdout($line);
        PH::print_stdout(" * result file: " . $this->resultFile);
        if( !$this->dryRun && $s['ok'] > 0 )
            PH::print_stdout(" * the changes are in the SCM candidate configuration - push them in SCM");

        if( $s['failed'] > 0 )
            exit(1);
    }

    private function summary(array $results)
    {
        $s = array('ok' => 0, 'failed' => 0, 'skipped-review' => 0, 'skipped-dependency' => 0, 'skipped-missing' => 0, 'skipped-from' => 0, 'not-run' => 0);
        foreach( $results as $r )
            $s[$r['status']]++;
        return $s;
    }

    // ------------------------------------------------------------------------------------------------

    public function apply(array $requests)
    {
        usort($requests, function ($a, $b) { return $a['seq'] <=> $b['seq']; });

        $status = array();
        $results = array();
        $stopped = FALSE;

        foreach( $requests as $req )
        {
            $seq = $req['seq'];
            $label = $seq . " " . $req['method'] . " " . $req['object']['resource'] . " '" . $req['object']['name'] . "' (" . $req['object']['scope_type'] . " '" . $req['object']['scope'] . "')";
            $result = array('seq' => $seq, 'method' => $req['method'], 'object' => $req['object'], 'status' => 'not-run');

            if( $seq < $this->fromSeq )
            {
                $result['status'] = 'skipped-from';
                $result['message'] = "before from=" . $this->fromSeq . ", assumed done";
                $status[$seq] = 'ok';      // assumed done by an earlier run
                $results[] = $result;
                continue;
            }
            if( $stopped )
            {
                $results[] = $result;
                continue;
            }

            if( $req['review'] && !$this->includeReview )
            {
                $result['status'] = $status[$seq] = 'skipped-review';
                $result['message'] = implode(" | ", $req['warnings']);
                PH::print_stdout("   - " . $label . ": skipped, needs review");
                $results[] = $result;
                continue;
            }

            $blocking = array();
            foreach( $req['depends_on'] as $dep )
                if( ($status[$dep] ?? 'not-run') !== 'ok' )
                    $blocking[] = $dep;
            if( !empty($blocking) )
            {
                $result['status'] = $status[$seq] = 'skipped-dependency';
                $result['message'] = "request(s) " . implode(", ", $blocking) . " did not succeed";
                PH::print_stdout("   - " . $label . ": skipped, depends on " . implode(", ", $blocking));
                $results[] = $result;
                continue;
            }

            try
            {
                $done = $this->send($req);
                if( !empty($done['skipped_missing']) )
                {
                    unset($done['skipped_missing']);
                    $result = array_merge($result, $done);
                    $result['status'] = $status[$seq] = 'skipped-missing';
                    PH::print_stdout("   - " . $label . ": skipped, " . $done['message']);
                }
                else
                {
                    $result = array_merge($result, $done);
                    $result['status'] = $status[$seq] = 'ok';
                    PH::print_stdout("   - " . $label . ": " . ($this->dryRun ? "would send " . $done['url'] : "OK " . $done['http_code']));
                }
            }
            catch( SCMApplyException $e )
            {
                $result = array_merge($result, $e->details);
                $result['status'] = $status[$seq] = 'failed';
                $result['message'] = $e->getMessage();
                PH::print_stdout("   - " . $label . ": " . PH::boldText("FAILED") . " " . $e->getMessage());
                if( !$this->continueOnError )
                {
                    $stopped = TRUE;
                    PH::print_stdout("   * stopped; resume with from=" . $seq . " after fixing it, or use continue-on-error");
                }
            }
            $results[] = $result;
        }
        return $results;
    }

    private function send(array $req)
    {
        $path = $req['path'];
        $id = $req['id'];

        if( $req['method'] != 'POST' && $id === null )
        {
            if( $this->dryRun )
                $id = "{id of " . http_build_query($req['lookup']) . "}";
            else
            {
                $id = $this->lookupId($req);
                if( $id === null )
                    return array('skipped_missing' => TRUE, 'url' => $path, 'message' => "not in SCM: " . http_build_query($req['lookup']));
            }
            $path = preg_replace('#/\{id\}$#', '/' . $id, $path);
        }

        $query = (array)$req['query'];
        $url = $this->apiBase . $path . (empty($query) ? "" : "?" . http_build_query($query));

        if( $req['method'] == 'DELETE' )
            return $this->dryRun ? array('url' => $url) : $this->call('DELETE', $url);

        $body = (array)$req['body'];

        if( $req['method'] == 'PUT' && $req['merge'] )
        {
            if( $this->dryRun )
                return array('url' => $url, 'body' => $body, 'note' => 'merged with the live object (GET ' . $url . ')');

            $live = $this->call('GET', $url);
            $merged = $live['response'];
            if( !is_array($merged) )
                throw new SCMApplyException("GET " . $url . " returned no object", $live);
            $lists = $req['merge_lists'] ?? array();
            foreach( $body as $k => $v )
            {
                if( $v === null )
                    unset($merged[$k]);
                elseif( ($lists[$k] ?? null) === 'keep-others' && is_array($v) )
                {
                    // the listed entries on top in this order, entries the live object has besides them below
                    $others = array();
                    foreach( (array)($merged[$k] ?? array()) as $e )
                        if( !in_array($e, $v, TRUE) )
                            $others[] = $e;
                    $merged[$k] = array_merge($v, $others);
                }
                else
                    $merged[$k] = $v;
            }
            unset($merged['id']);
            $body = $merged;
        }

        if( $this->dryRun )
            return array('url' => $url, 'body' => $body);

        $res = $this->call($req['method'], $url, $body);
        if( $req['method'] == 'POST' && isset($res['response']['id']) )
            $res['id'] = $res['response']['id'];
        return $res;
    }

    private function lookupId(array $req)
    {
        $base = preg_replace('#/\{id\}$#', '', $req['path']);
        $query = $req['lookup'];
        unset($query['position']);
        if( isset($req['lookup']['position']) )
            $query['position'] = $req['lookup']['position'];
        $url = $this->apiBase . $base . "?" . http_build_query($query);
        $res = $this->call('GET', $url);
        $data = $res['response']['data'] ?? array();
        foreach( $data as $obj )
            if( ($obj['name'] ?? null) === $req['lookup']['name'] && isset($obj['id']) )
                return $obj['id'];
        if( !empty($req['skip_if_missing']) )
            return null;
        throw new SCMApplyException("object not found: GET " . $url, $res);
    }

    private function call($method, $url, $body = null)
    {
        $this->scm->getAccessToken();

        if( $this->curl === null )
            $this->curl = curl_init();
        else
            curl_reset($this->curl);

        $header = array("Authorization: Bearer " . $this->scm->access_token, "Accept: application/json");
        $payload = null;
        if( $body !== null )
        {
            $payload = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            $header[] = "Content-Type: application/json";
        }

        curl_setopt($this->curl, CURLOPT_URL, str_replace(' ', '%20', $url));
        curl_setopt($this->curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($this->curl, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($this->curl, CURLOPT_CUSTOMREQUEST, $method);
        curl_setopt($this->curl, CURLOPT_TIMEOUT, 120);
        if( $payload !== null )
            curl_setopt($this->curl, CURLOPT_POSTFIELDS, $payload);

        if( $this->debugAPI )
        {
            PH::print_stdout("     " . $method . " " . $url);
            if( $payload !== null )
                PH::print_stdout("     BODY: " . $payload);
        }

        $raw = curl_exec($this->curl);
        $code = (int)curl_getinfo($this->curl, CURLINFO_RESPONSE_CODE);
        $details = array('url' => $url, 'http_code' => $code);
        if( $payload !== null )
            $details['body'] = $body;

        if( $raw === FALSE )
            throw new SCMApplyException("connection error: " . curl_error($this->curl), $details);

        $json = json_decode($raw, TRUE);
        $details['response'] = $json ?? $raw;

        if( $this->debugAPI )
            PH::print_stdout("     HTTP " . $code . ": " . (is_string($raw) ? substr($raw, 0, 2000) : ''));

        if( $code < 200 || $code >= 300 )
        {
            $msg = "HTTP " . $code;
            if( isset($json['_errors'][0]['message']) )
                $msg .= ": " . $json['_errors'][0]['message'];
            if( isset($json['_errors'][0]['details']) )
                $msg .= " " . json_encode($json['_errors'][0]['details'], JSON_UNESCAPED_SLASHES);
            throw new SCMApplyException($msg, $details);
        }
        return $details;
    }
}

class SCMApplyException extends Exception
{
    public $details = array();

    public function __construct($message, array $details = array())
    {
        parent::__construct($message);
        $this->details = $details;
    }
}
