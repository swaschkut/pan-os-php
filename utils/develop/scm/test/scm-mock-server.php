<?php
/**
 * Minimal Strata Cloud Manager API mock for tests, run with the PHP built-in server:
 *   SCM_MOCK_STATE=state.json SCM_MOCK_LOG=requests.log php -S 127.0.0.1:8099 scm-mock-server.php
 *
 * state.json: {"<resource>": {"<id>": {object}, ...}, ...}; it is updated by POST / PUT / DELETE.
 * Checks like SCM: bearer token, JSON content type, exactly one of folder / snippet / device,
 * the folder / snippet must exist, id not writable, 409 for a name that exists in the same location,
 * profile-group references; setup: folder parent and attached snippets must exist, devices cannot be created.
 */
$STATE = getenv('SCM_MOCK_STATE');
$LOG = getenv('SCM_MOCK_LOG') ?: '/dev/null';
if( !$STATE )
{
    http_response_code(500);
    echo "SCM_MOCK_STATE not set";
    exit;
}

function out($code, $data) { http_response_code($code); header('Content-Type: application/json'); echo json_encode($data); exit; }
function err($code, $msg) { out($code, array('_errors' => array(array('code' => "E$code", 'message' => $msg)), '_request_id' => 'mock')); }

$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI']);
$path = $uri['path'];
parse_str($uri['query'] ?? '', $q);
$raw = file_get_contents('php://input');
file_put_contents($LOG, $method . " " . $_SERVER['REQUEST_URI'] . ($raw !== '' ? " " . $raw : "") . "\n", FILE_APPEND);

if( $path == '/oauth2/access_token' )
    out(200, array('access_token' => 'mock-token', 'expires_in' => 899, 'token_type' => 'Bearer'));

if( ($_SERVER['HTTP_AUTHORIZATION'] ?? '') !== 'Bearer mock-token' )
    err(401, 'missing or wrong token');

$st = json_decode(file_get_contents($STATE), TRUE);
if( !preg_match('#^/config/(objects|security|network|setup|identity|device)/v1/([a-z-]+)(?:/([^/]+))?$#', $path, $m) )
    err(404, 'unknown path ' . $path);
$res = $m[2];
$id = $m[3] ?? null;
$setup = $m[1] == 'setup';
$exists = function ($res, $name) use (&$st) { foreach( $st[$res] ?? array() as $o ) if( $o['name'] === $name ) return TRUE; return FALSE; };

$scopeOf = function ($o) { foreach( array('folder', 'snippet', 'device') as $s ) if( isset($o[$s]) ) return array($s, $o[$s]); return array(null, null); };

if( in_array($method, array('POST', 'PUT')) )
{
    if( stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') === FALSE )
        err(415, 'Content-Type must be application/json');
    $body = json_decode($raw, TRUE);
    if( !is_array($body) || (!isset($body['name']) && !($setup && $res == 'devices')) )
        err(400, 'body must be an object with name');
    if( isset($body['id']) )
        err(400, 'id is read-only');
    if( $setup )
    {
        if( $res == 'devices' && $method == 'POST' )
            err(405, 'devices cannot be created, onboard the firewall');
        $unchangedRoot = $method == 'PUT' && isset($st[$res][$id]) && ($st[$res][$id]['parent'] ?? '') === ($body['parent'] ?? '');
        if( $res == 'folders' && !$unchangedRoot && (!isset($body['parent']) || !$exists('folders', $body['parent'])) )
            err(400, "folder parent '" . ($body['parent'] ?? '') . "' does not exist");
        if( $res == 'devices' && isset($body['folder']) && !$exists('folders', $body['folder']) )
            err(400, "folder '" . $body['folder'] . "' does not exist");
        foreach( $body['snippets'] ?? array() as $sn )
            if( !$exists('snippets', $sn) )
                err(400, "snippet '$sn' does not exist");
    }
    else
    {
        $scopes = array_intersect(array('folder', 'snippet', 'device'), array_keys($body));
        if( count($scopes) != 1 )
            err(400, 'exactly one of folder, snippet, device is required');
        if( isset($body['folder']) && !$exists('folders', $body['folder']) )
            err(400, "folder '" . $body['folder'] . "' does not exist");
        if( isset($body['snippet']) && !$exists('snippets', $body['snippet']) )
            err(400, "snippet '" . $body['snippet'] . "' does not exist");
    }
    if( $res == 'profile-groups' )
        foreach( array('spyware' => 'anti-spyware-profiles', 'vulnerability' => 'vulnerability-protection-profiles',
                     'file_blocking' => 'file-blocking-profiles', 'url_filtering' => 'url-access-profiles',
                     'dns_security' => 'dns-security-profiles', 'virus_and_wildfire_analysis' => 'wildfire-anti-virus-profiles') as $f => $r )
            foreach( $body[$f] ?? array() as $ref )
            {
                $found = FALSE;
                foreach( $st[$r] ?? array() as $o ) if( $o['name'] === $ref ) $found = TRUE;
                if( !$found ) err(400, "profile-group references unknown $r '$ref'");
            }
}

if( $method == 'GET' && $id === null )
{
    $data = array();
    foreach( $st[$res] ?? array() as $o )
    {
        list($s, $n) = $scopeOf($o);
        if( isset($q['name']) && $o['name'] !== $q['name'] ) continue;
        if( !$setup && (isset($q[$s]) ? $q[$s] !== $n : (isset($q['folder']) || isset($q['snippet']) || isset($q['device']))) ) continue;
        $data[] = $o;
    }
    out(200, array('data' => $data, 'total' => count($data), 'limit' => 200, 'offset' => 0));
}
if( $method == 'GET' )
{
    if( !isset($st[$res][$id]) ) err(404, "$res $id not found");
    out(200, $st[$res][$id]);
}
if( $method == 'POST' )
{
    list($s, $n) = $scopeOf($body);
    foreach( $st[$res] ?? array() as $o )
    {
        list($s2, $n2) = $scopeOf($o);
        if( $o['name'] === $body['name'] && ($setup || ($s2 === $s && $n2 === $n)) ) err(409, "$res '" . $body['name'] . "' exists");
    }
    $body = array('id' => 'new-' . substr(md5($res . $body['name'] . $n), 0, 8)) + $body;
    if( $res == 'security-rules' ) $body['position'] = $q['position'] ?? 'pre';
    $st[$res][$body['id']] = $body;
    file_put_contents($STATE, json_encode($st));
    out(201, $body);
}
if( $method == 'PUT' )
{
    if( !isset($st[$res][$id]) ) err(404, "$res $id not found");
    $body = array('id' => $id) + $body;
    $st[$res][$id] = $body;
    file_put_contents($STATE, json_encode($st));
    out(200, $body);
}
if( $method == 'DELETE' )
{
    if( !isset($st[$res][$id]) ) err(404, "$res $id not found");
    unset($st[$res][$id]);
    file_put_contents($STATE, json_encode($st));
    out(200, array('id' => $id));
}
err(405, 'method not allowed');
