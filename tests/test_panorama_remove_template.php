<?php
/**
 * Tests of PanoramaConf::removeTemplate() / removeTemplateStack() (guard: template still used by a template stack,
 * readonly entries, references) and of the actions template-delete / templatestack-delete.
 *
 *   cd tests && php test_panorama_remove_template.php
 *
 * Input: input/panorama-move/panorama-move-A.xml
 *   Paris_Datacenter_Stack   templates: Datacenter Master Template, Paris Datacenter      (fw 007100000290)
 *   DE_Berlin_Office_Stack   templates: DE-Berling_Office, Internet Perimeter Master, Datacenter Master Template
 *   testDG                   reference-templates: Paris_Datacenter_Stack
 * Exit code 0 = all passed.
 */

$here = dirname(__FILE__);
require_once $here . '/../lib/pan_php_framework.php';
PH::processCliArgs();

$in = $here . '/input/panorama-move/panorama-move-A.xml';
$work = sys_get_temp_dir() . '/pan-os-php-test-remove-template-' . getmypid();
@mkdir( $work, 0700, TRUE );

$failed = array();
$checks = 0;

function check( $cond, $msg )
{
    global $failed, $checks;
    $checks++;
    if( !$cond )
        $failed[] = $msg;
}

function load( $file )
{
    $p = new PanoramaConf();
    $p->load_from_file( $file );
    return $p;
}

function xpCount( PanoramaConf $p, $q )
{
    $x = new DOMXPath( $p->xmldoc );
    return $x->query( $q )->length;
}

/** runs $fn and returns array( result, warnings ) - mwarning() collects into PH::$JSON_OUT with shadow-json */
function captured( $fn )
{
    $json = PH::$shadow_json;
    PH::$shadow_json = TRUE;
    unset( PH::$JSON_OUT['warning'] );
    ob_start();
    $r = $fn();
    ob_end_clean();
    $w = isset(PH::$JSON_OUT['warning']) ? implode( "\n", PH::$JSON_OUT['warning'] ) : '';
    unset( PH::$JSON_OUT['warning'] );
    PH::$shadow_json = $json;
    return array( $r, $w );
}

$T = "/config/devices/entry[@name='localhost.localdomain']/template/entry";
$S = "/config/devices/entry[@name='localhost.localdomain']/template-stack/entry";
$RO = "/config/readonly/devices/entry[@name='localhost.localdomain']";

// 1. template used by two stacks: refused, nothing changed
$p = load( $in );
$t = $p->findTemplate( 'Datacenter Master Template' );
list( $r, $out ) = captured( function() use ( $p, $t ) { return $p->removeTemplate( $t ); } );
check( $r === FALSE, 'template in use: removeTemplate() returns FALSE' );
check( strpos($out, 'Paris_Datacenter_Stack') !== FALSE && strpos($out, 'DE_Berlin_Office_Stack') !== FALSE, 'template in use: warning names both stacks' );
check( xpCount($p, $T . "[@name='Datacenter Master Template']") == 1, 'template in use: XML entry kept' );
check( $p->findTemplate( 'Datacenter Master Template' ) !== null, 'template in use: object kept' );
check( count($p->templateStacksUsingTemplate( 'Datacenter Master Template' )) == 2, 'templateStacksUsingTemplate() by name' );

// 2. remove a stack: XML, readonly, object, template references; warning for reference-templates of testDG
$stack = $p->findTemplateStack( 'Paris_Datacenter_Stack' );
$paris = $p->findTemplate( 'Paris Datacenter' );
check( isset( $paris->getReferences()[spl_object_id($stack)] ), 'before: template references the stack' );
list( $r, $out ) = captured( function() use ( $p, $stack ) { return $p->removeTemplateStack( $stack ); } );
check( $r === TRUE, 'removeTemplateStack() returns TRUE' );
check( xpCount($p, $S . "[@name='Paris_Datacenter_Stack']") == 0, 'stack XML entry removed' );
check( xpCount($p, $RO . "/template-stack/entry[@name='Paris_Datacenter_Stack']") == 0, 'stack readonly entry removed' );
check( $p->findTemplateStack( 'Paris_Datacenter_Stack' ) === null, 'stack object removed' );
check( !isset( $paris->getReferences()[spl_object_id($stack)] ), 'template no longer references the removed stack' );
check( strpos($out, "DeviceGroup 'testDG' references the removed TemplateStack 'Paris_Datacenter_Stack'") !== FALSE, 'warning: reference-templates of testDG' );
check( strpos($out, 'tried to unreference') === FALSE, 'no unreference warnings' );

// 3. template of the removed stack only: now removable
list( $r, $out ) = captured( function() use ( $p, $paris ) { return $p->removeTemplate( $paris ); } );
check( $r === TRUE, 'template without stack: removeTemplate() returns TRUE' );
check( xpCount($p, $T . "[@name='Paris Datacenter']") == 0, 'template XML entry removed' );
check( xpCount($p, $RO . "/template/entry[@name='Paris Datacenter']") == 0, 'template readonly entry removed' );
check( $p->findTemplate( 'Paris Datacenter' ) === null, 'template object removed' );
check( count( $paris->getReferences() ) == 0, 'removed template has no references left' );
check( strpos($out, 'tried to unreference') === FALSE, 'no unreference warnings (template)' );

// 4. shared template: still in DE_Berlin_Office_Stack -> refused, after removing that stack -> removed
$dmt = $p->findTemplate( 'Datacenter Master Template' );
list( $r ) = captured( function() use ( $p, $dmt ) { return $p->removeTemplate( $dmt ); } );
check( $r === FALSE, 'template still in the other stack: refused' );
captured( function() use ( $p ) { return $p->removeTemplateStack( $p->findTemplateStack( 'DE_Berlin_Office_Stack' ) ); } );
list( $r ) = captured( function() use ( $p, $dmt ) { return $p->removeTemplate( $dmt ); } );
check( $r === TRUE, 'template after both stacks are removed: removed' );

// 5. saved file loads again
$out1 = $work . '/removed.xml';
$p->save_to_file( $out1 );
$p2 = load( $out1 );
check( $p2->findTemplate( 'Datacenter Master Template' ) === null && $p2->findTemplateStack( 'DE_Berlin_Office_Stack' ) === null, 'saved file: removed items are gone' );
check( $p2->findTemplate( 'Internet Perimeter Master' ) !== null, 'saved file: other templates kept' );

// 6. actions: template-delete on a template used by a stack is skipped; an unused template is deleted
$cli = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($here . '/../utils/pan-os-php.php') . ' type=device';
$out2 = $work . '/action.xml';
exec( $cli . ' devicetype=template in=' . escapeshellarg($in) . ' out=' . escapeshellarg($out2)
    . ' ' . escapeshellarg("filter=(name eq Datacenter Master Template)") . ' actions=template-delete 2>&1', $o, $rc );
check( strpos( implode("\n", $o), "passing through Action='template-delete'" ) !== FALSE, 'action template-delete: filter matched' );
$p3 = load( $out2 );
check( $p3->findTemplate( 'Datacenter Master Template' ) !== null, 'action template-delete: template in use kept' );

$out3 = $work . '/created.xml'; $out4 = $work . '/deleted.xml';
exec( $cli . ' devicetype=template in=' . escapeshellarg($in) . ' out=' . escapeshellarg($out3) . ' actions=template-create:unused-tpl 2>&1', $o, $rc );
$o = array();
exec( $cli . ' devicetype=template in=' . escapeshellarg($out3) . ' out=' . escapeshellarg($out4)
    . ' ' . escapeshellarg("filter=(name eq unused-tpl)") . ' actions=template-delete 2>&1', $o, $rc );
$p4 = load( $out3 );
check( $p4->findTemplate( 'unused-tpl' ) !== null, 'action template-create: template created' );
$p5 = load( $out4 );
check( $p5->findTemplate( 'unused-tpl' ) === null, 'action template-delete: unused template removed' );
check( xpCount($p5, $RO . "/template/entry[@name='unused-tpl']") == 0, 'action template-delete: readonly entry removed' );

exec( 'rm -rf ' . escapeshellarg($work) );
print "\n" . $checks . " checks, " . count($failed) . " failed\n";
if( count($failed) )
{
    foreach( $failed as $f ) print " - " . $f . "\n";
    exit( 1 );
}
exit( 0 );
