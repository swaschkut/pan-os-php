<?php
/**
 * Parser root of the test plug-ins of tests/test_config_viewer.php: a stand-in for a migration plug-in. The real
 * 3rd party parsers are not part of pan-os-php (private repository pan-os-php_migration).
 */
return array(
    'ciscoswitch' => array( 'file' => 'STUB/STUB.php', 'class' => 'STUBPARSER', 'title' => 'stub: switch' ),
    'ciscoisr' => array( 'file' => 'STUB/STUB.php', 'class' => 'STUBPARSER', 'title' => 'stub: router' ),
);
