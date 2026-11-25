<?php
/**
 * Stand-in of the migration base for the tests (see ../vendors.php): what "type=vendor-migration" loads from a
 * migration plug-in (PH::migrationLoad). It reads vendor= file= out=, takes the vendor parser of the parser roots
 * (PH::migrationVendors) and writes the base configuration with the rules of the file.
 */
class CONVERTER extends UTIL
{
    public function utilStart()
    {
        PH::processCliArgs();
        foreach( array( 'vendor', 'file', 'out' ) as $arg )
            if( !isset( PH::$args[$arg] ) )
                derr( '"' . $arg . '" is missing from arguments', null, FALSE );
        $vendors = PH::migrationVendors();
        $vendor = strtolower( PH::$args['vendor'] );
        if( !isset( $vendors[$vendor] ) )
            derr( "VENDOR: " . $vendor . " is not supported", null, FALSE );
        PH::print_stdout( " - vendor parser: " . $vendors[$vendor]['file'] . " [" . $vendors[$vendor]['root'] . "]" );
        require_once $vendors[$vendor]['root'] . '/' . $vendors[$vendor]['file'];
        $parser = new $vendors[$vendor]['class']();

        $pan = new PANConf();
        $pan->load_from_file( PH::rootDir() . '/lib/resources/baseconfig/panos_baseconfig.xml' );
        $vsys = $pan->findVirtualSystem( 'vsys1' );
        foreach( $parser->rules( (string)file_get_contents( PH::$args['file'] ) ) as $i => $action )
        {
            $rule = $vsys->securityRules->newSecurityRule( 'stub-' . ( $i + 1 ) );
            $rule->setAction( $action );
        }
        $pan->save_to_file( PH::$args['out'] );
    }
}
