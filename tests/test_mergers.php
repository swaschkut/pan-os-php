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



set_include_path(dirname(__FILE__) . '/../' . PATH_SEPARATOR . get_include_path());
require_once dirname(__FILE__)."/../lib/pan_php_framework.php";

PH::print_stdout( "\n*************************************************" );
PH::print_stdout(  "**************** MERGER TESTERS *****************" );

PH::processCliArgs();

if( ini_get('safe_mode') )
{
    derr("SAFE MODE IS ACTIVE");
}


function runCommand($bin, &$stream, $force = TRUE, $command = '')
{
    $stream = '';

    $bin .= $force ? " 2>&1" : '';

    $descriptorSpec = array
    (
        0 => array('pipe', 'r'),
        1 => array('pipe', 'w'),
        2 => array('pipe', 'w'),
    );

    $pipes = array();

    $process = proc_open($bin, $descriptorSpec, $pipes);

    if( $process !== FALSE )
    {
        fwrite($pipes[0], $command);
        fclose($pipes[0]);

        $stream = stream_get_contents($pipes[1]);
        fclose($pipes[1]);

        $stream += stream_get_contents($pipes[2]);
        fclose($pipes[2]);

        return proc_close($process);
    }
    else
        return -1;

}

#$totalFilterCount = 0;
#$totalFilterWithCiCount = 0;

$test_merger = array('address', 'service', 'addressgroup', 'servicegroup', 'tag');

foreach( $test_merger as $merger )
{
    if( isset(PH::$args['in']) )
    {
        $ci['input'] = PH::$args['in'];
    }
    else
    {
        #$ci['input'] = 'input/panorama-8.0-merger.xml';
        $ci['input'] = 'input/panorama-10.0-merger.xml';
    }


    PH::print_stdout( "\n\n\n *** Processing merger: {$merger} " );

    $dupalgorithm_array = array();
    if( $merger == 'address' )
    {
        $util = '../utils/pan-os-php.php type=address-merger';
        $dupalgorithm_array[] = 'SameAddress';
        $dupalgorithm_array[] = 'Identical';
        $dupalgorithm_array[] = 'Whereused';
    }
    elseif( $merger == 'addressgroup' )
    {
        $util = '../utils/pan-os-php.php type=addressgroup-merger';
        $dupalgorithm_array[] = 'SameMembers';
        $dupalgorithm_array[] = 'SameIP4Mapping';
        $dupalgorithm_array[] = 'Identical';
        $dupalgorithm_array[] = 'Whereused';

    }
    elseif( $merger == 'service' )
    {
        $util = '../utils/pan-os-php.php type=service-merger';
        $dupalgorithm_array[] = 'SameDstSrcPorts';
        $dupalgorithm_array[] = 'SamePorts';
        $dupalgorithm_array[] = 'Identical';
        $dupalgorithm_array[] = 'Whereused';
    }
    elseif( $merger == 'servicegroup' )
    {
        $util = '../utils/pan-os-php.php type=servicegroup-merger';
        $dupalgorithm_array[] = 'SameMembers';
        $dupalgorithm_array[] = 'SamePortMapping';
        $dupalgorithm_array[] = 'Identical';
        $dupalgorithm_array[] = 'Whereused';
    }
    elseif( $merger == 'tag' )
    {
        $util = '../utils/pan-os-php.php type=tag-merger';
        $dupalgorithm_array[] = 'SameColor';
        $dupalgorithm_array[] = 'Identical';
        $dupalgorithm_array[] = 'WhereUsed';
        $dupalgorithm_array[] = 'SameName';
    }elseif( $merger == 'customurlprofile' )
    {
        $util = '../utils/pan-os-php.php type=custom-url-category-merger';
        $dupalgorithm_array[] = 'SameValue';
        $dupalgorithm_array[] = 'Identical';
        $dupalgorithm_array[] = 'SameName';
    }

    else
        derr('unsupported');

    $array = array("", "allowMergingWithUpperLevel");
    foreach( $array as $allowmergingwithupperlevel )
    {
        foreach( $dupalgorithm_array as $dupalgorithm )
        {
            $location = 'any';
            $output = '/dev/null';

            $path = dirname(__FILE__)."/";
            $cli = "php ".$path.$util." in=".$path.$ci['input']." out={$output} location={$location} {$allowmergingwithupperlevel}";

            #if( $merger != 'address' )
                $cli .= " DupAlgorithm={$dupalgorithm}";


            $cli .= ' shadow-ignoreinvalidaddressobjects';
            $cli .= ' 2>&1';

            PH::print_stdout( " * Executing CLI: {$cli}" );

            $output = array();
            $retValue = 0;

            exec($cli, $output, $retValue);

            foreach( $output as $line )
            {
                $string = '   ##  ';
                $string .= $line;
                PH::print_stdout( $string );
            }

            if( $retValue != 0 )
                derr("CLI exit with error code '{$retValue}'");

            PH::print_stdout();
        }
    }


}

PH::print_stdout( "\n*****  *****" );
#PH::print_stdout( " - Processed {$totalFilterCount} actions" );
#PH::print_stdout( " - Found {$totalFilterWithCiCount} that are CI enabled" );

PH::print_stdout();
PH::print_stdout( "\n*********** FINISHED TESTING MERGERS ************" );
PH::print_stdout( "*************************************************" );




