<?php
/**
 * ISC License
 *
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

class CONFIG_COMMIT__ extends UTIL
{
    public $utilType = null;

    public function utilStart()
    {
        $this->supportedArguments = Array();
        $this->supportedArguments['in'] = Array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['debugapi'] = Array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
#$supportedArguments['help'] = Array('niceName' => 'help', 'shortHelp' => 'this message');

        $this->usageMsg = PH::boldText("USAGE: ")."php ".basename(__FILE__)." in=api://192.168.1.1\n" .
            "php ".basename(__FILE__)." help          : more help messages\n";

        $this->prepareSupportedArgumentsArray();

        $this->utilInit();

        $this->main();


        
    }

    public function main( )
    {

        $pan = $this->pan;
        $inputConnector = $pan->connector;



        if( $this->configInput['type'] !== 'api' )
            derr('only API connection supported');

########################################################################################################################
        $inputConnector->refreshSystemInfos();

        $inputConnector->commitAll();
        //$inputConnector->commitPartial( "user", "admin");

    }
}