<?php


class PREDEFINED extends UTIL
{
    public $utilType = null;


    public function utilStart()
    {
        $this->usageMsg = PH::boldText("USAGE: ") . "php " . basename(__FILE__) . " in=api://[MGMT-IP-Address] ";


        $this->prepareSupportedArgumentsArray();


        PH::processCliArgs();

        $this->help(PH::$args);

        $this->arg_validation();
        $this->init_arguments();

        $this->main();


        $this->endOfScript();
    }

    public function main()
    {
        #$request = 'type=config&action=get&xpath=%2Fconfig%2Fpredefined';
        $request = 'type=op&cmd=<show><predefined><xpath>%2Fpredefined<%2Fxpath><%2Fpredefined><%2Fshow>';

        try
        {
            $candidateDoc = $this->configInput['connector']->sendSimpleRequest($request);
        } catch(Exception $e)
        {
            PH::disableExceptionSupport();
            PH::print_stdout( " ***** an error occured : " . $e->getMessage() );
        }


        //make XMLroot for <predefined>
        $predefinedRoot = DH::findFirstElement('response', $candidateDoc);
        if( $predefinedRoot === FALSE )
            derr("<response> was not found", $candidateDoc);

        $predefinedRoot = DH::findFirstElement('result', $predefinedRoot);
        if( $predefinedRoot === FALSE )
            derr("<result> was not found", $predefinedRoot);

        $predefinedRoot = DH::findFirstElement('predefined', $predefinedRoot);
        if( $predefinedRoot === FALSE )
            derr("<predefined> was not found", $predefinedRoot);


        $xmlDoc = new DomDocument;
        $xmlDoc->appendChild($xmlDoc->importNode($predefinedRoot, TRUE));


################################################################################################


        $cursor = DH::findXPathSingleEntryOrDie('/predefined/application-version', $xmlDoc);
        $exernal_version = $cursor->nodeValue;

        $panc_version = $this->pan->appStore->predefinedStore_appid_version;


        $external_appid = explode("-", $exernal_version);
        $pan_c_appid = explode("-", $panc_version);


        if( intval($pan_c_appid[0]) > intval($external_appid[0]) )
        {
            PH::print_stdout( "\n\n - PAN-OS-PHP has already a newer APP-id version '" . $panc_version . "' installed. Device App-ID version: " . $exernal_version );
        }
        elseif( intval($pan_c_appid[0]) == intval($external_appid[0]) )
        {
            PH::print_stdout( " - same app-id version '" . $panc_version . "' available => do nothing");
        }
        else
        {
            PH::print_stdout( " - PAN-OS-PHP has an old app-id version '" . $panc_version . "' available. Device App-ID version: " . $exernal_version );

            $predefined_path = __DIR__ . '/../lib/object-classes/predefined.xml';

            PH::print_stdout( " *** predefined.xml is saved to '" . $predefined_path . "''" );
            file_put_contents( $predefined_path, $xmlDoc->saveXML());
        }
    }

    public function supportedArguments()
    {
        $this->supportedArguments['in'] = array('niceName' => 'in', 'shortHelp' => 'input file or api. ie: in=config.xml  or in=api://192.168.1.1 or in=api://0018CAEC3@panorama.company.com', 'argDesc' => '[filename]|[api://IP]|[api://serial@IP]');
        $this->supportedArguments['location'] = array('niceName' => 'location', 'shortHelp' => 'specify if you want to limit your query to a VSYS. By default location=vsys1 for PANOS. ie: location=any or location=vsys2,vsys1', 'argDesc' => '=sub1[,sub2]');
        $this->supportedArguments['debugapi'] = array('niceName' => 'DebugAPI', 'shortHelp' => 'prints API calls when they happen');
        $this->supportedArguments['help'] = array('niceName' => 'help', 'shortHelp' => 'this message');
    }

}