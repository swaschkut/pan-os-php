<?php

require_once("lib/panconfigurator.php");
PH::processCliArgs();



if( isset(PH::$args['action']) )
    $action = PH::$args['action'];
else
    {
        print "Argument action not found\n";
        exit;
    }

if( isset(PH::$args['hours']) )
    $hours = PH::$args['hours'];
else
{
    $hours = 0.25;
}

if( isset(PH::$args['debugapi']) )
    $print_api = true;
else
{
    $print_api = false;
}

$panorama_ip = 'IP-address';
$panorama_api_key = 'XXXXXXXXXXXXXXXXXXX';




########################################################################################################################

$con = new PanAPIConnector($panorama_ip, $panorama_api_key, 'panos');
$con->refreshSystemInfos();
$con->setShowApiCalls($print_api);



date_default_timezone_set("Europe/Berlin");
$time = time() - ($hours * 3600);
$time = date('Y/m/d H:i:s', $time);

$query = '(subtype eq pppoe) and (eventid eq connect) and ( receive_time geq \'' . $time . '\' )';

$apiArgs = Array();
$apiArgs['type'] = 'log';
$apiArgs['log-type'] = 'system';
$apiArgs['query'] = $query;

$output = $con->getLog($apiArgs);

if( empty($output) )
{
    print "##########################################\n";
    print "no new PPPoE session established since: ".$time."\n";
    print "##########################################\n";
}
elseif( count($output) == 1 )
{
    print "##########################################\n";
    print "PPPoE was successfully established during the last ".$hours."h:\n\n";

    foreach( $output as $log )
    {
        $opaque = explode(',', $log['opaque']);
        $ipaddress = explode(':', $opaque[3]);

        print "time: " . $log['receive_time'] . " - ipaddress: " . $ipaddress[1] . "\n\n";
    }

    print "##########################################\n\n\n";


    if( $action === 'clear_session' )
    {
        $query = '<show><session><all><filter><from>DMZ</from><to>untrust</to></filter></all></session></show>';
        $apiArgs = Array();
        $apiArgs['type'] = 'op';
        $apiArgs['cmd'] = $query;

        $output = $con->getSession($apiArgs);

        foreach( $output as $session )
        {
            $query = '<clear><session><id>'.$session['idx'].'</id></session></clear>';
            $output = $con->sendOpRequest($query);

            print $output->textContent;
        }
    }

}
else
    {
        print "##########################################\n";
        print "PPPoE was successfully established during the last ".$hours."h:\n\n";

        foreach( $output as $log )
        {
            $opaque = explode(',', $log['opaque']);
            $ipaddress = explode(':', $opaque[3]);

            print "time: " . $log['receive_time'] . " - ipaddress: " . $ipaddress[1] . "\n\n";
        }

        print "##########################################\n\n\n";
    }





