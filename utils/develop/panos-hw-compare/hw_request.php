<?php

set_include_path(get_include_path() . PATH_SEPARATOR . dirname(__FILE__) . '/../');

require_once dirname(__FILE__)."/../../../lib/pan_php_framework.php";


$device = "pa-3410";

$deviceArray = array();


$deviceArray["pa-410"] = true;
$deviceArray["pa-415"] = true;
$deviceArray["pa-415-5g"] = true;

$deviceArray["pa-440"] = true;
$deviceArray["pa-445"] = true;
$deviceArray["pa-450"] = true;
$deviceArray["pa-455"] = true;

$deviceArray["pa-460"] = true;

$deviceArray["pa-410r"] = true;
$deviceArray["pa-410r-5g"] = true;
$deviceArray["pa-450r"] = true;
$deviceArray["pa-450r-5g"] = true;


$deviceArray["pa-1410"] = true;
$deviceArray["pa-1420"] = true;

$deviceArray["pa-3410"] = true;
$deviceArray["pa-3420"] = true;
$deviceArray["pa-3430"] = true;
$deviceArray["pa-3440"] = true;

$deviceArray["pa-5410"] = true;
$deviceArray["pa-5420"] = true;
$deviceArray["pa-5430"] = true;
$deviceArray["pa-5440"] = true;
$deviceArray["pa-5445"] = true;

$deviceArray["pa-5450"] = true;
$deviceArray["pa-7500"] = true;

///////////////////////////////////////
//VM
$deviceArray["pa-7500"] = true;
$deviceArray["vm-series%20(2%20vcpu,%204.5%20gb)"] = true;
$deviceArray["vm-series%20(2%20vcpu,%205.5%20gb)"] = true;
$deviceArray["vm-series%20(2%20vcpu,%206.5%20gb)"] = true;
$deviceArray["vm-series%20(4%20vcpu,%209%20gb)"] = true;
$deviceArray["vm-series%20(8%20vcpu,%2016%20gb)"] = true;
$deviceArray["vm-series%20(16%20vcpu,%2056%20gb)"] = true;
$deviceArray["vm-series%20(22%20vcpu,%2056%20gb)"] = true;
$deviceArray["vm-series%20(32vcpu,%2056%20gb)"] = true;
$deviceArray["cn-series%20(cn-ngfw:%201%20vcpu,%202g;%20cn-mgmt:%202%20vcpu,%202g)"] = true;
///////////////////////////////////////
//old HW - EoL
$deviceArray["pa-220"] = true;
$deviceArray["pa-220r"] = true;

$deviceArray["pa-820"] = true;
$deviceArray["pa-850"] = true;

$deviceArray["pa-3220"] = true;
$deviceArray["pa-3250"] = true;
$deviceArray["pa-3260"] = true;

$deviceArray["pa-5210"] = true;
$deviceArray["pa-5220"] = true;
$deviceArray["pa-5250"] = true;
$deviceArray["pa-5260"] = true;
$deviceArray["pa-5280"] = true;

///////////////////////////////////////

foreach($deviceArray as $device => $deviceEnabled)
{

    $file_name = $device;

    $url = "https://www.paloaltonetworks.com/products/product-comparison?chosen=" . $device;

    PH::print_stdout($url);

    $directory = "../panos-hw-compare/";

    if (!file_exists($directory . 'html')) {
        mkdir($directory . 'html', 0777, true);
    }

    if (file_put_contents($directory . "html/" . $file_name, file_get_contents($url)))
    {
        print "File downloaded successfully\n";
    } else {
        print "File downloading failed.\n";
    }
}
