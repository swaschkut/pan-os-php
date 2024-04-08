<?php

/*
MYSQL_ROOT_PASSWORD: MYSQL_ROOT_PASSWORD
MYSQL_DATABASE: MYSQL_DATABASE
MYSQL_USER: MYSQL_USER
MYSQL_PASSWORD: MYSQL_PASSWORD
*/

$demo = true;

$db_host = "localhost";
$uname = "root";
#$password = "MYSQL_ROOT_PASSWORD";
#$db_name = "MYSQL_DATABASE";
#$db_root_pwd = getenv('MYSQL_ROOT_PASSWORD', true) ?: getenv('MYSQL_ROOT_PASSWORD');

// The MySQL service named in the docker-compose.yml.
$db_host = getenv('MYSQL_HOST', true) ?: getenv('MYSQL_HOST');
$db_name = getenv('MYSQL_DATABASE', true) ?: getenv('MYSQL_DATABASE');
// Database use name
$db_user = getenv('MYSQL_USER', true) ?: getenv('MYSQL_USER');
//database user password
$db_pwd  = getenv('MYSQL_PASSWORD', true) ?: getenv('MYSQL_PASSWORD');

// The MySQL service named in the docker-compose.yml.
#$db_host = 'db';
#$host = "127.0.0.1";
// Database use name
#$db_user = 'MYSQL_USER';

//database user password
#$db_pwd = 'MYSQL_PASSWORD';


// check the MySQL connection status
try
{
    if( $db_host !== "" && $db_user !== "" && $db_pwd !== "" && $db_name !== "" )
    {
        $conn = new mysqli($db_host, $db_user, $db_pwd, $db_name);
        if ($conn->connect_error) {
            #die("Connection failed: " . $conn->connect_error);
        } else {
            $demo = false;
            #echo "Connected to MySQL server successfully!";
        }
    }
}
catch(Exception $e)
{
    #echo "Connected to MySQL server not working!";
}




