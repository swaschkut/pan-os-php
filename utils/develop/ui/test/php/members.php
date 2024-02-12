<?php
$conn = null;
$demo = true;
//include must be mentioned as below, not ../db_conn.php as session already exist
//also no session_start() as already started
include "db_conn.php";

if (!$demo && isset($_SESSION['username']) && isset($_SESSION['id'])) {
    
    $sql = "SELECT * FROM users ORDER BY id ASC";
    $res = mysqli_query($conn, $sql);
}else{
	header("Location: index.php");
} 