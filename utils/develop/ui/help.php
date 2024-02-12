<?php
session_start();
$demo = true;
include "test/db_conn.php";
if( !$demo && isset($_SESSION['folder']) && isset($_SESSION['id']) )
{
    $panconfkeystoreFILE = $_SESSION['folder']."/.panconfkeystore";
    $projectFOLDER = $_SESSION['folder'];
}
else
{
    $tmpFOLDER = '/../../api/v1/project';
    $panconfkeystoreFILE = dirname(__FILE__) . $tmpFOLDER.'/.panconfkeystore';
    $projectFOLDER = dirname(__FILE__) . $tmpFOLDER;
}

?>

    <!--
/**
* ISC License
*
* Copyright (c) 2019, Palo Alto Networks Inc.
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
-->

<!DOCTYPE html>
<html>

<head>
    <title>PAN-OS-PHP UI</title>


    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta1/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-giJF6kkoqNQ00vy+HMDP7azOuL0xtbfIcaT9wjKHr8RbDVddVHyTfAAsrekwKmP1" crossorigin="anonymous">

    <script type="text/javascript"
            src="../../common/html/jquery.min.js"
    ></script>

    <script type="text/javascript"
            src="../../common/html/bootstrap.min.js"
    ></script>



    <script type="text/javascript"
            src="json_array.js"
    ></script>


    <script type="text/javascript"
            src="ui_function.js"
    ></script>

    <script type="text/javascript"
            src="js.js"
    ></script>

</head>
<style>
    iframe{
        display: block;  /* iframes are inline by default */
        height: 100vh;  /* Set height to 100% of the viewport height */
        width: 100vw;  /* Set width to 100% of the viewport width */
        border: none; /* Remove default border */
        background: lightyellow; /* Just for styling */
    }
</style>
<body>


<div >

    <div class="border shadow p-3 rounded">
        <table class="table table-bordered" style="width:100%">
            <tr>
            <tr>
                <td><a href="index.php">MAIN page</a></td>
                <td><a href="single.php">single command</a></td>
                <td><a href="playbook.php">JSON PLAYBOOK</a></td>
                <td><a href="preparation.php">upload file / store APIkey</a></td>
                <td><a href="help.php">action / filter help</a></td>
                <?php
                if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
                {
                    echo '<td>logged in as: <a href="test/home.php">'.$_SESSION['name'].'</a>  |  <a href="test/logout.php">LOGOUT</a></td>';
                }
                ?>
            </tr>
        </table>
    </div>

    <iframe src="../../doc/help.html" ></iframe>

</div>

</body>

</html>
