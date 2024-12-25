<?php
session_start();
include "test/db_conn.php";
if( isset($_SESSION['folder']) && isset($_SESSION['id']) )
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
-->

<!DOCTYPE html>
<html>

<head>
    <title>PAN-OS-PHP UI</title>

    <link rel="stylesheet"
          href="../../common/html/bootstrap.min.css"
          crossorigin="anonymous"
    >
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

<body>


<div style="border:0px solid #000000; padding: 10px; width:100%">

    <div class="menu" style="border:1px solid black; padding: 10px;">
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

    <div class="load-json" style="border:1px solid #000000; padding: 10px; width:100%">
        <table class="table table-bordered" style="width:100%">
            <tr>
                <td style="width:50%" >
                    load Playbook from JSON-file:

                    <input type="button" value="Clear TextArea" onclick="eraseTextBP();">
                    <form method="post">
                        <textarea disabled id="js-textareaBP" style="width:100%" ></textarea>
                        <input type="file" id="js-fileBP" accept=".txt,.json" onclick="this.value=null">
                    </form>
                </td>
                <td>
                    store Playbook to JSON-file:
                    <input type="text" id="json-outputBP" value="bp_config.json" />
                    <button class="btn btn-md btn-primary" id="storeBtnBP" type="button">download PLAYBOOK JSON file</button>
                    <div>
                        <textarea type="text" disabled id="json-display-outBP" name="json-display-outBP" style="width:100%" ></textarea>
                    </div>
                </td>
            </tr>
        </table>
    </div>

    <form id="user_form" target="_blank" name="user_form" method="post" enctype="multipart/form-data">

        <div class="table-responsive" style="border:1px solid black; padding: 10px; width:100%">
            <table id="myTable" class="table table-bordered" style="width:100%">
                <thead>
                <tr>
                    <th class="text-center">Remove Row</th>
                    <th class="text-center" style="width:80%">SCRIPT</th>
                </tr>
                </thead>
                <form id="json-storeBP">
                    <tbody id="tbodyBP">

                    </tbody>
                </form>
            </table>
            <button class="btn btn-md btn-primary"
                    id="addBtnBP" type="button">
                new RowBP
            </button>
        </div>
    </form>


</div>

</body>

</html>