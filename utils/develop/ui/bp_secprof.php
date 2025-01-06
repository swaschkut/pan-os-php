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

    <style>
        table {
            width: 100%;
            border-collapse: collapse;
        }
        table, th, td {
            border: 1px solid black;
        }
        th, td {
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
    </style>

</head>

<body>

<div style="border:0px solid #000000; padding: 10px; width:100%">

    <div class="menu" style="border:1px solid black; padding: 10px;">
        <table class="table table-bordered" style="width:100%">
            <tr>
            <tr>
                <td><a href="index.php">MAIN page</a></td>
                <td><a href="bp_config.php">BP config page</a></td>
                <td><a href="bp_secprof.php">BP secprof page</a></td>
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
                    load BP SecProf from JSON-file:

                    <input type="button" value="Clear TextArea" onclick="eraseTextBPsecprof();">
                    <input type="button" value="update JSON Table" onclick="updateTable();">
                    <input type="button" value="clear JSON Table" onclick="generateTable();">
                    <form method="post">
                        <textarea disabled id="js-textareaBPsecprof" style="width:100%" ></textarea>
                        <input type="file" id="js-fileBPsecprof" accept=".txt,.json" onclick="this.value=null">
                    </form>
                </td>
                <td>
                    store BP SecProf to JSON-file:
                    <input type="text" id="json-outputBP" value="bp_secprof.json" />
                    <button class="btn btn-md btn-primary" id="storeBtnBPsecprof" type="button">download BP SecProf JSON file</button>
                    <div>
                        <textarea type="text" disabled id="json-display-outBPsecprof" name="json-display-outBPsecprof" style="width:100%" ></textarea>
                    </div>
                </td>
            </tr>
        </table>
    </div>

    <div>

    <h2>JSON Data Display in Table</h2>
<table id="jsonTable">
    <thead>
    <tr>
        <th>Category</th>
        <th>Type</th>
        <th>Action</th>
    </tr>
    </thead>
    <tbody>
    <!-- Table rows will be inserted here by JavaScript -->
    </tbody>
</table>

    </div>
</div>


<script>
    // JSON data (as per your example)
    const jsonData = {
        "virus": {
            "rule": {
                "bp": {
                    "action": {
                        "type": [
                            "ftp",
                            "http",
                            "http2",
                            "smb"
                        ],
                        "action": [
                            "reset-both",
                            "default"
                        ],
                        "action-not-matching-type": [
                            "reset-both"
                        ]
                    },
                    "wildfire-action": {
                        "type": [
                            "ftp",
                            "http",
                            "http2",
                            "smb"
                        ],
                        "action": [
                            "reset-both",
                            "default"
                        ],
                        "action-not-matching-type": [
                            "reset-both"
                        ]
                    },
                    "mlav-action": {
                        "type": [
                            "ftp",
                            "http",
                            "http2",
                            "smb"
                        ],
                        "action": [
                            "reset-both",
                            "default"
                        ],
                        "action-not-matching-type": [
                            "reset-both"
                        ]
                    }
                },
                "visibility": {
                    "action": [
                        "!allow"
                    ],
                    "wildfire-action": [
                        "!allow"
                    ],
                    "mlav-action": [
                        "!allow"
                    ]
                }
            },
            "cloud-inline": {
                "bp": {
                    "inline-policy-action": [
                        "enable"
                    ]
                },
                "visibility": {
                    "inline-policy-action": [
                        "!disable"
                    ]
                }
            }
        },
        "spyware": {
            "rule": {
                "bp": {
                    "severity": [
                        "any",
                        "critical",
                        "high",
                        "medium"
                    ],
                    "action": [
                        "reset-both"
                    ],
                    "packet-capture": [
                        "single-packet",
                        "extended-capture"
                    ]
                },
                "visibility": {
                    "severity": [
                        "any",
                        "critical",
                        "high",
                        "medium",
                        "low",
                        "informational"
                    ],
                    "action": [
                        "!allow"
                    ]
                }
            },
            "dns": {
                "bp": {
                    "action": [
                        {
                            "type": [
                                "pan-dns-sec-malware",
                                "pan-dns-sec-phishing"
                            ],
                            "action": [
                                "sinkhole"
                            ],
                            "packet-capture": [
                                "single-packet"
                            ]
                        },
                        {
                            "type": [
                                "pan-dns-sec-cc"
                            ],
                            "action": [
                                "sinkhole"
                            ],
                            "packet-capture": [
                                "extended-capture"
                            ]
                        }
                    ]
                }
            },
            "lists": {
                "bp": {
                    "action": [
                        {
                            "type": [
                                "default-paloalto-dns"
                            ],
                            "action": [
                                "sinkhole"
                            ]
                        }
                    ]
                },
                "visibility": {
                    "action": [
                        {
                            "type": [
                                "default-paloalto-dns"
                            ],
                            "action": [
                                "!allow"
                            ]
                        }
                    ]
                }
            },
            "cloud-inline": {
                "bp": {
                    "inline-policy-action": [
                        "reset-both"
                    ]
                },
                "visibility": {
                    "inline-policy-action": [
                        "!allow"
                    ]
                }
            }
        },
        "vulnerability": {
            "rule": {
                "bp": {
                    "severity": [
                        "any",
                        "critical",
                        "high",
                        "medium"
                    ],
                    "action": [
                        "reset-both"
                    ],
                    "packet-capture": [
                        "single-packet",
                        "extended-capture"
                    ],
                    "category-exclude": [
                        "brute-force",
                        "app-id-change"
                    ]
                },
                "visibility": {
                    "severity": [
                        "any",
                        "critical",
                        "high",
                        "medium",
                        "low",
                        "informational"
                    ],
                    "action": [
                        "!allow"
                    ]
                }
            },
            "cloud-inline": {
                "bp": {
                    "inline-policy-action": [
                        "reset-both"
                    ]
                },
                "visibility": {
                    "inline-policy-action": [
                        "!allow"
                    ]
                }
            }
        }
    };

    function splitArray( actionCell, testArray )
    {
        const ulCell = document.createElement('ul');
        for (const Key in testArray)
        {
            if (testArray.hasOwnProperty(Key))
            {
                actionsBP = JSON.stringify(testArray[Key]);
                const liCell = document.createElement('li');

                if(  actionsBP.includes( "{" ) )
                    liCell.textContent = Key + ": ";
                else
                    liCell.textContent = Key + ": " + actionsBP;

                ulCell.appendChild(liCell);

                obj = testArray[Key];
                for(var prop in obj)
                {
                    if( typeof obj[prop]=='object' )
                        splitArray(ulCell, obj)
                }
            }
        }
        actionCell.appendChild(ulCell)
    }

    function generateTable(data) {

        $("#jsonTable tr").remove();

        const tableBody = document.querySelector('#jsonTable tbody');
        for (const category in data) {
            if (data.hasOwnProperty(category)) {
                const subCategory = data[category];
                for (const subKey in subCategory) {
                    if (subCategory.hasOwnProperty(subKey)) {
                        const row = document.createElement('tr');

                        // Create table cells based on the structure of the JSON
                        const categoryCell = document.createElement('td');
                        categoryCell.textContent = category;

                        const subCategoryCell = document.createElement('td');
                        subCategoryCell.textContent = subKey;

                        const actionCell = document.createElement('td');
                        const actions = JSON.stringify(subCategory[subKey]);

                        //console.table(subCategory[subKey])
                        splitArray( actionCell, subCategory[subKey] );


                        row.appendChild(categoryCell);
                        row.appendChild(subCategoryCell);
                        row.appendChild(actionCell);
                        tableBody.appendChild(row);
                    }
                }
            }
        }
    }

    // Call the function to generate the table with JSON data
    generateTable(jsonData);

    function setTextAreaBP( data ) {
        $('#js-textareaBPsecprof').val('');
        $("#js-textareaBPsecprof").val( JSON.stringify(data, null, 2) );
        $("#js-textareaBPsecprof").height( '300px' );
    }

    function updateTable( )
    {
        data = $("#js-textareaBPsecprof").val()
        obj = JSON.parse( data )
        generateTable(obj);
    }

    $("#js-fileBPsecprof2").change(function(){
        var reader = new FileReader();
        reader.onload = function(e){
            createTableFromJSON_bp_secprof(  e.target.result );
            //updateTable();
        };
        reader.readAsText($("#js-fileBPsecprof2")[0].files[0], "UTF-8");
    });

    setTextAreaBP(jsonData);
</script>

</body>
</html>
