<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JSON Data in Table</title>
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
</script>

</body>
</html>
