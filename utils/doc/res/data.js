var data = {
    "actions": {
        "rule": [
            {
                "name": "action-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "supported Security Rule actions: 'allow','deny','drop','reset-client','reset-server','reset-both'",
                        "name": "action"
                    }
                ]
            },
            {
                "name": "app-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "appName"
                    }
                ]
            },
            {
                "name": "app-Add-Force",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "appName"
                    }
                ]
            },
            {
                "name": "app-Fix-Dependencies",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "fix"
                    }
                ]
            },
            {
                "name": "app-postgres-fix",
                "help": null,
                "args": false
            },
            {
                "name": "app-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "appName"
                    }
                ]
            },
            {
                "name": "app-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "appName"
                    }
                ]
            },
            {
                "name": "app-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "app-Usage-clear",
                "help": null,
                "args": false
            },
            {
                "name": "appid-toolbox-cleanup",
                "help": null,
                "args": false
            },
            {
                "name": "biDirNat-Split",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "-DST",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "clone",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "before"
                    },
                    {
                        "type": "string",
                        "default": "-cloned",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "cloneForAppOverride",
                "help": "This&nbspaction&nbspwill&nbsptake&nbspa&nbspSecurity&nbsprule&nbspand&nbspclone&nbspit&nbspas&nbspan&nbspApp-Override&nbsprule.&nbspBy&nbspdefault&nbspall&nbspservices&nbspspecified&nbspin&nbspthe&nbsprule&nbspwill&nbspalso&nbspbe&nbspin&nbspthe&nbspAppOverride&nbsprule.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "specify the application to put in the resulting App-Override rule",
                        "name": "applicationName"
                    },
                    {
                        "type": "string",
                        "default": "*sameAsInRule*",
                        "help": "you can limit which services will be included in the AppOverride rule by providing a #-separated list or a subquery prefixed with a @:\n  - svc1#svc2#svc3... : #-separated list\n  - @subquery1 : script will look for subquery1 filter which you have to provide as an additional argument to the script (ie: 'subquery1=(name eq tcp-50-web)')",
                        "name": "restrictToListOfServices"
                    }
                ]
            },
            {
                "name": "copy",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "location"
                    },
                    {
                        "type": "string",
                        "default": "pre",
                        "choices": [
                            "pre",
                            "post"
                        ],
                        "name": "preORpost"
                    }
                ]
            },
            {
                "name": "create-new-Rule-from-file-FastAPI",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "fileName"
                    }
                ]
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "description-Append",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n",
                        "name": "stringFormula"
                    },
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "newline"
                    }
                ]
            },
            {
                "name": "description-Prepend",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    },
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "newline"
                    }
                ]
            },
            {
                "name": "description-Replace-Character",
                "help": "possible&nbspvariable&nbsp$$comma$$&nbspor&nbsp$$forwardslash$$&nbspor&nbsp$$colon$$&nbspor&nbsp$$pipe$$&nbspor&nbsp$$newline$$&nbspor&nbsp$$appRID#$$;&nbspexample&nbsp\"actions=description-Replace-Character:$$comma$$word1\"",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "search"
                    },
                    {
                        "type": "string",
                        "default": "",
                        "name": "replace"
                    }
                ]
            },
            {
                "name": "disabled-Set",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "disabled-Set-FastAPI",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "display",
                "help": null,
                "args": [
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "ResolveAddressSummary",
                            "ResolveServiceSummary",
                            "ResolveServiceAppDefaultSummary",
                            "ResolveApplicationSummary",
                            "ResolveScheduleSummary",
                            "ApplicationSeen",
                            "HitCount"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - ResolveAddressSummary : fields with address objects will be resolved to IP addressed and summarized in a new column)\n  - ResolveServiceSummary : fields with service objects will be resolved to their value and summarized in a new column)\n  - ResolveServiceAppDefaultSummary : fields with application objects will be resolved to their service default value and summarized in a new column)\n  - ResolveApplicationSummary : fields with application objects will be resolved to their category and risk)\n  - ResolveScheduleSummary : fields with schedule objects will be resolved to their expire time)\n  - ApplicationSeen : all App-ID seen on the Device SecurityRule will be listed\n  - HitCount : Rule - 'first-hit' - 'last-hit' - 'hit-count' - 'rule-creation' will be listed",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "display-app-seen",
                "help": null,
                "args": false
            },
            {
                "name": "DNat-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "static",
                        "help": "The following DNAT-type are possible:\n  - static\n  - dynamic\n  - none\n",
                        "name": "DNATtype"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "servicePort"
                    }
                ]
            },
            {
                "name": "dsri-Set",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "dsri-Set-FastAPI",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "dst-Add",
                "help": "adds&nbspan&nbspobject&nbspin&nbspthe&nbsp'DESTINATION'&nbspfield&nbspof&nbspa&nbsprule,&nbspif&nbspthat&nbspfield&nbspwas&nbspset&nbspto&nbsp'ANY'&nbspit&nbspwill&nbspthen&nbspbe&nbspreplaced&nbspby&nbspthis&nbspobject.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "dst-Add-from-file",
                "help": "adds&nbspall&nbspobjects&nbspto&nbspthe&nbsp'DESTINATION'&nbspfield&nbspof&nbspa&nbsprule,&nbspif&nbspthat&nbspfield&nbspwas&nbspset&nbspto&nbsp'ANY'&nbspit&nbspwill&nbspthen&nbspbe&nbspreplaced&nbspby&nbspthese&nbspobjects&nbspdefined&nbspin&nbspfile.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "file"
                    }
                ]
            },
            {
                "name": "dst-Negate-Set",
                "help": "manages&nbspDestination&nbspNegation&nbspenablement",
                "args": [
                    {
                        "type": "bool",
                        "default": "*nodefault*",
                        "name": "YESorNO"
                    }
                ]
            },
            {
                "name": "dst-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "dst-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "dst-Remove-Objects-Matching-Filter",
                "help": "this&nbspaction&nbspwill&nbspgo&nbspthrough&nbspall&nbspobjects&nbspand&nbspsee&nbspif&nbspthey&nbspmatch&nbspthe&nbspquery&nbspyou&nbspinput&nbspand&nbspthen&nbspremove&nbspthem&nbspif&nbspit's&nbspthe&nbspcase.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "specify the subquery that will be used to filter the objects to be removed: \"actions=dst-Remove-Objects-Matching-Filter:subquery1\" \"subquery1=!(value ip4.included-in 192.168.10.0\/24)\"",
                        "name": "SubqueryFilterName"
                    }
                ]
            },
            {
                "name": "dst-set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "enabled-Set",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "enabled-Set-FastAPI",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "yes",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "ResolveAddressSummary",
                            "ResolveServiceSummary",
                            "ResolveServiceAppDefaultSummary",
                            "ResolveApplicationSummary",
                            "ResolveScheduleSummary",
                            "ApplicationSeen",
                            "HitCount"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - ResolveAddressSummary : fields with address objects will be resolved to IP addressed and summarized in a new column\n  - ResolveServiceSummary : fields with service objects will be resolved to their value and summarized in a new column\n  - ResolveServiceAppDefaultSummary : fields with application objects will be resolved to their service default value and summarized in a new column\n  - ResolveApplicationSummary : fields with application objects will be resolved to their category and risk\n  - ResolveScheduleSummary : fields with schedule objects will be resolved to their expire time\n  - ApplicationSeen : all App-ID seen on the Device SecurityRule will be listed\n  - HitCount : Rule - 'first-hit' - 'last-hit' - 'hit-count' - 'rule-creation will be listed\n",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "from-Add",
                "help": "Adds&nbspa&nbspzone&nbspin&nbspthe&nbsp'FROM'&nbspfield&nbspof&nbspa&nbsprule.&nbspIf&nbspFROM&nbspwas&nbspset&nbspto&nbspANY&nbspthen&nbspit&nbspwill&nbspbe&nbspreplaced&nbspby&nbspzone&nbspin&nbspargument.Zone&nbspmust&nbspbe&nbspexisting&nbspalready&nbspor&nbspscript&nbspwill&nbspout&nbspan&nbsperror.&nbspUse&nbspaction&nbspfrom-add-force&nbspif&nbspyou&nbspwant&nbspto&nbspadd&nbspa&nbspzone&nbspthat&nbspdoes&nbspnot&nbspnot&nbspexist.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "from-Add-Force",
                "help": "Adds&nbspa&nbspzone&nbspin&nbspthe&nbsp'FROM'&nbspfield&nbspof&nbspa&nbsprule.&nbspIf&nbspFROM&nbspwas&nbspset&nbspto&nbspANY&nbspthen&nbspit&nbspwill&nbspbe&nbspreplaced&nbspby&nbspzone&nbspin&nbspargument.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "from-calculate-zones",
                "help": "This&nbspAction&nbspwill&nbspuse&nbsprouting&nbsptables&nbspto&nbspresolve&nbspzones.&nbspWhen&nbspthe&nbspprogram&nbspcannot&nbspfind&nbspall&nbspparameters&nbspby&nbspitself&nbsp(like&nbspvsys&nbspor&nbsptemplate&nbspname&nbspyou&nbspwill&nbsphave&nbspti&nbspmanually&nbspprovide&nbspthem.<br><br>Usage&nbspexamples:<br><br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:append,vr1<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace,vr3,api@0011C890C,vsys1<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:show,vr5,Datacenter_template<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace,vr3,file@firewall.xml,vsys1<br>",
                "args": [
                    {
                        "type": "string",
                        "default": "append",
                        "choices": [
                            "replace",
                            "append",
                            "show",
                            "unneeded-tag-add"
                        ],
                        "help": "Will determine what to do with resolved zones : show them, replace them in the rule , only append them (removes none but adds missing ones) or tag-add for unneeded zones",
                        "name": "mode"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "Can optionally be provided if script cannot find which virtualRouter it should be using (ie: there are several VR in same VSYS)",
                        "name": "virtualRouter"
                    },
                    {
                        "type": "string",
                        "default": "*notPanorama*",
                        "help": "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden or if you are not using Templates then you will want load firewall config in lieu of specifying a template. \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then specify file@\/folderXYZ\/config.xml.",
                        "name": "template"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "specify vsys when script cannot autodetermine it or when you when to manually override",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "from-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "from-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "from-Remove-from-file",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "fileName"
                    }
                ]
            },
            {
                "name": "from-Replace",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneToReplaceName"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneForReplacementName"
                    },
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "force"
                    }
                ]
            },
            {
                "name": "from-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "group-tag-Remove",
                "help": null,
                "args": false
            },
            {
                "name": "group-tag-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "Group-Tag"
                    }
                ]
            },
            {
                "name": "hip-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "HipProfile"
                    }
                ]
            },
            {
                "name": "invertPreAndPost",
                "help": null,
                "args": false
            },
            {
                "name": "logEnd-Disable",
                "help": "disables&nbsp'log&nbspat&nbspend'&nbspin&nbspa&nbspsecurity&nbsprule.",
                "args": false
            },
            {
                "name": "logend-Disable-FastAPI",
                "help": "disables&nbsp'log&nbspat&nbspend'&nbspin&nbspa&nbspsecurity&nbsprule.<br>'FastAPI'&nbspallows&nbspAPI&nbspcommands&nbspto&nbspbe&nbspsent&nbspall&nbspat&nbsponce&nbspinstead&nbspof&nbspa&nbspsingle&nbspcall&nbspper&nbsprule,&nbspallowing&nbspmuch&nbspfaster&nbspexecution&nbsptime.",
                "args": false
            },
            {
                "name": "logEnd-Enable",
                "help": "enables&nbsp'log&nbspat&nbspend'&nbspin&nbspa&nbspsecurity&nbsprule.",
                "args": false
            },
            {
                "name": "logend-Enable-FastAPI",
                "help": "enables&nbsp'log&nbspat&nbspend'&nbspin&nbspa&nbspsecurity&nbsprule.<br>'FastAPI'&nbspallows&nbspAPI&nbspcommands&nbspto&nbspbe&nbspsent&nbspall&nbspat&nbsponce&nbspinstead&nbspof&nbspa&nbspsingle&nbspcall&nbspper&nbsprule,&nbspallowing&nbspmuch&nbspfaster&nbspexecution&nbsptime.",
                "args": false
            },
            {
                "name": "logSetting-disable",
                "help": "Remove&nbsplog&nbspsetting\/forwarding&nbspprofile&nbspof&nbspa&nbspSecurity&nbsprule&nbspif&nbspany.",
                "args": false
            },
            {
                "name": "logSetting-set",
                "help": "Sets&nbsplog&nbspsetting\/forwarding&nbspprofile&nbspof&nbspa&nbspSecurity&nbsprule&nbspto&nbspthe&nbspvalue&nbspspecified.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "logSetting-set-FastAPI",
                "help": "Sets&nbsplog&nbspsetting\/forwarding&nbspprofile&nbspof&nbspa&nbspSecurity&nbsprule&nbspto&nbspthe&nbspvalue&nbspspecified.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "logStart-Disable",
                "help": "enables&nbsp\"log&nbspat&nbspstart\"&nbspin&nbspa&nbspsecurity&nbsprule",
                "args": false
            },
            {
                "name": "logStart-Disable-FastAPI",
                "help": "disables&nbsp'log&nbspat&nbspstart'&nbspin&nbspa&nbspsecurity&nbsprule.<br>'FastAPI'&nbspallows&nbspAPI&nbspcommands&nbspto&nbspbe&nbspsent&nbspall&nbspat&nbsponce&nbspinstead&nbspof&nbspa&nbspsingle&nbspcall&nbspper&nbsprule,&nbspallowing&nbspmuch&nbspfaster&nbspexecution&nbsptime.",
                "args": false
            },
            {
                "name": "logStart-Enable",
                "help": "disables&nbsp\"log&nbspat&nbspstart\"&nbspin&nbspa&nbspsecurity&nbsprule",
                "args": false
            },
            {
                "name": "logStart-Enable-FastAPI",
                "help": "enables&nbsp'log&nbspat&nbspstart'&nbspin&nbspa&nbspsecurity&nbsprule.<br>'FastAPI'&nbspallows&nbspAPI&nbspcommands&nbspto&nbspbe&nbspsent&nbspall&nbspat&nbsponce&nbspinstead&nbspof&nbspa&nbspsingle&nbspcall&nbspper&nbsprule,&nbspallowing&nbspmuch&nbspfaster&nbspexecution&nbsptime.",
                "args": false
            },
            {
                "name": "move",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "location"
                    },
                    {
                        "type": "string",
                        "default": "pre",
                        "choices": [
                            "pre",
                            "post"
                        ],
                        "name": "preORpost"
                    }
                ]
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    },
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1.",
                        "name": "accept63characters"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    },
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1.",
                        "name": "accept63characters"
                    }
                ]
            },
            {
                "name": "name-Append",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    },
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1.",
                        "name": "accept63characters"
                    }
                ]
            },
            {
                "name": "name-Prepend",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    },
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1.",
                        "name": "accept63characters"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-Rename",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n  - $$sequential.number$$ : sequential number - starting with 1\n  - $$uuid$$ : rule uuid\n",
                        "name": "stringFormula"
                    },
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "This bool is used to allow longer rule name for PAN-OS starting with version 8.1.",
                        "name": "accept63characters"
                    }
                ]
            },
            {
                "name": "name-Replace-Character",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "search"
                    },
                    {
                        "type": "string",
                        "default": "",
                        "name": "replace"
                    }
                ]
            },
            {
                "name": "position-Move-After",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "rulename"
                    }
                ]
            },
            {
                "name": "position-Move-Before",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "rulename"
                    }
                ]
            },
            {
                "name": "position-Move-to-Bottom",
                "help": null,
                "args": false
            },
            {
                "name": "position-Move-to-Top",
                "help": null,
                "args": false
            },
            {
                "name": "qosMarking-Remove",
                "help": null,
                "args": false
            },
            {
                "name": "qosMarking-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "arg1"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "arg2"
                    }
                ]
            },
            {
                "name": "rule-hit-count-clear",
                "help": null,
                "args": false
            },
            {
                "name": "rule-hit-count-show",
                "help": null,
                "args": false
            },
            {
                "name": "ruleType-Change",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "text"
                    }
                ]
            },
            {
                "name": "schedule-Remove",
                "help": null,
                "args": false
            },
            {
                "name": "schedule-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "Schedule"
                    }
                ]
            },
            {
                "name": "securityProfile-Group-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "securityProfile-Group-Set-FastAPI",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "securityProfile-Group-Set-Force",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "securityProfile-Profile-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "choices": [
                            "virus",
                            "vulnerability",
                            "url-filtering",
                            "data-filtering",
                            "file-blocking",
                            "spyware",
                            "wildfire"
                        ],
                        "name": "type"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            },
            {
                "name": "securityProfile-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "any",
                        "choices": [
                            "any",
                            "virus",
                            "vulnerability",
                            "url-filtering",
                            "data-filtering",
                            "file-blocking",
                            "spyware",
                            "wildfire"
                        ],
                        "name": "type"
                    }
                ]
            },
            {
                "name": "securityProfile-Remove-FastAPI",
                "help": null,
                "args": false
            },
            {
                "name": "securityProfile-replace-by-Group",
                "help": null,
                "args": false
            },
            {
                "name": "service-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "svcName"
                    }
                ]
            },
            {
                "name": "service-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "svcName"
                    }
                ]
            },
            {
                "name": "service-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "svcName"
                    }
                ]
            },
            {
                "name": "service-Remove-Objects-Matching-Filter",
                "help": "this&nbspaction&nbspwill&nbspgo&nbspthrough&nbspall&nbspobjects&nbspand&nbspsee&nbspif&nbspthey&nbspmatch&nbspthe&nbspquery&nbspyou&nbspinput&nbspand&nbspthen&nbspremove&nbspthem&nbspif&nbspit's&nbspthe&nbspcase.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "specify the query that will be used to filter the objects to be removed - \nexample: 'actions=service-remove-objects-matching-filter:subquery1,true' 'subquery1=(value > 600) && (object is.udp) && (value is.single.port)'",
                        "name": "filterName"
                    },
                    {
                        "type": "bool",
                        "default": "false",
                        "name": "forceAny"
                    }
                ]
            },
            {
                "name": "service-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "service-Set-AppDefault",
                "help": null,
                "args": false
            },
            {
                "name": "SNat-set-interface",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "SNATInterface"
                    }
                ]
            },
            {
                "name": "src-Add",
                "help": "adds&nbspan&nbspobject&nbspin&nbspthe&nbsp'SOURCE'&nbspfield&nbspof&nbspa&nbsprule,&nbspif&nbspthat&nbspfield&nbspwas&nbspset&nbspto&nbsp'ANY'&nbspit&nbspwill&nbspthen&nbspbe&nbspreplaced&nbspby&nbspthis&nbspobject.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "src-Add-from-file",
                "help": "adds&nbspall&nbspobjects&nbspto&nbspthe&nbsp'SOURCE'&nbspfield&nbspof&nbspa&nbsprule,&nbspif&nbspthat&nbspfield&nbspwas&nbspset&nbspto&nbsp'ANY'&nbspit&nbspwill&nbspthen&nbspbe&nbspreplaced&nbspby&nbspthese&nbspobjects&nbspdefined&nbspin&nbspfile.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "file"
                    }
                ]
            },
            {
                "name": "src-dst-swap",
                "help": "moves&nbspall&nbspsource&nbspobjects&nbspto&nbspdestination&nbspand&nbspreverse.",
                "args": false
            },
            {
                "name": "src-Negate-Set",
                "help": "manages&nbspSource&nbspNegation&nbspenablement",
                "args": [
                    {
                        "type": "bool",
                        "default": "*nodefault*",
                        "name": "YESorNO"
                    }
                ]
            },
            {
                "name": "src-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "src-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objName"
                    }
                ]
            },
            {
                "name": "src-Remove-Objects-Matching-Filter",
                "help": "this&nbspaction&nbspwill&nbspgo&nbspthrough&nbspall&nbspobjects&nbspand&nbspsee&nbspif&nbspthey&nbspmatch&nbspthe&nbspquery&nbspyou&nbspinput&nbspand&nbspthen&nbspremove&nbspthem&nbspif&nbspit's&nbspthe&nbspcase.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "specify the subquery that will be used to filter the objects to be removed: \"actions=src-Remove-Objects-Matching-Filter:subquery1\" \"subquery1=!(value ip4.included-in 192.168.10.0\/24)\"",
                        "name": "SubqueryFilterName"
                    }
                ]
            },
            {
                "name": "src-set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "stats-address-destination-FastAPI",
                "help": "returns&nbspTRUE&nbspif&nbsprule&nbspname&nbspmatches&nbspthe&nbspspecified&nbsptimestamp&nbspMM\/DD\/YYYY&nbsp[american]&nbsp\/&nbspDD-MM-YYYY&nbsp[european]&nbsp\/&nbsp21&nbspSeptember&nbsp2021&nbsp\/&nbsp-90&nbspdays",
                "args": [
                    {
                        "type": "string",
                        "default": "last-15-minutes",
                        "name": "logHistory"
                    }
                ]
            },
            {
                "name": "stats-address-FastAPI",
                "help": "returns&nbspTRUE&nbspif&nbsprule&nbspname&nbspmatches&nbspthe&nbspspecified&nbsptimestamp&nbspMM\/DD\/YYYY&nbsp[american]&nbsp\/&nbspDD-MM-YYYY&nbsp[european]&nbsp\/&nbsp21&nbspSeptember&nbsp2021&nbsp\/&nbsp-90&nbspdays",
                "args": [
                    {
                        "type": "string",
                        "default": "last-15-minutes",
                        "name": "logHistory"
                    }
                ]
            },
            {
                "name": "stats-address-source-FastAPI",
                "help": "returns&nbspTRUE&nbspif&nbsprule&nbspname&nbspmatches&nbspthe&nbspspecified&nbsptimestamp&nbspMM\/DD\/YYYY&nbsp[american]&nbsp\/&nbspDD-MM-YYYY&nbsp[european]&nbsp\/&nbsp21&nbspSeptember&nbsp2021&nbsp\/&nbsp-90&nbspdays",
                "args": [
                    {
                        "type": "string",
                        "default": "last-15-minutes",
                        "name": "logHistory"
                    }
                ]
            },
            {
                "name": "stats-appid-FastAPI",
                "help": "returns&nbspTRUE&nbspif&nbsprule&nbspname&nbspmatches&nbspthe&nbspspecified&nbsptimestamp&nbspMM\/DD\/YYYY&nbsp[american]&nbsp\/&nbspDD-MM-YYYY&nbsp[european]&nbsp\/&nbsp21&nbspSeptember&nbsp2021&nbsp\/&nbsp-90&nbspdays",
                "args": [
                    {
                        "type": "string",
                        "default": "last-15-minutes",
                        "name": "logHistory"
                    }
                ]
            },
            {
                "name": "stats-service-FastAPI",
                "help": "returns&nbspTRUE&nbspif&nbsprule&nbspname&nbspmatches&nbspthe&nbspspecified&nbsptimestamp&nbspMM\/DD\/YYYY&nbsp[american]&nbsp\/&nbspDD-MM-YYYY&nbsp[european]&nbsp\/&nbsp21&nbspSeptember&nbsp2021&nbsp\/&nbsp-90&nbspdays",
                "args": [
                    {
                        "type": "string",
                        "default": "last-15-minutes",
                        "name": "logHistory"
                    }
                ]
            },
            {
                "name": "stats-traffic-FastAPI",
                "help": "returns&nbspTRUE&nbspif&nbsprule&nbspname&nbspmatches&nbspthe&nbspspecified&nbsptimestamp&nbspMM\/DD\/YYYY&nbsp[american]&nbsp\/&nbspDD-MM-YYYY&nbsp[european]&nbsp\/&nbsp21&nbspSeptember&nbsp2021&nbsp\/&nbsp-90&nbspdays",
                "args": [
                    {
                        "type": "string",
                        "default": "last-15-minutes",
                        "name": "logHistory"
                    }
                ]
            },
            {
                "name": "tag-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Add-Force",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    },
                    {
                        "type": "string",
                        "default": "none",
                        "name": "tagColor"
                    }
                ]
            },
            {
                "name": "tag-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Remove-All",
                "help": null,
                "args": false
            },
            {
                "name": "tag-Remove-Regex",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "regex"
                    }
                ]
            },
            {
                "name": "target-Add-Device",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "serial"
                    },
                    {
                        "type": "string",
                        "default": "*NULL*",
                        "help": "if target firewall is single VSYS you should ignore this argument, otherwise just input it",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "target-Negate-Set",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "*nodefault*",
                        "name": "trueOrFalse"
                    }
                ]
            },
            {
                "name": "target-Remove-Device",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "serial"
                    },
                    {
                        "type": "string",
                        "default": "*NULL*",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "target-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "to-Add",
                "help": "Adds&nbspa&nbspzone&nbspin&nbspthe&nbsp'TO'&nbspfield&nbspof&nbspa&nbsprule.&nbspIf&nbspTO&nbspwas&nbspset&nbspto&nbspANY&nbspthen&nbspit&nbspwill&nbspbe&nbspreplaced&nbspby&nbspzone&nbspin&nbspargument.Zone&nbspmust&nbspbe&nbspexisting&nbspalready&nbspor&nbspscript&nbspwill&nbspout&nbspan&nbsperror.&nbspUse&nbspaction&nbspto-add-force&nbspif&nbspyou&nbspwant&nbspto&nbspadd&nbspa&nbspzone&nbspthat&nbspdoes&nbspnot&nbspnot&nbspexist.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "to-Add-Force",
                "help": "Adds&nbspa&nbspzone&nbspin&nbspthe&nbsp'FROM'&nbspfield&nbspof&nbspa&nbsprule.&nbspIf&nbspFROM&nbspwas&nbspset&nbspto&nbspANY&nbspthen&nbspit&nbspwill&nbspbe&nbspreplaced&nbspby&nbspzone&nbspin&nbspargument.",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "to-calculate-zones",
                "help": "This&nbspAction&nbspwill&nbspuse&nbsprouting&nbsptables&nbspto&nbspresolve&nbspzones.&nbspWhen&nbspthe&nbspprogram&nbspcannot&nbspfind&nbspall&nbspparameters&nbspby&nbspitself&nbsp(like&nbspvsys&nbspor&nbsptemplate&nbspname&nbspyou&nbspwill&nbsphave&nbspti&nbspmanually&nbspprovide&nbspthem.<br><br>Usage&nbspexamples:<br><br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:append,vr1<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace,vr3,api@0011C890C,vsys1<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:show,vr5,Datacenter_template<br>&nbsp&nbsp&nbsp&nbsp-&nbspxxx-calculate-zones:replace,vr3,file@firewall.xml,vsys1<br>",
                "args": [
                    {
                        "type": "string",
                        "default": "append",
                        "choices": [
                            "replace",
                            "append",
                            "show",
                            "unneeded-tag-add"
                        ],
                        "help": "Will determine what to do with resolved zones : show them, replace them in the rule , only append them (removes none but adds missing ones) or tag-add for unneeded zones",
                        "name": "mode"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "Can optionally be provided if script cannot find which virtualRouter it should be using (ie: there are several VR in same VSYS)",
                        "name": "virtualRouter"
                    },
                    {
                        "type": "string",
                        "default": "*notPanorama*",
                        "help": "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden or if you are not using Templates then you will want load firewall config in lieu of specifying a template. \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then specify file@\/folderXYZ\/config.xml.",
                        "name": "template"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "specify vsys when script cannot autodetermine it or when you when to manually override",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "to-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "to-Remove-Force-Any",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneName"
                    }
                ]
            },
            {
                "name": "to-Remove-from-file",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "fileName"
                    }
                ]
            },
            {
                "name": "to-Replace",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneToReplaceName"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "zoneForReplacementName"
                    },
                    {
                        "type": "bool",
                        "default": "no",
                        "name": "force"
                    }
                ]
            },
            {
                "name": "to-Set-Any",
                "help": null,
                "args": false
            },
            {
                "name": "user-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "userName"
                    }
                ]
            },
            {
                "name": "user-check-ldap",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "show",
                        "help": "'show' and 'remove' are supported.",
                        "name": "actionType"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "define LDAP user for authentication to server",
                        "name": "ldapUser"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "LDAP server fqdn \/ IP",
                        "name": "ldapServer"
                    },
                    {
                        "type": "string",
                        "default": "OU=TEST;DC=domain;DC=local",
                        "help": "full OU to an LDAP part, sparated with ';' - this is a specific setting",
                        "name": "dn"
                    },
                    {
                        "type": "string",
                        "default": "mailNickname",
                        "help": "Domain\\username - specify the search filter criteria where your Security Rule defined user name can be found in LDAP",
                        "name": "filtercriteria"
                    },
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "users no longer available in LDAP => false | users available in LDAP => true, e.g. if users are disabled and available in a specific LDAP group",
                        "name": "existentUser"
                    }
                ]
            },
            {
                "name": "user-remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "userName"
                    }
                ]
            },
            {
                "name": "user-replace",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "old-userName"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "new-userName"
                    }
                ]
            },
            {
                "name": "user-replace-from-file",
                "help": "file&nbspsyntax:&nbsp'old-user-name,newusername'&nbsp;&nbspeach&nbsppair&nbspon&nbspa&nbspnewline!",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "file"
                    }
                ]
            },
            {
                "name": "user-set-any",
                "help": null,
                "args": false
            },
            {
                "name": "xml-extract",
                "help": null,
                "args": false
            }
        ],
        "address": [
            {
                "name": "add-member",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "addressobjectname"
                    }
                ]
            },
            {
                "name": "addObjectWhereUsed",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    },
                    {
                        "type": "bool",
                        "default": false,
                        "name": "skipNatRules"
                    }
                ]
            },
            {
                "name": "address-group-create-edl-fqdn",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    }
                ]
            },
            {
                "name": "address-group-create-edl-ip",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    }
                ]
            },
            {
                "name": "AddToGroup",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "addressgroupname"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "please define a DeviceGroup name for Panorama config or vsys name for Firewall config.\n",
                        "name": "devicegroupname"
                    }
                ]
            },
            {
                "name": "combine-addressgroups",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "new_addressgroup_name"
                    },
                    {
                        "type": "bool",
                        "default": false,
                        "name": "replace_groups"
                    }
                ]
            },
            {
                "name": "create-address",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "name"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "value"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "tmp, ip-netmask, ip-range, fqdn, dynamic, ip-wildcard",
                        "name": "type"
                    }
                ]
            },
            {
                "name": "create-address-from-file",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "file syntax:   AddressObjectName,IP-Address,Address-group\n\nexample:\n    h-192.168.0.1,192.168.0.1\/32,private-network-AddressGroup\n    n-192.168.2.0m24,192.168.2.0\/24,private-network-AddressGroup\n",
                        "name": "file"
                    },
                    {
                        "type": "bool",
                        "default": false,
                        "name": "force-add-to-group"
                    },
                    {
                        "type": "bool",
                        "default": false,
                        "name": "force-change-value"
                    }
                ]
            },
            {
                "name": "create-addressgroup",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "name"
                    }
                ]
            },
            {
                "name": "decommission",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "file"
                    }
                ]
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "delete-Force",
                "help": null,
                "args": false
            },
            {
                "name": "description-Append",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n",
                        "name": "stringFormula"
                    }
                ]
            },
            {
                "name": "description-Delete",
                "help": null,
                "args": false
            },
            {
                "name": "description-Replace-Character",
                "help": "possible&nbspvariable&nbsp$$comma$$&nbspor&nbsp$$forwardslash$$&nbspor&nbsp$$colon$$&nbspor&nbsp$$pipe$$;&nbspexample&nbsp\"actions=description-Replace-Character:$$comma$$word1\"",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "search"
                    },
                    {
                        "type": "string",
                        "default": "",
                        "name": "replace"
                    }
                ]
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "display-NAT-usage",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation",
                            "ResolveIP",
                            "NestedMembers"
                        ],
                        "help": "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n  - NestedMembers: lists all members, even the ones that may be included in nested groups\n  - ResolveIP\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n  - WhereUsed : list places where object is used (rules, groups ...)\n",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "move",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "location"
                    },
                    {
                        "type": "string",
                        "default": "skipIfConflict",
                        "choices": [
                            "skipIfConflict",
                            "removeIfMatch",
                            "removeIfNumericalMatch"
                        ],
                        "name": "mode"
                    }
                ]
            },
            {
                "name": "move-range2network",
                "help": null,
                "args": false
            },
            {
                "name": "move-wildcard2network",
                "help": null,
                "args": false
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-Rename",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n  - $$netmask$$ : netmask\n  - $$netmask.blank32$$ : netmask or nothing if 32\n  - $$reverse-dns$$ : value truncated of netmask if any\n  - $$value$$ : value of the object\n  - $$value.no-netmask$$ : value truncated of netmask if any\n",
                        "name": "stringFormula"
                    }
                ]
            },
            {
                "name": "name-Replace-Character",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "search"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "replace"
                    }
                ]
            },
            {
                "name": "removeWhereUsed",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "delete",
                        "choices": [
                            "delete",
                            "disable",
                            "setAny"
                        ],
                        "name": "actionIfLastMemberInRule"
                    }
                ]
            },
            {
                "name": "replace-IP-by-MT-like-Object",
                "help": null,
                "args": false
            },
            {
                "name": "replace-Object-by-IP",
                "help": null,
                "args": false
            },
            {
                "name": "replaceByMembersAndDelete",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "choices": [
                            "tag",
                            "description"
                        ],
                        "help": "- replaceByMembersAndDelete:tag -> create Tag with name from AddressGroup name and add to the object\n- replaceByMembersAndDelete:description -> create Tag with name from AddressGroup name and add to the object\n",
                        "name": "keepgroupname"
                    }
                ]
            },
            {
                "name": "replaceWithObject",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
            },
            {
                "name": "showIP4Mapping",
                "help": null,
                "args": false
            },
            {
                "name": "split-large-address-groups",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "2490",
                        "name": "largeGroupsCount"
                    }
                ]
            },
            {
                "name": "tag-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Add-Force",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Remove-All",
                "help": null,
                "args": false
            },
            {
                "name": "tag-Remove-Regex",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "regex"
                    }
                ]
            },
            {
                "name": "upload-address-2cloudmanager",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "panorama_file"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "dg_name"
                    }
                ]
            },
            {
                "name": "upload-addressgroup-2cloudmanager",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "panorama_file"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "dg_name"
                    }
                ]
            },
            {
                "name": "value-host-object-add-netmask-m32",
                "help": null,
                "args": false
            },
            {
                "name": "value-replace",
                "help": "search&nbspfor&nbspa&nbspfull&nbspor&nbsppartial&nbspvalue&nbspand&nbspreplace;&nbspexample&nbsp\"actions=value-replace:1.1.1.,2.2.2.\"&nbspit&nbspis&nbsprecommend&nbspto&nbspuse&nbspadditional&nbspfilter:&nbsp\"filter=(value&nbspstring.regex&nbsp\/^1.1.1.\/)\"<br>&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp&nbsp\"actions=value-replace:$$netmask.32$$,$$netmask.blank32$$\"<br>&nbsp&nbsp&nbsp&nbsp",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "1.1.1.",
                        "name": "search"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "2.2.2.",
                        "name": "replace"
                    }
                ]
            },
            {
                "name": "value-set-ip-for-fqdn",
                "help": null,
                "args": false
            },
            {
                "name": "value-set-reverse-dns",
                "help": null,
                "args": false
            },
            {
                "name": "z_BETA_summarize",
                "help": null,
                "args": false
            }
        ],
        "service": [
            {
                "name": "addObjectWhereUsed",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
            },
            {
                "name": "create-service",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "name"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "protocol"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "port"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "sport"
                    }
                ]
            },
            {
                "name": "create-servicegroup",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "name"
                    }
                ]
            },
            {
                "name": "decommission",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "file"
                    }
                ]
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "delete-Force",
                "help": null,
                "args": false
            },
            {
                "name": "description-Append",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n",
                        "name": "stringFormula"
                    }
                ]
            },
            {
                "name": "description-Delete",
                "help": null,
                "args": false
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation",
                            "ResolveSRV",
                            "NestedMembers"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n  - NestedMembers: lists all members, even the ones that may be included in nested groups\n  - ResolveSRV\n",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "move",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "location"
                    },
                    {
                        "type": "string",
                        "default": "skipIfConflict",
                        "choices": [
                            "skipIfConflict",
                            "removeIfMatch",
                            "removeIfNumericalMatch"
                        ],
                        "name": "mode"
                    }
                ]
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-Rename",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n  - $$destinationport$$ : destination Port\n  - $$protocol$$ : service protocol\n  - $$sourceport$$ : source Port\n  - $$value$$ : value of the object\n  - $$timeout$$ : timeout value of the object\n",
                        "name": "stringFormula"
                    }
                ]
            },
            {
                "name": "name-Replace-Character",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "search"
                    },
                    {
                        "type": "string",
                        "default": "",
                        "name": "replace"
                    }
                ]
            },
            {
                "name": "removeWhereUsed",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "delete",
                        "choices": [
                            "delete",
                            "disable",
                            "setAny"
                        ],
                        "name": "actionIfLastMemberInRule"
                    }
                ]
            },
            {
                "name": "replaceByMembersAndDelete",
                "help": null,
                "args": false
            },
            {
                "name": "replaceGroupByService",
                "help": null,
                "args": false
            },
            {
                "name": "replaceWithObject",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
            },
            {
                "name": "show-dstportmapping",
                "help": null,
                "args": false
            },
            {
                "name": "sourceport-delete",
                "help": null,
                "args": false
            },
            {
                "name": "sourceport-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "sourceportValue"
                    }
                ]
            },
            {
                "name": "split-large-service-groups",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "2490",
                        "name": "largeGroupsCount"
                    }
                ]
            },
            {
                "name": "tag-Add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Add-Force",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "tagName"
                    }
                ]
            },
            {
                "name": "tag-Remove-All",
                "help": null,
                "args": false
            },
            {
                "name": "tag-Remove-Regex",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "regex"
                    }
                ]
            },
            {
                "name": "timeout-halfclose-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "timeoutValue"
                    }
                ]
            },
            {
                "name": "timeout-inherit",
                "help": null,
                "args": false
            },
            {
                "name": "timeout-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "timeoutValue"
                    }
                ]
            },
            {
                "name": "timeout-timewait-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "timeoutValue"
                    }
                ]
            }
        ],
        "tag": [
            {
                "name": "Color-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "choices": [
                            "none",
                            "red",
                            "green",
                            "blue",
                            "yellow",
                            "copper",
                            "orange",
                            "purple",
                            "gray",
                            "light green",
                            "cyan",
                            "light gray",
                            "blue gray",
                            "lime",
                            "black",
                            "gold",
                            "brown",
                            "dark green"
                        ],
                        "name": "color"
                    }
                ]
            },
            {
                "name": "Comments-add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "comments"
                    }
                ]
            },
            {
                "name": "Comments-delete",
                "help": null,
                "args": false
            },
            {
                "name": "create",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "name"
                    }
                ]
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "deleteForce",
                "help": null,
                "args": false
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "move",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "location"
                    },
                    {
                        "type": "string",
                        "default": "skipIfConflict",
                        "choices": [
                            "skipIfConflict",
                            "removeIfMatch"
                        ],
                        "name": "mode"
                    }
                ]
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-toLowerCase",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUCWords",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUpperCase",
                "help": null,
                "args": false
            },
            {
                "name": "replace-With-Object",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
            }
        ],
        "zone": [
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "deleteForce",
                "help": null,
                "args": false
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation",
                            "ResolveIP",
                            "NestedMembers"
                        ],
                        "help": "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n  - NestedMembers: lists all members, even the ones that may be included in nested groups\n  - ResolveIP\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n  - WhereUsed : list places where object is used (rules, groups ...)\n",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "logsetting-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "this argument can be also 'none' to remove the Log Setting back to PAN-OS default.",
                        "name": "logforwardingprofile-name"
                    }
                ]
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-Rename",
                "help": "",
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "This string is used to compose a name. You can use the following aliases :\n  - $$current.name$$ : current name of the object\n",
                        "name": "stringFormula"
                    }
                ]
            },
            {
                "name": "name-toLowerCase",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUCWords",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUpperCase",
                "help": null,
                "args": false
            },
            {
                "name": "PacketBufferProtection-Set",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "*nodefault*",
                        "name": "PacketBufferProtection"
                    }
                ]
            },
            {
                "name": "replaceWithObject",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
            },
            {
                "name": "UserID-enable",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "TRUE",
                        "name": "enable"
                    }
                ]
            },
            {
                "name": "zpp-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "ZPP-name"
                    }
                ]
            }
        ],
        "securityprofile": [
            {
                "name": "action-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "allow, alert, block, continue, override",
                        "name": "action"
                    },
                    {
                        "type": "string",
                        "default": "all",
                        "help": "all \/ all-[action] \/ category",
                        "name": "filter"
                    }
                ]
            },
            {
                "name": "custom-url-category-add-ending-token",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "\/",
                        "help": "supported ending token: '.', '\/', '?', '&', '=', ';', '+', '*', '\/*' - please be aware for '\/*' please use '$$*'\n\n'actions=custom-url-category-add-ending-token:\/' is the default value, it can NOT be run directly\nplease use: 'actions=custom-url-category-add-ending-token' to avoid problems like: '**ERROR** unsupported Action:\"\"'",
                        "name": "endingtoken"
                    }
                ]
            },
            {
                "name": "custom-url-category-fix-leading-dot",
                "help": null,
                "args": false
            },
            {
                "name": "custom-url-category-remove-ending-token",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "\/",
                        "help": "supported ending token: '.', '\/', '?', '&', '=', ';', '+', '*', '\/*' - please be aware for '\/*' please use '$$*'\n\n'actions=custom-url-category-add-ending-token:\/' is the default value, it can NOT be run directly\nplease use: 'actions=custom-url-category-add-ending-token' to avoid problems like: '**ERROR** unsupported Action:\"\"'",
                        "name": "endingtoken"
                    }
                ]
            },
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "deleteForce",
                "help": null,
                "args": false
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation"
                        ],
                        "help": "pipe(|) separated list of additional fields (ie: Arg1|Arg2|Arg3...) to include in the report. The following is available:\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n  - WhereUsed : list places where object is used (rules, groups ...)\n",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-toLowerCase",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUCWords",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUpperCase",
                "help": null,
                "args": false
            },
            {
                "name": "url-filtering-action-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "action"
                    },
                    {
                        "type": "string",
                        "default": "false",
                        "name": "url-category"
                    }
                ]
            }
        ],
        "securityprofilegroup": [
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "securityProfile-Remove",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "any",
                        "choices": [
                            "any",
                            "virus",
                            "vulnerability",
                            "url-filtering",
                            "data-filtering",
                            "file-blocking",
                            "spyware",
                            "wildfire"
                        ],
                        "name": "type"
                    }
                ]
            },
            {
                "name": "securityProfile-Set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "choices": [
                            "virus",
                            "vulnerability",
                            "url-filtering",
                            "data-filtering",
                            "file-blocking",
                            "spyware",
                            "wildfire"
                        ],
                        "name": "type"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "profName"
                    }
                ]
            }
        ],
        "device": [
            {
                "name": "addressstore-rewrite",
                "help": null,
                "args": false
            },
            {
                "name": "cleanuprule-create-bp",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "default",
                        "help": "LogForwardingProfile name",
                        "name": "logprof"
                    }
                ]
            },
            {
                "name": "defaultsecurityrule-action-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "define which ruletype; 'intrazone'|'interzone'|'all' ",
                        "name": "ruletype"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "define the action you like to set 'allow'|'deny'",
                        "name": "action"
                    }
                ]
            },
            {
                "name": "defaultsecurityRule-create-bp",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "default",
                        "help": "LogForwardingProfile name",
                        "name": "logprof"
                    }
                ]
            },
            {
                "name": "defaultsecurityrule-logend-enable",
                "help": null,
                "args": false
            },
            {
                "name": "defaultsecurityrule-logsetting-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "default",
                        "help": "LogForwardingProfile name",
                        "name": "logprof"
                    },
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "LogForwardingProfile overwrite",
                        "name": "force"
                    }
                ]
            },
            {
                "name": "defaultsecurityrule-logstart-disable",
                "help": null,
                "args": false
            },
            {
                "name": "defaultsecurityrule-remove-override",
                "help": null,
                "args": false
            },
            {
                "name": "defaultsecurityrule-securityprofile-remove",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "per default, remove SecurityProfiles only if Rule action is NOT allow. force=true => remove always",
                        "name": "force"
                    }
                ]
            },
            {
                "name": "defaultsecurityrule-securityprofile-setAlert",
                "help": null,
                "args": false
            },
            {
                "name": "defaultsecurityrule-securityprofilegroup-set",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "set SecurityProfileGroup to default SecurityRules, if the Rule is an allow rule",
                        "name": "securityProfileGroup"
                    }
                ]
            },
            {
                "name": "devicegroup-addserial",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "name"
                    },
                    {
                        "type": "string",
                        "default": "null",
                        "name": "serial"
                    }
                ]
            },
            {
                "name": "devicegroup-create",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "name"
                    },
                    {
                        "type": "string",
                        "default": "null",
                        "name": "parentdg"
                    }
                ]
            },
            {
                "name": "devicegroup-delete",
                "help": null,
                "args": false
            },
            {
                "name": "devicegroup-removeserial",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "name"
                    },
                    {
                        "type": "string",
                        "default": "null",
                        "name": "serial"
                    }
                ]
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "display-shadowrule",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "define an argument with filename to also store shadow rule to an excel\/html speardsheet file",
                        "name": "exportToExcel"
                    }
                ]
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "exportInventoryToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "only usable with 'devicetype=manageddevice'",
                        "name": "filename"
                    }
                ]
            },
            {
                "name": "exportLicenseToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "only usable with 'devicetype=manageddevice'",
                        "name": "filename"
                    }
                ]
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n",
                        "name": "additionalFields"
                    }
                ]
            },
            {
                "name": "find-zone-from-ip",
                "help": "This&nbspAction&nbspwill&nbspuse&nbsprouting&nbsptables&nbspto&nbspresolve&nbspzones.&nbspWhen&nbspthe&nbspprogram&nbspcannot&nbspfind&nbspall&nbspparameters&nbspby&nbspitself&nbsp(like&nbspvsys&nbspor&nbsptemplate&nbspname&nbspyou&nbspwill&nbsphave&nbspto&nbspmanually&nbspprovide&nbspthem.<br><br>Usage&nbspexamples:<br><br>&nbsp&nbsp&nbsp&nbsp-&nbspfind-zone-from-ip:8.8.8.8<br>&nbsp&nbsp&nbsp&nbsp-&nbspfind-zone-from-ip:8.8.8.8,vr1<br>&nbsp&nbsp&nbsp&nbsp-&nbspfind-zone-from-ip:8.8.8.8,vr3,api@0011C890C,vsys1<br>&nbsp&nbsp&nbsp&nbsp-&nbspfind-zone-from-ip:8.8.8.8,vr5,Datacenter_template<br>&nbsp&nbsp&nbsp&nbsp-&nbspfind-zone-from-ip:8.8.8.8,vr3,file@firewall.xml,vsys1<br>",
                "args": [
                    {
                        "type": "string",
                        "default": "*noDefault*",
                        "help": "Please bring in an IP-Address, to find the corresponding Zone.",
                        "name": "ip"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "Can optionally be provided if script cannot find which virtualRouter it should be using (ie: there are several VR in same VSYS)",
                        "name": "virtualRouter"
                    },
                    {
                        "type": "string",
                        "default": "*notPanorama*",
                        "help": "When you are using Panorama then 1 or more templates could apply to a DeviceGroup, in such a case you may want to specify which Template name to use.\nBeware that if the Template is overriden or if you are not using Templates then you will want load firewall config in lieu of specifying a template. \nFor this, give value 'api@XXXXX' where XXXXX is serial number of the Firewall device number you want to use to calculate zones.\nIf you don't want to use API but have firewall config file on your computer you can then specify file@\/folderXYZ\/config.xml.",
                        "name": "template"
                    },
                    {
                        "type": "string",
                        "default": "*autodetermine*",
                        "help": "specify vsys when script cannot autodetermine it or when you when to manually override",
                        "name": "vsys"
                    }
                ]
            },
            {
                "name": "geoIP-check",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "8.8.8.8",
                        "help": "checkIP is IPv4 or IPv6 host address",
                        "name": "checkIP"
                    }
                ]
            },
            {
                "name": "logforwardingprofile-create-bp",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "if set to true; LogForwardingProfile is create at SHARED level; at least one DG must be available",
                        "name": "shared"
                    }
                ]
            },
            {
                "name": "manageddevice-create",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "serial"
                    }
                ]
            },
            {
                "name": "manageddevice-delete",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "decommission Manageddevice, also if used on Device-Group or Template-stack",
                        "name": "force"
                    }
                ]
            },
            {
                "name": "sharedgateway-delete",
                "help": null,
                "args": false
            },
            {
                "name": "sharedgateway-migrate-to-vsys",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "name"
                    }
                ]
            },
            {
                "name": "sp_spg-create-alert-only-bp",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "if set to true; securityProfiles are create at SHARED level; at least one DG must be available",
                        "name": "shared"
                    }
                ]
            },
            {
                "name": "sp_spg-create-bp",
                "help": null,
                "args": [
                    {
                        "type": "bool",
                        "default": "false",
                        "help": "if set to true; securityProfiles are create at SHARED level; at least one DG must be available",
                        "name": "shared"
                    },
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "help": "if set, only ironskillet SP called 'Outbound' are created with the name defined",
                        "name": "sp-name"
                    }
                ]
            },
            {
                "name": "system-admin-session",
                "help": "This&nbspAction&nbspis&nbspdisplaying&nbspthe&nbspactual&nbsplogged&nbspin&nbspadmin&nbspsessions",
                "args": [
                    {
                        "type": "string",
                        "default": "display",
                        "name": "action"
                    },
                    {
                        "type": "string",
                        "default": "8",
                        "name": "idle-since-hours"
                    }
                ]
            },
            {
                "name": "system-mgt-config_users",
                "help": "This&nbspAction&nbspwill&nbspdisplay&nbspthe&nbspconfigured&nbspAdmin&nbspusers&nbspon&nbspthe&nbspDevice",
                "args": false
            },
            {
                "name": "system-restart",
                "help": "This&nbspAction&nbspis&nbsprebooting&nbspthe&nbspDevice",
                "args": false
            },
            {
                "name": "template-add",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "templateName"
                    },
                    {
                        "type": "string",
                        "default": "bottom",
                        "name": "position"
                    }
                ]
            },
            {
                "name": "template-clone",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "newname"
                    }
                ]
            },
            {
                "name": "template-create",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "name"
                    }
                ]
            },
            {
                "name": "template-delete",
                "help": null,
                "args": false
            },
            {
                "name": "templatestack-addserial",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "name"
                    },
                    {
                        "type": "string",
                        "default": "null",
                        "name": "serial"
                    }
                ]
            },
            {
                "name": "templatestack-clone",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "newname"
                    }
                ]
            },
            {
                "name": "templatestack-create",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "name"
                    }
                ]
            },
            {
                "name": "templatestack-delete",
                "help": null,
                "args": false
            },
            {
                "name": "templatestack-removeserial",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "false",
                        "name": "name"
                    },
                    {
                        "type": "string",
                        "default": "null",
                        "name": "serial"
                    }
                ]
            },
            {
                "name": "virtualsystem-delete",
                "help": null,
                "args": false
            },
            {
                "name": "xml-extract",
                "help": null,
                "args": false
            },
            {
                "name": "zoneprotectionprofile-create-bp",
                "help": null,
                "args": false
            },
            {
                "name": "zpp-create-alert-only-bp",
                "help": null,
                "args": false
            },
            {
                "name": "zpp-create-bp",
                "help": null,
                "args": false
            }
        ],
        "interface": [
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayreferences",
                "help": null,
                "args": false
            }
        ],
        "routing": [
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "exportToExcel",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "filename"
                    },
                    {
                        "type": "pipeSeparatedList",
                        "subtype": "string",
                        "default": "*NONE*",
                        "choices": [
                            "WhereUsed",
                            "UsedInLocation"
                        ],
                        "help": "pipe(|) separated list of additional field to include in the report. The following is available:\n  - WhereUsed : list places where object is used (rules, groups ...)\n  - UsedInLocation : list locations (vsys,dg,shared) where object is used\n",
                        "name": "additionalFields"
                    }
                ]
            }
        ],
        "virtualwire": [
            {
                "name": "display",
                "help": null,
                "args": false
            }
        ],
        "schedule": [
            {
                "name": "delete",
                "help": null,
                "args": false
            },
            {
                "name": "deleteForce",
                "help": null,
                "args": false
            },
            {
                "name": "display",
                "help": null,
                "args": false
            },
            {
                "name": "displayReferences",
                "help": null,
                "args": false
            },
            {
                "name": "name-addPrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-addSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-removePrefix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "prefix"
                    }
                ]
            },
            {
                "name": "name-removeSuffix",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "suffix"
                    }
                ]
            },
            {
                "name": "name-toLowerCase",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUCWords",
                "help": null,
                "args": false
            },
            {
                "name": "name-toUpperCase",
                "help": null,
                "args": false
            },
            {
                "name": "replaceWithObject",
                "help": null,
                "args": [
                    {
                        "type": "string",
                        "default": "*nodefault*",
                        "name": "objectName"
                    }
                ]
            }
        ]
    },
    "filters": {
        "rule": [
            {
                "name": "action",
                "help": null,
                "operators": [
                    {
                        "name": "is.allow",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.deny",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.drop",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.negative",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "app",
                "help": null,
                "operators": [
                    {
                        "name": "category.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "characteristic.has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "custom.has.signature",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.from.query",
                        "help": "example: 'filter=(app has.from.query subquery1)' 'subquery1=(object is.application-group)'",
                        "argument": "*required*"
                    },
                    {
                        "name": "has.missing.dependencies",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "has.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.seen.fast-api",
                        "help": "example: 'filter=(app has.seen.fast-api unknown-tcp)'",
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "risk.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "risk.recursive.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "subcategory.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "technology.is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "description",
                "help": null,
                "operators": [
                    {
                        "name": "is.empty",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "description.length",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "dnat",
                "help": null,
                "operators": [
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "dnatdistribution",
                "help": null,
                "operators": [
                    {
                        "name": "is.ip-hash",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.ip-modulo",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.least-sessions",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.round-robin",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.source-ip-hash",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "dnathost",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.partial",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "dnatport",
                "help": null,
                "operators": [
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "dnattype",
                "help": null,
                "operators": [
                    {
                        "name": "is.dynamic",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.static",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "dst",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.from.query",
                        "help": "example: 'filter=(dst has.from.query subquery1)' 'subquery1=(value ip4.includes-full 10.10.0.1)'",
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.fully.included.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.fully.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.negated",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.partially.included.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.partially.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.partially.or.fully.included.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.partially.or.fully.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "dst-interface",
                "help": null,
                "operators": [
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "from",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.same.to.zone",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.in.file",
                        "help": "returns TRUE if rule name matches one of the names found in text file provided in argument",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "from.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "group-tag",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "hit-count.fast",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": "returns TRUE if rule name matches the specified hit count value",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.parent.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches the regular expression specified in argument",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "log",
                "help": null,
                "operators": [
                    {
                        "name": "at.end",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "at.start",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "logprof",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "return true if Log Forwarding Profile is the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": "returns TRUE if rule name matches the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": "returns TRUE if rule name matches one of the names found in text file provided in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": "returns TRUE if rule name matches the regular expression provided in argument",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "natruletype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "supported filter: 'ipv4', 'nat64', 'ptv6'",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "rule",
                "help": null,
                "operators": [
                    {
                        "name": "has.destination.nat",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "has.source.nat",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.bidir.nat",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.disabled",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.dsri",
                        "help": "return TRUE if Disable Server Response Inspection has been enabled",
                        "argument": null
                    },
                    {
                        "name": "is.enabled",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.interzone",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.intrazone",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.postrule",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.prerule",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.universal",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused.fast",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "schedule",
                "help": null,
                "operators": [
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.expired",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "schedule.expire.in.days",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "secprof",
                "help": null,
                "operators": [
                    {
                        "name": "as-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "as-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "av-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "av-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "data-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "data-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "file-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "file-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "group.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.group",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.profile",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "not.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "type.is.group",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "type.is.profile",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "url-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "url-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "vuln-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "vuln-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "wf-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "wf-profile.is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "service",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.from.query",
                        "help": "example: 'filter=(service has.from.query subquery1)' 'subquery1=(value regex 8443)'",
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.value",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.value.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.value.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.application-default",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.tcp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.tcp.only",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.udp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.udp.only",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "no.app-default.ports",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "timeout.is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "service.object.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "service.port.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "service.port.tcp.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "service.port.udp.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "snat",
                "help": null,
                "operators": [
                    {
                        "name": "is.dynamic-ip",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.dynamic-ip-and-port",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.static",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "snathost",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.from.query",
                        "help": "example: 'filter=(snathost has.from.query subquery1)' 'subquery1=(netmask < 32)'",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "snathost.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "snatinterface",
                "help": null,
                "operators": [
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "src",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.from.query",
                        "help": "example: 'filter=(src has.from.query subquery1)' 'subquery1=(value ip4.includes-full 10.10.0.1)'",
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.from.query",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.recursive.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "included-in.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.full.or.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "includes.partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.fully.included.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.fully.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.negated",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.partially.included.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.partially.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.partially.or.fully.included.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.partially.or.fully.included.in.list",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "target",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "timestamp-first-hit.fast",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": "returns TRUE if rule name matches the specified timestamp MM\/DD\/YYYY [american] \/ DD-MM-YYYY [european] \/ 21 September 2021 \/ -90 days",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "timestamp-last-hit.fast",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": "returns TRUE if rule name matches the specified timestamp MM\/DD\/YYYY [american] \/ DD-MM-YYYY [european] \/ 21 September 2021 \/ -90 days",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "timestamp-rule-creation.fast",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": "returns TRUE if rule name matches the specified timestamp MM\/DD\/YYYY [american] \/ DD-MM-YYYY [european] \/ 21 September 2021 \/ -90 days",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "timestamp-rule-modification.fast",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": "returns TRUE if rule name matches the specified timestamp MM\/DD\/YYYY [american] \/ DD-MM-YYYY [european] \/ 21 September 2021 \/ -90 days",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "to",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": "returns TRUE if field TO is using zone mentionned in argument. Ie: \"(to has Untrust)\"",
                        "argument": "*required*"
                    },
                    {
                        "name": "has.only",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.same.from.zone",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.in.file",
                        "help": "returns TRUE if rule name matches one of the names found in text file provided in argument",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "to.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "url.category",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "url.category.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "user",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.any",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.in.file",
                        "help": "returns TRUE if rule name matches one of the names found in text file provided in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.known",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.prelogon",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unknown",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "user.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "uuid",
                "help": null,
                "operators": [
                    {
                        "name": "eq",
                        "help": "returns TRUE if rule uuid matches the one specified in argument",
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "address": [
            {
                "name": "description",
                "help": null,
                "operators": [
                    {
                        "name": "is.empty",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "ip.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": "returns TRUE if object IP value describe multiple IP addresses; e.g. ip-range: 10.0.0.0-10.0.0.255 will match \"ip.count > 200\"",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.parent.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "members.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": "possible variables to bring in as argument: $$value$$ \/ $$ipv4$$ \/ $$ipv6$$ \/ $$value.no-netmask$$ \/ $$netmask$$ \/ $$netmask.blank32$$",
                        "argument": "*required*"
                    },
                    {
                        "name": "same.as.region.predefined",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "netmask",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "has.group.as.member",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.dynamic",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.fqdn",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.group",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.ip-netmask",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.ip-range",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.ip-wildcard",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.ipv4",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.ipv6",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.member.of",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.recursive.member.of",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.region",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused.recursive",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "overriden.at.lower.level",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "overrides.upper.level",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocationcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocationtype",
                "help": null,
                "operators": [
                    {
                        "name": "is.devicegroup",
                        "help": "returns TRUE if object locationtype is Template or TemplateStack",
                        "argument": null
                    },
                    {
                        "name": "is.only.devicegroup",
                        "help": "returns TRUE if object locationtype is Template or TemplateStack",
                        "argument": null
                    },
                    {
                        "name": "is.only.template",
                        "help": "returns TRUE if object locationtype is Template or TemplateStack",
                        "argument": null
                    },
                    {
                        "name": "is.template",
                        "help": "returns TRUE if object locationtype is Template or TemplateStack",
                        "argument": null
                    }
                ]
            },
            {
                "name": "refobjectname",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "returns TRUE if object name matches refobjectname",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": "returns TRUE if RUE if object name matches only refobjectname",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.recursive",
                        "help": "returns TRUE if object name matches refobjectname",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "tag.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "value",
                "help": null,
                "operators": [
                    {
                        "name": "has.wrong.network",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "ip4.included-in",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "ip4.includes-full",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "ip4.includes-full-or-partial",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "ip4.match.exact",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "ip4.match.exact.from.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.included-in.name",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "netmask.blank32",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "string.eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "string.regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "service": [
            {
                "name": "description",
                "help": null,
                "operators": [
                    {
                        "name": "is.empty",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.parent.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "members.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": "possible variables to bring in as argument: $$current.name$$ \/ $$protocol$$ \/ $$destinationport$$ \/ $$soruceport$$ \/ $$timeout$$",
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "has.group.as.member",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "has.srcport",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.group",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.member.of",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.recursive.member.of",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.tcp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.udp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused.recursive",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "overriden.at.lower.level",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "overrides.upper.level",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "port.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "port.tcp.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "port.udp.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocationcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "sourceport.value",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.comma.separated",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.port.range",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.single.port",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "string.eq",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "has.regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "tag.count",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "timeout",
                "help": null,
                "operators": [
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "timeout-halfclose",
                "help": null,
                "operators": [
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "timeout-halfclose.value",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "timeout-timewait",
                "help": null,
                "operators": [
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "timeout-timewait.value",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "timeout.value",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "value",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.comma.separated",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.port.range",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.single.port",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "string.eq",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "value.length",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "tag": [
            {
                "name": "color",
                "help": null,
                "operators": [
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "comments",
                "help": null,
                "operators": [
                    {
                        "name": "is.empty",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.parent.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "zone": [
            {
                "name": "interface",
                "help": null,
                "operators": [
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.parent.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "logprof",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "return true if Log Forwarding Profile is the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "userid",
                "help": null,
                "operators": [
                    {
                        "name": "is.enabled",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "zpp",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": "return true if Zone Protection Profile is the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            }
        ],
        "securityprofile": [
            {
                "name": "alert",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "allow",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "block",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "continue",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "exception",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.parent.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "override",
                "help": null,
                "operators": [
                    {
                        "name": "has",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "securityprofilegroup": [
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.parent.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "secprof",
                "help": null,
                "operators": [
                    {
                        "name": "as-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "as-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "av-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "av-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "data-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "data-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "file-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "file-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "url-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "url-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "vuln-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "vuln-profile.is.set",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "wf-profile.is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "wf-profile.is.set",
                        "help": null,
                        "argument": null
                    }
                ]
            }
        ],
        "device": [
            {
                "name": "devicegroup",
                "help": null,
                "operators": [
                    {
                        "name": "has.vsys",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "with-no-serial",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "manageddevice",
                "help": null,
                "operators": [
                    {
                        "name": "with-no-dg",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "template",
                "help": null,
                "operators": [
                    {
                        "name": "has-multi-vsys",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "templatestack",
                "help": null,
                "operators": [
                    {
                        "name": "has.member",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "interface": [
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "routing": [
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "protocol.bgp",
                "help": null,
                "operators": [
                    {
                        "name": "is.enabled",
                        "help": null,
                        "argument": null
                    }
                ]
            }
        ],
        "virtualwire": [
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ],
        "schedule": [
            {
                "name": "expire.in.days",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "location",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.child.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is child the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "is.parent.of",
                        "help": "returns TRUE if object location (shared\/device-group\/vsys name) matches \/ is parent the one specified in argument",
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "name",
                "help": null,
                "operators": [
                    {
                        "name": "contains",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "eq.nocase",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.in.file",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "regex",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "object",
                "help": null,
                "operators": [
                    {
                        "name": "expire.in.days",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.expired",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.tmp",
                        "help": null,
                        "argument": null
                    },
                    {
                        "name": "is.unused",
                        "help": null,
                        "argument": null
                    }
                ]
            },
            {
                "name": "refcount",
                "help": null,
                "operators": [
                    {
                        "name": ">,<,=,!",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reflocation",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    },
                    {
                        "name": "is.only",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "refstore",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            },
            {
                "name": "reftype",
                "help": null,
                "operators": [
                    {
                        "name": "is",
                        "help": null,
                        "argument": "*required*"
                    }
                ]
            }
        ]
    }
};