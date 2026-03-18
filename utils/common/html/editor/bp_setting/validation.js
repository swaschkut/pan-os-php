// validation.js
const BP_VALIDATION = {
    "virus": {
        "rule": {
            "bp": {
                "action": {
                    "type": { "multi": true, "options": ["ftp", "http", "http2", "smb", "any"] },
                    "action": { "multi": true, "options": ["reset-both", "default", "allow", "block"] },
                    "action-not-matching-type": { "multi": true, "options": ["reset-both", "none"] }
                },
                "wildfire-action": {
                    "type": { "multi": true, "options": ["ftp", "http", "http2", "smb", "any"] },
                    "action": { "multi": true, "options": ["reset-both", "default", "allow", "block"] },
                    "action-not-matching-type": { "multi": true, "options": ["reset-both", "none"] }
                },
                "mlav-action": {
                    "type": { "multi": true, "options": ["ftp", "http", "http2", "smb", "any"] },
                    "action": { "multi": true, "options": ["reset-both", "default", "allow", "block"] },
                    "action-not-matching-type": { "multi": true, "options": ["reset-both", "none"] }
                }
            },
            "visibility": {
                "action": { "multi": false, "options": ["!allow"] },
                "wildfire-action": { "multi": false, "options": ["!allow"] },
                "mlav-action": { "multi": false, "options": ["!allow"] },
            }
        },
        "cloud-inline": {
            "bp": {
                "inline-policy-action": {
                    "type": { "multi": true, "options": ["any"] },
                    "action": { "multi": true, "options": ["enable", "disable"] }
                }
            },
            "visibility": {
                "inline-policy-action": {
                    "type": { "multi": false, "options": ["any"] },
                    "action": { "multi": false, "options": ["!disable"] }
                }
            }
        }
    },
    "spyware": {
        "rule": {
            "bp": {
                "severity": { "multi": true, "behavior": "inclusive", "options": ["any", "critical", "high", "medium", "low", "informational"] },
                "action": { "multi": true, "options": ["reset-both", "block-ip", "alert", "allow"] },
                "packet-capture": { "multi": true, "options": ["disable", "single-packet", "extended-capture"] }
            },
            "visibility": {
                "severity": { "multi": true, "behavior": "inclusive", "options": ["any", "critical", "high", "medium", "low", "informational"] },
                "action": { "multi": false, "options": ["!allow"] }
            }
        },
        "dns": {
            "bp": {
                "action": {
                    "type": { "multi": true, "options": ["pan-dns-sec-adtracking", "pan-dns-sec-ddns", "pan-dns-sec-grayware", "pan-dns-sec-malware", "pan-dns-sec-phishing", "pan-dns-sec-proxy", "pan-dns-sec-recent", "pan-dns-sec-cc", "pan-dns-sec-parked"], "allowCustom": true },
                    "action": { "multi": true, "options": ["sinkhole", "alert", "block"] },
                    "packet-capture": { "multi": true, "options": ["disable", "single-packet", "extended-capture"] }
                }
            }
        },
        "advanced-dns": {
            "bp": {
                "action": {
                    "type": { "multi": true, "options": ["pan-adns-sec-dnsmisconfig", "pan-adns-sec-hijacking"], "allowCustom": true },
                    "action": { "multi": true, "options": ["reset-both"] },
                    "log-level": { "multi": false, "options": ["!none"] }
                }
            }
        },
        "lists": {
            "bp": {
                "action": {
                    "type": { "multi": true, "options": ["default-paloalto-dns"], "allowCustom": true },
                    "action": { "multi": true, "options": ["sinkhole"] },
                    "packet-capture": { "multi": false, "options": ["extended-capture"] }
                }
            },
            "visibility": {
                "action": {
                    "type": { "multi": true, "options": ["default-paloalto-dns"], "allowCustom": true },
                    "action": { "multi": false, "options": ["!allow"] }
                }
            }
        },
        "cloud-inline": {
            "bp": {
                "inline-policy-action": {
                    "type": { "multi": true, "options": ["any", "HTTP Command and Control detector", "HTTP2 Command and Control detector"] },
                    "action": { "multi": true, "options": ["reset-both", "enable", "disable"] },
                    "local-deep-learning": { "multi": false, "options": ["enable", "disable"] }
                }
            },
            "visibility": {
                "inline-policy-action": {
                    "type": { "multi": true, "options": ["any", "HTTP Command and Control detector", "HTTP2 Command and Control detector"] },
                    "action": { "multi": false, "options": ["!allow"] },
                    "local-deep-learning": { "multi": false, "options": ["enable"] }
                }
            }
        }
    },
    "vulnerability": {
        "rule": {
            "bp": {
                "severity": { "multi": true, "behavior": "inclusive", "options": ["any", "critical", "high", "medium", "low", "informational"] },
                "action": { "multi": true, "options": ["reset-both", "block-ip", "default"] },
                "packet-capture": { "multi": true, "options": ["disable", "single-packet", "extended-capture"] },
                "category-exclude": { "multi": true, "options": ["brute-force", "app-id-change", "data-theft"] }
            },
            "visibility": {
                "severity": { "multi": true, "behavior": "inclusive", "options": ["any", "critical", "high", "medium", "low", "informational"] },
                "action": { "multi": false, "options": ["!allow"] }
            }
        },
        "cloud-inline": {
            "bp": {
                "inline-policy-action": {
                    "type": { "multi": false, "options": ["any"] },
                    "action": { "multi": false, "options": ["reset-both", "enable", "disable"] }
                }
            },
            "visibility": {
                "inline-policy-action": {
                    "type": { "multi": false, "options": ["any"] },
                    "action": { "multi": false, "options": ["!allow"] }
                }
            }
        }
    },
    "url": {
        "site_access": {
            "bp": {
                "type": { "multi": true, "options": ["command-and-control", "compromised-website", "grayware", "malware", "phishing", "ransomware", "scanning-activity", "dynamic-dns", "hacking", "insufficient-content", "newly-registered-domain", "not-resolved", "parked", "proxy-avoidance-and-anonymizers", "unknown", "abused-drugs", "adult", "copyright-infringement", "extremism", "gambling", "peer-to-peer", "questionable", "weapons"], "allowCustom": true },
                "action": { "multi": false, "options": ["block", "alert", "allow", "continue", "override"] }
            },
            "visibility": { "multi": false, "options": ["!allow"] }
        },
        "user_credential_submission": {
            "bp": {
                "category": {
                    "type": { "multi": true, "options": ["command-and-control", "compromised-website", "grayware", "malware", "phishing", "ransomware", "scanning-activity"], "allowCustom": true },
                    "action": { "multi": false, "options": ["block", "alert", "allow"] }
                },
                "tab": {
                    "mode": { "multi": false, "options": ["disabled", "ip-user", "domain-user"] }
                }
            },
            "visibility": {
                "category": { "multi": false, "options": ["!allow"] },
                "tab": {
                    "mode": { "multi": false, "options": ["!disabled"] }
                }
            }
        }
    },
    "file-blocking": {
        "rule": {
            "bp": {
                "block": {
                    "filetype": { "multi": true, "behavior": "exclusive", "options": ["any", "7z", "bat", "chm", "class", "cpl", "dll", "hlp", "hta", "jar", "ocx", "pif", "scr", "torrent", "vbe", "wsf", "cab", "exe", "flash", "msi", "Multi-Level-Encoding", "PE", "rar", "tar", "encrypted-rar", "encrypted-zip"], "allowCustom": true },
                    "action": { "multi": false, "options": ["block", "alert", "continue"] },
                    "direction": { "multi": false, "options": ["both", "upload", "download"] },
                    "application": { "multi": true, "behavior": "exclusive", "options": ["any"], "allowCustom": true },
                    "all_other_filetypes": { "multi": false, "options": ["alert", "block", "allow"] }
                }
            },
            "visibility": {
                "alert": {
                    "filetype": { "multi": true, "behavior": "exclusive", "options": ["any"], "allowCustom": true },
                    "action": { "multi": false, "options": ["alert"] },
                    "direction": { "multi": false, "options": ["both"] },
                    "application": { "multi": true, "behavior": "exclusive", "options": ["any"], "allowCustom": true  }
                }
            }
        }
    },
    "wildfire": {
        "rule": {
            "bp": {
                "application": { "multi": true, "options": ["any"], "allowCustom": true },
                "filetype": { "multi": true, "options": ["any", "pe", "apk", "pdf", "ms-office"], "allowCustom": true },
                "direction": { "multi": false, "options": ["both", "upload", "download"] },
                "analysis": { "multi": false, "options": ["public-cloud", "private-cloud"] }
            },
            "visibility": {
                "application": { "multi": true, "options": ["any"], "allowCustom": true },
                "filetype": { "multi": true, "options": ["any"], "allowCustom": true },
                "direction": { "multi": false, "options": ["both"] },
                "analysis": { "multi": false, "options": ["public-cloud"] }
            }
        },
        "cloud-inline": {
            "bp": {
                "inline-policy-action": {
                    "application": {"multi": true, "options": ["any"], "allowCustom": true},
                    "type": {"multi": true, "options": ["any", "pe", "apk", "pdf", "ms-office"], "allowCustom": true},
                    "direction": {"multi": false, "options": ["both", "upload", "download"]},
                    "action": {"multi": false, "options": ["block", "allow", "alert"]}
                }
            },
            "visibility": {
                "inline-policy-action": {
                    "application": {"multi": true, "options": ["any"], "allowCustom": true},
                    "type": {"multi": true, "options": ["any"], "allowCustom": true},
                    "direction": {"multi": false, "options": ["both"]},
                    "action": {"multi": false, "options": ["!allow"]}
                }
            }
        }
    }
};