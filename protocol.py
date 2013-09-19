#!/usr/bin/python3

"""

{
    "subject": "app@host#user",
    "bin-ctx": {
        "bin-hash": "exe hex hash",
        "path/to/exe-1": "",
        "path/to/exe-2": ""
    },
    "env-ctx": {
        "bin-dir": "/home/jz/bin",
        "cmd-arg": "spaceseperated",
        "cwd": "/",
        "root": "/",
        "env-list": [
            {
                "name1": "value2"
            },
            {
                "name2": "value2"
            }
        ]
    },
    "app-ctx": [
        {
            "name1": "value2"
        },
        {
            "name2": "value2"
        }
    ],
    "sys-ctx": [
        {
            "name1": "value2"
        },
        {
            "name2": "value2"
        }
    ],
    "proxy-ctx": {
        "app@host#user": {
            "authn_type": "TPM",
            "srvs-list": [
                {
                    "srvs-id": "app@host#user",
                    "srvs-proxy-ctx": {
                        "proxy-ctx": "arbituaryvalue"
                    },
                    "transitive": "false"
                }
            ]
        }
    },
    "sig_salt": "0123456789abcdef",
    "validty": "from-toinseconds",
    "authn_type": "TPM",
    "authn_algo": "sha1-ecc",
    "authn-sig": "b64hash"
}


"""
