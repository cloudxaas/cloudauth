#!/usr/bin/python

import os
import sys
import pwd
import uuid 
import struct
import socket
import logging
import base64
import urlparse
import time
import datetime
import json 
import grp, pwd

from libauthn import verify_authn, SIG_KEY_FILE #key will be removed

from M2Crypto import EVP, EC, util

AuZ_KEY_FILE = "./ssh_host_ecdsa_key"

logger = logging.getLogger("identityd")

def assert_authz(authn, *services):

    authz = authn

    # verify authn token

    if (verify_authn(authn, SIG_KEY_FILE) == False):
        return authn

    if (authn.startswith("authn_qst:")):
    
        authn = authn.lstrip("authn_qst:")

        attrs = urlparse.parse_qs(authn)

        app, host, usr = attrs["s"][0].split("~", 2)

        logger.info("%s %s %s", app, host, usr)
    
    # get service agnostic roles    

    # get service specific roles       
    for svs in services:
        pass 

    # one token per service for perf


    return authz

def assert_roles(user):
    """
    test function to get user's group info 
    """
    groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
    gid = pwd.getpwnam(user).pw_gid
    groups.append(grp.getgrgid(gid).gr_name)

    return groups
