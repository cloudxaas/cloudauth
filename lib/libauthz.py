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

import libauthn

from M2Crypto import EVP, EC, util

logger = logging.getLogger("libauthz")

def assert_authz(qstr, authn_cert = None, authz_key = None):

    #token_type=authn_qst&<token>&srvs=foo

    logger.info(qstr)

    tkn_s = qstr.find("&") + 1
    tkn_e = qstr.find("&srvs=")

    ttype = qstr[qstr.find("=") + 1 : tkn_s -1]
 
    token = qstr[tkn_s:tkn_e]

    with open("cnf/ssh_host_ecdsa_key.crt", 'rb') as fh:
        cert = fh.read()

    #TODO get cert from request body and modify verify_authn to use cert
    if (libauthn.verify_authn(ttype + ":" + token, cert) == False):
        return authn

    logger.info("TODO: build and sign authz token")

    return token # TODO    

    """
    authz = authn

    # verify authn token

    if (libauthn.verify_authn(authn, authn_keyfile) == False):
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
    """

def assert_roles(user):
    """
    test function to get user's group info 
    """
    groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
    gid = pwd.getpwnam(user).pw_gid
    groups.append(grp.getgrgid(gid).gr_name)

    return groups
