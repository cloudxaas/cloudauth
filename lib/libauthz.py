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

def assert_authz(qstr, authn_cert, authz_keypem = None):

    #qstr: token_type=authn_qst&<token>&srvs=foo

    logger.info(qstr)

    if (qstr.startswith("token_type=authn_qst") == False):
        logger.error("unsupported authn token: %s", qstr)
        return qstr

    tkn_s = qstr.find("&") + 1
    tkn_e = qstr.find("&srvs=")

    ttype = qstr[qstr.find("=") + 1 : tkn_s -1]
 
    token = qstr[tkn_s:tkn_e]

    if (libauthn.verify_authn(ttype + ":" + token, authn_cert) == False):
        return qstr 

    token = token[0:token.find("&h=")] #strip of authn sig

    tkn_attrs = urlparse.parse_qs(token)

    subject = tkn_attrs["s"][0]

    services = urlparse.parse_qs(qstr[tkn_e + 1 :])["srvs"]

    logger.info("services %s", services)

    authz_tokens = ""

    for i in range(0, len(services)):

        srvs = services[i]

        stkn = token + "&sv=" + srvs 

        roles = assert_roles(subject, srvs)

        logger.info("roles for %s %s: %s", subject, srvs, roles)
     
        for i in range(0, len(roles)):
            stkn += "&role=" + roles[i]

        sig = libauthn.hash_n_sign(stkn, "sha1", authz_keypem) 

        stkn = "authz_qst:" + stkn + "&h=" + base64.urlsafe_b64encode(sig).rstrip("=")

        authz_tokens += stkn + "\r\n"        

    logger.info(authz_tokens)

    return authz_tokens 
    

    """
    #TODO one token for each service
    # get service agnostic roles    

    # get service specific roles       
    for svs in services:
        pass 

    # one token per service for perf


    return authz
    """

def assert_roles(subject, service = None):

    # test function to get user's group info 

    app, host, user = subject.split("~", 2)

    groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
    gid = pwd.getpwnam(user).pw_gid
    groups.append(grp.getgrgid(gid).gr_name)

    return groups
