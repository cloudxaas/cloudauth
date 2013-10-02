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

    #qstr: token_type=qst&token_val=b64urlsafe&srvs=foo&srvs=bar
    #qstr: token_type=jmt&token_val=jmt-token&srvs=foo&srvs=bar

    logger.info(qstr)

    attrs = urlparse.parse_qs(qstr)

    #base64url_decode

    ttype = attrs["token_type"][0]

    if (ttype != "authn_qst"):
        logger.error("unsupported authn token: %s", qstr)
        return qstr

    token = attrs["token_val"][0]

    token = libauthn.base64url_decode(token)

    try:
         services = attrs["srvs"]
    except KeyError:
         services = ["OMNI"]

    if (libauthn.verify_authn(ttype + ":" + token, authn_cert) == False):
        return qstr 

    token = token[0:token.find("&h=")] #strip of authn sig

    tkn_attrs = urlparse.parse_qs(token)

    subject = tkn_attrs["s"][0]

    authz_tokens = ""

    for srvs in services :

        stkn = token + "&sv=" + srvs 

        roles = assert_roles(subject, srvs)

        logger.info("roles for %s %s: %s", subject, srvs, roles)
     
        for role in roles:
            stkn += "&role=" + role

        sig = libauthn.hash_n_sign(stkn, "sha1", authz_keypem) 

        stkn = "authz_qst:" + stkn + "&h=" + base64.urlsafe_b64encode(sig).rstrip("=")

        authz_tokens += stkn + "\r\n"        

    logger.info(authz_tokens)

    return authz_tokens 

def assert_roles(subject, service = None):

    # test function to get user's group info 

    app, host, user = subject.split("~", 2)

    groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
    gid = pwd.getpwnam(user).pw_gid
    groups.append(grp.getgrgid(gid).gr_name)

    return groups
