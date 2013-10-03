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

def assert_authz(qstr, authn_cert, authz_keypem):

    #qstr: token_type=authn_qst&token_val=b64urlsafe&srvs=foo&srvs=bar
    #qstr: token_type=authn_jmt&token_val=jmt-token&srvs=foo&srvs=bar

    logger.info(qstr)

    attrs = urlparse.parse_qs(qstr)

    ttype = attrs["token_type"][0]

    token = attrs["token_val"][0]

    if (ttype == "authn_qst"):
        token = libauthn.base64url_decode(token)

    try:
         services = attrs["srvs"]
    except KeyError:
         services = ["OMNI"]

    if (libauthn.verify_authn(ttype + ":" + token, authn_cert) == False):
        return qstr 

    if (ttype == "authn_qst"):
        return assert_authz_qst(token, services, authn_cert, authz_keypem)
    elif (ttype == "authn_qsb"):
        token = libauthn.qsb2qst(token)
        token = assert_authz_qst(token, services, authn_cert, authz_keypem)
   
        btkns = ""

        tkns = token.split("\r\n")
        for token in tkns :
            if (token == None or len(token.strip()) <= 0): break
            btkns += "authz_qsb:" + libauthn.qst2qsb(token.lstrip("authz_qst:"), "authz") + "\r\n"

        return btkns

    elif (ttype == "authn_jwt"):
        return assert_authz_jwt(token, services, authn_cert, authz_keypem)
    else:
        logger.error("unsupported authn token: %s", qstr)
        return qstr

def assert_authz_jwt(token, services, authn_cert, authz_keypem):

    hdr, bdy, sig = token.split(".", 2)

    hdr = libauthn.base64url_decode(hdr).strip()
    bdy = libauthn.base64url_decode(bdy).strip()

    logger.info("hdr=%s", hdr)
    logger.info("bdy=%s", bdy)

    hdr_obj = json.loads(hdr)
    bdy_obj = json.loads(bdy)

    subject = bdy_obj["s"]
 
    authz_tokens = ""

    for srvs in services :
   
        bd = bdy[:-1] if bdy.endswith('}') else bdy 

        bd += ', "sv":"' + srvs + '"' 
  
        roles = assert_roles(subject, srvs)

        logger.info("roles for %s %s: %s", subject, srvs, roles)
 
        if (len(roles) > 0): 
            bd += ', "rl" : ["' + roles[0] + '"'
 
        for i in range(1, len(roles)):
            bd += ', "' + roles[i] + '"'

        bd += "]}"

        bd = json.loads(bd)
        bd = json.dumps(bd)

        logger.info("body=%s", bd)

        stkn = base64.urlsafe_b64encode(json.dumps(hdr)) + "." + base64.urlsafe_b64encode(bd).rstrip("=")

        sig = libauthn.hash_n_sign(stkn, "sha1", authz_keypem) 

        stkn = "authz_jwt:" + stkn + "." + base64.urlsafe_b64encode(sig).rstrip("=")

        authz_tokens += stkn + "\r\n"        

    logger.info(authz_tokens)

    return authz_tokens 

def assert_authz_qst(token, services, authn_cert, authz_keypem):

    token = token[0:token.find("&h=")] #strip of authn sig

    tkn_attrs = urlparse.parse_qs(token)

    subject = tkn_attrs["s"][0]

    authz_tokens = ""

    for srvs in services :

        stkn = token + "&sv=" + srvs 

        roles = assert_roles(subject, srvs)

        logger.info("roles for %s %s: %s", subject, srvs, roles)
     
        for role in roles:
            stkn += "&rl=" + role

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
