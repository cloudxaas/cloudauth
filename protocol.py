#!/usr/bin/python

import os
import sys
import pwd
import uuid 
import struct
import socket
import logging
import base64
import time
import datetime
import json 
import urlparse

import sock2proc

from M2Crypto import EVP, EC, util

logger = logging.getLogger("protocol")

#sub-levels using . (dot), e.g. e.PATH for path env variable
#v: issue time in sec in hex (since MY_EPOCH) | duration in sec in hex
#i: locally pseudo-unique identifier 
#r: server challenge
#a: algo, algo identifier: XY, here X is the signing algo, Y is the hashing algo 
#         00-HMAC, 11 - ecdsa-sha1, 12 - ecdsa-sha256, 21 - dsa-sha1, 31 - rsa-sha1
#k: url to pub key
SUBJECT_AUTH   = 0x0001 #s
APP_BIN_AUTH   = 0x0002 #b
CMDLINE_AUTH   = 0x0004 #c
ENVVARS_AUTH   = 0x0008 #e
APP_CTX_AUTH   = 0x0010 #ac
SYS_CTX_AUTH   = 0x0020 #sc
PXY_CTX_AUTH   = 0x0040 #pc
AUTHCTX_AUTH   = 0x0080 #an
ROLEATT_AUTH   = 0x0100 #az

MY_EPOCH = time.mktime(datetime.datetime(2013,1,1,0,0).timetuple())

def base64url_decode(value) :

    if (len(value) % 3 != 0) :
        value += "=" * (3 - len(value) % 3)  # add pading if needed

    return base64.urlsafe_b64decode(value)

def time_left(v) :

    start, delta = v.split("~", 1)

    expiry = int(start, 16) + MY_EPOCH + int(delta, 16)
       
    return expiry - time.time()

def verify_authn(authn, keyfile):

    if (authn.startswith("authn_qst:")):
    
        authn = authn.lstrip("authn_qst:")
   
        token = authn[0:authn.rfind("&h=")]
     
        attrs = urlparse.parse_qs(authn)
 
        #i: token identifier
        #s: subject app~host~user
        #a: algo
        #k: url to key
        #h: signature

        attrs["h"][0] = base64url_decode(attrs["h"][0])

        #TODO check revocation based token identifier
            
        #TODO check revocation based on signing cert

        #Check token expiration

        if (time_left(attrs["v"][0]) <= 0):
            logger.info("token %s expired", attrs["i"][0])
            return False
         
        logger.info("token %s not expired", attrs["i"][0])

        #TODO check other algo
        if (attrs["a"][0] != "11"):
            logger.info("verification fail: unsupported algo %s", attrs["a"][0])
            return False

        md = EVP.MessageDigest('sha1')
        md.update(token)        
        token = md.final()
   
        ec = EC.load_key(keyfile)
        
        good = ec.verify_dsa_asn1(token, attrs["h"][0])
        if (good ==1):
            logger.info("verification done: %s", attrs["s"][0])
            return True
        else:
            logger.info("verification fail: %s", attrs["s"][0])
            return False 
             
    elif (authn.startswith("authn_jwt:")):
        
        authn = authn.lstrip("authn_jwt:")

        head, body, sign = authn.split(".", 2)

        sign = base64url_decode(sign)

        hdr = base64url_decode(head)
        bdy = base64url_decode(body)

        hdr = json.loads(hdr)
        bdy = json.loads(bdy)
 
        logger.info("jwt head: %s", hdr)
        logger.info("jwt body: %s", bdy)
   
        #Check token expiration

        if (time_left(bdy["v"]) <= 0):
            logger.info("token %s expired", bdy["i"])
            return False
         
        logger.info("token %s not expired", bdy["i"])

        #TODO check other algo
        if (hdr["alg"] != "es256"):
            logger.info("verification fail: unsupported algo %s", hdr["alg"])
            return False

        ec = EC.load_key(keyfile)

        md = EVP.MessageDigest('sha256')
        md.update(head +"." + body)

        good = ec.verify_dsa_asn1(md.final(), sign)
        if (good ==1):
            logger.info("verification done")
        else:
            logger.info("verification fail")
            return False 
        
        return True

def assert_authz(authn, *services):

    authz = authn

    # verify authn token

    verify_authn(authn)

    # get service agnostic roles    

    # get service specific roles       
    for svs in services:
        pass 

    # one token per service for perf

    return authz


def assert_authn_jwt(proc, keyfile, fmt = SUBJECT_AUTH, validity=300, challenge=None):

    hdr = '{"alg":"es256","x5u":""}'

    logger.info("authnz header: %s", hdr)

    bdy = '{'

    #uuid is an overkill, hence time-in-microsec and proc.pid seperated by '-'
    #m = "i=" + hex(uuid.uuid4()).lstrip("0x")
    bdy += '"i":"' + hex(int(time.time() * 1000000)).lstrip("0x").rstrip("L") + "~" + hex(int(proc.pid)).lstrip("0x") + '"'
 
    bdy += ',"s":"' + proc.clnt + '"'
    
    bdy += ',"v":"' + str(hex(int(time.time() - MY_EPOCH))).lstrip("0x") + "~" +  hex(validity).lstrip("0x") +'"'

    if (fmt & APP_BIN_AUTH):    
        bdy += ',"b":"'+ proc.binh + '"'

    if (challenge != None):
   	    bdy += ',"r":"' + str(challenge) + '"'

    bdy += "}"

    logger.info("anthnz payload: %s", bdy)

    md = EVP.MessageDigest('sha256')

    pkt = base64.urlsafe_b64encode(hdr).rstrip("=") + "." + base64.urlsafe_b64encode(bdy).rstrip("=")

    md.update(pkt)

    h = md.final()
   
    ec = EC.load_key(keyfile)

    sig = ec.sign_dsa_asn1(h)
    
    """
    good = ec.verify_dsa_asn1(h, sig)
    if (good ==1):
        logger.info("verified: %s", len(sig))
    """

    ret = "authn_jwt:" + pkt + "." + base64.urlsafe_b64encode(sig).rstrip("=")

    logger.info(ret)

    return ret

def assert_authn_qst(proc, keyfile, fmt = SUBJECT_AUTH, validity=300, challenge=None):

    #uuid is an overkill, hence time-in-microsec and proc.pid seperated by '-'
    #m = "i=" + hex(uuid.uuid4()).lstrip("0x")
    m = "i=" + hex(int(time.time() * 1000000)).lstrip("0x").rstrip("L") + "~" + hex(int(proc.pid)).lstrip("0x")
 
    m += "&s=" + proc.clnt
    
    m += "&v=" + str(hex(int(time.time() - MY_EPOCH))).lstrip("0x") + "~" +  hex(validity).lstrip("0x")

    if (fmt & APP_BIN_AUTH):    
        m += "&b=" + proc.binh

    if (challenge != None):
       	m += "&r=" + str(challenge)

    m += "&a=11"
    m += "&k=url"
     
    md = EVP.MessageDigest('sha1')
    md.update(m)        
   
    h = md.final()
   
    ec = EC.load_key(keyfile)

    sig = ec.sign_dsa_asn1(h)
    
    """
    good = ec.verify_dsa_asn1(h, sig)
    if (good ==1):
        logger.info("verified: %s", len(sig))
    """

    ret = "authn_qst:" + m + "&h=" + base64.urlsafe_b64encode(sig).rstrip("=")

    logger.info(ret)

    return ret
 
def assert_authn(proc, keyfile, fmt = SUBJECT_AUTH, validity=300, challenge=None):

    token = assert_authn_qst(proc, keyfile, fmt, validity, challenge)

    verify_authn(token, keyfile) #TODO: remove

    return token 
    
