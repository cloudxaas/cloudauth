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
import urllib2

import sock2proc

from M2Crypto import m2, EVP, EC, util, BIO, X509

logger = logging.getLogger("libauthn")

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

def file2buf(fname):
    with open(fname, 'rb') as fh:
         buf = fh.read()
    return buf

def base64url_decode(value) :

    value += "=" * (len(value)%4)

    return base64.urlsafe_b64decode(value)

def time_left(v) :

    start, delta = v.split("~", 1)

    expiry = int(start, 16) + MY_EPOCH + int(delta, 16)
       
    return expiry - time.time()

def hash_n_sign(data, hash_algo, keypem) :

    md = EVP.MessageDigest(hash_algo)

    md.update(data)

    h = md.final()

    bio = BIO.MemoryBuffer(keypem)
    ec = EC.load_key_bio(bio)

    return ec.sign_dsa_asn1(h)

def sig_verify(data, sig, hash_algo, pkey) :

    md = EVP.MessageDigest(hash_algo)
    md.update(data)        
    hash = md.final()
        
    der = pkey.as_der()
    pubk = EC.pub_key_from_der(der)

    return pubk.verify_dsa_asn1(hash, sig)

def verify_authn(authn, certpem):

    logger.info("<%s>", certpem)

    x509 = X509.load_cert_string(certpem)

    logger.info("<%s>", x509.get_subject())

    # TODO verify cert

    pkey = x509.get_pubkey() #EVP.PKEY
 
    return verify_authn_pkey(authn, pkey)

def verify_authn_pkey(authn, pkey):

    if (authn.startswith("authn_qst:")):
    
        authn = authn.lstrip("authn_qst:")
   
        token = authn[0:authn.rfind("&h=")]
     
        attrs = urlparse.parse_qs(authn)
 
        #i: token identifier
        #s: subject app~host~user
        #a: algo
        #k: url to key
        #h: signature

        if (len(attrs["s"][0]) <= 0):
            return False

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

        good = sig_verify(token, attrs["h"][0], "sha1", pkey) 
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

        good = sig_verify(head +"." + body, sign, "sha256", pkey)
        if (good ==1):
            logger.info("verification done")
        else:
            logger.info("verification fail")
            return False 
        
        return True

def assert_authn_jwt(proc, keypem, ctx = SUBJECT_AUTH, validity=300, challenge=None):

    hdr = '{"alg":"es256","x5u":"/cert"}'

    logger.info("authnz header: %s", hdr)

    bdy = '{'

    #uuid is an overkill, hence time-in-microsec and proc.pid seperated by '-'
    #m = "i=" + hex(uuid.uuid4()).lstrip("0x")
    bdy += '"i":"' + hex(int(time.time() * 1000000)).lstrip("0x").rstrip("L") + "~" + hex(int(proc.pid)).lstrip("0x") + '"'
 
    bdy += ',"s":"' + proc.clnt + '"'
    
    bdy += ',"v":"' + str(hex(int(time.time() - MY_EPOCH))).lstrip("0x") + "~" +  hex(validity).lstrip("0x") +'"'

    if (ctx & APP_BIN_AUTH):    
        bdy += ',"b":"'+ proc.binh + '"'

    if (challenge != None):
   	    bdy += ',"r":"' + str(challenge) + '"'

    bdy += "}"

    logger.info("anthnz payload: %s", bdy)

    pkt = base64.urlsafe_b64encode(hdr).rstrip("=") + "." + base64.urlsafe_b64encode(bdy).rstrip("=")

    sig = hash_n_sign(pkt, "sha256", keypem) 
    
    ret = "authn_jwt:" + pkt + "." + base64.urlsafe_b64encode(sig).rstrip("=")

    logger.info(ret)

    return ret

def assert_authn_qst(proc, keypem, ctx = SUBJECT_AUTH, validity=300, challenge=None):

    #uuid is an overkill, hence time-in-microsec and proc.pid seperated by '-'
    #m = "i=" + hex(uuid.uuid4()).lstrip("0x")
    m = "i=" + hex(int(time.time() * 1000000)).lstrip("0x").rstrip("L") + "~" + hex(int(proc.pid)).lstrip("0x")
 
    m += "&s=" + proc.clnt
    
    m += "&v=" + str(hex(int(time.time() - MY_EPOCH))).lstrip("0x") + "~" +  hex(validity).lstrip("0x")

    if (ctx & APP_BIN_AUTH):    
        m += "&b=" + proc.binh

    if (challenge != None):
       	m += "&r=" + str(challenge)

    m += "&a=11"
    m += "&k=%2Fcert"
 
    sig = hash_n_sign(m, "sha1", keypem) 
    
    ret = "authn_qst:" + m + "&h=" + base64.urlsafe_b64encode(sig).rstrip("=")

    logger.info(ret)

    return ret
 
def assert_authn(proc, keypem, qstr, body) :

    attrs = urlparse.parse_qs(qstr)

    try:
        tkn_type = attrs["token_type"][0]
    except KeyError:
        tkn_type = "qst"

    try:
        ctx = attrs["authn_type"][0]
        ctx = int(ctx)
    except KeyError:
        ctx = SUBJECT_AUTH

    try:
        validity = attrs["validity"][0]
        validity = int(validity)
    except KeyError:
        validity = 300 

    try:
        challenge = attrs["challenge"][0]
    except KeyError:
        challenge = None 

    if (tkn_type == "qst"):
        token = assert_authn_qst(proc, keypem, ctx, validity, challenge)
    elif (tkn_type == "jwt"):
        token = assert_authn_jwt(proc, keypem, ctx, validity, challenge)
    else:
        return None

    return token 

def askfor_authz(authn, certpem, idpurl, qstr, body):

    if (authn.startswith("authn_qst:")):
        idpurl += "?token_type=authn_qst"
        idpurl += "&token_val=" + base64.urlsafe_b64encode(authn[len("authn_qst:"):]).rstrip("=")
    elif (authn.startswith("authn_jmt:")):
        idpurl += "?token_type=authn_jmt"
        idpurl += "&token_val=" + authn[len("authn_jmt:"):]
    else:
        logger.info("unsupported authn token %s", authn)
        return authn

    if (qstr != None and qstr != "") :
        idpurl += "&" + qstr # target service added here

    # /roles?token_type=qst&token_val=b64urlsafe&srvs=foo&srvs=bar

    logger.info("idpurl: %s", idpurl)

    req = urllib2.Request(idpurl, certpem)
    req.add_header('Content-Length', '%d' % len(certpem))
    req.add_header('Content-Type', 'application/octet-stream')
    f = urllib2.urlopen(req)

    return f.read()

