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

import sock2proc

from M2Crypto import EVP, EC, util

logger = logging.getLogger("protocol")

#sub-levels using . (dot), e.g. e.PATH for path env variable
#v: valid until (seconds since 2013/1/1 0:0:0)

SUBJECT_AUTH   = 0x0001 #s
APP_BIN_AUTH   = 0x0002 #b
CMDLINE_AUTH   = 0x0004 #c
ENVVARS_AUTH   = 0x0008 #e
APP_CTX_AUTH   = 0x0010 #ac
SYS_CTX_AUTH   = 0x0020 #sc
PXY_CTX_AUTH   = 0x0040 #pe
AUTHCTX_AUTH   = 0x0080 #an
ROLEATT_AUTH   = 0x0100 #az

MY_EPOCH = time.mktime(datetime.datetime(2013,1,1,0,0).timetuple())

def assert_authnz(proc, fmt = SUBJECT_AUTH, validity=300):

    m = ""
 
    m += "s=" + proc.clnt
    
    m += "&v=" + str(hex(int(time.time() - MY_EPOCH + validity))) 

    if (fmt & APP_BIN_AUTH):    
        m += "&b=" + proc.binh
 
    md = EVP.MessageDigest('sha1')
    md.update(m)        
   
    h = md.final()
   
    ec = EC.load_key("./ssh_host_ecdsa_key")

    sig = ec.sign_dsa_asn1(h)
    
    """
    good = ec.verify_dsa_asn1(h, sig)
    if (good ==1):
        logger.info("verified: %s", len(sig))
    """

    ret = m + "&h=" + base64.urlsafe_b64encode(sig)

    logger.info(ret)

    return ret
 
