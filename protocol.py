#!/usr/bin/python

import os
import sys
import pwd
import uuid 
import struct
import socket
import logging
import base64

import sock2proc

from M2Crypto import EVP, EC, util

logger = logging.getLogger("protocol")


def proc_sign(proc):

    m = "uuid=" + str(uuid.uuid4())
 
    m += "&subject=" + proc.clnt
        
    m += "&procbin=" + proc.binh
 
    md = EVP.MessageDigest('sha1')
    md.update(m)        
   
    h = md.final()
   
    ec = EC.load_key("./ssh_host_ecdsa_key")

    sig = ec.sign_dsa_asn1(h)

    good = ec.verify_dsa_asn1(h, sig)
    if (good ==1):
        logger.info("verified: %s", len(sig))

    s64 = base64.urlsafe_b64encode(sig)

    logger.info(s64)
 
