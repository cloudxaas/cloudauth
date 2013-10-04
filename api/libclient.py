#!/usr/bin/python

import os
import sys
import pwd
import uuid
import struct
import socket
import logging
import base64
import tempfile
import time

from socket import socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET

import httplib

logger = logging.getLogger("libclient")

LOCAL_PATH = tempfile.gettempdir() + "/cloudauth.sk"

SO_PASSCRED = 16 # Pulled from /usr/include/asm-generic/socket.h

class UHTTPConnection(httplib.HTTPConnection):

    def __init__(self, path):
        httplib.HTTPConnection.__init__(self, 'localhost')
        self.path = path
 
    def connect(self):
        sock = socket(AF_UNIX, SOCK_STREAM)
        sock.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)
        sock.connect(self.path)
        self.sock = sock

def assert_authnz():

    conn = UHTTPConnection(LOCAL_PATH)

    conn.request("GET", "/authz?ttype=qst&srvs=az&srvs=jz")

    resp = conn.getresponse()

    data = resp.read()

    logger.info("1st: %s %s\n%s", resp.status, resp.reason, data)     

    conn.request("GET", "/authz?ttype=qst&srvs=foo&srvs=bar")

    resp = conn.getresponse()

    data = resp.read()

    logger.info("2nd: %s %s\n%s", resp.status, resp.reason, data)     


# Entrance for stand-alone execution
def main():

    logging.basicConfig(format='%(asctime)s %(levelname)s %(name)s %(message)s', level=logging.INFO) 

    assert_authnz()

if __name__ == "__main__":
    
    main()
