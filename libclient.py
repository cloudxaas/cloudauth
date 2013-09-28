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

from socket import socket, AF_UNIX, SOCK_STREAM, SOL_SOCKET

logger = logging.getLogger("libclient")

LOCAL_PATH = tempfile.gettempdir() + "/cloudauth.sk"

SO_PASSCRED = 16 # Pulled from /usr/include/asm-generic/socket.h

def assert_authnz():

    s = socket(AF_UNIX, SOCK_STREAM)

    s.setsockopt(SOL_SOCKET, SO_PASSCRED, 1)

    s.connect(LOCAL_PATH)

    s.send("GET /authz HTTP/1.0\r\nHost:localhost\r\n\r\n");

    data = s.recv(8192)

    logger.info(data)     

    s.close()

# Entrance for stand-alone execution
def main():

    logging.basicConfig(format='%(asctime)s %(levelname)s %(name)s %(message)s', level=logging.INFO) 

    assert_authnz()

if __name__ == "__main__":
    
    main()
