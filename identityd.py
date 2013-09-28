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
import grp, pwd

import sock2proc

from M2Crypto import EVP, EC, util

logger = logging.getLogger("identityd")

def assert_roles(user):
    """
    test function to get user's group info 
    """
    groups = [g.gr_name for g in grp.getgrall() if user in g.gr_mem]
    gid = pwd.getpwnam(user).pw_gid
    groups.append(grp.getgrgid(gid).gr_name)

    return groups
