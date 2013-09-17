#!/usr/bin/python3

import os
import sys
import pwd
import struct
import socket
import hashlib
import logging

logger = logging.getLogger("sock2proc")

class ProcInfo(object):
    
    sock = -1 # used to find proc info vi proc/etc/net
    
    pid = -1
    euid = -1
    user = ""
    cmd = ""
    arg = [] 
    env = {} 
    clnt = ""
    binh = ""
    bindir = ""   

    # Either sock (local tcp) or pid/euid (unix stream) must be present
    def __init__(self, sock = -1, pid = -1, euid = -1):
        self.sock = sock
        self.pid = pid
        self.euid = euid
        
            
    def proc_info(self):

        # Either pid or sock must be available

        if (self.pid == -1):
            if (self.sock ==""):
                return False       
            else:
                inode, self.euid = ProcInfo.find_inode(self.sock)
                if (inode == -1):
                    return False

                self.pid = ProcInfo.find_pid(inode)
                if (self.pid == -1):
                    return False
               
        self.user = pwd.getpwuid(int(self.euid))[0];
        logger.info("user = %s", self.user)

        fname = open("/proc/" + self.pid + "/cmdline", "r")
        self.cmd = fname.readline()
        self.cmd = self.cmd.strip()
        fname.close()

        if (len(self.cmd) > 0):
             argv = self.cmd.split("\0")
             self.cmd = argv[0] 
             for i in range(1, len(argv)):
                 arg = argv[i].strip()
                 if (len(arg) > 0):
                     self.arg.append(arg)
       
        #Special case where args part of command
        #TODO bug if space in filename (escaping handling)
        idx = self.cmd.find(" ")
        if (idx > 0):
            self.cmd = self.cmd[:idx].strip()
            self.arg += self.cmd[(idx + 1):].split(" ")
             
        logger.info("clnt exe: %s", self.cmd)
        logger.info("clnt arg: %s", self.arg)

        self.bindir, self.cmd = os.path.split(self.cmd)
              
        logger.info("clnt bin dir: %s", self.bindir)

        self.clnt = self.cmd + "@" + socket.getfqdn() + "#" + self.user
        logger.info("clnt id: %s", self.clnt) 

        self.binh = ProcInfo.hash_file("/proc/" + self.pid + "/exe")
 
        logger.info("clnt exe hash: %s",self.binh) 

        fname = open("/proc/" + self.pid + "/environ", "r")
        envlist = fname.readline()
        fname.close()

        envlist = envlist.split("\0")

        for i in range(0, len(envlist)) :
             nv = envlist[i].split("=", 2)
             if (len(nv[0]) == 0):
                 break
             self.env[nv[0].strip()] = nv[1].strip()
    
        logger.info("clnt env: %s", self.env)
             
        return True

    # Find the inode of a local sock address    
    @staticmethod
    def find_inode(sock):
        
        inode = -1
        euid = -1;
        
        fname = open("/proc/net/tcp", "r")
        fname.readline() # discard the 1st line
        while (True):
            line = fname.readline();
            if not line:
                break
            items = line.split()
            if (items[1].find(sock.upper()) != -1) :
                euid = items[7]
                inode = items[9]
                break
            
        fname.close()
        
        logger.info("euid = %s", euid)
        
        if (euid == -1):
            return -1, -1 
    

        return int(inode), euid
    
    # Find the pid given its inode
    @staticmethod
    def find_pid(inode):
            
        files = os.listdir("/proc/")
    
        files.remove(str(os.getpid()))
    
        pids = []
    
        for f in files:
            try:
                integer = int(f)
                pids.append(str(integer))
            except ValueError:
                # don't care if not a pid
                pass
    
        for pid in pids:
            fds = os.listdir("/proc/%s/fd/" % pid)
            for fd in fds:
                if ('socket:[%d]' % inode) == os.readlink("/proc/%s/fd/%s" % (pid, fd)):
                    return pid
        return -1
 
    @staticmethod 
    def hash_file(file):

        hash = ""

        with open(file, 'rb') as fh:
            m = hashlib.sha1()
            while True:
                data = fh.read(8192)
                if not data:
                    break
                m.update(data)
            hash = m.hexdigest()

        return hash 
 
    @staticmethod
    def ip_to_nl(ip):
        t = socket.inet_aton(ip)
        return struct.unpack("I", t)[0]

    @staticmethod
    def sock2proc(client_address):

        logger.info ("client sock: %s", client_address);

        host, port = client_address

        clnt = hex(ProcInfo.ip_to_nl(host)).lstrip('0x') + ":" + hex(int(port)).lstrip('0x')

        proc = ProcInfo(sock = clnt)

        proc.proc_info()

        return proc

    @staticmethod
    def pipe2proc(pid, euid):

        logger.info ("client pid: %s, euid: %s", pid, euid);

        proc = ProcInfo(pid = pid, euid = euid)

        proc.proc_info()

        return proc

 
# Entrance for stand-alone execution
def main():

    logging.basicConfig(format='%(asctime)s %(levelname)s %(name)s %(message)s', level=logging.INFO) 

    proc = ProcInfo.pipe2proc(sys.argv[1], sys.argv[2])  

if __name__ == "__main__":
    
    main()
    
