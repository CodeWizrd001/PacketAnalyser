import socket
import time

from scapy.all import *

from ..harden import Tables

verboseLevels = {
    0 : 'logFile' ,
    1 : 'stdout' ,
    2 : 'both'
}

class HoneyPot :
    def __init__(self,addr='0.0.0.0') :
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.ReadBuffer = 81920
        self.addr = addr
        self.port = 2000
        created = False 
        while not created :
            try :
                self.sock.bind((addr,self.port))
                created = True
            except :
                self.port += 1
        self.running = True
    def start(self) :
        self.sock.listen(50)
        print(Log("Listening At {}:{}".format(self.addr[0],self.addr[1])))
        while self.running :
            cl , addr = self.sock.accept()
            # print(Log("Accepted connection from {}:{}".format(addr[0],addr[1])))
            self.handle_accepted(cl,addr)
    def handle_accepted(self,cl,addr) :
        """
        Currently handling "parallelism" by multithreading"""
        thread = Thread(target=self.handle_io,args=(cl,addr,))
        thread.start()
    def handle_io(self,cl,addr) :
        """
        Should Be Overridden in child class
        Or Will Funcion as Echo server"""
        client = cl 
        while True :
            try :
                a = client.recv(self.ReadBuffer)
                client.send(a)
                if 'exit' in a.decode() :
                    client.close()
                    break
            except OSError :
                print("OSError {}".format(addr))
                client.close()
                break
            except BaseException as e :
                print("{} cause by {}".format(e,addr))
                break
            finally :
                print("Connection with {} terminated".format(addr))

class Logger :
    def __init__(self,verbose=1) :
        self.verbose = verboseLevels[verbose] 

    def setVerbose(self,level) :
        self.verbose = verboseLevels[level]

    def __call__(self,event) :
        log = f"[{time.ctime()}] {event}"

        if self.verbose in ['logFile','both']:
            logFile.write(log)
        if self.verbose in ['logFile','stdout']:
            print(log)    

class Request :
    udp = 0
    tcp = 0
    icmp = 0 
    other = 0

    def reset(self) :
        self.udp = 0
        self.tcp = 0
        self.icmp = 0
        self.other = 0

    def __sub__(self,x) :
        self.udp -= x 
        self.tcp -= x
        self.other -= x
        self.icmp -= x

        if self.udp < 0 :
            self.udp = 0

        if self.tcp < 0 :
            self.tcp = 0 

        if self.icmp < 0 :
            self.icmp = 0

        if self.other < 0 :
            self.other = 0

        return self

    def __gt__(self,x) :
        if self.tcp > x or self.udp > x or self.icmp > x or self.other > 3*x :
            return True
        else :
            return False

    def __repr__(self) :
        return f'Request(tcp={self.tcp},udp={self.udp},icmp={self.icmp},other={self.other})'

class Counter :
    host = []
    requests = {}
    thread = None

    def __init__(self) :
        self.thread = Thread(target=self.tick)
        self.thread.start()
        self.tables = Tables()

    def tick(self) :
        while True :
            self.checkDOS()
            for ip in self.requests :
                self.requests[ip] -= 50
            time.sleep(1)
        
    def addRequest(self,target,t='other') :
        if target not in self.requests :
            self.requests[target] = Request()

        if t == 'tcp' :
            self.requests[target].tcp += 1
        elif t == 'udp' :
            self.requests[target].udp += 1
        elif t == 'icmp':
            self.requests[target].icmp += 1
        else :
            self.requests[target].other += 1

    def checkDOS(self) :
        for ip in self.requests :
            if self.requests[ip] > 100 :
                src , port = ip.split(':')
                self.tables.replace(src, port, 'eth0')
                self.requests[ip].reset()

    def reset(self) :
        del self.host 
        del self.requests

        self.host = []
        self.requests = {}

def initLog() :
    global logFile 
    logFile = open(f"Logs/Log_{'_'.join((time.ctime().split()[1:]))}",'w')
    Log("Log File Created")

logFile = None 
Log = Logger()
Count = Counter()