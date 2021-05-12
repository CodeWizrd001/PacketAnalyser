'''Hardening Module

Module Designed To Harden The System In Case Of Threat'''

from pyptables import default_tables, restore
from pyptables.rules import Rule, Accept

from ..Logs import Log

from threading import Thread

import socket

import json
import time

import os

def getDummyService() :
    honeypot = HoneyPot()
    return honeypot

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
                pass
                # print("Connection with {} terminated".format(addr))

class Tables :
    def __init__(self) :
        self.commands = []
        self.honeyPotRules = []
        self.honeyPots = []
        self.blocked = []
        return
        configFile = open('netconf.json')
        rules = json.load(configFile) 

    def block(self,proto = None,ip=None,ports=None,network=None) :
        rule = {
            'jump' : 'DROP' ,
        }

        if proto :
            rule['proto'] = proto

        if ip :
            if ip in self.blocked :
                return 
            rule['src'] = ip
            self.blocked.append(ip)

        if ports :
            for port in ports :
                rule['port'] = port
                self.commands.append(self.generateCommand(rule))
        else :
            self.commands.append(self.generateCommand(rule))
        self.write()

    def accept(self,proto=None,ip=None,ports=None,network=None) :
        rule = {
            'jump' : 'ACCEPT' ,
        }

        if proto :
            rule['proto'] = proto

        if ip :
            rule['src'] = ip
            
        if ports :
            for port in ports :
                rule['port'] = port
                self.commands.append(self.generateCommand(rule))
        else :
            self.commands.append(self.generateCommand(rule))
        self.write()
    
    def write(self) :
        for command in self.commands :
            code = os.system(command)
            print(f'[+] Executed  -> {command}')
        self.commands = []

    def replace(self,src,port,iface) :
        honeypot = getDummyService()
        rule = {
            'proto' : 'tcp' ,
            'action' : 'afd',
            'src' : src ,
            'iface' : iface ,
            'from' : port ,
            'jump' : 'REDIRECT' ,
            'to' : honeypot.port ,
        }
        self.honeyPotRules.append(rule) 
        self.honeyPots.append(honeypot)
        self.commands.append(self.generateCommand(rule))
        self.write()

        thread = Thread(target=honeypot.start) 
        thread.start()
        thread = Thread(target=self.restore,args=(20,rule,honeypot,))
        thread.start()
    
    def restore(self,duration,rule,honeypot) :
        time.sleep(duration)
        self.honeyPots.remove(honeypot)
        honeypot.running = False
        self.honeyPotRules.remove(rule)
        rule['action'] = 'rfd' 
        self.commands.append(self.generateCommand(rule))
        self.write()
        
        # nRule = {
        #     'src' : rule['src'] ,
        #     'jump' : 'DROP',
        # }
        #
        # self.commands.append(self.generateCommand(nRule))
        # self.write()

        self.block(ip=rule['src'])

        return

    def generateCommand(self,rule) :
        command = 'iptables '
        args = list(rule.keys())
        try :
            if rule['action'] == 'add' :
                command += '-A FORWARD '
            elif rule['action'] == 'delete' :
                command += '-D FORWARD '
            elif rule['action'] == 'afd' :
                command += f'-A PREROUTING -t nat '
            elif rule['action'] == 'rfd' :
                command += f'-D PREROUTING -t nat '
            args.remove('action')
        except KeyError :
            command += '-A FORWARD '
        for arg in args : 
            if arg == 'iface' :
                command += '-i '
            if arg == 'proto' :
                command += '-p '
            if arg == 'jump' :
                command += '-j '
            if arg == 'dport' : 
                command += '--dport '
            if arg == 'src' :
                command += '-s '
            if arg == 'from' :
                command += '--dport '
            if arg == 'to' :
                command += '--to-port '
            command += str(rule[arg]) + ' '

        return command # + '> Logs/commands'