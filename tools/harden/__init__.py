'''Hardening Module

Module Designed To Harden The System In Case Of Threat'''

from pyptables import default_tables, restore
from pyptables.rules import Rule, Accept

from ..Logs import Log
from ..utils import HoneyPotServer

from threading import Thread

import sockets 

import json

def getDummyService() :
    honeypot = HoneyPotServer() 
    return honeypot

class Tables :
    def __init__(self) :
        self.commands = []
        self.honeyPotRules = []
        self.honeyPots = []
        return
        configFile = open('netconf.json')
        rules = json.load(configFile) 

    def block(self,proto,ports=None,network=None) :
        rule = {
            'proto' : proto ,
            'jump' : 'DROP' ,
        }
        if ports :
            for port in ports :
                rule['port'] = port
                self.commands.append(self.generateCommand(rule))
        else :
            self.commands.append(self.generateCommand(rule))
        self.write()

    def accept(self,proto,ports=None,network=None) :
        rule = {
            'proto' : proto,
            'jump' : 'ACCEPT' ,
        }
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
        thread = Thread(target=self.restore,args=(600,rule,honeypot,))
        thread.start()
    
    def restore(self,duration,rule,honeypot) :
        time.sleep(duration)
        self.honeyPots.remove(honeypot)
        honeypot.running = False
        self.honeyPotRules.remove(rule)
        rule['action'] = 'rfd' 
        self.commands.append(self.generateCommand(rule))
        self.write()
        
        nRule = {
            'proto' : tcp ,
            'src' : rule['src'] ,
            'jump' : 'DROP',
        }

        self.commands.append(self.generateCommand(rule))
        self.write()

        return

    def generateCommand(self,rule) :
        command = 'iptables '
        args = list(rule.keys())
        args.remove('action')
        try :
            if rule['action'] == 'add' :
                command += '-A INPUT '
            elif rule['action'] == 'delete' :
                command += '-D INPUT '
            elif rule['action'] == 'afd' :
                command += f'-A PREROUTING -t nat '
            elif rule['action'] == 'rfd' :
                command += f'-D PREROUTING -t nat '
        except KeyError :
            command += '-A INPUT '
        for arg in args : 
            if arg == 'iface' :
                command += '-i'
            if arg == 'proto' :
                command += '-p '
            if arg == 'jump' :
                command += '-j '
            if args == 'dport' : 
                command += '--dport '
            if args == 'src' :
                command += -'-s '
            if args == 'from' :
                command += '--dport '
            if args == 'to' :
                command += '--to-port'
            command += rule[arg] + ' '

        return command + '> Logs/commands'