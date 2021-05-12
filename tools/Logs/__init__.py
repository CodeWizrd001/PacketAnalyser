verboseLevels = {
    0 : 'logFile' ,
    1 : 'stdout' ,
    2 : 'both'
}

import time

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

def initLog() :
    global logFile 
    logFile = open(f"Logs/Log_{'_'.join((time.ctime().split()[1:]))}",'w')
    Log("Log File Created")

logFile = None 
Log = Logger()