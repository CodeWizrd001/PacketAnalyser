from tools.sniff import Sniffer
from tools.utils import Log , initLog

import argparse

def get_interface():
    return arguments.interface

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
parser.add_argument('-v','--verbose',dest='verbose',default=1,help='Specify Verbose Level 0(LogFile)/1(Console)/2(Both)    Default : 1')
arguments = parser.parse_args()

# initLog()

Log.verbose = arguments.verbose

iface = get_interface()

print(f'Got {iface}')

sniffer = Sniffer(interface=iface)
sniffer.run()
