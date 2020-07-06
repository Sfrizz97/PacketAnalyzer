from scapy.all import *
from portscanning import *
from portscannermanager import *
from synfloodmanager import *
import logging

file_handler = logging.FileHandler(filename='history.log')
stdout_handler = logging.StreamHandler(sys.stdout)
handlers_ = [file_handler]

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=handlers_
)
psm = PSManager(logging)
sfm = SFManager(logging)

def analyzer(pkt):
    logging.info("%s",pkt.summary())
    psm.analyzePkt(pkt)
    sfm.analyzePkt(pkt)

def if_choose():
    ifs = get_if_list()
    for i in range(0,len(ifs)):
        print("Choose " + str(i) + " for this interface: " + str(ifs[i]) + "\n")
    x = input("Your choose: ")
    choose = ifs[int(x)]
    return choose

def main():
    if_ = if_choose()
    print("you have choose to sniff", if_)
    logging.info("Starting capture on this interface: %s",if_)
    capture = sniff(iface=if_,prn = lambda x:analyzer(x))
    #capture.summary()

if __name__ == "__main__":
    main()