import random
from scapy.all import *

def Port_Scanner(ip_target, start_port, end_port):
    for dst_port in range(start_port, end_port):
        src = random.randint((2**10)+1,2**16)
        resp = sr1(
            IP(dst=ip_target)/TCP(sport=src,dport=dst_port,flags="S"),
            timeout=1,
            verbose=0,
        )
    if resp is None:
        print("This port is dropped: ", dst_port)
    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            send_rst = sr(
                IP(dst=ip_target)/TCP(sport=src,dport=dst_port,flags="R"),
                timeout=1,
                verbose=0,
            )
            print("This port is open: ",dst_port)
        elif(esp.getlayer(TCP).flags == 0x14):
            print("This port is closed: ", dst_port)
    elif(resp.haslayer(ICMP)):
        if(
            int(resp.getlayer(ICMP).type) == 3 and
            int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
        ):
            print("This port is dropped: ", dst_port)

def main():
    ip_target = input("Target IP: ")
    start_port = input("Initial target port: ")
    end_port = input("Final target port: ")

    Port_Scanner(str(ip_target), int(start_port), int(end_port))

if __name__ == "__main__":
    main()