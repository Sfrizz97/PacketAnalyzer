from synflood import *
from scapy.all import *
import logging

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

class SFManager:

    def __init__(self,logging):
        self.elements = {}
        self.treshold = 20
        self.logging = logging

    def analyzePkt(self,pkt):
        if TCP in pkt and pkt[TCP].dport not in self.elements:
            self.elements[pkt[TCP].dport] = SynFloodAnalyzer()
        if TCP in pkt and pkt[TCP].flags & SYN and pkt[TCP].flags & ACK:
           self.elements[pkt[TCP].dport].update_synack()
        elif TCP in pkt and pkt[TCP].flags & SYN:
            self.elements[pkt[TCP].dport].update_syn()
        elif TCP in pkt and pkt[TCP].flags & ACK:
            self.elements[pkt[TCP].dport].update_ack()

        self.checkCondition(pkt[TCP].dport)
    
    def checkCondition(self, port):
        if self.elements[port].syn_count > ((self.elements[port].synack_count + self.elements[port].ack_count)/2)+self.treshold:
            self.elements[port].alert(port)
            self.logging.warning("[s] Syn flood attack on this port: %s",port)