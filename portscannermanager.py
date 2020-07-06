from portscanning import *
from scapy.all import *
import logging

class PSManager:

    def __init__(self,logging):
        self.elements = {}
        self.treshold = 5
        self.logging = logging

    def analyzePkt(self,pkt):
        src = dst_p = ""
        if IP in pkt:
            src = pkt[IP].src
        if TCP in pkt:
            dst_p = pkt[TCP].dport
        elif UDP in pkt:
            dst_p = pkt[UDP].dport

        if src in self.elements:
            self.elements[src].update_ports(dst_p)
        else:
            self.elements[src] = PortScanAnalyzer(dst_p)

        self.check_condition(src)

    def check_condition(self,ip):
        if self.elements[ip].getPortsLen() > self.treshold:
            self.elements[ip].alert(ip)
            self.logging.warning("[p] Port Scanning from this IP: %s",ip)