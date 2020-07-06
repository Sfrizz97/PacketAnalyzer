class PortScanAnalyzer:

    def __init__(self, port):
        self.cont = 0
        self.ports = []
        self.update_ports(port)

    def update_ports(self, port):
        if port not in self.ports:
            self.ports.append(port)
        self.cont += 1

    def getPortsLen(self):
        return len(self.ports)

    def alert(self, ip):
        print("PortScanning attacck by this ip: ", ip)