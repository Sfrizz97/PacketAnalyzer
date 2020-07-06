class SynFloodAnalyzer:
    
    def __init__(self):
        self.syn_count = 0
        self.ack_count = 0
        self.synack_count = 0
    
    def update_syn(self):
        self.syn_count += 1

    def update_ack(self):
        self.ack_count += 1

    def update_synack(self):
        self.synack_count += 1
    
    def alert(self, port):
        print("syn flood attack on this port: ", port)