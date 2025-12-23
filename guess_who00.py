from scapy.all import *
import guess_who.AnalyzeNetwork as an

PCAP_PATH = "pcap-00.pcapng"

analysis = an.AnalyzeNetwork(PCAP_PATH)
print(analysis.get_info())