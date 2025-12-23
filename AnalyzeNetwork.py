from scapy.all import *
from mac_vendor_lookup import MacLookup

class AnalyzeNetwork:

    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.packets = rdpcap(pcap_path)

    def get_ips(self):
        """
        returns a list of ip addresses (strings) that appear in
        the pcap
        """
        ips = []
        for p in self.packets:
            ip = p[ARP].psrc 
            if not ip in ips:
                ips.append(ip)
        return ips


    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        macs = []
        for p in self.packets:
            mac = p[Ether].src
            if not mac in macs:
                macs.append(mac)
        return macs


    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        return {mac : MacLookup().lookup(mac)}


    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        return None


    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        devices = []
        macs = self.get_macs()
        for p in self.packets:
            mac = p[Ether].src
            if mac in macs:
                macs.remove(mac)
                vendor = self.get_info_by_mac(mac)[mac]
                devices.append({"MAC" : mac, "IP" : p[ARP].psrc, "VENDOR" : vendor })
        return devices


    def __repr__(self):
        return self.__str__()
    
    def __str__(self):
        return self.packets.summery()