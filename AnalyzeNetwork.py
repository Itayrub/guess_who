#FIrst version  - guess who 00
from scapy.all import *
from mac_vendor_lookup import MacLookup

class AnalyzeNetwork:

    def __device_info__(self, p):
        mac = self.__get_mac__(p)
        vendor = MacLookup().lookup(mac)
        ip = self.__get_ip__(p)
        ttl = self.__get_ttl__(p)
        
        dev_info = ({"MAC" : mac, "IP" : ip, "VENDOR" : vendor, "TTL" : ttl })
        dev_info["OS"] = self.guess_os(dev_info)
        return dev_info


    def __get_ttl__(self, p):
        if IP in p:
            return p[IP].ttl
        return None
    

    def __get_ip__(self, p):
        if ARP in p:
            return p[ARP].psrc
        if IP in p:
            return p[IP].src
        return None


    def __get_mac__(self, p):
        if Ether in p:
            return p[Ether].src
        
        return None


    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.packets = rdpcap(pcap_path)
        devices = []
        for p in self.packets:
            dev_info = self.__device_info__(p)
            if not dev_info in devices:
                devices.append(dev_info)
        self.devices = devices



    def get_ips(self):
        """
        returns a list of ip addresses (strings) that appear in
        the pcap
        """
        return [dev["MAC"] for dev in self.devices]


    def get_macs(self):
        """returns a list of MAC addresses (strings) that appear in
        the pcap"""
        return [dev["MAC"] for dev in self.devices]


    def get_info_by_mac(self, mac):
        """returns a dict with all information about the device with
        given MAC address"""
        for dev in self.devices:
            if dev["MAC"] == mac:
                return dev
        print(f"MAC : {mac} not found")
        return None


    def get_info_by_ip(self, ip):
        """returns a dict with all information about the device with
        given IP address"""
        for dev in self.devices:
            if dev["IP"] == ip:
                return dev
        print(f"IP : {ip} not found")
        return None

    def guess_os(self, device_info):
        """returns assumed os"""
        ttl = device_info["TTL"]
        if ttl is None:
            return None
        if ttl <= 64:
            return f"Linux/Unix"
        elif ttl <= 128:
            return f"Windows"
        else:
            return f"Cisco/Solaris"


    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        return self.devices


    def __repr__(self):
        return self.__str__()
    
    def __str__(self):
        return self.packets.summary()