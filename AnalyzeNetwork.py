#FIrst version  - guess who 00
from scapy.all import *
from mac_vendor_lookup import MacLookup

OS_PING_LOADS = {
    "Windows": b"abcdefgh",
    "Linux": b"\x00\x01\x02\x03\x04\x05\x06\x07",
    "Cisco": b"abcdabcd",
    "FreeBSD": b" !\"#$%&'",
    "Solaris": b"\x00\x00\x00\x00\x00\x00\x00\x00"
}
class AnalyzeNetwork:

    def __device_info__(self, p):
        mac = self.__get_mac__(p)
        vendor = MacLookup().lookup(mac)
        ip = self.__get_ip__(p)
        
        dev_info = ({"MAC" : mac, "IP" : ip, "VENDOR" : vendor, "PACKETS" : [p]})
        dev_info["OS"] = self.guess_os(dev_info)
        return dev_info


    def __get_ttl__(self, device):
        for p in device["PACKETS"]:   
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

    def __is_new_device__(self, mac, devices):
        for dev in devices:
            if mac == dev["MAC"]:
                return dev
        return True
    
    def __get_ping_payload__(self, device_info):
        for p in device_info["PACKETS"]:
            if p.haslayer(ICMP) and p[ICMP].type == 8 and p.haslayer(Raw):
                return p[Raw].load
        return b""


    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.packets = rdpcap(pcap_path)
        devices = []
        for p in self.packets:
            dev_info = self.__device_info__(p)
            if self.__is_new_device__(dev_info["MAC"], devices):
                devices.append(dev_info)
            else:
                self.__is_new_device__(dev_info["MAC"], devices)["PACKETS"].append(p)
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
        possible_os = {}
        #by ttl
        ttl = self.__get_ttl__(device_info)
        if not ttl is None:
            if ttl <= 64:
                possible_os["Linux"] = 1
                possible_os["Unix"] = 1
            elif ttl <= 128:
                possible_os["Windows"] = 1
            else:
                possible_os["Cisco"] = 1

        #by payload
        load = self.__get_ping_payload__(device_info)
        for os, fingerprint in OS_PING_LOADS.items():
            if fingerprint in load:
                if not os in possible_os:
                    possible_os[os] = 2
                else:
                    possible_os[os] += 2
        

        possible_os = sorted(possible_os.items(), key=lambda item: item[1], reverse=True)
        max = possible_os[0][1]
        return [guess[0] for guess in possible_os if guess[1] == max]
            


    def get_info(self):
        """returns a list of dicts with information about every
        device in the pcap"""
        ret = []
        keys_to_add = ["MAC" ,"IP", "VENDOR", "OS"]
        for dev in self.devices:
            info_to_add = {}
            for key in keys_to_add:
                info_to_add[key] = dev[key]
            ret.append(info_to_add)
        return ret


    def __repr__(self):
        return self.__str__()
    
    def __str__(self):
        return self.packets.summary()