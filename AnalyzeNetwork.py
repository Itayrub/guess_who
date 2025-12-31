from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
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
        dev_info = ({"MAC" : mac, "IP" : ip, "VENDOR" : vendor, "PACKETS" : [p], "APP" : None, "SERVICE" : None, "ROLE" : None})
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
        return None


    def __get_ping_payload__(self, device_info):
        for p in device_info["PACKETS"]:
            if p.haslayer(ICMP) and p[ICMP].type == 8 and p.haslayer(Raw):
                return p[Raw].load
        return b""


    def __get_app__(self, p):
        if not p.haslayer(HTTPRequest):
            return None
            
        ua_bytes = p[HTTPRequest].User_Agent
        if not ua_bytes:
            return None

        ua_string = ua_bytes.decode(errors='ignore')
        noise = {'mozilla', 'applewebkit', 'safari', 'gecko', 'khtml', 'mobile'}

        labels = ua_string.split(" ")
        candidate_apps = []

        for label in labels:
            clean_label = label.strip("(),;")
            if "/" in clean_label:
                name = clean_label.split("/")[0].lower()
                if name not in noise:
                    candidate_apps.append(clean_label)

        if candidate_apps:
            return candidate_apps[0]
        
        return labels[-1].strip("(),;") if labels else None


    def __get_service__(self, p):
        if not p.haslayer(HTTP) or p.haslayer(HTTPRequest):
            return None
        
        server_bytes = p[HTTP].Server
        if not server_bytes:
            return None

        server_string = server_bytes.decode()
        labels = server_string.split(" ")
        
        if labels:
            return labels[0].strip("(),;")

        return None
    
    def __find_apps__(self):
        for dev in self.devices:
            for p in dev["PACKETS"]:
                app = self.__get_app__(p)
                if app is not None:
                    dev["SERVICE"] = app
                    dev["ROLE"] = "server"
                    break
    

    def __find_services__(self):
        for dev in self.devices:
            for p in dev["PACKETS"]:
                service = self.__get_service__(p)
                if service is not None:
                    dev["SERVICE"] = service
                    dev["ROLE"] = "server"
                    break


    def __device_info__(self, p):
        mac = self.__get_mac__(p)
        vendor = MacLookup().lookup(mac)
        ip = self.__get_ip__(p)
        dev_info = ({"MAC" : mac, "IP" : ip, "VENDOR" : vendor, "PACKETS" : [p], "APP" : None, "SERVICE" : None, "ROLE" : None})
        dev_info["OS"] = self.guess_os(dev_info)
        return dev_info
    
    def __init__(self, pcap_path):
        """
        pcap_path (string): path to a pcap file
        """
        self.packets = rdpcap(pcap_path)
        devices = []
        for p in self.packets:
            dev_info = self.__device_info__(p)
            mac = dev_info["MAC"]

            dev_found = self.__is_new_device__(mac, devices)
            if dev_found is None:
                devices.append(dev_info)
            else:
                dev_found["PACKETS"].append(dev_info["PACKETS"][0])
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
        self.__find_apps__()
        self.__find_services__()
        ret = []
        keys_to_add = ["MAC" ,"IP", "VENDOR", "OS", "APP", "SERVICE", "ROLE"]
        for dev in self.devices:
            print(len(dev["PACKETS"]))
            info_to_add = {}
            for key in keys_to_add:
                info_to_add[key] = dev[key]
            ret.append(info_to_add)
        return ret


    def __repr__(self):
        return self.__str__()
    
    def __str__(self):
        return self.packets.summary()