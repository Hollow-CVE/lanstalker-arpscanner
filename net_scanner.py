#!/usr/bin/ python3


"""
Developer: Moiz
Date-Created: 6/11/2026
Version: 1.0
"""




import scapy.all as scapy
import csv
import argparse
import re
import sys
from time import sleep
from os import geteuid
from table import print_devices_table


class scanner:

    def __init__(self) -> None:

        self.arp_info: list = []

    def arp_packet(self, ip_address: str):
        """This function simply creates an ARP packet"""

        packet = scapy.ARP(pdst=ip_address)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        return broadcast / packet

    def request_arp(self, packet) -> list:
        """This function send arp request to the broadcast mac address"""

        answered = scapy.srp(packet, timeout=1, verbose=False)[0]
        return [
            {"ip": rcv.psrc, "mac": rcv.hwsrc, "vendor": None, "count": 1}
            for _, rcv in answered
        ]

    def new_request_arp(self, new_list: list, old_list: list) -> None:
        """This function simply update the previous list and compares it with previous one for count"""

        extracted_mac: dict = {mac["mac"]: mac["count"] for mac in old_list}

        for device in new_list:
            device["count"] = extracted_mac.get(device["mac"], 0) + 1

        self.arp_info = new_list

    def get_input(self) -> str:
        """This function simply gets the ip address as input from the user"""

        parser = argparse.ArgumentParser(
            description="Displays all the online devices on the LAN"
        )


        parser.add_argument("-i", "--ip", help="IP address to scan")
        parser.add_argument("-t", "--timeout", action="store_true", help="Timeout for ARP request")


        arg = parser.parse_args()

        return [arg.ip, arg.timeout]

    def validate_input(self, ip_address) -> bool:
        """This function will check if the regix is correct or not"""

        # this is just a regix to identify an ip address
        regix_code = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
            r"(?:/(?:[0-9]|[12]\d|3[0-2]))?$"
        )

        return bool(regix_code.fullmatch(ip_address))

    def check_input(self, ip: str) -> str:
        """If the user don't enter any ip as an arg then he/she can input within program"""

        try:
            if ip == None:
                ip = str(input("[+] IP ADDRESS: "))

        except KeyboardInterrupt:
            print(f"[*] Exitting the Program")
            sys.exit(1)

        if len(ip) < 1:
            print("[-] Please enter an IP Address or enter Ctrl+c to exit")
            self.check_input(None)

        if not self.validate_input(ip):
            print("[-] Invalid IP address")
            sys.exit(1)

        return ip

    def load_vendors(self) -> dict:
        """Load IEEE OUI prefixes from the system ieee-data package"""
        path = "/usr/share/ieee-data/oui.csv"
        vendors = {}

        try:
            with open(path, newline="", encoding="utf-8") as f:
                for row in csv.DictReader(f):
                    vendors[row["Assignment"].strip().upper()] = row[
                        "Organization Name"
                    ].strip()

        except FileNotFoundError:
            print(f"[-] {path} not found (try: sudo apt install ieee-data)")
        return vendors

    def check_random(self, mac: str) -> bool:
        """Mostly devices using random mac addresses even In I use it too"""
        return bool(int(mac.split(":")[0], 16) & 0x02)

    def assign_mac(self, devices_list: list, vendor: dict) -> None:
        """Assign vendor to devices whose vendor is None"""

        for device in devices_list:
            if device.get("vendor") is not None:
                continue

            # Now we assign mac because currenlty everydevice have None mac
            mac = device["mac"]
            name = vendor.get(mac[:8].replace(":", "").upper())

            if name:
                device["vendor"] = name
            elif self.check_random(mac):
                device["vendor"] = "Randomized MAC (private)"
            else:
                device["vendor"] = "Unknown"
        self.arp_info = devices_list

    def check_root(self) -> None:
        """This program reques root access. So if user doesn't run with sudo it will not work"""

        if geteuid() != 0:
            print("[-] Permission denied")
            sys.exit(1)

    def main(self) -> None:
        """This is the main function that handles the flow of the program"""

        self.check_root()

        ip_address: str = self.check_input(ip=self.get_input())

        packet = self.arp_packet(ip_address=ip_address)
        vendors: dict = self.load_vendors()

        try:
            while True:
                self.new_request_arp(
                    new_list=self.request_arp(packet=packet), old_list=self.arp_info
                )
                self.assign_mac(devices_list=self.arp_info, vendor=vendors)

                print_devices_table(self.arp_info)
                sleep(4)

        except KeyboardInterrupt:
            print("Quiting...")


obj = scanner()
test = obj.get_input()
print(test)