from scapy.all import rdpcap,wrpcap
import random

def mac_changer_ipv4(packets, pktnumbr):
    if packets[pktnumbr]["IP"].dst in macip_list:
        random_mac = macip_list[packets[pktnumbr]["IP"].dst]["new"]
    else:
        random_mac = random.choice(MACs)
        while random_mac in new_MACs:
            random_mac = random.choice(MACs)
    macip_list[packets[pktnumbr]["IP"].dst] = {"old":packets[pktnumbr]["Ether"].dst}
    macip_list[packets[pktnumbr]["IP"].dst]["new"] = random_mac
    packets[pktnumbr]["Ether"].dst = random_mac
    new_MACs.append(random_mac)
    if packets[pktnumbr]["IP"].src in macip_list:
        random_mac = macip_list[packets[pktnumbr]["IP"].src]["new"]
    else:
        random_mac = random.choice(MACs)
        while random_mac in new_MACs:
            random_mac = random.choice(MACs)
    macip_list[packets[pktnumbr]["IP"].src] = {"old":packets[pktnumbr]["Ether"].src}
    macip_list[packets[pktnumbr]["IP"].src]["new"] = random_mac
    packets[pktnumbr]["Ether"].src = random_mac
    new_MACs.append(random_mac)
def mac_changer_arp(packets, pktnumbr):
    if packets[pktnumbr]["ARP"].pdst in macip_list:
        random_mac = macip_list[packets[pktnumbr]["ARP"].pdst]["new"]
    else:
        random_mac = random.choice(MACs)
        while random_mac in new_MACs:
            random_mac = random.choice(MACs)
    macip_list[packets[pktnumbr]["ARP"].pdst] = {"old":packets[pktnumbr]["Ether"].dst}
    macip_list[packets[pktnumbr]["ARP"].pdst]["new"] = random_mac
    packets[pktnumbr]["Ether"].dst = packets[pktnumbr]["ARP"].hwdst = random_mac
    new_MACs.append(random_mac)
    if packets[pktnumbr]["ARP"].psrc in macip_list:
        random_mac = macip_list[packets[pktnumbr]["ARP"].psrc]["new"]
    else:
        random_mac = random.choice(MACs)
        while random_mac in new_MACs:
            random_mac = random.choice(MACs)
    macip_list[packets[pktnumbr]["ARP"].psrc] = {"old":packets[pktnumbr]["Ether"].src}
    macip_list[packets[pktnumbr]["ARP"].psrc]["new"] = random_mac
    packets[pktnumbr]["Ether"].src = packets[pktnumbr]["ARP"].hwsrc = random_mac
    new_MACs.append(random_mac)
def mac_changer_ipv6(packets, pktnumbr):
    for mac_list in macip_list.values():
        if packets[pktnumbr]["Ether"].src == mac_list["old"]:
            packets[pktnumbr]["Ether"].src = mac_list["new"]
        elif packets[pktnumbr]["Ether"].dst == mac_list["old"]:
            packets[pktnumbr]["Ether"].dst = mac_list["new"]
def main():
    for pktnumbr in range(0,len(packets)):
        if packets[pktnumbr]["Ether"].type == 2048:
            mac_changer_ipv4(packets, pktnumbr)
        elif packets[pktnumbr]["Ether"].type == 2054:
            mac_changer_arp(packets, pktnumbr)
        else:    
            continue
    for pktnumbr in range(0,len(packets)):
        if packets[pktnumbr]["Ether"].type == 34525:
            mac_changer_ipv6(packets, pktnumbr)
if __name__ == "__main__":
    packets = rdpcap(input("Enter filename: "))
    MACs = open('maclist.txt').read().splitlines()
    macip_list={}
    new_MACs = []
    main()
    wrpcap("output.pcap", packets)
