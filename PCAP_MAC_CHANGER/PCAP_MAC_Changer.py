from scapy.all import rdpcap,wrpcap
import random

packets = rdpcap(input("Enter filename: "))
MACs = open('maclist.txt').read().splitlines()
macip_list={}
def mac_changer(packets, pktnumber):
    if packets[pktnumbr]["IP"].dst in macip_list:
        random_mac = macip_list[packets[pktnumbr]["IP"].dst]
    else:
        random_mac = random.choice(MACs)
        if random_mac in macip_list.values():
            mac_changer(packets, pktnumbr)
    packets[pktnumbr]["Ether"].dst = random_mac
    macip_list[packets[pktnumbr]["IP"].dst] = random_mac
    if packets[pktnumbr]["IP"].src in macip_list:
        random_mac = macip_list[packets[pktnumbr]["IP"].src]
    else:
        random_mac = random.choice(MACs)
        if random_mac in macip_list.values():
            mac_changer(packets, pktnumbr)
    packets[pktnumbr]["Ether"].src = random_mac
    macip_list[packets[pktnumbr]["IP"].src] = random_mac
for pktnumbr in range(0,len(packets)):
    if packets[pktnumbr]["Ether"].type == 2048:
        mac_changer(packets, pktnumbr)
    else:
        continue
wrpcap("output.pcap", packets)
