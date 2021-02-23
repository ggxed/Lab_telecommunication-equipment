import base64
import re
from urllib.request import urlopen

from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, IP
import logging
import urllib
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re

jpg_url_list = []
png_url_list = []
gif_url_list = []


def packet_callback(packet):
    if packet[TCP].payload:
        pkt = str(packet[TCP].payload)
        if packet[IP].dport == 80:
            print("\n{} ----HTTP----> {}:{}:\n{}".format(packet[IP].src, packet[IP].dst, packet[IP].dport, str(bytes(packet[TCP].payload))))
            print(str(bytes(packet[Raw])))
            TCPHttpExtract(packet)

def get_data(network_packets):
    decoded_commands = []
    decoded_data = ""
    for packet in network_packets:
        if DNSQR in packet:
            if packet[DNS].id == 0x1337:
                decoded_data = base64.b64decode(str(packet[DNS].an.rdata))
                print(decoded_data.decode('utf-8'))
    return decoded_data


def TCPHttpExtract(packet):
    if packet.haslayer(TCP) and packet.getlayer(TCP).dport == 80 and packet.getlayer(Raw):
        StringJPG = ""
        StringPNG = ""
        StringGIF = ""
    liste = []

    for line in packet.getlayer(Raw):
        liste.append(line)
    StringPacket = re.findall('(\s\/.*?\s)', str(liste))
    StringJPG = re.findall('.*\.jpg', str(StringPacket))
    StringPNG = re.findall('.*\.png', str(StringPacket))
    StringGIF = re.findall('.*\.gif', str(StringPacket))
    if (StringJPG):
        data = socket.gethostbyaddr(packet[IP].dst)
        host = repr(data[0])
        image_url = "http://" + host.replace("'", '') + ''.join(StringJPG).replace("[' ", '')
        #print(get_data(packet))
        print(image_url)
        jpg_url_list.append(image_url)
    if (StringPNG):
        data = socket.gethostbyaddr(packet[IP].dst)
        host = repr(data[0])
        image_url = "http://" + host.replace("'", '') + ''.join(StringPNG).replace("[' ", '')
        print(image_url)
        png_url_list.append(image_url)
    if (StringGIF):
        data = socket.gethostbyaddr(packet[IP].dst)
        host = repr(data[0])
        image_url = "http://" + host.replace("'", '') + ''.join(StringGIF).replace("[' ", '')
        print(image_url)
        gif_url_list.append(image_url)

def download_image():
    i = 0
    for image in jpg_url_list:
        urllib.request.urlretrieve(image, "image/" + i.__str__() + ".jpg")
        i+=1
    for image in png_url_list:
        urllib.request.urlretrieve(image, "image/" + i.__str__() + ".png")
        i+=1
    for image in gif_url_list:
        urllib.request.urlretrieve(image, "image/" + i.__str__() + ".gif")
        i+=1

def capture_int(name_int, file, time):
    packets = sniff(timeout=time, iface=name_int)
    wrpcap(file, packets)

if __name__ == '__main__':
    sniff(timeout=30, filter="tcp", prn=packet_callback ,store=0)
    download_image()

