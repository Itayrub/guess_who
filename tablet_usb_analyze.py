from scapy.all import *
from matplotlib import pyplot as plt


load_contrib("usb")
FILE = "tablet.pcap"

def get_data(packets):
    data = []
    for p in packets:
        if p.haslayer(USBpcap):
            if p[USBpcap].endpoint == 129 and p.haslayer(Raw):

                p.show()
        #p.show()
        #print(p.type)
        #raw_data = bytes(p[Raw].load)
        #print("data: " + raw_data.hex())


packets = rdpcap(FILE)
setting = packets[9]
data = []
for p in packets[12:]:
        if p.haslayer(USBpcap):
            if p[USBpcap].endpoint == 129 and p.haslayer(Raw):
                data.append(p[Raw].load[1 : 4])
deltas = [(d[1] - 256 if d[1] > 127 else d[1], d[2] - 256 if d[2] > 127 else d[2], d[0]) for d in data]
points = [(0, 0, 0)] * (len(deltas) + 1)

for i in range(len(deltas)):
    points[i + 1] = (points[i][0] + deltas[i][0], points[i][1] + deltas[i][1], deltas[i][2])
print(points)
x_list = []
y_list = []

for p in points:
    if p[2] == 129:
        x_list.append(p[0])
        y_list.append(-p[1])

plt.scatter(x_list, y_list)
plt.show()


