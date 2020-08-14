from scapy.all import *
import socket
import subprocess
import sys
import time
import numpy as np
from tkinter import *
from tkinter import ttk
import tkinter as tk

scan_result = []
t_ultimo_scan = time.time()

def arp_scan(target_ip):

    t_ultimo_scan = time.time()

    print(f'Iniciando escaneo de dispositivos en red {target_ip} por envio de paquetes ARP')
    # Creacion de paquete ARP
    arp = ARP(pdst=target_ip)

    # Creamos el paquete Broadcast, La MAC ff:ff:ff:ff:ff:ff Indica Broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Apilamos los paquetes
    packet = ether/arp

    #Se realiza la peticion
    result = srp(packet, timeout=5, verbose=0)[0]

    # Una lista de dispositivos encontrados en la red
    clients = []

    for sent, received in result:
        # Por cada respuesta recibida, se almacena las direcciones IP y MAC de los dispositivos
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    scan_result = clients

    print("Dispositivos disponibles en la red:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

    return clients

def look_for_attacker(clients):
    attackers = []
    i = 0;
    for client in clients:
        for comparer in clients[i+1:]:
            if client['mac'] == comparer['mac']:
                attackers.append({'ip': comparer['ip'], 'mac': comparer['mac']})
        i = i + 1
    if attackers == []:
        print('No se ha detectado atacantes en el escaneo de IP')
    return attackers

def port_scan(host,i,f):

    hostIP = socket.gethostbyname(host)

    open_ports = []

    try:
        for port in range(i,f):  
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((hostIP, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

    except socket.gaierror:
        print('Hostname could not be resolved. Exiting')
        sys.exit()

    except socket.error:
        print("Couldn't connect to server")
        sys.exit()

    return open_ports

##def tcp_port_scan(host,i,f):
##    listaPuertos = list(range(i,f))
##    puestos = []
##    for puerto in listaPuertos:
##        puertoOrigen = RandShort()
##        paquete = IP(dst = host)/TCP(sport = puertoOrigen, dport = puerto, flags = "S")
##        respuesta = sr1(paquete, timeout = 2)
##        if("NoneType" in str(type(respuesta))):
##            pass
##        elif(respuesta.haslayer(TCP) and respuesta.getlayer(TCP).flags == 0x12):
##            p = IP(dst = host)/TCP(sport = puertoOrigen, dport = puerto, flags = "R")
##            rst = sr(p, timeout = 1)
##            try:
##                servicio = socket.getservbyport(puerto)
##            except:
##                servicio = "¿?"
##            puertos.append({'puerto': puerto, 'servicio': servicio})
##            print("[ABIERTO]",puerto," ->",servicio)
##    return puertos

def main():
    construct_window()    

#sniff_arp_traffic()

if __name__ == "__main__":
    main()
