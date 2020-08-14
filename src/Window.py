from tkinter import *
from tkinter import ttk
import tkinter as tk
from arp_defender import *
import threading
from datetime import datetime as dt, timedelta

class Window():

    network_ip = ''
    scan_table = []
    scan_result = []
    sniffer=False
    advised=False
    under_attack=False
    autoscan=False
    time_last_scan = datetime.now()
    time_next_scan = 0

    def __init__(self):
        self.root = Tk()
        self.root.title("ARP-Defender V0.01")
        self.root.geometry("600x400")
        self.root.iconbitmap('./files/shield-icon.png')

        self.panel_main = PanedWindow(bd=4, bg='green', relief="raised", orient=HORIZONTAL)
        self.panel_main.pack(fill=BOTH, expand=1)

        self.panel_notificacion = PanedWindow(self.panel_main, orient=VERTICAL, bg='green', bd=4, width=460)
        self.panel_main.add(self.panel_notificacion)

        self.panel_monitor = PanedWindow(self.panel_notificacion, orient=VERTICAL, bd=4, height=125)
        self.panel_notificacion.add(self.panel_monitor)

        self.top = Label(self.panel_monitor, text="Panel de notificacion de ataque", font=('Arial',10,'bold'))
        self.panel_monitor.add(self.top)

        self.state_label = Label(self.panel_monitor, text="Iniciando detector de ataques...",font=('Arial',12,'bold'))
        self.panel_monitor.add(self.state_label)

        self.panel_scanner = PanedWindow(self.panel_notificacion, orient=VERTICAL, bd=4)
        self.panel_notificacion.add(self.panel_scanner)

        self.desc = Label(self.panel_scanner, height=11, text="Tabla de dispositivos disponibles en la red", font=('Arial',12,'bold'))
        self.panel_scanner.add(self.desc)

        self.bottom = Label(self.panel_scanner, text="Aquí se anunciará el escaneo de un atacante...")
        self.bottom.place(relx=0.0, rely=1.0, anchor='s')
        self.panel_scanner.add(self.bottom)

        self.panel_accion = PanedWindow(self.panel_main, orient=VERTICAL, bd=4)
        self.panel_main.add(self.panel_accion)

        self.mon_label = Label(self.panel_accion, text="Panel de opciones", font=('Arial',10,'bold'))
        self.panel_accion.add(self.mon_label)

        self.ip_label = Label(self.panel_accion, text="IP de red")
        self.panel_accion.add(self.ip_label)

        self.entrada_ip = Entry(self.panel_accion)
        self.panel_accion.add(self.entrada_ip)

        self.boton_ip = Button(self.panel_accion, text = "Escanear IP", command=self.set_ip)
        self.panel_accion.add(self.boton_ip)
        
##        self.autoscanVar = StringVar()
##        self.combo_autoscan = ttk.Combobox(self.panel_accion,textvariable=self.autoscanVar, state='enabled',values=["No autoscan","10 min", "20 min", "30 min", "1h"], postcommand=self.program_autoscan)
##        self.panel_accion.add(self.combo_autoscan)

##        self.CheckDetector = IntVar()
##        self.detector_cb = Button(self.panel_accion, text = "Detector", variable=self.CheckDetector, onvalue = 1, offvalue = 0)
##        self.panel_accion.add(self.detector_cb)

        self.label = Label(self.panel_accion, text="")
        self.panel_accion.add(self.label)

        self.autoscan()

    def change_bgcolor(self,color):
        self.panel_main['bg'] = color
        self.panel_notificacion['bg'] = color

    def program_autoscan(self):
        self.autoscan = True
        time_last_scan = datetime.now()
        index = self.combo_autoscan.current()
        if index == 0:
            print('Autoscan cancelado.')
            self.autoscan = False
            return; 
        elif index == 1:
            print('Autoescaneo programado a 10 min')
            self.time_next_scan = datetime.now() + timedelta(minutes=1) 
        elif index == 2:
            print('Autoescaneo programado a 20 min')
            self.time_next_scan = datetime.now() + timedelta(minutes=20)
        elif index == 3:
            print('Autoescaneo programado a 30 min')
            self.time_next_scan = datetime.now() + timedelta(minutes=30)
        elif index == 4:
            print('Autoescaneo programado a 1 hora')
            self.time_next_scan = datetime.now() + timedelta(minutes=60)
        else:
            return;
        pass

    def autoscan(self):
        if self.autoscan == True:
            if datetime.now() > self.time_next_scan:
                self.scan_network()
                self.program_autoscan()
            else:
                print('Aun no es tiempo de autoescaneo')

    def initialize(self):
        self.root.mainloop()

    def set_ip(self):
        self.network_ip = self.entrada_ip.get()
        print(f"IP de red: {self.network_ip}")
        self.scan_network()

    def scan_network(self):
        self.clear_table()
        self.scan_result = arp_scan(self.network_ip)
        self.construct_scan_table()

    def clear_table(self):
        total_rows = len(self.scan_table) 
        for i in range(total_rows): 
            for j in range(3):
                e = Entry(self.panel_scanner, width=16, font=('Arial',12))
                e.grid(row=i, column=j)
                e.delete(tk.END)

    def proccess_scan_result(self):
        self.scan_table = []
        attackers = look_for_attacker(self.scan_result)
        attackers_ips = []
        if len(attackers) > 0:
            self.bottom['text'] = 'Se han detectado agentes maliciosos en el escaneo ARP!'
        else:
            self.bottom['text'] = 'El escaneo ARP no ha detectado atacantes.'
        for attacker in attackers:
            attackers_ips.append(attacker['ip'])
        self.scan_table.append({'ip':"Direccion IP", 'mac':"Direccion MAC", 'trust':"Confianza"})
        for host in self.scan_result:
            if host['ip'] in attackers_ips:
                self.scan_table.append({'ip':host['ip'], 'mac':host['mac'], 'trust':'X'})
            else:
                self.scan_table.append({'ip':host['ip'], 'mac':host['mac'], 'trust':'-'})
        print(self.scan_table)
        #scan_table = np.vstack((col_names,np.array(scan_table)))

    def pop_alert(self,mensaje):
        if self.advised == False:
            self.advised = True
            messagebox.showinfo("Ataque de ARP spoofing detectado", mensaje)
            self.alert_attack()
            self.state_label['text'] = mensaje
            self.change_bgcolor('red')

    def normalize(self):
        self.under_attack = False
        self.advised = False
        self.state_label['text'] = 'Nada sospechoso...'
        self.change_bgcolor('green')
##        img = PhotoImage(file="files/good.jpg")
##        self.canvas['image']=img

    def alert_attack(self):
        self.under_attack = True
##        img = PhotoImage(file="files/bad.png")
##        self.canvas['image']=img

    def construct_scan_table(self):
        self.proccess_scan_result()
        table = np.array(self.scan_table)
        total_rows = len(self.scan_table) 
        for i in range(total_rows): 
            for j in range(3):
                e = Entry(self.panel_scanner, width=16, font=('Arial',12))
                e.grid(row=i, column=j)
                col = ''
                if j == 0:
                    col = 'ip'
                elif j == 1:
                    col = 'mac'
                elif j == 2:
                    col = 'trust'
                e.insert(tk.END, table[i][col])

def initialize_sniffer():
    target=sniff_arp_traffic()

class ARP_sniffer:

    under_attack = False
    uninfected_packet_streak = 0

    def __init__(self,window):
        self.window = window
        self.send_sniff_confirmation()
        try:
            self.iface = sys.argv[1]
        except IndexError:
            self.iface = conf.iface

    def send_sniff_confirmation(self):
        self.window.normalize()
    
    def get_mac(self,ip):
        p = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip)
        result = srp(p, timeout=3, verbose=False)[0]
        return result[0][1].hwsrc

    def sniff_arp_traffic(self):
        print('Analizando trafico ARP...')
        sniff(store=False, prn=self.analyze_arp_packet, iface=self.iface)

    def analyze_arp_packet(self,packet):
        
        # Si se recibe un paquete ARP
        if packet.haslayer(ARP):
            # Si es una respuesta ARP
            if packet[ARP].op == 2:
                try:
                    # Obtiene la direccion MAC real del dispositivo
                    real_mac = self.get_mac(packet[ARP].psrc)
                    
                    # Obtiene la direccion MAC recibida en el paquete
                    response_mac = packet[ARP].hwsrc
                    
                    # Si son diferentes, hay un ataque de ARP spoofing
                    if real_mac != response_mac:
                        self.under_attack = True
                        alerta = f"[!] Estas bajo ataque\n IP personificada:{packet[ARP].psrc} \n MAC FALSA: {real_mac.upper()}, \n MAC REAL: {response_mac.upper()}"
                        print(alerta)
                        self.window.pop_alert(alerta)
                    elif self.under_attack == True:
                        if self.uninfected_packet_streak > 10:
                            self.under_attack = False
                            self.window.normalize()
                        else:
                            self.uninfected_packet_streak = self.uninfected_packet_streak +1
                        
                except IndexError:
                    # No se pudo obtener la direccion MAC real
                    # Puede ser una IP falsa o un firewall que bloquea el paquete
                    pass
    

def main():
    w = Window()
    sniffer = ARP_sniffer(w)
    sniff = threading.Thread(target=sniffer.sniff_arp_traffic)
    sniff.start()
    w.initialize()

if __name__ == "__main__":
    main()
