# ARP-defender V0.01 (BETA)

ARP-Defender es un sistema de software detector de ataques de ARP spoofing que sean dirigidos hacia tu equipo, esto lo hace analizando el tráfico ARP proveniente al equipo en busca de paquetes maliciosos. ARP-Defender también cuenta con un scanner ARP que permite identificar los dispositivos conectados a la red y enlazarlos con su dirección IP asignada.

Para utilizar el detector de ataques, solo debe correrse el archivo src/Window.py desde la consola de python3, este automaticamente empezará a analizar el tráfico de tu equipo.

Para utilizar el scanner ARP, debes especificar la dirección IP de la red a escanear con su mascara de red (ej:192.168.0.0/24) y el scanner empezará a escanear el rango especificado de direcciones IP en busca de dispositivos, también puedes escanear direcciones IP específicas (ej: 192.168.0.12).

Navega por internet desde cualquier punto de acceso protegido de cualquier atacante presente en la red.

# Dependencias

- Scapy 2.4.3

Instala esta libreria con pip con el comando "pip install scapy"

- Numpy 1.18.3

Instala esta libreria con pip con el comando "pip install scapy"

Desarrollado por Christian Muñoz.
Ingeniería de sistemas.
Universidad Distrital Francisco José de Caldas.
