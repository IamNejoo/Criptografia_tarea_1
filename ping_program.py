#!/usr/bin/python3
import sys
import time
import os
import random
from scapy.all import *

def send_ping(target_ip, message):
    try:
        # Generar un identificador único para el paquete ICMP
        identifier = os.getpid() & 0xFFFF

        # Inicializar el número de secuencia
        sequence = 1

        for char in message:
            # Crear el paquete ICMP
            icmp_packet = IP(dst=target_ip) / ICMP(type=8, id=identifier, seq=sequence)

            # Obtener el tiempo actual en formato UNIX
            timestamp = int(time.time())

            # Crear el campo de datos
            data = bytes([random.randint(0, 255), random.randint(0, 255)])
            data += b'\x00\x00\x00\x00\x00'
            data += bytes(range(0x10, 0x38))
            data += char.encode()  # Agregar el caracter del mensaje al final

            icmp_packet /= Raw(load=data)

            # Establecer el tiempo de envío en icmp.packet.time
            icmp_packet.time = timestamp

            # Enviar el paquete ICMP
            send(icmp_packet, verbose=False)

            # Incrementar el número de secuencia
            sequence += 1

        print("Pings enviados con éxito")
    except Exception as e:
        print(f"Error al enviar los pings: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: ./ping_program.py 'mensaje'")
        sys.exit(1)

    target_ip = "8.8.8.8"  # Dirección IP de destino (Google DNS)
    message = sys.argv[1]  # Obtener el mensaje desde los argumentos de la línea de comandos

    send_ping(target_ip, message)
