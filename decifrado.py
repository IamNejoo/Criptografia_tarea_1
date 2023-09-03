import scapy.all as scapy
import string
from colorama import init, Fore

init(autoreset=True)

def extract_last_byte(packet):
    if packet.haslayer(scapy.ICMP):
        icmp_packet = packet[scapy.ICMP]
        if icmp_packet.type == 8:  # ICMP Request
            return icmp_packet.load[-1]

def caesar_decrypt(ciphertext, shift):
    decrypted_text = ""
    for char in ciphertext:
        if char.isalpha():
            shifted_char = chr(((ord(char) - ord('a' if char.islower() else 'A') - shift) % 26) + ord('a' if char.islower() else 'A'))
            decrypted_text += shifted_char
        else:
            decrypted_text += char
    return decrypted_text

def calculate_probable_message(decrypted_text):
    # Este es un ejemplo simple para calcular la probabilidad.
    # Puedes ajustar este código o utilizar bibliotecas de análisis de texto más avanzadas.
    spanish_letter_frequencies = {
        'a': 0.121,
        'b': 0.014,
        'c': 0.046,
        'd': 0.052,
        'e': 0.134,
        'f': 0.010,
        'g': 0.010,
        'h': 0.010,
        'i': 0.067,
        'j': 0.004,
        'k': 0.001,
        'l': 0.049,
        'm': 0.031,
        'n': 0.067,
        'o': 0.086,
        'p': 0.025,
        'q': 0.008,
        'r': 0.068,
        's': 0.079,
        't': 0.046,
        'u': 0.029,
        'v': 0.010,
        'w': 0.001,
        'x': 0.002,
        'y': 0.010,
        'z': 0.005,
    }
    
    probability = 1.0

    for char in decrypted_text:
        if char.isalpha():
            char = char.lower()
            if char in spanish_letter_frequencies:
                probability *= spanish_letter_frequencies[char]
            else:
                # Si el carácter no está en el diccionario de frecuencias,
                # puedes asumir una probabilidad mínima para ese carácter.
                probability *= 0.001
    
    return probability

def main(pcapng_file):
    packets = scapy.rdpcap(pcapng_file)
    icmp_payload = ""

    for packet in packets:
        last_byte = extract_last_byte(packet)
        if last_byte:
            icmp_payload += chr(last_byte)

    probable_message = ""
    max_probability = 0

    for shift in range(1, 26):
        decrypted_text = caesar_decrypt(icmp_payload, shift)
        probability = calculate_probable_message(decrypted_text)

        if probability > max_probability:
            max_probability = probability
            probable_message = decrypted_text

    for shift in range(1, 26):
        decrypted_text = caesar_decrypt(icmp_payload, shift)
        if decrypted_text == probable_message:
            print(Fore.GREEN + f"Shift {shift}: {decrypted_text}")
        else:
            print(f"Shift {shift}: {decrypted_text}")

if __name__ == "__main__":
    pcapng_file = input("Ingrese el nombre del archivo pcapng: ")
    main(pcapng_file)
