#!/usr/bin/env python3
"""
mif.py - Message Interception from ICMP Frames
Analiza archivos pcapng de Wireshark para extraer mensajes secretos de paquetes ICMP
"""

import pyshark
import sys
from collections import defaultdict
import string

def analyze_icmp_packets(pcap_file):
    """
    Analiza el archivo pcapng y extrae los datos de los paquetes ICMP
    """
    print(f"Analizando archivo: {pcap_file}")
    print("=" * 60)
    
    try:
        # Configurar captura desde archivo
        cap = pyshark.FileCapture(pcap_file, display_filter='icmp.type == 8')
        
        packets_info = []
        sequence_packets = defaultdict(list)
        
        packet_count = 0
        for packet in cap:
            packet_count += 1
            try:
                # Extraer información del paquete ICMP
                if hasattr(packet.icmp, 'seq'):
                    sequence = int(packet.icmp.seq)
                    identifier = int(packet.icmp.ident) if hasattr(packet.icmp, 'ident') else 0
                    
                    # Extraer payload/data del paquete
                    if hasattr(packet.icmp, 'data'):
                        payload_hex = packet.icmp.data
                        payload_bytes = bytes.fromhex(payload_hex.replace(':', ''))
                        
                        # El payload debería tener al menos 8 bytes (timestamp) + 1 byte de dato
                        if len(payload_bytes) >= 9:
                            # El carácter secreto está en el byte 8 (después del timestamp)
                            secret_byte = payload_bytes[8:9]
                            secret_char = secret_byte.decode('latin-1', errors='ignore')
                            
                            packet_info = {
                                'sequence': sequence,
                                'identifier': identifier,
                                'payload': payload_bytes,
                                'secret_byte': secret_byte,
                                'secret_char': secret_char,
                                'timestamp': packet.sniff_time,
                                'src_ip': packet.ip.src,
                                'dst_ip': packet.ip.dst
                            }
                            
                            packets_info.append(packet_info)
                            sequence_packets[sequence].append(packet_info)
                            
            except AttributeError as e:
                continue
            except Exception as e:
                print(f"Error procesando paquete {packet_count}: {e}")
                continue
        
        cap.close()
        
        print(f"Paquetes ICMP Request encontrados: {len(packets_info)}")
        return packets_info, sequence_packets
        
    except Exception as e:
        print(f"Error abriendo archivo pcapng: {e}")
        return [], defaultdict(list)

def extract_raw_message(packets_info):
    """
    Extrae el mensaje crudo ordenando por sequence number
    """
    # Ordenar paquetes por sequence number
    sorted_packets = sorted(packets_info, key=lambda x: x['sequence'])
    
    raw_message = ''.join([p['secret_char'] for p in sorted_packets])
    
    print("Mensaje crudo extraído (ordenado por sequence):")
    print(f"→ {raw_message}")
    print("-" * 60)
    
    return raw_message, sorted_packets

def generate_all_shifts(message):
    """
    Genera todas las combinaciones posibles de corrimientos Caesar
    """
    shifts = []
    for shift in range(1, 26):
        decoded = []
        for char in message:
            if char in string.ascii_uppercase:
                # Corrimiento para mayúsculas
                decoded_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            elif char in string.ascii_lowercase:
                # Corrimiento para minúsculas
                decoded_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            elif char in string.digits:
                # Corrimiento para dígitos (0-9 → 0-9)
                decoded_char = chr((ord(char) - ord('0') - shift) % 10 + ord('0'))
            else:
                # Mantener caracteres especiales sin cambios
                decoded_char = char
            decoded.append(decoded_char)
        shifts.append((''.join(decoded), shift))
    
    return shifts

def calculate_english_score(text):
    """
    Calcula un score basado en frecuencia de letras en inglés
    """
    # Frecuencias de letras en inglés (porcentajes)
    letter_freq = {
        'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
        'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
        'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
        'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
        'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974, 'z': 0.074
    }
    
    common_words = ['the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'i']
    
    score = 0
    text_lower = text.lower()
    
    # Puntos por frecuencia de letras
    for char in text_lower:
        if char in letter_freq:
            score += letter_freq[char]
    
    # Puntos adicionales por palabras comunes
    for word in common_words:
        if word in text_lower:
            score += len(word) * 10
    
    # Puntos por espacios (indicador de texto legible)
    if ' ' in text:
        score += 20
    
    return score

def print_colored(text, color_code):
    """
    Imprime texto en color (para resaltar el mensaje más probable)
    """
    print(f"\033[{color_code}m{text}\033[0m")

def main():
    if len(sys.argv) != 2:
        print("Uso: python3 mif.py <archivo_pcapng>")
        print("Ejemplo: python3 mif.py output.pcapng")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Analizar paquetes ICMP del archivo
    packets_info, sequence_packets = analyze_icmp_packets(pcap_file)
    
    if not packets_info:
        print("No se encontraron paquetes ICMP Request con payload válido.")
        sys.exit(1)
    
    # Extraer mensaje crudo
    raw_message, sorted_packets = extract_raw_message(packets_info)
    
    # Mostrar información detallada de los paquetes
    print("\nINFORMACIÓN DETALLADA DE PAQUETES:")
    print("-" * 40)
    for i, packet in enumerate(sorted_packets):
        print(f"Seq {packet['sequence']:3d}: "
              f"ID {packet['identifier']:5d} | "
              f"Char '{packet['secret_char']}' | "
              f"Byte: {packet['secret_byte'].hex()} | "
              f"From: {packet['src_ip']} → {packet['dst_ip']}")
    
    # Generar todas las combinaciones de corrimientos
    print(f"\nGenerando todas las combinaciones de corrimiento Caesar...")
    all_shifts = generate_all_shifts(raw_message)
    
    # Calcular scores para cada corrimiento
    scored_shifts = []
    for decoded_message, shift in all_shifts:
        score = calculate_english_score(decoded_message)
        scored_shifts.append((decoded_message, shift, score))
    
    # Ordenar por score (mayor score primero)
    scored_shifts.sort(key=lambda x: x[2], reverse=True)
    
    print(f"\nTODAS LAS COMBINACIONES POSIBLES:")
    print("=" * 60)
    
    # Imprimir todas las combinaciones
    for i, (decoded_message, shift, score) in enumerate(scored_shifts):
        if i == 0:  # El más probable
            print_colored(f"Shift {shift:2d} [Score: {score:6.1f}]: {decoded_message}", "92")  # Verde
        elif score > 50:  # Opciones plausibles
            print_colored(f"Shift {shift:2d} [Score: {score:6.1f}]: {decoded_message}", "93")  # Amarillo
        else:
            print(f"Shift {shift:2d} [Score: {score:6.1f}]: {decoded_message}")
    
    # Mostrar análisis estadístico
    print(f"\nANÁLISIS ESTADÍSTICO:")
    print("-" * 40)
    print(f"Mensaje crudo length: {len(raw_message)} caracteres")
    print(f"Caracteres alfabéticos: {sum(1 for c in raw_message if c.isalpha())}")
    print(f"Caracteres numéricos: {sum(1 for c in raw_message if c.isdigit())}")
    print(f"Caracteres especiales: {sum(1 for c in raw_message if not c.isalnum())}")
    
    # El mensaje más probable
    best_message, best_shift, best_score = scored_shifts[0]
    print_colored(f"\nMENSAJE MÁS PROBABLE (Shift {best_shift}):", "92")
    print_colored(f"→ {best_message}", "92")
    print_colored(f"Score: {best_score:.1f}", "92")

if __name__ == "__main__":
    main()