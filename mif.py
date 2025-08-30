#!/usr/bin/env python3
"""
Decodificador de mensajes exfiltrados mediante paquetes ICMP request desde archivo PCAP.
Analiza archivos .pcap/.pcapng para extraer mensajes ocultos en paquetes ICMP.
Versión corregida con mejor cálculo de scores.
"""

import argparse
import sys
import re
from collections import Counter
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import colorama
from colorama import Fore, Style

# Inicializar colorama para colores en terminal
colorama.init()

# Frecuencias de letras en español (porcentajes aproximados)
SPANISH_LETTER_FREQ = {
    'a': 12.53, 'b': 1.42, 'c': 4.68, 'd': 5.86, 'e': 13.68, 
    'f': 0.69, 'g': 1.01, 'h': 0.70, 'i': 6.25, 'j': 0.44, 
    'k': 0.02, 'l': 4.97, 'm': 3.15, 'n': 6.71, 'o': 8.68, 
    'p': 2.51, 'q': 0.88, 'r': 6.87, 's': 7.98, 't': 4.63, 
    'u': 3.93, 'v': 0.90, 'w': 0.01, 'x': 0.22, 'y': 0.90, 
    'z': 0.52, ' ': 17.00,  # Espacio es el carácter más común
    '.': 0.90, ',': 0.90, '!': 0.30, '?': 0.30, ':': 0.20, 
    ';': 0.20, '"': 0.20, "'": 0.20, '-': 0.20, '_': 0.05
}

# Palabras comunes en español para validación (las 100 más frecuentes)
COMMON_SPANISH_WORDS = {
    'de', 'la', 'que', 'el', 'en', 'y', 'a', 'los', 'del', 'se', 
    'las', 'por', 'un', 'para', 'con', 'no', 'una', 'su', 'al', 
    'lo', 'como', 'más', 'pero', 'sus', 'le', 'ya', 'o', 'este', 
    'sí', 'porque', 'esta', 'entre', 'cuando', 'muy', 'sin', 
    'sobre', 'también', 'me', 'hasta', 'hay', 'donde', 'quien', 
    'desde', 'todo', 'nos', 'durante', 'todos', 'uno', 'les', 
    'ni', 'contra', 'otros', 'ese', 'eso', 'ante', 'ellos', 
    'e', 'esto', 'mí', 'antes', 'algunos', 'qué', 'unos', 'yo', 
    'otro', 'otras', 'otra', 'él', 'tanto', 'esa', 'estos', 
    'mucho', 'quienes', 'nada', 'muchos', 'cual', 'poco', 'ella', 
    'estar', 'estas', 'algunas', 'algo', 'nosotros', 'mi', 'mis', 
    'tú', 'te', 'ti', 'tu', 'tus', 'ellas', 'nosotras', 'vosotros', 'seguridad',
    'vosotras', 'os', 'mío', 'mía', 'míos', 'mías', 'tuyo', 'tuya','criptografia'
}

class ICMPPCAPDecoder:
    def __init__(self, args):
        self.args = args
        self.captured_chars = []
        self.packet_info = []  # Almacena (timestamp, char, src_ip, dst_ip)
        
    def load_pcap_file(self):
        """Carga y analiza el archivo PCAP"""
        try:
            print(f"{Fore.GREEN}[+] Analizando archivo: {self.args.pcap_file}{Style.RESET_ALL}")
            packets = rdpcap(self.args.pcap_file)
            return packets
        except Exception as e:
            print(f"{Fore.RED}[!] Error al leer el archivo PCAP: {e}{Style.RESET_ALL}")
            sys.exit(1)
    
    def extract_icmp_data(self, packets):
        """Extrae datos de paquetes ICMP request"""
        icmp_count = 0
        
        for packet in packets:
            try:
                if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # ICMP Echo Request
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        timestamp = packet.time
                        
                        # Obtener los datos del paquete
                        if packet.haslayer(Raw):
                            data = packet[Raw].load
                            
                            # Considerar solo el primer byte como carácter
                            if len(data) >= 1:
                                try:
                                    # Intentar decodificar como UTF-8
                                    char = data[:1].decode('utf-8', errors='strict')
                                except UnicodeDecodeError:
                                    # Si falla UTF-8, usar representación hexadecimal
                                    char = f"\\x{data[0]:02x}"
                                
                                self.captured_chars.append(char)
                                self.packet_info.append((timestamp, char, src_ip, dst_ip))
                                icmp_count += 1
                                
                                if self.args.verbose:
                                    print(f"{Fore.CYAN}[+] Paquete ICMP: {src_ip} -> {dst_ip} | '{char}' | Timestamp: {timestamp}{Style.RESET_ALL}")
               
            except Exception as e:
                if self.args.verbose:
                    print(f"{Fore.YELLOW}[!] Error procesando paquete: {e}{Style.RESET_ALL}")
        
        return icmp_count
    
    def sort_by_timestamp(self):
        """Ordena los paquetes por timestamp para reconstruir el mensaje en el orden correcto"""
        if not self.packet_info:
            return
        
        # Ordenar por timestamp
        self.packet_info.sort(key=lambda x: x[0])
        self.captured_chars = [char for _, char, _, _ in self.packet_info]
    
    def apply_shift(self, char, shift):
        """Aplica un desplazamiento (corrimiento) a un carácter"""
        if not char.isalpha():
            return char  # No cambiar caracteres no alfabéticos
        
        is_upper = char.isupper()
        base = ord('A') if is_upper else ord('a')
        char_code = ord(char) - base
        shifted_code = (char_code - shift) % 26  # Desplazamiento inverso (César inverso)
        return chr(shifted_code + base)
    
    def calculate_readability_score(self, text):
        """Calcula un score de legibilidad basado en frecuencia de letras y palabras comunes"""
        if not text or len(text) < 3:
            return 0
            
        score = 0
        text_lower = text.lower()
        
        # 1. Frecuencia de caracteres (40% del score)
        char_freq = Counter(text_lower)
        total_chars = len(text_lower)
        
        char_score = 0
        for char, count in char_freq.items():
            freq_percentage = (count / total_chars) * 100
            expected_freq = SPANISH_LETTER_FREQ.get(char, 0)
            # Puntuar según qué tan cerca está de la frecuencia esperada
            if expected_freq > 0:
                deviation = abs(freq_percentage - expected_freq)
                # Menor desviación = mayor puntuación (máximo 10 puntos por carácter)
                char_score += max(0, 10 - deviation / 2)
        
        # Normalizar puntuación de caracteres (máximo 40 puntos)
        char_score = min(40, char_score * 40 / (len(char_freq) * 10)) if char_freq else 0
        score += char_score
        
        # 2. Presencia de espacios (15% del score)
        space_count = text.count(' ')
        space_ratio = space_count / total_chars if total_chars > 0 else 0
        if 0.05 <= space_ratio <= 0.25:  # Rango razonable para texto
            score += 15 * min(1, space_ratio / 0.15)  # Máximo 15 puntos
        
        # 3. Proporción de vocales (15% del score)
        vowel_count = sum(1 for c in text_lower if c in 'aeiouáéíóú')
        vowel_ratio = vowel_count / total_chars if total_chars > 0 else 0
        if 0.3 <= vowel_ratio <= 0.5:  # Rango típico en español
            score += 15 * min(1, vowel_ratio / 0.4)  # Máximo 15 puntos
        
        # 4. Palabras comunes (30% del score)
        words = re.findall(r'\b[a-záéíóúñ]+\b', text_lower)
        if words:
            common_word_count = sum(1 for word in words if word in COMMON_SPANISH_WORDS)
            common_word_ratio = common_word_count / len(words)
            
            # Bonus por palabras comunes (máximo 30 puntos)
            score += 30 * min(1, common_word_ratio * 3)  # Ajuste para que no domine el score
            
            # 5. Longitud promedio de palabras (solo bonus/penalización)
            avg_word_len = sum(len(word) for word in words) / len(words)
            if 3.5 <= avg_word_len <= 8.5:  # Rango razonable para español
                score += 5
            else:
                score -= 5
        
        # Asegurar que el score esté entre 0 y 100
        return max(0, min(100, score))
    
    def decrypt_all_shifts(self):
        """Genera todas las combinaciones posibles de descifrado con corrimientos 0-25"""
        results = []
        
        if not self.captured_chars:
            print(f"{Fore.RED}[!] No se encontraron caracteres para descifrar{Style.RESET_ALL}")
            return results
        
        original_text = ''.join(self.captured_chars)
        print(f"{Fore.GREEN}[+] Caracteres recolectados: {original_text}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Generando combinaciones con corrimiento 0-25:{Style.RESET_ALL}\n")
        
        for shift in range(26):
            decrypted_text = ''.join(self.apply_shift(c, shift) if c.isalpha() else c for c in self.captured_chars)
            score = self.calculate_readability_score(decrypted_text)
            results.append((shift, decrypted_text, score))
        
        # Ordenar por score descendente
        results.sort(key=lambda x: x[2], reverse=True)
        return results
    
    def export_results(self, results):
        """Exporta los resultados a un archivo si se especificó"""
        if not self.args.output:
            return
        
        try:
            with open(self.args.output, 'w', encoding='utf-8') as f:
                f.write("Resultados de descifrado ICMP desde PCAP\n")
                f.write("========================================\n\n")
                
                f.write(f"Archivo analizado: {self.args.pcap_file}\n")
                f.write(f"Caracteres capturados: {''.join(self.captured_chars)}\n")
                f.write(f"Total de paquetes ICMP: {len(self.captured_chars)}\n\n")
                
                f.write("Detalles de paquetes:\n")
                f.write("---------------------\n")
                for i, (timestamp, char, src_ip, dst_ip) in enumerate(self.packet_info):
                    f.write(f"Paquete {i+1}: {src_ip} -> {dst_ip} | '{char}' | Timestamp: {timestamp}\n")
                
                f.write("\nTodas las combinaciones:\n")
                f.write("-----------------------\n")
                
                for shift, text, score in results:
                    f.write(f"Corrimiento {shift:2d}: {text} (Score: {score:.1f})\n")
                
                # El más probable
                if results:
                    best_shift, best_text, best_score = results[0]
                    f.write(f"\nMejor opción:\n")
                    f.write(f"Corrimiento {best_shift}: {best_text} (Score: {best_score:.1f})\n")
            
            print(f"{Fore.GREEN}[+] Resultados exportados a {self.args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error exportando resultados: {e}{Style.RESET_ALL}")
    
    def run(self):
        """Ejecuta el proceso completo de decodificación"""
        packets = self.load_pcap_file()
        icmp_count = self.extract_icmp_data(packets)
        
        print(f"{Fore.GREEN}[+] Paquetes ICMP request encontrados: {icmp_count}{Style.RESET_ALL}")
        
        if not self.captured_chars:
            print(f"{Fore.RED}[!] No se encontraron paquetes ICMP con datos.{Style.RESET_ALL}")
            return
        
        # Ordenar por timestamp para reconstruir el mensaje en el orden correcto
        self.sort_by_timestamp()
        
        results = self.decrypt_all_shifts()
        
        if not results:
            return
        
        # Mostrar todas las combinaciones
        for shift, text, score in results:
            # Resaltar la mejor opción
            if shift == results[0][0]:
                print(f"{Fore.GREEN}Corrimiento {shift:2d}: {text} ✅ (Score: {score:.1f}){Style.RESET_ALL}")
            else:
                print(f"Corrimiento {shift:2d}: {text} (Score: {score:.1f})")
        
        # Mostrar el mejor resultado
        if results[0][2] > 50:  # Solo si tiene un score razonable
            best_shift, best_text, best_score = results[0]
            print(f"\n{Fore.GREEN}[+] Mensaje más probable (corrimiento {best_shift}): {best_text}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] Score de legibilidad: {best_score:.1f}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[!] No se encontró un mensaje claramente legible.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] El mejor score fue: {results[0][2]:.1f}{Style.RESET_ALL}")
        
        # Exportar resultados si se especificó
        if self.args.output:
            self.export_results(results)

def main():
    parser = argparse.ArgumentParser(description="Decodificador de mensajes exfiltrados via ICMP desde archivo PCAP")
    parser.add_argument("pcap_file", help="Archivo PCAP/PCAPNG a analizar")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose para mostrar detalles de paquetes")
    parser.add_argument("-o", "--output", help="Archivo para exportar resultados")
    
    args = parser.parse_args()
    
    decoder = ICMPPCAPDecoder(args)
    decoder.run()

if __name__ == "__main__":
    main()