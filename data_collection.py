# data_collection.py

import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import os
from collections import defaultdict

# Initialize packet count
packet_count = 0

# Define the path for storing captured data
data_path = 'captured_packets.csv'

# Initialize traffic counters
ip_counter = defaultdict(int)
port_counter = defaultdict(int)

# Thresholds for flagging anomalies (adjust based on your network)
IP_THRESHOLD = 100
PORT_THRESHOLD = 50

# Check if file exists, create if not
if not os.path.exists(data_path):
    with open(data_path, 'w') as f:
        f.write('timestamp,ip_src,ip_dst,ip_proto,sport,dport,tcp_flags,anomaly_flag\n')

def extract_features(packet):
    features = {
        'timestamp': pd.Timestamp.now(),
        'ip_src': packet[IP].src,
        'ip_dst': packet[IP].dst,
        'ip_proto': packet[IP].proto,
        'sport': 0,
        'dport': 0,
        'tcp_flags': 0,
        'anomaly_flag': 0
    }
    
    if TCP in packet:
        features.update({
            'sport': packet[TCP].sport,
            'dport': packet[TCP].dport,
            'tcp_flags': packet[TCP].flags
        })
    elif UDP in packet:
        features.update({
            'sport': packet[UDP].sport,
            'dport': packet[UDP].dport
        })

    return features

def detect_anomalies(features):
    ip_counter[features['ip_src']] += 1
    port_counter[features['dport']] += 1
    
    if ip_counter[features['ip_src']] > IP_THRESHOLD or port_counter[features['dport']] > PORT_THRESHOLD:
        features['anomaly_flag'] = 1  # Flag as potential anomaly
        print(f"Potential anomaly detected: {features}")  # Debug statement

def save_packet(packet):
    global packet_count
    packet_count += 1
    if IP in packet:
        features = extract_features(packet)
        detect_anomalies(features)
        df = pd.DataFrame([features])
        df.to_csv(data_path, mode='a', header=False, index=False)
        print(f"Packet {packet_count} captured")

def start_packet_capture():
    print("Starting packet capture...")
    sniff(filter="ip", prn=save_packet, store=0)

if __name__ == '__main__':
    start_packet_capture()
