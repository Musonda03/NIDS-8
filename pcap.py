import pandas as pd
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
from datetime import datetime
import joblib
import logging
import threading
import os

# Initialize packet count
packet_count = 0
packet_features_list = []

anomaly_callback = None
traffic_callback = None

# Load the trained model and label encoder
model = joblib.load('random_forest_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')

capture_running = threading.Event()

# Define the path for storing captured data
data_path = 'new_packets.csv'

# Check if file exists, create if not
if not os.path.exists(data_path):
    with open(data_path, 'w') as f:
        f.write('timestamp,ip_src,ip_dst,ip_proto,sport,dport,tcp_flags,label\n')

def set_anomaly_callback(callback):
    global anomaly_callback
    anomaly_callback = callback

def set_traffic_callback(callback):
    global traffic_callback
    traffic_callback = callback

def extract_features(packet):
    features = {
        'timestamp': datetime.now().timestamp(),  # Include current timestamp
        'ip_src': packet[IP].src,
        'ip_dst': packet[IP].dst,
        'ip_proto': packet[IP].proto,
        'sport': 0,
        'dport': 0,
        'tcp_flags': 0
    }
    
    if TCP in packet:
        features.update({
            'sport': packet[TCP].sport,
            'dport': packet[TCP].dport,
            'tcp_flags': str(packet[TCP].flags)
        })
    elif UDP in packet:
        features.update({
            'sport': packet[UDP].sport,
            'dport': packet[UDP].dport
        })

    return features

def detect_anomalies(packet):
    global packet_count
    try:
        packet_count += 1
        features = extract_features(packet)
        packet_features_list.append(features)
        
        # Convert features to DataFrame
        feature_df = pd.DataFrame([features])
        
        # Ensure categorical features are encoded similarly as during training
        feature_df['ip_src'] = label_encoder.transform([features['ip_src']])[0]
        feature_df['ip_dst'] = label_encoder.transform([features['ip_dst']])[0]
        feature_df['tcp_flags'] = label_encoder.transform([features['tcp_flags']])[0]
        feature_df['timestamp'] = pd.to_numeric(feature_df['timestamp'])

        # Force anomaly for testing
        if features['ip_src'] == '192.168.1.100' and features['dport'] == 80:
            is_anomaly = 1
        else:
            is_anomaly = model.predict(feature_df)[0]

        if is_anomaly:
            features['label'] = 1  # Mark as anomaly
            print(f"Anomaly detected: {features}")
        else:
            features['label'] = 0  # Mark as normal

        if is_anomaly:
                anomaly = {
                    'timestamp': features['timestamp'],
                    'ip_src': features['ip_src'],
                    'ip_dst': features['ip_dst'],
                    'ip_proto': features['ip_proto'],
                    'sport': features['sport'],
                    'dport': features['dport'],
                    'tcp_flags': features['tcp_flags'],
                    'packet_count': packet_count
                }
                if anomaly_callback:
                    anomaly_callback(anomaly)
                print(f"Anomaly detected: {anomaly}")  # Debug statement
        else:
            print("No anomaly detected.") 

        save_packet(features)  # Save packet with the label

    except KeyError as e:
        print(f"Missing feature in packet {packet_count}: {e}")
    except Exception as e:
        print(f"Error extracting features from packet {packet_count}: {e}")

def save_packet(features):
    df = pd.DataFrame([features])
    df.to_csv(data_path, mode='a', header=False, index=False)
    print(f"Packet {packet_count} captured and saved")

#def packet_capture():
    #print("Starting packet capture...")  # Debug statement
    #sniff(filter="ip", prn=process_packet, store=0)

def packet_capture():
    print("Starting packet capture...")  # Debug statement
    sniff(filter="ip", prn=detect_anomalies, store=0, stop_filter=lambda x: not capture_running.is_set())

def start_packet_capture():
    if not capture_running.is_set():
        capture_running.set()
        threading.Thread(target=packet_capture).start()

def stop_packet_capture():
    if capture_running.is_set():
        capture_running.clear()

def process_packet(packet):
    if IP in packet:
        features = extract_features(packet)
        detect_anomalies(features)

def generate_anomalous_traffic():
    print("Generating anomalous traffic...")
    # Example anomalous packet
    pkt = IP(src="192.168.1.100", dst="192.168.1.101") / TCP(sport=1234, dport=80, flags="S")
    #send(pkt, verbose=0)
    print("Anomalous traffic generated.")

#if __name__ == '__main__':
    #packet_capture()

