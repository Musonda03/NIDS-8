def detect_anomalies(packet):
    global packet_count
    if IP in packet:
        packet_count += 1
        print(f"Packet captured: {packet.summary()}")  # Debug statement
        
        try:
            features = extract_features(packet)
            print(f"Extracted features: {features}")
            packet_features_list.append(features)
            
            if traffic_callback:
                traffic_callback(packet_count)
                print(f"Packet count updated: {packet_count}")  # Debug statement
            
            # Convert features to DataFrame
            feature_df = pd.DataFrame([features])
            
            # Ensure categorical features are encoded similarly as during training
            feature_df['ip_src'] = label_encoder.transform([features['ip_src']])[0]
            feature_df['ip_dst'] = label_encoder.transform([features['ip_dst']])[0]
            feature_df['tcp_flags'] = label_encoder.transform([features['tcp_flags']])[0]
            feature_df['timestamp'] = pd.to_numeric(feature_df['timestamp'])

            #print(f"Feature DataFrame after encoding: {feature_df}")  # Debug statement
            #is_anomaly = model.predict(feature_df)[0]
            #print(f"Model prediction: {is_anomaly}")  # Debug statement

             # Force anomaly for testing
            if features['ip_src'] == '192.168.1.100' and features['dport'] == 80:
                is_anomaly = 1
                print("Forced anomaly detected.")  # Debug statement
            else:
                is_anomaly = model.predict(feature_df)[0]
                print(f"Model prediction: {is_anomaly}")  # Debug statement

            if is_anomaly:
                anomaly = f"Anomaly detected: {features}"
                if anomaly_callback:
                    anomaly_callback(anomaly)
                print(anomaly)  # Debug statement
            else:
                print("No anomaly detected.")  # Debug statement
        except KeyError as e:
            print(f"Missing feature in packet {packet_count}: {e}")
        except Exception as e:
            print(f"Error extracting features from packet {packet_count}: {e}")

#anomalies.append({
        #"timestamp": datetime.now().timestamp(),
        #"ip_src": anomaly["ip_src"],
        #"ip_dst": anomaly["ip_dst"],
        #"ip_proto": anomaly["ip_proto"],
        #"sport": anomaly["sport"],
        #"dport": anomaly["dport"],
        #"tcp_flags": anomaly["tcp_flags"]
    #})

#packet_count = 0

# Configure Socket.IO
sio = socketio.Client()
sio.connect('http://localhost:5000')

def detect_anomalies(packet):
    global packet_count
    packet_count += 1
    
    # Extract packet features
    features = parse_packet(packet)
    
    # Example conditions for an anomaly
    anomaly_detected = False
    
    # Define some thresholds for anomaly detection
    PORT_THRESHOLD = 1024
    PROTO_THRESHOLD = 6  # Assuming TCP as the protocol of interest

    # Check if source or destination port is higher than the threshold
    if features['sport'] > PORT_THRESHOLD or features['dport'] > PORT_THRESHOLD:
        anomaly_detected = True
    
    # Check if the protocol is not TCP
    if features['ip_proto'] != PROTO_THRESHOLD:
        anomaly_detected = True

    if anomaly_detected:
        anomaly = {
            "timestamp": datetime.now().strftime('%m/%d/%Y, %I:%M:%S %p'),
            "ip_src": features.get('ip_src', 'undefined'),
            "ip_dst": features.get('ip_dst', 'undefined'),
            "ip_proto": features.get('ip_proto', 'undefined'),
            "sport": features.get('sport', 'undefined'),
            "dport": features.get('dport', 'undefined'),
            "tcp_flags": features.get('tcp_flags', 'undefined'),
            "packet_count": packet_count
        }
        sio.emit('new_anomaly', anomaly)

def parse_packet(packet):
    features = {
        'ip_src': packet[0][1].src,
        'ip_dst': packet[0][1].dst,
        'ip_proto': packet[0][1].proto,
        'sport': packet[0][2].sport,
        'dport': packet[0][2].dport,
        'tcp_flags': packet[0][2].flags if hasattr(packet[0][2], 'flags') else '0',
    }
    return features

