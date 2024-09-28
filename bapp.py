@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html', capturing=capturing)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.form['username'] == USER['username'] and request.form['password'] == USER['password']:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        else:
            return "Invalid credentials. Please try again."
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/anomalies', methods=['GET'])
@login_required
def get_anomalies():
    return jsonify(anomalies)


@app.route('/traffic_data', methods=['GET'])
@login_required
def get_traffic_data():
    return jsonify(traffic_data)


@app.route('/traffic')
@login_required
def traffic():
    return render_template('traffic.html')

@app.route('/plotly_chart')
@login_required
def plotly_chart():
    global traffic_data
    df = pd.DataFrame({
        'Time': traffic_data['time'],
        'Packet Count': traffic_data['packet_count']
    })
    fig = px.line(df, x='Time', y='Packet Count', title='Network Traffic Over Time')
    graph_html = fig.to_html(full_html=False)
    return render_template('plotly_chart.html', graph_html=graph_html)

@app.route('/view_anomalies', methods=['GET'])
@login_required
def view_anomalies():
    global anomalies
    return render_template('anomalies.html', anomalies=anomalies)

@app.route('/generate_anomalous_traffic', methods=['GET'])
@login_required
def generate_anomalous_traffic_route():
    generate_anomalous_traffic()
    return jsonify({"status": "Anomalous traffic generated"})


@app.route('/user_guide')
@login_required
def user_guide():
    return render_template('user_guide.html')

@app.route('/captured_data', methods=['GET'])
@login_required
def get_captured_data():
    try:
        df = pd.read_csv('new_packets.csv')
        data = df.to_dict(orient='records')
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/captured_data')
@login_required
def captured_data():
    return render_template('captured_data.html')

@app.route('/start_capture', methods=['POST'])
@login_required
def start_capture():
    global capturing
    capturing = True
    capture_thread = threading.Thread(target=packet_capture.start_packet_capture)
    capture_thread.daemon = True
    capture_thread.start()
    return jsonify({"status": "Capture started"})
    #packet_capture.start_packet_capture()
    #return jsonify({"status": "Packet capture started"})

@app.route('/stop_capture', methods=['POST'])
@login_required
def stop_capture():
    global capturing
    capturing = False
    packet_capture.stop_packet_capture()
    return jsonify({"status": "Capture stopped"})
    #packet_capture.stop_packet_capture()
    #return jsonify({"status": "Packet capture stopped"})

@app.route('/update_model', methods=['POST'])
@login_required
def update_model():
    try:
        result = subprocess.run(['python', 'update_model.py'], capture_output=True, text=True)
        if result.returncode == 0:
            return jsonify({'message': 'Model updated successfully.'})
        else:
            return jsonify({'message': 'Model update failed.', 'error': result.stderr}), 500
    except Exception as e:
        return jsonify({'message': 'An error occurred while updating the model.', 'error': str(e)}), 500

# Function to add anomaly to the list
def add_anomaly(anomaly):
    global anomalies
    #anomalies.append(anomaly)
    anomalies.append({
        "timestamp": anomaly['timestamp'],
        "ip_src": anomaly['ip_src'],
        "ip_dst": anomaly['ip_dst'],
        "ip_proto": anomaly['ip_proto'],
        "sport": anomaly['sport'],
        "dport": anomaly['dport'],
        "tcp_flags": str(anomaly['tcp_flags'])  # Ensure this is a string
    })
    if len(anomalies) > 100:
        anomalies.pop(0)
    print(f"Anomaly detected: {anomaly}")  # Debug statement
    print("Emitting new_anomaly event")  # Debug statement
    # Emit the anomaly to the front end
    socketio.emit('new_anomaly', anomaly)

# Function to update traffic data
def update_traffic_data(packet_count):
    global traffic_data
    traffic_data["time"].append(datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))
    traffic_data["packet_count"].append(packet_count)
    if len(traffic_data["time"]) > 60:
        traffic_data["time"].pop(0)
        traffic_data["packet_count"].pop(0)

if __name__ == '__main__':
    # Set the anomaly and traffic data callbacks
    packet_capture.set_anomaly_callback(add_anomaly)
    packet_capture.set_traffic_callback(update_traffic_data)
    
    socketio.run(app, debug=True)

