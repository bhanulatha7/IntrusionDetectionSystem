from flask import Flask, jsonify, render_template, request
import scapy.all as scapy
import threading
from datetime import datetime

app = Flask(__name__)

# Global variables for packet capture
capturing = False
capture_thread = None
monitored_data = []  # Store monitored data
detected_intrusions = []  # Store detected intrusions

def packet_callback(packet):
    global monitored_data, detected_intrusions

    # Process each captured packet here
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Raw):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        payload = str(packet[scapy.Raw].load, 'utf-8', 'ignore')
        print(payload)
        # Check for intrusion in the payload
        if "intrusion" in payload.lower():
            intrusion_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'source_ip': source_ip,
                'destination_ip': destination_ip,
                'payload': payload
            }

            # Add intrusion information to detected intrusions
            detected_intrusions.append(intrusion_info)

            print(f"Intrusion detected: {payload}")
        print(payload)
        # Add packet summary to monitored data
        monitored_data.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'payload': payload
        })

def capture_packets():
    global capturing
    scapy.sniff(prn=packet_callback)
    capturing = False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capturing, capture_thread, monitored_data, detected_intrusions
    monitored_data = []  # Clear monitored data when starting capture
    detected_intrusions = []  # Clear detected intrusions when starting capture

    if not capturing:
        capturing = True
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.start()
        return jsonify({'status': 'success', 'message': 'Packet capture started.'})
    else:
        return jsonify({'status': 'error', 'message': 'Packet capture already in progress.'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capturing, capture_thread
    if capturing:
        capturing = False
        capture_thread.join()
        return jsonify({'status': 'success', 'message': 'Packet capture stopped.'})
    else:
        return jsonify({'status': 'error', 'message': 'No capture in progress.'})

@app.route('/send_suspicious_packet', methods=['POST'])
def send_suspicious_packet():
    global detected_intrusions

    try:
        # Get the suspicious payload from the request
        suspicious_payload = request.get_data(as_text=True)
        print("Data: ", request.get_data())
        print(suspicious_payload)

        # Check for intrusion in the payload
        if "intrusion" in suspicious_payload.lower():
            intrusion_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'payload': suspicious_payload
            }

            # Add intrusion information to detected intrusions
            detected_intrusions.append(intrusion_info)

            # Return success response with an alert message
            return jsonify({'status': 'success', 'message': 'Suspicious packet received. Intrusion detected.'})
        else:
            # Return success response without an alert message
            return jsonify({'status': 'success', 'message': 'Suspicious packet received. No intrusion detected.'})
    except Exception as e:
        # Return error response if an exception occurs
        return jsonify({'status': 'error', 'message': f'Error processing suspicious packet: {str(e)}'})

@app.route('/get_monitored_data', methods=['GET'])
def get_monitored_data():
    global monitored_data
    # Return the list of monitored data to the client
    return jsonify({'monitored_data': monitored_data})

@app.route('/get_detected_intrusions', methods=['GET'])
def get_detected_intrusions():
    global detected_intrusions
    # Return the list of detected intrusions to the client
    return jsonify({'detected_intrusions': detected_intrusions})

if __name__ == '__main__':
    app.run(debug=True)
