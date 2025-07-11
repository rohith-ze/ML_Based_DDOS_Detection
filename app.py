import threading
import pandas as pd
import joblib
import os
import time
import pefile
from pefile import PEFormatError
from collections import defaultdict
from flask import Flask, jsonify, request
from scapy.all import sniff, IP, TCP, UDP

app = Flask(__name__)

# Load Pre-trained Models
ddos_model = joblib.load('models/rf_ddos_model.pkl')
malware_model = joblib.load('models/rf_malware_model.pkl')

# Store DDoS detection results
detection_result = {"status": "Normal Traffic"}

# Dictionary to store flow data
flows = defaultdict(lambda: {
    'start_time': None, 'total_fwd_packets': 0, 'total_backward_packets': 0,
    'fwd_packet_length_total': 0, 'bwd_packet_length_total': 0,
    'syn_count': 0, 'ack_count': 0, 'rst_count': 0, 'last_time': None
})

# Feature order
expected_features = [
    'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Flow Bytes/s',
    'Flow Packets/s', 'SYN Flag Count', 'ACK Flag Count', 'RST Flag Count'
]

# Extract DDoS Features
def extract_ddos_features(flow):
    duration = flow['last_time'] - flow['start_time']
    features = {
        'Protocol': 6,  # Placeholder for TCP
        'Flow Duration': duration,
        'Total Fwd Packets': flow['total_fwd_packets'],
        'Total Backward Packets': flow['total_backward_packets'],
        'Fwd Packet Length Mean': flow['fwd_packet_length_total'] / max(flow['total_fwd_packets'], 1),
        'Bwd Packet Length Mean': flow['bwd_packet_length_total'] / max(flow['total_backward_packets'], 1),
        'Flow Bytes/s': (flow['fwd_packet_length_total'] + flow['bwd_packet_length_total']) / max(duration, 1),
        'Flow Packets/s': (flow['total_fwd_packets'] + flow['total_backward_packets']) / max(duration, 1),
        'SYN Flag Count': flow['syn_count'],
        'ACK Flag Count': flow['ack_count'],
        'RST Flag Count': flow['rst_count']
    }
    df_features = pd.DataFrame([features])
    df_features = df_features[expected_features]
    return df_features

# Packet Sniffing
def capture_packets():
    global detection_result
    print("🚀 Monitoring Network Traffic...")

    def process_packet(packet):
        if IP in packet:
            flow_key = (packet[IP].src, packet[IP].dst)
            if flows[flow_key]['start_time'] is None:
                flows[flow_key]['start_time'] = time.time()
                flows[flow_key]['last_time'] = flows[flow_key]['start_time']

            flows[flow_key]['last_time'] = time.time()
            if TCP in packet:
                flows[flow_key]['total_fwd_packets'] += 1
                flows[flow_key]['fwd_packet_length_total'] += len(packet)
                if packet[TCP].flags & 0x02: flows[flow_key]['syn_count'] += 1
                if packet[TCP].flags & 0x10: flows[flow_key]['ack_count'] += 1
                if packet[TCP].flags & 0x04: flows[flow_key]['rst_count'] += 1

            features = extract_ddos_features(flows[flow_key])
            prediction = ddos_model.predict(features)
            if prediction[0] == 1:
                print("⚠️ [ALERT] DDoS Attack Detected!")
                detection_result["status"] = "DDoS Attack Detected"

    sniff(prn=process_packet, store=0)

threading.Thread(target=capture_packets, daemon=True).start()

@app.route('/ddos_detect', methods=['POST'])
def ddos_detect():
    return jsonify(detection_result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)