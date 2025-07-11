# ML_Based_DDOS_Detection
# 🛡️ CyberSentinel: Real-Time DDoS & Malware Detection Using ML

**CyberSentinel** is a real-time network traffic monitoring and file analysis tool that uses machine learning to detect **DDoS attacks** and **malware-infected executables**. It leverages Scapy for packet sniffing, a trained Random Forest model for DDoS classification, and PE file feature extraction for malware detection — all wrapped in a simple Flask web interface.

--- 

## 🚀 Features

- ✅ Real-time DDoS attack detection using network flow statistics
- ✅ High packet-rate alerting (e.g., SYN flood, UDP flood)
- ✅ Malware detection from uploaded PE (Windows executable) files
- ✅ Live network packet logging via console
- ✅ Lightweight and modular Flask web server
- ✅ Designed for local networks or test environments

---

##🔍 How It Works
-🧠 DDoS Detection

    -Captures live packets using scapy

    -Groups packets by source-destination flows

    -Extracts flow-based features:

        -Packet counts

        -Byte rates

        -Flag counts (SYN, ACK, RST)

    -Uses a pre-trained Random Forest model to classify traffic

-🐛 Malware Detection

    -Accepts user-uploaded .exe or .dll files

    -Extracts features using pefile:

        -Number of sections

        -Entry point

        -File size, timestamp

    -Classifies using a trained model


