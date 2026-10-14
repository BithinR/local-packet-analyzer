# SECURITY TOOL DEVELOPMENT REPORT
# NETWORK TRAFFIC TRIAGE TOOL: BROWSER-BASED SOC ANALYTICS

**Developer & Analyst:** Bithin Krishna Radhakrishnan[cite: 2]
**Date:** October 2026
**Project Type:** Security Operations Development & Network Analysis

---

## 1. Executive Summary

A custom, browser-based Network Traffic Triage Tool was engineered to assist cybersecurity analysts in parsing, visualizing, and investigating raw network captures. Developed entirely using HTML5, CSS3, and Vanilla JavaScript, the tool ingests Wireshark CSV exports and applies an explainable, rule-based detection engine to identify network anomalies.

Unlike commercial "black-box" alerting tools, this application prioritizes transparent educational context. Every generated alert provides immediate guidance on investigative scoring, potential benign explanations, and structured investigation steps, enforcing the methodology that an anomaly is merely an indicator, not a definitive compromise.

---

## 2. Scope and Architecture

### 2.1 Technical Specifications
* **Frontend:** HTML5, CSS3 (Custom Dark Theme for reduced eye strain).
* **Logic Engine:** Vanilla JavaScript (ES6+).
* **Data Processing:** Client-side CSV fuzzy-parsing algorithm.
* **Dependencies:** Zero external libraries or frameworks. 

### 2.2 Privacy & Data Security
Strict data governance was a primary architectural requirement. 
* The tool operates entirely within the Document Object Model (DOM). 
* Network captures are read into volatile browser memory and are **never** transmitted over the internet, preventing the accidental exposure of sensitive IP addresses or payload headers to external servers or telemetry platforms.
* Cross-Site Scripting (XSS) protections are built into the data rendering pipeline to sanitize untrusted CSV inputs.

---

<div align="center">

<img width="700" height="500" alt="image" src="https://github.com/user-attachments/assets/cb053600-6557-4f83-9e32-a811f84484b3" />

</div>

---

## 3. Core Detection Capabilities

The custom Javascript analysis engine evaluates parsed traffic against seven core behavioral metrics. Thresholds are dynamically configurable by the analyst to account for varying network baseline behaviors.

### 3.1 High-Volume & Scanning Detections
* **High Packet Volume:** Identifies hosts exceeding standard baseline transmission rates, prompting investigation into data exfiltration, automated scripts, or legitimate bulk file transfers.
* **Network Scanning Behavior:** Flags sources communicating with highly abnormal quantities of unique IP addresses, indicative of subnet discovery (e.g., Nmap ping sweeps).
* **Port Scanning Behavior:** Extracts port data from packet info headers to identify service enumeration against targeted assets.

### 3.2 Protocol-Specific Anomalies
* **ICMP Anomalies:** Tracks excessive Internet Control Message Protocol (ICMP) echo requests, highlighting potential internal network mapping or persistent monitoring.
* **DNS Query Spikes:** Monitors Domain Name System (DNS) request volume to flag rapid automated lookups, often associated with malware beaconing or Domain Generation Algorithms (DGA).
* **TCP SYN Heavy Activity:** Evaluates incomplete TCP handshakes to identify aggressive scanning or SYN flood behavior.

---

<div align="center">

<img width="700" height="800" alt="image" src="https://github.com/user-attachments/assets/5eef8737-e4f7-4bc6-8f4a-c0da3dc1972d" />

</div>

---

## 4. Investigative Philosophy & Scoring

Rather than utilizing arbitrary "Malicious Confidence" percentages, the tool implements an **Investigation Score**. 

For example, a host generating high packet volume (+20 points) while simultaneously pinging 30 unique internal destinations (+30 points) generates a cumulative Investigation Score. The analyst is immediately presented with:
1. **The Observed Evidence** (e.g., "Contacted 27 unique destinations").
2. **Context** (Why this behavior matters in a SOC environment).
3. **Benign Explanations** (e.g., Authorized asset discovery tools, vulnerability scanners).
4. **Actionable Next Steps** (e.g., Verify source IP authorization, review endpoint telemetry).

---

## 5. Limitations & Future Development

* **Data Format Constraints:** Version 1 relies on Wireshark CSV exports, which lack the deep packet inspection (DPI) capabilities of raw `.pcap` analysis. 
* **Encryption Blindspots:** Encrypted payloads (TLS/SSL) restrict visibility to header-level analysis, necessitating correlation with endpoint logs.
* **Future Roadmap:** Planned iterations include direct WebAssembly-based PCAP parsing, dynamic time-window (packets-per-second) baseline generation, and exportable forensic PDF reports.

## 6. Conclusion

The Network Traffic Triage Tool successfully bridges the gap between raw data ingestion and analytical triage. By enforcing a strict client-side privacy model and prioritizing transparent, actionable intelligence over opaque alerting, it serves as a highly effective utility for rapid localized network assessment and analyst training.

---
Note: The IP addresses does not belong to anyone, they are mock ip addresses.
