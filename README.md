<div align="center">

# 🚨 Network Traffic Triage Tool

**Browser-Based Security Operations Center (SOC) Analytics Lab**

</div>

<p align="center">
  <img src="https://img.shields.io/badge/Skill-Cybersecurity-404040?style=flat-square&labelColor=C00000" />
  <img src="https://img.shields.io/badge/Language-JavaScript%20(Vanilla)-F7DF1E?style=flat-square&labelColor=000000&logo=javascript&logoColor=yellow" />
  <img src="https://img.shields.io/badge/Language-HTML5%20%7C%20CSS3-E34F26?style=flat-square&labelColor=000000" />
  <img src="https://img.shields.io/badge/Privacy-100%25%20Client--Side-10B981?style=flat-square&labelColor=000000" />
  <img src="https://img.shields.io/badge/Status-Completed-238F89?style=flat-square&labelColor=000000" />
</p>

---

<div align="center">

<img width="282" height="407" alt="image" src="https://github.com/user-attachments/assets/87281c20-a66b-487b-92dc-0c9c15a08e66" />

</div>

---

## 📌 The Scenario & Project Purpose

When learning network defense, analysts often struggle to bridge the gap between staring at raw Wireshark packets and understanding *why* a specific pattern matters. 

I engineered this **Network Traffic Triage Tool** to simulate a simplified SOC triage workflow. Users can upload a CSV of network traffic, and the custom rule-based JavaScript engine will highlight anomalies (like potential port scanning or high ICMP volume). 

Most importantly, every alert explains **why it matters**, lists **possible benign explanations**, and provides **suggested investigation steps**, reinforcing the core cybersecurity philosophy: *An anomaly is a starting point for investigation, not proof of an attack.*

**Live Interactive Demo:** [🔗 Insert Your GitHub Pages URL Here]

---

## 🏗️ Architecture & Privacy Guarantee

This application was built entirely from scratch without frameworks (No React, No Node.js, No backend databases). 

**Zero-Data-Leakage Design:** All parsing, statistical analysis, and rule evaluations happen **100% locally in the user's web browser**. 
* 🚫 No data is sent to a server.
* 🚫 No external APIs or AI endpoints are used.
* 🚫 No cookies, telemetry, or analytics.

This strict client-side architecture ensures that sensitive `.pcap` / `CSV` network data never leaves the user's device, making it safe for isolated enterprise environments.

---

<div align="center">
  
<img width="392" height="175" alt="image" src="https://github.com/user-attachments/assets/748003bf-8055-48d5-8e70-729f34a73087" />


</div>

---

## ⚙️ Detection Engine Rules

The tool applies an explainable rule-based engine utilizing configurable thresholds. 

| Detection Module | Default Threshold | Analytic Focus |
|---|---|---|
| **High Packet Volume** | > 50 Packets | Identifies anomalous data transfers, automated scripts, or backups. |
| **Network Scanning** | > 10 Unique Dsts | Flags potential host discovery or vulnerability sweep behavior. |
| **Port Scanning** | > 10 Unique Ports | Identifies service enumeration against a single target. |
| **High ICMP Activity** | > 30 Packets | Detects ping sweeps, heavy monitoring, or potential DoS activity. |
| **High DNS Activity** | > 30 Queries | Flags rapid resolution activity, potential beaconing, or DGA. |
| **Repeated Comms** | > 40 Packets | Highlights sustained connections for baseline comparison. |
| **TCP SYN Heavy** | Configurable | Identifies aggressive connection attempts or SYN flood behavior. |

*Note: Thresholds can be dynamically adjusted in the UI based on the specific network environment.*

---

## 🚀 How to Run Locally

1. Clone or download this repository.
2. Ensure `index.html`, `styles.css`, and `script.js` are in the same directory.
3. Double-click `index.html` to open it in any modern web browser.
4. Export a Wireshark capture as a CSV (`File > Export Packet Dissections > As CSV...`) and upload it to the tool.

---

## ⚠️ Educational Disclaimer

This tool is designed for educational triage and does not replace enterprise Intrusion Detection Systems (IDS) like Snort or Suricata, nor does it replace professional SIEM monitoring[cite: 2]. Alerts indicate activity worth investigating and do not definitively prove malicious behavior. All activities must be performed exclusively on authorized targets or captured traffic you own[cite: 1, 2].

---

## 👤 Author

**Bithin Krishna Radhakrishnan**[cite: 1, 2]
Cybersecurity Professional & Developer

* LinkedIn: [Insert URL]
* GitHub: [Insert URL]
