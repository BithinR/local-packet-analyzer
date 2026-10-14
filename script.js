// --- DOM Elements ---
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const uploadBtn = document.getElementById('upload-btn');
const uploadStatus = document.getElementById('upload-status');
const dashboard = document.getElementById('dashboard');
const filterInput = document.getElementById('alert-filter');

// --- Demo Data ---
const demoNormal = `No.,Time,Source,Destination,Protocol,Length,Info
1,0.00,192.168.1.10,8.8.8.8,DNS,74,Standard query 0x1a2b A www.google.com
2,0.01,8.8.8.8,192.168.1.10,DNS,90,Standard query response 0x1a2b A 142.250.190.36
3,0.05,192.168.1.10,142.250.190.36,TCP,66,54321 > 443 [SYN] Seq=0 Win=64240 Len=0
4,0.08,142.250.190.36,192.168.1.10,TCP,66,443 > 54321 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0
5,0.09,192.168.1.10,142.250.190.36,TCP,54,54321 > 443 [ACK] Seq=1 Ack=1 Win=65535 Len=0
6,0.10,192.168.1.10,142.250.190.36,TLSv1.2,125,Application Data
7,0.15,142.250.190.36,192.168.1.10,TLSv1.2,250,Application Data`;

const demoHighVolume = `No.,Time,Source,Destination,Protocol,Length,Info\n` + 
    Array.from({length: 60}, (_, i) => `${i+1},0.${i},192.168.1.50,10.0.0.5,TCP,1500,4444 > 80 [ACK] Seq=${i} Ack=1 Len=1446`).join('\n');

const demoMixed = `No.,Time,Source,Destination,Protocol,Length,Info
1,0.01,192.168.1.100,192.168.1.1,ICMP,74,Echo (ping) request
2,0.02,192.168.1.100,192.168.1.2,ICMP,74,Echo (ping) request
3,0.03,192.168.1.100,192.168.1.3,ICMP,74,Echo (ping) request
4,0.04,192.168.1.100,192.168.1.4,ICMP,74,Echo (ping) request
5,0.05,192.168.1.100,192.168.1.5,ICMP,74,Echo (ping) request
6,0.06,192.168.1.100,192.168.1.6,ICMP,74,Echo (ping) request
7,0.07,192.168.1.100,192.168.1.7,ICMP,74,Echo (ping) request
8,0.08,192.168.1.100,192.168.1.8,ICMP,74,Echo (ping) request
9,0.09,192.168.1.100,192.168.1.9,ICMP,74,Echo (ping) request
10,0.10,192.168.1.100,192.168.1.10,ICMP,74,Echo (ping) request
11,0.11,192.168.1.100,192.168.1.11,ICMP,74,Echo (ping) request
12,0.12,192.168.1.100,192.168.1.12,ICMP,74,Echo (ping) request
13,0.13,10.0.0.5,8.8.8.8,DNS,85,Standard query A malware.com
14,0.14,10.0.0.5,8.8.8.8,DNS,85,Standard query A botnet.com
15,0.15,10.0.0.5,8.8.8.8,DNS,85,Standard query A c2.com\n` + 
Array.from({length: 45}, (_, i) => `${i+16},0.${i+20},172.16.0.15,192.168.1.200,TCP,66,5555 > 22 [SYN] Seq=0 Win=64240 Len=0`).join('\n') + '\n' +
Array.from({length: 35}, (_, i) => `${i+61},0.${i+60},192.168.1.50,8.8.8.8,ICMP,74,Echo (ping) request`).join('\n');


// --- Security: HTML Sanitization ---
// Prevents malicious CSV data from executing scripts in the browser
function sanitize(str) {
    if (!str) return 'Unknown';
    const div = document.createElement('div');
    div.textContent = str.trim();
    return div.innerHTML;
}

// --- Event Listeners ---
uploadBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});

document.getElementById('btn-normal').addEventListener('click', () => processCSVText(demoNormal, "Demo: Normal Traffic"));
document.getElementById('btn-high-volume').addEventListener('click', () => processCSVText(demoHighVolume, "Demo: High Volume"));
document.getElementById('btn-mixed').addEventListener('click', () => processCSVText(demoMixed, "Demo: Mixed SOC Lab"));
document.getElementById('btn-reset').addEventListener('click', () => {
    document.getElementById('thresh-packets').value = 50;
    document.getElementById('thresh-destinations').value = 10;
    document.getElementById('thresh-ports').value = 10;
    document.getElementById('thresh-icmp').value = 30;
    document.getElementById('thresh-dns').value = 30;
    document.getElementById('thresh-repeated').value = 40;
});

// --- File Handling & Parsing ---
function handleFile(file) {
    if (!file) return;
    if (!file.name.endsWith('.csv')) {
        uploadStatus.innerHTML = `<span style="color: var(--alert-high)">Error: Please upload a .csv file. PCAP files are not supported in Version 1.</span>`;
        return;
    }
    uploadStatus.textContent = `Reading ${file.name}...`;
    
    const reader = new FileReader();
    reader.onload = (e) => processCSVText(e.target.result, file.name);
    reader.readAsText(file);
}

function processCSVText(csvText, filename) {
    try {
        const lines = csvText.split('\n').filter(line => line.trim() !== '');
        if (lines.length < 2) throw new Error("CSV file is empty or missing data.");

        // Fuzzy Column Matching
        const headers = lines[0].toLowerCase().split(',').map(h => h.trim().replace(/"/g, ''));
        const idx = {
            src: headers.findIndex(h => h === 'source' || h === 'src' || h === 'ip.src'),
            dst: headers.findIndex(h => h === 'destination' || h === 'dst' || h === 'ip.dst'),
            proto: headers.findIndex(h => h === 'protocol' || h === 'proto'),
            info: headers.findIndex(h => h === 'info' || h === 'information')
        };

        if (idx.src === -1) throw new Error("Could not identify a Source column.");
        if (idx.dst === -1) throw new Error("Could not identify a Destination column.");

        let packets = [];
        // Basic CSV parsing (handles simple commas, ignores complex quoting for performance/simplicity)
        for (let i = 1; i < lines.length; i++) {
            // Regex splits by comma unless inside quotes
            const cols = lines[i].split(/,(?=(?:(?:[^"]*"){2})*[^"]*$)/);
            if (cols.length > Math.max(idx.src, idx.dst)) {
                packets.push({
                    src: cols[idx.src]?.replace(/"/g, ''),
                    dst: cols[idx.dst]?.replace(/"/g, ''),
                    proto: cols[idx.proto] ? cols[idx.proto].replace(/"/g, '') : 'Unknown',
                    info: cols[idx.info] ? cols[idx.info].replace(/"/g, '') : ''
                });
            }
        }

        uploadStatus.innerHTML = `<span style="color: #10b981;">Successfully parsed ${sanitize(filename)} (${packets.length} packets loaded).</span>`;
        analyzeTraffic(packets);

    } catch (err) {
        uploadStatus.innerHTML = `<span style="color: var(--alert-high)">Error: ${sanitize(err.message)}</span>`;
    }
}

// --- Analysis Engine ---
function analyzeTraffic(packets) {
    const stats = {
        total: packets.length,
        sources: {},
        destinations: {},
        protocols: {}
    };

    // Tally Phase
    packets.forEach(p => {
        const src = p.src;
        const dst = p.dst;
        const proto = p.proto.toUpperCase();
        const info = p.info;

        // Protocols
        stats.protocols[proto] = (stats.protocols[proto] || 0) + 1;
        
        // Destinations
        stats.destinations[dst] = (stats.destinations[dst] || 0) + 1;

        // Sources
        if (!stats.sources[src]) {
            stats.sources[src] = { 
                count: 0, 
                dests: new Set(), 
                ports: new Set(),
                icmp: 0, 
                dns: 0, 
                syn: 0,
                targetCounts: {}
            };
        }
        
        const s = stats.sources[src];
        s.count++;
        s.dests.add(dst);
        
        s.targetCounts[dst] = (s.targetCounts[dst] || 0) + 1;

        if (proto === 'ICMP') s.icmp++;
        if (proto === 'DNS') s.dns++;
        if (proto === 'TCP' && info.includes('[SYN]') && !info.includes('[SYN, ACK]')) s.syn++;

        // Basic port extraction from Info (e.g. "443 > 50123")
        const portMatch = info.match(/(\d{1,5})\s*>\s*(\d{1,5})/);
        if (portMatch) {
            s.ports.add(portMatch[2]); // Destination port
        }
    });

    renderDashboard(stats);
    runDetectionRules(stats);
}

function runDetectionRules(stats) {
    // Get thresholds
    const tPackets = parseInt(document.getElementById('thresh-packets').value) || 50;
    const tDests = parseInt(document.getElementById('thresh-destinations').value) || 10;
    const tPorts = parseInt(document.getElementById('thresh-ports').value) || 10;
    const tIcmp = parseInt(document.getElementById('thresh-icmp').value) || 30;
    const tDns = parseInt(document.getElementById('thresh-dns').value) || 30;
    const tRepeated = parseInt(document.getElementById('thresh-repeated').value) || 40;

    const alerts = [];

    for (const [src, data] of Object.entries(stats.sources)) {
        let score = 0;
        let hostAlerts = [];

        // Rule 1: High Packet Volume
        if (data.count > tPackets) {
            score += 20;
            hostAlerts.push(createAlertObj('HIGH PACKET VOLUME', 'Low', src, null, 
                `Generated ${data.count} packets (Threshold: ${tPackets})`,
                'A host generating significantly more traffic than expected may warrant investigation.',
                ['Legitimate file transfer', 'Software updates', 'Backups', 'Automated scripts'],
                'Identify the host and verify if high data transfer is expected.'
            ));
        }

        // Rule 2: Possible Host Scanning
        if (data.dests.size > tDests) {
            score += 30;
            hostAlerts.push(createAlertObj('POSSIBLE NETWORK SCANNING', 'Medium', src, null,
                `Contacted ${data.dests.size} unique destinations (Threshold: ${tDests})`,
                'A single host communicating with many destination systems over a short capture may indicate network discovery.',
                ['Network management software', 'Asset discovery tools', 'Vulnerability scanners'],
                'Check if the source is an authorised scanner. Review the destination ports being targeted.'
            ));
        }

        // Rule 3: Possible Port Scanning
        if (data.ports.size > tPorts) {
            score += 30;
            hostAlerts.push(createAlertObj('POSSIBLE PORT SCANNING', 'Medium', src, null,
                `Contacted ${data.ports.size} unique destination ports (Threshold: ${tPorts})`,
                'Attempting to connect to many different ports can indicate service discovery or vulnerability scanning.',
                ['Active FTP/P2P software', 'Complex legitimate applications', 'IT discovery tools'],
                'Review the exact ports targeted. Sequential ports (80, 81, 82) strongly suggest a scanner.'
            ));
        }

        // Rule 4: High ICMP
        if (data.icmp > tIcmp) {
            score += 15;
            hostAlerts.push(createAlertObj('HIGH ICMP ACTIVITY', 'Low', src, null,
                `Generated ${data.icmp} ICMP packets (Threshold: ${tIcmp})`,
                'Unusual ping activity can be used for network mapping or maintaining persistence.',
                ['IT troubleshooting', 'Network monitoring systems (e.g. SolarWinds)'],
                'Determine if the host belongs to the IT team. Check if the pings are targeted at one host or sweeping a subnet.'
            ));
        }

        // Rule 5: High DNS
        if (data.dns > tDns) {
            score += 20;
            hostAlerts.push(createAlertObj('HIGH DNS QUERY ACTIVITY', 'Medium', src, null,
                `Generated ${data.dns} DNS packets (Threshold: ${tDns})`,
                'Rapid DNS requests can indicate malware beaconing, domain generation algorithms (DGA), or data exfiltration.',
                ['Normal heavy browsing', 'Software updates resolving CDNs', 'Active Directory background noise'],
                'Look at the actual domains being requested. Are they known services or random characters?'
            ));
        }

        // Rule 6: Repeated Source-to-Destination
        for (const [dst, count] of Object.entries(data.targetCounts)) {
            if (count > tRepeated) {
                hostAlerts.push(createAlertObj('REPEATED COMMUNICATION', 'Informational', src, dst,
                    `Sent ${count} packets to ${dst} (Threshold: ${tRepeated})`,
                    'Sustained communication between two endpoints can represent data transfer or automated beaconing.',
                    ['Streaming media', 'Database connections', 'File downloads'],
                    'Identify the protocol used. Check if this communication occurs regularly or is an isolated event.'
                ));
            }
        }

        // Rule 7: TCP SYN Heavy
        if (data.syn > 20) { // Hardcoded sane threshold for SYN activity
            score += 40;
            hostAlerts.push(createAlertObj('HIGH TCP SYN ACTIVITY', 'High', src, null,
                `Generated ${data.syn} TCP SYN packets without establishing connections.`,
                'A high volume of SYN packets without completing the handshake indicates aggressive scanning or a SYN flood.',
                ['Connecting to an offline service', 'Aggressive application retry logic'],
                'Look for corresponding SYN/ACK responses. If none exist, the target is ignoring or dropping the traffic.'
            ));
        }

        // Apply Investigation Score to all alerts for this host
        hostAlerts.forEach(a => {
            a.score = score;
            alerts.push(a);
        });
    }

    renderAlerts(alerts);
}

function createAlertObj(name, severity, src, dst, evidence, why, benign, investigation) {
    return { name, severity, src, dst, evidence, why, benign, investigation };
}

// --- UI Rendering ---
function renderDashboard(stats) {
    dashboard.classList.remove('hidden');

    document.getElementById('stat-total-packets').textContent = stats.total;
    document.getElementById('stat-unique-sources').textContent = Object.keys(stats.sources).length;
    document.getElementById('stat-unique-destinations').textContent = Object.keys(stats.destinations).length;
    
    // Sort logic
    const sortedSources = Object.entries(stats.sources).sort((a, b) => b[1].count - a[1].count).slice(0, 10);
    const sortedDests = Object.entries(stats.destinations).sort((a, b) => b[1] - a[1]).slice(0, 10);
    const sortedProtos = Object.entries(stats.protocols).sort((a, b) => b[1] - a[1]);

    if(sortedProtos.length > 0) document.getElementById('stat-top-protocol').textContent = sortedProtos[0][0];

    document.getElementById('list-top-sources').innerHTML = sortedSources.map(s => 
        `<li><span>${sanitize(s[0])}</span> <span>${s[1].count} pkts</span></li>`).join('');
    
    document.getElementById('list-top-destinations').innerHTML = sortedDests.map(d => 
        `<li><span>${sanitize(d[0])}</span> <span>${d[1]} pkts</span></li>`).join('');

    document.getElementById('list-protocols').innerHTML = sortedProtos.map(p => 
        `<li><span>${sanitize(p[0])}</span> <span>${p[1]} pkts</span></li>`).join('');
}

function renderAlerts(alerts) {
    const container = document.getElementById('alerts-container');
    if (alerts.length === 0) {
        container.innerHTML = '<div class="alert alert-info"><strong>No significant anomalies detected.</strong> The traffic levels fall below the configured thresholds.</div>';
        return;
    }

    // Sort High to Low
    const sevValue = { 'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0 };
    alerts.sort((a, b) => sevValue[b.severity] - sevValue[a.severity]);

    // Store alerts globally for filtering
    window.currentAlerts = alerts;
    displayFilteredAlerts(alerts);
}

function displayFilteredAlerts(alerts) {
    const container = document.getElementById('alerts-container');
    container.innerHTML = '';

    alerts.forEach(a => {
        const div = document.createElement('div');
        div.className = `alert alert-${a.severity.toLowerCase()}`;
        
        let targetText = a.dst ? ` ➔ ${sanitize(a.dst)}` : '';
        let scoreHTML = a.score > 0 ? `<div class="score-badge">Investigation Score: ${a.score}</div>` : '';

        div.innerHTML = `
            <div class="alert-header">
                <span class="alert-title">${sanitize(a.name)}</span>
                <span class="severity-badge badge-${a.severity.toLowerCase()}">${sanitize(a.severity)}</span>
            </div>
            <div class="alert-body">
                <p><strong>Source:</strong> <span style="color:var(--text-main)">${sanitize(a.src)}${targetText}</span></p>
                <p><strong>Observed Activity:</strong> ${sanitize(a.evidence)}</p>
                ${scoreHTML}
                
                <div class="alert-section-title">Why this could matter</div>
                <p>${sanitize(a.why)}</p>
                
                <div class="alert-section-title">Possible benign explanations</div>
                <ul class="alert-list">
                    ${a.benign.map(b => `<li>${sanitize(b)}</li>`).join('')}
                </ul>
                
                <div class="alert-section-title">Suggested investigation</div>
                <p>${sanitize(a.investigation)}</p>
            </div>
        `;
        container.appendChild(div);
    });
}

// Simple Filter function
filterInput.addEventListener('input', (e) => {
    const term = e.target.value.toLowerCase();
    if (!window.currentAlerts) return;
    
    const filtered = window.currentAlerts.filter(a => 
        a.src.toLowerCase().includes(term) || 
        (a.dst && a.dst.toLowerCase().includes(term)) ||
        a.severity.toLowerCase().includes(term) ||
        a.name.toLowerCase().includes(term)
    );
    displayFilteredAlerts(filtered);
});