/**
 * AegisMobile DBN-IDS - Core Application Engine
 * Underpins the DBN simulation, training, analytics, and network visualizer.
 */

document.addEventListener('DOMContentLoaded', () => {
    // -------------------------------------------------------------------------
    // 1. STATE & ROUTING MANAGEMENT
    // -------------------------------------------------------------------------
    const state = {
        activeTab: 'dashboard',
        isTrafficSimulating: false,
        trafficInterval: null,
        trafficRate: 15, // Packets/sec
        totalPackets: 0,
        threatsDetected: 0,
        currentScenario: 'normal',
        confidenceScore: 98.4,
        
        // DBN Engine parameters (simulated inputs)
        hyperparameters: {
            layers: 3,
            neuronsStr: '64, 32, 16',
            learningRate: 0.01,
            epochs: 100,
            activation: 'sigmoid'
        },
        
        // Interactive Network State
        network: {
            nodes: [],
            connections: [],
            selectedLayer: null,
            animOffset: 0
        },
        
        // Confusion Matrix Counts
        cm: {
            tn: 1420,
            fp: 12,
            fn: 21,
            tp: 547
        },
        
        // Telemetry tracking
        threatDistribution: {
            normal: 1441,
            imsi: 210,
            smishing: 155,
            ddos: 182
        }
    };

    // DOM Navigation elements
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');
    const viewTitle = document.getElementById('view-title');
    const viewSubtitle = document.getElementById('view-subtitle');

    // Tab Switcher Router
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = item.getAttribute('data-tab');
            
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            tabContents.forEach(content => {
                content.classList.remove('active');
                if (content.id === targetTab) {
                    content.classList.add('active');
                }
            });

            state.activeTab = targetTab;
            updateHeader(targetTab);
            
            // Trigger specific canvas resizing or chart drawing when views change
            if (targetTab === 'architecture') {
                initNetworkCanvas();
            } else if (targetTab === 'analytics') {
                renderAnalyticsCharts();
            }
        });
    });

    function updateHeader(tab) {
        const titles = {
            dashboard: { title: "SOC Dashboard", subtitle: "Real-time mobile network intrusion detection and telemetry analysis" },
            architecture: { title: "DBN Model Architecture", subtitle: "Visualizing stacked Restricted Boltzmann Machines (RBM) and activation logs" },
            simulator: { title: "Training Sandbox", subtitle: "Tune network configurations and pre-train DBN model with mobile signatures" },
            analytics: { title: "IDS Analytics & Metrics", subtitle: "In-depth performance evaluation, classification matrix, and ROC sensitivity curves" },
            reference: { title: "Project Thesis & Documentation", subtitle: "Full academic specifications, RBM mathematics, and SS7/RAN threat assessments" }
        };
        
        if (titles[tab]) {
            viewTitle.textContent = titles[tab].title;
            viewSubtitle.textContent = titles[tab].subtitle;
        }
    }

    // Docs navigation scrollspy behavior
    const docLinks = document.querySelectorAll('.docs-menu-item a');
    const docSections = document.querySelectorAll('.docs-section');
    
    docLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href');
            const targetSec = document.querySelector(targetId);
            
            docSections.forEach(sec => sec.scrollIntoView({ behavior: 'smooth' })); // Simple smooth scroll mockup
            targetSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
            
            document.querySelectorAll('.docs-menu-item').forEach(li => li.classList.remove('active'));
            link.parentElement.classList.add('active');
        });
    });

    // -------------------------------------------------------------------------
    // 2. LIVE TRAFFIC & IDS SIMULATION
    // -------------------------------------------------------------------------
    const simTriggerBtn = document.getElementById('sim-trigger-btn');
    const scenarioSelect = document.getElementById('scenarioSelect');
    const applyScenarioBtn = document.getElementById('apply-scenario-btn');
    
    // Stats displays
    const statPacketRate = document.getElementById('stat-packet-rate');
    const statTotalPackets = document.getElementById('stat-total-packets');
    const statThreatsDetected = document.getElementById('stat-threats-detected');
    const threatFooterPercentage = document.getElementById('threat-footer-percentage');
    const logStream = document.getElementById('logStream');

    simTriggerBtn.addEventListener('click', () => {
        if (state.isTrafficSimulating) {
            stopTrafficSimulation();
        } else {
            startTrafficSimulation();
        }
    });

    applyScenarioBtn.addEventListener('click', () => {
        state.currentScenario = scenarioSelect.value;
        addLogLine("warning", "SYSTEM CONFIG", `Scenario preset updated to: [${state.currentScenario.toUpperCase()}]`);
        if (!state.isTrafficSimulating) {
            startTrafficSimulation();
        }
    });

    function startTrafficSimulation() {
        state.isTrafficSimulating = true;
        simTriggerBtn.innerHTML = '<i class="fa-solid fa-pause"></i> <span>Pause Traffic</span>';
        simTriggerBtn.classList.remove('btn-primary');
        simTriggerBtn.classList.add('btn-danger');
        addLogLine("normal", "IDS CORE", "Real-time cellular traffic capture interface bound successfully. Analyzing...");
        
        state.trafficInterval = setInterval(generatePacketInference, 1000 / state.trafficRate);
    }

    function stopTrafficSimulation() {
        state.isTrafficSimulating = false;
        simTriggerBtn.innerHTML = '<i class="fa-solid fa-play"></i> <span>Start Live Traffic</span>';
        simTriggerBtn.classList.remove('btn-danger');
        simTriggerBtn.classList.add('btn-primary');
        addLogLine("warning", "IDS CORE", "Traffic ingestion paused by operator.");
        clearInterval(state.trafficInterval);
        statPacketRate.textContent = "0 /s";
    }

    // Mobile Packet Generation Telemetry generator
    function generatePacketInference() {
        state.totalPackets++;
        statTotalPackets.textContent = state.totalPackets.toLocaleString();
        
        // Random variance in packet rate display
        const varianceRate = Math.floor(state.trafficRate + (Math.random() * 6 - 3));
        statPacketRate.textContent = `${varianceRate} /s`;

        let packet = {
            timestamp: new Date().toISOString().split('T')[1].slice(0, 12),
            signal: Math.floor(-85 - (Math.random() * 20)),
            lac: Math.floor(4000 + Math.random() * 100),
            cellId: Math.floor(10000 + Math.random() * 5000),
            protocol: "LTE-RAN",
            entropy: (Math.random() * 1.5 + 2.0).toFixed(2),
            status: "normal",
            confidence: (96 + Math.random() * 3.8).toFixed(2),
            message: "Radio Connection Request (RRC_CONN_REQ)"
        };

        // Inject custom profile values depending on user configuration
        const activeScenario = state.currentScenario === 'mixed' ? getRandomScenario() : state.currentScenario;

        if (activeScenario === 'imsi') {
            // Stingray catcher impersonation
            if (Math.random() > 0.4) {
                packet.signal = Math.floor(-50 - (Math.random() * 8)); // Exceedingly strong signal strength override
                packet.lac = 9999; // Rogue LAC signature
                packet.protocol = "GSM-A (A5/0 Bypass)";
                packet.entropy = (Math.random() * 0.5 + 0.1).toFixed(2); // Low payload complexity (downgraded mode)
                packet.status = "imsi";
                packet.confidence = (94 + Math.random() * 5.2).toFixed(2);
                packet.message = "Alert! Forced fallback link cipher bypass configuration initiated.";
            }
        } else if (activeScenario === 'smishing') {
            // Spam sms phishing payloads
            if (Math.random() > 0.5) {
                packet.protocol = "MAP-SMS";
                packet.entropy = (Math.random() * 2.5 + 4.8).toFixed(2); // High payload complexity / keywords
                packet.status = "smishing";
                packet.confidence = (97 + Math.random() * 2.1).toFixed(2);
                packet.message = "SMS Content: 'Confirm your banking card security credentials at https://auth-mobile.net/verify'";
            }
        } else if (activeScenario === 'ddos') {
            // Signaling overload (SS7 / Diameter query storms)
            if (Math.random() > 0.2) {
                packet.protocol = "Diameter-S6a";
                packet.signal = -95;
                packet.entropy = (Math.random() * 1.0 + 1.5).toFixed(2);
                packet.status = "ddos";
                packet.confidence = (95 + Math.random() * 4.3).toFixed(2);
                packet.message = "Bulk SendRoutingInfoForSM requests. Rate: 420 req/s. Memory exhaustion risk.";
            }
        }

        // Process Prediction through DBN Simulator
        runDbnInferenceSimulation(packet);
    }

    function getRandomScenario() {
        const list = ['normal', 'normal', 'imsi', 'smishing', 'ddos'];
        return list[Math.floor(Math.random() * list.length)];
    }

    function runDbnInferenceSimulation(packet) {
        const isAnomaly = packet.status !== 'normal';
        let logClass = "normal";
        let tag = "NORMAL";
        let message = `Packet verified. Signal: ${packet.signal}dBm, Cell: [LAC:${packet.lac}, ID:${packet.cellId}], Protocol: ${packet.protocol}. DBN reconstruction error normal.`;

        if (isAnomaly) {
            state.threatsDetected++;
            statThreatsDetected.textContent = state.threatsDetected.toLocaleString();
            logClass = "alert";
            
            if (packet.status === 'imsi') {
                tag = "IMSI MITM";
                message = `CRITICAL DETECT: [Rogue Base Station Impersonation] - Signal strength jump to ${packet.signal}dBm under LAC ${packet.lac} with unencrypted protocol.`;
                state.cm.tp++;
                state.threatDistribution.imsi++;
            } else if (packet.status === 'smishing') {
                tag = "SMISHING";
                message = `ALERT: [Smishing Signature Detected] - Message text payload entropy (${packet.entropy}) contains financial verification phishing URLs.`;
                state.cm.tp++;
                state.threatDistribution.smishing++;
            } else if (packet.status === 'ddos') {
                tag = "SIGNAL DDOS";
                message = `WARN: [S6a Signaling Storm] - Volumetric roam queries exceed threshold. Node buffer threat. Rate: ${packet.entropy} requests/burst.`;
                state.cm.tp++;
                state.threatDistribution.ddos++;
            }
            
            // Random false negatives/positives to match real classifier percentages
            if (Math.random() < 0.015) {
                state.cm.fn++;
            }
        } else {
            state.threatDistribution.normal++;
            state.cm.tn++;
            if (Math.random() < 0.008) {
                state.cm.fp++;
                logClass = "warning";
                tag = "FALSE ALARM";
                message = `FALSE ALARM: DBN misclassified high-velocity handover signal as packet anomalies (Confidence ${packet.confidence}%).`;
            }
        }

        // Update threat rate text
        const threatPct = ((state.threatsDetected / state.totalPackets) * 100).toFixed(1);
        threatFooterPercentage.innerHTML = `<span>${threatPct}%</span> anomaly rate`;

        // Render line log
        addLogLine(logClass, tag, message, packet.timestamp, packet.confidence);

        // Update gauges and analytics
        updateThreatGauge(isAnomaly ? (80 + Math.random()*20) : (5 + Math.random()*15), tag);
        
        // Highlight active neuron connections in canvas if current tab is architecture
        if (state.activeTab === 'architecture') {
            pulseNeuralActivity(packet.status);
        }
    }

    function addLogLine(type, tag, msg, time = null, confidence = null) {
        const timestamp = time || new Date().toISOString().split('T')[1].slice(0, 12);
        const confText = confidence ? ` [Conf: ${confidence}%]` : "";
        
        const line = document.createElement('div');
        line.className = `log-line ${type}`;
        line.innerHTML = `
            <div class="log-meta">
                <span class="log-timestamp">[${timestamp}]</span>
                <span class="log-tag ${type}">${tag}</span>
            </div>
            <div class="log-msg">${msg}${confText}</div>
        `;
        
        logStream.appendChild(line);
        logStream.scrollTop = logStream.scrollHeight;

        // Cap log size to 100 items to avoid DOM overload
        if (logStream.children.length > 100) {
            logStream.removeChild(logStream.children[0]);
        }
    }

    // -------------------------------------------------------------------------
    // 3. THREAT INDEX GAUGE RENDERING
    // -------------------------------------------------------------------------
    const gaugeCanvas = document.getElementById('gaugeCanvas');
    const gaugeCtx = gaugeCanvas.getContext('2d');
    const gaugeValueText = document.getElementById('gaugeValue');
    const gaugeStatusText = document.getElementById('gaugeStatus');
    
    let currentGaugeVal = 0;
    let targetGaugeVal = 0;

    function updateThreatGauge(val, statusLabel) {
        targetGaugeVal = val;
        gaugeValueText.textContent = `${Math.floor(val)}%`;
        gaugeStatusText.textContent = statusLabel;

        if (statusLabel === 'NORMAL') {
            gaugeStatusText.style.color = 'var(--neon-green)';
            gaugeValueText.style.color = 'var(--neon-green)';
        } else if (statusLabel === 'FALSE ALARM' || statusLabel === 'SIGNAL DDOS') {
            gaugeStatusText.style.color = 'var(--neon-yellow)';
            gaugeValueText.style.color = 'var(--neon-yellow)';
        } else {
            gaugeStatusText.style.color = 'var(--neon-pink)';
            gaugeValueText.style.color = 'var(--neon-pink)';
        }
    }

    // Gauge Loop Animation
    function animateGauge() {
        // Linear interpolation
        currentGaugeVal += (targetGaugeVal - currentGaugeVal) * 0.1;
        
        const cx = gaugeCanvas.width / 2;
        const cy = gaugeCanvas.height - 10;
        const r = 85;

        gaugeCtx.clearRect(0, 0, gaugeCanvas.width, gaugeCanvas.height);

        // Draw track
        gaugeCtx.beginPath();
        gaugeCtx.arc(cx, cy, r, Math.PI, 2 * Math.PI);
        gaugeCtx.lineWidth = 10;
        gaugeCtx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
        gaugeCtx.stroke();

        // Draw filled arc
        const fillEndAngle = Math.PI + (Math.PI * (currentGaugeVal / 100));
        gaugeCtx.beginPath();
        gaugeCtx.arc(cx, cy, r, Math.PI, fillEndAngle);
        gaugeCtx.lineWidth = 10;

        // Choose color based on threat value
        let color = 'rgba(0, 242, 254, 0.8)'; // normal cyan
        if (currentGaugeVal > 40 && currentGaugeVal <= 75) {
            color = 'rgba(255, 215, 0, 0.8)'; // warning yellow
        } else if (currentGaugeVal > 75) {
            color = 'rgba(255, 0, 127, 0.8)'; // alert pink
        }
        
        gaugeCtx.strokeStyle = color;
        gaugeCtx.stroke();

        requestAnimationFrame(animateGauge);
    }
    animateGauge();

    // -------------------------------------------------------------------------
    // 4. DBN NEURAL NETWORK ARCHITECTURE VISUALIZER
    // -------------------------------------------------------------------------
    const networkCanvas = document.getElementById('networkCanvas');
    const netCtx = networkCanvas ? networkCanvas.getContext('2d') : null;
    
    function initNetworkCanvas() {
        if (!networkCanvas) return;

        // Fit canvas to parent element size
        const rect = networkCanvas.parentElement.getBoundingClientRect();
        networkCanvas.width = rect.width;
        networkCanvas.height = rect.height;

        const layersConfig = [8, 6, 4, 4]; // visible, hidden1, hidden2, class softmax
        const layerNames = ["Input Vector (Mobile Features)", "RBM Hidden Layer 1", "RBM Hidden Layer 2", "Inference softmax Out"];
        
        state.network.nodes = [];
        state.network.connections = [];

        const xGap = networkCanvas.width / (layersConfig.length + 1);

        for (let l = 0; l < layersConfig.length; l++) {
            const nodesCount = layersConfig[l];
            const yGap = networkCanvas.height / (nodesCount + 1);
            
            for (let n = 0; n < nodesCount; n++) {
                state.network.nodes.push({
                    id: `L${l}_N${n}`,
                    layerIndex: l,
                    nodeIndex: n,
                    x: xGap * (l + 1),
                    y: yGap * (n + 1),
                    r: l === 0 || l === layersConfig.length - 1 ? 12 : 9,
                    activation: 0.1 + Math.random() * 0.4,
                    pulseIntensity: 0
                });
            }
        }

        // Build connection weights
        for (let l = 0; l < layersConfig.length - 1; l++) {
            const currentNodes = state.network.nodes.filter(n => n.layerIndex === l);
            const nextNodes = state.network.nodes.filter(n => n.layerIndex === l + 1);

            currentNodes.forEach(cNode => {
                nextNodes.forEach(nNode => {
                    state.network.connections.push({
                        from: cNode,
                        to: nNode,
                        weight: (Math.random() * 2 - 1).toFixed(2),
                        active: false,
                        pulseProgress: 0
                    });
                });
            });
        }
        
        // Initial setup of layer details title
        updateLayerDetailsPanel(null);
        renderWeightHeatmap(8, 6);
    }

    function renderWeightHeatmap(rows, cols) {
        const heatmap = document.getElementById('weightHeatmap');
        if (!heatmap) return;
        
        heatmap.innerHTML = '';
        
        for (let i = 0; i < rows * cols; i++) {
            const cell = document.createElement('div');
            cell.className = 'heatmap-cell';
            const value = Math.random();
            cell.style.backgroundColor = `rgba(0, 242, 254, ${value})`;
            cell.title = `Weight index ${i}: ${(value * 2 - 1).toFixed(2)}`;
            heatmap.appendChild(cell);
        }
    }

    // Set interactive visual click triggers
    if (networkCanvas) {
        networkCanvas.addEventListener('mousedown', (e) => {
            const rect = networkCanvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;

            let nodeClicked = null;
            
            // Check node bounds
            state.network.nodes.forEach(node => {
                const dist = Math.hypot(node.x - mouseX, node.y - mouseY);
                if (dist <= node.r + 5) {
                    nodeClicked = node;
                }
            });

            if (nodeClicked) {
                updateLayerDetailsPanel(nodeClicked);
            }
        });
    }

    function updateLayerDetailsPanel(node) {
        const detailsTitle = document.getElementById('layer-details-title');
        const detailsDesc = document.getElementById('layer-details-desc');
        const dType = document.getElementById('detail-layer-type');
        const dNeurons = document.getElementById('detail-layer-neurons');
        const dStatus = document.getElementById('detail-layer-status');
        const dActivation = document.getElementById('detail-layer-activation');

        if (!node) {
            detailsTitle.textContent = "Global DBN Structure";
            detailsDesc.textContent = "Three Restricted Boltzmann Machines pre-trained greedily via Contrastive Divergence, mapped directly to a feedforward softmax network for intrusion sorting.";
            dType.textContent = "Stacked RBMs";
            dNeurons.textContent = "8 Vis ➔ 6 Hid ➔ 4 Hid ➔ 4 Class";
            dStatus.textContent = "Operating Inline";
            dActivation.textContent = "CD-k / Cross-Entropy";
            return;
        }

        const layerLabel = ["Visible Network Features", "RBM Stacking Layer 1", "RBM Stacking Layer 2", "Inference Softmax Layer"];
        detailsTitle.textContent = `Node: Layer ${node.layerIndex} (No. ${node.nodeIndex})`;
        dType.textContent = layerLabel[node.layerIndex];
        dNeurons.textContent = `Neuron ID: ${node.id}`;
        dStatus.textContent = "Active Telemetry";
        dActivation.textContent = node.layerIndex === 3 ? "Softmax" : "Sigmoid h(v)";

        const descriptions = [
            "Input nodes feeding 8 network measurements: signal power offsets, cell registration profiles, packet rates, and protocol metadata.",
            "RBM Layer 1: Learns primary correlations between raw signal values and protocol indicators. Focuses on low-level signal stability parameters.",
            "RBM Layer 2: Learns advanced joint distributions mapping combinations of signal changes and traffic behavior correlations.",
            "Softmax Layer: Standard output neurons providing threat probabilities: Normal (0), IMSI Catcher (1), SMS Smishing (2), DDoS (3)."
        ];
        
        detailsDesc.textContent = descriptions[node.layerIndex];
        
        // Re-draw weights corresponding to the selected layer sizes
        if (node.layerIndex === 0) renderWeightHeatmap(8, 6);
        if (node.layerIndex === 1) renderWeightHeatmap(6, 4);
        if (node.layerIndex === 2) renderWeightHeatmap(4, 4);
    }

    function pulseNeuralActivity(status) {
        // Highlight nodes corresponding to anomalies
        state.network.nodes.forEach(node => {
            if (node.layerIndex === 3) {
                // Softmax outputs mapping: 0=normal, 1=imsi, 2=smishing, 3=ddos
                if (status === 'normal' && node.nodeIndex === 0) node.pulseIntensity = 1.0;
                if (status === 'imsi' && node.nodeIndex === 1) node.pulseIntensity = 1.0;
                if (status === 'smishing' && node.nodeIndex === 2) node.pulseIntensity = 1.0;
                if (status === 'ddos' && node.nodeIndex === 3) node.pulseIntensity = 1.0;
            } else {
                // Input layers pulse randomly
                node.pulseIntensity = 0.5 + Math.random() * 0.5;
            }
        });

        // Trigger active pulses on connections
        state.network.connections.forEach(conn => {
            if (Math.random() > 0.4) {
                conn.active = true;
                conn.pulseProgress = 0;
            }
        });
    }

    // Neural Canvas Rendering Loop
    function drawNetworkVisuals() {
        if (state.activeTab !== 'architecture' || !netCtx) {
            requestAnimationFrame(drawNetworkVisuals);
            return;
        }

        netCtx.clearRect(0, 0, networkCanvas.width, networkCanvas.height);
        state.network.animOffset += 0.05;

        // Draw Layer Annotations
        const layerLabelText = ["Input Features", "RBM Hidden 1", "RBM Hidden 2", "Inference Out"];
        const xGap = networkCanvas.width / 5;
        
        netCtx.font = "bold 11px 'Space Grotesk'";
        netCtx.textAlign = "center";
        
        for (let l = 0; l < 4; l++) {
            netCtx.fillStyle = "var(--text-secondary)";
            netCtx.fillText(layerLabelText[l], xGap * (l + 1), 30);
            
            // Subtitle
            netCtx.font = "9px 'Plus Jakarta Sans'";
            netCtx.fillStyle = "var(--text-muted)";
            const counts = ["8 Vis Nodes", "6 Hidden Units", "4 Hidden Units", "4 Class Units"];
            netCtx.fillText(counts[l], xGap * (l + 1), 45);
            netCtx.font = "bold 11px 'Space Grotesk'";
        }

        // Draw connections (weights)
        state.network.connections.forEach(conn => {
            const weightVal = parseFloat(conn.weight);
            netCtx.beginPath();
            netCtx.moveTo(conn.from.x, conn.from.y);
            netCtx.lineTo(conn.to.x, conn.to.y);
            
            // Weight color (cyan positive, purple negative)
            let strokeColor = 'rgba(255, 255, 255, 0.04)';
            if (weightVal > 0) {
                strokeColor = `rgba(0, 242, 254, ${Math.min(0.2, weightVal * 0.15)})`;
            } else {
                strokeColor = `rgba(138, 43, 226, ${Math.min(0.2, Math.abs(weightVal) * 0.15)})`;
            }
            
            netCtx.strokeStyle = strokeColor;
            netCtx.lineWidth = 1;
            netCtx.stroke();

            // Draw floating activation pulse along the wire
            if (conn.active) {
                conn.pulseProgress += 0.02;
                if (conn.pulseProgress >= 1) {
                    conn.active = false;
                    conn.pulseProgress = 0;
                } else {
                    const px = conn.from.x + (conn.to.x - conn.from.x) * conn.pulseProgress;
                    const py = conn.from.y + (conn.to.y - conn.from.y) * conn.pulseProgress;
                    
                    netCtx.beginPath();
                    netCtx.arc(px, py, 2, 0, 2 * Math.PI);
                    netCtx.fillStyle = 'var(--neon-cyan)';
                    netCtx.shadowColor = 'var(--neon-cyan)';
                    netCtx.shadowBlur = 4;
                    netCtx.fill();
                    netCtx.shadowBlur = 0; // reset
                }
            }
        });

        // Draw Nodes
        state.network.nodes.forEach(node => {
            // Decay pulses
            if (node.pulseIntensity > 0) {
                node.pulseIntensity -= 0.02;
            } else {
                node.pulseIntensity = 0;
            }

            netCtx.beginPath();
            netCtx.arc(node.x, node.y, node.r, 0, 2 * Math.PI);
            
            // Neon glow matching node types
            let nodeFill = 'rgba(13, 20, 38, 0.9)';
            let nodeStroke = 'rgba(255, 255, 255, 0.2)';
            
            if (node.layerIndex === 0) {
                nodeStroke = 'rgba(0, 242, 254, 0.4)';
                if (node.pulseIntensity > 0) {
                    nodeFill = `rgba(0, 242, 254, ${node.pulseIntensity * 0.3})`;
                    nodeStroke = 'var(--neon-cyan)';
                }
            } else if (node.layerIndex === 3) {
                // soft max outputs coloring
                if (node.nodeIndex === 0) nodeStroke = 'rgba(57, 255, 20, 0.4)'; // normal
                if (node.nodeIndex === 1) nodeStroke = 'rgba(255, 0, 127, 0.4)'; // imsi
                if (node.nodeIndex === 2) nodeStroke = 'rgba(255, 0, 127, 0.4)'; // smishing
                if (node.nodeIndex === 3) nodeStroke = 'rgba(255, 215, 0, 0.4)'; // ddos
                
                if (node.pulseIntensity > 0) {
                    const color = node.nodeIndex === 0 ? '57, 255, 20' : (node.nodeIndex === 3 ? '255, 215, 0' : '255, 0, 127');
                    nodeFill = `rgba(${color}, ${node.pulseIntensity * 0.4})`;
                    nodeStroke = `rgb(${color})`;
                }
            } else {
                nodeStroke = 'rgba(138, 43, 226, 0.4)';
                if (node.pulseIntensity > 0) {
                    nodeFill = `rgba(138, 43, 226, ${node.pulseIntensity * 0.3})`;
                    nodeStroke = 'var(--neon-purple)';
                }
            }

            netCtx.fillStyle = nodeFill;
            netCtx.fill();
            netCtx.strokeStyle = nodeStroke;
            netCtx.lineWidth = 2;
            netCtx.stroke();

            // Label softmax layer classes
            if (node.layerIndex === 3) {
                netCtx.fillStyle = 'var(--text-secondary)';
                netCtx.font = "8px 'Space Grotesk'";
                netCtx.textAlign = "left";
                const labels = ["Normal", "IMSI MitM", "Smishing", "Sig DDoS"];
                netCtx.fillText(labels[node.nodeIndex], node.x + node.r + 5, node.y + 3);
            }
        });

        requestAnimationFrame(drawNetworkVisuals);
    }
    drawNetworkVisuals();

    // -------------------------------------------------------------------------
    // 5. TRAINING PLAYGROUND & LIVE GRAPHS
    // -------------------------------------------------------------------------
    const pLayers = document.getElementById('param-layers');
    const vLayers = document.getElementById('val-layers');
    const pNeurons = document.getElementById('param-neurons');
    const pLr = document.getElementById('param-lr');
    const vLr = document.getElementById('val-lr');
    const pEpochs = document.getElementById('param-epochs');
    const vEpochs = document.getElementById('val-epochs');
    
    const trainRunBtn = document.getElementById('train-run-btn');
    const trainResetBtn = document.getElementById('train-reset-btn');
    const trainStageText = document.getElementById('train-stage-text');
    const trainPctText = document.getElementById('train-pct-text');
    const trainProgressBar = document.getElementById('trainProgressBar');
    const trainingPhaseText = document.getElementById('training-phase-indicator');

    // Hyperparameter sliders callbacks
    pLayers.addEventListener('input', () => {
        const val = pLayers.value;
        vLayers.textContent = val;
        let structures = ["64", "64, 32", "64, 32, 16", "64, 32, 16, 8"];
        pNeurons.value = structures[val - 1];
        state.hyperparameters.layers = parseInt(val);
    });

    pLr.addEventListener('input', () => {
        vLr.textContent = parseFloat(pLr.value).toFixed(3);
        state.hyperparameters.learningRate = parseFloat(pLr.value);
    });

    pEpochs.addEventListener('input', () => {
        vEpochs.textContent = pEpochs.value;
        state.hyperparameters.epochs = parseInt(pEpochs.value);
    });

    // Chart.js configurations for training panel
    const trainingCtx = document.getElementById('trainingChart').getContext('2d');
    
    // Set baseline data (Reconstruction error and backpropagation loss)
    const trainingChart = new Chart(trainingCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'RBM Reconstruction Error (Unsupervised)',
                    data: [],
                    borderColor: 'rgba(0, 242, 254, 0.85)',
                    backgroundColor: 'rgba(0, 242, 254, 0.05)',
                    borderWidth: 2,
                    yAxisID: 'y-error',
                    tension: 0.3,
                    pointRadius: 0
                },
                {
                    label: 'Fine-tuning Classifier Loss (Supervised)',
                    data: [],
                    borderColor: 'rgba(255, 0, 127, 0.85)',
                    backgroundColor: 'rgba(255, 0, 127, 0.05)',
                    borderWidth: 2,
                    yAxisID: 'y-loss',
                    tension: 0.3,
                    pointRadius: 0
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    title: { display: true, text: 'Training Epochs', color: 'var(--text-secondary)' },
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: 'var(--text-muted)' }
                },
                'y-error': {
                    type: 'linear',
                    position: 'left',
                    title: { display: true, text: 'RBM Recon Error', color: 'rgba(0, 242, 254, 0.85)' },
                    grid: { color: 'rgba(255, 255, 255, 0.04)' },
                    ticks: { color: 'var(--text-muted)' },
                    min: 0,
                    max: 1.2
                },
                'y-loss': {
                    type: 'linear',
                    position: 'right',
                    title: { display: true, text: 'Classification Loss', color: 'rgba(255, 0, 127, 0.85)' },
                    grid: { drawOnChartArea: false }, // avoid grid overlap
                    ticks: { color: 'var(--text-muted)' },
                    min: 0,
                    max: 0.8
                }
            },
            plugins: {
                legend: {
                    labels: { color: 'var(--text-primary)', font: { family: 'Space Grotesk' } }
                }
            }
        }
    });

    let trainingTimer = null;
    let currentEpoch = 0;

    trainRunBtn.addEventListener('click', () => {
        if (trainingTimer) return; // already training
        
        // Disable controls
        pLayers.disabled = true;
        pLr.disabled = true;
        pEpochs.disabled = true;
        trainRunBtn.disabled = true;
        
        currentEpoch = 0;
        trainingChart.data.labels = [];
        trainingChart.data.datasets[0].data = [];
        trainingChart.data.datasets[1].data = [];
        trainingChart.update();
        
        trainingPhaseText.textContent = "TRAINING IN PROGRESS";
        
        const totalEpochs = state.hyperparameters.epochs;
        const learningRate = state.hyperparameters.learningRate;
        
        // Emulated training cycle interval
        trainingTimer = setInterval(() => {
            currentEpoch++;
            const pct = Math.floor((currentEpoch / totalEpochs) * 100);
            
            trainPctText.textContent = `${pct}%`;
            trainProgressBar.style.width = `${pct}%`;
            
            // Determine active stage
            // Pre-training takes first 70% of epochs, divided among configuration layer counts
            const numLayers = state.hyperparameters.layers;
            const pretrainThreshold = Math.floor(totalEpochs * 0.7);
            
            let epochError = null;
            let epochLoss = null;
            
            if (currentEpoch <= pretrainThreshold) {
                // RBM Stack pre-training phase
                const stageRatio = pretrainThreshold / numLayers;
                const activeRbm = Math.floor((currentEpoch - 1) / stageRatio) + 1;
                trainStageText.innerHTML = `Unsupervised Pre-training (<strong>RBM ${activeRbm}</strong>)`;
                
                // Exponential error decline with random noise
                const baseNoise = (Math.random() - 0.5) * 0.03;
                // Scale error behavior based on learning rate
                const rateFactor = learningRate * 50;
                epochError = 0.95 * Math.exp(-((currentEpoch - (activeRbm-1)*stageRatio) / 15) * rateFactor) + 0.08 + baseNoise;
                epochError = Math.max(0.02, epochError);
            } else {
                // Backpropagation supervised fine-tuning phase
                trainStageText.innerHTML = `Supervised Fine-tuning (<strong>Backpropagation</strong>)`;
                
                // Fine-tuning loss decreases
                const backpropEpoch = currentEpoch - pretrainThreshold;
                const baseNoise = (Math.random() - 0.5) * 0.015;
                epochLoss = 0.65 * Math.exp(-(backpropEpoch / 10)) + 0.05 + baseNoise;
                epochLoss = Math.max(0.01, epochLoss);
                
                // Visual backprop classifier error can be plotted here
                epochError = 0.08 + (Math.random() - 0.5) * 0.01; // constant low recon error
            }

            // Feed labels and update chart
            trainingChart.data.labels.push(currentEpoch);
            trainingChart.data.datasets[0].data.push(epochError ? epochError.toFixed(4) : null);
            trainingChart.data.datasets[1].data.push(epochLoss ? epochLoss.toFixed(4) : null);
            
            // Limit view scope or update chart dynamically
            trainingChart.update('none'); // silent update for performance
            
            if (currentEpoch >= totalEpochs) {
                clearInterval(trainingTimer);
                trainingTimer = null;
                
                // Calculate resulting accuracy based on hyperparameters
                // Higher epochs and optimal learning rate (around 0.01 - 0.03) produce better scores
                let baseAcc = 94.2;
                
                // Learning rate penalty if too large or too small
                const lrDiff = Math.abs(learningRate - 0.02);
                const lrPenalty = lrDiff > 0.01 ? (lrDiff * 50) : 0;
                
                // Epoch weight
                const epochBonus = (totalEpochs / 200) * 4.5;
                
                // Layers structure weight
                const layerBonus = numLayers * 0.8;
                
                const finalAccuracy = Math.min(99.6, baseAcc + epochBonus + layerBonus - lrPenalty).toFixed(1);
                state.confidenceScore = parseFloat(finalAccuracy);
                document.getElementById('stat-confidence').textContent = `${finalAccuracy}%`;
                
                // Re-enable elements
                pLayers.disabled = false;
                pLr.disabled = false;
                pEpochs.disabled = false;
                trainRunBtn.disabled = false;
                trainingPhaseText.textContent = "COMPLETED";
                trainStageText.innerHTML = "Training complete. DBN weights loaded into active SOC runtime.";
                
                addLogLine("normal", "DBN CONFIG", `Deep Belief Network training finished. Final verification accuracy: ${finalAccuracy}%. Model deployed.`);
                
                // Recalculate confusion matrix values based on the newly trained strength
                updateConfusionMatrixForNewModel(finalAccuracy);
            }
        }, 80);
    });

    trainResetBtn.addEventListener('click', () => {
        if (trainingTimer) {
            clearInterval(trainingTimer);
            trainingTimer = null;
        }
        
        pLayers.disabled = false;
        pLr.disabled = false;
        pEpochs.disabled = false;
        trainRunBtn.disabled = false;
        
        trainStageText.innerHTML = "Idle. Click 'Start DBN Training' to begin model simulation.";
        trainPctText.textContent = "0%";
        trainProgressBar.style.width = "0%";
        trainingPhaseText.textContent = "Idle";
        
        trainingChart.data.labels = [];
        trainingChart.data.datasets[0].data = [];
        trainingChart.data.datasets[1].data = [];
        trainingChart.update();
    });

    function updateConfusionMatrixForNewModel(accuracy) {
        const total = 2000;
        const correct = Math.floor(total * (accuracy / 100));
        const incorrect = total - correct;
        
        state.cm.tp = Math.floor(correct * 0.28);
        state.cm.tn = correct - state.cm.tp;
        state.cm.fp = Math.floor(incorrect * 0.35);
        state.cm.fn = incorrect - state.cm.fp;
        
        // Trigger values update
        document.getElementById('cm-tn').textContent = state.cm.tn;
        document.getElementById('cm-fp').textContent = state.cm.fp;
        document.getElementById('cm-fn').textContent = state.cm.fn;
        document.getElementById('cm-tp').textContent = state.cm.tp;
    }

    // -------------------------------------------------------------------------
    // 6. THREAT ANALYTICS TAB CHARTS
    // -------------------------------------------------------------------------
    let radarChartInstance = null;
    let rocChartInstance = null;
    let breakdownChartInstance = null;

    function renderAnalyticsCharts() {
        // Radar Chart (Model evaluation parameters)
        const radarCtx = document.getElementById('metricsRadarChart');
        if (radarCtx) {
            if (radarChartInstance) radarChartInstance.destroy();
            
            // Compute visual performance ratios
            const precision = (state.cm.tp / (state.cm.tp + state.cm.fp) * 100).toFixed(1);
            const recall = (state.cm.tp / (state.cm.tp + state.cm.fn) * 100).toFixed(1);
            const f1 = (2 * (precision * recall) / (parseFloat(precision) + parseFloat(recall))).toFixed(1);
            const sensitivity = recall;
            const specificity = (state.cm.tn / (state.cm.tn + state.cm.fp) * 100).toFixed(1);

            radarChartInstance = new Chart(radarCtx.getContext('2d'), {
                type: 'radar',
                data: {
                    labels: ['Precision', 'Recall (Sensitivity)', 'Specificity', 'F1-Score', 'AUC/ROC Index'],
                    datasets: [{
                        label: 'Inference Capabilities (%)',
                        data: [precision, recall, specificity, f1, 98.7],
                        borderColor: 'var(--neon-cyan)',
                        backgroundColor: 'rgba(0, 242, 254, 0.15)',
                        borderWidth: 2,
                        pointBackgroundColor: 'var(--neon-cyan)'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        r: {
                            grid: { color: 'rgba(255, 255, 255, 0.05)' },
                            angleLines: { color: 'rgba(255, 255, 255, 0.05)' },
                            pointLabels: { color: 'var(--text-secondary)', font: { family: 'Space Grotesk', size: 10 } },
                            ticks: { display: false },
                            min: 80,
                            max: 100
                        }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

        // ROC Curve Line Chart
        const rocCtx = document.getElementById('rocChart');
        if (rocCtx) {
            if (rocChartInstance) rocChartInstance.destroy();
            
            // Curved coordinates demonstrating standard ROC behavior
            rocChartInstance = new Chart(rocCtx.getContext('2d'), {
                type: 'line',
                data: {
                    labels: [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
                    datasets: [
                        {
                            label: 'DBN Classifier (AUC = 0.987)',
                            data: [0.0, 0.85, 0.94, 0.97, 0.985, 0.99, 0.992, 0.995, 0.998, 1.0, 1.0],
                            borderColor: 'var(--neon-purple)',
                            backgroundColor: 'rgba(138, 43, 226, 0.05)',
                            fill: true,
                            borderWidth: 2,
                            tension: 0.3
                        },
                        {
                            label: 'Random Guess',
                            data: [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
                            borderColor: 'rgba(255, 255, 255, 0.15)',
                            borderDash: [5, 5],
                            borderWidth: 1.5,
                            fill: false
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            title: { display: true, text: 'False Positive Rate (1 - Specificity)', color: 'var(--text-secondary)' },
                            grid: { color: 'rgba(255, 255, 255, 0.03)' },
                            ticks: { color: 'var(--text-muted)' }
                        },
                        y: {
                            title: { display: true, text: 'True Positive Rate (Sensitivity)', color: 'var(--text-secondary)' },
                            grid: { color: 'rgba(255, 255, 255, 0.03)' },
                            ticks: { color: 'var(--text-muted)' },
                            min: 0,
                            max: 1.0
                        }
                    },
                    plugins: {
                        legend: { labels: { color: 'var(--text-secondary)' } }
                    }
                }
            });
        }

        // Threat Breakdown Pie Chart
        const breakCtx = document.getElementById('breakdownChart');
        if (breakCtx) {
            if (breakdownChartInstance) breakdownChartInstance.destroy();
            
            breakdownChartInstance = new Chart(breakCtx.getContext('2d'), {
                type: 'doughnut',
                data: {
                    labels: ['Normal Base', 'IMSI MITM', 'SMS Phish', 'Signaling DDoS'],
                    datasets: [{
                        data: [
                            state.threatDistribution.normal,
                            state.threatDistribution.imsi,
                            state.threatDistribution.smishing,
                            state.threatDistribution.ddos
                        ],
                        backgroundColor: [
                            'rgba(57, 255, 20, 0.6)',   // normal green
                            'rgba(255, 0, 127, 0.7)',   // imsi pink
                            'rgba(138, 43, 226, 0.7)',  // smishing purple
                            'rgba(255, 215, 0, 0.7)'    // ddos yellow
                        ],
                        borderColor: 'var(--bg-main)',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: 'var(--text-secondary)', font: { family: 'Space Grotesk' } }
                        }
                    },
                    cutout: '65%'
                }
            });
        }
    }
});
