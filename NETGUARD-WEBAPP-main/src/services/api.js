/**
 * NetGuard Telemetry & World Model Inference API Service
 * 
 * Standalone decoupled API layer for NTRO PS-26153.
 * Maintains DEMO_MODE = true for offline demonstration & air-gapped evaluation.
 */

export const DEMO_MODE = true;

export const SIMULATION_PRESETS = [
  {
    id: 'cic2018',
    name: 'CIC-IDS-2018 Preset (Infiltration Scenario)',
    file: 'cic_ids_2018_sample_flow.csv',
    size: '14.2 MB',
    type: 'CSV Flow Aggregates',
    threatLevel: 'CRITICAL',
    mitreTechnique: 'T1046 (Network Service Scanning) → T1190 (Exploit Public App)',
    threatProb: [12, 45, 78, 94, 98],
    shapFeatures: [
      { name: 'SYN Flag Burst Count', score: 42, color: 'bg-red-500' },
      { name: 'Port Scan Entropy (Dest Ports)', score: 29, color: 'bg-amber-500' },
      { name: 'Payload Shannon Entropy', score: 18, color: 'bg-indigo-500' },
      { name: 'TCP Window Size Variance', score: 11, color: 'bg-blue-500' },
    ],
    logs: [
      '[00:01:02] FLOW_INGEST: Ingested 12,450 IPFIX flow packets from 192.168.1.1',
      '[00:01:04] FEATURE_EXTRACT: SYN_Burst=450/sec, Unique_Dst_Ports=1024',
      '[00:01:06] WORLD_MODEL: Forecast rollout t+1 P(Attack)=12%, t+3 P(Attack)=78%',
      '[00:01:08] ALERT_RAISED: MITRE T1046 Network Service Scanning detected',
      '[00:01:10] ISOLATION_PLAYBOOK: Generated automated IP block rule for 192.168.1.105'
    ]
  },
  {
    id: 'ctu13',
    name: 'CTU-13 Malware Botnet Preset',
    file: 'ctu13_botnet_capture.pcap',
    size: '48.9 MB',
    type: 'Raw PCAP Stream',
    threatLevel: 'HIGH',
    mitreTechnique: 'T1071 (Application Layer Protocol: DNS C2)',
    threatProb: [8, 25, 52, 79, 86],
    shapFeatures: [
      { name: 'DNS Request Frequency (C2 Query)', score: 48, color: 'bg-red-500' },
      { name: 'Outbound Encrypted Payload Ratio', score: 24, color: 'bg-amber-500' },
      { name: 'Flow Inter-Arrival Standard Dev', score: 16, color: 'bg-indigo-500' },
      { name: 'TTL Hop Decay Variance', score: 12, color: 'bg-blue-500' },
    ],
    logs: [
      '[00:02:14] PCAP_PARSER: Decoding layer 3/4 headers for 45,100 packets...',
      '[00:02:16] GNN_ENCODER: Node 192.168.1.53 showing anomalous C2 beaconing pattern',
      '[00:02:18] WORLD_MODEL: Forecast rollout t+2 P(Botnet C2)=52%',
      '[00:02:20] XAI_EXPLAIN: SHAP attributes 48% weight to repetitive DNS TXT records',
      '[00:02:22] REMEDIATION: DNS sinkhole policy deployed to edge firewall'
    ]
  },
  {
    id: 'clean',
    name: 'Normal Enterprise Traffic Baseline',
    file: 'enterprise_clean_baseline.csv',
    size: '8.4 MB',
    type: 'CSV Baseline',
    threatLevel: 'NORMAL',
    mitreTechnique: 'N/A (Baseline Traffic)',
    threatProb: [1, 2, 1, 3, 2],
    shapFeatures: [
      { name: 'HTTP 200 OK Response Ratio', score: 65, color: 'bg-emerald-500' },
      { name: 'Standard TLS 1.3 Handshake', score: 20, color: 'bg-blue-500' },
      { name: 'Normal Workstation Duty Cycle', score: 10, color: 'bg-slate-400' },
      { name: 'ICMP Keep-Alive Echo', score: 5, color: 'bg-slate-300' },
    ],
    logs: [
      '[00:00:01] SYSTEM_START: Ingestion daemon bound to eth0 interface',
      '[00:00:05] TELEMETRY: 5,000 flow records parsed. Entropy index 1.2 (Normal)',
      '[00:00:10] WORLD_MODEL: Rollout horizon t+1 to t+5 remains stable. P(Attack) < 3%',
      '[00:00:15] HEALTH_CHECK: All 5 network topology nodes reporting SECURE status'
    ]
  }
];

export async function fetchTelemetryPreset(presetId) {
  if (DEMO_MODE) {
    const found = SIMULATION_PRESETS.find(p => p.id === presetId);
    return found || SIMULATION_PRESETS[0];
  }
  // Future production API hook
  const res = await fetch(`/api/telemetry/${presetId}`);
  return res.json();
}
