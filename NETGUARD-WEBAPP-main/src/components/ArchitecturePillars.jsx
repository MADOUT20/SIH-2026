import React, { useState } from 'react';
import { Layers, Network, ShieldCheck, Database, Cpu, Eye, ArrowRight, CheckCircle2, Code2, BarChart2 } from 'lucide-react';
import { useScrollReveal } from '../hooks/useScrollReveal';
import GDGInteractiveCard from './GDGInteractiveCard';

export default function ArchitecturePillars() {
  const [activeTab, setActiveTab] = useState(0);
  const [sectionRef, isVisible] = useScrollReveal();

  const pillars = [
    {
      id: 'ingestion',
      title: 'Dual-Level Telemetry Ingestion',
      subtitle: 'NetFlow/IPFIX Aggregates & Raw PCAP Packet Trait Extraction',
      badge: 'Layer 1: Data Engine',
      badgeColor: 'bg-blue-50 text-blue-700 border-blue-200',
      icon: Layers,
      summary: 'Captures both high-throughput IPFIX aggregate records and sub-second raw PCAP packet traits for zero-omission visibility.',
      features: [
        'NetFlow / IPFIX flow duration & Inter-Arrival Time (IAT) distribution',
        'TCP Flag bitmasks (SYN, ACK, FIN, RST, PSH, URG)',
        'Payload byte ratios & entropy variance calculation',
        'Raw packet traits: TTL variance, TCP window size, payload size distribution'
      ],
      codeSnippet: `// IPFIX & PCAP Trait Extractor Pipeline
struct TelemetryRecord {
  uint32_t src_ip, dst_ip;
  uint16_t src_port, dst_port;
  float    inter_arrival_time_stddev;
  uint8_t  tcp_flags_mask;
  double   payload_entropy; // Shannon Entropy [0.0 - 8.0]
};`
    },
    {
      id: 'worldmodel',
      title: 'State-Transition World Model',
      subtitle: 'Temporal Transformers & Graph Neural Networks (GNNs)',
      badge: 'Layer 2: Generative Predictor',
      badgeColor: 'bg-indigo-50 text-indigo-700 border-indigo-200',
      icon: Network,
      summary: 'Learns transition dynamic distribution P(S_t+1 | S_t) over topological graph embedding space for K-step forward simulation.',
      features: [
        'Spatio-Temporal Graph Neural Network (ST-GNN) network topology encoder',
        'Temporal Transformer with multi-head attention over flow time-series',
        'K=5 step forward rollout simulation of unobserved future states',
        'Transition dynamic estimation: P(S_{t+1} | S_t, A_t)'
      ],
      codeSnippet: `# World Model State Transition Loss
def transition_loss(pred_state, target_state, kl_weight=0.1):
    recon_loss = F.mse_loss(pred_state.mean, target_state)
    kl_div = torch.distributions.kl_divergence(pred_state.dist, prior_dist)
    return recon_loss + kl_weight * kl_div.sum()`
    },
    {
      id: 'mitre_xai',
      title: 'MITRE ATT&CK & XAI Mapping',
      subtitle: 'Interpretable Decision Support via SHAP Attribution',
      badge: 'Layer 3: Explainable Defense',
      badgeColor: 'bg-emerald-50 text-emerald-700 border-emerald-200',
      icon: ShieldCheck,
      summary: 'Translates high-dimensional vector predictions into actionable MITRE tactics and human-auditable SHAP feature importance values.',
      features: [
        'Automated mapping to MITRE ATT&CK enterprise tactics & techniques',
        'TreeSHAP & KernelSHAP real-time feature attribution scoring',
        'Confidence bounds on predicted kill-chain stage advancement',
        'Actionable remediation playbooks generated for SOC analysts'
      ],
      codeSnippet: `// SHAP Attribution Output Vector
{
  "mitre_technique": "T1046 (Network Service Scanning)",
  "confidence": 0.9842,
  "top_shap_features": [
    { "feature": "SYN_Burst_Count", "contribution": +0.42 },
    { "feature": "Port_Entropy",    "contribution": +0.29 },
    { "feature": "Payload_Anomaly", "contribution": +0.18 }
  ]
}`
    }
  ];

  return (
    <section 
      ref={sectionRef}
      id="architecture" 
      className="py-24 bg-transparent border-t border-slate-200/60 relative z-10"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className={`text-center max-w-3xl mx-auto space-y-4 transition-all duration-700 ${
          isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
        }`}>
          <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-slate-200/70 text-slate-800 text-xs font-mono font-bold border border-slate-300/80">
            <Cpu className="w-3.5 h-3.5 text-brand-600" />
            <span>CORE ARCHITECTURAL PILLARS</span>
          </div>
          
          <h2 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
            How NetGuard Models Network Transition Dynamics
          </h2>
          
          <p className="text-slate-600 text-base sm:text-lg">
            Unlike reactive signature matchers, NetGuard leverages generative World Models to learn normal network mechanics and forecast adversarial multi-step trajectories.
          </p>
        </div>

        {/* 3-Card Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-14">
          {pillars.map((pillar, idx) => {
            const IconComponent = pillar.icon;
            const isSelected = activeTab === idx;
            return (
              <GDGInteractiveCard
                key={pillar.id}
                onClick={() => setActiveTab(idx)}
                className={`glass-card rounded-3xl p-7 border flex flex-col justify-between ${
                  isVisible ? `opacity-100 translate-y-0 delay-${(idx + 1) * 100}` : 'opacity-0 translate-y-8'
                } ${
                  isSelected
                    ? 'border-brand-500 shadow-xl ring-2 ring-brand-500/20 bg-white'
                    : 'hover:border-blue-300 hover:shadow-xl hover:shadow-blue-500/5'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-5">
                    <div className="w-12 h-12 rounded-2xl bg-brand-50 border border-brand-200 flex items-center justify-center text-brand-600 shadow-subtle">
                      <IconComponent className="w-6 h-6" />
                    </div>
                    <span className={`px-2.5 py-1 rounded-full text-xs font-mono font-semibold border ${pillar.badgeColor}`}>
                      {pillar.badge}
                    </span>
                  </div>

                  <h3 className="text-xl font-bold text-slate-900 mb-1">
                    {pillar.title}
                  </h3>
                  
                  <p className="text-xs font-mono font-semibold text-brand-600 mb-3">
                    {pillar.subtitle}
                  </p>

                  <p className="text-sm text-slate-600 mb-5 leading-relaxed">
                    {pillar.summary}
                  </p>

                  <div className="space-y-2 pt-2 border-t border-slate-100">
                    {pillar.features.map((feat, fIdx) => (
                      <div key={fIdx} className="flex items-start space-x-2 text-xs text-slate-700">
                        <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                        <span>{feat}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="mt-6 pt-4 border-t border-slate-100 flex items-center justify-between text-xs font-bold text-brand-600">
                  <span>View Code Specifications</span>
                  <ArrowRight className={`w-4 h-4 transition-transform ${isSelected ? 'translate-x-1' : ''}`} />
                </div>
              </GDGInteractiveCard>
            );
          })}
        </div>

        {/* Dynamic Interactive Code & Technical Deep-Dive Panel */}
        <div className="mt-12 bg-slate-900 rounded-3xl p-6 sm:p-8 text-white shadow-floating border border-slate-800 font-mono text-xs overflow-hidden">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-4 mb-6 gap-3">
            <div className="flex items-center space-x-3">
              <Code2 className="w-5 h-5 text-brand-400" />
              <span className="font-bold text-sm text-slate-200">
                TECHNICAL IMPLEMENTATION: {pillars[activeTab].title.toUpperCase()}
              </span>
            </div>
            
            <div className="flex space-x-2">
              {pillars.map((p, idx) => (
                <button
                  key={p.id}
                  onClick={() => setActiveTab(idx)}
                  className={`px-3 py-1.5 rounded-lg text-xs transition-all ${
                    activeTab === idx ? 'bg-brand-600 text-white font-bold shadow-glow-cobalt' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                  }`}
                >
                  Pillar {idx + 1}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            <div className="lg:col-span-6 space-y-3 font-sans">
              <h4 className="text-lg font-bold text-white font-sans">
                {pillars[activeTab].title}
              </h4>
              <p className="text-slate-300 text-sm leading-relaxed">
                {pillars[activeTab].summary}
              </p>
              <div className="bg-slate-800/80 p-4 rounded-2xl border border-slate-700 space-y-2">
                <p className="text-xs font-mono font-bold text-brand-300">BENEFITS & NTRO COMPLIANCE:</p>
                <ul className="text-xs text-slate-300 space-y-1.5 list-disc list-inside">
                  <li>Zero reliance on cloud API endpoints - run 100% air-gapped.</li>
                  <li>Inference latency under 12ms per 10,000 flow records.</li>
                  <li>Interoperable with Suricata, Snort, and Elastic SIEM logs.</li>
                </ul>
              </div>
            </div>

            <div className="lg:col-span-6">
              <div className="bg-[#050811] rounded-2xl p-4 border border-slate-800 overflow-x-auto text-emerald-400 font-mono text-xs shadow-inner">
                <pre>{pillars[activeTab].codeSnippet}</pre>
              </div>
            </div>
          </div>
        </div>

      </div>
    </section>
  );
}
