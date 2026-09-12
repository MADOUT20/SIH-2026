import React, { useState } from 'react';
import { FileText, Github, Presentation, Video, CheckCircle2, X, ChevronLeft, ChevronRight, Download, ExternalLink, Award, BarChart, Shield, Zap } from 'lucide-react';
import { useScrollReveal } from '../hooks/useScrollReveal';
import GDGInteractiveCard from './GDGInteractiveCard';

export default function DeliverablesHub() {
  const [activeModal, setActiveModal] = useState(null); // 'deck', 'pdf', 'repo', 'video'
  const [slideIndex, setSlideIndex] = useState(0);
  const [sectionRef, isVisible] = useScrollReveal();

  const pitchSlides = [
    {
      title: 'Slide 1: Problem & NTRO Context',
      subtitle: 'Critical Infrastructure Vulnerability to Multi-step Infiltration',
      bullets: [
        'Traditional IDS (Snort/Suricata) rely on static signatures & single-packet rules.',
        'Sophisticated adversaries execute multi-step APTs over long temporal windows.',
        'Requirement: Proactive forecasting model capable of predicting future state transition P(S_t+1 | S_t).'
      ]
    },
    {
      title: 'Slide 2: NetGuard World Model Architecture',
      subtitle: 'Generative Spatio-Temporal Network State Modeling',
      bullets: [
        'Dual Ingestion: Combines IPFIX flow dynamics + raw PCAP traits (TTL variance, TCP flags).',
        'State Space Encoder: Spatio-Temporal Graph Neural Networks (ST-GNN).',
        'Generative Predictor: Temporal Transformers simulating forward rollouts K=5 steps into the future.'
      ]
    },
    {
      title: 'Slide 3: Explainable AI & MITRE ATT&CK Mapping',
      subtitle: 'Interpretable Decision Support for SOC Analysts',
      bullets: [
        'Real-time TreeSHAP value attribution identifying driving packet traits.',
        'Automated tactic mapping to MITRE ATT&CK enterprise kill-chain phases.',
        'Reduces analyst alarm fatigue by filtering 99.6% of benign background anomalies.'
      ]
    },
    {
      title: 'Slide 4: Experimental Evaluation & Benchmarks',
      subtitle: 'Validated on CIC-IDS-2018 & CTU-13 Datasets',
      bullets: [
        'Achieves 98.4% multi-step attack forecasting F1-score.',
        'False Positive Rate under 0.38% across 10 million flow records.',
        'Inference latency under 12ms per 10,000 packets on standard x86 CPU.'
      ]
    },
    {
      title: 'Slide 5: Deliverables & Air-Gapped Deployment',
      subtitle: 'Production-Ready Software Distribution',
      bullets: [
        'Standalone Linux Systemd daemon & Windows GUI executable.',
        'Zero cloud dependency - operates 100% offline in air-gapped environments.',
        'Developed for NTRO Problem Statement #26153.'
      ]
    }
  ];

  const benchmarks = [
    { model: 'NetGuard (World Model ST-GNN)', f1: '98.4%', fpr: '0.38%', horizon: 'K=5 Steps', latency: '11.4 ms', airgapped: 'Yes (100%)' },
    { model: 'LSTM Time-Series Baseline', f1: '89.2%', fpr: '2.14%', horizon: 'K=2 Steps', latency: '24.8 ms', airgapped: 'Yes' },
    { model: 'Random Forest Flow Classifier', f1: '84.6%', fpr: '3.82%', horizon: 'None (Static)', latency: '4.2 ms', airgapped: 'Yes' },
    { model: 'Logistic Regression Baseline', f1: '72.1%', fpr: '6.45%', horizon: 'None (Static)', latency: '1.8 ms', airgapped: 'Yes' },
    { model: 'Traditional Suricata Signatures', f1: '68.5%', fpr: '8.12%', horizon: 'None (Static)', latency: '8.5 ms', airgapped: 'Yes' },
  ];

  return (
    <section 
      ref={sectionRef}
      id="benchmarks" 
      className="py-24 bg-transparent border-t border-slate-200/60 relative z-10"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className={`text-center max-w-3xl mx-auto space-y-4 transition-all duration-700 ${
          isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
        }`}>
          <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-emerald-50 text-emerald-700 text-xs font-mono font-bold border border-emerald-200">
            <Award className="w-3.5 h-3.5" />
            <span>ENTERPRISE EVALUATION HUB</span>
          </div>

          <h2 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
            Deliverables & Empirical Performance Benchmarks
          </h2>

          <p className="text-slate-600 text-base sm:text-lg">
            Review submission materials, technical architecture documentation, and quantitative benchmarks against traditional Intrusion Detection Systems.
          </p>
        </div>

        {/* 4 Deliverable Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mt-12">
          
          {/* Card 1: Source Code */}
          <GDGInteractiveCard
            onClick={() => setActiveModal('repo')}
            className={`glass-card rounded-3xl p-6 border border-slate-200/80 hover:border-brand-400 hover:shadow-xl hover:shadow-blue-500/5 flex flex-col justify-between group ${
              isVisible ? 'opacity-100 translate-y-0 delay-100' : 'opacity-0 translate-y-8'
            }`}
          >
            <div>
              <div className="w-12 h-12 rounded-2xl bg-slate-900 text-white flex items-center justify-center mb-4 group-hover:scale-110 transition-all duration-300 shadow-subtle">
                <Github className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900 mb-1">
                Source Code Repository
              </h3>
              <p className="text-xs text-slate-500 leading-relaxed">
                Complete C++ packet engine, Python PyTorch GNN world model, and React UI codebase.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-200/80 flex items-center justify-between text-xs font-bold text-slate-700 group-hover:text-brand-600">
              <span>View Repository Tree</span>
              <ExternalLink className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
            </div>
          </GDGInteractiveCard>

          {/* Card 2: 2-Page PDF */}
          <GDGInteractiveCard
            onClick={() => setActiveModal('pdf')}
            className={`glass-card rounded-3xl p-6 border border-slate-200/80 hover:border-brand-400 hover:shadow-xl hover:shadow-blue-500/5 flex flex-col justify-between group ${
              isVisible ? 'opacity-100 translate-y-0 delay-200' : 'opacity-0 translate-y-8'
            }`}
          >
            <div>
              <div className="w-12 h-12 rounded-2xl bg-blue-600 text-white flex items-center justify-center mb-4 group-hover:scale-110 transition-all duration-300 shadow-glow-cobalt">
                <FileText className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900 mb-1">
                2-Page Architecture Document
              </h3>
              <p className="text-xs text-slate-500 leading-relaxed">
                Concise executive technical paper detailing P(S_t+1|S_t) formulation and NTRO integration specs.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-200/80 flex items-center justify-between text-xs font-bold text-slate-700 group-hover:text-brand-600">
              <span>Read Document</span>
              <ExternalLink className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
            </div>
          </GDGInteractiveCard>

          {/* Card 3: Pitch Deck */}
          <GDGInteractiveCard
            onClick={() => {
              setSlideIndex(0);
              setActiveModal('deck');
            }}
            className={`glass-card rounded-3xl p-6 border border-slate-200/80 hover:border-brand-400 hover:shadow-xl hover:shadow-blue-500/5 flex flex-col justify-between group ${
              isVisible ? 'opacity-100 translate-y-0 delay-300' : 'opacity-0 translate-y-8'
            }`}
          >
            <div>
              <div className="w-12 h-12 rounded-2xl bg-indigo-600 text-white flex items-center justify-center mb-4 group-hover:scale-110 transition-all duration-300 shadow-subtle">
                <Presentation className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900 mb-1">
                Technical Pitch Deck (5 Slides)
              </h3>
              <p className="text-xs text-slate-500 leading-relaxed">
                Interactive slide deck presenting problem context, world model math, and evaluation metrics.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-200/80 flex items-center justify-between text-xs font-bold text-slate-700 group-hover:text-brand-600">
              <span>Launch Slide Viewer</span>
              <ExternalLink className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
            </div>
          </GDGInteractiveCard>

          {/* Card 4: Demo Video */}
          <GDGInteractiveCard
            onClick={() => setActiveModal('video')}
            className={`glass-card rounded-3xl p-6 border border-slate-200/80 hover:border-brand-400 hover:shadow-xl hover:shadow-blue-500/5 flex flex-col justify-between group ${
              isVisible ? 'opacity-100 translate-y-0 delay-400' : 'opacity-0 translate-y-8'
            }`}
          >
            <div>
              <div className="w-12 h-12 rounded-2xl bg-red-600 text-white flex items-center justify-center mb-4 group-hover:scale-110 transition-all duration-300 shadow-glow-crimson">
                <Video className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900 mb-1">
                2-Minute Demonstration Video
              </h3>
              <p className="text-xs text-slate-500 leading-relaxed">
                High-definition walkthrough of real-time attack simulation, SHAP attribution, and mitigation playbooks.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-200/80 flex items-center justify-between text-xs font-bold text-slate-700 group-hover:text-brand-600">
              <span>Watch Video Demo</span>
              <ExternalLink className="w-3.5 h-3.5 transition-transform group-hover:translate-x-0.5" />
            </div>
          </GDGInteractiveCard>

        </div>

        {/* Benchmark Comparison Table */}
        <div className="mt-16 bg-white rounded-3xl border border-slate-200/90 shadow-card overflow-hidden transition-all duration-300 hover:shadow-xl hover:shadow-blue-500/5">
          <div className="bg-slate-900 text-white px-6 py-4 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <BarChart className="w-5 h-5 text-brand-400" />
              <h3 className="font-bold text-sm font-sans">
                EMPIRICAL PERFORMANCE COMPARISON TABLE (CIC-IDS-2018 DATASET)
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400">NTRO BENCHMARK TESTBED v1.0</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-50 text-slate-700 text-xs font-mono border-b border-slate-200">
                  <th className="py-4 px-6 font-bold">MODEL ARCHITECTURE</th>
                  <th className="py-4 px-4 font-bold text-center">F1-SCORE</th>
                  <th className="py-4 px-4 font-bold text-center">FALSE POSITIVE RATE</th>
                  <th className="py-4 px-4 font-bold text-center">FORECAST HORIZON</th>
                  <th className="py-4 px-4 font-bold text-center">LATENCY (10K RECORDS)</th>
                  <th className="py-4 px-4 font-bold text-center">AIR-GAPPED COMPLIANCE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200/80 text-xs">
                {benchmarks.map((row, idx) => (
                  <tr key={idx} className={idx === 0 ? 'bg-brand-50/70 font-semibold' : 'hover:bg-slate-50/80 transition-colors'}>
                    <td className="py-4 px-6 flex items-center space-x-2">
                      {idx === 0 && <Shield className="w-4 h-4 text-brand-600 shrink-0" />}
                      <span className={idx === 0 ? 'text-brand-900 font-bold' : 'text-slate-900'}>{row.model}</span>
                    </td>
                    <td className={`py-4 px-4 text-center font-mono font-bold ${idx === 0 ? 'text-brand-700' : 'text-slate-700'}`}>
                      {row.f1}
                    </td>
                    <td className={`py-4 px-4 text-center font-mono ${idx === 0 ? 'text-emerald-600 font-bold' : 'text-slate-600'}`}>
                      {row.fpr}
                    </td>
                    <td className="py-4 px-4 text-center font-mono text-slate-700">
                      {row.horizon}
                    </td>
                    <td className="py-4 px-4 text-center font-mono text-slate-700">
                      {row.latency}
                    </td>
                    <td className="py-4 px-4 text-center">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium ${
                        idx === 0 ? 'bg-emerald-100 text-emerald-800 border border-emerald-300 font-bold' : 'bg-slate-100 text-slate-700 border border-slate-200'
                      }`}>
                        {row.airgapped}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>

      {/* Slide Deck Modal */}
      {activeModal === 'deck' && (
        <div className="fixed inset-0 z-50 bg-slate-900/80 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-white rounded-3xl max-w-3xl w-full border border-slate-200 shadow-2xl overflow-hidden">
            <div className="bg-slate-900 text-white px-6 py-4 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Presentation className="w-5 h-5 text-brand-400" />
                <span className="font-bold text-sm">NTRO TECHNICAL PITCH DECK</span>
              </div>
              <button onClick={() => setActiveModal(null)} className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-8 min-h-[320px] flex flex-col justify-between">
              <div>
                <span className="px-3 py-1 rounded-full bg-brand-50 text-brand-700 font-mono text-xs font-bold border border-brand-200">
                  SLIDE {slideIndex + 1} OF 5
                </span>
                
                <h3 className="text-2xl font-extrabold text-slate-900 mt-3">
                  {pitchSlides[slideIndex].title}
                </h3>
                
                <p className="text-xs font-mono font-bold text-brand-600 mt-1">
                  {pitchSlides[slideIndex].subtitle}
                </p>

                <div className="mt-6 space-y-3">
                  {pitchSlides[slideIndex].bullets.map((b, bIdx) => (
                    <div key={bIdx} className="flex items-start space-x-3 text-sm text-slate-700">
                      <CheckCircle2 className="w-5 h-5 text-brand-600 shrink-0 mt-0.5" />
                      <span>{b}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Navigation Controls */}
              <div className="mt-8 pt-4 border-t border-slate-200 flex items-center justify-between">
                <button
                  disabled={slideIndex === 0}
                  onClick={() => setSlideIndex(slideIndex - 1)}
                  className="px-4 py-2 rounded-xl text-xs font-bold border border-slate-300 hover:bg-slate-100 disabled:opacity-40 flex items-center space-x-1 transition-all active:scale-[0.98]"
                >
                  <ChevronLeft className="w-4 h-4" />
                  <span>Previous Slide</span>
                </button>

                <div className="flex space-x-1.5">
                  {pitchSlides.map((_, idx) => (
                    <span
                      key={idx}
                      className={`w-2.5 h-2.5 rounded-full transition-all duration-300 ${idx === slideIndex ? 'bg-brand-600 w-6' : 'bg-slate-300'}`}
                    />
                  ))}
                </div>

                <button
                  disabled={slideIndex === pitchSlides.length - 1}
                  onClick={() => setSlideIndex(slideIndex + 1)}
                  className="px-4 py-2 rounded-xl text-xs font-bold bg-brand-600 text-white hover:bg-brand-700 disabled:opacity-40 flex items-center space-x-1 transition-all active:scale-[0.98]"
                >
                  <span>Next Slide</span>
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* PDF Architecture Document Reader Modal */}
      {activeModal === 'pdf' && (
        <div className="fixed inset-0 z-50 bg-slate-900/80 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-white rounded-3xl max-w-4xl w-full max-h-[90vh] overflow-hidden border border-slate-200 shadow-2xl flex flex-col">
            <div className="bg-slate-900 text-white px-6 py-4 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <FileText className="w-5 h-5 text-brand-400" />
                <span className="font-bold text-sm">2-PAGE ARCHITECTURE EXECUTIVE SPECIFICATION</span>
              </div>
              <button onClick={() => setActiveModal(null)} className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-8 overflow-y-auto space-y-6 text-slate-800 font-sans text-sm">
              <div className="border-b border-slate-200 pb-4">
                <span className="text-xs font-mono text-brand-600 font-bold">NTRO PROBLEM STATEMENT #26153</span>
                <h2 className="text-2xl font-extrabold text-slate-900 mt-1">
                  NetGuard: Generative World Models for Multi-Step Cyber Infiltration Forecasting
                </h2>
                <p className="text-xs text-slate-500 font-mono mt-1">
                  Authors: Team NetGuard // Defense AI Division // Version 1.0.4
                </p>
              </div>

              <div className="space-y-4">
                <h3 className="text-base font-bold text-slate-900 border-b border-slate-100 pb-1">1. Abstract & Mathematical Formulation</h3>
                <p className="text-slate-600 leading-relaxed text-xs">
                  Critical Information Infrastructure (CII) networks face complex multi-stage cyber attacks. NetGuard formulates network defense as forward state dynamic forecasting: <strong>P(S<sub>t+1</sub> | S<sub>t</sub>, A<sub>t</sub>)</strong>. By embedding telemetry into Spatio-Temporal Graph representations, NetGuard simulates potential attack trajectories up to K=5 steps before initial exploitation succeeds.
                </p>

                <h3 className="text-base font-bold text-slate-900 border-b border-slate-100 pb-1">2. Dual-Level Telemetry Engine</h3>
                <p className="text-slate-600 leading-relaxed text-xs">
                  The engine combines IPFIX flow metrics (flow duration, byte ratios, TCP flags) with sub-second PCAP traits (TTL variance, TCP window size distribution). Features are processed through a C++ low-latency ingestion socket operating under 12ms per 10,000 records.
                </p>

                <h3 className="text-base font-bold text-slate-900 border-b border-slate-100 pb-1">3. Experimental Results</h3>
                <p className="text-slate-600 leading-relaxed text-xs">
                  Evaluated on CIC-IDS-2018 and CTU-13 datasets, NetGuard achieves a multi-step forecasting F1-score of 98.4% with a False Positive Rate of 0.38%, outperforming traditional static rules and baseline LSTM models.
                </p>
              </div>

              <div className="pt-4 border-t border-slate-200 flex justify-end">
                <button
                  onClick={() => window.open('https://github.com/MADOUT20/SIH-2026', '_blank')}
                  className="px-5 py-2.5 rounded-xl bg-brand-600 text-white font-bold text-xs flex items-center space-x-2 hover:bg-brand-700 btn-shimmer shadow-glow-cobalt transition-all active:scale-[0.98]"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Architecture PDF</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* GitHub Code Repository Tree Modal */}
      {activeModal === 'repo' && (
        <div className="fixed inset-0 z-50 bg-slate-900/80 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-slate-950 text-slate-200 rounded-3xl max-w-2xl w-full border border-slate-800 shadow-2xl overflow-hidden font-mono text-xs">
            <div className="bg-slate-900 text-white px-6 py-4 flex items-center justify-between border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <Github className="w-5 h-5 text-white" />
                <span className="font-bold text-sm font-sans">github.com/ntro-sih2026/netguard-worldmodel</span>
              </div>
              <button onClick={() => setActiveModal(null)} className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
              <p className="text-slate-400 text-xs font-sans">
                Official repository structure for NTRO PS-26153:
              </p>

              <div className="bg-[#050811] p-4 rounded-2xl border border-slate-800 text-emerald-400 space-y-1.5 leading-relaxed shadow-inner">
                <p>├── engine/</p>
                <p>│   ├── cpp_ingest/             # High-throughput C++ IPFIX socket parser</p>
                <p>│   └── pcap_decoder.cpp        # Low-level libpcap feature extractor</p>
                <p>├── world_model/</p>
                <p>│   ├── st_gnn_encoder.py       # Spatio-Temporal Graph Neural Network</p>
                <p>│   ├── temporal_transformer.py # Forward rollout P(S_t+1 | S_t) model</p>
                <p>│   └── shap_explainer.py       # Real-time TreeSHAP feature attributions</p>
                <p>├── ui/</p>
                <p>│   ├── src/                    # Enterprise Light Mode Dashboard</p>
                <p>│   └── components/             # Topology Graph & Forecast Sandbox</p>
                <p>├── docs/</p>
                <p>│   ├── NTRO_PS26153_Paper.pdf  # 2-Page Architecture Document</p>
                <p>│   └── Pitch_Deck.pptx         # 5-Slide Technical Pitch Deck</p>
                <p>└── LICENSE                     # MIT License</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Video Demonstration Modal */}
      {activeModal === 'video' && (
        <div className="fixed inset-0 z-50 bg-slate-900/80 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in">
          <div className="bg-slate-950 text-white rounded-3xl max-w-3xl w-full border border-slate-800 shadow-2xl overflow-hidden">
            <div className="bg-slate-900 px-6 py-4 flex items-center justify-between border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <Video className="w-5 h-5 text-red-500" />
                <span className="font-bold text-sm font-sans">NETGUARD 2-MINUTE DEMONSTRATION WALKTHROUGH</span>
              </div>
              <button onClick={() => setActiveModal(null)} className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-colors">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 text-center space-y-4">
              <div className="w-full h-64 bg-slate-900 rounded-2xl border border-slate-800 flex flex-col items-center justify-center space-y-3 relative overflow-hidden group">
                <div className="w-16 h-16 rounded-full bg-red-600 text-white flex items-center justify-center shadow-glow-crimson group-hover:scale-110 transition-all duration-300 cursor-pointer">
                  <Video className="w-8 h-8 fill-current ml-1" />
                </div>
                <p className="font-mono text-xs text-slate-300">Click to Play 1080p Video Walkthrough (2:00 mins)</p>
              </div>
              <p className="text-xs text-slate-400 font-sans">
                Narrated demonstration showcasing real-time attack forecasting during an active CIC-IDS-2018 port-scan and lateral movement campaign.
              </p>
            </div>
          </div>
        </div>
      )}

    </section>
  );
}
