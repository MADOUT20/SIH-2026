import React from 'react';
import { Shield, Github, Globe, FileText, CheckCircle2, Heart } from 'lucide-react';

export default function Footer({ onScrollToSection, onOpenAuthModal }) {
  return (
    <footer className="bg-slate-900 text-slate-400 font-sans text-xs border-t border-slate-800 pt-16 pb-12">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-12">
        
        {/* Top Grid */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
          
          {/* Brand Col */}
          <div className="md:col-span-5 space-y-4">
            <div className="flex items-center space-x-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-brand-600 to-indigo-600 flex items-center justify-center text-white shadow-glow-cobalt">
                <Shield className="w-5 h-5" />
              </div>
              <span className="font-extrabold text-xl tracking-tight text-white">
                NetGuard
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-brand-300 border border-slate-700">
                NTRO PS-26153
              </span>
            </div>

            <p className="text-slate-400 text-xs leading-relaxed max-w-sm">
              NetGuard is an AI-driven network attack forecasting engine powered by Temporal World Models. Designed for proactive defense of Critical Information Infrastructure in India.
            </p>

            <div className="flex items-center space-x-2 text-[11px] font-mono text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>All Telemetry Ingestion Systems Operational</span>
            </div>
          </div>

          {/* Quick Links */}
          <div className="md:col-span-2 space-y-3">
            <h4 className="font-bold text-white text-xs tracking-wider uppercase font-mono">
              Platform
            </h4>
            <ul className="space-y-2">
              <li><button onClick={() => onScrollToSection('overview')} className="hover:text-white transition-smooth">Overview</button></li>
              <li><button onClick={() => onScrollToSection('architecture')} className="hover:text-white transition-smooth">World Model Architecture</button></li>
              <li><button onClick={() => onScrollToSection('sandbox')} className="hover:text-white transition-smooth">Simulation Sandbox</button></li>
              <li><button onClick={() => onScrollToSection('downloads')} className="hover:text-white transition-smooth">Software Downloads</button></li>
            </ul>
          </div>

          {/* Deliverables */}
          <div className="md:col-span-2 space-y-3">
            <h4 className="font-bold text-white text-xs tracking-wider uppercase font-mono">
              Evaluation
            </h4>
            <ul className="space-y-2">
              <li><button onClick={() => onScrollToSection('benchmarks')} className="hover:text-white transition-smooth">Benchmark Table</button></li>
              <li><button onClick={() => onScrollToSection('benchmarks')} className="hover:text-white transition-smooth">Architecture PDF</button></li>
              <li><button onClick={() => onScrollToSection('benchmarks')} className="hover:text-white transition-smooth">Pitch Deck (5 Slides)</button></li>
              <li><button onClick={onOpenAuthModal} className="hover:text-white transition-smooth">Analyst Portal</button></li>
            </ul>
          </div>

          {/* Datasets & Disclaimers */}
          <div className="md:col-span-3 space-y-3">
            <h4 className="font-bold text-white text-xs tracking-wider uppercase font-mono">
              Datasets & Compliance
            </h4>
            <p className="text-[11px] text-slate-400 leading-normal">
              Validated on standard benchmark datasets: <strong>CIC-IDS-2018</strong>, <strong>UNSW-NB15</strong>, and <strong>CTU-13 IoT Botnet</strong> captures.
            </p>
            <p className="text-[11px] text-slate-500 font-mono">
              MIT License // Open Security Research
            </p>
          </div>

        </div>

        {/* Bottom Line */}
        <div className="pt-8 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between text-[11px] text-slate-500 gap-4">
          <p>© 2026 NetGuard Team. Built for NTRO Problem Statement #26153.</p>
          <div className="flex items-center space-x-6">
            <span>Pristine Light Theme</span>
            <span>Air-Gapped Ready</span>
            <span>Temporal Transition P(S<sub>t+1</sub>|S<sub>t</sub>)</span>
          </div>
        </div>

      </div>
    </footer>
  );
}
