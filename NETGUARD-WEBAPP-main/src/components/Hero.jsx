import React, { useState } from 'react';
import { Download, Play, ShieldAlert, Sparkles, ChevronDown, Check, Terminal, Cpu, Zap, Activity } from 'lucide-react';
import NetworkTopologyVisualizer from './NetworkTopologyVisualizer';
import { useScrollReveal } from '../hooks/useScrollReveal';

export default function Hero({ onScrollToSection, onOpenAuthModal }) {
  const [osMenuOpen, setOsMenuOpen] = useState(false);
  const [selectedOS, setSelectedOS] = useState('Windows x64 (.exe)');
  const [sectionRef, isVisible] = useScrollReveal();

  const osOptions = [
    { label: 'Windows x64 (.exe / GUI)', icon: '💻', file: 'NetGuard-v1.0.4-Win64.zip' },
    { label: 'Linux Daemon (.tar.gz / CLI)', icon: '🐧', file: 'netguard-v1.0.4-linux-x86_64.tar.gz' },
    { label: 'macOS Universal (.dmg / GUI)', icon: '🍎', file: 'NetGuard-v1.0.4-macOS.dmg' }
  ];

  const handleDownloadOS = (os) => {
    setSelectedOS(os.label);
    setOsMenuOpen(false);
    window.open('https://github.com/MADOUT20/SIH-2026', '_blank');
  };

  return (
    <section 
      ref={sectionRef}
      id="hero" 
      className="relative pt-28 pb-16 lg:pt-36 lg:pb-24 overflow-hidden bg-transparent"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className={`grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center transition-all duration-700 ${
          isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
        }`}>
          
          {/* Left Column: Value Proposition & CTAs */}
          <div className="lg:col-span-6 space-y-6 text-left">
            
            {/* Top Pill Tag */}
            <div className="inline-flex items-center space-x-2 px-4 py-1.5 rounded-full bg-gradient-to-r from-brand-50 via-indigo-50 to-emerald-50 border border-brand-200/80 text-brand-700 shadow-subtle hover:border-brand-300 transition-all">
              <Sparkles className="w-4 h-4 text-brand-600 animate-pulse" />
              <span className="text-xs font-bold font-sans tracking-wide bg-clip-text text-transparent bg-gradient-to-r from-brand-700 via-indigoAcc-600 to-emerald-600">
                ✨ World Models for Proactive Network Defense
              </span>
            </div>

            {/* Headline */}
            <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold text-slate-900 tracking-tight leading-[1.15]">
              Predict Infiltration <span className="bg-clip-text text-transparent bg-gradient-to-r from-brand-600 via-indigoAcc-600 to-brand-700">Before Compromise Occurs</span> with World Models.
            </h1>

            {/* Subtitle with Math Formula */}
            <p className="text-base sm:text-lg text-slate-600 font-normal leading-relaxed">
              NetGuard ingests NetFlow and raw packet telemetry to learn temporal network transition dynamics{' '}
              <span className="font-mono text-sm font-semibold bg-white/90 text-brand-900 px-2.5 py-1 rounded-lg border border-slate-200 shadow-subtle inline-block">
                P(S<sub>t+1</sub> | S<sub>t</sub>)
              </span>
              , enabling forward simulation of multi-step cyber attacks in Critical Information Infrastructure (CII).
            </p>

            {/* Metric Pills Row */}
            <div className="grid grid-cols-3 gap-3 pt-2">
              <div className="glass-card p-3.5 rounded-2xl hover:border-brand-300 hover:shadow-xl hover:shadow-blue-500/5 hover:-translate-y-1 transition-all duration-300">
                <p className="text-lg sm:text-xl font-extrabold text-slate-900 font-mono">98.4%</p>
                <p className="text-[11px] font-medium text-slate-500">Attack F1-Score</p>
              </div>
              <div className="glass-card p-3.5 rounded-2xl hover:border-emerald-300 hover:shadow-xl hover:shadow-emerald-500/5 hover:-translate-y-1 transition-all duration-300">
                <p className="text-lg sm:text-xl font-extrabold text-emerald-600 font-mono">&lt; 0.4%</p>
                <p className="text-[11px] font-medium text-slate-500">False Positives</p>
              </div>
              <div className="glass-card p-3.5 rounded-2xl hover:border-indigo-300 hover:shadow-xl hover:shadow-indigo-500/5 hover:-translate-y-1 transition-all duration-300">
                <p className="text-lg sm:text-xl font-extrabold text-indigoAcc-600 font-mono">K=5 Step</p>
                <p className="text-[11px] font-medium text-slate-500">Forward Rollout</p>
              </div>
            </div>

            {/* CTA Button Group */}
            <div className="pt-2 flex flex-col sm:flex-row items-stretch sm:items-center space-y-3 sm:space-y-0 sm:space-x-4 relative">
              
              {/* Primary Dropdown Button */}
              <div className="relative">
                <div className="inline-flex rounded-xl shadow-glow-cobalt overflow-hidden active:scale-[0.98] transition-transform">
                  <button
                    onClick={() => window.open('https://github.com/MADOUT20/SIH-2026', '_blank')}
                    className="px-5 py-3.5 bg-gradient-to-r from-brand-600 via-brand-600 to-indigoAcc-600 hover:from-brand-700 hover:to-indigoAcc-700 text-white text-sm font-bold flex items-center space-x-2 btn-shimmer transition-all"
                  >
                    <Download className="w-4 h-4 stroke-[2.5]" />
                    <span>Download Client (v1.0.4)</span>
                  </button>
                  <button
                    onClick={() => setOsMenuOpen(!osMenuOpen)}
                    className="px-3 py-3.5 bg-brand-700 hover:bg-brand-800 text-white border-l border-brand-500/50 transition-all"
                    title="Select Operating System"
                  >
                    <ChevronDown className="w-4 h-4" />
                  </button>
                </div>

                {/* OS Dropdown */}
                {osMenuOpen && (
                  <div className="absolute left-0 mt-2 w-64 bg-white/95 backdrop-blur-lg rounded-2xl shadow-floating border border-slate-200/80 p-2 z-30 animate-fade-in">
                    <p className="text-[10px] font-mono font-bold text-slate-400 px-3 py-1.5 uppercase">
                      Select Target Platform
                    </p>
                    {osOptions.map((os, idx) => (
                      <button
                        key={idx}
                        onClick={() => handleDownloadOS(os)}
                        className="w-full text-left px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-brand-50 hover:text-brand-700 rounded-xl flex items-center justify-between transition-all"
                      >
                        <span className="flex items-center space-x-2">
                          <span>{os.icon}</span>
                          <span>{os.label}</span>
                        </span>
                        {selectedOS === os.label && <Check className="w-3.5 h-3.5 text-brand-600" />}
                      </button>
                    ))}
                  </div>
                )}
              </div>

              {/* Secondary Telemetry Sandbox Scroll CTA */}
              <button
                onClick={() => onScrollToSection('sandbox')}
                className="px-5 py-3.5 bg-white/80 hover:bg-white text-slate-800 border border-slate-200/90 hover:border-slate-300 rounded-xl text-sm font-bold flex items-center justify-center space-x-2 transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/5 active:scale-[0.98]"
              >
                <Activity className="w-4 h-4 text-brand-600" />
                <span>Open Telemetry Sandbox</span>
              </button>

            </div>

            {/* Compliance Footnote */}
            <div className="flex flex-wrap items-center gap-4 pt-2 text-xs text-slate-500 font-mono">
              <span className="flex items-center space-x-1.5">
                <Check className="w-3.5 h-3.5 text-emerald-500" />
                <span>CIC-IDS-2018 Validated</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <Check className="w-3.5 h-3.5 text-emerald-500" />
                <span>Air-Gapped Ready</span>
              </span>
              <span className="flex items-center space-x-1.5">
                <Check className="w-3.5 h-3.5 text-emerald-500" />
                <span>NTRO Compliant</span>
              </span>
            </div>

          </div>

          {/* Right Column: Network Topology Interactive Visualizer */}
          <div className="lg:col-span-6">
            <NetworkTopologyVisualizer />
          </div>

        </div>
      </div>
    </section>
  );
}
