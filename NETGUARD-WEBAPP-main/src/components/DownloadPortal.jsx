import React, { useState } from 'react';
import { Download, Copy, Check, Terminal, Shield, Cpu, Package, Server, Lock, ExternalLink, HardDrive, Laptop } from 'lucide-react';
import { useScrollReveal } from '../hooks/useScrollReveal';

export default function DownloadPortal({ onOpenAuthModal }) {
  const [copied, setCopied] = useState(false);
  const [selectedOS, setSelectedOS] = useState('windows');
  const [downloadSuccess, setDownloadSuccess] = useState(null);
  const [sectionRef, isVisible] = useScrollReveal();

  const setupBashScript = `curl -fsSL https://get.netguard.ntro.gov.in/install.sh | sudo bash -s -- \\
  --mode=daemon \\
  --license=CII-AIRGAPPED-FREE-EVAL \\
  --telemetry-port=9092`;

  const downloads = [
    {
      id: 'windows',
      name: 'Windows Standalone Analyst GUI',
      file: 'NetGuard-Analyst-v1.0.4-Win64.exe',
      version: 'v1.0.4 Build 2026.08',
      size: '84.2 MB',
      format: '.exe Standalone Installer',
      icon: HardDrive,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      reqs: 'Windows 10/11 x64, 4GB RAM, Npcap 1.70+'
    },
    {
      id: 'linux',
      name: 'Linux Systemd Daemon (CLI)',
      file: 'netguard-daemon-v1.0.4-linux-x64.tar.gz',
      version: 'v1.0.4 Daemon Core',
      size: '42.1 MB',
      format: '.tar.gz Systemd Unit',
      icon: Terminal,
      sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      reqs: 'Ubuntu 20.04+, RHEL 8+, Kernel 5.4+, libpcap-dev'
    },
    {
      id: 'macos',
      name: 'macOS Standalone Analyst GUI',
      file: 'NetGuard-Analyst-v1.0.4-macOS.dmg',
      version: 'v1.0.4 Universal Binary',
      size: '76.4 MB',
      format: '.dmg Standalone App Package',
      icon: Laptop,
      sha256: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
      reqs: 'macOS 12.0+ (Monterey/Ventura/Sonoma), Apple Silicon & Intel'
    }
  ];

  const handleCopyScript = () => {
    navigator.clipboard.writeText(setupBashScript);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  const handleTriggerDownload = (item) => {
    window.open('https://github.com/MADOUT20/SIH-2026', '_blank');
    setDownloadSuccess(item.name);
    setTimeout(() => setDownloadSuccess(null), 4000);
  };

  const activeDownload = downloads.find((d) => d.id === selectedOS);

  return (
    <section 
      ref={sectionRef}
      id="downloads" 
      className="py-24 bg-slate-900 text-white relative overflow-hidden z-10"
    >
      
      {/* Background Radial Glow */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-brand-600/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 left-0 w-96 h-96 bg-indigo-600/10 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        
        {/* Section Header */}
        <div className={`text-center max-w-3xl mx-auto space-y-4 transition-all duration-700 ${
          isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
        }`}>
          <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-brand-900/60 border border-brand-700 text-brand-300 font-mono text-xs font-bold">
            <Server className="w-3.5 h-3.5" />
            <span>DEPLOYMENT & DOWNLOAD PORTAL</span>
          </div>

          <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
            Enterprise Client Distribution Hub
          </h2>

          <p className="text-slate-400 text-base sm:text-lg">
            Deploy NetGuard on air-gapped critical infrastructure networks or analyst workstations with full SHA-256 cryptographic verification.
          </p>
        </div>

        {/* OS Platform Selector Tabs */}
        <div className="mt-12 flex justify-center">
          <div className="bg-slate-800/80 p-1.5 rounded-2xl border border-slate-700/80 flex space-x-2 backdrop-blur-md">
            {downloads.map((d) => {
              const IconComp = d.icon;
              const isSelected = selectedOS === d.id;
              return (
                <button
                  key={d.id}
                  onClick={() => setSelectedOS(d.id)}
                  className={`px-5 py-2.5 rounded-xl text-xs font-bold font-sans flex items-center space-x-2 transition-all duration-300 active:scale-[0.98] ${
                    isSelected
                      ? 'bg-gradient-to-r from-brand-600 to-indigoAcc-600 text-white shadow-glow-cobalt'
                      : 'text-slate-400 hover:text-white hover:bg-slate-700/50'
                  }`}
                >
                  <IconComp className="w-4 h-4" />
                  <span>{d.name.split(' ')[0]}</span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Enterprise Style Download Showcase Card */}
        <div className="mt-8 bg-slate-950 rounded-3xl p-6 sm:p-10 border border-slate-800/90 shadow-2xl transition-all duration-300">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            
            {/* Left Specs Column */}
            <div className="lg:col-span-7 space-y-6">
              <div>
                <div className="flex items-center space-x-3 mb-2">
                  <span className="px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 text-[11px] font-mono font-bold flex items-center space-x-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 beacon-dot-emerald"></span>
                    <span>AIR-GAPPED READY</span>
                  </span>
                  <span className="text-xs font-mono text-slate-500">{activeDownload.version}</span>
                </div>
                
                <h3 className="text-2xl sm:text-3xl font-extrabold text-white">
                  {activeDownload.name}
                </h3>
                <p className="text-sm text-slate-400 mt-1">
                  Includes pre-compiled C++ IPFIX engine, Temporal World Model runtime, and local Web GUI.
                </p>
              </div>

              {/* SHA-256 Checksum & System Requirements */}
              <div className="space-y-3 font-mono text-xs bg-slate-900/90 p-4.5 rounded-2xl border border-slate-800">
                <div>
                  <span className="text-slate-500 font-bold block mb-1">SHA-256 CHECKSUM HASH:</span>
                  <p className="text-brand-300 break-all bg-slate-950 p-2.5 rounded-xl border border-slate-800/80 font-bold">
                    {activeDownload.sha256}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4 text-slate-300 pt-2 border-t border-slate-800">
                  <div>
                    <span className="text-slate-500 text-[10px] block">FILE FORMAT</span>
                    <span className="font-semibold">{activeDownload.format}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px]">MINIMUM REQUIREMENTS</span>
                    <span className="font-semibold">{activeDownload.reqs}</span>
                  </div>
                </div>
              </div>

              {/* Download CTA Button */}
              <div className="flex flex-col sm:flex-row items-stretch sm:items-center space-y-3 sm:space-y-0 sm:space-x-4 pt-2">
                <button
                  onClick={() => handleTriggerDownload(activeDownload)}
                  className="px-8 py-4 rounded-xl bg-gradient-to-r from-brand-600 via-brand-600 to-indigoAcc-600 hover:from-brand-500 hover:to-indigoAcc-500 text-white font-bold text-sm flex items-center justify-center space-x-3 shadow-glow-cobalt btn-shimmer transition-all duration-300 active:scale-[0.98]"
                >
                  <Download className="w-5 h-5 stroke-[2.5]" />
                  <span>Download Binary ({activeDownload.size})</span>
                </button>

                <button
                  onClick={onOpenAuthModal}
                  className="px-5 py-4 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white font-semibold text-xs border border-slate-700 flex items-center justify-center space-x-2 transition-all active:scale-[0.98]"
                >
                  <Lock className="w-4 h-4 text-slate-400" />
                  <span>Request CII License Key</span>
                </button>
              </div>

              {downloadSuccess && (
                <div className="p-3.5 rounded-xl bg-emerald-950/90 border border-emerald-800 text-emerald-300 text-xs font-mono flex items-center space-x-2 animate-fade-in">
                  <Check className="w-4 h-4 text-emerald-400" />
                  <span>Initiated download for {downloadSuccess}!</span>
                </div>
              )}
            </div>

            {/* Right Quick Setup Bash Script Block */}
            <div className="lg:col-span-5">
              <div className="bg-[#040711] rounded-3xl p-5 border border-slate-800 space-y-3 font-mono text-xs shadow-inner">
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="text-slate-400 font-bold flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-brand-400" />
                    <span>ONE-LINE AUTOMATED SETUP</span>
                  </span>
                  
                  <button
                    onClick={handleCopyScript}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] flex items-center space-x-1.5 border border-slate-700 transition-all active:scale-[0.98]"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied!' : 'Copy Script'}</span>
                  </button>
                </div>

                <div className="p-3.5 bg-slate-950 rounded-xl text-emerald-400 border border-slate-800/80 overflow-x-auto">
                  <pre className="text-[11px] leading-relaxed">{setupBashScript}</pre>
                </div>

                <p className="text-[11px] text-slate-500 font-sans leading-normal">
                  Installs systemd service daemon, configures local socket listening on port 9092, and sets up offline threat database cache.
                </p>
              </div>
            </div>

          </div>
        </div>

      </div>
    </section>
  );
}
