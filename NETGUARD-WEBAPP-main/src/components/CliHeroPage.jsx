import React, { useState } from 'react';
import { Terminal, Copy, Check, ChevronRight, Github, MessageSquare, Sparkles, ArrowRight, Shield } from 'lucide-react';

export default function CliHeroPage({ onNavigateToDocs, onNavigateHome }) {
  const [copied, setCopied] = useState(false);
  const command = 'iwr -useb https://raw.githubusercontent.com/MADOUT20/SIH-2026/main/NetGuard-Offline-CLI/install.ps1 | iex';

  const handleCopy = () => {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-white flex flex-col justify-between font-sans relative overflow-hidden selection:bg-brand-500 selection:text-white">
      
      {/* Dynamic Ambient Background Glows */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[500px] bg-gradient-to-tr from-brand-600/20 via-indigo-600/15 to-purple-600/10 rounded-full blur-[140px] pointer-events-none" />
      <div className="absolute bottom-10 right-10 w-[400px] h-[400px] bg-emerald-500/10 rounded-full blur-[120px] pointer-events-none" />

      {/* Top Banner Alert Bar */}
      <div className="bg-gradient-to-r from-brand-900/90 via-slate-900 to-indigo-950/90 border-b border-brand-500/20 py-2.5 px-4 text-center text-xs font-medium text-slate-300 relative z-20">
        <span className="inline-flex items-center space-x-2">
          <span className="px-2 py-0.5 rounded-full bg-brand-500/20 text-brand-300 font-mono text-[11px] font-bold border border-brand-500/30">
            NEW RELEASE
          </span>
          <span>NetGuard CLI v1.2.0 is live! Enterprise terminal threat engine & automated defense.</span>
          <button 
            onClick={onNavigateToDocs}
            className="text-brand-400 hover:text-brand-300 underline font-semibold ml-1 cursor-pointer transition-colors"
          >
            Learn more &rarr;
          </button>
        </span>
      </div>

      {/* Page Header Bar matching image header */}
      <header className="border-b border-slate-800/80 bg-slate-950/60 backdrop-blur-md sticky top-0 z-30 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          
          <div className="flex items-center space-x-8">
            {/* Logo */}
            <div 
              onClick={onNavigateHome}
              className="flex items-center space-x-2 cursor-pointer group"
            >
              <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-brand-600 to-indigoAcc-600 flex items-center justify-center text-white shadow-glow-cobalt group-hover:scale-105 transition-transform">
                <Shield className="w-5 h-5" />
              </div>
              <span className="font-extrabold text-lg tracking-tight text-white font-sans">
                NetGuard <span className="font-mono text-brand-400 font-bold">CLI</span>
              </span>
            </div>

            {/* Sub-nav Links */}
            <nav className="hidden lg:flex items-center space-x-6 text-sm text-slate-400 font-medium">
              <button onClick={onNavigateHome} className="hover:text-white transition-colors">Platform</button>
              <button onClick={onNavigateToDocs} className="hover:text-white transition-colors">Docs</button>
              <button onClick={onNavigateToDocs} className="hover:text-white transition-colors">Reference</button>
              <button onClick={onNavigateToDocs} className="hover:text-white transition-colors">Resources</button>
              <button onClick={onNavigateToDocs} className="hover:text-white transition-colors">Changelog</button>
            </nav>
          </div>

        </div>
      </header>

      {/* Main Hero Content matching Image 1 layout */}
      <main className="flex-1 flex flex-col items-center justify-center px-4 py-20 relative z-10 text-center max-w-4xl mx-auto">
        
        {/* Main Bold Headline */}
        <h1 className="text-3xl sm:text-5xl md:text-6xl font-extrabold text-white tracking-tight leading-[1.15] mb-6 uppercase">
          NETGUARD{' '}
          <span className="inline-flex items-center justify-center mx-1.5 w-11 h-11 sm:w-14 sm:h-14 rounded-2xl bg-gradient-to-tr from-brand-600 via-indigoAcc-600 to-purple-600 text-white shadow-glow-cobalt align-middle">
            <Shield className="w-6 h-6 sm:w-8 sm:h-8 stroke-[2.2]" />
          </span>{' '}
          OFFLINE DEMONSTRATION INTERFACE
        </h1>

        {/* Subtitle description */}
        <p className="text-slate-300 text-base sm:text-xl max-w-3xl font-normal leading-relaxed mb-10">
          Working demonstration interface (CLI) that accepts a PCAP or CSV And PARQUET file as input, runs the world model inference, and displays the infiltration probability timeline, flagged flows, and attack stage annotations.
        </p>

        {/* Terminal Installation Code Box */}
        <div className="w-full max-w-3xl bg-slate-950/90 border border-slate-800 rounded-2xl p-3 shadow-2xl backdrop-blur-xl hover:border-brand-500/50 transition-all duration-300">
          <div className="flex items-center justify-between font-mono text-xs sm:text-sm px-3 py-1.5">
            <div className="flex items-center space-x-2 text-slate-300 overflow-x-auto text-left mr-2">
              <span className="text-brand-400 font-bold">$</span>
              <span className="break-all">{command}</span>
            </div>
            
            <button
              onClick={handleCopy}
              title="Copy to clipboard"
              className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800/80 transition-all active:scale-95 flex-shrink-0"
            >
              {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Link requested by user: 'More Install Options and Documentation' */}
        <div className="mt-6">
          <button
            onClick={onNavigateToDocs}
            className="inline-flex items-center space-x-2 text-brand-400 hover:text-brand-300 font-medium text-sm sm:text-base group transition-all duration-200 underline underline-offset-4 decoration-brand-500/40 hover:decoration-brand-400"
          >
            <span>More Install Options and Documentation</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </button>
        </div>

      </main>

      {/* Footer minimal info */}
      <footer className="border-t border-slate-900 bg-slate-950/40 py-6 px-6 text-center text-xs text-slate-500 relative z-10">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <p>© 2026 NetGuard Security Architecture. All rights reserved.</p>
          <div className="flex space-x-6 text-slate-400">
            <button onClick={onNavigateHome} className="hover:text-white">Main Site</button>
            <button onClick={onNavigateToDocs} className="hover:text-white">CLI Documentation</button>
            <a href="https://github.com/MADOUT20/SIH-2026" target="_blank" rel="noreferrer" className="hover:text-white">Repository</a>
          </div>
        </div>
      </footer>

    </div>
  );
}
