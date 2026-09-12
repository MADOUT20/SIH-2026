import React, { useState } from 'react';
import { Terminal, Copy, Check, ChevronRight, Shield, ArrowLeft, Info, AlertTriangle, ExternalLink } from 'lucide-react';

export default function CliDocsPage({ onNavigateToHero, onNavigateHome }) {
  const [copiedMap, setCopiedMap] = useState({});
  const [pageCopied, setPageCopied] = useState(false);

  const commands = {
    macLinux: 'curl -fsSL https://netguard.ntro.gov.in/install.sh | bash',
    powershell: 'iwr -useb https://raw.githubusercontent.com/MADOUT20/SIH-2026/main/NetGuard-Offline-CLI/install.ps1 | iex',
    cmd: '.\\venv\\Scripts\\python.exe -m main --file "Your_path_file"',
    uninstall1: 'cd <project-folder>',
    uninstall2: 'Remove-Item -Recurse -Force NetGuard-CLI'
  };

  const handleCopyCommand = (key) => {
    navigator.clipboard.writeText(commands[key]);
    setCopiedMap((prev) => ({ ...prev, [key]: true }));
    setTimeout(() => {
      setCopiedMap((prev) => ({ ...prev, [key]: false }));
    }, 2000);
  };

  const handleCopyPageLink = () => {
    navigator.clipboard.writeText(window.location.href);
    setPageCopied(true);
    setTimeout(() => setPageCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#0c0d12] text-slate-200 font-sans selection:bg-brand-500 selection:text-white">
      
      {/* Top sticky header bar */}
      <header className="border-b border-slate-800/80 bg-[#07080c]/90 backdrop-blur-md sticky top-0 z-30 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <button
              onClick={onNavigateToHero}
              className="inline-flex items-center space-x-2 text-xs font-semibold text-slate-400 hover:text-white bg-slate-800/60 hover:bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700/60 transition-all"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to CLI Overview</span>
            </button>

            <div className="h-4 w-[1px] bg-slate-800 hidden sm:block" />

            <div 
              onClick={onNavigateHome}
              className="flex items-center space-x-2 cursor-pointer group"
            >
              <Shield className="w-5 h-5 text-brand-400" />
              <span className="font-bold text-sm text-white font-sans">
                NetGuard Docs
              </span>
            </div>
          </div>

          <button
            onClick={handleCopyPageLink}
            className="inline-flex items-center space-x-2 px-3 py-1.5 rounded-xl bg-slate-800/80 hover:bg-slate-800 text-xs font-semibold text-slate-300 border border-slate-700/80 transition-all active:scale-95"
          >
            {pageCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{pageCopied ? 'Page Link Copied!' : 'Copy page'}</span>
          </button>
        </div>
      </header>

      {/* Main Documentation Container */}
      <main className="max-w-4xl mx-auto px-6 py-12">
        
        {/* GETTING STARTED Badge */}
        <div className="text-xs font-bold font-mono tracking-wider text-rose-400/90 uppercase mb-3">
          GETTING STARTED
        </div>

        {/* Overview Header Section */}
        <div className="flex items-start justify-between border-b border-slate-800/60 pb-8 mb-8">
          <div>
            <h1 className="text-4xl sm:text-5xl font-extrabold text-white tracking-tight font-serif">
              Overview
            </h1>
            <div className="mt-4 space-y-4 text-slate-300 text-base sm:text-lg leading-relaxed max-w-3xl font-normal">
              <p>
                NetGuard CLI is an offline working demonstration interface (CLI) that accepts a PCAP or CSV and PARQUET file as input, runs the world model inference, and displays the infiltration probability timeline, flagged flows, and attack stage annotations.
              </p>
            </div>
          </div>
        </div>

        {/* Get Started Section */}
        <section className="mb-10">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight mb-4 font-serif">
            Get started
          </h2>
          <p className="text-slate-300 text-base leading-relaxed mb-6 max-w-3xl">
            NetGuard CLI runs on your terminal. Most setups require a{' '}
            <span className="text-white underline font-semibold cursor-pointer hover:text-brand-400">
              NetGuard subscription
            </span>{' '}
            or{' '}
            <span className="text-white underline font-semibold cursor-pointer hover:text-brand-400">
              Enterprise Console
            </span>{' '}
            account. The Terminal CLI also supports third-party integrations.
          </p>

          {/* Surface Tabs - ONLY Terminal included as requested (No VS Code, Desktop app, Web, JetBrains) */}
          <div className="border-b border-slate-800 mb-6">
            <div className="flex space-x-8">
              <button className="pb-3 text-sm font-semibold text-rose-400 border-b-2 border-rose-400 font-sans">
                Terminal
              </button>
            </div>
          </div>

          <p className="text-slate-300 text-sm sm:text-base leading-relaxed mb-6">
            The full-featured CLI for working with NetGuard CLI directly in your terminal. Displays the infiltration probability timeline, flagged flows, and attack stage annotations.
          </p>

          <p className="text-slate-400 text-sm mb-4">
            To install NetGuard CLI, use one of the following methods:
          </p>

          {/* Sub-tabs - ONLY Native Install (Recommended) included (No Homebrew, WinGet) */}
          <div className="border-b border-slate-800 mb-8">
            <div className="flex space-x-8">
              <button className="pb-3 text-sm font-semibold text-rose-400 border-b-2 border-rose-400 font-sans">
                Native Install (Recommended)
              </button>
            </div>
          </div>

          {/* Operating System Install Command Blocks */}
          <div className="space-y-8">
            
            {/* Block 1: macOS, Linux, WSL */}
            <div>
              <h3 className="text-sm font-bold text-white mb-3">
                macOS, Linux, WSL:
              </h3>
              <div className="bg-[#05070a] border border-slate-800/90 rounded-2xl p-4 flex items-center justify-between group hover:border-slate-700 transition-colors">
                <code className="font-mono text-xs sm:text-sm text-amber-200/90 break-all pr-4">
                  {commands.macLinux}
                </code>
                <button
                  onClick={() => handleCopyCommand('macLinux')}
                  className="p-2 rounded-xl text-slate-400 hover:text-white bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all active:scale-95 flex-shrink-0"
                  title="Copy command"
                >
                  {copiedMap.macLinux ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Block 2: Windows PowerShell */}
            <div>
              <h3 className="text-sm font-bold text-white mb-3">
                Windows PowerShell:
              </h3>
              <div className="bg-[#05070a] border border-slate-800/90 rounded-2xl p-4 flex items-center justify-between group hover:border-slate-700 transition-colors">
                <code className="font-mono text-xs sm:text-sm text-amber-200/90 break-all pr-4">
                  {commands.powershell}
                </code>
                <button
                  onClick={() => handleCopyCommand('powershell')}
                  className="p-2 rounded-xl text-slate-400 hover:text-white bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all active:scale-95 flex-shrink-0"
                  title="Copy command"
                >
                  {copiedMap.powershell ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Block 3: File Upload Command */}
            <div>
              <h3 className="text-sm font-bold text-white mb-3">
                File Upload Command:
              </h3>
              <div className="bg-[#05070a] border border-slate-800/90 rounded-2xl p-4 flex items-center justify-between group hover:border-slate-700 transition-colors">
                <code className="font-mono text-xs sm:text-sm text-amber-200/90 break-all pr-4">
                  {commands.cmd}
                </code>
                <button
                  onClick={() => handleCopyCommand('cmd')}
                  className="p-2 rounded-xl text-slate-400 hover:text-white bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all active:scale-95 flex-shrink-0"
                  title="Copy command"
                >
                  {copiedMap.cmd ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Block 4: Uninstalling the Netguard CLI */}
            <div>
              <h3 className="text-sm font-bold text-white mb-3">
                Uninstalling the Netguard CLI:
              </h3>
              <div className="space-y-3">
                <div className="bg-[#05070a] border border-slate-800/90 rounded-2xl p-4 flex items-center justify-between group hover:border-slate-700 transition-colors">
                  <code className="font-mono text-xs sm:text-sm text-amber-200/90 break-all pr-4">
                    {commands.uninstall1}
                  </code>
                  <button
                    onClick={() => handleCopyCommand('uninstall1')}
                    className="p-2 rounded-xl text-slate-400 hover:text-white bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all active:scale-95 flex-shrink-0"
                    title="Copy command"
                  >
                    {copiedMap.uninstall1 ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>

                <div className="bg-[#05070a] border border-slate-800/90 rounded-2xl p-4 flex items-center justify-between group hover:border-slate-700 transition-colors">
                  <code className="font-mono text-xs sm:text-sm text-amber-200/90 break-all pr-4">
                    {commands.uninstall2}
                  </code>
                  <button
                    onClick={() => handleCopyCommand('uninstall2')}
                    className="p-2 rounded-xl text-slate-400 hover:text-white bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all active:scale-95 flex-shrink-0"
                    title="Copy command"
                  >
                    {copiedMap.uninstall2 ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>

          </div>
        </section>

        {/* Troubleshooting & Syntax Notes matching Image 2 */}
        <section className="mt-12 space-y-6 text-sm text-slate-300 leading-relaxed border-t border-slate-800/70 pt-8">
          
          {/* Note 1: Token && and irm clarification */}
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-5 space-y-3">
            <p>
              If you see{' '}
              <code className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800 font-mono text-xs text-slate-200">
                The token '&amp;&amp;' is not a valid statement separator
              </code>
              , you're in PowerShell, not CMD. If you see{' '}
              <code className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800 font-mono text-xs text-slate-200">
                'irm' is not recognized as an internal or external command
              </code>
              , you're in CMD, not PowerShell. Your prompt shows{' '}
              <code className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800 font-mono text-xs text-white">
                PS C:\
              </code>{' '}
              when you're in PowerShell and{' '}
              <code className="bg-slate-950 px-2 py-0.5 rounded border border-slate-800 font-mono text-xs text-white">
                C:\
              </code>{' '}
              without the <span className="font-mono text-white font-bold">PS</span> when you're in CMD.
            </p>
          </div>

          {/* Note 2: Curl failure matching Image 2 */}
          <p>
            If the install command fails with{' '}
            <code className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 font-mono text-xs text-slate-200">
              syntax error near unexpected token '&lt;'
            </code>
            , a{' '}
            <code className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800 font-mono text-xs text-slate-200">
              403
            </code>
            , or another curl error, see{' '}
            <span className="font-semibold text-rose-300 underline cursor-pointer hover:text-rose-200">
              Troubleshoot installation
            </span>{' '}
            to match the error to a fix and for alternative install methods.
          </p>

          {/* Note 3: Git for Windows matching Image 2 */}
          <p className="pt-2">
            <strong className="text-white border-b border-slate-500">Git for Windows</strong> is recommended on native Windows so NetGuard CLI can use the Bash tool. If Git for Windows is not installed, NetGuard CLI uses PowerShell as the shell tool instead. WSL setups do not need Git for Windows.
          </p>

        </section>

      </main>

      {/* Simple Docs Footer */}
      <footer className="border-t border-slate-800 bg-[#07080c] py-8 px-6 text-center text-xs text-slate-500 mt-20">
        <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <p>© 2026 NetGuard Security Architecture. Documentation &amp; CLI Guides.</p>
          <div className="flex space-x-6">
            <button onClick={onNavigateToHero} className="hover:text-white">CLI Hero</button>
            <button onClick={onNavigateHome} className="hover:text-white">Main Website</button>
          </div>
        </div>
      </footer>

    </div>
  );
}
