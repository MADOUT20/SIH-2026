import React, { useState } from 'react';
import { X, Lock, Key, Shield, User, Building, Mail, Check, Copy, Sparkles, Terminal } from 'lucide-react';

export default function AuthModal({ isOpen, onClose }) {
  const [activeTab, setActiveTab] = useState('login'); // 'login' or 'request'
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  // License Request Form
  const [orgName, setOrgName] = useState('');
  const [sector, setSector] = useState('Defense & Aerospace');
  const [contactEmail, setContactEmail] = useState('');
  const [generatedKey, setGeneratedKey] = useState(null);
  const [copiedKey, setCopiedKey] = useState(false);

  if (!isOpen) return null;

  const handleLoginSubmit = (e) => {
    e.preventDefault();
    setIsLoggedIn(true);
  };

  const handleGenerateKey = (e) => {
    e.preventDefault();
    const randomHex1 = Math.random().toString(36).substring(2, 6).toUpperCase();
    const randomHex2 = Math.random().toString(36).substring(2, 6).toUpperCase();
    const key = `NETGUARD-NTRO-2026-${randomHex1}-${randomHex2}-AIRGAPPED`;
    setGeneratedKey(key);
  };

  const handleCopyKey = () => {
    if (generatedKey) {
      navigator.clipboard.writeText(generatedKey);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2500);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-md flex items-center justify-center p-4 animate-fade-in">
      <div className="bg-white rounded-3xl max-w-md w-full border border-slate-200 shadow-2xl overflow-hidden relative">
        
        {/* Top Header */}
        <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-brand-950 p-6 text-white relative">
          <button
            onClick={onClose}
            className="absolute top-5 right-5 p-1.5 rounded-full bg-slate-800/80 text-slate-400 hover:text-white hover:bg-slate-700 transition-smooth"
          >
            <X className="w-5 h-5" />
          </button>

          <div className="w-10 h-10 rounded-xl bg-brand-600 flex items-center justify-center text-white mb-3 shadow-glow-cobalt">
            <Shield className="w-6 h-6" />
          </div>

          <h3 className="text-xl font-extrabold font-sans">
            NetGuard CII Portal Access
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            NTRO Problem Statement #26153
          </p>

          {/* Navigation Tabs */}
          <div className="mt-5 grid grid-cols-2 gap-1 bg-slate-800/90 p-1 rounded-xl border border-slate-700/80">
            <button
              onClick={() => setActiveTab('login')}
              className={`py-1.5 rounded-lg text-xs font-bold transition-smooth ${
                activeTab === 'login' ? 'bg-brand-600 text-white shadow-subtle' : 'text-slate-400 hover:text-white'
              }`}
            >
              Analyst Login
            </button>
            <button
              onClick={() => setActiveTab('request')}
              className={`py-1.5 rounded-lg text-xs font-bold transition-smooth ${
                activeTab === 'request' ? 'bg-brand-600 text-white shadow-subtle' : 'text-slate-400 hover:text-white'
              }`}
            >
              Request CII Access Key
            </button>
          </div>
        </div>

        {/* Form Body */}
        <div className="p-6 space-y-4">
          
          {/* Tab 1: Analyst Login */}
          {activeTab === 'login' && (
            <div>
              {isLoggedIn ? (
                <div className="text-center py-6 space-y-3">
                  <div className="w-12 h-12 rounded-full bg-emerald-100 text-emerald-600 mx-auto flex items-center justify-center">
                    <Check className="w-6 h-6 stroke-[3]" />
                  </div>
                  <h4 className="text-lg font-bold text-slate-900">SOC Analyst Authenticated</h4>
                  <p className="text-xs text-slate-500 font-mono">
                    Session token active for 12 hours. Full telemetry access unlocked.
                  </p>
                  <button
                    onClick={onClose}
                    className="w-full py-2.5 rounded-xl bg-slate-900 text-white font-bold text-xs"
                  >
                    Return to Dashboard
                  </button>
                </div>
              ) : (
                <form onSubmit={handleLoginSubmit} className="space-y-4">
                  <div>
                    <label className="block text-xs font-bold text-slate-700 mb-1.5">
                      Government / Org Security Email
                    </label>
                    <div className="relative">
                      <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                      <input
                        type="email"
                        required
                        value={loginEmail}
                        onChange={(e) => setLoginEmail(e.target.value)}
                        placeholder="analyst@ntro.gov.in"
                        className="w-full pl-9 pr-3 py-2.5 rounded-xl border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-brand-600 focus:ring-1 focus:ring-brand-600"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-700 mb-1.5">
                      Password & MFA Security Token
                    </label>
                    <div className="relative">
                      <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
                      <input
                        type="password"
                        required
                        value={loginPassword}
                        onChange={(e) => setLoginPassword(e.target.value)}
                        placeholder="••••••••••••"
                        className="w-full pl-9 pr-3 py-2.5 rounded-xl border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-brand-600 focus:ring-1 focus:ring-brand-600"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    className="w-full py-3 rounded-xl bg-brand-600 hover:bg-brand-700 text-white font-bold text-xs shadow-glow-cobalt btn-shimmer transition-all active:scale-[0.98]"
                  >
                    Authenticate Analyst Portal
                  </button>
                </form>
              )}
            </div>
          )}

          {/* Tab 2: Request Access Key */}
          {activeTab === 'request' && (
            <div>
              {generatedKey ? (
                <div className="space-y-4 pt-1">
                  <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-center">
                    <Sparkles className="w-5 h-5 text-emerald-600 mx-auto mb-1" />
                    <h4 className="text-sm font-bold text-emerald-900">CII Evaluation License Generated</h4>
                    <p className="text-[11px] text-emerald-700 mt-0.5">Air-gapped deployment ready.</p>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] font-mono font-bold text-slate-500">YOUR CRYPTOGRAPHIC LICENSE KEY:</span>
                    <div className="flex items-center space-x-2">
                      <input
                        type="text"
                        readOnly
                        value={generatedKey}
                        className="flex-1 bg-slate-900 text-emerald-400 font-mono text-xs p-2.5 rounded-xl border border-slate-800 font-bold"
                      />
                      <button
                        onClick={handleCopyKey}
                        className="px-3 py-2.5 rounded-xl bg-brand-600 hover:bg-brand-700 text-white text-xs font-bold transition-all shrink-0 active:scale-[0.98]"
                      >
                        {copiedKey ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <p className="text-[11px] text-slate-500 leading-normal">
                    This license key is valid for local air-gapped deployments of NetGuard Linux Daemon and Windows Analyst GUI.
                  </p>

                  <button
                    onClick={() => setGeneratedKey(null)}
                    className="w-full py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 font-bold text-xs active:scale-[0.98]"
                  >
                    Generate Another License
                  </button>
                </div>
              ) : (
                <form onSubmit={handleGenerateKey} className="space-y-3">
                  <div>
                    <label className="block text-xs font-bold text-slate-700 mb-1">
                      Organization Name
                    </label>
                    <div className="relative">
                      <Building className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        required
                        value={orgName}
                        onChange={(e) => setOrgName(e.target.value)}
                        placeholder="NTRO / Defense Lab / Power Grid Authority"
                        className="w-full pl-9 pr-3 py-2 rounded-xl border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-brand-600"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-700 mb-1">
                      Critical Infrastructure Sector
                    </label>
                    <select
                      value={sector}
                      onChange={(e) => setSector(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-brand-600 bg-white"
                    >
                      <option>Defense & Aerospace</option>
                      <option>Power & Energy Grid</option>
                      <option>Banking & Financial Services (BFSI)</option>
                      <option>Telecom & Subsea Cables</option>
                      <option>Academic & Defense Research</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-700 mb-1">
                      Official Contact Email
                    </label>
                    <div className="relative">
                      <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                      <input
                        type="email"
                        required
                        value={contactEmail}
                        onChange={(e) => setContactEmail(e.target.value)}
                        placeholder="researcher@cii.gov.in"
                        className="w-full pl-9 pr-3 py-2 rounded-xl border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-brand-600"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    className="w-full py-3 rounded-xl bg-gradient-to-r from-brand-600 to-indigoAcc-600 hover:from-brand-700 hover:to-indigoAcc-700 text-white font-bold text-xs shadow-glow-cobalt btn-shimmer transition-all mt-2 active:scale-[0.98]"
                  >
                    Generate Instant Evaluation Access Key
                  </button>
                </form>
              )}
            </div>
          )}

        </div>

      </div>
    </div>
  );
}
