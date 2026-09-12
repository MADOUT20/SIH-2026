import React, { useState, useEffect } from 'react';
import { Shield, Activity, AlertTriangle, ShieldCheck, Database, Server, Globe, Cpu, Radio, RefreshCw, Play, SkipForward } from 'lucide-react';

const STAGES = [
  {
    id: 0,
    name: 'Normal Telemetry Baseline',
    status: 'normal',
    badge: 'Baseline Operational',
    badgeColor: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    description: 'Environmental state normal. No anomaly detected. Markov transition dynamic stable.',
    prob: '0.02%',
    activeNodes: ['gateway', 'web', 'dns', 'workstation', 'db'],
    infectedNodes: [],
    warningNodes: [],
  },
  {
    id: 1,
    name: 'Step 1: Reconnaissance & Port Scan',
    status: 'warning',
    badge: 'Stage T1046: Network Service Scanning',
    badgeColor: 'bg-amber-50 text-amber-700 border-amber-200',
    description: 'High SYN packet bursts detected at Edge Gateway & Web Server. Entropy spike +3.4.',
    prob: '28.4%',
    activeNodes: ['gateway', 'web'],
    infectedNodes: [],
    warningNodes: ['gateway', 'web'],
  },
  {
    id: 2,
    name: 'Step 2: Web Server Vulnerability Exploitation',
    status: 'warning',
    badge: 'Stage T1190: Exploit Public App',
    badgeColor: 'bg-amber-50 text-amber-700 border-amber-200',
    description: 'Unauthenticated RCE payload match on Web Server. Privilege escalation sequence initiated.',
    prob: '64.8%',
    activeNodes: ['gateway', 'web', 'dns'],
    infectedNodes: ['web'],
    warningNodes: ['dns', 'workstation'],
  },
  {
    id: 3,
    name: 'Step 3: Internal Host Lateral Movement',
    status: 'critical',
    badge: 'Stage T1021: Remote Services',
    badgeColor: 'bg-red-50 text-red-700 border-red-200',
    description: 'Pass-the-hash payload propagated to DNS Server & Host Workstation. Internal pivoting detected.',
    prob: '89.1%',
    activeNodes: ['web', 'dns', 'workstation', 'db'],
    infectedNodes: ['web', 'dns', 'workstation'],
    warningNodes: ['db'],
  },
  {
    id: 4,
    name: 'Step 4: Target Database Compromise Forecast',
    status: 'critical',
    badge: 'Stage T1567: Data Exfiltration Horizon',
    badgeColor: 'bg-red-50 text-red-700 border-red-200',
    description: 'World Model predicts high probability (98.4%) of Target DB breach within t+4 rollout steps.',
    prob: '98.4%',
    activeNodes: ['workstation', 'db'],
    infectedNodes: ['web', 'dns', 'workstation', 'db'],
    warningNodes: [],
  }
];

export default function NetworkTopologyVisualizer() {
  const [currentStageIndex, setCurrentStageIndex] = useState(0);
  const [autoPlay, setAutoPlay] = useState(false);

  useEffect(() => {
    let interval = null;
    if (autoPlay) {
      interval = setInterval(() => {
        setCurrentStageIndex((prev) => (prev + 1) % STAGES.length);
      }, 3500);
    }
    return () => clearInterval(interval);
  }, [autoPlay]);

  const stage = STAGES[currentStageIndex];

  const getNodeColor = (nodeId) => {
    if (stage.infectedNodes.includes(nodeId)) {
      return {
        bg: 'bg-red-50',
        border: 'border-red-400',
        icon: 'text-red-600',
        glow: 'shadow-glow-crimson pulse-ring-crimson',
        pill: 'bg-red-500 text-white',
        statusText: 'COMPROMISED'
      };
    }
    if (stage.warningNodes.includes(nodeId)) {
      return {
        bg: 'bg-amber-50',
        border: 'border-amber-400',
        icon: 'text-amber-600',
        glow: 'shadow-md',
        pill: 'bg-amber-500 text-white',
        statusText: 'TARGETED'
      };
    }
    return {
      bg: 'bg-emerald-50/70',
      border: 'border-emerald-300',
      icon: 'text-emerald-600',
      glow: 'shadow-sm',
      pill: 'bg-emerald-500 text-white',
      statusText: 'SECURE'
    };
  };

  return (
    <div className="w-full glass-card-elevated rounded-3xl overflow-hidden transition-all duration-300 hover:border-brand-300/80 hover:shadow-2xl hover:shadow-blue-500/10">
      
      {/* Top Header Bar */}
      <div className="bg-slate-900 text-white px-5 py-3.5 flex items-center justify-between font-mono text-xs border-b border-slate-800">
        <div className="flex items-center space-x-2.5">
          <div className="flex space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
          </div>
          <span className="text-slate-400 font-semibold border-l border-slate-700 pl-3">
            WORLD_MODEL_SIMULATION_CANVAS
          </span>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-slate-400">STATE HORIZON:</span>
          <span className="px-2 py-0.5 rounded bg-brand-900 text-brand-200 border border-brand-700 font-bold">
            t + {currentStageIndex} (k=5)
          </span>
        </div>
      </div>

      {/* Main Interactive Canvas Area */}
      <div className="p-6 bg-gradient-to-b from-slate-50/50 to-white relative min-h-[380px]">
        
        {/* SVG Telemetry Packet Flow Lines */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none z-0">
          <defs>
            <linearGradient id="normalGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.6" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.6" />
            </linearGradient>
            <linearGradient id="attackGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#f59e0b" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.8" />
            </linearGradient>
          </defs>

          {/* Lines connecting topology */}
          {/* Gateway -> Web Server */}
          <line x1="20%" y1="25%" x2="50%" y2="25%" 
            stroke={currentStageIndex >= 1 ? '#f59e0b' : '#94a3b8'} 
            strokeWidth={currentStageIndex >= 1 ? '2.5' : '1.5'} 
            className={currentStageIndex >= 1 ? 'animate-packet-line' : ''} 
          />
          {/* Gateway -> DNS Server */}
          <line x1="20%" y1="25%" x2="50%" y2="70%" 
            stroke={currentStageIndex >= 2 ? '#f59e0b' : '#94a3b8'} 
            strokeWidth="1.5"
          />
          {/* Web Server -> Workstation */}
          <line x1="50%" y1="25%" x2="80%" y2="25%" 
            stroke={currentStageIndex >= 2 ? '#ef4444' : '#94a3b8'} 
            strokeWidth={currentStageIndex >= 2 ? '2.5' : '1.5'} 
            className={currentStageIndex >= 2 ? 'animate-packet-line' : ''} 
          />
          {/* Web Server -> DNS */}
          <line x1="50%" y1="25%" x2="50%" y2="70%" 
            stroke={currentStageIndex >= 3 ? '#ef4444' : '#94a3b8'} 
            strokeWidth="1.5" 
          />
          {/* Workstation -> Core Target DB */}
          <line x1="80%" y1="25%" x2="80%" y2="70%" 
            stroke={currentStageIndex >= 3 ? '#ef4444' : '#94a3b8'} 
            strokeWidth={currentStageIndex >= 3 ? '3' : '1.5'} 
            className={currentStageIndex >= 3 ? 'animate-packet-line' : ''} 
          />
          {/* DNS -> Core Target DB */}
          <line x1="50%" y1="70%" x2="80%" y2="70%" 
            stroke={currentStageIndex >= 4 ? '#ef4444' : '#94a3b8'} 
            strokeWidth="1.5" 
          />
        </svg>

        {/* Dynamic Topology Node Elements Grid */}
        <div className="relative z-10 grid grid-cols-3 gap-6 h-full items-center">
          
          {/* Column 1: Gateway */}
          <div className="flex flex-col items-center justify-center space-y-2">
            <div className={`w-16 h-16 rounded-2xl ${getNodeColor('gateway').bg} ${getNodeColor('gateway').border} border-2 flex items-center justify-center transition-all duration-500 ${getNodeColor('gateway').glow}`}>
              <Globe className={`w-8 h-8 ${getNodeColor('gateway').icon}`} />
            </div>
            <div className="text-center">
              <p className="text-xs font-bold text-slate-800">Edge Gateway</p>
              <p className="text-[10px] font-mono text-slate-500">192.168.1.1</p>
              <span className={`inline-block mt-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${getNodeColor('gateway').pill}`}>
                {getNodeColor('gateway').statusText}
              </span>
            </div>
          </div>

          {/* Column 2: Web Server & DNS */}
          <div className="flex flex-col space-y-8 items-center justify-between">
            {/* Web Server */}
            <div className="flex flex-col items-center space-y-2">
              <div className={`w-16 h-16 rounded-2xl ${getNodeColor('web').bg} ${getNodeColor('web').border} border-2 flex items-center justify-center transition-all duration-500 ${getNodeColor('web').glow}`}>
                <Server className={`w-8 h-8 ${getNodeColor('web').icon}`} />
              </div>
              <div className="text-center">
                <p className="text-xs font-bold text-slate-800">Web App API</p>
                <p className="text-[10px] font-mono text-slate-500">192.168.1.80</p>
                <span className={`inline-block mt-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${getNodeColor('web').pill}`}>
                  {getNodeColor('web').statusText}
                </span>
              </div>
            </div>

            {/* DNS Server */}
            <div className="flex flex-col items-center space-y-2">
              <div className={`w-16 h-16 rounded-2xl ${getNodeColor('dns').bg} ${getNodeColor('dns').border} border-2 flex items-center justify-center transition-all duration-500 ${getNodeColor('dns').glow}`}>
                <Radio className={`w-8 h-8 ${getNodeColor('dns').icon}`} />
              </div>
              <div className="text-center">
                <p className="text-xs font-bold text-slate-800">DNS Resolver</p>
                <p className="text-[10px] font-mono text-slate-500">192.168.1.53</p>
                <span className={`inline-block mt-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${getNodeColor('dns').pill}`}>
                  {getNodeColor('dns').statusText}
                </span>
              </div>
            </div>
          </div>

          {/* Column 3: Workstation & Core DB */}
          <div className="flex flex-col space-y-8 items-center justify-between">
            {/* Internal Workstation */}
            <div className="flex flex-col items-center space-y-2">
              <div className={`w-16 h-16 rounded-2xl ${getNodeColor('workstation').bg} ${getNodeColor('workstation').border} border-2 flex items-center justify-center transition-all duration-500 ${getNodeColor('workstation').glow}`}>
                <Cpu className={`w-8 h-8 ${getNodeColor('workstation').icon}`} />
              </div>
              <div className="text-center">
                <p className="text-xs font-bold text-slate-800">Analyst Host</p>
                <p className="text-[10px] font-mono text-slate-500">192.168.1.105</p>
                <span className={`inline-block mt-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${getNodeColor('workstation').pill}`}>
                  {getNodeColor('workstation').statusText}
                </span>
              </div>
            </div>

            {/* Core Database */}
            <div className="flex flex-col items-center space-y-2">
              <div className={`w-16 h-16 rounded-2xl ${getNodeColor('db').bg} ${getNodeColor('db').border} border-2 flex items-center justify-center transition-all duration-500 ${getNodeColor('db').glow}`}>
                <Database className={`w-8 h-8 ${getNodeColor('db').icon}`} />
              </div>
              <div className="text-center">
                <p className="text-xs font-bold text-slate-800">Target Core DB</p>
                <p className="text-[10px] font-mono text-slate-500">10.0.4.15 [CII]</p>
                <span className={`inline-block mt-1 px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${getNodeColor('db').pill}`}>
                  {getNodeColor('db').statusText}
                </span>
              </div>
            </div>
          </div>

        </div>

      </div>

      {/* Stage Description & Controls Footer */}
      <div className="bg-slate-50 p-4 border-t border-slate-200">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3">
          <div>
            <div className="flex items-center space-x-2">
              <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${stage.badgeColor}`}>
                {stage.badge}
              </span>
              <span className="text-xs font-mono font-bold text-slate-700">
                P(Compromise) = <span className={currentStageIndex >= 3 ? 'text-red-600 font-extrabold' : 'text-slate-900'}>{stage.prob}</span>
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-1 font-medium">
              {stage.description}
            </p>
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            <button
              onClick={() => setAutoPlay(!autoPlay)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center space-x-1.5 transition-smooth ${
                autoPlay ? 'bg-amber-500 text-white' : 'bg-slate-900 text-white hover:bg-slate-800'
              }`}
            >
              {autoPlay ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
              <span>{autoPlay ? 'Pause Rollout' : 'Auto Play Rollout'}</span>
            </button>
            
            <button
              onClick={() => setCurrentStageIndex((prev) => (prev + 1) % STAGES.length)}
              className="p-1.5 rounded-lg text-slate-700 bg-white border border-slate-300 hover:bg-slate-100 transition-smooth"
              title="Next Attack Step"
            >
              <SkipForward className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Step Buttons Bar */}
        <div className="grid grid-cols-5 gap-1.5 pt-2 border-t border-slate-200/60">
          {STAGES.map((s, idx) => (
            <button
              key={s.id}
              onClick={() => {
                setCurrentStageIndex(idx);
                setAutoPlay(false);
              }}
              className={`py-1.5 px-2 rounded text-[11px] font-mono font-medium transition-smooth text-center truncate ${
                currentStageIndex === idx
                  ? 'bg-brand-600 text-white font-bold shadow-subtle'
                  : 'bg-white text-slate-600 border border-slate-200 hover:bg-slate-100'
              }`}
            >
              Step {idx}
            </button>
          ))}
        </div>
      </div>

    </div>
  );
}
