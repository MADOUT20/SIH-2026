import React, { useState, useEffect } from 'react';
import { Play, Pause, RefreshCw, BarChart2, ShieldAlert, CheckCircle, Terminal, HelpCircle, Layers, Sliders, Activity, Target } from 'lucide-react';
import { SIMULATION_PRESETS } from '../services/api';
import { useScrollReveal } from '../hooks/useScrollReveal';

export default function SimulationSandbox() {
  const [selectedPreset, setSelectedPreset] = useState(SIMULATION_PRESETS[0]);
  const [isRunning, setIsRunning] = useState(false);
  const [activeStep, setActiveStep] = useState(5);
  const [sectionRef, isVisible] = useScrollReveal();

  useEffect(() => {
    let timer = null;
    if (isRunning) {
      timer = setInterval(() => {
        setActiveStep((prev) => (prev % 5) + 1);
      }, 1500);
    }
    return () => clearInterval(timer);
  }, [isRunning]);

  return (
    <section 
      ref={sectionRef}
      id="sandbox" 
      className="py-24 bg-transparent border-t border-slate-200/60 relative z-10"
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        {/* Section Header */}
        <div className={`flex flex-col md:flex-row md:items-end justify-between mb-12 gap-6 transition-all duration-700 ${
          isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'
        }`}>
          <div>
            <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-emerald-50 text-emerald-700 text-xs font-mono font-bold border border-emerald-200 mb-3">
              <Terminal className="w-3.5 h-3.5 text-emerald-600" />
              <span>LIVE DEMONSTRATION SANDBOX</span>
            </div>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-slate-900 tracking-tight">
              Interactive Attack Forecasting Engine
            </h2>
            <p className="text-slate-600 text-base max-w-2xl mt-2">
              Ingest PCAP or NetFlow captures to generate real-time probability forecast curves and SHAP decision attributions.
            </p>
          </div>

          {/* Preset Buttons */}
          <div className="flex items-center space-x-2 bg-slate-100/90 p-1.5 rounded-2xl border border-slate-200/80 backdrop-blur-sm">
            {SIMULATION_PRESETS.map((preset) => (
              <button
                key={preset.id}
                onClick={() => {
                  setSelectedPreset(preset);
                  setActiveStep(5);
                }}
                className={`px-3.5 py-2 rounded-xl text-xs font-bold transition-all duration-200 ${
                  selectedPreset.id === preset.id
                    ? 'bg-white text-brand-700 shadow-subtle border border-slate-200/60'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {preset.name.split(' ')[0]}
              </button>
            ))}
          </div>
        </div>

        {/* Sandbox Container Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* Left Column: Preset Telemetry Status */}
          <div className="lg:col-span-5 space-y-6">
            
            {/* Ingested Dataset Summary Card */}
            <div className="bg-slate-900 text-white rounded-3xl p-5 border border-slate-800 space-y-4 font-mono text-xs shadow-floating">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <span className="text-slate-400">CURRENT_ACTIVE_DATASET</span>
                <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold ${
                  selectedPreset.threatLevel === 'CRITICAL' ? 'bg-red-900/80 text-red-300 border border-red-700' :
                  selectedPreset.threatLevel === 'HIGH' ? 'bg-amber-900/80 text-amber-300 border border-amber-700' :
                  'bg-emerald-900/80 text-emerald-300 border border-emerald-700'
                }`}>
                  THREAT_STATUS: {selectedPreset.threatLevel}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-3 text-slate-300">
                <div>
                  <p className="text-slate-500 text-[10px]">FILE_NAME</p>
                  <p className="font-bold truncate">{selectedPreset.file}</p>
                </div>
                <div>
                  <p className="text-slate-500 text-[10px]">FORMAT_TYPE</p>
                  <p className="font-bold">{selectedPreset.type}</p>
                </div>
              </div>

              {/* MITRE Technique Badge */}
              {selectedPreset.mitreTechnique && (
                <div className="pt-2 border-t border-slate-800 flex items-center space-x-2 text-[11px] text-amber-300 font-sans">
                  <Target className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                  <span className="font-semibold">{selectedPreset.mitreTechnique}</span>
                </div>
              )}

              {/* Live Controls */}
              <div className="pt-2 flex items-center space-x-3">
                <button
                  onClick={() => setIsRunning(!isRunning)}
                  className={`flex-1 py-2.5 px-3 rounded-xl font-sans text-xs font-bold flex items-center justify-center space-x-2 transition-all active:scale-[0.98] ${
                    isRunning ? 'bg-amber-500 hover:bg-amber-600 text-white' : 'bg-brand-600 hover:bg-brand-700 text-white shadow-glow-cobalt btn-shimmer'
                  }`}
                >
                  {isRunning ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                  <span>{isRunning ? 'Pause Real-time Ingestion' : 'Run World Model Inference'}</span>
                </button>
              </div>
            </div>

            {/* Synthetic Streaming Console Log */}
            <div className="bg-[#050811] text-emerald-400 rounded-3xl p-4 border border-slate-800 font-mono text-[11px] h-44 overflow-y-auto space-y-1.5 shadow-inner">
              <div className="text-slate-500 border-b border-slate-800 pb-1 mb-2 font-bold flex justify-between">
                <span>INFERENCE_STREAM_LOG</span>
                <span className="text-emerald-500 animate-pulse">● LIVE</span>
              </div>
              {selectedPreset.logs.map((log, lIdx) => (
                <p key={lIdx} className="leading-relaxed">
                  {log}
                </p>
              ))}
            </div>

          </div>

          {/* Right Column: Infiltration Horizon Timeline + Explainability SHAP */}
          <div className="lg:col-span-7 space-y-6">
            
            {/* Forecast Probability Timeline Bar */}
            <div className="glass-card rounded-3xl p-6 border border-slate-200/80 shadow-card space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    Temporal Attack Infiltration Probability Curve P(S_t+k)
                  </h3>
                  <p className="text-xs text-slate-500">
                    Forward rollout prediction window over 5 temporal horizon steps (t+1 to t+5)
                  </p>
                </div>

                <span className="px-3 py-1 rounded-full bg-brand-50 text-brand-700 font-mono text-xs font-bold border border-brand-200">
                  K=5 Horizon
                </span>
              </div>

              {/* Timeline Horizontal Step Bar */}
              <div className="pt-4 grid grid-cols-5 gap-3">
                {selectedPreset.threatProb.map((prob, stepIdx) => (
                  <div key={stepIdx} className="flex flex-col items-center space-y-2">
                    {/* Probability Bar */}
                    <div className="w-full bg-slate-100 rounded-2xl h-36 p-1 flex flex-col justify-end relative overflow-hidden border border-slate-200/80 shadow-inner">
                      <div
                        className={`w-full rounded-xl transition-all duration-700 ease-out ${
                          prob > 75 ? 'bg-gradient-to-t from-red-600 to-red-400' :
                          prob > 35 ? 'bg-gradient-to-t from-amber-500 to-amber-400' :
                          'bg-gradient-to-t from-emerald-500 to-emerald-400'
                        }`}
                        style={{ height: `${prob}%` }}
                      />
                      <span className="absolute inset-0 flex items-center justify-center font-mono font-bold text-xs text-slate-900 drop-shadow">
                        {prob}%
                      </span>
                    </div>

                    {/* Step Label */}
                    <div className="text-center">
                      <span className="text-xs font-mono font-bold text-slate-700">
                        t + {stepIdx + 1}
                      </span>
                      <p className="text-[10px] text-slate-400">
                        +{stepIdx * 15}s
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Explainability Panel (SHAP Feature Attribution) */}
            <div className="glass-card rounded-3xl p-6 border border-slate-200/80 shadow-card space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-slate-900">
                    SHAP Value Feature Attribution (Explainable AI)
                  </h3>
                  <p className="text-xs text-slate-500">
                    Top packet & flow features driving the temporal World Model prediction score
                  </p>
                </div>
                <div className="flex items-center space-x-1 text-slate-400">
                  <HelpCircle className="w-4 h-4" />
                </div>
              </div>

              {/* Feature Progress Bars */}
              <div className="space-y-3.5 pt-2">
                {selectedPreset.shapFeatures.map((feat, fIdx) => (
                  <div key={fIdx} className="space-y-1.5">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-slate-800">{feat.name}</span>
                      <span className="font-mono font-bold text-slate-900">+{feat.score}% Impact</span>
                    </div>
                    <div className="w-full bg-slate-100 h-3 rounded-full overflow-hidden border border-slate-200/80 p-0.5">
                      <div
                        className={`h-full ${feat.color} rounded-full transition-all duration-1000 ease-out`}
                        style={{ width: `${feat.score * 1.8}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

          </div>

        </div>

      </div>
    </section>
  );
}
