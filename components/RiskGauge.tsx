
import React from 'react';
import { RiskLevel } from '../types';

interface RiskGaugeProps {
  score: number;
  decision: RiskLevel;
}

const RiskGauge: React.FC<RiskGaugeProps> = ({ score, decision }) => {
  const getColor = () => {
    if (decision === RiskLevel.SAFE) return '#22c55e';
    if (decision === RiskLevel.SUSPICIOUS) return '#eab308';
    return '#ef4444';
  };

  const color = getColor();

  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-8 flex flex-col items-center justify-center relative overflow-hidden">
      <div className="absolute top-0 left-0 w-full h-1" style={{ backgroundColor: color }}></div>
      
      <p className="text-xs font-bold text-slate-500 mono mb-4 uppercase tracking-widest">Risk Analysis Score</p>
      
      <div className="relative flex items-center justify-center">
        <svg className="w-48 h-48 transform -rotate-90">
          <circle
            cx="96"
            cy="96"
            r="80"
            stroke="currentColor"
            strokeWidth="12"
            fill="transparent"
            className="text-slate-700"
          />
          <circle
            cx="96"
            cy="96"
            r="80"
            stroke={color}
            strokeWidth="12"
            fill="transparent"
            strokeDasharray={502.4}
            strokeDashoffset={502.4 - (502.4 * score) / 100}
            strokeLinecap="round"
            className="transition-all duration-1000 ease-out"
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className="text-5xl font-black text-white">{score}</span>
          <span className="text-[10px] text-slate-400 font-bold uppercase mono">of 100</span>
        </div>
      </div>

      <div className="mt-6 text-center">
        <h3 className="text-xl font-bold" style={{ color }}>{decision}</h3>
        <p className="text-xs text-slate-400 mt-1 max-w-[150px] mx-auto">
          {decision === RiskLevel.SAFE ? 'Low-risk profile. Safe to proceed.' :
           decision === RiskLevel.SUSPICIOUS ? 'Moderately concerning. Use reconstruction.' :
           'Highly malicious markers detected.'}
        </p>
      </div>
    </div>
  );
};

export default RiskGauge;
