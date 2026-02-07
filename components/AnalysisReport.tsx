
import React from 'react';
import { AnalysisResult, RiskLevel } from '../types';
import { 
  FileCode, 
  AlertCircle, 
  Info, 
  Database, 
  User, 
  Calendar, 
  ShieldCheck, 
  Code, 
  Activity, 
  ShieldAlert,
  Clock,
  ExternalLink
} from 'lucide-react';

interface AnalysisReportProps {
  result: AnalysisResult;
}

const AnalysisReport: React.FC<AnalysisReportProps> = ({ result }) => {
  const hasVTData = !!result.vtSummary;
  const vt = result.vtSummary;

  return (
    <div className="flex flex-col gap-8 pb-12">
      {/* DETECTED FILE TYPE */}
      <section>
        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-[0.2em] mb-3">DETECTED FILE TYPE:</h4>
        <div className="bg-slate-800/50 border border-slate-700 p-4 rounded-xl flex items-center gap-3">
          <FileCode className="w-5 h-5 text-blue-400" />
          <div className="flex flex-col">
            <span className="text-lg font-semibold text-white">{result.detectedType}</span>
            {vt?.fileType && <span className="text-[10px] mono text-slate-500 font-bold uppercase tracking-widest">VT Identification: {vt.fileType}</span>}
          </div>
        </div>
      </section>

      {/* EXTRACTED CONTENT Section */}
      <section>
        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-[0.2em] mb-3">EXTRACTED CONTENT LAYER:</h4>
        <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl max-h-[250px] overflow-y-auto group">
          <pre className="text-xs mono text-slate-400 whitespace-pre-wrap leading-relaxed group-hover:text-slate-300 transition-colors">
            {result.extractedContent || 'NO EXTRACTABLE CONTENT FOUND'}
          </pre>
        </div>
      </section>

      {/* VIRUSTOTAL INTELLIGENCE */}
      <section>
        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-[0.2em] mb-3">VIRUSTOTAL INTELLIGENCE:</h4>
        <div className="bg-slate-800/50 border border-slate-700 p-6 rounded-2xl">
          {!hasVTData ? (
             <div className="text-sm text-slate-500 italic flex items-center gap-2">
               <Info className="w-4 h-4" />
               VirusTotal intelligence not available for this session.
             </div>
          ) : vt?.quotaExceeded ? (
            <div className="text-sm text-yellow-400/80 italic flex items-center gap-2">
              <ShieldAlert className="w-4 h-4" />
              API Limit Reached: Community reputation data throttled.
            </div>
          ) : vt?.notFound ? (
            <div className="text-sm text-slate-500 italic flex items-center gap-2">
              <Info className="w-4 h-4" />
              Hash not found in VirusTotal public corpus; only local heuristics are applied.
            </div>
          ) : (
            <div className="space-y-8">
              {/* Top Stats */}
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-6">
                <div>
                  <p className="text-[10px] text-slate-500 uppercase mono mb-1">Detections</p>
                  <p className={`text-xl font-black ${vt.malicious > 0 ? 'text-red-500' : 'text-green-500'}`}>
                    {vt.malicious} / {vt.malicious + vt.harmless + vt.suspicious + vt.undiscovered}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-slate-500 uppercase mono mb-1">Reputation Score</p>
                  <p className={`text-xl font-black ${vt.reputation < 0 ? 'text-red-500' : vt.reputation > 10 ? 'text-green-500' : 'text-slate-300'}`}>
                    {vt.reputation > 0 ? `+${vt.reputation}` : vt.reputation}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-slate-500 uppercase mono mb-1">File Size</p>
                  <p className="text-xl font-black text-white">
                    {vt.size ? (vt.size / 1024).toFixed(1) + ' KB' : 'N/A'}
                  </p>
                </div>
                <div>
                  <p className="text-[10px] text-slate-500 uppercase mono mb-1">Scan Status</p>
                  <p className="text-xl font-black text-blue-400">Complete</p>
                </div>
              </div>

              {/* Engine Verdicts */}
              {vt.engineVerdicts && vt.engineVerdicts.length > 0 && (
                <div className="border-t border-slate-700/50 pt-6">
                  <p className="text-[10px] text-slate-500 uppercase mono mb-4 flex items-center gap-2">
                    <Activity className="w-3 h-3" /> Flagging AV Engines
                  </p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {vt.engineVerdicts.map((ev, i) => (
                      <div key={i} className="flex justify-between items-center p-2 bg-slate-900/50 rounded-lg border border-slate-700/30 text-[11px]">
                        <span className="font-bold text-slate-400 uppercase mono">{ev.engineName}</span>
                        <span className="text-red-400 font-bold">{ev.result || 'Suspicious'}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* History Timeline */}
              <div className="border-t border-slate-700/50 pt-6 grid grid-cols-1 md:grid-cols-2 gap-4">
                 <div className="flex items-center gap-3">
                   <div className="p-2 bg-slate-700/50 rounded-lg"><Clock className="w-4 h-4 text-slate-400" /></div>
                   <div>
                     <p className="text-[9px] text-slate-500 uppercase mono">First Seen</p>
                     <p className="text-xs text-slate-300">{vt.firstSeenDate ? new Date(vt.firstSeenDate).toLocaleDateString() : 'New submission'}</p>
                   </div>
                 </div>
                 <div className="flex items-center gap-3">
                   <div className="p-2 bg-slate-700/50 rounded-lg"><Activity className="w-4 h-4 text-slate-400" /></div>
                   <div>
                     <p className="text-[9px] text-slate-500 uppercase mono">Last Analysis</p>
                     <p className="text-xs text-slate-300">{new Date(vt.lastAnalysisDate).toLocaleString()}</p>
                   </div>
                 </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* SECURITY FINDINGS Section */}
      <section>
        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-[0.2em] mb-3">HEURISTIC FINDINGS:</h4>
        <div className="space-y-2">
          {result.findings.length > 0 ? (
            result.findings.map((finding, idx) => (
              <div key={idx} className="flex items-center gap-3 p-3 bg-red-500/5 border border-red-500/10 rounded-lg">
                <AlertCircle className="w-4 h-4 text-red-500" />
                <span className="text-sm text-slate-300 font-medium">- {finding.message}</span>
              </div>
            ))
          ) : (
            <div className="flex items-center gap-3 p-3 bg-green-500/5 border border-green-500/10 rounded-lg">
              <ShieldCheck className="w-4 h-4 text-green-500" />
              <span className="text-sm text-slate-400 italic">- No local security markers identified</span>
            </div>
          )}
        </div>
      </section>

      {/* METADATA Section */}
      <section>
        <h4 className="text-xs font-bold text-slate-500 uppercase tracking-[0.2em] mb-3">INTERNAL METADATA:</h4>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="bg-slate-800/30 border border-slate-700/50 p-4 rounded-xl flex items-center gap-3">
            <User className="w-4 h-4 text-slate-500" />
            <div className="overflow-hidden">
              <p className="text-[10px] text-slate-500 uppercase mono">Author</p>
              <p className="text-sm text-slate-300 truncate">{result.metadata.author || 'Undefined'}</p>
            </div>
          </div>
          <div className="bg-slate-800/30 border border-slate-700/50 p-4 rounded-xl flex items-center gap-3">
            <Database className="w-4 h-4 text-slate-500" />
            <div className="overflow-hidden">
              <p className="text-[10px] text-slate-500 uppercase mono">Producer</p>
              <p className="text-sm text-slate-300 truncate">{result.metadata.createdBy || 'Unknown'}</p>
            </div>
          </div>
        </div>
      </section>

      {/* RECONSTRUCTED CONTENT Section */}
      {result.reconstructedContent && (
        <section className="animate-in fade-in slide-in-from-top-2 duration-700">
          <h4 className="text-xs font-bold text-slate-500 uppercase tracking-[0.2em] mb-3">SAFE RECONSTRUCTION:</h4>
          <div className="bg-blue-900/10 border border-blue-500/20 p-4 rounded-xl">
            <div className="flex items-center gap-2 mb-3 text-blue-400 text-xs font-bold uppercase mono">
              <Code className="w-4 h-4" /> Cleaned Output (Zero-Trust)
            </div>
            <div className="bg-slate-950 p-4 rounded-lg max-h-[300px] overflow-y-auto">
              <pre className="text-xs mono text-slate-300 whitespace-pre-wrap leading-relaxed">
                {result.reconstructedContent}
              </pre>
            </div>
          </div>
        </section>
      )}

      {/* FINAL DECISION Footer */}
      <section className="mt-4 border-t border-slate-800 pt-8 grid grid-cols-2 gap-6">
        <div>
          <h4 className="text-xs font-bold text-slate-500 uppercase tracking-[0.2em] mb-1">TOTAL RISK SCORE:</h4>
          <p className="text-4xl font-black text-white">{result.riskScore}</p>
        </div>
        <div>
          <h4 className="text-xs font-bold text-slate-500 uppercase tracking-[0.2em] mb-1">ANALYSIS DECISION:</h4>
          <p className={`text-2xl font-black tracking-tighter ${
            result.decision === RiskLevel.SAFE ? 'text-green-500' :
            result.decision === RiskLevel.SUSPICIOUS ? 'text-yellow-500' :
            'text-red-500'
          }`}>
            {result.decision}
          </p>
        </div>
      </section>
    </div>
  );
};

export default AnalysisReport;
