
import React, { useState } from 'react';
import { Upload, FileSearch, ShieldCheck, AlertTriangle, Download, Trash2, ShieldAlert, Bot } from 'lucide-react';
import { AnalysisResult, RiskLevel } from './types';
import * as analysisEngine from './services/analysisEngine';
import * as vtService from './services/vtService';
import { GoogleGenAI } from "@google/genai";

// Sub-components
import RiskGauge from './components/RiskGauge';
import AnalysisReport from './components/AnalysisReport';

const App: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setResult(null);
      setAiExplanation(null);
      setError(null);
    }
  };

  const startAnalysis = async () => {
    if (!file) return;

    setAnalyzing(true);
    setError(null);
    setAiExplanation(null);

    try {
      const hash = await analysisEngine.computeHash(file);
      const type = await analysisEngine.detectFileType(file);
      const { content, metadata } = await analysisEngine.extractContentAndMetadata(file, type);
      const findings = analysisEngine.runStaticScan(content, file.name);
      const vtData = await vtService.getVTReport(hash);
      
      const riskScore = analysisEngine.calculateRiskScore(findings, vtData?.malicious || 0);
      const decision = analysisEngine.getDecision(riskScore);
      
      let reconstructedContent = undefined;
      if (decision !== RiskLevel.SAFE) {
        reconstructedContent = analysisEngine.reconstructSafely(content);
      }

      const analysisResult: AnalysisResult = {
        fileName: file.name,
        hash: hash,
        detectedType: type,
        extractedContent: content,
        reconstructedContent: reconstructedContent,
        findings: findings,
        vtSummary: vtData || undefined,
        metadata: metadata,
        riskScore: riskScore,
        decision: decision
      };

      setResult(analysisResult);

      // Optional: AI Explainability using Gemini
      if (findings.length > 0 || (vtData && vtData.malicious > 0)) {
        try {
          const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || process.env.API_KEY || '' });
          const explanation = await ai.models.generateContent({
            model: 'gemini-3-flash-preview',
            contents: `As a malware analyst, explain why this file is marked as ${decision}. 
            Findings: ${findings.map(f => f.message).join(', ')}. 
            VirusTotal Flagged: ${vtData?.malicious || 0} engines.
            Strict Rule: Only use the detected evidence. Do not invent details. Be professional and brief.`,
          });
          setAiExplanation(explanation.text);
        } catch (aiErr) {
          console.debug("AI Explanation not available (likely missing key)");
        }
      }

    } catch (err) {
      console.error(err);
      setError("Analysis failed. The file structure might be too corrupted or unsupported.");
    } finally {
      setAnalyzing(false);
    }
  };

  const clear = () => {
    setFile(null);
    setResult(null);
    setAiExplanation(null);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-slate-200 p-4 md:p-8 selection:bg-blue-500/30">
      {/* Header */}
      <header className="max-w-6xl mx-auto flex items-center justify-between mb-12">
        <div className="flex items-center gap-4">
          <div className="bg-gradient-to-br from-blue-600 to-indigo-700 p-2.5 rounded-xl shadow-xl shadow-blue-500/10 border border-white/10">
            <ShieldCheck className="w-8 h-8 text-white" />
          </div>
          <div>
            <h1 className="text-3xl font-black tracking-tight text-white italic">MalScan</h1>
            <p className="text-[10px] text-slate-500 mono font-bold uppercase tracking-widest">Zero-Trust Analysis Engine</p>
          </div>
        </div>
        <div className="hidden lg:flex items-center gap-6 text-[11px] font-bold text-slate-500 uppercase tracking-widest">
          <span className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-green-500"></div> No-Persistence</span>
          <span className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-blue-500"></div> Heuristic-First</span>
          <span className="flex items-center gap-1.5"><div className="w-1.5 h-1.5 rounded-full bg-indigo-500"></div> VT v3 vSync</span>
        </div>
      </header>

      <main className="max-w-6xl mx-auto">
        {!result ? (
          <div className="max-w-2xl mx-auto">
            <div className="bg-slate-800/40 border border-slate-700/50 rounded-3xl p-10 backdrop-blur-md shadow-2xl overflow-hidden relative">
              <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 blur-3xl rounded-full -mr-16 -mt-16"></div>
              
              <div className="text-center mb-10">
                <h2 className="text-2xl font-bold text-white mb-3">Begin Inspection</h2>
                <p className="text-slate-400 text-sm leading-relaxed max-w-sm mx-auto">Upload a file for deep heuristic inspection and reconstruction. All processing happens in-memory.</p>
              </div>

              <div className="relative group">
                <input
                  type="file"
                  onChange={handleFileChange}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                  accept=".txt,.pdf,.docx,.html"
                />
                <div className={`border-2 border-dashed rounded-2xl p-16 transition-all duration-300 flex flex-col items-center justify-center gap-5 ${file ? 'border-blue-500 bg-blue-500/5 shadow-inner' : 'border-slate-700 group-hover:border-slate-500 bg-slate-900/40'}`}>
                  <div className={`p-4 rounded-full transition-colors ${file ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-500'}`}>
                    <Upload className="w-10 h-10" />
                  </div>
                  <div className="text-center">
                    <p className={`font-bold text-lg transition-colors ${file ? 'text-blue-400' : 'text-slate-300'}`}>
                      {file ? file.name : 'Select target file'}
                    </p>
                    <p className="text-xs text-slate-500 mt-2 mono font-medium">
                      {file ? `${(file.size / 1024).toFixed(2)} KB • READY FOR SCAN` : 'MAX SIZE: 10MB • TXT/PDF/DOCX/HTML'}
                    </p>
                  </div>
                </div>
              </div>

              {error && (
                <div className="mt-6 p-4 bg-red-500/10 border border-red-500/20 rounded-xl flex items-center gap-3 text-red-400 text-sm animate-in zoom-in-95">
                  <AlertTriangle className="w-5 h-5 flex-shrink-0" />
                  {error}
                </div>
              )}

              <button
                disabled={!file || analyzing}
                onClick={startAnalysis}
                className="w-full mt-8 bg-white hover:bg-slate-100 disabled:bg-slate-800 disabled:text-slate-600 text-slate-900 font-black py-4 rounded-2xl transition-all shadow-xl active:scale-[0.98] flex items-center justify-center gap-3 text-lg tracking-tight"
              >
                {analyzing ? (
                  <>
                    <div className="w-5 h-5 border-2 border-slate-900/30 border-t-slate-900 rounded-full animate-spin"></div>
                    RUNNING HEURISTICS...
                  </>
                ) : (
                  <>
                    <FileSearch className="w-6 h-6" />
                    INITIATE ANALYSIS
                  </>
                )}
              </button>
            </div>
          </div>
        ) : (
          <div className="animate-in fade-in slide-in-from-bottom-6 duration-700">
            <div className="flex flex-col lg:flex-row gap-8">
              {/* Left Column - Score & Action */}
              <div className="lg:w-[380px] flex flex-col gap-6">
                <RiskGauge score={result.riskScore} decision={result.decision} />
                
                {aiExplanation && (
                  <div className="bg-indigo-500/5 border border-indigo-500/20 rounded-2xl p-6">
                    <h3 className="text-sm font-bold mb-3 flex items-center gap-2 text-indigo-400 uppercase tracking-widest">
                      <Bot className="w-4 h-4" /> AI Reasoning
                    </h3>
                    <p className="text-sm text-slate-300 italic leading-relaxed">"{aiExplanation}"</p>
                  </div>
                )}

                <div className="bg-slate-800/50 border border-slate-700 rounded-2xl p-6 shadow-xl">
                  <h3 className="text-xs font-bold mb-5 text-slate-500 uppercase tracking-widest flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4" /> Policy Enforcement
                  </h3>
                  
                  <div className={`p-4 rounded-xl border-2 text-sm font-black text-center mb-6 tracking-tight ${
                    result.decision === RiskLevel.SAFE ? 'bg-green-500/5 border-green-500/20 text-green-500' :
                    result.decision === RiskLevel.SUSPICIOUS ? 'bg-yellow-500/5 border-yellow-500/20 text-yellow-500' :
                    'bg-red-500/5 border-red-500/20 text-red-500'
                  }`}>
                    {result.decision === RiskLevel.SAFE ? 'ACCESS AUTHORIZED' : 
                     result.decision === RiskLevel.SUSPICIOUS ? 'RESTRICTED RECONSTRUCTION' :
                     'ACCESS DENIED: MALICIOUS'}
                  </div>

                  <div className="flex flex-col gap-3">
                    {result.decision !== RiskLevel.MALICIOUS ? (
                      <button 
                        onClick={() => {
                          const content = result.reconstructedContent || result.extractedContent;
                          const blob = new Blob([content], { type: 'text/plain' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `${result.decision === RiskLevel.SUSPICIOUS ? 'RECONSTRUCTED' : 'SAFE'}_${result.fileName}.txt`;
                          a.click();
                        }}
                        className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-4 rounded-xl transition-all shadow-lg shadow-blue-600/20 flex items-center justify-center gap-2 active:scale-95"
                      >
                        <Download className="w-5 h-5" />
                        Download File
                      </button>
                    ) : (
                      <div className="p-4 bg-red-900/20 border border-red-500/30 rounded-xl text-[10px] text-red-400 font-bold uppercase mono leading-tight text-center">
                        Download Blocked: Security Policy prohibits the retrieval of high-risk assets.
                      </div>
                    )}
                    <button 
                      onClick={clear}
                      className="w-full bg-slate-700/50 hover:bg-slate-700 text-slate-300 font-bold py-3 rounded-xl transition-colors flex items-center justify-center gap-2 border border-slate-600/30"
                    >
                      <Trash2 className="w-4 h-4" />
                      Wipe Analysis
                    </button>
                  </div>
                </div>
              </div>

              {/* Right Column - Details */}
              <div className="flex-1">
                <AnalysisReport result={result} />
              </div>
            </div>
          </div>
        )}
      </main>

      <footer className="max-w-6xl mx-auto mt-20 pt-8 border-t border-slate-800/50 flex flex-col md:flex-row justify-between items-center text-slate-500 text-[10px] mono uppercase font-bold tracking-[0.2em] gap-4">
        <p>MALSCAN FRAMEWORK // v1.0.4-STABLE</p>
        <div className="flex gap-6">
          <span>PRIVATE_IN_MEMORY: TRUE</span>
          <span>DATA_PERSISTENCE: NULL</span>
        </div>
      </footer>
    </div>
  );
};

export default App;
