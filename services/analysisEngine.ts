
import { SecurityFinding, FileMetadata, RiskLevel } from '../types';
import * as JSZip from 'jszip';
import * as pdfjs from 'pdfjs-dist';

pdfjs.GlobalWorkerOptions.workerSrc = `https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.0.379/pdf.worker.min.mjs`;

const MALICIOUS_PATTERNS = [
  // 0. Industry Standard Test Signatures (Immediate Detection)
  { 
    regex: /X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/gi, 
    msg: 'EICAR Standard Anti-Virus Test File Detected', 
    severity: 'high' as const, 
    baseScore: 100 
  },

  // 1. Technical Execution & Obfuscation (Severe)
  { regex: /<script[\s\S]*?>[\s\S]*?<\/script>/gi, msg: 'Embedded Script Tag Detected', severity: 'high' as const, baseScore: 40 },
  { regex: /javascript:/gi, msg: 'JavaScript URI Protocol Detected', severity: 'high' as const, baseScore: 35 },
  { regex: /eval\s*\(/gi, msg: 'Dangerous JavaScript Function (eval) Detected', severity: 'high' as const, baseScore: 45 },
  { regex: /document\.write\s*\(/gi, msg: 'Dangerous DOM Manipulation Detected', severity: 'high' as const, baseScore: 35 },
  { regex: /atob\s*\(/gi, msg: 'Base64 Payload Decoding Detected', severity: 'high' as const, baseScore: 30 },
  { regex: /base64,[a-zA-Z0-9+/=]+/gi, msg: 'Inline Base64 Data Detected', severity: 'medium' as const, baseScore: 20 },
  { regex: /(0x[0-9a-f]{2},?\s*){8,}/gi, msg: 'Potential Shellcode Byte Array Detected', severity: 'high' as const, baseScore: 50 },
  { regex: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/gi, msg: 'Escaped Hexadecimal Sequence (Shellcode) Detected', severity: 'high' as const, baseScore: 50 },
  { regex: /unescape\s*\(/gi, msg: 'Obfuscated String Decoding Detected', severity: 'high' as const, baseScore: 35 },
  { regex: /%u[0-9a-f]{4}%u[0-9a-f]{4}/gi, msg: 'Unicode Obfuscated Shellcode Detected', severity: 'high' as const, baseScore: 60 },

  // 2. OS Commands & Shell
  { regex: /(rm\s+-rf|del\s+\/s|format\s+[a-z]:|sudo\s+|chmod\s+\d+|cmd\.exe|powershell|bash\s+-c)/gi, msg: 'OS Command Execution Pattern', severity: 'high' as const, baseScore: 50 },
  { regex: /(curl|wget|nc\s+-e|telnet)\s+/gi, msg: 'Suspicious Network Downloader Pattern', severity: 'high' as const, baseScore: 45 },
  { regex: /IEX\s*\(/gi, msg: 'PowerShell Invoke-Expression (IEX) Pattern', severity: 'high' as const, baseScore: 60 },

  // 3. Social Engineering & Phishing
  { regex: /(urgent|immediately|action required|verify your account|suspended|account verification|hacked|pwned|compromised)/gi, msg: 'Urgency/Threat Language Detected', severity: 'medium' as const, baseScore: 25 },
  { regex: /(send invoice|payment due|overdue|billing|wire transfer|bank details|login here|click here)/gi, msg: 'Financial Phishing/Baiting Patterns', severity: 'medium' as const, baseScore: 25 },
  { regex: /(bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|buff\.ly)/gi, msg: 'Suspicious Shortened URL Pattern', severity: 'medium' as const, baseScore: 15 },
];

export const computeHash = async (file: File): Promise<string> => {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
};

export const detectFileType = async (file: File): Promise<string> => {
  const buffer = await file.slice(0, 8).arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');

  if (hex.startsWith('25 50 44 46')) return 'PDF Document (%PDF)';
  if (hex.startsWith('50 4B 03 04')) return 'Word Document / ZIP (PK)';
  
  const text = await file.slice(0, 1000).text();
  if (text.toLowerCase().includes('<!doctype html') || text.toLowerCase().includes('<html')) return 'HTML Document';
  if (text.includes('<script')) return 'Script File';
  
  return 'Plain Text File';
};

export const extractContentAndMetadata = async (file: File, detectedType: string): Promise<{ content: string; metadata: FileMetadata }> => {
  let content = '';
  let metadata: FileMetadata = {};

  if (detectedType.includes('Word Document')) {
    try {
      const zip = await JSZip.loadAsync(file);
      const docXml = await zip.file('word/document.xml')?.async('text');
      if (docXml) {
        content = docXml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      }
      const coreXml = await zip.file('docProps/core.xml')?.async('text');
      if (coreXml) {
        metadata.author = coreXml.match(/<dc:creator>([^<]+)<\/dc:creator>/)?.[1];
        metadata.createdOn = coreXml.match(/<dcterms:created[^>]+>([^<]+)<\/dcterms:created>/)?.[1];
      }
    } catch (e) {
      content = "[Error extracting Word content]";
    }
  } else if (detectedType.includes('PDF')) {
    try {
      const arrayBuffer = await file.arrayBuffer();
      const pdf = await pdfjs.getDocument({ data: arrayBuffer }).promise;
      let fullText = '';
      const info = await pdf.getMetadata();
      metadata.author = (info.info as any)?.Author || 'Unknown';
      metadata.createdBy = (info.info as any)?.Producer || 'PDF.js Extractor';
      metadata.createdOn = (info.info as any)?.CreationDate || 'N/A';
      for (let i = 1; i <= Math.min(pdf.numPages, 10); i++) {
        const page = await pdf.getPage(i);
        const textContent = await page.getTextContent();
        const pageText = textContent.items.map((item: any) => item.str).join(' ');
        fullText += pageText + '\n';
      }
      content = fullText.trim() || "[PDF contains no extractable text layer]";
    } catch (e) {
      content = "[Error: PDF parsing failed or file is password protected]";
    }
  } else {
    content = await file.text();
  }
  return { content, metadata };
};

export const runStaticScan = (content: string, fileName: string): SecurityFinding[] => {
  const findings: SecurityFinding[] = [];

  if (/\.[a-z0-9]+\.[a-z0-9]+$/i.test(fileName)) {
    const parts = fileName.split('.');
    if (parts.length > 2) {
      findings.push({ severity: 'medium', message: `Double Extension: .${parts[parts.length-2]}.${parts[parts.length-1]}` });
    }
  }

  MALICIOUS_PATTERNS.forEach(pattern => {
    const re = new RegExp(pattern.regex.source, pattern.regex.flags);
    if (re.test(content)) {
      findings.push({ severity: pattern.severity, message: pattern.msg });
    }
  });

  return findings;
};

export const calculateRiskScore = (findings: SecurityFinding[], vtMaliciousCount: number): number => {
  let score = 0;
  
  // Aggregate finding scores
  findings.forEach(f => {
    const pattern = MALICIOUS_PATTERNS.find(p => p.msg === f.message);
    if (pattern) {
      score += pattern.baseScore;
    } else if (f.message.includes('Double Extension')) {
      score += 20;
    }
  });

  // VirusTotal contribution (Highly influential)
  if (vtMaliciousCount > 0) {
    score += (vtMaliciousCount * 25) + 30;
  }

  return Math.min(100, score);
};

export const reconstructSafely = (content: string): string => {
  if (!content) return "";
  const lines = content.split('\n');
  const cleanedLines = lines.map(line => {
    let isMalicious = false;
    for (const pattern of MALICIOUS_PATTERNS) {
      const re = new RegExp(pattern.regex.source, pattern.regex.flags);
      if (re.test(line)) {
        isMalicious = true;
        break;
      }
    }
    return isMalicious ? '[REMOVED: MALICIOUS CONTENT DETECTED]' : line;
  });
  return cleanedLines.join('\n');
};

export const getDecision = (score: number): RiskLevel => {
  if (score <= 25) return RiskLevel.SAFE;
  if (score <= 60) return RiskLevel.SUSPICIOUS;
  return RiskLevel.MALICIOUS;
};
