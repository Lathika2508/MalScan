
export enum RiskLevel {
  SAFE = 'SAFE',
  SUSPICIOUS = 'SUSPICIOUS',
  MALICIOUS = 'MALICIOUS'
}

export interface SecurityFinding {
  severity: 'high' | 'medium' | 'low';
  message: string;
}

export interface EngineVerdict {
  engineName: string;
  category: string;
  result: string | null;
}

export interface VirusTotalData {
  malicious: number;
  suspicious: number;
  harmless: number;
  undiscovered: number;
  reputation: number; // Community score
  lastAnalysisDate: string;
  firstSeenDate?: string;
  lastSeenDate?: string;
  quotaExceeded?: boolean;
  // True when VirusTotal has no record for the given hash (HTTP 404 from VT)
  notFound?: boolean;
  engineVerdicts?: EngineVerdict[];
  fileType?: string;
  size?: number;
}

export interface FileMetadata {
  author?: string;
  createdBy?: string;
  createdOn?: string;
  modifiedOn?: string;
}

export interface AnalysisResult {
  fileName: string;
  hash: string;
  detectedType: string;
  extractedContent: string;
  reconstructedContent?: string;
  findings: SecurityFinding[];
  vtSummary?: VirusTotalData;
  metadata: FileMetadata;
  riskScore: number;
  decision: RiskLevel;
}
