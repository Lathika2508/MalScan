
import { VirusTotalData, EngineVerdict } from '../types';

const API_KEY = process.env.API_KEY || '';

export const getVTReport = async (hash: string): Promise<VirusTotalData | null> => {
  if (!API_KEY || API_KEY === 'undefined' || API_KEY === '') {
    return {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undiscovered: 0,
      reputation: 0,
      lastAnalysisDate: new Date().toISOString(),
      quotaExceeded: true
    };
  }

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: {
        'x-apikey': API_KEY
      }
    });

    if (response.status === 429) {
      return { malicious: 0, suspicious: 0, harmless: 0, undiscovered: 0, reputation: 0, lastAnalysisDate: '', quotaExceeded: true };
    }

    if (response.status === 404) {
      // Hash not present in VirusTotal corpus yet – surface this explicitly to the UI
      return {
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undiscovered: 0,
        reputation: 0,
        lastAnalysisDate: new Date().toISOString(),
        notFound: true,
      };
    }

    if (!response.ok) return null;

    const json = await response.json();
    const attr = json.data.attributes;
    const stats = attr.last_analysis_stats;
    
    // Extract specific engine verdicts (only malicious/suspicious ones to save space)
    const engineVerdicts: EngineVerdict[] = [];
    const results = attr.last_analysis_results;
    for (const engine in results) {
      if (results[engine].category === 'malicious' || results[engine].category === 'suspicious') {
        engineVerdicts.push({
          engineName: results[engine].engine_name,
          category: results[engine].category,
          result: results[engine].result
        });
      }
    }

    return {
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undiscovered: stats.undetected || 0,
      reputation: attr.reputation || 0,
      lastAnalysisDate: new Date(attr.last_analysis_date * 1000).toISOString(),
      firstSeenDate: attr.first_submission_date ? new Date(attr.first_submission_date * 1000).toISOString() : undefined,
      lastSeenDate: attr.last_submission_date ? new Date(attr.last_submission_date * 1000).toISOString() : undefined,
      engineVerdicts,
      fileType: attr.type_description,
      size: attr.size
    };
  } catch (err) {
    console.warn('VirusTotal API Connection Issue:', err);
    return {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undiscovered: 0,
      reputation: 0,
      lastAnalysisDate: '',
      quotaExceeded: true
    };
  }
};
