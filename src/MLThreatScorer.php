<?php

class MLThreatScorer {
    private $db;
    private $historicalData = [];
    private $weights = [
        'keyword_criticality' => 0.25,
        'ioc_count' => 0.20,
        'source_reputation' => 0.15,
        'temporal_clustering' => 0.15,
        'content_analysis' => 0.15,
        'correlation_score' => 0.10
    ];
    
    public function __construct($db) {
        $this->db = $db;
        $this->loadHistoricalData();
    }
    
    private function loadHistoricalData() {
        try {
            $stmt = $this->db->prepare("
                SELECT source, severity, keywords, iocs, created_at
                FROM findings
                WHERE created_at >= datetime('now', '-30 days')
                ORDER BY created_at DESC
                LIMIT 1000
            ");
            $stmt->execute();
            $this->historicalData = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch (Exception $e) {
            error_log("Failed to load historical data: " . $e->getMessage());
        }
    }
    
    public function scoreFinding($finding) {
        $scores = [
            'keyword_criticality' => $this->scoreKeywordCriticality($finding),
            'ioc_count' => $this->scoreIOCCount($finding),
            'source_reputation' => $this->scoreSourceReputation($finding),
            'temporal_clustering' => $this->scoreTemporalClustering($finding),
            'content_analysis' => $this->scoreContentAnalysis($finding),
            'correlation_score' => $this->scoreCorrelation($finding)
        ];
        
        $weightedScore = 0;
        foreach ($scores as $metric => $score) {
            $weightedScore += $score * $this->weights[$metric];
        }
        
        $normalizedScore = $this->normalizeScore($weightedScore);
        
        return [
            'ml_score' => $normalizedScore,
            'confidence' => $this->calculateConfidence($scores),
            'severity' => $this->determineSeverity($normalizedScore),
            'risk_factors' => $this->identifyRiskFactors($scores),
            'individual_scores' => $scores
        ];
    }
    
    private function scoreKeywordCriticality($finding) {
        $criticalKeywords = [
            'ransomware' => 100,
            'breach' => 95,
            'exfiltration' => 90,
            'credential dump' => 95,
            'database leak' => 90,
            'zero-day' => 100,
            'apt' => 85,
            'backdoor' => 80,
            'c2' => 80,
            'malware' => 75,
            'vulnerability' => 70,
            'exploit' => 75,
            'phishing' => 65,
            'ddos' => 60,
            'botnet' => 70
        ];
        
        $highKeywords = [
            'leaked' => 60,
            'hacked' => 60,
            'stolen' => 55,
            'exposed' => 55,
            'compromised' => 60,
            'password' => 50,
            'attack' => 45,
            'threat' => 40
        ];
        
        $keywords = is_string($finding['keywords']) ? 
            json_decode($finding['keywords'], true) : 
            ($finding['keywords'] ?? []);
        
        if (!is_array($keywords)) {
            return 0;
        }
        
        $maxScore = 0;
        foreach ($keywords as $keyword) {
            $keywordLower = strtolower($keyword);
            
            foreach ($criticalKeywords as $critKey => $score) {
                if (stripos($keywordLower, $critKey) !== false) {
                    $maxScore = max($maxScore, $score);
                }
            }
            
            foreach ($highKeywords as $highKey => $score) {
                if (stripos($keywordLower, $highKey) !== false) {
                    $maxScore = max($maxScore, $score);
                }
            }
        }
        
        return $maxScore;
    }
    
    private function scoreIOCCount($finding) {
        $iocs = is_string($finding['iocs']) ? 
            json_decode($finding['iocs'], true) : 
            ($finding['iocs'] ?? []);
        
        if (!is_array($iocs)) {
            return 0;
        }
        
        $totalIOCs = 0;
        foreach ($iocs as $type => $list) {
            if (is_array($list)) {
                $totalIOCs += count($list);
            }
        }
        
        $weights = [
            'ips' => 10,
            'domains' => 8,
            'urls' => 5,
            'hashes' => 15,
            'emails' => 12,
            'credentials' => 20
        ];
        
        $weightedIOCs = 0;
        foreach ($iocs as $type => $list) {
            if (is_array($list)) {
                $weight = $weights[$type] ?? 5;
                $weightedIOCs += count($list) * $weight;
            }
        }
        
        return min(100, $weightedIOCs * 2);
    }
    
    private function scoreSourceReputation($finding) {
        $sourceReputations = [
            'Dark Web' => 95,
            'Pastebin' => 80,
            'GitHub Secret Scanning' => 90,
            'Telegram' => 75,
            'Reddit' => 65,
            'Clear Web Forum' => 60,
            'Social Media' => 50
        ];
        
        $source = $finding['source'] ?? '';
        
        foreach ($sourceReputations as $key => $score) {
            if (stripos($source, $key) !== false) {
                return $score;
            }
        }
        
        return 50;
    }
    
    private function scoreTemporalClustering($finding) {
        $keywords = is_string($finding['keywords']) ? 
            json_decode($finding['keywords'], true) : 
            ($finding['keywords'] ?? []);
        
        if (!is_array($keywords) || empty($keywords)) {
            return 0;
        }
        
        $recentMatches = 0;
        $timeWindow = strtotime('-24 hours');
        
        foreach ($this->historicalData as $historical) {
            $histTime = strtotime($historical['created_at']);
            if ($histTime < $timeWindow) continue;
            
            $histKeywords = is_string($historical['keywords']) ? 
                json_decode($historical['keywords'], true) : 
                ($historical['keywords'] ?? []);
            
            if (!is_array($histKeywords)) continue;
            
            $commonKeywords = array_intersect(
                array_map('strtolower', $keywords),
                array_map('strtolower', $histKeywords)
            );
            
            if (count($commonKeywords) > 0) {
                $recentMatches++;
            }
        }
        
        return min(100, $recentMatches * 15);
    }
    
    private function scoreContentAnalysis($finding) {
        $content = $finding['content'] ?? '';
        $score = 0;
        
        $dangerousPatterns = [
            '/(?:root|admin|sudo).*password/i' => 20,
            '/\bAWS_?(?:SECRET_?)?ACCESS_?KEY/i' => 25,
            '/\bapi[_\s]?key/i' => 15,
            '/\b(?:INSERT|UPDATE|DELETE)\s+(?:INTO|FROM)/i' => 15,
            '/\bSELECT.*FROM.*WHERE/i' => 10,
            '/\b(?:CVE-\d{4}-\d{4,})/i' => 20,
            '/\b(?:0day|zero-day)/i' => 25,
            '/\b(?:username|user|login)\s*[:=].*?(?:password|pass|pwd)\s*[:=]/i' => 30
        ];
        
        foreach ($dangerousPatterns as $pattern => $points) {
            if (preg_match($pattern, $content)) {
                $score += $points;
            }
        }
        
        if (str_word_count($content) > 500) {
            $score += 10;
        }
        
        return min(100, $score);
    }
    
    private function scoreCorrelation($finding) {
        $iocs = is_string($finding['iocs']) ? 
            json_decode($finding['iocs'], true) : 
            ($finding['iocs'] ?? []);
        
        if (!is_array($iocs)) {
            return 0;
        }
        
        $correlationCount = 0;
        
        foreach ($this->historicalData as $historical) {
            $histIOCs = is_string($historical['iocs']) ? 
                json_decode($historical['iocs'], true) : 
                ($historical['iocs'] ?? []);
            
            if (!is_array($histIOCs)) continue;
            
            foreach ($iocs as $type => $list) {
                if (!is_array($list)) continue;
                
                $histList = $histIOCs[$type] ?? [];
                if (!is_array($histList)) continue;
                
                $common = array_intersect($list, $histList);
                if (count($common) > 0) {
                    $correlationCount += count($common) * 10;
                }
            }
        }
        
        return min(100, $correlationCount);
    }
    
    private function normalizeScore($rawScore) {
        return max(0, min(100, $rawScore));
    }
    
    private function calculateConfidence($scores) {
        $variance = $this->calculateVariance(array_values($scores));
        
        $normalizedVariance = min(100, $variance);
        
        $confidence = 100 - ($normalizedVariance / 2);
        
        return max(0, min(100, $confidence));
    }
    
    private function calculateVariance($values) {
        $mean = array_sum($values) / count($values);
        $variance = 0;
        
        foreach ($values as $value) {
            $variance += pow($value - $mean, 2);
        }
        
        return sqrt($variance / count($values));
    }
    
    private function determineSeverity($mlScore) {
        if ($mlScore >= 80) return 'CRITICAL';
        if ($mlScore >= 60) return 'HIGH';
        if ($mlScore >= 40) return 'MEDIUM';
        return 'LOW';
    }
    
    private function identifyRiskFactors($scores) {
        $factors = [];
        
        if ($scores['keyword_criticality'] >= 75) {
            $factors[] = 'High-criticality keywords detected';
        }
        
        if ($scores['ioc_count'] >= 70) {
            $factors[] = 'Large number of IOCs identified';
        }
        
        if ($scores['source_reputation'] >= 80) {
            $factors[] = 'High-risk source (Dark Web/Pastebin)';
        }
        
        if ($scores['temporal_clustering'] >= 50) {
            $factors[] = 'Part of active campaign (temporal clustering)';
        }
        
        if ($scores['content_analysis'] >= 60) {
            $factors[] = 'Dangerous content patterns detected';
        }
        
        if ($scores['correlation_score'] >= 40) {
            $factors[] = 'Correlated with previous threats';
        }
        
        return $factors;
    }
    
    public function predictThreatTrend($source, $days = 7) {
        $trends = [];
        
        for ($i = 0; $i < $days; $i++) {
            $date = date('Y-m-d', strtotime("-$i days"));
            $stmt = $this->db->prepare("
                SELECT COUNT(*) as count, AVG(
                    CASE severity
                        WHEN 'CRITICAL' THEN 100
                        WHEN 'HIGH' THEN 75
                        WHEN 'MEDIUM' THEN 50
                        WHEN 'LOW' THEN 25
                        ELSE 0
                    END
                ) as avg_severity
                FROM findings
                WHERE source LIKE :source
                AND DATE(created_at) = :date
            ");
            $stmt->execute([
                'source' => "%$source%",
                'date' => $date
            ]);
            
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $trends[$date] = [
                'count' => $result['count'] ?? 0,
                'avg_severity' => $result['avg_severity'] ?? 0
            ];
        }
        
        return $trends;
    }
}
