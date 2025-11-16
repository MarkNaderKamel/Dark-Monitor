<?php
/**
 * Threat Correlation Class
 * 
 * Correlates findings and identifies threat patterns using MITRE ATT&CK framework
 */

class ThreatCorrelation {
    private $db;
    private $logger;
    private $config;

    // MITRE ATT&CK technique mapping
    private $mitrePatterns = [
        'T1078' => ['keywords' => ['credential', 'password', 'account', 'login'], 'name' => 'Valid Accounts'],
        'T1110' => ['keywords' => ['brute', 'bruteforce', 'password spray'], 'name' => 'Brute Force'],
        'T1566' => ['keywords' => ['phishing', 'spearphishing'], 'name' => 'Phishing'],
        'T1059' => ['keywords' => ['command', 'script', 'shell', 'powershell'], 'name' => 'Command and Scripting Interpreter'],
        'T1003' => ['keywords' => ['credential dump', 'lsass', 'sam'], 'name' => 'OS Credential Dumping'],
        'T1190' => ['keywords' => ['exploit', 'vulnerability', 'rce'], 'name' => 'Exploit Public-Facing Application'],
        'T1133' => ['keywords' => ['vpn', 'remote access', 'rdp'], 'name' => 'External Remote Services'],
        'T1071' => ['keywords' => ['c2', 'command and control', 'beacon'], 'name' => 'Application Layer Protocol'],
        'T1048' => ['keywords' => ['exfiltration', 'data leak', 'stolen data'], 'name' => 'Exfiltration Over Alternative Protocol'],
        'T1486' => ['keywords' => ['ransomware', 'encryption', 'locked'], 'name' => 'Data Encrypted for Impact']
    ];

    public function __construct($db, $logger, $config) {
        $this->db = $db;
        $this->logger = $logger;
        $this->config = $config;
    }

    /**
     * Correlate findings to identify patterns
     */
    public function correlateFindings() {
        $this->logger->info('CORRELATION', 'Starting threat correlation analysis');
        
        $recentFindings = $this->db->getFindings(['from_date' => date('Y-m-d H:i:s', strtotime('-24 hours'))]);
        
        $correlations = [];
        $findingsCount = count($recentFindings);
        
        for ($i = 0; $i < $findingsCount; $i++) {
            for ($j = $i + 1; $j < $findingsCount; $j++) {
                $correlation = $this->correlatePair($recentFindings[$i], $recentFindings[$j]);
                
                if ($correlation['score'] > 0.3) {
                    $correlations[] = $correlation;
                    $this->storeCorrelation($correlation);
                }
            }
        }

        $this->logger->info('CORRELATION', 'Found ' . count($correlations) . ' correlations');
        return $correlations;
    }

    /**
     * Correlate two findings
     */
    private function correlatePair($finding1, $finding2) {
        $score = 0.0;
        $commonIOCs = [];
        $mitreTechniques = [];

        // Check for common IOCs
        if (!empty($finding1['iocs']) && !empty($finding2['iocs'])) {
            $iocs1 = $finding1['iocs'];
            $iocs2 = $finding2['iocs'];

            foreach (['ips', 'urls', 'emails', 'hashes'] as $type) {
                if (!empty($iocs1[$type]) && !empty($iocs2[$type])) {
                    $common = array_intersect($iocs1[$type], $iocs2[$type]);
                    if (!empty($common)) {
                        $commonIOCs[$type] = $common;
                        $score += 0.3;
                    }
                }
            }
        }

        // Check for common keywords
        if (!empty($finding1['keywords']) && !empty($finding2['keywords'])) {
            $commonKeywords = array_intersect($finding1['keywords'], $finding2['keywords']);
            if (!empty($commonKeywords)) {
                $score += count($commonKeywords) * 0.1;
            }
        }

        // Check for same source
        if ($finding1['source'] === $finding2['source']) {
            $score += 0.2;
        }

        // Check temporal proximity (within 1 hour)
        $time1 = strtotime($finding1['timestamp']);
        $time2 = strtotime($finding2['timestamp']);
        $timeDiff = abs($time1 - $time2);
        
        if ($timeDiff < 3600) {
            $score += 0.2;
        } elseif ($timeDiff < 7200) {
            $score += 0.1;
        }

        // Map to MITRE ATT&CK techniques
        $mitreTechniques = $this->mapToMITRE([$finding1, $finding2]);

        return [
            'finding_id_1' => $finding1['id'],
            'finding_id_2' => $finding2['id'],
            'score' => min($score, 1.0),
            'common_iocs' => $commonIOCs,
            'mitre_techniques' => $mitreTechniques
        ];
    }

    /**
     * Map findings to MITRE ATT&CK techniques
     */
    private function mapToMITRE($findings) {
        $techniques = [];

        foreach ($findings as $finding) {
            $text = strtolower(($finding['title'] ?? '') . ' ' . ($finding['snippet'] ?? ''));
            
            foreach ($this->mitrePatterns as $techniqueId => $pattern) {
                foreach ($pattern['keywords'] as $keyword) {
                    if (stripos($text, $keyword) !== false) {
                        if (!isset($techniques[$techniqueId])) {
                            $techniques[$techniqueId] = $pattern['name'];
                        }
                    }
                }
            }
        }

        return $techniques;
    }

    /**
     * Store correlation in database
     */
    private function storeCorrelation($correlation) {
        try {
            $dbInstance = $this->db->getDbInstance();
            $stmt = $dbInstance->prepare('
                INSERT INTO threat_correlations 
                (finding_id_1, finding_id_2, correlation_score, common_iocs, mitre_techniques)
                VALUES (:id1, :id2, :score, :iocs, :mitre)
            ');

            $stmt->bindValue(':id1', $correlation['finding_id_1'], SQLITE3_INTEGER);
            $stmt->bindValue(':id2', $correlation['finding_id_2'], SQLITE3_INTEGER);
            $stmt->bindValue(':score', $correlation['score'], SQLITE3_FLOAT);
            $stmt->bindValue(':iocs', json_encode($correlation['common_iocs']), SQLITE3_TEXT);
            $stmt->bindValue(':mitre', json_encode($correlation['mitre_techniques']), SQLITE3_TEXT);

            $stmt->execute();

        } catch (Exception $e) {
            $this->logger->error('CORRELATION', 'Failed to store correlation: ' . $e->getMessage());
        }
    }

    /**
     * Get threat groups based on correlations
     */
    public function getThreatGroups() {
        try {
            $dbInstance = $this->db->getDbInstance();
            $stmt = $dbInstance->prepare('
                SELECT * FROM threat_correlations 
                WHERE correlation_score > 0.5 
                ORDER BY correlation_score DESC 
                LIMIT 50
            ');

            $result = $stmt->execute();
            $groups = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $row['common_iocs'] = json_decode($row['common_iocs'], true);
                $row['mitre_techniques'] = json_decode($row['mitre_techniques'], true);
                $groups[] = $row;
            }

            return $groups;

        } catch (Exception $e) {
            $this->logger->error('CORRELATION', 'Failed to get threat groups: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Calculate threat score for a finding
     */
    public function calculateThreatScore($finding) {
        $score = 50;

        // Severity multiplier
        $severityScores = [
            'CRITICAL' => 40,
            'HIGH' => 30,
            'MEDIUM' => 20,
            'LOW' => 10
        ];
        $score += $severityScores[$finding['severity'] ?? 'MEDIUM'];

        // IOC count
        if (!empty($finding['iocs'])) {
            $iocCount = 0;
            foreach ($finding['iocs'] as $type => $items) {
                $iocCount += count($items);
            }
            $score += min($iocCount * 2, 20);
        }

        // Keyword sensitivity
        $criticalKeywords = ['ransomware', 'apt', 'zero-day', 'breach', 'dump'];
        foreach ($criticalKeywords as $keyword) {
            if (in_array($keyword, $finding['keywords'] ?? [])) {
                $score += 5;
            }
        }

        // Source reliability
        $reliableSources = ['GitHub', 'Telegram'];
        if (isset($finding['source']) && in_array($finding['source'], $reliableSources)) {
            $score += 10;
        }

        return min($score, 100);
    }
}
