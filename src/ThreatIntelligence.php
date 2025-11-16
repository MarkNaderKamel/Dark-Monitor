<?php
/**
 * Threat Intelligence Class
 * 
 * Integrates with external threat intelligence APIs to enrich findings
 * - Have I Been Pwned (HIBP) for breach checking
 * - VirusTotal for hash/URL scanning
 * - AbuseIPDB for IP reputation
 */

class ThreatIntelligence {
    private $config;
    private $logger;
    private $httpClient;

    public function __construct($config, $logger, $httpClient) {
        $this->config = $config;
        $this->logger = $logger;
        $this->httpClient = $httpClient;
    }

    /**
     * Check if email has been pwned using HIBP API
     */
    public function checkHaveIBeenPwned($email) {
        $apiKey = $this->config['threat_intelligence']['hibp_api_key'] ?? '';
        
        if (empty($apiKey)) {
            return null;
        }

        try {
            $url = "https://haveibeenpwned.com/api/v3/breachedaccount/" . urlencode($email);
            
            $ch = curl_init($url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                "hibp-api-key: $apiKey",
                "User-Agent: Security-Monitor"
            ]);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $breaches = json_decode($response, true);
                return [
                    'compromised' => true,
                    'breach_count' => count($breaches),
                    'breaches' => array_map(fn($b) => $b['Name'], $breaches)
                ];
            } elseif ($httpCode === 404) {
                return ['compromised' => false];
            }

            return null;

        } catch (Exception $e) {
            $this->logger->error('HIBP', 'Error checking email: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Check URL/hash reputation with VirusTotal
     */
    public function checkVirusTotal($resource, $type = 'url') {
        $apiKey = $this->config['threat_intelligence']['virustotal_api_key'] ?? '';
        
        if (empty($apiKey)) {
            return null;
        }

        try {
            if ($type === 'url') {
                // Scan URL
                $url = "https://www.virustotal.com/vtapi/v2/url/report";
                $params = [
                    'apikey' => $apiKey,
                    'resource' => $resource
                ];
            } else {
                // Scan file hash
                $url = "https://www.virustotal.com/vtapi/v2/file/report";
                $params = [
                    'apikey' => $apiKey,
                    'resource' => $resource
                ];
            }

            $ch = curl_init($url . '?' . http_build_query($params));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $data = json_decode($response, true);
                
                if ($data['response_code'] === 1) {
                    return [
                        'detected' => $data['positives'] > 0,
                        'positives' => $data['positives'],
                        'total' => $data['total'],
                        'scan_date' => $data['scan_date'] ?? null,
                        'permalink' => $data['permalink'] ?? null
                    ];
                }
            }

            return null;

        } catch (Exception $e) {
            $this->logger->error('VirusTotal', 'Error checking resource: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Check IP reputation with AbuseIPDB
     */
    public function checkAbuseIPDB($ip) {
        $apiKey = $this->config['threat_intelligence']['abuseipdb_api_key'] ?? '';
        
        if (empty($apiKey)) {
            return null;
        }

        try {
            $url = "https://api.abuseipdb.com/api/v2/check";
            
            $ch = curl_init($url . '?' . http_build_query([
                'ipAddress' => $ip,
                'maxAgeInDays' => '90'
            ]));
            
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                "Key: $apiKey",
                "Accept: application/json"
            ]);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $data = json_decode($response, true);
                
                if (isset($data['data'])) {
                    return [
                        'is_malicious' => $data['data']['abuseConfidenceScore'] > 75,
                        'confidence_score' => $data['data']['abuseConfidenceScore'],
                        'total_reports' => $data['data']['totalReports'],
                        'country' => $data['data']['countryCode'] ?? 'Unknown'
                    ];
                }
            }

            return null;

        } catch (Exception $e) {
            $this->logger->error('AbuseIPDB', 'Error checking IP: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Extract IOCs (Indicators of Compromise) from text
     */
    public function extractIOCs($text) {
        $iocs = [
            'ips' => [],
            'domains' => [],
            'emails' => [],
            'hashes' => []
        ];

        // Extract IP addresses
        preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $text, $matches);
        $iocs['ips'] = array_unique($matches[0]);

        // Extract domains
        preg_match_all('/\b[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,6}\b/i', $text, $matches);
        $iocs['domains'] = array_unique($matches[0]);

        // Extract emails
        preg_match_all('/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/', $text, $matches);
        $iocs['emails'] = array_unique($matches[0]);

        // Extract hashes (MD5, SHA1, SHA256)
        preg_match_all('/\b[a-f0-9]{32}\b/i', $text, $md5);
        preg_match_all('/\b[a-f0-9]{40}\b/i', $text, $sha1);
        preg_match_all('/\b[a-f0-9]{64}\b/i', $text, $sha256);
        
        $iocs['hashes'] = array_unique(array_merge($md5[0], $sha1[0], $sha256[0]));

        return $iocs;
    }

    /**
     * Calculate threat severity score for a finding
     */
    public function calculateThreatScore($finding) {
        $score = 0;
        $factors = [];

        // Keyword severity
        $highSeverityKeywords = ['breach', 'dump', 'stolen', 'hacked', 'compromised', 'ransomware'];
        $mediumSeverityKeywords = ['leak', 'exposed', 'database', 'credentials'];
        
        $keywords = $finding['keywords'] ?? [];
        
        foreach ($keywords as $keyword) {
            if (in_array(strtolower($keyword), $highSeverityKeywords)) {
                $score += 30;
                $factors[] = 'High-severity keyword';
            } elseif (in_array(strtolower($keyword), $mediumSeverityKeywords)) {
                $score += 15;
                $factors[] = 'Medium-severity keyword';
            }
        }

        // Source reputation
        $trustedSources = ['Telegram', 'BreachForums', 'RaidForums', 'XSS'];
        $source = $finding['source'] ?? '';
        
        foreach ($trustedSources as $trusted) {
            if (stripos($source, $trusted) !== false) {
                $score += 20;
                $factors[] = 'Trusted source';
                break;
            }
        }

        // IOC presence
        $snippet = $finding['snippet'] ?? '';
        $iocs = $this->extractIOCs($snippet);
        
        if (count($iocs['emails']) > 0) {
            $score += 15;
            $factors[] = 'Contains email addresses';
        }
        if (count($iocs['ips']) > 0) {
            $score += 10;
            $factors[] = 'Contains IP addresses';
        }
        if (count($iocs['hashes']) > 0) {
            $score += 25;
            $factors[] = 'Contains file hashes';
        }

        // Normalize to 0-100 scale
        $score = min(100, $score);

        // Determine severity level
        if ($score >= 75) {
            $severity = 'CRITICAL';
        } elseif ($score >= 50) {
            $severity = 'HIGH';
        } elseif ($score >= 25) {
            $severity = 'MEDIUM';
        } else {
            $severity = 'LOW';
        }

        return [
            'score' => $score,
            'severity' => $severity,
            'factors' => $factors
        ];
    }
}
