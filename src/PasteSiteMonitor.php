<?php

class PasteSiteMonitor {
    private $keywords;
    private $db;
    private $lastCheck = [];
    private $sites = [
        'pastebin' => [
            'api' => 'https://scrape.pastebin.com/api_scraping.php?limit=100',
            'raw_url' => 'https://pastebin.com/raw/',
            'requires_auth' => false
        ],
        'slexy' => [
            'recent' => 'https://slexy.org/recent',
            'requires_auth' => false
        ],
        'ghostbin' => [
            'recent' => 'https://ghostbin.com/browse',
            'requires_auth' => false
        ]
    ];
    
    public function __construct($keywords, $db) {
        $this->keywords = $keywords;
        $this->db = $db;
        $this->loadLastCheck();
    }
    
    private function loadLastCheck() {
        $stateFile = __DIR__ . '/../data/paste_state.json';
        if (file_exists($stateFile)) {
            $this->lastCheck = json_decode(file_get_contents($stateFile), true) ?? [];
        }
    }
    
    private function saveLastCheck() {
        $stateFile = __DIR__ . '/../data/paste_state.json';
        file_put_contents($stateFile, json_encode($this->lastCheck));
    }
    
    public function scan() {
        $findings = [];
        
        $findings = array_merge($findings, $this->scanPastebin());
        
        $this->saveLastCheck();
        return $findings;
    }
    
    private function scanPastebin() {
        $findings = [];
        
        try {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->sites['pastebin']['api']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 30);
            curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Security Monitor Bot)');
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            
            if ($httpCode !== 200 || !$response) {
                error_log("Pastebin API failed: HTTP $httpCode");
                return $findings;
            }
            
            $pastes = json_decode($response, true);
            if (!is_array($pastes)) {
                return $findings;
            }
            
            foreach ($pastes as $paste) {
                $pasteKey = $paste['key'] ?? '';
                if (!$pasteKey) continue;
                
                if (isset($this->lastCheck['pastebin']) && 
                    in_array($pasteKey, $this->lastCheck['pastebin'])) {
                    continue;
                }
                
                $content = $this->fetchPasteContent($pasteKey);
                if (!$content) continue;
                
                $matchedKeywords = $this->findKeywords($content);
                if (!empty($matchedKeywords)) {
                    $findings[] = [
                        'source' => 'Pastebin',
                        'url' => 'https://pastebin.com/' . $pasteKey,
                        'title' => $paste['title'] ?? 'Untitled',
                        'content' => substr($content, 0, 5000),
                        'keywords' => $matchedKeywords,
                        'severity' => $this->calculateSeverity($content, $matchedKeywords),
                        'iocs' => $this->extractIOCs($content),
                        'metadata' => [
                            'paste_key' => $pasteKey,
                            'author' => $paste['user'] ?? 'Anonymous',
                            'date' => $paste['date'] ?? time(),
                            'size' => $paste['size'] ?? strlen($content)
                        ]
                    ];
                    
                    if (!isset($this->lastCheck['pastebin'])) {
                        $this->lastCheck['pastebin'] = [];
                    }
                    $this->lastCheck['pastebin'][] = $pasteKey;
                    if (count($this->lastCheck['pastebin']) > 500) {
                        $this->lastCheck['pastebin'] = array_slice($this->lastCheck['pastebin'], -500);
                    }
                }
                
                usleep(500000);
            }
            
        } catch (Exception $e) {
            error_log("Pastebin scan error: " . $e->getMessage());
        }
        
        return $findings;
    }
    
    private function fetchPasteContent($pasteKey) {
        $url = $this->sites['pastebin']['raw_url'] . $pasteKey;
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Security Monitor Bot)');
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        
        $content = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode === 200 && $content) {
            return $content;
        }
        
        return false;
    }
    
    private function findKeywords($content) {
        $found = [];
        $contentLower = strtolower($content);
        
        foreach ($this->keywords as $keyword) {
            if (stripos($contentLower, strtolower($keyword)) !== false) {
                $found[] = $keyword;
            }
        }
        
        return $found;
    }
    
    private function extractIOCs($content) {
        $iocs = [
            'ips' => [],
            'domains' => [],
            'emails' => [],
            'urls' => [],
            'hashes' => [],
            'credentials' => []
        ];
        
        preg_match_all('/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/', $content, $matches);
        $iocs['ips'] = array_values(array_unique($matches[0]));
        
        preg_match_all('/\b[a-zA-Z0-9][\w\-\.]+\.[a-zA-Z]{2,}\b/', $content, $matches);
        $iocs['domains'] = array_values(array_unique(array_filter($matches[0], function($d) {
            return !filter_var($d, FILTER_VALIDATE_IP);
        })));
        
        preg_match_all('/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/', $content, $matches);
        $iocs['emails'] = array_values(array_unique($matches[0]));
        
        preg_match_all('/https?:\/\/[^\s<>"{}|\\^`\[\]]+/', $content, $matches);
        $iocs['urls'] = array_values(array_unique($matches[0]));
        
        preg_match_all('/\b[a-fA-F0-9]{32}\b/', $content, $md5);
        preg_match_all('/\b[a-fA-F0-9]{40}\b/', $content, $sha1);
        preg_match_all('/\b[a-fA-F0-9]{64}\b/', $content, $sha256);
        $iocs['hashes'] = array_values(array_unique(array_merge($md5[0], $sha1[0], $sha256[0])));
        
        preg_match_all('/(?:username|user|login|email)\s*[:=]\s*([^\s\r\n]+).*?(?:password|pass|pwd)\s*[:=]\s*([^\s\r\n]+)/is', $content, $credMatches);
        if (!empty($credMatches[0])) {
            $iocs['credentials'] = array_slice($credMatches[0], 0, 10);
        }
        
        return $iocs;
    }
    
    private function calculateSeverity($content, $keywords) {
        $score = 0;
        
        $contentLower = strtolower($content);
        
        $criticalTerms = ['password', 'credential', 'database dump', 'leaked', 'breach', 'compromised', 'hacked', 'stolen'];
        foreach ($criticalTerms as $term) {
            if (stripos($contentLower, $term) !== false) {
                $score += 15;
            }
        }
        
        if (preg_match_all('/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/', $content) > 50) {
            $score += 20;
        }
        
        if (preg_match('/(?:username|user|login|email)\s*[:=].*?(?:password|pass|pwd)\s*[:=]/is', $content)) {
            $score += 25;
        }
        
        if (preg_match_all('/\b[a-fA-F0-9]{32,64}\b/', $content) > 10) {
            $score += 15;
        }
        
        $score += count($keywords) * 5;
        
        if ($score >= 50) return 'CRITICAL';
        if ($score >= 30) return 'HIGH';
        if ($score >= 15) return 'MEDIUM';
        return 'LOW';
    }
    
    public function getStatus() {
        return [
            'enabled' => true,
            'sites_monitored' => count($this->sites),
            'last_scan' => $this->lastCheck['last_scan'] ?? 'Never',
            'pastes_tracked' => count($this->lastCheck['pastebin'] ?? [])
        ];
    }
}
