<?php
/**
 * Reputation Scorer Class
 * 
 * Scores and classifies IPs, domains, and URLs based on threat intelligence
 */

class ReputationScorer {
    private $db;
    private $logger;
    private $config;

    public function __construct($db, $logger, $config) {
        $this->db = $db;
        $this->logger = $logger;
        $this->config = $config;
    }

    /**
     * Score an entity (IP, domain, URL)
     */
    public function scoreEntity($type, $value, $context = []) {
        $score = 50;
        $classification = 'unknown';
        $metadata = [];

        switch ($type) {
            case 'ip':
                list($score, $classification, $metadata) = $this->scoreIP($value, $context);
                break;
            case 'domain':
                list($score, $classification, $metadata) = $this->scoreDomain($value, $context);
                break;
            case 'url':
                list($score, $classification, $metadata) = $this->scoreURL($value, $context);
                break;
            case 'hash':
                list($score, $classification, $metadata) = $this->scoreHash($value, $context);
                break;
        }

        $this->updateReputationDB($type, $value, $score, $classification, $metadata, $context);

        return [
            'score' => $score,
            'classification' => $classification,
            'metadata' => $metadata
        ];
    }

    /**
     * Score an IP address
     */
    private function scoreIP($ip, $context) {
        $score = 50;
        $factors = [];

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return [0, 'invalid', ['error' => 'Invalid IP address']];
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $parts = explode('.', $ip);
            
            if ($parts[0] == '10' || ($parts[0] == '172' && $parts[1] >= 16 && $parts[1] <= 31) || 
                ($parts[0] == '192' && $parts[1] == '168')) {
                $score -= 40;
                $factors[] = 'private_ip';
            }
        }

        if (isset($context['malicious'])) {
            $score -= 30;
            $factors[] = 'flagged_malicious';
        }

        if (isset($context['tor_exit_node'])) {
            $score -= 25;
            $factors[] = 'tor_exit';
        }

        if (isset($context['vpn'])) {
            $score -= 15;
            $factors[] = 'vpn';
        }

        if (isset($context['cloud_provider'])) {
            $score -= 5;
            $factors[] = 'cloud_hosting';
        }

        $history = $this->getEntityHistory('ip', $ip);
        if ($history && $history['malicious_count'] > 0) {
            $score -= ($history['malicious_count'] * 5);
            $factors[] = 'bad_history';
        }

        $classification = $this->getClassification($score);

        return [$score, $classification, [
            'factors' => $factors,
            'ip_type' => filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 'IPv4' : 'IPv6'
        ]];
    }

    /**
     * Score a domain
     */
    private function scoreDomain($domain, $context) {
        $score = 50;
        $factors = [];

        $domain = strtolower(trim($domain));

        if (!filter_var('http://' . $domain, FILTER_VALIDATE_URL)) {
            return [0, 'invalid', ['error' => 'Invalid domain']];
        }

        $tld = substr(strrchr($domain, "."), 1);
        $suspiciousTLDs = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'win', 'loan'];
        
        if (in_array($tld, $suspiciousTLDs)) {
            $score -= 20;
            $factors[] = 'suspicious_tld';
        }

        if (preg_match('/\d{4,}/', $domain)) {
            $score -= 15;
            $factors[] = 'excessive_numbers';
        }

        if (strlen($domain) > 50) {
            $score -= 10;
            $factors[] = 'long_domain';
        }

        $suspiciousWords = ['login', 'verify', 'secure', 'account', 'banking', 'paypal', 'update'];
        foreach ($suspiciousWords as $word) {
            if (stripos($domain, $word) !== false) {
                $score -= 10;
                $factors[] = 'suspicious_keyword_' . $word;
                break;
            }
        }

        if (isset($context['recently_registered'])) {
            $score -= 20;
            $factors[] = 'new_domain';
        }

        if (isset($context['malicious'])) {
            $score -= 35;
            $factors[] = 'flagged_malicious';
        }

        $history = $this->getEntityHistory('domain', $domain);
        if ($history && $history['malicious_count'] > 0) {
            $score -= ($history['malicious_count'] * 5);
            $factors[] = 'bad_history';
        }

        $classification = $this->getClassification($score);

        return [$score, $classification, [
            'factors' => $factors,
            'tld' => $tld,
            'length' => strlen($domain)
        ]];
    }

    /**
     * Score a URL
     */
    private function scoreURL($url, $context) {
        $score = 50;
        $factors = [];

        $parsed = parse_url($url);
        if (!$parsed || !isset($parsed['host'])) {
            return [0, 'invalid', ['error' => 'Invalid URL']];
        }

        list($domainScore, $domainClass, $domainMeta) = $this->scoreDomain($parsed['host'], $context);
        $score = $domainScore;
        $factors = array_merge($factors, $domainMeta['factors'] ?? []);

        if (isset($parsed['scheme']) && $parsed['scheme'] === 'http') {
            $score -= 10;
            $factors[] = 'no_https';
        }

        if (isset($parsed['path'])) {
            $suspiciousPaths = ['/admin', '/login', '/verify', '/update', '/secure'];
            foreach ($suspiciousPaths as $path) {
                if (stripos($parsed['path'], $path) !== false) {
                    $score -= 5;
                    $factors[] = 'suspicious_path';
                    break;
                }
            }
        }

        if (isset($parsed['query']) && strlen($parsed['query']) > 100) {
            $score -= 5;
            $factors[] = 'long_query_string';
        }

        if (preg_match('/(\d{1,3}\.){3}\d{1,3}/', $parsed['host'])) {
            $score -= 15;
            $factors[] = 'ip_based_url';
        }

        $classification = $this->getClassification($score);

        return [$score, $classification, [
            'factors' => $factors,
            'scheme' => $parsed['scheme'] ?? '',
            'host' => $parsed['host']
        ]];
    }

    /**
     * Score a file hash
     */
    private function scoreHash($hash, $context) {
        $score = 50;
        $factors = [];

        if (!preg_match('/^[a-f0-9]{32,64}$/i', $hash)) {
            return [0, 'invalid', ['error' => 'Invalid hash format']];
        }

        if (isset($context['malicious'])) {
            $score = 0;
            $factors[] = 'known_malware';
        }

        if (isset($context['suspicious'])) {
            $score -= 30;
            $factors[] = 'suspicious_behavior';
        }

        $history = $this->getEntityHistory('hash', $hash);
        if ($history && $history['malicious_count'] > 0) {
            $score = 0;
            $factors[] = 'malware_history';
        }

        $classification = $this->getClassification($score);

        return [$score, $classification, [
            'factors' => $factors,
            'hash_type' => strlen($hash) == 32 ? 'MD5' : (strlen($hash) == 64 ? 'SHA256' : 'Unknown')
        ]];
    }

    /**
     * Get entity history from database
     */
    private function getEntityHistory($type, $value) {
        try {
            $dbInstance = $this->db->getDbInstance();
            $stmt = $dbInstance->prepare('
                SELECT * FROM reputation_scores 
                WHERE entity_type = :type AND entity_value = :value
            ');
            $stmt->bindValue(':type', $type, SQLITE3_TEXT);
            $stmt->bindValue(':value', $value, SQLITE3_TEXT);
            
            $result = $stmt->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            
            if ($row) {
                $row['metadata'] = json_decode($row['metadata'], true);
                return $row;
            }
            
            return null;
        } catch (Exception $e) {
            $this->logger->error('REPUTATION', 'Failed to get entity history: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Update reputation in database
     */
    private function updateReputationDB($type, $value, $score, $classification, $metadata, $context) {
        try {
            $dbInstance = $this->db->getDbInstance();
            $existing = $this->getEntityHistory($type, $value);
            
            if ($existing) {
                $maliciousCount = $existing['malicious_count'];
                if (isset($context['malicious'])) {
                    $maliciousCount++;
                }
                
                $stmt = $dbInstance->prepare('
                    UPDATE reputation_scores 
                    SET score = :score, 
                        classification = :classification,
                        last_seen = CURRENT_TIMESTAMP,
                        occurrences = occurrences + 1,
                        malicious_count = :malicious_count,
                        metadata = :metadata
                    WHERE entity_type = :type AND entity_value = :value
                ');
                $stmt->bindValue(':malicious_count', $maliciousCount, SQLITE3_INTEGER);
            } else {
                $stmt = $dbInstance->prepare('
                    INSERT INTO reputation_scores 
                    (entity_type, entity_value, score, classification, malicious_count, metadata)
                    VALUES (:type, :value, :score, :classification, :malicious_count, :metadata)
                ');
                $stmt->bindValue(':malicious_count', isset($context['malicious']) ? 1 : 0, SQLITE3_INTEGER);
            }
            
            $stmt->bindValue(':type', $type, SQLITE3_TEXT);
            $stmt->bindValue(':value', $value, SQLITE3_TEXT);
            $stmt->bindValue(':score', $score, SQLITE3_INTEGER);
            $stmt->bindValue(':classification', $classification, SQLITE3_TEXT);
            $stmt->bindValue(':metadata', json_encode($metadata), SQLITE3_TEXT);
            
            $stmt->execute();
            
        } catch (Exception $e) {
            $this->logger->error('REPUTATION', 'Failed to update reputation: ' . $e->getMessage());
        }
    }

    /**
     * Get classification based on score
     */
    private function getClassification($score) {
        if ($score >= 80) return 'trusted';
        if ($score >= 60) return 'likely_safe';
        if ($score >= 40) return 'unknown';
        if ($score >= 20) return 'suspicious';
        return 'malicious';
    }

    /**
     * Get reputation for entity
     */
    public function getReputation($type, $value) {
        $history = $this->getEntityHistory($type, $value);
        
        if (!$history) {
            return $this->scoreEntity($type, $value);
        }
        
        return [
            'score' => $history['score'],
            'classification' => $history['classification'],
            'metadata' => $history['metadata'] ?? [],
            'occurrences' => $history['occurrences'],
            'last_seen' => $history['last_seen']
        ];
    }

    /**
     * Add method to get database instance
     */
    public function getDbInstance() {
        return $this->db->getDbInstance();
    }
}
