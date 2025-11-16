<?php

class VirusTotalEnricher {
    private $apiKey;
    private $logger;
    private $db;
    private $rateLimiter;
    private $enabled;

    public function __construct($config, $logger, $db) {
        $this->apiKey = getenv('VIRUSTOTAL_API_KEY') ?: ($config['virustotal']['api_key'] ?? null);
        $this->logger = $logger;
        $this->db = $db;
        $this->enabled = !empty($this->apiKey);
        $this->rateLimiter = [
            'requests' => 0,
            'reset_time' => time() + 60
        ];
    }

    public function isEnabled() {
        return $this->enabled;
    }

    private function checkRateLimit() {
        if (time() > $this->rateLimiter['reset_time']) {
            $this->rateLimiter = [
                'requests' => 0,
                'reset_time' => time() + 60
            ];
        }

        // VirusTotal free tier: 4 requests per minute
        // Instead of blocking, return false to skip enrichment
        if ($this->rateLimiter['requests'] >= 4) {
            $waitTime = $this->rateLimiter['reset_time'] - time();
            if ($waitTime > 0) {
                $this->logger->warning('VT', "Rate limit reached, skipping enrichment (resets in {$waitTime}s)");
                return false;
            }
            $this->rateLimiter = [
                'requests' => 0,
                'reset_time' => time() + 60
            ];
        }
        
        return true;
    }

    private function makeRequest($endpoint, $data = null) {
        if (!$this->enabled) {
            return null;
        }

        // Check rate limit - skip if limit reached
        if (!$this->checkRateLimit()) {
            return null;
        }

        $url = "https://www.virustotal.com/api/v3/{$endpoint}";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "x-apikey: {$this->apiKey}",
            "Content-Type: application/json"
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); // Reduced timeout
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);

        if ($data) {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        }

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        $this->rateLimiter['requests']++;

        if ($httpCode !== 200) {
            $this->logger->error('VT', "API request failed: HTTP $httpCode");
            return null;
        }

        return json_decode($response, true);
    }

    public function enrichIP($ip) {
        // Check cache first
        $cached = $this->db->getEnrichment('ip', $ip);
        if ($cached) {
            $this->logger->debug('VT', "Using cached enrichment for IP: $ip");
            return $cached;
        }
        
        $this->logger->info('VT', "Enriching IP: $ip");
        
        $response = $this->makeRequest("ip_addresses/$ip");
        
        if (!$response || !isset($response['data'])) {
            return null;
        }

        $data = $response['data'];
        $attributes = $data['attributes'] ?? [];
        $stats = $attributes['last_analysis_stats'] ?? [];

        $enrichment = [
            'malicious' => $stats['malicious'] ?? 0,
            'suspicious' => $stats['suspicious'] ?? 0,
            'harmless' => $stats['harmless'] ?? 0,
            'undetected' => $stats['undetected'] ?? 0,
            'country' => $attributes['country'] ?? 'Unknown',
            'asn' => $attributes['asn'] ?? 'Unknown',
            'as_owner' => $attributes['as_owner'] ?? 'Unknown',
            'reputation' => $attributes['reputation'] ?? 0
        ];

        // Store enrichment
        $this->db->storeEnrichment('ip', $ip, $enrichment);

        return $enrichment;
    }

    public function enrichDomain($domain) {
        // Check cache first
        $cached = $this->db->getEnrichment('domain', $domain);
        if ($cached) {
            $this->logger->debug('VT', "Using cached enrichment for domain: $domain");
            return $cached;
        }
        
        $this->logger->info('VT', "Enriching domain: $domain");
        
        $response = $this->makeRequest("domains/$domain");
        
        if (!$response || !isset($response['data'])) {
            return null;
        }

        $data = $response['data'];
        $attributes = $data['attributes'] ?? [];
        $stats = $attributes['last_analysis_stats'] ?? [];

        $enrichment = [
            'malicious' => $stats['malicious'] ?? 0,
            'suspicious' => $stats['suspicious'] ?? 0,
            'harmless' => $stats['harmless'] ?? 0,
            'undetected' => $stats['undetected'] ?? 0,
            'reputation' => $attributes['reputation'] ?? 0,
            'categories' => $attributes['categories'] ?? [],
            'creation_date' => $attributes['creation_date'] ?? null,
            'last_update_date' => $attributes['last_update_date'] ?? null
        ];

        $this->db->storeEnrichment('domain', $domain, $enrichment);

        return $enrichment;
    }

    public function enrichURL($url) {
        // Check cache first
        $cached = $this->db->getEnrichment('url', $url);
        if ($cached) {
            $this->logger->debug('VT', "Using cached enrichment for URL: $url");
            return $cached;
        }
        
        $this->logger->info('VT', "Enriching URL: $url");
        
        // Encode URL for API
        $urlId = base64_encode($url);
        $urlId = str_replace(['+', '/', '='], ['-', '_', ''], $urlId);
        
        $response = $this->makeRequest("urls/$urlId");
        
        if (!$response || !isset($response['data'])) {
            return null;
        }

        $data = $response['data'];
        $attributes = $data['attributes'] ?? [];
        $stats = $attributes['last_analysis_stats'] ?? [];

        $enrichment = [
            'malicious' => $stats['malicious'] ?? 0,
            'suspicious' => $stats['suspicious'] ?? 0,
            'harmless' => $stats['harmless'] ?? 0,
            'undetected' => $stats['undetected'] ?? 0,
            'categories' => $attributes['categories'] ?? [],
            'threat_names' => $attributes['threat_names'] ?? []
        ];

        $this->db->storeEnrichment('url', $url, $enrichment);

        return $enrichment;
    }

    public function enrichHash($hash) {
        // Check cache first
        $cached = $this->db->getEnrichment('hash', $hash);
        if ($cached) {
            $this->logger->debug('VT', "Using cached enrichment for hash: $hash");
            return $cached;
        }
        
        $this->logger->info('VT', "Enriching hash: $hash");
        
        $response = $this->makeRequest("files/$hash");
        
        if (!$response || !isset($response['data'])) {
            return null;
        }

        $data = $response['data'];
        $attributes = $data['attributes'] ?? [];
        $stats = $attributes['last_analysis_stats'] ?? [];

        $enrichment = [
            'malicious' => $stats['malicious'] ?? 0,
            'suspicious' => $stats['suspicious'] ?? 0,
            'harmless' => $stats['harmless'] ?? 0,
            'undetected' => $stats['undetected'] ?? 0,
            'file_type' => $attributes['type_description'] ?? 'Unknown',
            'file_size' => $attributes['size'] ?? 0,
            'tags' => $attributes['tags'] ?? [],
            'threat_label' => $attributes['popular_threat_classification']['suggested_threat_label'] ?? 'Unknown'
        ];

        $this->db->storeEnrichment('hash', $hash, $enrichment);

        return $enrichment;
    }

    public function enrichIOCs($iocs) {
        $enrichedData = [];

        // Limit to 2 IOCs per type to avoid blocking
        if (isset($iocs['ips']) && is_array($iocs['ips'])) {
            foreach (array_slice($iocs['ips'], 0, 2) as $ip) {
                $result = $this->enrichIP($ip);
                if ($result !== null) {
                    $enrichedData['ips'][$ip] = $result;
                }
            }
        }

        if (isset($iocs['urls']) && is_array($iocs['urls'])) {
            foreach (array_slice($iocs['urls'], 0, 1) as $url) {
                $result = $this->enrichURL($url);
                if ($result !== null) {
                    $enrichedData['urls'][$url] = $result;
                }
            }
        }

        if (isset($iocs['hashes']) && is_array($iocs['hashes'])) {
            foreach (array_slice($iocs['hashes'], 0, 1) as $hash) {
                $result = $this->enrichHash($hash);
                if ($result !== null) {
                    $enrichedData['hashes'][$hash] = $result;
                }
            }
        }

        return $enrichedData;
    }

    public function calculateThreatScore($enrichmentData) {
        $score = 0;

        if (isset($enrichmentData['malicious'])) {
            $score += min($enrichmentData['malicious'] * 10, 50);
        }

        if (isset($enrichmentData['suspicious'])) {
            $score += min($enrichmentData['suspicious'] * 5, 25);
        }

        if (isset($enrichmentData['reputation']) && $enrichmentData['reputation'] < 0) {
            $score += abs($enrichmentData['reputation']);
        }

        return min($score, 100);
    }
}
