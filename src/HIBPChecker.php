<?php

class HIBPChecker {
    private $apiKey;
    private $logger;
    private $db;
    private $enabled;
    private $userAgent;

    public function __construct($config, $logger, $db) {
        $this->apiKey = getenv('HIBP_API_KEY') ?: ($config['hibp']['api_key'] ?? null);
        $this->logger = $logger;
        $this->db = $db;
        $this->enabled = !empty($this->apiKey);
        $this->userAgent = 'Security-Monitoring-System-v1.0';
    }

    public function isEnabled() {
        return $this->enabled;
    }

    private function makeRequest($endpoint) {
        if (!$this->enabled) {
            return null;
        }

        $url = "https://haveibeenpwned.com/api/v3/{$endpoint}";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            "hibp-api-key: {$this->apiKey}",
            "User-Agent: {$this->userAgent}"
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode === 404) {
            return []; // Not found = no breaches
        }

        if ($httpCode !== 200) {
            $this->logger->error('HIBP', "API request failed: HTTP $httpCode");
            return null;
        }

        return json_decode($response, true);
    }

    public function checkEmail($email) {
        // Check cache first
        $cached = $this->db->getEnrichment('email', $email);
        if ($cached) {
            $this->logger->debug('HIBP', "Using cached enrichment for email: $email");
            return $cached;
        }
        
        $this->logger->info('HIBP', "Checking email: $email");
        
        $emailEncoded = urlencode($email);
        $breaches = $this->makeRequest("breachedaccount/$emailEncoded?truncateResponse=false");
        
        if ($breaches === null) {
            return null;
        }

        $enrichment = [
            'breach_count' => count($breaches),
            'breaches' => [],
            'sensitive_breaches' => 0,
            'verified_breaches' => 0
        ];

        foreach ($breaches as $breach) {
            $enrichment['breaches'][] = [
                'name' => $breach['Name'] ?? 'Unknown',
                'domain' => $breach['Domain'] ?? 'Unknown',
                'breach_date' => $breach['BreachDate'] ?? 'Unknown',
                'pwn_count' => $breach['PwnCount'] ?? 0,
                'data_classes' => $breach['DataClasses'] ?? [],
                'is_verified' => $breach['IsVerified'] ?? false,
                'is_sensitive' => $breach['IsSensitive'] ?? false
            ];

            if ($breach['IsSensitive'] ?? false) {
                $enrichment['sensitive_breaches']++;
            }
            if ($breach['IsVerified'] ?? false) {
                $enrichment['verified_breaches']++;
            }
        }

        // Store enrichment with original (non-encoded) email
        $this->db->storeEnrichment('email', $email, $enrichment);

        return $enrichment;
    }

    public function checkDomain($domain) {
        $this->logger->info('HIBP', "Checking domain: $domain");
        
        $domainEncoded = urlencode($domain);
        $breaches = $this->makeRequest("breaches?domain=$domainEncoded");
        
        if ($breaches === null) {
            return null;
        }

        $enrichment = [
            'breach_count' => count($breaches),
            'total_accounts' => 0,
            'breaches' => []
        ];

        foreach ($breaches as $breach) {
            $pwnCount = $breach['PwnCount'] ?? 0;
            $enrichment['total_accounts'] += $pwnCount;
            
            $enrichment['breaches'][] = [
                'name' => $breach['Name'] ?? 'Unknown',
                'breach_date' => $breach['BreachDate'] ?? 'Unknown',
                'pwn_count' => $pwnCount,
                'data_classes' => $breach['DataClasses'] ?? []
            ];
        }

        // Store with original (non-encoded) domain
        $this->db->storeEnrichment('domain', $domain, $enrichment);

        return $enrichment;
    }

    public function checkPassword($password) {
        // Use k-anonymity model (Pwned Passwords)
        $sha1 = strtoupper(sha1($password));
        $prefix = substr($sha1, 0, 5);
        $suffix = substr($sha1, 5);

        $url = "https://api.pwnedpasswords.com/range/$prefix";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERAGENT, $this->userAgent);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            return null;
        }

        // Parse response
        $lines = explode("\r\n", $response);
        foreach ($lines as $line) {
            list($hashSuffix, $count) = explode(':', $line);
            if ($hashSuffix === $suffix) {
                return [
                    'pwned' => true,
                    'count' => (int)$count,
                    'severity' => $count > 100000 ? 'CRITICAL' : ($count > 10000 ? 'HIGH' : 'MEDIUM')
                ];
            }
        }

        return [
            'pwned' => false,
            'count' => 0,
            'severity' => 'SAFE'
        ];
    }

    public function enrichEmails($emails) {
        $enrichedData = [];

        // Limit to first 2 emails to avoid delays
        foreach (array_slice($emails, 0, 2) as $email) {
            $enrichedData[$email] = $this->checkEmail($email);
        }

        return $enrichedData;
    }

    public function calculateBreachSeverity($enrichmentData) {
        $score = 0;

        if (isset($enrichmentData['breach_count'])) {
            $score += min($enrichmentData['breach_count'] * 10, 40);
        }

        if (isset($enrichmentData['sensitive_breaches'])) {
            $score += $enrichmentData['sensitive_breaches'] * 20;
        }

        if (isset($enrichmentData['verified_breaches'])) {
            $score += $enrichmentData['verified_breaches'] * 10;
        }

        return min($score, 100);
    }
}
