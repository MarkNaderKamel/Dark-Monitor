<?php
/**
 * AbuseIPDB Enrichment Service
 * 
 * Enriches IP addresses with abuse reports and threat intelligence from AbuseIPDB
 */

class AbuseIPDBEnricher {
    private $apiKey;
    private $baseUrl;
    private $rateLimit;
    private $logger;

    public function __construct($config, $logger) {
        $this->logger = $logger;
        $this->apiKey = $config['enrichment']['apis']['abuseipdb']['api_key'] ?? '';
        $this->baseUrl = $config['enrichment']['apis']['abuseipdb']['base_url'] ?? 'https://api.abuseipdb.com/api/v2';
        $this->rateLimit = $config['enrichment']['apis']['abuseipdb']['rate_limit'] ?? 1000;
    }

    public function checkIP($ip) {
        if (empty($this->apiKey)) {
            $this->logger->debug('ENRICHMENT', 'AbuseIPDB API key not configured');
            return null;
        }

        try {
            $url = $this->baseUrl . '/check';
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url . '?' . http_build_query([
                'ipAddress' => $ip,
                'maxAgeInDays' => 90,
                'verbose' => ''
            ]));
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Key: ' . $this->apiKey,
                'Accept: application/json'
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 && $response) {
                $data = json_decode($response, true);
                
                if (isset($data['data'])) {
                    return [
                        'source' => 'abuseipdb',
                        'ip' => $ip,
                        'abuse_confidence_score' => $data['data']['abuseConfidenceScore'] ?? 0,
                        'usage_type' => $data['data']['usageType'] ?? 'Unknown',
                        'isp' => $data['data']['isp'] ?? 'Unknown',
                        'domain' => $data['data']['domain'] ?? '',
                        'country_code' => $data['data']['countryCode'] ?? '',
                        'is_whitelisted' => $data['data']['isWhitelisted'] ?? false,
                        'total_reports' => $data['data']['totalReports'] ?? 0,
                        'last_reported_at' => $data['data']['lastReportedAt'] ?? null,
                    ];
                }
            }

            $this->logger->warning('ENRICHMENT', "AbuseIPDB enrichment failed for $ip: HTTP $httpCode");
            return null;

        } catch (Exception $e) {
            $this->logger->error('ENRICHMENT', 'AbuseIPDB enrichment error: ' . $e->getMessage());
            return null;
        }
    }

    public function isEnabled() {
        return !empty($this->apiKey);
    }
}
