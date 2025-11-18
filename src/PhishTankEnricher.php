<?php

class PhishTankEnricher {
    private $apiKey;
    private $baseUrl = 'https://checkurl.phishtank.com/checkurl/';
    private $logger;
    private $db;
    private $enabled;

    public function __construct($config, $logger, $db) {
        $this->logger = $logger;
        $this->db = $db;
        $this->apiKey = getenv('PHISHTANK_API_KEY') ?: ($config['enrichment']['apis']['phishtank']['api_key'] ?? '');
        $this->enabled = !empty($this->apiKey);
    }

    public function isEnabled() {
        return $this->enabled;
    }

    public function checkURL($url) {
        if (!$this->enabled) {
            return null;
        }

        $cached = $this->db->getEnrichment('phishtank', $url);
        if ($cached) {
            return $cached;
        }

        try {
            $data = [
                'url' => base64_encode($url),
                'format' => 'json',
                'app_key' => $this->apiKey
            ];

            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $this->baseUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'User-Agent: phishtank/security-monitor-1.0'
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode !== 200 || !$response) {
                return null;
            }

            $data = json_decode($response, true);
            
            if (!isset($data['results'])) {
                return null;
            }

            $enrichment = [
                'source' => 'phishtank',
                'url' => $url,
                'in_database' => $data['results']['in_database'] ?? false,
                'phish_id' => $data['results']['phish_id'] ?? null,
                'phish_detail_url' => $data['results']['phish_detail_url'] ?? '',
                'verified' => $data['results']['verified'] ?? false,
                'verified_at' => $data['results']['verified_at'] ?? '',
                'valid' => $data['results']['valid'] ?? false,
            ];

            $this->db->storeEnrichment('phishtank', $url, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('PHISHTANK', 'Error checking URL: ' . $e->getMessage());
            return null;
        }
    }
}
