<?php

class GreyNoiseEnricher {
    private $apiKey;
    private $baseUrl = 'https://api.greynoise.io/v3';
    private $logger;
    private $db;
    private $enabled;

    public function __construct($config, $logger, $db) {
        $this->logger = $logger;
        $this->db = $db;
        $this->apiKey = getenv('GREYNOISE_API_KEY') ?: ($config['enrichment']['apis']['greynoise']['api_key'] ?? '');
        $this->enabled = !empty($this->apiKey);
    }

    public function isEnabled() {
        return $this->enabled;
    }

    public function quickCheck($ip) {
        try {
            $url = "https://api.greynoise.io/v3/community/$ip";
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Accept: application/json'
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
            
            return [
                'source' => 'greynoise_community',
                'ip' => $ip,
                'noise' => $data['noise'] ?? false,
                'riot' => $data['riot'] ?? false,
                'classification' => $data['classification'] ?? 'unknown',
                'name' => $data['name'] ?? '',
                'link' => $data['link'] ?? '',
                'last_seen' => $data['last_seen'] ?? '',
            ];

        } catch (Exception $e) {
            $this->logger->error('GREYNOISE', 'Error in quick check: ' . $e->getMessage());
            return null;
        }
    }

    public function enrichIP($ip) {
        if (!$this->enabled) {
            return $this->quickCheck($ip);
        }

        $cached = $this->db->getEnrichment('greynoise', $ip);
        if ($cached) {
            return $cached;
        }

        try {
            $response = $this->makeRequest("ip/$ip");
            
            if (!$response) {
                return $this->quickCheck($ip);
            }

            $enrichment = [
                'source' => 'greynoise',
                'ip' => $ip,
                'seen' => $response['seen'] ?? false,
                'classification' => $response['classification'] ?? 'unknown',
                'first_seen' => $response['first_seen'] ?? '',
                'last_seen' => $response['last_seen'] ?? '',
                'actor' => $response['actor'] ?? '',
                'tags' => $response['tags'] ?? [],
                'metadata' => [
                    'country' => $response['metadata']['country'] ?? '',
                    'city' => $response['metadata']['city'] ?? '',
                    'organization' => $response['metadata']['organization'] ?? '',
                    'asn' => $response['metadata']['asn'] ?? '',
                ],
                'raw_data' => $response['raw_data'] ?? [],
            ];

            $this->db->storeEnrichment('greynoise', $ip, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('GREYNOISE', 'Error enriching IP: ' . $e->getMessage());
            return $this->quickCheck($ip);
        }
    }

    private function makeRequest($endpoint) {
        $url = $this->baseUrl . '/' . $endpoint;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'key: ' . $this->apiKey,
            'Accept: application/json'
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200 || !$response) {
            return null;
        }

        return json_decode($response, true);
    }
}
