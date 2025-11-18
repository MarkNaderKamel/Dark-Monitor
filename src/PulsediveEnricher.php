<?php

class PulsediveEnricher {
    private $apiKey;
    private $baseUrl = 'https://pulsedive.com/api';
    private $logger;
    private $db;
    private $enabled;

    public function __construct($config, $logger, $db) {
        $this->logger = $logger;
        $this->db = $db;
        $this->apiKey = getenv('PULSEDIVE_API_KEY') ?: ($config['enrichment']['apis']['pulsedive']['api_key'] ?? '');
        $this->enabled = !empty($this->apiKey);
    }

    public function isEnabled() {
        return $this->enabled;
    }

    public function enrichIndicator($indicator, $type = null) {
        if (!$this->enabled) {
            return null;
        }

        $cacheKey = 'pulsedive_' . md5($indicator);
        $cached = $this->db->getEnrichment($cacheKey, $indicator);
        if ($cached) {
            return $cached;
        }

        try {
            $params = [
                'indicator' => $indicator,
                'key' => $this->apiKey
            ];

            $response = $this->makeRequest('info.php', $params);
            
            if (!$response) {
                return null;
            }

            $enrichment = [
                'source' => 'pulsedive',
                'indicator' => $indicator,
                'risk' => $response['risk'] ?? 'unknown',
                'risk_recommended' => $response['riskfactors']['risk_recommended'] ?? 'unknown',
                'threat_count' => $response['threats'] ?? 0,
                'properties' => [],
                'feeds' => [],
                'threats' => [],
            ];

            if (isset($response['properties'])) {
                foreach ($response['properties'] as $prop) {
                    $enrichment['properties'][] = $prop['name'] ?? '';
                }
            }

            if (isset($response['feeds'])) {
                foreach ($response['feeds'] as $feed) {
                    $enrichment['feeds'][] = $feed['name'] ?? '';
                }
            }

            if (isset($response['threats_data'])) {
                foreach ($response['threats_data'] as $threat) {
                    $enrichment['threats'][] = $threat['name'] ?? '';
                }
            }

            $this->db->storeEnrichment($cacheKey, $indicator, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('PULSEDIVE', 'Error enriching indicator: ' . $e->getMessage());
            return null;
        }
    }

    public function enrichIP($ip) {
        return $this->enrichIndicator($ip, 'ip');
    }

    public function enrichDomain($domain) {
        return $this->enrichIndicator($domain, 'domain');
    }

    public function enrichURL($url) {
        return $this->enrichIndicator($url, 'url');
    }

    private function makeRequest($endpoint, $params = []) {
        $url = $this->baseUrl . '/' . $endpoint;
        
        if (!empty($params)) {
            $url .= '?' . http_build_query($params);
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
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
