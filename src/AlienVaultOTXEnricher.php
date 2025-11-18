<?php

class AlienVaultOTXEnricher {
    private $apiKey;
    private $baseUrl = 'https://otx.alienvault.com/api/v1';
    private $logger;
    private $db;
    private $enabled;

    public function __construct($config, $logger, $db) {
        $this->logger = $logger;
        $this->db = $db;
        $this->apiKey = getenv('ALIENVAULT_OTX_API_KEY') ?: ($config['enrichment']['apis']['alienvault_otx']['api_key'] ?? '');
        $this->enabled = !empty($this->apiKey);
    }

    public function isEnabled() {
        return $this->enabled;
    }

    public function enrichIP($ip) {
        if (!$this->enabled) {
            return null;
        }

        $cached = $this->db->getEnrichment('otx_ip', $ip);
        if ($cached) {
            return $cached;
        }

        try {
            $response = $this->makeRequest("indicators/IPv4/$ip/general");
            
            if (!$response) {
                return null;
            }

            $enrichment = [
                'source' => 'alienvault_otx',
                'pulse_count' => $response['pulse_info']['count'] ?? 0,
                'reputation' => $response['reputation'] ?? 0,
                'country_code' => $response['country_code'] ?? '',
                'asn' => $response['asn'] ?? '',
                'threat_types' => [],
            ];

            if (isset($response['pulse_info']['pulses'])) {
                foreach (array_slice($response['pulse_info']['pulses'], 0, 5) as $pulse) {
                    $enrichment['threat_types'][] = $pulse['name'] ?? 'Unknown';
                }
            }

            $this->db->storeEnrichment('otx_ip', $ip, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('OTX', 'Error enriching IP: ' . $e->getMessage());
            return null;
        }
    }

    public function enrichDomain($domain) {
        if (!$this->enabled) {
            return null;
        }

        $cached = $this->db->getEnrichment('otx_domain', $domain);
        if ($cached) {
            return $cached;
        }

        try {
            $response = $this->makeRequest("indicators/domain/$domain/general");
            
            if (!$response) {
                return null;
            }

            $enrichment = [
                'source' => 'alienvault_otx',
                'pulse_count' => $response['pulse_info']['count'] ?? 0,
                'threat_types' => [],
                'alexa_rank' => $response['alexa'] ?? null,
            ];

            if (isset($response['pulse_info']['pulses'])) {
                foreach (array_slice($response['pulse_info']['pulses'], 0, 5) as $pulse) {
                    $enrichment['threat_types'][] = $pulse['name'] ?? 'Unknown';
                }
            }

            $this->db->storeEnrichment('otx_domain', $domain, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('OTX', 'Error enriching domain: ' . $e->getMessage());
            return null;
        }
    }

    public function enrichHash($hash) {
        if (!$this->enabled) {
            return null;
        }

        $cached = $this->db->getEnrichment('otx_hash', $hash);
        if ($cached) {
            return $cached;
        }

        try {
            $response = $this->makeRequest("indicators/file/$hash/general");
            
            if (!$response) {
                return null;
            }

            $enrichment = [
                'source' => 'alienvault_otx',
                'pulse_count' => $response['pulse_info']['count'] ?? 0,
                'threat_types' => [],
                'malware_families' => [],
            ];

            if (isset($response['pulse_info']['pulses'])) {
                foreach (array_slice($response['pulse_info']['pulses'], 0, 5) as $pulse) {
                    $enrichment['threat_types'][] = $pulse['name'] ?? 'Unknown';
                    if (isset($pulse['malware_families'])) {
                        $enrichment['malware_families'] = array_merge(
                            $enrichment['malware_families'], 
                            $pulse['malware_families']
                        );
                    }
                }
            }

            $enrichment['malware_families'] = array_unique($enrichment['malware_families']);

            $this->db->storeEnrichment('otx_hash', $hash, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('OTX', 'Error enriching hash: ' . $e->getMessage());
            return null;
        }
    }

    private function makeRequest($endpoint) {
        $url = $this->baseUrl . '/' . $endpoint;

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'X-OTX-API-KEY: ' . $this->apiKey,
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
