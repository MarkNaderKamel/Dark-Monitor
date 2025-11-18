<?php

class URLhausEnricher {
    private $baseUrl = 'https://urlhaus-api.abuse.ch/v1/';
    private $logger;
    private $db;

    public function __construct($logger, $db) {
        $this->logger = $logger;
        $this->db = $db;
    }

    public function isEnabled() {
        return true;
    }

    public function lookupURL($url) {
        $cached = $this->db->getEnrichment('urlhaus_url', $url);
        if ($cached) {
            return $cached;
        }

        try {
            $data = ['url' => $url];
            $response = $this->makeRequest('url/', $data);
            
            if (!$response || $response['query_status'] !== 'ok') {
                return null;
            }

            $enrichment = [
                'source' => 'urlhaus',
                'url' => $url,
                'url_status' => $response['url_status'] ?? '',
                'threat' => $response['threat'] ?? '',
                'tags' => $response['tags'] ?? [],
                'urlhaus_reference' => $response['urlhaus_reference'] ?? '',
                'date_added' => $response['date_added'] ?? '',
                'reporter' => $response['reporter'] ?? '',
                'malware_families' => [],
            ];

            if (isset($response['payloads'])) {
                foreach ($response['payloads'] as $payload) {
                    if (isset($payload['signature'])) {
                        $enrichment['malware_families'][] = $payload['signature'];
                    }
                }
            }

            $enrichment['malware_families'] = array_unique($enrichment['malware_families']);

            $this->db->storeEnrichment('urlhaus_url', $url, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('URLHAUS', 'Error looking up URL: ' . $e->getMessage());
            return null;
        }
    }

    public function lookupDomain($domain) {
        $cached = $this->db->getEnrichment('urlhaus_domain', $domain);
        if ($cached) {
            return $cached;
        }

        try {
            $data = ['host' => $domain];
            $response = $this->makeRequest('host/', $data);
            
            if (!$response || $response['query_status'] !== 'ok') {
                return null;
            }

            $enrichment = [
                'source' => 'urlhaus',
                'domain' => $domain,
                'firstseen' => $response['firstseen'] ?? '',
                'url_count' => $response['url_count'] ?? 0,
                'blacklists' => $response['blacklists'] ?? [],
                'tags' => [],
            ];

            if (isset($response['urls'])) {
                foreach ($response['urls'] as $urlData) {
                    if (isset($urlData['tags'])) {
                        $enrichment['tags'] = array_merge($enrichment['tags'], $urlData['tags']);
                    }
                }
            }

            $enrichment['tags'] = array_unique($enrichment['tags']);

            $this->db->storeEnrichment('urlhaus_domain', $domain, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('URLHAUS', 'Error looking up domain: ' . $e->getMessage());
            return null;
        }
    }

    public function lookupHash($hash) {
        $cached = $this->db->getEnrichment('urlhaus_hash', $hash);
        if ($cached) {
            return $cached;
        }

        try {
            $hashType = strlen($hash) == 32 ? 'md5_hash' : (strlen($hash) == 64 ? 'sha256_hash' : null);
            
            if (!$hashType) {
                return null;
            }

            $data = [$hashType => $hash];
            $response = $this->makeRequest('payload/', $data);
            
            if (!$response || $response['query_status'] !== 'ok') {
                return null;
            }

            $enrichment = [
                'source' => 'urlhaus',
                'hash' => $hash,
                'file_type' => $response['file_type'] ?? '',
                'file_size' => $response['file_size'] ?? 0,
                'signature' => $response['signature'] ?? '',
                'firstseen' => $response['firstseen'] ?? '',
                'lastseen' => $response['lastseen'] ?? '',
                'url_count' => $response['url_count'] ?? 0,
                'virustotal' => $response['virustotal'] ?? null,
            ];

            $this->db->storeEnrichment('urlhaus_hash', $hash, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('URLHAUS', 'Error looking up hash: ' . $e->getMessage());
            return null;
        }
    }

    private function makeRequest($endpoint, $data) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->baseUrl . $endpoint);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
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
