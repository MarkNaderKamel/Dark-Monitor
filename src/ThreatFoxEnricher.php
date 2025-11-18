<?php

class ThreatFoxEnricher {
    private $baseUrl = 'https://threatfox-api.abuse.ch/api/v1/';
    private $logger;
    private $db;

    public function __construct($logger, $db) {
        $this->logger = $logger;
        $this->db = $db;
    }

    public function isEnabled() {
        return true;
    }

    public function searchIOC($ioc, $iocType = 'auto') {
        $cached = $this->db->getEnrichment('threatfox', $ioc);
        if ($cached) {
            return $cached;
        }

        try {
            $query = [
                'query' => 'search_ioc',
                'search_term' => $ioc
            ];

            $response = $this->makeRequest($query);
            
            if (!$response || $response['query_status'] !== 'ok') {
                return null;
            }

            $enrichment = [
                'source' => 'threatfox',
                'ioc' => $ioc,
                'threat_type' => '',
                'malware' => '',
                'confidence_level' => 0,
                'first_seen' => '',
                'last_seen' => '',
                'tags' => [],
            ];

            if (isset($response['data']) && !empty($response['data'])) {
                $data = $response['data'][0];
                $enrichment['threat_type'] = $data['threat_type'] ?? '';
                $enrichment['malware'] = $data['malware'] ?? '';
                $enrichment['confidence_level'] = $data['confidence_level'] ?? 0;
                $enrichment['first_seen'] = $data['first_seen'] ?? '';
                $enrichment['last_seen'] = $data['last_seen'] ?? '';
                $enrichment['tags'] = $data['tags'] ?? [];
                $enrichment['ioc_type'] = $data['ioc_type'] ?? '';
            }

            $this->db->storeEnrichment('threatfox', $ioc, $enrichment);
            return $enrichment;

        } catch (Exception $e) {
            $this->logger->error('THREATFOX', 'Error searching IOC: ' . $e->getMessage());
            return null;
        }
    }

    public function getRecentIOCs($limit = 100) {
        try {
            $query = [
                'query' => 'get_iocs',
                'days' => 1
            ];

            $response = $this->makeRequest($query);
            
            if (!$response || $response['query_status'] !== 'ok') {
                return [];
            }

            return array_slice($response['data'] ?? [], 0, $limit);

        } catch (Exception $e) {
            $this->logger->error('THREATFOX', 'Error fetching recent IOCs: ' . $e->getMessage());
            return [];
        }
    }

    private function makeRequest($data) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->baseUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
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
