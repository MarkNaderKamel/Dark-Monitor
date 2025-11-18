<?php
/**
 * Shodan Enrichment Service
 * 
 * Enriches IP addresses with port scans and service information from Shodan
 */

class ShodanEnricher {
    private $apiKey;
    private $baseUrl;
    private $rateLimit;
    private $logger;

    public function __construct($config, $logger) {
        $this->logger = $logger;
        $this->apiKey = $config['enrichment']['apis']['shodan']['api_key'] ?? '';
        $this->baseUrl = $config['enrichment']['apis']['shodan']['base_url'] ?? 'https://api.shodan.io';
        $this->rateLimit = $config['enrichment']['apis']['shodan']['rate_limit'] ?? 1;
    }

    public function checkIP($ip) {
        if (empty($this->apiKey)) {
            $this->logger->debug('ENRICHMENT', 'Shodan API key not configured');
            return null;
        }

        try {
            $url = $this->baseUrl . '/shodan/host/' . $ip . '?key=' . $this->apiKey;
            
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 15);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 && $response) {
                $data = json_decode($response, true);
                
                $ports = [];
                $services = [];
                $vulns = [];
                
                if (isset($data['data'])) {
                    foreach ($data['data'] as $service) {
                        if (isset($service['port'])) {
                            $ports[] = $service['port'];
                        }
                        if (isset($service['product'])) {
                            $services[] = $service['product'];
                        }
                        if (isset($service['vulns'])) {
                            $vulns = array_merge($vulns, array_keys($service['vulns']));
                        }
                    }
                }
                
                return [
                    'source' => 'shodan',
                    'ip' => $ip,
                    'org' => $data['org'] ?? 'Unknown',
                    'asn' => $data['asn'] ?? '',
                    'isp' => $data['isp'] ?? 'Unknown',
                    'country_code' => $data['country_code'] ?? '',
                    'city' => $data['city'] ?? '',
                    'ports' => array_unique($ports),
                    'services' => array_unique($services),
                    'vulns' => array_unique($vulns),
                    'hostnames' => $data['hostnames'] ?? [],
                    'os' => $data['os'] ?? null,
                    'last_update' => $data['last_update'] ?? null,
                ];
            }

            if ($httpCode === 404) {
                return [
                    'source' => 'shodan',
                    'ip' => $ip,
                    'error' => 'No information available'
                ];
            }

            $this->logger->warning('ENRICHMENT', "Shodan enrichment failed for $ip: HTTP $httpCode");
            return null;

        } catch (Exception $e) {
            $this->logger->error('ENRICHMENT', 'Shodan enrichment error: ' . $e->getMessage());
            return null;
        }
    }

    public function isEnabled() {
        return !empty($this->apiKey);
    }
}
