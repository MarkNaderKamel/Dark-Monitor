<?php

class GeolocateIP {
    private $logger;
    private $db;
    private $cacheEnabled;

    public function __construct($logger, $db) {
        $this->logger = $logger;
        $this->db = $db;
        $this->cacheEnabled = true;
    }

    public function locate($ip) {
        // Check cache first
        if ($this->cacheEnabled) {
            $cached = $this->db->getEnrichment('ip_geo', $ip);
            if ($cached) {
                $this->logger->info('GEO', "Using cached geolocation for $ip");
                return $cached;
            }
        }

        $this->logger->info('GEO', "Geolocating IP: $ip");

        // Use free ip-api.com service (no API key required)
        // Limit: 45 requests per minute
        $url = "http://ip-api.com/json/$ip?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query";
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            $this->logger->error('GEO', "Geolocation API failed: HTTP $httpCode");
            return null;
        }

        $data = json_decode($response, true);

        if (!$data || $data['status'] !== 'success') {
            $this->logger->error('GEO', "Geolocation failed: " . ($data['message'] ?? 'Unknown error'));
            return null;
        }

        $geoData = [
            'country' => $data['country'] ?? 'Unknown',
            'country_code' => $data['countryCode'] ?? 'XX',
            'region' => $data['regionName'] ?? 'Unknown',
            'city' => $data['city'] ?? 'Unknown',
            'latitude' => $data['lat'] ?? 0,
            'longitude' => $data['lon'] ?? 0,
            'timezone' => $data['timezone'] ?? 'Unknown',
            'isp' => $data['isp'] ?? 'Unknown',
            'organization' => $data['org'] ?? 'Unknown',
            'asn' => $data['as'] ?? 'Unknown',
            'is_mobile' => $data['mobile'] ?? false,
            'is_proxy' => $data['proxy'] ?? false,
            'is_hosting' => $data['hosting'] ?? false
        ];

        // Store in cache
        $this->db->storeEnrichment('ip_geo', $ip, $geoData);

        return $geoData;
    }

    public function locateMultiple($ips) {
        $results = [];

        // Limit to first 3 IPs to avoid delays
        foreach (array_slice($ips, 0, 3) as $ip) {
            $results[$ip] = $this->locate($ip);
            
            // Small delay between requests (non-blocking for cached results)
            if (count($results) < count($ips)) {
                usleep(500000); // 0.5 seconds
            }
        }

        return $results;
    }

    public function calculateRiskScore($geoData) {
        $score = 0;

        // High-risk countries (known for cyber attacks)
        $highRiskCountries = ['CN', 'RU', 'KP', 'IR'];
        if (in_array($geoData['country_code'] ?? '', $highRiskCountries)) {
            $score += 30;
        }

        // Proxy/VPN usage
        if ($geoData['is_proxy'] ?? false) {
            $score += 20;
        }

        // Hosting provider (potential bot/server)
        if ($geoData['is_hosting'] ?? false) {
            $score += 15;
        }

        // Mobile device (less likely to be malicious)
        if ($geoData['is_mobile'] ?? false) {
            $score -= 10;
        }

        return max(0, min($score, 100));
    }
}
