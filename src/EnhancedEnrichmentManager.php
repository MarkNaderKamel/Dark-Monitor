<?php

require_once __DIR__ . '/IOCExtractor.php';
require_once __DIR__ . '/AlienVaultOTXEnricher.php';
require_once __DIR__ . '/ThreatFoxEnricher.php';
require_once __DIR__ . '/URLhausEnricher.php';
require_once __DIR__ . '/GreyNoiseEnricher.php';
require_once __DIR__ . '/PhishTankEnricher.php';
require_once __DIR__ . '/PulsediveEnricher.php';
require_once __DIR__ . '/VirusTotalEnricher.php';
require_once __DIR__ . '/AbuseIPDBEnricher.php';
require_once __DIR__ . '/ShodanEnricher.php';

class EnhancedEnrichmentManager {
    private $logger;
    private $db;
    private $config;
    private $iocExtractor;
    private $enrichers = [];

    public function __construct($logger, $db, $config) {
        $this->logger = $logger;
        $this->db = $db;
        $this->config = $config;
        
        $this->iocExtractor = new IOCExtractor($logger);
        $this->initializeEnrichers();
    }

    private function initializeEnrichers() {
        $this->enrichers = [
            'alienvault_otx' => new AlienVaultOTXEnricher($this->config, $this->logger, $this->db),
            'threatfox' => new ThreatFoxEnricher($this->logger, $this->db),
            'urlhaus' => new URLhausEnricher($this->logger, $this->db),
            'greynoise' => new GreyNoiseEnricher($this->config, $this->logger, $this->db),
            'phishtank' => new PhishTankEnricher($this->config, $this->logger, $this->db),
            'pulsedive' => new PulsediveEnricher($this->config, $this->logger, $this->db),
            'virustotal' => new VirusTotalEnricher($this->config, $this->logger, $this->db),
            'abuseipdb' => new AbuseIPDBEnricher($this->config, $this->logger),
            'shodan' => new ShodanEnricher($this->config, $this->logger),
        ];

        $enabledCount = 0;
        foreach ($this->enrichers as $name => $enricher) {
            if ($enricher->isEnabled()) {
                $enabledCount++;
            }
        }

        $this->logger->info('ENRICHMENT', "Initialized $enabledCount enrichment services");
    }

    public function extractAndEnrichIOCs($text, $findingId = null) {
        $iocs = $this->iocExtractor->extract($text);
        
        if (empty($iocs)) {
            return null;
        }

        $enrichedData = [
            'iocs' => $iocs,
            'enrichment' => [],
            'risk_score' => 0,
            'threat_indicators' => [],
        ];

        if (isset($iocs['ips'])) {
            foreach (array_slice($iocs['ips'], 0, 3) as $ip) {
                $ipEnrichment = $this->enrichIP($ip);
                if ($ipEnrichment) {
                    $enrichedData['enrichment']['ips'][$ip] = $ipEnrichment;
                }
            }
        }

        if (isset($iocs['domains'])) {
            foreach (array_slice($iocs['domains'], 0, 3) as $domain) {
                $domainEnrichment = $this->enrichDomain($domain);
                if ($domainEnrichment) {
                    $enrichedData['enrichment']['domains'][$domain] = $domainEnrichment;
                }
            }
        }

        if (isset($iocs['urls'])) {
            foreach (array_slice($iocs['urls'], 0, 2) as $url) {
                $urlEnrichment = $this->enrichURL($url);
                if ($urlEnrichment) {
                    $enrichedData['enrichment']['urls'][$url] = $urlEnrichment;
                }
            }
        }

        if (isset($iocs['hashes'])) {
            foreach (array_slice($iocs['hashes'], 0, 2) as $hash) {
                $hashEnrichment = $this->enrichHash($hash);
                if ($hashEnrichment) {
                    $enrichedData['enrichment']['hashes'][$hash] = $hashEnrichment;
                }
            }
        }

        $enrichedData['risk_score'] = $this->calculateRiskScore($enrichedData);
        $enrichedData['threat_indicators'] = $this->identifyThreatIndicators($enrichedData);

        return $enrichedData;
    }

    private function enrichIP($ip) {
        $results = [];

        if ($this->enrichers['greynoise']->isEnabled()) {
            $result = $this->enrichers['greynoise']->enrichIP($ip);
            if ($result) $results['greynoise'] = $result;
        }

        if ($this->enrichers['abuseipdb']->isEnabled()) {
            $result = $this->enrichers['abuseipdb']->checkIP($ip);
            if ($result) $results['abuseipdb'] = $result;
        }

        if ($this->enrichers['alienvault_otx']->isEnabled()) {
            $result = $this->enrichers['alienvault_otx']->enrichIP($ip);
            if ($result) $results['alienvault_otx'] = $result;
        }

        if ($this->enrichers['virustotal']->isEnabled()) {
            $result = $this->enrichers['virustotal']->enrichIP($ip);
            if ($result) $results['virustotal'] = $result;
        }

        if ($this->enrichers['pulsedive']->isEnabled()) {
            $result = $this->enrichers['pulsedive']->enrichIP($ip);
            if ($result) $results['pulsedive'] = $result;
        }

        return $results;
    }

    private function enrichDomain($domain) {
        $results = [];

        if ($this->enrichers['urlhaus']->isEnabled()) {
            $result = $this->enrichers['urlhaus']->lookupDomain($domain);
            if ($result) $results['urlhaus'] = $result;
        }

        if ($this->enrichers['alienvault_otx']->isEnabled()) {
            $result = $this->enrichers['alienvault_otx']->enrichDomain($domain);
            if ($result) $results['alienvault_otx'] = $result;
        }

        if ($this->enrichers['virustotal']->isEnabled()) {
            $result = $this->enrichers['virustotal']->enrichDomain($domain);
            if ($result) $results['virustotal'] = $result;
        }

        if ($this->enrichers['pulsedive']->isEnabled()) {
            $result = $this->enrichers['pulsedive']->enrichDomain($domain);
            if ($result) $results['pulsedive'] = $result;
        }

        return $results;
    }

    private function enrichURL($url) {
        $results = [];

        if ($this->enrichers['phishtank']->isEnabled()) {
            $result = $this->enrichers['phishtank']->checkURL($url);
            if ($result) $results['phishtank'] = $result;
        }

        if ($this->enrichers['urlhaus']->isEnabled()) {
            $result = $this->enrichers['urlhaus']->lookupURL($url);
            if ($result) $results['urlhaus'] = $result;
        }

        if ($this->enrichers['virustotal']->isEnabled()) {
            $result = $this->enrichers['virustotal']->enrichURL($url);
            if ($result) $results['virustotal'] = $result;
        }

        return $results;
    }

    private function enrichHash($hash) {
        $results = [];

        if ($this->enrichers['threatfox']->isEnabled()) {
            $result = $this->enrichers['threatfox']->searchIOC($hash);
            if ($result) $results['threatfox'] = $result;
        }

        if ($this->enrichers['urlhaus']->isEnabled()) {
            $result = $this->enrichers['urlhaus']->lookupHash($hash);
            if ($result) $results['urlhaus'] = $result;
        }

        if ($this->enrichers['alienvault_otx']->isEnabled()) {
            $result = $this->enrichers['alienvault_otx']->enrichHash($hash);
            if ($result) $results['alienvault_otx'] = $result;
        }

        if ($this->enrichers['virustotal']->isEnabled()) {
            $result = $this->enrichers['virustotal']->enrichHash($hash);
            if ($result) $results['virustotal'] = $result;
        }

        return $results;
    }

    private function calculateRiskScore($enrichedData) {
        $score = 0;
        
        $iocDensity = $this->iocExtractor->calculateIOCDensity(
            json_encode($enrichedData['iocs']), 
            $enrichedData['iocs']
        );
        $score += min($iocDensity * 2, 20);

        if (isset($enrichedData['enrichment']['ips'])) {
            foreach ($enrichedData['enrichment']['ips'] as $ipData) {
                if (isset($ipData['abuseipdb']['abuse_confidence_score'])) {
                    $score += min($ipData['abuseipdb']['abuse_confidence_score'] / 2, 25);
                }
                if (isset($ipData['virustotal']['malicious'])) {
                    $score += min($ipData['virustotal']['malicious'] * 5, 15);
                }
                if (isset($ipData['greynoise']['classification']) && 
                    $ipData['greynoise']['classification'] === 'malicious') {
                    $score += 10;
                }
            }
        }

        if (isset($enrichedData['enrichment']['domains'])) {
            foreach ($enrichedData['enrichment']['domains'] as $domainData) {
                if (isset($domainData['virustotal']['malicious'])) {
                    $score += min($domainData['virustotal']['malicious'] * 5, 15);
                }
                if (isset($domainData['urlhaus']['url_count']) && 
                    $domainData['urlhaus']['url_count'] > 0) {
                    $score += 15;
                }
            }
        }

        if (isset($enrichedData['enrichment']['urls'])) {
            foreach ($enrichedData['enrichment']['urls'] as $urlData) {
                if (isset($urlData['phishtank']['in_database']) && 
                    $urlData['phishtank']['in_database']) {
                    $score += 20;
                }
                if (isset($urlData['urlhaus']['url_status']) && 
                    $urlData['urlhaus']['url_status'] === 'online') {
                    $score += 15;
                }
            }
        }

        if (isset($enrichedData['enrichment']['hashes'])) {
            foreach ($enrichedData['enrichment']['hashes'] as $hashData) {
                if (isset($hashData['virustotal']['malicious'])) {
                    $score += min($hashData['virustotal']['malicious'] * 3, 20);
                }
                if (isset($hashData['threatfox']['confidence_level'])) {
                    $score += min($hashData['threatfox']['confidence_level'] / 2, 15);
                }
            }
        }

        return min($score, 100);
    }

    private function identifyThreatIndicators($enrichedData) {
        $indicators = [];

        if (isset($enrichedData['iocs']['hashes']) && !empty($enrichedData['iocs']['hashes'])) {
            $indicators[] = 'File hashes detected';
        }

        if (isset($enrichedData['iocs']['crypto_addresses']) && !empty($enrichedData['iocs']['crypto_addresses'])) {
            $indicators[] = 'Cryptocurrency addresses found';
        }

        if (isset($enrichedData['iocs']['cves']) && !empty($enrichedData['iocs']['cves'])) {
            $indicators[] = 'CVE references detected';
        }

        if (isset($enrichedData['enrichment']['urls'])) {
            foreach ($enrichedData['enrichment']['urls'] as $urlData) {
                if (isset($urlData['phishtank']['in_database']) && $urlData['phishtank']['in_database']) {
                    $indicators[] = 'Known phishing URL';
                    break;
                }
            }
        }

        if (isset($enrichedData['enrichment']['hashes'])) {
            foreach ($enrichedData['enrichment']['hashes'] as $hashData) {
                if (isset($hashData['threatfox']['malware'])) {
                    $indicators[] = 'Known malware: ' . $hashData['threatfox']['malware'];
                }
            }
        }

        return array_unique($indicators);
    }
}
