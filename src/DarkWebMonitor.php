<?php
/**
 * Dark Web Monitor Class
 * 
 * Monitors dark web sites via Tor SOCKS5 proxy
 */

class DarkWebMonitor {
    private $config;
    private $logger;
    private $httpClient;

    public function __construct($config, $logger, $httpClient) {
        $this->config = $config['darkweb_sources'];
        $this->logger = $logger;
        $this->httpClient = $httpClient;
    }

    /**
     * Check if dark web monitoring is enabled
     */
    public function isEnabled() {
        return $this->config['enabled'] ?? false;
    }

    /**
     * Monitor dark web sites
     */
    public function monitor($keywords) {
        if (!$this->isEnabled()) {
            $this->logger->info('DARKWEB', 'Dark web monitoring disabled');
            return [];
        }

        $findings = [];
        $sites = $this->config['sites'] ?? [];

        foreach ($sites as $site) {
            if (!($site['enabled'] ?? true)) {
                continue;
            }

            $this->logger->info('DARKWEB', "Monitoring {$site['name']} via Tor");

            try {
                $result = $this->monitorSite($site, $keywords);
                $findings = array_merge($findings, $result);
                
                // Extra delay for Tor
                sleep(5);

            } catch (Exception $e) {
                $this->logger->error('DARKWEB', "Failed to monitor {$site['name']}: " . $e->getMessage());
            }
        }

        $this->logger->info('DARKWEB', 'Total findings from dark web: ' . count($findings));
        return $findings;
    }

    /**
     * Monitor a single dark web site
     */
    private function monitorSite($site, $keywords) {
        $findings = [];
        
        // Construct .onion URL
        $url = 'http://' . $site['url'];

        // Fetch via Tor proxy
        $result = $this->httpClient->get($url, [
            'use_tor' => true,
            'timeout' => 60,
            'max_retries' => 2,
        ]);

        if (!$result['success']) {
            throw new Exception($result['error'] ?? 'Failed to fetch via Tor');
        }

        $html = $result['data'];
        $text = strip_tags($html);

        // Search for keywords
        $foundKeywords = [];
        foreach ($keywords as $keyword) {
            if (mb_stripos($text, $keyword) !== false) {
                $foundKeywords[] = $keyword;
            }
        }

        if (!empty($foundKeywords)) {
            $snippet = $this->extractSnippet($text, $foundKeywords[0]);
            
            $findings[] = [
                'source' => 'Dark Web: ' . $site['name'],
                'title' => 'Keywords detected on ' . $site['name'],
                'url' => $url,
                'snippet' => $snippet,
                'keywords' => $foundKeywords,
                'timestamp' => date('Y-m-d H:i:s'),
            ];

            $this->logger->info('DARKWEB', "Match found on {$site['name']}: " . implode(', ', $foundKeywords));
        }

        return $findings;
    }

    /**
     * Extract snippet around keyword
     */
    private function extractSnippet($text, $keyword) {
        $pos = mb_stripos($text, $keyword);
        
        if ($pos === false) {
            return mb_substr($text, 0, 200);
        }

        $start = max(0, $pos - 100);
        $snippet = mb_substr($text, $start, 200);
        
        return '...' . trim($snippet) . '...';
    }
}
