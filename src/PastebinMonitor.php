<?php
/**
 * Pastebin Monitor Class
 * 
 * Monitors Pastebin for leaked data and credentials
 */

class PastebinMonitor {
    private $config;
    private $logger;
    private $httpClient;
    private $seenPastes = [];

    public function __construct($config, $logger, $httpClient) {
        $this->config = $config;
        $this->logger = $logger;
        $this->httpClient = $httpClient;
        $this->loadSeenPastes();
    }

    /**
     * Check if monitoring is enabled
     */
    public function isEnabled() {
        return $this->config['pastebin']['enabled'] ?? false;
    }

    /**
     * Monitor Pastebin for new pastes
     */
    public function monitor($keywords) {
        if (!$this->isEnabled()) {
            $this->logger->debug('PASTEBIN', 'Pastebin monitoring disabled');
            return [];
        }

        $findings = [];

        try {
            // Use Pastebin scraping API or public archive
            $recentPastes = $this->getRecentPastes();

            foreach ($recentPastes as $paste) {
                // Skip if already seen
                if (in_array($paste['key'], $this->seenPastes)) {
                    continue;
                }

                // Check paste content for keywords
                $finding = $this->checkPaste($paste, $keywords);
                
                if ($finding) {
                    $findings[] = $finding;
                    $this->seenPastes[] = $paste['key'];
                }
            }

            $this->saveSeenPastes();
            $this->logger->info('PASTEBIN', 'Checked ' . count($recentPastes) . ' pastes, found ' . count($findings) . ' matches');

        } catch (Exception $e) {
            $this->logger->error('PASTEBIN', 'Error monitoring Pastebin: ' . $e->getMessage());
        }

        return $findings;
    }

    /**
     * Get recent public pastes
     */
    private function getRecentPastes() {
        $pastes = [];

        // Using pastebin.com/archive endpoint (public)
        $result = $this->httpClient->get('https://pastebin.com/archive');

        if (!$result['success']) {
            throw new Exception('Failed to fetch Pastebin archive');
        }

        $html = $result['data'];

        // Parse paste links from archive page
        preg_match_all('/<a href="\/([a-zA-Z0-9]+)"[^>]*>(.*?)<\/a>/s', $html, $matches, PREG_SET_ORDER);

        foreach ($matches as $match) {
            $pastes[] = [
                'key' => $match[1],
                'title' => strip_tags($match[2]),
                'url' => 'https://pastebin.com/' . $match[1]
            ];
        }

        return array_slice($pastes, 0, 50); // Limit to recent 50
    }

    /**
     * Check a paste for keywords
     */
    private function checkPaste($paste, $keywords) {
        // Fetch raw paste content
        $rawUrl = 'https://pastebin.com/raw/' . $paste['key'];
        
        $result = $this->httpClient->get($rawUrl);

        if (!$result['success']) {
            return null;
        }

        $content = $result['data'];
        $textLower = strtolower($content);

        // Check for keywords
        $foundKeywords = [];
        foreach ($keywords as $keyword) {
            if (stripos($textLower, strtolower($keyword)) !== false) {
                $foundKeywords[] = $keyword;
            }
        }

        if (empty($foundKeywords)) {
            return null;
        }

        // Extract snippet
        $snippet = mb_substr($content, 0, 300);

        $this->logger->info('PASTEBIN', "Match found: {$paste['title']}");

        return [
            'source' => 'Pastebin',
            'title' => $paste['title'] ?: 'Untitled Paste',
            'url' => $paste['url'],
            'snippet' => $snippet,
            'keywords' => $foundKeywords,
            'timestamp' => date('Y-m-d H:i:s'),
        ];
    }

    /**
     * Load seen pastes from cache
     */
    private function loadSeenPastes() {
        $cacheFile = $this->config['storage']['cache_dir'] . '/pastebin_seen.json';
        
        if (file_exists($cacheFile)) {
            $data = json_decode(file_get_contents($cacheFile), true);
            $this->seenPastes = $data ?: [];
        }
    }

    /**
     * Save seen pastes to cache
     */
    private function saveSeenPastes() {
        $cacheFile = $this->config['storage']['cache_dir'] . '/pastebin_seen.json';
        
        // Keep only last 1000 pastes to prevent unbounded growth
        $this->seenPastes = array_slice($this->seenPastes, -1000);
        
        file_put_contents($cacheFile, json_encode($this->seenPastes));
    }
}
