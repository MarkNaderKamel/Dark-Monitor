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
        $snippet = $this->extractSnippet($content, $foundKeywords[0]);
        
        // Extract IOCs
        $iocs = $this->extractIOCs($content);

        $this->logger->info('PASTEBIN', "Match found: {$paste['title']}");

        return [
            'source' => 'Pastebin',
            'title' => $paste['title'] ?: 'Untitled Paste',
            'url' => $paste['url'],
            'snippet' => $snippet,
            'keywords' => $foundKeywords,
            'timestamp' => date('Y-m-d H:i:s'),
            'iocs' => $iocs
        ];
    }

    /**
     * Extract snippet around keyword
     */
    private function extractSnippet($content, $keyword, $length = 300) {
        $pos = stripos($content, $keyword);
        
        if ($pos === false) {
            return mb_substr($content, 0, $length);
        }

        $start = max(0, $pos - 100);
        $snippet = mb_substr($content, $start, $length);
        
        if ($start > 0) {
            $snippet = '...' . $snippet;
        }
        
        if (mb_strlen($content) > $start + $length) {
            $snippet .= '...';
        }

        return $snippet;
    }

    /**
     * Extract IOCs (Indicators of Compromise) from content
     */
    private function extractIOCs($content) {
        $iocs = [];

        // Extract IP addresses
        preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $content, $ips);
        if (!empty($ips[0])) {
            $iocs['ips'] = array_unique(array_slice($ips[0], 0, 10));
        }

        // Extract email addresses
        preg_match_all('/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/', $content, $emails);
        if (!empty($emails[0])) {
            $iocs['emails'] = array_unique(array_slice($emails[0], 0, 10));
        }

        // Extract URLs
        preg_match_all('/\b(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s]*)?\b/i', $content, $urls);
        if (!empty($urls[0])) {
            $iocs['urls'] = array_unique(array_slice($urls[0], 0, 10));
        }

        // Extract hashes (MD5, SHA1, SHA256)
        preg_match_all('/\b[a-f0-9]{32,64}\b/i', $content, $hashes);
        if (!empty($hashes[0])) {
            $iocs['hashes'] = array_unique(array_slice($hashes[0], 0, 5));
        }

        return $iocs;
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
