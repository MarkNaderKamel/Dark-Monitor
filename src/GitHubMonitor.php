<?php
/**
 * GitHub Monitor Class
 * 
 * Monitors GitHub for leaked credentials and sensitive data
 */

class GitHubMonitor {
    private $config;
    private $logger;
    private $httpClient;

    public function __construct($config, $logger, $httpClient) {
        $this->config = $config;
        $this->logger = $logger;
        $this->httpClient = $httpClient;
    }

    /**
     * Check if monitoring is enabled
     */
    public function isEnabled() {
        return $this->config['github']['enabled'] ?? false;
    }

    /**
     * Monitor GitHub code search
     */
    public function monitor($keywords) {
        if (!$this->isEnabled()) {
            $this->logger->debug('GITHUB', 'GitHub monitoring disabled');
            return [];
        }

        $findings = [];
        $token = $this->config['github']['api_token'] ?? '';

        // Custom search queries (e.g., company domains, API keys)
        $customQueries = $this->config['github']['search_queries'] ?? [];

        foreach ($customQueries as $query) {
            try {
                $this->logger->debug('GITHUB', "Searching GitHub for: $query");
                
                $results = $this->searchCode($query, $token);
                
                foreach ($results as $result) {
                    $finding = $this->processResult($result, $keywords);
                    
                    if ($finding) {
                        $findings[] = $finding;
                    }
                }

                // Rate limiting for GitHub API
                sleep(3);

            } catch (Exception $e) {
                $this->logger->error('GITHUB', "Error searching GitHub: " . $e->getMessage());
            }
        }

        $this->logger->info('GITHUB', 'Found ' . count($findings) . ' matches on GitHub');
        return $findings;
    }

    /**
     * Search GitHub code
     */
    private function searchCode($query, $token) {
        $url = 'https://api.github.com/search/code?q=' . urlencode($query) . '&per_page=10';
        
        $headers = [
            'Accept: application/vnd.github.v3+json',
            'User-Agent: Security-Monitor'
        ];

        if (!empty($token)) {
            $headers[] = "Authorization: Bearer $token";
        }

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($httpCode !== 200) {
            throw new Exception("GitHub API returned HTTP $httpCode");
        }

        $data = json_decode($response, true);

        if (!isset($data['items'])) {
            return [];
        }

        return $data['items'];
    }

    /**
     * Process search result
     */
    private function processResult($result, $keywords) {
        $snippet = $result['text_matches'][0]['fragment'] ?? '';
        $textLower = strtolower($snippet);

        // Check for keywords
        $foundKeywords = [];
        foreach ($keywords as $keyword) {
            if (stripos($textLower, strtolower($keyword)) !== false) {
                $foundKeywords[] = $keyword;
            }
        }

        // Always report GitHub findings as they're often sensitive
        if (empty($foundKeywords) && empty($snippet)) {
            // Still create finding but mark as informational
            $foundKeywords = ['github-leak'];
        }

        $this->logger->info('GITHUB', "Match found: {$result['name']}");

        return [
            'source' => 'GitHub',
            'title' => $result['repository']['full_name'] . ' / ' . $result['name'],
            'url' => $result['html_url'],
            'snippet' => mb_substr($snippet, 0, 200),
            'keywords' => $foundKeywords,
            'timestamp' => date('Y-m-d H:i:s'),
        ];
    }
}
