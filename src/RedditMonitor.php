<?php
/**
 * Reddit Monitor Class
 * 
 * Monitors Reddit subreddits for leak mentions
 */

class RedditMonitor {
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
        return $this->config['reddit']['enabled'] ?? false;
    }

    /**
     * Monitor Reddit subreddits
     */
    public function monitor($keywords) {
        if (!$this->isEnabled()) {
            $this->logger->debug('REDDIT', 'Reddit monitoring disabled');
            return [];
        }

        $findings = [];
        $subreddits = $this->config['reddit']['subreddits'] ?? [];

        foreach ($subreddits as $subreddit) {
            try {
                $this->logger->debug('REDDIT', "Checking r/$subreddit");
                
                $posts = $this->getRecentPosts($subreddit);
                
                foreach ($posts as $post) {
                    $finding = $this->checkPost($post, $keywords);
                    
                    if ($finding) {
                        $findings[] = $finding;
                    }
                }

                // Rate limiting for Reddit
                sleep(2);

            } catch (Exception $e) {
                $this->logger->error('REDDIT', "Error checking r/$subreddit: " . $e->getMessage());
            }
        }

        $this->logger->info('REDDIT', 'Found ' . count($findings) . ' matches on Reddit');
        return $findings;
    }

    /**
     * Get recent posts from a subreddit
     */
    private function getRecentPosts($subreddit) {
        // Use Reddit JSON API (public, no auth required)
        $url = "https://www.reddit.com/r/$subreddit/new.json?limit=25";
        
        $result = $this->httpClient->get($url);

        if (!$result['success']) {
            throw new Exception('Failed to fetch Reddit posts');
        }

        $data = json_decode($result['data'], true);

        if (!isset($data['data']['children'])) {
            return [];
        }

        $posts = [];
        foreach ($data['data']['children'] as $child) {
            $post = $child['data'];
            $posts[] = [
                'id' => $post['id'],
                'title' => $post['title'],
                'selftext' => $post['selftext'] ?? '',
                'url' => 'https://www.reddit.com' . $post['permalink'],
                'created' => $post['created_utc'],
                'author' => $post['author']
            ];
        }

        return $posts;
    }

    /**
     * Check a post for keywords
     */
    private function checkPost($post, $keywords) {
        $text = $post['title'] . ' ' . $post['selftext'];
        $textLower = strtolower($text);

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

        $snippet = $this->extractSnippet($text, $foundKeywords[0]);
        $iocs = $this->extractIOCs($text);

        $this->logger->info('REDDIT', "Match found: {$post['title']}");

        return [
            'source' => 'Reddit',
            'title' => $post['title'],
            'url' => $post['url'],
            'snippet' => $snippet,
            'keywords' => $foundKeywords,
            'timestamp' => date('Y-m-d H:i:s', $post['created']),
            'iocs' => $iocs
        ];
    }

    /**
     * Extract snippet around keyword
     */
    private function extractSnippet($content, $keyword, $length = 200) {
        $pos = stripos($content, $keyword);
        
        if ($pos === false) {
            return mb_substr($content, 0, $length);
        }

        $start = max(0, $pos - 50);
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
     * Extract IOCs from content
     */
    private function extractIOCs($content) {
        $iocs = [];

        // Extract IP addresses
        preg_match_all('/\b(?:\d{1,3}\.){3}\d{1,3}\b/', $content, $ips);
        if (!empty($ips[0])) {
            $iocs['ips'] = array_unique(array_slice($ips[0], 0, 5));
        }

        // Extract URLs
        preg_match_all('/\b(?:https?:\/\/)?(?:www\.)?([a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s]*)?\b/i', $content, $urls);
        if (!empty($urls[0])) {
            $iocs['urls'] = array_unique(array_slice($urls[0], 0, 5));
        }

        // Extract email addresses
        preg_match_all('/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/', $content, $emails);
        if (!empty($emails[0])) {
            $iocs['emails'] = array_unique(array_slice($emails[0], 0, 5));
        }

        return $iocs;
    }
}
