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

        $snippet = mb_substr($text, 0, 200);

        $this->logger->info('REDDIT', "Match found: {$post['title']}");

        return [
            'source' => 'Reddit',
            'title' => $post['title'],
            'url' => $post['url'],
            'snippet' => $snippet,
            'keywords' => $foundKeywords,
            'timestamp' => date('Y-m-d H:i:s', $post['created']),
        ];
    }
}
