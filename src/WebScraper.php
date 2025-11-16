<?php
/**
 * Web Scraper Class
 * 
 * Scrapes clear web forums and websites for leak mentions
 */

class WebScraper {
    private $config;
    private $logger;
    private $httpClient;

    public function __construct($config, $logger, $httpClient) {
        $this->config = $config;
        $this->logger = $logger;
        $this->httpClient = $httpClient;
    }

    /**
     * Scrape all configured clear web sources
     */
    public function scrapeAll($keywords) {
        $findings = [];
        $sources = $this->config['clearweb_sources'];

        foreach ($sources as $source) {
            if (!($source['enabled'] ?? true)) {
                continue;
            }

            $this->logger->info('SCRAPER', "Scraping {$source['name']} - {$source['url']}");

            try {
                $result = $this->scrapeSite($source, $keywords);
                $findings = array_merge($findings, $result);
                
                // Rate limiting
                $this->httpClient->rateLimit();

            } catch (Exception $e) {
                $this->logger->error('SCRAPER', "Failed to scrape {$source['name']}: " . $e->getMessage());
            }
        }

        $this->logger->info('SCRAPER', 'Total findings from clear web: ' . count($findings));
        return $findings;
    }

    /**
     * Scrape a single site
     */
    private function scrapeSite($source, $keywords) {
        $findings = [];

        // Check robots.txt
        if (!$this->httpClient->checkRobotsTxt($source['url'])) {
            $this->logger->warning('SCRAPER', "Skipping {$source['name']} due to robots.txt");
            return $findings;
        }

        // Fetch page content
        $result = $this->httpClient->get($source['url']);

        if (!$result['success']) {
            throw new Exception($result['error'] ?? 'Unknown error');
        }

        $html = $result['data'];

        // Parse and search for keywords
        $matches = $this->parseContent($html, $keywords, $source);

        foreach ($matches as $match) {
            $findings[] = [
                'source' => $source['name'],
                'title' => $match['title'],
                'url' => $match['url'],
                'snippet' => $match['snippet'],
                'keywords' => $match['keywords'],
                'timestamp' => date('Y-m-d H:i:s'),
            ];

            $this->logger->info('SCRAPER', "Match found: {$match['title']}");
        }

        return $findings;
    }

    /**
     * Parse HTML content and search for keywords
     */
    private function parseContent($html, $keywords, $source) {
        $matches = [];

        // Remove HTML tags for text search
        $text = strip_tags($html);

        // Check if any keyword is present
        $foundKeywords = [];
        foreach ($keywords as $keyword) {
            if (mb_stripos($text, $keyword) !== false) {
                $foundKeywords[] = $keyword;
            }
        }

        if (empty($foundKeywords)) {
            return $matches;
        }

        // Try to extract structured data using simple parsing
        // Look for common patterns: threads, posts, articles

        // Extract links and titles using regex
        preg_match_all('/<a[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)<\/a>/is', $html, $links);

        for ($i = 0; $i < count($links[1]); $i++) {
            $url = $links[1][$i];
            $title = strip_tags($links[2][$i]);
            
            // Check if title contains keywords
            $titleKeywords = [];
            foreach ($keywords as $keyword) {
                if (mb_stripos($title, $keyword) !== false) {
                    $titleKeywords[] = $keyword;
                }
            }

            if (!empty($titleKeywords)) {
                // Make URL absolute
                if (!preg_match('/^https?:\/\//i', $url)) {
                    $parsedSource = parse_url($source['url']);
                    $baseUrl = $parsedSource['scheme'] . '://' . $parsedSource['host'];
                    $url = $baseUrl . '/' . ltrim($url, '/');
                }

                $matches[] = [
                    'title' => trim($title),
                    'url' => $url,
                    'snippet' => mb_substr($title, 0, 200),
                    'keywords' => $titleKeywords,
                ];

                // Limit to 10 matches per site to avoid spam
                if (count($matches) >= 10) {
                    break;
                }
            }
        }

        // If no structured matches but keywords found, create generic finding
        if (empty($matches) && !empty($foundKeywords)) {
            $snippet = $this->extractSnippet($text, $foundKeywords[0]);
            
            $matches[] = [
                'title' => 'Keywords detected on ' . $source['name'],
                'url' => $source['url'],
                'snippet' => $snippet,
                'keywords' => $foundKeywords,
            ];
        }

        return $matches;
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
