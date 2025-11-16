<?php

class AdditionalPasteSites {
    private $httpClient;
    private $logger;
    private $enabled;

    public function __construct($httpClient, $logger) {
        $this->httpClient = $httpClient;
        $this->logger = $logger;
        $this->enabled = true;
    }

    public function isEnabled() {
        return $this->enabled;
    }

    /**
     * Monitor Paste.ee (https://paste.ee)
     */
    public function monitorPasteEe($keywords) {
        $findings = [];
        
        try {
            $this->logger->info('PASTE.EE', 'Checking for new pastes');
            
            // Paste.ee has an API but requires registration
            // Using recent pastes page as fallback
            $url = 'https://paste.ee/r';
            $html = $this->httpClient->get($url);
            
            if (!$html) {
                return $findings;
            }

            // Parse recent pastes
            preg_match_all('/<a href="\/p\/([^"]+)"[^>]*>([^<]+)<\/a>/i', $html, $matches, PREG_SET_ORDER);
            
            foreach ($matches as $match) {
                $pasteId = $match[1];
                $title = $match[2];
                
                // Check if title matches keywords
                $matchedKeywords = [];
                foreach ($keywords as $keyword) {
                    if (stripos($title, $keyword) !== false) {
                        $matchedKeywords[] = $keyword;
                    }
                }
                
                if (!empty($matchedKeywords)) {
                    $pasteUrl = "https://paste.ee/p/$pasteId";
                    
                    $findings[] = [
                        'source' => 'Paste.ee',
                        'title' => $title,
                        'url' => $pasteUrl,
                        'snippet' => 'Keywords matched: ' . implode(', ', $matchedKeywords),
                        'keywords' => $matchedKeywords,
                        'severity' => 'MEDIUM',
                        'iocs' => []
                    ];
                    
                    $this->logger->info('PASTE.EE', "Match found: $title");
                }
            }
            
        } catch (Exception $e) {
            $this->logger->error('PASTE.EE', 'Error monitoring: ' . $e->getMessage());
        }
        
        return $findings;
    }

    /**
     * Monitor Ghostbin (https://ghostbin.com)
     */
    public function monitorGhostbin($keywords) {
        $findings = [];
        
        try {
            $this->logger->info('GHOSTBIN', 'Checking for new pastes');
            
            $url = 'https://ghostbin.com/browse';
            $html = $this->httpClient->get($url);
            
            if (!$html) {
                return $findings;
            }

            // Parse paste listings
            preg_match_all('/<a href="\/paste\/([^"]+)"[^>]*>([^<]+)<\/a>/i', $html, $matches, PREG_SET_ORDER);
            
            foreach ($matches as $match) {
                $pasteId = $match[1];
                $title = $match[2];
                
                $matchedKeywords = [];
                foreach ($keywords as $keyword) {
                    if (stripos($title, $keyword) !== false) {
                        $matchedKeywords[] = $keyword;
                    }
                }
                
                if (!empty($matchedKeywords)) {
                    $pasteUrl = "https://ghostbin.com/paste/$pasteId";
                    
                    $findings[] = [
                        'source' => 'Ghostbin',
                        'title' => $title,
                        'url' => $pasteUrl,
                        'snippet' => 'Keywords matched: ' . implode(', ', $matchedKeywords),
                        'keywords' => $matchedKeywords,
                        'severity' => 'MEDIUM',
                        'iocs' => []
                    ];
                    
                    $this->logger->info('GHOSTBIN', "Match found: $title");
                }
            }
            
        } catch (Exception $e) {
            $this->logger->error('GHOSTBIN', 'Error monitoring: ' . $e->getMessage());
        }
        
        return $findings;
    }

    /**
     * Monitor Slexy (https://slexy.org)
     */
    public function monitorSlexy($keywords) {
        $findings = [];
        
        try {
            $this->logger->info('SLEXY', 'Checking for new pastes');
            
            $url = 'https://slexy.org/recent';
            $html = $this->httpClient->get($url);
            
            if (!$html) {
                return $findings;
            }

            // Parse recent pastes
            preg_match_all('/\/view\/([^\s"<]+)/i', $html, $pasteMatches);
            preg_match_all('/<td>([^<]+)<\/td>/i', $html, $titleMatches);
            
            $pasteIds = array_unique($pasteMatches[1] ?? []);
            $titles = $titleMatches[1] ?? [];
            
            foreach ($pasteIds as $index => $pasteId) {
                $title = $titles[$index] ?? 'Untitled';
                
                $matchedKeywords = [];
                foreach ($keywords as $keyword) {
                    if (stripos($title, $keyword) !== false) {
                        $matchedKeywords[] = $keyword;
                    }
                }
                
                if (!empty($matchedKeywords)) {
                    $pasteUrl = "https://slexy.org/view/$pasteId";
                    
                    $findings[] = [
                        'source' => 'Slexy',
                        'title' => $title,
                        'url' => $pasteUrl,
                        'snippet' => 'Keywords matched: ' . implode(', ', $matchedKeywords),
                        'keywords' => $matchedKeywords,
                        'severity' => 'MEDIUM',
                        'iocs' => []
                    ];
                    
                    $this->logger->info('SLEXY', "Match found: $title");
                }
            }
            
        } catch (Exception $e) {
            $this->logger->error('SLEXY', 'Error monitoring: ' . $e->getMessage());
        }
        
        return $findings;
    }

    /**
     * Monitor Rentry (https://rentry.co)
     */
    public function monitorRentry($keywords) {
        $findings = [];
        
        try {
            $this->logger->info('RENTRY', 'Checking for new entries');
            
            // Rentry doesn't have a public recent list, but we can check specific keywords
            foreach (array_slice($keywords, 0, 5) as $keyword) {
                $searchUrl = "https://rentry.co/$keyword";
                $html = $this->httpClient->get($searchUrl);
                
                if ($html && strlen($html) > 100) {
                    $findings[] = [
                        'source' => 'Rentry',
                        'title' => "Entry found for: $keyword",
                        'url' => $searchUrl,
                        'snippet' => substr(strip_tags($html), 0, 200),
                        'keywords' => [$keyword],
                        'severity' => 'LOW',
                        'iocs' => []
                    ];
                    
                    $this->logger->info('RENTRY', "Entry found: $keyword");
                }
            }
            
        } catch (Exception $e) {
            $this->logger->error('RENTRY', 'Error monitoring: ' . $e->getMessage());
        }
        
        return $findings;
    }

    public function monitor($keywords) {
        $allFindings = [];
        
        $allFindings = array_merge($allFindings, $this->monitorPasteEe($keywords));
        $allFindings = array_merge($allFindings, $this->monitorGhostbin($keywords));
        $allFindings = array_merge($allFindings, $this->monitorSlexy($keywords));
        $allFindings = array_merge($allFindings, $this->monitorRentry($keywords));
        
        return $allFindings;
    }
}
