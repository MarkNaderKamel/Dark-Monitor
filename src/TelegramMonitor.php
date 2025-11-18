<?php
/**
 * Telegram Monitor Class
 * 
 * Monitors Telegram channels for new messages containing leak keywords
 */

class TelegramMonitor {
    private $config;
    private $logger;
    private $httpClient;
    private $botToken;
    private $apiUrl;

    public function __construct($config, $logger, $httpClient) {
        $this->config = $config['telegram'];
        $this->logger = $logger;
        $this->httpClient = $httpClient;
        $this->botToken = $this->config['bot_token'];
        $this->apiUrl = $this->config['api_url'] . $this->botToken;
    }

    /**
     * Check if Telegram monitoring is configured
     */
    public function isEnabled() {
        return $this->config['enabled'] && !empty($this->botToken);
    }

    /**
     * Monitor Telegram channels for updates
     */
    public function monitor($keywords) {
        if (!$this->isEnabled()) {
            $this->logger->info('TELEGRAM', 'Telegram monitoring disabled or not configured');
            return [];
        }

        $findings = [];
        
        try {
            // Get updates using long polling
            $offset = $this->getOffset();
            $updates = $this->getUpdates($offset);

            if (empty($updates)) {
                $this->logger->debug('TELEGRAM', 'No new updates');
                return $findings;
            }

            foreach ($updates as $update) {
                $updateId = $update['update_id'] ?? 0;
                
                // Update offset
                $this->saveOffset($updateId + 1);

                // Check if update contains a message
                if (isset($update['message']) || isset($update['channel_post'])) {
                    $message = $update['message'] ?? $update['channel_post'];
                    $finding = $this->processMessage($message, $keywords);
                    
                    if ($finding) {
                        $findings[] = $finding;
                    }
                }
            }

            $this->logger->info('TELEGRAM', 'Processed ' . count($updates) . ' updates, found ' . count($findings) . ' matches');

        } catch (Exception $e) {
            $this->logger->error('TELEGRAM', 'Error monitoring Telegram: ' . $e->getMessage());
        }

        return $findings;
    }

    /**
     * Get updates from Telegram API
     */
    private function getUpdates($offset = 0) {
        $url = $this->apiUrl . '/getUpdates?offset=' . $offset . '&timeout=30';
        
        $maxRetries = 3;
        $attempt = 0;
        
        while ($attempt < $maxRetries) {
            try {
                $ch = curl_init($url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 40);
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
                curl_setopt($ch, CURLOPT_ENCODING, '');
                curl_setopt($ch, CURLOPT_HTTPHEADER, [
                    'Accept: application/json',
                    'Connection: keep-alive'
                ]);
                
                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $curlError = curl_error($ch);
                curl_close($ch);

                if ($response === false) {
                    throw new Exception("cURL error: $curlError");
                }

                if ($httpCode !== 200) {
                    throw new Exception("HTTP error: $httpCode");
                }

                $data = json_decode($response, true);

                if (!isset($data['ok']) || !$data['ok']) {
                    $error = $data['description'] ?? 'Unknown error';
                    throw new Exception("Telegram API error: $error");
                }

                return $data['result'] ?? [];

            } catch (Exception $e) {
                $attempt++;
                if ($attempt < $maxRetries) {
                    $this->logger->warning('TELEGRAM', "Request failed (attempt $attempt/$maxRetries): " . $e->getMessage() . " - Retrying...");
                    sleep(2);
                } else {
                    throw new Exception("Failed after $maxRetries attempts: " . $e->getMessage());
                }
            }
        }

        return [];
    }

    /**
     * Process a single message
     */
    private function processMessage($message, $keywords) {
        $text = $message['text'] ?? '';
        $caption = $message['caption'] ?? '';
        $content = $text . ' ' . $caption;

        if (empty($content)) {
            return null;
        }

        // Check for keywords
        $matches = $this->findKeywords($content, $keywords);
        
        if (empty($matches)) {
            return null;
        }

        // Extract message info
        $chat = $message['chat'] ?? [];
        $chatTitle = $chat['title'] ?? $chat['username'] ?? 'Unknown';
        $messageId = $message['message_id'] ?? 0;
        $date = $message['date'] ?? time();

        $snippet = mb_substr($content, 0, 200);

        $this->logger->info('TELEGRAM', "Match found in $chatTitle: " . implode(', ', $matches));

        return [
            'source' => 'Telegram: ' . $chatTitle,
            'title' => 'Message #' . $messageId,
            'url' => $this->getMessageUrl($chat, $messageId),
            'snippet' => $snippet,
            'keywords' => $matches,
            'timestamp' => date('Y-m-d H:i:s', $date),
        ];
    }

    /**
     * Find keywords in text
     */
    private function findKeywords($text, $keywords) {
        $found = [];
        $textLower = mb_strtolower($text);

        foreach ($keywords as $keyword) {
            if (mb_stripos($textLower, mb_strtolower($keyword)) !== false) {
                $found[] = $keyword;
            }
        }

        return $found;
    }

    /**
     * Generate message URL
     */
    private function getMessageUrl($chat, $messageId) {
        $username = $chat['username'] ?? null;
        
        if ($username) {
            return "https://t.me/$username/$messageId";
        }

        return "Telegram Chat ID: " . ($chat['id'] ?? 'Unknown');
    }

    /**
     * Get stored offset
     */
    private function getOffset() {
        $offsetFile = $this->config['offset_file'];
        
        if (file_exists($offsetFile)) {
            return (int) file_get_contents($offsetFile);
        }

        return 0;
    }

    /**
     * Save offset
     */
    private function saveOffset($offset) {
        $offsetFile = $this->config['offset_file'];
        $dir = dirname($offsetFile);
        
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents($offsetFile, $offset);
    }
}
