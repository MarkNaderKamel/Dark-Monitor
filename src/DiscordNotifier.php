<?php
/**
 * Discord Notifier Class
 * 
 * Sends notifications to Discord via webhooks with rich embeds
 */

class DiscordNotifier {
    private $logger;
    private $config;
    private $webhookUrl;

    public function __construct($logger, $config) {
        $this->logger = $logger;
        $this->config = $config;
        $this->webhookUrl = $config['notifications']['discord']['webhook_url'] ?? '';
    }

    /**
     * Check if Discord notifications are enabled
     */
    public function isEnabled() {
        return ($this->config['notifications']['discord']['enabled'] ?? false) && !empty($this->webhookUrl);
    }

    /**
     * Send a notification to Discord
     */
    public function notify($finding) {
        if (!$this->isEnabled()) {
            return false;
        }

        try {
            $message = $this->buildMessage($finding);
            return $this->sendWebhook($message);

        } catch (Exception $e) {
            $this->logger->error('DISCORD', 'Failed to send notification: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Build Discord message with embed
     */
    private function buildMessage($finding) {
        $severity = $finding['severity'] ?? 'MEDIUM';
        $color = $this->getSeverityColor($severity);
        
        $keywords = is_array($finding['keywords']) ? implode(', ', $finding['keywords']) : '';
        
        $fields = [
            [
                'name' => 'Source',
                'value' => $finding['source'],
                'inline' => true
            ],
            [
                'name' => 'Severity',
                'value' => $severity,
                'inline' => true
            ],
            [
                'name' => 'Keywords',
                'value' => $keywords ?: 'N/A',
                'inline' => false
            ]
        ];

        if (!empty($finding['iocs'])) {
            $iocSummary = $this->formatIOCs($finding['iocs']);
            if ($iocSummary) {
                $fields[] = [
                    'name' => 'IOCs Detected',
                    'value' => $iocSummary,
                    'inline' => false
                ];
            }
        }

        $embed = [
            'title' => '🚨 ' . $finding['title'],
            'url' => $finding['url'] ?? '',
            'description' => $finding['snippet'] ?? '',
            'color' => $color,
            'fields' => $fields,
            'footer' => [
                'text' => 'Security Monitoring System'
            ],
            'timestamp' => date('c', strtotime($finding['timestamp'] ?? 'now'))
        ];

        return [
            'username' => 'Security Monitor',
            'avatar_url' => 'https://cdn.discordapp.com/embed/avatars/0.png',
            'embeds' => [$embed]
        ];
    }

    /**
     * Get color based on severity (decimal color for Discord)
     */
    private function getSeverityColor($severity) {
        $colors = [
            'CRITICAL' => 16711680,  // Red
            'HIGH' => 16737792,      // Orange
            'MEDIUM' => 16776960,    // Yellow
            'LOW' => 3066993         // Green
        ];

        return $colors[$severity] ?? 8421504; // Gray
    }

    /**
     * Format IOCs for display
     */
    private function formatIOCs($iocs) {
        $parts = [];

        if (!empty($iocs['ips'])) {
            $ips = array_slice($iocs['ips'], 0, 3);
            $parts[] = '**IPs:** `' . implode('`, `', $ips) . '`';
        }

        if (!empty($iocs['urls'])) {
            $parts[] = '**URLs:** ' . count($iocs['urls']) . ' detected';
        }

        if (!empty($iocs['emails'])) {
            $parts[] = '**Emails:** ' . count($iocs['emails']) . ' detected';
        }

        if (!empty($iocs['hashes'])) {
            $parts[] = '**Hashes:** ' . count($iocs['hashes']) . ' detected';
        }

        if (!empty($iocs['api_keys'])) {
            $parts[] = '**API Keys:** ' . count($iocs['api_keys']) . ' detected';
        }

        return implode("\n", $parts);
    }

    /**
     * Send webhook to Discord
     */
    private function sendWebhook($message) {
        $ch = curl_init($this->webhookUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($message));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($httpCode !== 204 && $httpCode !== 200) {
            throw new Exception("Discord API returned HTTP $httpCode: $error");
        }

        $this->logger->info('DISCORD', 'Notification sent successfully');
        return true;
    }

    /**
     * Send summary report
     */
    public function sendSummary($stats) {
        if (!$this->isEnabled()) {
            return false;
        }

        try {
            $embed = [
                'title' => '📊 Security Monitoring Daily Summary',
                'color' => 3066993, // Green
                'fields' => [
                    [
                        'name' => 'Total Findings',
                        'value' => $stats['total'] ?? 0,
                        'inline' => true
                    ],
                    [
                        'name' => 'Critical',
                        'value' => '🔴 ' . ($stats['critical'] ?? 0),
                        'inline' => true
                    ],
                    [
                        'name' => 'High',
                        'value' => '🟠 ' . ($stats['high'] ?? 0),
                        'inline' => true
                    ],
                    [
                        'name' => 'Medium',
                        'value' => '🟡 ' . ($stats['medium'] ?? 0),
                        'inline' => true
                    ],
                    [
                        'name' => 'Low',
                        'value' => '🟢 ' . ($stats['low'] ?? 0),
                        'inline' => true
                    ],
                    [
                        'name' => 'Sources Monitored',
                        'value' => $stats['sources'] ?? 0,
                        'inline' => true
                    ],
                    [
                        'name' => 'Period',
                        'value' => $stats['period'] ?? 'Last 24 hours',
                        'inline' => false
                    ]
                ],
                'footer' => [
                    'text' => 'Security Monitoring System'
                ],
                'timestamp' => date('c')
            ];

            $message = [
                'username' => 'Security Monitor',
                'embeds' => [$embed]
            ];

            return $this->sendWebhook($message);

        } catch (Exception $e) {
            $this->logger->error('DISCORD', 'Failed to send summary: ' . $e->getMessage());
            return false;
        }
    }
}
