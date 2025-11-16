<?php
/**
 * Slack Notifier Class
 * 
 * Sends notifications to Slack via webhooks
 */

class SlackNotifier {
    private $logger;
    private $config;
    private $webhookUrl;

    public function __construct($logger, $config) {
        $this->logger = $logger;
        $this->config = $config;
        $this->webhookUrl = $config['notifications']['slack']['webhook_url'] ?? '';
    }

    /**
     * Check if Slack notifications are enabled
     */
    public function isEnabled() {
        return ($this->config['notifications']['slack']['enabled'] ?? false) && !empty($this->webhookUrl);
    }

    /**
     * Send a notification to Slack
     */
    public function notify($finding) {
        if (!$this->isEnabled()) {
            return false;
        }

        try {
            $message = $this->buildMessage($finding);
            return $this->sendWebhook($message);

        } catch (Exception $e) {
            $this->logger->error('SLACK', 'Failed to send notification: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Build Slack message payload
     */
    private function buildMessage($finding) {
        $severity = $finding['severity'] ?? 'MEDIUM';
        $color = $this->getSeverityColor($severity);
        
        $keywords = is_array($finding['keywords']) ? implode(', ', $finding['keywords']) : '';
        
        $fields = [
            [
                'title' => 'Source',
                'value' => $finding['source'],
                'short' => true
            ],
            [
                'title' => 'Severity',
                'value' => $severity,
                'short' => true
            ],
            [
                'title' => 'Keywords',
                'value' => $keywords,
                'short' => false
            ]
        ];

        if (!empty($finding['iocs'])) {
            $iocSummary = $this->formatIOCs($finding['iocs']);
            if ($iocSummary) {
                $fields[] = [
                    'title' => 'IOCs Detected',
                    'value' => $iocSummary,
                    'short' => false
                ];
            }
        }

        return [
            'username' => 'Security Monitor',
            'icon_emoji' => ':warning:',
            'attachments' => [
                [
                    'color' => $color,
                    'title' => $finding['title'],
                    'title_link' => $finding['url'] ?? '',
                    'text' => $finding['snippet'] ?? '',
                    'fields' => $fields,
                    'footer' => 'Security Monitoring System',
                    'footer_icon' => 'https://platform.slack-edge.com/img/default_application_icon.png',
                    'ts' => strtotime($finding['timestamp'] ?? 'now')
                ]
            ]
        ];
    }

    /**
     * Get color based on severity
     */
    private function getSeverityColor($severity) {
        $colors = [
            'CRITICAL' => '#ff0000',
            'HIGH' => '#ff6600',
            'MEDIUM' => '#ffcc00',
            'LOW' => '#36a64f'
        ];

        return $colors[$severity] ?? '#808080';
    }

    /**
     * Format IOCs for display
     */
    private function formatIOCs($iocs) {
        $parts = [];

        if (!empty($iocs['ips'])) {
            $parts[] = 'IPs: ' . implode(', ', array_slice($iocs['ips'], 0, 3));
        }

        if (!empty($iocs['urls'])) {
            $parts[] = 'URLs: ' . count($iocs['urls']);
        }

        if (!empty($iocs['emails'])) {
            $parts[] = 'Emails: ' . count($iocs['emails']);
        }

        if (!empty($iocs['hashes'])) {
            $parts[] = 'Hashes: ' . count($iocs['hashes']);
        }

        return implode(' | ', $parts);
    }

    /**
     * Send webhook to Slack
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

        if ($httpCode !== 200) {
            throw new Exception("Slack API returned HTTP $httpCode: $error");
        }

        $this->logger->info('SLACK', 'Notification sent successfully');
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
            $message = [
                'username' => 'Security Monitor',
                'icon_emoji' => ':bar_chart:',
                'text' => '*Security Monitoring Daily Summary*',
                'attachments' => [
                    [
                        'color' => '#36a64f',
                        'fields' => [
                            [
                                'title' => 'Total Findings',
                                'value' => $stats['total'] ?? 0,
                                'short' => true
                            ],
                            [
                                'title' => 'Critical',
                                'value' => $stats['critical'] ?? 0,
                                'short' => true
                            ],
                            [
                                'title' => 'High',
                                'value' => $stats['high'] ?? 0,
                                'short' => true
                            ],
                            [
                                'title' => 'Medium',
                                'value' => $stats['medium'] ?? 0,
                                'short' => true
                            ],
                            [
                                'title' => 'Sources Monitored',
                                'value' => $stats['sources'] ?? 0,
                                'short' => true
                            ],
                            [
                                'title' => 'Period',
                                'value' => $stats['period'] ?? 'Last 24 hours',
                                'short' => true
                            ]
                        ],
                        'footer' => 'Security Monitoring System',
                        'ts' => time()
                    ]
                ]
            ];

            return $this->sendWebhook($message);

        } catch (Exception $e) {
            $this->logger->error('SLACK', 'Failed to send summary: ' . $e->getMessage());
            return false;
        }
    }
}
