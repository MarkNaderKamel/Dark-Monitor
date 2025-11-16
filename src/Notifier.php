<?php
/**
 * Notifier Class
 * 
 * Handles notifications via email and webhooks
 */

class Notifier {
    private $config;
    private $logger;

    public function __construct($config, $logger) {
        $this->config = $config['notifications'];
        $this->logger = $logger;
    }

    /**
     * Send notification for findings
     */
    public function notify($findings) {
        if (empty($findings)) {
            return;
        }

        $this->logger->info('NOTIFIER', 'Sending notifications for ' . count($findings) . ' findings');

        // Send email notification
        if ($this->config['email']['enabled']) {
            $this->sendEmail($findings);
        }

        // Send generic webhook notification
        if ($this->config['webhook']['enabled']) {
            $this->sendWebhook($findings);
        }

        // Send Slack notification
        if ($this->config['slack']['enabled'] ?? false) {
            $this->sendSlack($findings);
        }

        // Send Discord notification
        if ($this->config['discord']['enabled'] ?? false) {
            $this->sendDiscord($findings);
        }
    }

    /**
     * Send email notification using SMTP
     */
    private function sendEmail($findings) {
        try {
            $emailConfig = $this->config['email'];
            
            if (empty($emailConfig['to_email'])) {
                $this->logger->warning('NOTIFIER', 'Email notification skipped: no recipient configured');
                return;
            }

            $subject = $emailConfig['subject_prefix'] . ' ' . count($findings) . ' New Findings Detected';
            $body = $this->formatEmailBody($findings);

            // Use PHPMailer if available, otherwise fallback to mail()
            if ($this->sendViaSMTP($emailConfig, $subject, $body)) {
                $this->logger->info('NOTIFIER', 'Email notification sent successfully');
            } else {
                // Fallback to PHP mail()
                $headers = "From: {$emailConfig['from_email']}\r\n";
                $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
                
                if (mail($emailConfig['to_email'], $subject, $body, $headers)) {
                    $this->logger->info('NOTIFIER', 'Email sent via mail()');
                } else {
                    $this->logger->error('NOTIFIER', 'Failed to send email');
                }
            }

        } catch (Exception $e) {
            $this->logger->error('NOTIFIER', 'Email error: ' . $e->getMessage());
        }
    }

    /**
     * Send via SMTP using sockets
     */
    private function sendViaSMTP($config, $subject, $body) {
        try {
            $socket = fsockopen($config['smtp_host'], $config['smtp_port'], $errno, $errstr, 30);
            
            if (!$socket) {
                throw new Exception("SMTP connection failed: $errstr ($errno)");
            }

            // Basic SMTP conversation (simplified)
            fgets($socket);
            fputs($socket, "EHLO localhost\r\n");
            fgets($socket);
            
            // STARTTLS if port 587
            if ($config['smtp_port'] == 587) {
                fputs($socket, "STARTTLS\r\n");
                fgets($socket);
                stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                fputs($socket, "EHLO localhost\r\n");
                fgets($socket);
            }

            // AUTH LOGIN
            fputs($socket, "AUTH LOGIN\r\n");
            fgets($socket);
            fputs($socket, base64_encode($config['smtp_user']) . "\r\n");
            fgets($socket);
            fputs($socket, base64_encode($config['smtp_password']) . "\r\n");
            fgets($socket);

            // MAIL FROM
            fputs($socket, "MAIL FROM: <{$config['from_email']}>\r\n");
            fgets($socket);

            // RCPT TO
            fputs($socket, "RCPT TO: <{$config['to_email']}>\r\n");
            fgets($socket);

            // DATA
            fputs($socket, "DATA\r\n");
            fgets($socket);

            // Message
            fputs($socket, "Subject: $subject\r\n");
            fputs($socket, "From: {$config['from_email']}\r\n");
            fputs($socket, "To: {$config['to_email']}\r\n");
            fputs($socket, "Content-Type: text/html; charset=UTF-8\r\n\r\n");
            fputs($socket, "$body\r\n.\r\n");
            fgets($socket);

            // QUIT
            fputs($socket, "QUIT\r\n");
            fclose($socket);

            return true;

        } catch (Exception $e) {
            $this->logger->error('NOTIFIER', 'SMTP error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Format email body as HTML
     */
    private function formatEmailBody($findings) {
        $html = '<html><body>';
        $html .= '<h2>Security Monitoring Alert</h2>';
        $html .= '<p>The following potential data leaks or breaches were detected:</p>';
        $html .= '<table border="1" cellpadding="10" style="border-collapse: collapse;">';
        $html .= '<tr><th>Source</th><th>Title</th><th>URL</th><th>Keywords</th><th>Time</th></tr>';

        foreach ($findings as $finding) {
            $html .= '<tr>';
            $html .= '<td>' . htmlspecialchars($finding['source']) . '</td>';
            $html .= '<td>' . htmlspecialchars($finding['title']) . '</td>';
            $html .= '<td><a href="' . htmlspecialchars($finding['url']) . '">Link</a></td>';
            $html .= '<td>' . htmlspecialchars(implode(', ', $finding['keywords'] ?? [])) . '</td>';
            $html .= '<td>' . htmlspecialchars($finding['timestamp']) . '</td>';
            $html .= '</tr>';
        }

        $html .= '</table>';
        $html .= '<p><small>This is an automated alert from the Security Monitoring System.</small></p>';
        $html .= '</body></html>';

        return $html;
    }

    /**
     * Send webhook notification
     */
    private function sendWebhook($findings) {
        try {
            $webhookUrl = $this->config['webhook']['url'];
            
            if (empty($webhookUrl)) {
                return;
            }

            $payload = json_encode([
                'timestamp' => date('Y-m-d H:i:s'),
                'findings_count' => count($findings),
                'findings' => $findings,
            ]);

            $ch = curl_init($webhookUrl);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode >= 200 && $httpCode < 300) {
                $this->logger->info('NOTIFIER', 'Webhook notification sent successfully');
            } else {
                $this->logger->error('NOTIFIER', "Webhook failed with HTTP $httpCode");
            }

        } catch (Exception $e) {
            $this->logger->error('NOTIFIER', 'Webhook error: ' . $e->getMessage());
        }
    }

    /**
     * Send Slack notification
     */
    private function sendSlack($findings) {
        try {
            $webhookUrl = $this->config['slack']['webhook_url'] ?? '';
            
            if (empty($webhookUrl)) {
                return;
            }

            // Group findings by severity
            $bySeverity = [];
            foreach ($findings as $finding) {
                $severity = $finding['severity'] ?? 'LOW';
                if (!isset($bySeverity[$severity])) {
                    $bySeverity[$severity] = [];
                }
                $bySeverity[$severity][] = $finding;
            }

            // Build Slack message blocks
            $blocks = [
                [
                    'type' => 'header',
                    'text' => [
                        'type' => 'plain_text',
                        'text' => '🚨 Security Monitoring Alert',
                        'emoji' => true
                    ]
                ],
                [
                    'type' => 'section',
                    'text' => [
                        'type' => 'mrkdwn',
                        'text' => '*' . count($findings) . ' new security findings detected*'
                    ]
                ],
                [
                    'type' => 'divider'
                ]
            ];

            // Add findings by severity
            foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $sev) {
                if (isset($bySeverity[$sev])) {
                    $emoji = ['CRITICAL' => ':red_circle:', 'HIGH' => ':orange_circle:', 'MEDIUM' => ':yellow_circle:', 'LOW' => ':white_circle:'];
                    
                    $blocks[] = [
                        'type' => 'section',
                        'text' => [
                            'type' => 'mrkdwn',
                            'text' => $emoji[$sev] . ' *' . $sev . ' (' . count($bySeverity[$sev]) . ')*'
                        ]
                    ];

                    foreach (array_slice($bySeverity[$sev], 0, 5) as $finding) {
                        $blocks[] = [
                            'type' => 'section',
                            'text' => [
                                'type' => 'mrkdwn',
                                'text' => '*' . $finding['source'] . '*\n' . 
                                         $finding['title'] . '\n' .
                                         '<' . $finding['url'] . '|View Finding>'
                            ]
                        ];
                    }

                    if (count($bySeverity[$sev]) > 5) {
                        $blocks[] = [
                            'type' => 'context',
                            'elements' => [
                                [
                                    'type' => 'mrkdwn',
                                    'text' => '_+' . (count($bySeverity[$sev]) - 5) . ' more ' . $sev . ' findings_'
                                ]
                            ]
                        ];
                    }
                }
            }

            $payload = json_encode(['blocks' => $blocks]);

            $ch = curl_init($webhookUrl);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $this->logger->info('NOTIFIER', 'Slack notification sent successfully');
            } else {
                $this->logger->error('NOTIFIER', "Slack notification failed with HTTP $httpCode");
            }

        } catch (Exception $e) {
            $this->logger->error('NOTIFIER', 'Slack error: ' . $e->getMessage());
        }
    }

    /**
     * Send Discord notification
     */
    private function sendDiscord($findings) {
        try {
            $webhookUrl = $this->config['discord']['webhook_url'] ?? '';
            
            if (empty($webhookUrl)) {
                return;
            }

            // Build Discord embed
            $embeds = [];
            
            // Group by severity
            $bySeverity = [];
            foreach ($findings as $finding) {
                $severity = $finding['severity'] ?? 'LOW';
                if (!isset($bySeverity[$severity])) {
                    $bySeverity[$severity] = [];
                }
                $bySeverity[$severity][] = $finding;
            }

            // Color codes
            $colors = [
                'CRITICAL' => 0xFF0000, // Red
                'HIGH' => 0xFF6600,     // Orange
                'MEDIUM' => 0xFFCC00,   // Yellow
                'LOW' => 0x00FF00       // Green
            ];

            foreach (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as $sev) {
                if (isset($bySeverity[$sev])) {
                    $fields = [];
                    
                    foreach (array_slice($bySeverity[$sev], 0, 5) as $finding) {
                        $fields[] = [
                            'name' => $finding['source'],
                            'value' => $finding['title'] . '\n[View](' . $finding['url'] . ')',
                            'inline' => false
                        ];
                    }

                    $embeds[] = [
                        'title' => '🚨 ' . $sev . ' Severity (' . count($bySeverity[$sev]) . ')',
                        'color' => $colors[$sev],
                        'fields' => $fields,
                        'timestamp' => date('c'),
                        'footer' => [
                            'text' => 'Security Monitoring System'
                        ]
                    ];
                }
            }

            $payload = json_encode([
                'content' => '**' . count($findings) . ' new security findings detected**',
                'embeds' => array_slice($embeds, 0, 10) // Discord limit
            ]);

            $ch = curl_init($webhookUrl);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            
            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200 || $httpCode === 204) {
                $this->logger->info('NOTIFIER', 'Discord notification sent successfully');
            } else {
                $this->logger->error('NOTIFIER', "Discord notification failed with HTTP $httpCode");
            }

        } catch (Exception $e) {
            $this->logger->error('NOTIFIER', 'Discord error: ' . $e->getMessage());
        }
    }
}
