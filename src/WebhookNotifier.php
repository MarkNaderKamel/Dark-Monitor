<?php

class WebhookNotifier {
    private $webhooks = [];
    
    public function __construct($config) {
        $this->webhooks = $config['webhooks'] ?? [];
    }
    
    public function notify($finding) {
        $sent = [];
        
        foreach ($this->webhooks as $webhook) {
            if (!($webhook['enabled'] ?? true)) {
                continue;
            }
            
            if (!$this->shouldNotify($webhook, $finding)) {
                continue;
            }
            
            $result = $this->sendWebhook($webhook, $finding);
            $sent[] = [
                'name' => $webhook['name'] ?? 'Unknown',
                'success' => $result
            ];
        }
        
        return $sent;
    }
    
    private function shouldNotify($webhook, $finding) {
        $minSeverity = $webhook['min_severity'] ?? 'LOW';
        
        $severityLevels = [
            'LOW' => 1,
            'MEDIUM' => 2,
            'HIGH' => 3,
            'CRITICAL' => 4
        ];
        
        $findingSeverityLevel = $severityLevels[$finding['severity']] ?? 1;
        $minSeverityLevel = $severityLevels[$minSeverity] ?? 1;
        
        return $findingSeverityLevel >= $minSeverityLevel;
    }
    
    private function sendWebhook($webhook, $finding) {
        $type = $webhook['type'] ?? 'generic';
        
        switch ($type) {
            case 'slack':
                return $this->sendSlack($webhook, $finding);
            case 'discord':
                return $this->sendDiscord($webhook, $finding);
            case 'teams':
                return $this->sendTeams($webhook, $finding);
            default:
                return $this->sendGeneric($webhook, $finding);
        }
    }
    
    private function sendSlack($webhook, $finding) {
        $color = $this->getSeverityColor($finding['severity']);
        
        $payload = [
            'username' => 'Security Monitor',
            'icon_emoji' => ':shield:',
            'attachments' => [
                [
                    'color' => $color,
                    'title' => $finding['title'],
                    'title_link' => $finding['url'],
                    'text' => substr($finding['content'], 0, 500),
                    'fields' => [
                        [
                            'title' => 'Severity',
                            'value' => $finding['severity'],
                            'short' => true
                        ],
                        [
                            'title' => 'Source',
                            'value' => $finding['source'],
                            'short' => true
                        ],
                        [
                            'title' => 'Keywords',
                            'value' => implode(', ', $finding['keywords'] ?? []),
                            'short' => false
                        ]
                    ],
                    'footer' => 'Security Monitoring System',
                    'ts' => time()
                ]
            ]
        ];
        
        return $this->sendHttpPost($webhook['url'], $payload);
    }
    
    private function sendDiscord($webhook, $finding) {
        $color = $this->getSeverityColorCode($finding['severity']);
        
        $payload = [
            'username' => 'Security Monitor',
            'avatar_url' => 'https://cdn-icons-png.flaticon.com/512/2913/2913133.png',
            'embeds' => [
                [
                    'title' => $finding['title'],
                    'description' => substr($finding['content'], 0, 500),
                    'url' => $finding['url'],
                    'color' => $color,
                    'fields' => [
                        [
                            'name' => 'Severity',
                            'value' => $finding['severity'],
                            'inline' => true
                        ],
                        [
                            'name' => 'Source',
                            'value' => $finding['source'],
                            'inline' => true
                        ],
                        [
                            'name' => 'Keywords',
                            'value' => implode(', ', array_slice($finding['keywords'] ?? [], 0, 10)),
                            'inline' => false
                        ]
                    ],
                    'footer' => [
                        'text' => 'Security Monitoring System'
                    ],
                    'timestamp' => date('c')
                ]
            ]
        ];
        
        return $this->sendHttpPost($webhook['url'], $payload);
    }
    
    private function sendTeams($webhook, $finding) {
        $color = $this->getSeverityColor($finding['severity']);
        
        $payload = [
            '@type' => 'MessageCard',
            '@context' => 'https://schema.org/extensions',
            'summary' => $finding['title'],
            'themeColor' => str_replace('#', '', $color),
            'title' => $finding['title'],
            'sections' => [
                [
                    'activityTitle' => 'New Security Finding',
                    'activitySubtitle' => $finding['source'],
                    'facts' => [
                        [
                            'name' => 'Severity',
                            'value' => $finding['severity']
                        ],
                        [
                            'name' => 'Keywords',
                            'value' => implode(', ', array_slice($finding['keywords'] ?? [], 0, 10))
                        ],
                        [
                            'name' => 'Time',
                            'value' => date('Y-m-d H:i:s')
                        ]
                    ],
                    'text' => substr($finding['content'], 0, 500)
                ]
            ],
            'potentialAction' => [
                [
                    '@type' => 'OpenUri',
                    'name' => 'View Finding',
                    'targets' => [
                        [
                            'os' => 'default',
                            'uri' => $finding['url']
                        ]
                    ]
                ]
            ]
        ];
        
        return $this->sendHttpPost($webhook['url'], $payload);
    }
    
    private function sendGeneric($webhook, $finding) {
        $payload = [
            'title' => $finding['title'],
            'url' => $finding['url'],
            'severity' => $finding['severity'],
            'source' => $finding['source'],
            'keywords' => $finding['keywords'] ?? [],
            'content' => $finding['content'],
            'iocs' => $finding['iocs'] ?? [],
            'timestamp' => date('Y-m-d H:i:s'),
            'metadata' => $finding['metadata'] ?? []
        ];
        
        return $this->sendHttpPost($webhook['url'], $payload);
    }
    
    private function sendHttpPost($url, $payload) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        return $httpCode >= 200 && $httpCode < 300;
    }
    
    private function getSeverityColor($severity) {
        $colors = [
            'CRITICAL' => '#FF0000',
            'HIGH' => '#FF8800',
            'MEDIUM' => '#FFAA00',
            'LOW' => '#00AA00'
        ];
        
        return $colors[$severity] ?? '#CCCCCC';
    }
    
    private function getSeverityColorCode($severity) {
        $codes = [
            'CRITICAL' => 16711680,
            'HIGH' => 16744448,
            'MEDIUM' => 16755200,
            'LOW' => 43520
        ];
        
        return $codes[$severity] ?? 13421772;
    }
}
