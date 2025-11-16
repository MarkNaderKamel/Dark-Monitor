<?php

class AlertRulesEngine {
    private $db;
    private $logger;
    private $rules;

    public function __construct($db, $logger) {
        $this->db = $db;
        $this->logger = $logger;
        $this->rules = [];
        $this->loadRules();
    }

    private function loadRules() {
        $this->rules = [
            [
                'name' => 'Critical Finding Auto-Alert',
                'conditions' => function($finding) {
                    return ($finding['severity'] ?? '') === 'CRITICAL';
                },
                'actions' => ['slack', 'discord', 'email'],
                'enabled' => true
            ],
            [
                'name' => 'Multiple High-Severity in Hour',
                'conditions' => function($finding) {
                    // Check if we have 3+ high/critical findings in last hour
                    $recentFindings = $this->db->getFindings([
                        'since' => date('Y-m-d H:i:s', time() - 3600),
                        'severity' => ['HIGH', 'CRITICAL']
                    ]);
                    return count($recentFindings) >= 3;
                },
                'actions' => ['email_summary'],
                'enabled' => true
            ],
            [
                'name' => 'Known Malicious IP Detected',
                'conditions' => function($finding) {
                    if (empty($finding['iocs']['ips'])) return false;
                    
                    foreach ($finding['iocs']['ips'] as $ip) {
                        $reputation = $this->db->getReputationScore('ip', $ip);
                        if ($reputation && $reputation['score'] < 30) {
                            return true;
                        }
                    }
                    return false;
                },
                'actions' => ['slack', 'discord'],
                'enabled' => true
            ],
            [
                'name' => 'Ransomware Keywords Detected',
                'conditions' => function($finding) {
                    $ransomwareKeywords = ['ransomware', 'crypto-locker', 'wannacry', 'maze', 'ryuk', 'conti'];
                    $keywords = $finding['keywords'] ?? [];
                    
                    foreach ($ransomwareKeywords as $keyword) {
                        if (in_array($keyword, $keywords)) {
                            return true;
                        }
                    }
                    return false;
                },
                'actions' => ['slack', 'discord', 'email'],
                'enabled' => true
            ],
            [
                'name' => 'APT Group Indicators',
                'conditions' => function($finding) {
                    $aptKeywords = ['apt28', 'apt29', 'apt41', 'lazarus', 'fancy bear', 'cozy bear'];
                    $text = strtolower(($finding['title'] ?? '') . ' ' . ($finding['snippet'] ?? ''));
                    
                    foreach ($aptKeywords as $keyword) {
                        if (strpos($text, $keyword) !== false) {
                            return true;
                        }
                    }
                    return false;
                },
                'actions' => ['slack', 'discord', 'email'],
                'enabled' => true
            ],
            [
                'name' => 'Zero-Day Exploit Mention',
                'conditions' => function($finding) {
                    $text = strtolower(($finding['title'] ?? '') . ' ' . ($finding['snippet'] ?? ''));
                    return strpos($text, 'zero-day') !== false || strpos($text, '0day') !== false;
                },
                'actions' => ['slack', 'discord', 'email'],
                'enabled' => true
            ],
            [
                'name' => 'Database Dump Detected',
                'conditions' => function($finding) {
                    $keywords = $finding['keywords'] ?? [];
                    return in_array('database', $keywords) && 
                           (in_array('dump', $keywords) || in_array('leak', $keywords));
                },
                'actions' => ['slack'],
                'enabled' => true
            ]
        ];
    }

    public function evaluateFinding($finding) {
        $triggeredRules = [];

        foreach ($this->rules as $rule) {
            if (!$rule['enabled']) continue;

            try {
                if (call_user_func($rule['conditions'], $finding)) {
                    $triggeredRules[] = $rule;
                    $this->logger->info('ALERTS', "Rule triggered: {$rule['name']}");
                }
            } catch (Exception $e) {
                $this->logger->error('ALERTS', "Rule evaluation failed: {$rule['name']} - {$e->getMessage()}");
            }
        }

        return $triggeredRules;
    }

    public function executeActions($triggeredRules, $finding, $notifiers) {
        foreach ($triggeredRules as $rule) {
            foreach ($rule['actions'] as $action) {
                try {
                    switch ($action) {
                        case 'slack':
                            if (isset($notifiers['slack']) && $notifiers['slack']->isEnabled()) {
                                $notifiers['slack']->notify($finding);
                            }
                            break;
                        
                        case 'discord':
                            if (isset($notifiers['discord']) && $notifiers['discord']->isEnabled()) {
                                $notifiers['discord']->notify($finding);
                            }
                            break;
                        
                        case 'email':
                            if (isset($notifiers['email']) && $notifiers['email']->isEnabled()) {
                                $notifiers['email']->notify([$finding]);
                            }
                            break;
                    }
                } catch (Exception $e) {
                    $this->logger->error('ALERTS', "Action execution failed: $action - {$e->getMessage()}");
                }
            }
        }
    }

    public function addCustomRule($name, $conditionFn, $actions) {
        $this->rules[] = [
            'name' => $name,
            'conditions' => $conditionFn,
            'actions' => $actions,
            'enabled' => true
        ];
    }

    public function getRules() {
        return array_map(function($rule) {
            return [
                'name' => $rule['name'],
                'actions' => $rule['actions'],
                'enabled' => $rule['enabled']
            ];
        }, $this->rules);
    }
}
