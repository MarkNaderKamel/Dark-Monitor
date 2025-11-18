<?php

class MITREMapper {
    private $mappingRules = [];
    private $configFile;
    
    public function __construct($configFile = null) {
        $this->configFile = $configFile ?? __DIR__ . '/../config/mitre_mappings.json';
        $this->loadMappingRules();
    }
    
    private function loadMappingRules() {
        if (file_exists($this->configFile)) {
            $json = file_get_contents($this->configFile);
            $this->mappingRules = json_decode($json, true) ?? [];
        } else {
            $this->mappingRules = $this->getDefaultMappings();
            $this->saveMappingRules();
        }
    }
    
    private function saveMappingRules() {
        $dir = dirname($this->configFile);
        if (!file_exists($dir)) {
            mkdir($dir, 0755, true);
        }
        
        file_put_contents(
            $this->configFile,
            json_encode($this->mappingRules, JSON_PRETTY_PRINT)
        );
    }
    
    private function getDefaultMappings() {
        return [
            'keyword_mappings' => [
                'phishing' => [
                    ['id' => 'T1566', 'name' => 'Phishing', 'tactic' => 'initial-access']
                ],
                'credential dump' => [
                    ['id' => 'T1003', 'name' => 'OS Credential Dumping', 'tactic' => 'credential-access']
                ],
                'ransomware' => [
                    ['id' => 'T1486', 'name' => 'Data Encrypted for Impact', 'tactic' => 'impact'],
                    ['id' => 'T1490', 'name' => 'Inhibit System Recovery', 'tactic' => 'impact']
                ],
                'backdoor' => [
                    ['id' => 'T1547', 'name' => 'Boot or Logon Autostart Execution', 'tactic' => 'persistence']
                ],
                'c2' => [
                    ['id' => 'T1071', 'name' => 'Application Layer Protocol', 'tactic' => 'command-and-control']
                ],
                'exfiltration' => [
                    ['id' => 'T1041', 'name' => 'Exfiltration Over C2 Channel', 'tactic' => 'exfiltration']
                ],
                'lateral movement' => [
                    ['id' => 'T1021', 'name' => 'Remote Services', 'tactic' => 'lateral-movement']
                ],
                'privilege escalation' => [
                    ['id' => 'T1068', 'name' => 'Exploitation for Privilege Escalation', 'tactic' => 'privilege-escalation']
                ],
                'exploit' => [
                    ['id' => 'T1203', 'name' => 'Exploitation for Client Execution', 'tactic' => 'execution']
                ],
                'powershell' => [
                    ['id' => 'T1059.001', 'name' => 'PowerShell', 'tactic' => 'execution']
                ],
                'mimikatz' => [
                    ['id' => 'T1003.001', 'name' => 'LSASS Memory', 'tactic' => 'credential-access']
                ],
                'keylogger' => [
                    ['id' => 'T1056.001', 'name' => 'Keylogging', 'tactic' => 'collection']
                ],
                'rootkit' => [
                    ['id' => 'T1014', 'name' => 'Rootkit', 'tactic' => 'defense-evasion']
                ],
                'ddos' => [
                    ['id' => 'T1498', 'name' => 'Network Denial of Service', 'tactic' => 'impact']
                ],
                'sql injection' => [
                    ['id' => 'T1190', 'name' => 'Exploit Public-Facing Application', 'tactic' => 'initial-access']
                ],
                'brute force' => [
                    ['id' => 'T1110', 'name' => 'Brute Force', 'tactic' => 'credential-access']
                ]
            ],
            'ioc_mappings' => [
                'credentials' => [
                    ['id' => 'T1078', 'name' => 'Valid Accounts', 'tactic' => 'initial-access']
                ],
                'hashes' => [
                    ['id' => 'T1204', 'name' => 'User Execution', 'tactic' => 'execution']
                ]
            ],
            'source_mappings' => [
                'Pastebin' => [
                    ['id' => 'T1567', 'name' => 'Exfiltration Over Web Service', 'tactic' => 'exfiltration']
                ],
                'GitHub Secret Scanning' => [
                    ['id' => 'T1552.001', 'name' => 'Credentials In Files', 'tactic' => 'credential-access']
                ]
            ]
        ];
    }
    
    public function mapFindingToMITRE($finding) {
        $techniques = [];
        $uniqueTechniques = [];
        
        $keywords = is_string($finding['keywords']) ? 
            json_decode($finding['keywords'], true) : 
            ($finding['keywords'] ?? []);
        
        if (is_array($keywords)) {
            foreach ($keywords as $keyword) {
                $keywordLower = strtolower($keyword);
                
                foreach ($this->mappingRules['keyword_mappings'] ?? [] as $pattern => $techs) {
                    if (stripos($keywordLower, strtolower($pattern)) !== false) {
                        foreach ($techs as $tech) {
                            $key = $tech['id'];
                            if (!isset($uniqueTechniques[$key])) {
                                $uniqueTechniques[$key] = $tech;
                                $techniques[] = $tech;
                            }
                        }
                    }
                }
            }
        }
        
        $iocs = is_string($finding['iocs']) ? 
            json_decode($finding['iocs'], true) : 
            ($finding['iocs'] ?? []);
        
        if (is_array($iocs)) {
            foreach ($this->mappingRules['ioc_mappings'] ?? [] as $iocType => $techs) {
                if (!empty($iocs[$iocType])) {
                    foreach ($techs as $tech) {
                        $key = $tech['id'];
                        if (!isset($uniqueTechniques[$key])) {
                            $uniqueTechniques[$key] = $tech;
                            $techniques[] = $tech;
                        }
                    }
                }
            }
        }
        
        $source = $finding['source'] ?? '';
        foreach ($this->mappingRules['source_mappings'] ?? [] as $sourcePattern => $techs) {
            if (stripos($source, $sourcePattern) !== false) {
                foreach ($techs as $tech) {
                    $key = $tech['id'];
                    if (!isset($uniqueTechniques[$key])) {
                        $uniqueTechniques[$key] = $tech;
                        $techniques[] = $tech;
                    }
                }
            }
        }
        
        return $techniques;
    }
    
    public function enrichFindingWithMITRE($finding) {
        $techniques = $this->mapFindingToMITRE($finding);
        
        $metadata = is_string($finding['metadata']) ? 
            json_decode($finding['metadata'], true) : 
            ($finding['metadata'] ?? []);
        
        if (!is_array($metadata)) {
            $metadata = [];
        }
        
        $metadata['mitre_techniques'] = $techniques;
        $metadata['mitre_tactics'] = array_values(array_unique(
            array_column($techniques, 'tactic')
        ));
        
        $finding['metadata'] = $metadata;
        
        return $finding;
    }
    
    public function getTechniquesByTactic() {
        $byTactic = [];
        
        foreach ($this->mappingRules['keyword_mappings'] ?? [] as $keyword => $techniques) {
            foreach ($techniques as $tech) {
                $tactic = $tech['tactic'] ?? 'unknown';
                if (!isset($byTactic[$tactic])) {
                    $byTactic[$tactic] = [];
                }
                $byTactic[$tactic][] = [
                    'id' => $tech['id'],
                    'name' => $tech['name'],
                    'keyword' => $keyword
                ];
            }
        }
        
        return $byTactic;
    }
    
    public function addCustomMapping($keyword, $techniqueId, $techniqueName, $tactic) {
        if (!isset($this->mappingRules['keyword_mappings'][$keyword])) {
            $this->mappingRules['keyword_mappings'][$keyword] = [];
        }
        
        $this->mappingRules['keyword_mappings'][$keyword][] = [
            'id' => $techniqueId,
            'name' => $techniqueName,
            'tactic' => $tactic
        ];
        
        $this->saveMappingRules();
        
        return true;
    }
    
    public function getKillChainPhase($tactic) {
        $killChainMap = [
            'reconnaissance' => 1,
            'resource-development' => 2,
            'initial-access' => 3,
            'execution' => 4,
            'persistence' => 5,
            'privilege-escalation' => 6,
            'defense-evasion' => 7,
            'credential-access' => 8,
            'discovery' => 9,
            'lateral-movement' => 10,
            'collection' => 11,
            'command-and-control' => 12,
            'exfiltration' => 13,
            'impact' => 14
        ];
        
        return $killChainMap[$tactic] ?? 0;
    }
    
    public function generateAttackNarrative($finding) {
        $techniques = $this->mapFindingToMITRE($finding);
        
        if (empty($techniques)) {
            return "No MITRE ATT&CK techniques identified for this finding.";
        }
        
        usort($techniques, function($a, $b) {
            return $this->getKillChainPhase($a['tactic']) <=> 
                   $this->getKillChainPhase($b['tactic']);
        });
        
        $narrative = "Attack Analysis:\n\n";
        
        foreach ($techniques as $tech) {
            $narrative .= "• {$tech['name']} ({$tech['id']}) - {$tech['tactic']}\n";
        }
        
        return $narrative;
    }
}
