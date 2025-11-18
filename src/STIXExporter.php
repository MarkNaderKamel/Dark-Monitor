<?php

class STIXExporter {
    private $db;
    
    public function __construct($db) {
        $this->db = $db;
    }
    
    public function exportFindings($findingIds = [], $format = 'json') {
        if (empty($findingIds)) {
            $stmt = $this->db->query("SELECT * FROM findings ORDER BY created_at DESC LIMIT 100");
            $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } else {
            $placeholders = implode(',', array_fill(0, count($findingIds), '?'));
            $stmt = $this->db->prepare("SELECT * FROM findings WHERE id IN ($placeholders)");
            $stmt->execute($findingIds);
            $findings = $stmt->fetchAll(PDO::FETCH_ASSOC);
        }
        
        $stixBundle = $this->createSTIXBundle($findings);
        
        if ($format === 'json') {
            return json_encode($stixBundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        }
        
        return $stixBundle;
    }
    
    private function createSTIXBundle($findings) {
        $objects = [];
        
        foreach ($findings as $finding) {
            $objects = array_merge($objects, $this->convertFindingToSTIX($finding));
        }
        
        return [
            'type' => 'bundle',
            'id' => 'bundle--' . $this->generateUUID(),
            'spec_version' => '2.1',
            'objects' => $objects
        ];
    }
    
    private function convertFindingToSTIX($finding) {
        $objects = [];
        $timestamp = $this->formatTimestamp($finding['created_at']);
        
        $observedData = [
            'type' => 'observed-data',
            'spec_version' => '2.1',
            'id' => 'observed-data--' . $this->generateUUID(),
            'created' => $timestamp,
            'modified' => $timestamp,
            'first_observed' => $timestamp,
            'last_observed' => $timestamp,
            'number_observed' => 1,
            'objects' => $this->createObservables($finding)
        ];
        
        $objects[] = $observedData;
        
        $iocs = is_string($finding['iocs']) ? json_decode($finding['iocs'], true) : ($finding['iocs'] ?? []);
        if (is_array($iocs)) {
            foreach ($this->createIndicators($finding, $iocs, $timestamp) as $indicator) {
                $objects[] = $indicator;
            }
        }
        
        if (!empty($finding['metadata'])) {
            $metadata = is_string($finding['metadata']) ? json_decode($finding['metadata'], true) : $finding['metadata'];
            if (isset($metadata['mitre_techniques'])) {
                foreach ($metadata['mitre_techniques'] as $technique) {
                    $objects[] = $this->createAttackPattern($technique, $timestamp);
                }
            }
        }
        
        $sighting = [
            'type' => 'sighting',
            'spec_version' => '2.1',
            'id' => 'sighting--' . $this->generateUUID(),
            'created' => $timestamp,
            'modified' => $timestamp,
            'sighting_of_ref' => $observedData['id'],
            'count' => 1,
            'summary' => true
        ];
        
        $objects[] = $sighting;
        
        return $objects;
    }
    
    private function createObservables($finding) {
        $observables = [];
        $index = 0;
        
        $iocs = is_string($finding['iocs']) ? json_decode($finding['iocs'], true) : ($finding['iocs'] ?? []);
        if (!is_array($iocs)) {
            return $observables;
        }
        
        if (!empty($iocs['ips'])) {
            foreach (array_slice($iocs['ips'], 0, 50) as $ip) {
                $observables[(string)$index] = [
                    'type' => 'ipv4-addr',
                    'value' => $ip
                ];
                $index++;
            }
        }
        
        if (!empty($iocs['domains'])) {
            foreach (array_slice($iocs['domains'], 0, 50) as $domain) {
                $observables[(string)$index] = [
                    'type' => 'domain-name',
                    'value' => $domain
                ];
                $index++;
            }
        }
        
        if (!empty($iocs['urls'])) {
            foreach (array_slice($iocs['urls'], 0, 50) as $url) {
                $observables[(string)$index] = [
                    'type' => 'url',
                    'value' => $url
                ];
                $index++;
            }
        }
        
        if (!empty($iocs['emails'])) {
            foreach (array_slice($iocs['emails'], 0, 50) as $email) {
                $observables[(string)$index] = [
                    'type' => 'email-addr',
                    'value' => $email
                ];
                $index++;
            }
        }
        
        if (!empty($iocs['hashes'])) {
            foreach (array_slice($iocs['hashes'], 0, 50) as $hash) {
                $hashType = $this->detectHashType($hash);
                $observables[(string)$index] = [
                    'type' => 'file',
                    'hashes' => [
                        $hashType => strtolower($hash)
                    ]
                ];
                $index++;
            }
        }
        
        return $observables;
    }
    
    private function createIndicators($finding, $iocs, $timestamp) {
        $indicators = [];
        
        if (!empty($iocs['ips'])) {
            foreach (array_slice($iocs['ips'], 0, 20) as $ip) {
                $indicators[] = [
                    'type' => 'indicator',
                    'spec_version' => '2.1',
                    'id' => 'indicator--' . $this->generateUUID(),
                    'created' => $timestamp,
                    'modified' => $timestamp,
                    'name' => "Malicious IP: $ip",
                    'description' => "IP address found in: {$finding['title']}",
                    'pattern' => "[ipv4-addr:value = '$ip']",
                    'pattern_type' => 'stix',
                    'valid_from' => $timestamp,
                    'indicator_types' => ['malicious-activity']
                ];
            }
        }
        
        if (!empty($iocs['domains'])) {
            foreach (array_slice($iocs['domains'], 0, 20) as $domain) {
                $indicators[] = [
                    'type' => 'indicator',
                    'spec_version' => '2.1',
                    'id' => 'indicator--' . $this->generateUUID(),
                    'created' => $timestamp,
                    'modified' => $timestamp,
                    'name' => "Suspicious Domain: $domain",
                    'description' => "Domain found in: {$finding['title']}",
                    'pattern' => "[domain-name:value = '$domain']",
                    'pattern_type' => 'stix',
                    'valid_from' => $timestamp,
                    'indicator_types' => ['malicious-activity']
                ];
            }
        }
        
        if (!empty($iocs['hashes'])) {
            foreach (array_slice($iocs['hashes'], 0, 20) as $hash) {
                $hashType = $this->detectHashType($hash);
                $indicators[] = [
                    'type' => 'indicator',
                    'spec_version' => '2.1',
                    'id' => 'indicator--' . $this->generateUUID(),
                    'created' => $timestamp,
                    'modified' => $timestamp,
                    'name' => "Malicious File Hash",
                    'description' => "File hash found in: {$finding['title']}",
                    'pattern' => "[file:hashes.$hashType = '" . strtolower($hash) . "']",
                    'pattern_type' => 'stix',
                    'valid_from' => $timestamp,
                    'indicator_types' => ['malicious-activity']
                ];
            }
        }
        
        return $indicators;
    }
    
    private function createAttackPattern($technique, $timestamp) {
        return [
            'type' => 'attack-pattern',
            'spec_version' => '2.1',
            'id' => 'attack-pattern--' . $this->generateUUID(),
            'created' => $timestamp,
            'modified' => $timestamp,
            'name' => $technique['name'] ?? 'Unknown Technique',
            'external_references' => [
                [
                    'source_name' => 'mitre-attack',
                    'external_id' => $technique['id'] ?? '',
                    'url' => "https://attack.mitre.org/techniques/{$technique['id']}/"
                ]
            ]
        ];
    }
    
    private function detectHashType($hash) {
        $length = strlen($hash);
        
        if ($length === 32) return 'MD5';
        if ($length === 40) return 'SHA-1';
        if ($length === 64) return 'SHA-256';
        
        return 'Unknown';
    }
    
    private function generateUUID() {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }
    
    private function formatTimestamp($datetime) {
        if (empty($datetime)) {
            return gmdate('Y-m-d\TH:i:s.000\Z');
        }
        
        $timestamp = strtotime($datetime);
        if ($timestamp === false) {
            return gmdate('Y-m-d\TH:i:s.000\Z');
        }
        
        return gmdate('Y-m-d\TH:i:s.000\Z', $timestamp);
    }
    
    public function validateSTIX($stixData) {
        if (is_string($stixData)) {
            $stixData = json_decode($stixData, true);
        }
        
        $errors = [];
        
        if (!isset($stixData['type']) || $stixData['type'] !== 'bundle') {
            $errors[] = "Root object must be a bundle";
        }
        
        if (!isset($stixData['spec_version']) || $stixData['spec_version'] !== '2.1') {
            $errors[] = "Spec version must be 2.1";
        }
        
        if (!isset($stixData['objects']) || !is_array($stixData['objects'])) {
            $errors[] = "Bundle must contain objects array";
        }
        
        if (empty($errors)) {
            foreach ($stixData['objects'] as $index => $object) {
                if (!isset($object['type'])) {
                    $errors[] = "Object $index missing type field";
                }
                if (!isset($object['id'])) {
                    $errors[] = "Object $index missing id field";
                }
            }
        }
        
        return [
            'valid' => empty($errors),
            'errors' => $errors
        ];
    }
}
