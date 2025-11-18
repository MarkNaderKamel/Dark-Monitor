<?php

class EnhancedSTIXExporter {
    private $config;
    private $logger;
    private $db;
    private $producer;
    private $tlp;

    public function __construct($config, $logger, $db) {
        $this->config = $config['stix'] ?? [];
        $this->logger = $logger;
        $this->db = $db;
        $this->producer = $this->config['producer'] ?? 'Security Monitoring System';
        $this->tlp = $this->config['tlp'] ?? 'amber';
    }

    public function exportFindings($findings, $includeIOCs = true) {
        $bundle = [
            'type' => 'bundle',
            'id' => 'bundle--' . $this->generateUUID(),
            'spec_version' => '2.1',
            'objects' => []
        ];

        $identity = $this->createIdentity();
        $bundle['objects'][] = $identity;

        foreach ($findings as $finding) {
            $indicator = $this->createIndicator($finding, $identity['id']);
            if ($indicator) {
                $bundle['objects'][] = $indicator;
            }

            $observedData = $this->createObservedData($finding, $identity['id']);
            if ($observedData) {
                $bundle['objects'][] = $observedData;
            }

            if ($includeIOCs && isset($finding['iocs'])) {
                $iocObjects = $this->createIOCObjects($finding['iocs'], $identity['id']);
                $bundle['objects'] = array_merge($bundle['objects'], $iocObjects);
            }

            if (isset($finding['mitre_techniques'])) {
                $attackPatterns = $this->createAttackPatterns($finding['mitre_techniques'], $identity['id']);
                $bundle['objects'] = array_merge($bundle['objects'], $attackPatterns);
            }
        }

        $marking = $this->createTLPMarking();
        $bundle['objects'][] = $marking;

        return json_encode($bundle, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    private function createIdentity() {
        return [
            'type' => 'identity',
            'spec_version' => '2.1',
            'id' => 'identity--' . $this->generateUUID(),
            'created' => $this->getCurrentTimestamp(),
            'modified' => $this->getCurrentTimestamp(),
            'name' => $this->producer,
            'identity_class' => 'system',
        ];
    }

    private function createIndicator($finding, $identityId) {
        if (empty($finding['snippet']) && empty($finding['url'])) {
            return null;
        }

        $patterns = [];
        
        if (isset($finding['iocs']['ips'])) {
            foreach ($finding['iocs']['ips'] as $ip) {
                $patterns[] = "[ipv4-addr:value = '$ip']";
            }
        }

        if (isset($finding['iocs']['domains'])) {
            foreach ($finding['iocs']['domains'] as $domain) {
                $patterns[] = "[domain-name:value = '$domain']";
            }
        }

        if (isset($finding['iocs']['urls'])) {
            foreach ($finding['iocs']['urls'] as $url) {
                $patterns[] = "[url:value = '$url']";
            }
        }

        if (isset($finding['iocs']['hashes'])) {
            foreach ($finding['iocs']['hashes'] as $hash) {
                $hashType = $this->detectHashType($hash);
                $patterns[] = "[file:hashes.$hashType = '$hash']";
            }
        }

        if (empty($patterns)) {
            $patterns[] = "[x-custom:description = '" . addslashes($finding['snippet'] ?? '') . "']";
        }

        $pattern = implode(' OR ', $patterns);

        $indicator = [
            'type' => 'indicator',
            'spec_version' => '2.1',
            'id' => 'indicator--' . $this->generateUUID(),
            'created' => $this->parseTimestamp($finding['timestamp'] ?? date('Y-m-d H:i:s')),
            'modified' => $this->getCurrentTimestamp(),
            'name' => $finding['title'] ?? 'Security Finding',
            'description' => $finding['snippet'] ?? '',
            'pattern' => $pattern,
            'pattern_type' => 'stix',
            'valid_from' => $this->parseTimestamp($finding['timestamp'] ?? date('Y-m-d H:i:s')),
            'created_by_ref' => $identityId,
        ];

        if (isset($finding['keywords']) && !empty($finding['keywords'])) {
            $indicator['labels'] = array_map(function($k) {
                return strtolower(str_replace(' ', '-', $k));
            }, $finding['keywords']);
        }

        if (isset($finding['severity'])) {
            $indicator['x_severity'] = $finding['severity'];
        }

        if (isset($finding['source'])) {
            $indicator['x_source'] = $finding['source'];
        }

        return $indicator;
    }

    private function createObservedData($finding, $identityId) {
        $objects = [];
        $objectIndex = 0;

        if (isset($finding['iocs']['ips'])) {
            foreach ($finding['iocs']['ips'] as $ip) {
                $objects[(string)$objectIndex] = [
                    'type' => 'ipv4-addr',
                    'value' => $ip
                ];
                $objectIndex++;
            }
        }

        if (isset($finding['iocs']['domains'])) {
            foreach ($finding['iocs']['domains'] as $domain) {
                $objects[(string)$objectIndex] = [
                    'type' => 'domain-name',
                    'value' => $domain
                ];
                $objectIndex++;
            }
        }

        if (isset($finding['iocs']['urls'])) {
            foreach ($finding['iocs']['urls'] as $url) {
                $objects[(string)$objectIndex] = [
                    'type' => 'url',
                    'value' => $url
                ];
                $objectIndex++;
            }
        }

        if (isset($finding['iocs']['emails'])) {
            foreach ($finding['iocs']['emails'] as $email) {
                $objects[(string)$objectIndex] = [
                    'type' => 'email-addr',
                    'value' => $email
                ];
                $objectIndex++;
            }
        }

        if (empty($objects)) {
            return null;
        }

        return [
            'type' => 'observed-data',
            'spec_version' => '2.1',
            'id' => 'observed-data--' . $this->generateUUID(),
            'created' => $this->parseTimestamp($finding['timestamp'] ?? date('Y-m-d H:i:s')),
            'modified' => $this->getCurrentTimestamp(),
            'first_observed' => $this->parseTimestamp($finding['timestamp'] ?? date('Y-m-d H:i:s')),
            'last_observed' => $this->parseTimestamp($finding['timestamp'] ?? date('Y-m-d H:i:s')),
            'number_observed' => 1,
            'objects' => $objects,
            'created_by_ref' => $identityId,
        ];
    }

    private function createIOCObjects($iocs, $identityId) {
        $objects = [];

        if (isset($iocs['hashes'])) {
            foreach ($iocs['hashes'] as $hash) {
                $hashType = $this->detectHashType($hash);
                $objects[] = [
                    'type' => 'file',
                    'spec_version' => '2.1',
                    'id' => 'file--' . $this->generateUUID(),
                    'hashes' => [
                        $hashType => $hash
                    ]
                ];
            }
        }

        return $objects;
    }

    private function createAttackPatterns($techniques, $identityId) {
        $patterns = [];

        foreach ($techniques as $technique) {
            $patterns[] = [
                'type' => 'attack-pattern',
                'spec_version' => '2.1',
                'id' => 'attack-pattern--' . $this->generateUUID(),
                'created' => $this->getCurrentTimestamp(),
                'modified' => $this->getCurrentTimestamp(),
                'name' => $technique['name'] ?? 'Unknown Technique',
                'external_references' => [
                    [
                        'source_name' => 'mitre-attack',
                        'external_id' => $technique['id'] ?? '',
                        'url' => 'https://attack.mitre.org/techniques/' . ($technique['id'] ?? '')
                    ]
                ],
                'created_by_ref' => $identityId,
            ];
        }

        return $patterns;
    }

    private function createTLPMarking() {
        $tlpMap = [
            'white' => 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
            'green' => 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
            'amber' => 'marking-definition--f88d31f6-486f-44da-b317-01333bde0b82',
            'red' => 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
        ];

        $markingId = $tlpMap[$this->tlp] ?? $tlpMap['amber'];

        return [
            'type' => 'marking-definition',
            'spec_version' => '2.1',
            'id' => $markingId,
            'created' => '2017-01-20T00:00:00.000Z',
            'definition_type' => 'tlp',
            'name' => 'TLP:' . strtoupper($this->tlp),
            'definition' => [
                'tlp' => $this->tlp
            ]
        ];
    }

    private function detectHashType($hash) {
        $len = strlen($hash);
        switch ($len) {
            case 32:
                return 'MD5';
            case 40:
                return 'SHA-1';
            case 64:
                return 'SHA-256';
            case 128:
                return 'SHA-512';
            default:
                return 'UNKNOWN';
        }
    }

    private function generateUUID() {
        return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            mt_rand(0, 0xffff), mt_rand(0, 0xffff),
            mt_rand(0, 0xffff),
            mt_rand(0, 0x0fff) | 0x4000,
            mt_rand(0, 0x3fff) | 0x8000,
            mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
        );
    }

    private function getCurrentTimestamp() {
        return gmdate('Y-m-d\TH:i:s.000\Z');
    }

    private function parseTimestamp($timestamp) {
        $dt = new DateTime($timestamp, new DateTimeZone('UTC'));
        return $dt->format('Y-m-d\TH:i:s.000\Z');
    }

    public function exportToFile($findings, $filename) {
        $stixData = $this->exportFindings($findings);
        
        $exportDir = $this->config['export_dir'] ?? __DIR__ . '/../exports';
        if (!is_dir($exportDir)) {
            mkdir($exportDir, 0755, true);
        }

        $filepath = $exportDir . '/' . $filename;
        file_put_contents($filepath, $stixData);

        $this->logger->info('STIX', "Exported " . count($findings) . " findings to $filepath");
        
        return $filepath;
    }
}
