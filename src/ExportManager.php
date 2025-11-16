<?php

class ExportManager {
    private $db;
    private $logger;
    private $exportDir;

    public function __construct($db, $logger, $config) {
        $this->db = $db;
        $this->logger = $logger;
        $this->exportDir = $config['storage']['export_dir'] ?? __DIR__ . '/../exports';
        
        if (!is_dir($this->exportDir)) {
            mkdir($this->exportDir, 0755, true);
        }
    }

    public function exportToCSV($filters = []) {
        $this->logger->info('EXPORT', 'Exporting findings to CSV');
        
        $findings = $this->db->getFindings($filters);
        
        $filename = $this->exportDir . '/findings_' . date('Y-m-d_His') . '.csv';
        $fp = fopen($filename, 'w');
        
        // Header
        fputcsv($fp, ['ID', 'Timestamp', 'Source', 'Title', 'URL', 'Severity', 'Threat Score', 'Keywords', 'IOCs']);
        
        // Data
        foreach ($findings as $finding) {
            fputcsv($fp, [
                $finding['id'],
                $finding['timestamp'],
                $finding['source'],
                $finding['title'],
                $finding['url'],
                $finding['severity'],
                $finding['threat_score'],
                implode(', ', json_decode($finding['keywords'], true) ?? []),
                $this->formatIOCs(json_decode($finding['iocs'], true) ?? [])
            ]);
        }
        
        fclose($fp);
        
        $this->logger->info('EXPORT', "CSV export completed: $filename");
        return $filename;
    }

    public function exportToJSON($filters = []) {
        $this->logger->info('EXPORT', 'Exporting findings to JSON');
        
        $findings = $this->db->getFindings($filters);
        
        // Parse JSON fields
        foreach ($findings as &$finding) {
            $finding['keywords'] = json_decode($finding['keywords'], true) ?? [];
            $finding['iocs'] = json_decode($finding['iocs'], true) ?? [];
        }
        
        $export = [
            'export_date' => date('Y-m-d H:i:s'),
            'total_findings' => count($findings),
            'filters' => $filters,
            'findings' => $findings
        ];
        
        $filename = $this->exportDir . '/findings_' . date('Y-m-d_His') . '.json';
        file_put_contents($filename, json_encode($export, JSON_PRETTY_PRINT));
        
        $this->logger->info('EXPORT', "JSON export completed: $filename");
        return $filename;
    }

    public function exportIOCs($filters = []) {
        $this->logger->info('EXPORT', 'Exporting IOCs');
        
        $iocs = $this->db->getIOCs(null, 10000);
        
        $filename = $this->exportDir . '/iocs_' . date('Y-m-d_His') . '.txt';
        $fp = fopen($filename, 'w');
        
        $grouped = [];
        foreach ($iocs as $ioc) {
            $type = $ioc['ioc_type'];
            if (!isset($grouped[$type])) {
                $grouped[$type] = [];
            }
            $grouped[$type][] = $ioc['ioc_value'];
        }
        
        foreach ($grouped as $type => $values) {
            fwrite($fp, "# $type\n");
            foreach (array_unique($values) as $value) {
                fwrite($fp, "$value\n");
            }
            fwrite($fp, "\n");
        }
        
        fclose($fp);
        
        $this->logger->info('EXPORT', "IOC export completed: $filename");
        return $filename;
    }

    public function exportSTIX($filters = []) {
        $this->logger->info('EXPORT', 'Exporting to STIX format');
        
        $findings = $this->db->getFindings($filters);
        $iocs = $this->db->getIOCs(null, 10000);
        
        $stix = [
            'type' => 'bundle',
            'id' => 'bundle--' . $this->generateUUID(),
            'spec_version' => '2.1',
            'objects' => []
        ];
        
        // Add indicators
        foreach ($iocs as $ioc) {
            $pattern = $this->buildSTIXPattern($ioc['ioc_type'], $ioc['ioc_value']);
            
            $stix['objects'][] = [
                'type' => 'indicator',
                'id' => 'indicator--' . $this->generateUUID(),
                'created' => date('c', strtotime($ioc['first_seen'])),
                'modified' => date('c', strtotime($ioc['last_seen'])),
                'name' => $ioc['ioc_value'],
                'pattern' => $pattern,
                'pattern_type' => 'stix',
                'valid_from' => date('c', strtotime($ioc['first_seen'])),
                'labels' => ['malicious-activity'],
                'confidence' => $ioc['confidence']
            ];
        }
        
        $filename = $this->exportDir . '/stix_' . date('Y-m-d_His') . '.json';
        file_put_contents($filename, json_encode($stix, JSON_PRETTY_PRINT));
        
        $this->logger->info('EXPORT', "STIX export completed: $filename");
        return $filename;
    }

    private function buildSTIXPattern($type, $value) {
        switch ($type) {
            case 'ips':
                return "[ipv4-addr:value = '$value']";
            case 'urls':
                return "[url:value = '$value']";
            case 'emails':
                return "[email-addr:value = '$value']";
            case 'hashes':
                $hashType = strlen($value) === 32 ? 'MD5' : (strlen($value) === 40 ? 'SHA-1' : 'SHA-256');
                return "[file:hashes.$hashType = '$value']";
            default:
                return "[x-custom:value = '$value']";
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

    private function formatIOCs($iocs) {
        $parts = [];
        foreach ($iocs as $type => $values) {
            if (is_array($values) && count($values) > 0) {
                $parts[] = "$type:" . count($values);
            }
        }
        return implode(', ', $parts);
    }

    public function getExportedFiles() {
        $files = glob($this->exportDir . '/*');
        return array_map(function($file) {
            return [
                'filename' => basename($file),
                'path' => $file,
                'size' => filesize($file),
                'created' => filemtime($file)
            ];
        }, $files);
    }
}
