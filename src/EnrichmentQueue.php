<?php

require_once __DIR__ . '/VirusTotalEnricher.php';
require_once __DIR__ . '/AbuseIPDBEnricher.php';
require_once __DIR__ . '/ShodanEnricher.php';

class EnrichmentQueue {
    private $db;
    private $config;
    private $logger;
    private $enrichers = [];
    private $cache = [];
    private $cacheFile;
    
    public function __construct($db, $config, $logger) {
        $this->db = $db;
        $this->config = $config;
        $this->logger = $logger;
        $this->cacheFile = __DIR__ . '/../data/enrichment_cache.json';
        $this->loadCache();
        $this->initializeEnrichers();
    }
    
    private function loadCache() {
        if (file_exists($this->cacheFile)) {
            $this->cache = json_decode(file_get_contents($this->cacheFile), true) ?? [];
        }
    }
    
    private function saveCache() {
        file_put_contents($this->cacheFile, json_encode($this->cache));
    }
    
    private function initializeEnrichers() {
        if ($this->config['enrichment']['apis']['virustotal']['enabled'] ?? false) {
            require_once __DIR__ . '/VirusTotalEnricher.php';
            $dbManager = new DatabaseManager($this->config, $this->logger);
            $this->enrichers['virustotal'] = new VirusTotalEnricher($this->config, $this->logger, $dbManager);
        }
        
        if ($this->config['enrichment']['apis']['abuseipdb']['enabled'] ?? false) {
            $this->enrichers['abuseipdb'] = new AbuseIPDBEnricher($this->config, $this->logger);
        }
        
        if ($this->config['enrichment']['apis']['shodan']['enabled'] ?? false) {
            $this->enrichers['shodan'] = new ShodanEnricher($this->config, $this->logger);
        }
    }
    
    public function enqueueEnrichment($findingId, $iocs) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO enrichment_queue (finding_id, iocs, status, created_at)
                VALUES (:finding_id, :iocs, 'pending', datetime('now'))
            ");
            
            $stmt->execute([
                'finding_id' => $findingId,
                'iocs' => json_encode($iocs)
            ]);
            
            return true;
        } catch (Exception $e) {
            error_log("Failed to enqueue enrichment: " . $e->getMessage());
            return false;
        }
    }
    
    public function processQueue($batchSize = 10) {
        $stmt = $this->db->prepare("
            SELECT * FROM enrichment_queue
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT :limit
        ");
        $stmt->execute(['limit' => $batchSize]);
        $jobs = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        foreach ($jobs as $job) {
            $this->processJob($job);
        }
        
        $this->saveCache();
        
        return count($jobs);
    }
    
    private function processJob($job) {
        $this->updateJobStatus($job['id'], 'processing');
        
        try {
            $iocs = json_decode($job['iocs'], true) ?? [];
            $enrichedData = $this->enrichIOCs($iocs);
            
            $this->updateFindingEnrichment($job['finding_id'], $enrichedData);
            
            $this->updateJobStatus($job['id'], 'completed');
            
        } catch (Exception $e) {
            error_log("Enrichment job {$job['id']} failed: " . $e->getMessage());
            $this->updateJobStatus($job['id'], 'failed', $e->getMessage());
        }
    }
    
    private function enrichIOCs($iocs) {
        $enriched = [];
        
        if (!empty($iocs['ips'])) {
            $enriched['ips'] = [];
            foreach (array_slice($iocs['ips'], 0, 20) as $ip) {
                $enriched['ips'][$ip] = $this->enrichIP($ip);
            }
        }
        
        if (!empty($iocs['domains'])) {
            $enriched['domains'] = [];
            foreach (array_slice($iocs['domains'], 0, 20) as $domain) {
                $enriched['domains'][$domain] = $this->enrichDomain($domain);
            }
        }
        
        if (!empty($iocs['hashes'])) {
            $enriched['hashes'] = [];
            foreach (array_slice($iocs['hashes'], 0, 20) as $hash) {
                $enriched['hashes'][$hash] = $this->enrichHash($hash);
            }
        }
        
        return $enriched;
    }
    
    private function enrichIP($ip) {
        $cacheKey = "ip:$ip";
        
        if (isset($this->cache[$cacheKey])) {
            $cached = $this->cache[$cacheKey];
            if (time() - $cached['timestamp'] < 86400) {
                return $cached['data'];
            }
        }
        
        $data = [
            'ip' => $ip,
            'reputation_score' => 0,
            'sources' => []
        ];
        
        if (isset($this->enrichers['abuseipdb'])) {
            try {
                $abuseData = $this->enrichers['abuseipdb']->checkIP($ip);
                $data['sources']['abuseipdb'] = $abuseData;
                $data['reputation_score'] = max($data['reputation_score'], $abuseData['abuse_confidence_score'] ?? 0);
            } catch (Exception $e) {
                error_log("AbuseIPDB enrichment failed for $ip: " . $e->getMessage());
            }
            
            sleep(1);
        }
        
        if (isset($this->enrichers['virustotal'])) {
            try {
                $vtData = $this->enrichers['virustotal']->checkIP($ip);
                $data['sources']['virustotal'] = $vtData;
                if (isset($vtData['malicious'])) {
                    $vtScore = ($vtData['malicious'] * 10) + ($vtData['suspicious'] ?? 0) * 5;
                    $data['reputation_score'] = max($data['reputation_score'], min($vtScore, 100));
                }
            } catch (Exception $e) {
                error_log("VirusTotal enrichment failed for $ip: " . $e->getMessage());
            }
            
            sleep(15);
        }
        
        if (isset($this->enrichers['shodan'])) {
            try {
                $shodanData = $this->enrichers['shodan']->checkIP($ip);
                $data['sources']['shodan'] = $shodanData;
            } catch (Exception $e) {
                error_log("Shodan enrichment failed for $ip: " . $e->getMessage());
            }
            
            sleep(1);
        }
        
        $this->cache[$cacheKey] = [
            'timestamp' => time(),
            'data' => $data
        ];
        
        return $data;
    }
    
    private function enrichDomain($domain) {
        $cacheKey = "domain:$domain";
        
        if (isset($this->cache[$cacheKey])) {
            $cached = $this->cache[$cacheKey];
            if (time() - $cached['timestamp'] < 86400) {
                return $cached['data'];
            }
        }
        
        $data = [
            'domain' => $domain,
            'reputation_score' => 0,
            'sources' => []
        ];
        
        if (isset($this->enrichers['virustotal'])) {
            try {
                $vtData = $this->enrichers['virustotal']->checkDomain($domain);
                $data['sources']['virustotal'] = $vtData;
                if (isset($vtData['malicious'])) {
                    $vtScore = ($vtData['malicious'] * 10) + ($vtData['suspicious'] ?? 0) * 5;
                    $data['reputation_score'] = max($data['reputation_score'], min($vtScore, 100));
                }
            } catch (Exception $e) {
                error_log("VirusTotal enrichment failed for $domain: " . $e->getMessage());
            }
            
            sleep(15);
        }
        
        $this->cache[$cacheKey] = [
            'timestamp' => time(),
            'data' => $data
        ];
        
        return $data;
    }
    
    private function enrichHash($hash) {
        $cacheKey = "hash:$hash";
        
        if (isset($this->cache[$cacheKey])) {
            $cached = $this->cache[$cacheKey];
            if (time() - $cached['timestamp'] < 86400) {
                return $cached['data'];
            }
        }
        
        $data = [
            'hash' => $hash,
            'malicious' => false,
            'sources' => []
        ];
        
        if (isset($this->enrichers['virustotal'])) {
            try {
                $vtData = $this->enrichers['virustotal']->checkHash($hash);
                $data['sources']['virustotal'] = $vtData;
                if (isset($vtData['positives']) && $vtData['positives'] > 0) {
                    $data['malicious'] = true;
                }
            } catch (Exception $e) {
                error_log("VirusTotal enrichment failed for $hash: " . $e->getMessage());
            }
            
            sleep(15);
        }
        
        $this->cache[$cacheKey] = [
            'timestamp' => time(),
            'data' => $data
        ];
        
        return $data;
    }
    
    private function updateJobStatus($jobId, $status, $error = null) {
        $stmt = $this->db->prepare("
            UPDATE enrichment_queue
            SET status = :status, error = :error, updated_at = datetime('now')
            WHERE id = :id
        ");
        
        $stmt->execute([
            'id' => $jobId,
            'status' => $status,
            'error' => $error
        ]);
    }
    
    private function updateFindingEnrichment($findingId, $enrichedData) {
        $stmt = $this->db->prepare("
            SELECT metadata FROM findings WHERE id = :id
        ");
        $stmt->execute(['id' => $findingId]);
        $finding = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$finding) return;
        
        $metadata = is_string($finding['metadata']) ? 
            json_decode($finding['metadata'], true) : 
            ($finding['metadata'] ?? []);
        
        if (!is_array($metadata)) {
            $metadata = [];
        }
        
        $metadata['enrichment'] = $enrichedData;
        $metadata['enriched_at'] = date('Y-m-d H:i:s');
        
        $updateStmt = $this->db->prepare("
            UPDATE findings
            SET metadata = :metadata
            WHERE id = :id
        ");
        
        $updateStmt->execute([
            'id' => $findingId,
            'metadata' => json_encode($metadata)
        ]);
    }
    
    public function getQueueStats() {
        $stats = [];
        
        $stmt = $this->db->query("
            SELECT status, COUNT(*) as count
            FROM enrichment_queue
            GROUP BY status
        ");
        
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $stats[$row['status']] = $row['count'];
        }
        
        return $stats;
    }
}
