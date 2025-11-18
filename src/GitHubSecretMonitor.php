<?php

class GitHubSecretMonitor {
    private $token;
    private $organizations;
    private $repositories;
    private $db;
    private $apiBase = 'https://api.github.com';
    
    public function __construct($token, $config, $db) {
        $this->token = $token;
        $this->organizations = $config['organizations'] ?? [];
        $this->repositories = $config['repositories'] ?? [];
        $this->db = $db;
    }
    
    public function scan() {
        if (empty($this->token)) {
            error_log("GitHub token not configured");
            return [];
        }
        
        $findings = [];
        
        foreach ($this->organizations as $org) {
            $findings = array_merge($findings, $this->scanOrganization($org));
        }
        
        foreach ($this->repositories as $repo) {
            $findings = array_merge($findings, $this->scanRepository($repo));
        }
        
        return $findings;
    }
    
    private function scanOrganization($org) {
        $findings = [];
        $url = "{$this->apiBase}/orgs/{$org}/secret-scanning/alerts?state=open";
        
        $alerts = $this->makeApiRequest($url);
        if (!$alerts) return $findings;
        
        foreach ($alerts as $alert) {
            $findings[] = $this->convertAlertToFinding($alert, "Organization: {$org}");
        }
        
        return $findings;
    }
    
    private function scanRepository($repoPath) {
        $findings = [];
        $url = "{$this->apiBase}/repos/{$repoPath}/secret-scanning/alerts?state=open";
        
        $alerts = $this->makeApiRequest($url);
        if (!$alerts) return $findings;
        
        foreach ($alerts as $alert) {
            $findings[] = $this->convertAlertToFinding($alert, "Repository: {$repoPath}");
        }
        
        return $findings;
    }
    
    private function convertAlertToFinding($alert, $source) {
        $severity = $this->determineSeverity($alert);
        
        return [
            'source' => 'GitHub Secret Scanning',
            'url' => $alert['html_url'] ?? '',
            'title' => "Exposed {$alert['secret_type_display_name']} in {$source}",
            'content' => json_encode([
                'secret_type' => $alert['secret_type_display_name'] ?? 'Unknown',
                'state' => $alert['state'] ?? 'open',
                'created_at' => $alert['created_at'] ?? '',
                'publicly_leaked' => $alert['publicly_leaked'] ?? false,
                'multi_repo' => $alert['multi_repo'] ?? false
            ], JSON_PRETTY_PRINT),
            'keywords' => [$alert['secret_type'] ?? 'secret', 'github', 'exposed'],
            'severity' => $severity,
            'iocs' => [
                'secrets' => [$alert['secret_type_display_name'] ?? 'Unknown'],
                'urls' => [$alert['html_url'] ?? '']
            ],
            'metadata' => [
                'alert_number' => $alert['number'] ?? 0,
                'github_alert_id' => $alert['number'] ?? 0,
                'validity' => $alert['validity'] ?? 'unknown',
                'resolution' => $alert['resolution'] ?? null
            ]
        ];
    }
    
    private function determineSeverity($alert) {
        if ($alert['publicly_leaked'] ?? false) {
            return 'CRITICAL';
        }
        
        if ($alert['multi_repo'] ?? false) {
            return 'HIGH';
        }
        
        $criticalSecrets = [
            'aws_access_key_id',
            'aws_secret_access_key',
            'azure_storage_account_key',
            'google_cloud_private_key',
            'private_key'
        ];
        
        if (in_array($alert['secret_type'] ?? '', $criticalSecrets)) {
            return 'HIGH';
        }
        
        return 'MEDIUM';
    }
    
    private function makeApiRequest($url) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/vnd.github+json',
            'Authorization: Bearer ' . $this->token,
            'X-GitHub-Api-Version: 2022-11-28',
            'User-Agent: Security-Monitor/1.0'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200 || !$response) {
            error_log("GitHub API error: HTTP $httpCode for $url");
            return null;
        }
        
        return json_decode($response, true);
    }
    
    public function getStatus() {
        return [
            'enabled' => !empty($this->token),
            'organizations_monitored' => count($this->organizations),
            'repositories_monitored' => count($this->repositories),
            'api_endpoint' => $this->apiBase
        ];
    }
}
