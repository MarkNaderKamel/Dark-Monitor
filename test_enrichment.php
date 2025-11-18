<?php

require_once 'config.php';
require_once 'src/Logger.php';
require_once 'src/DatabaseManager.php';
require_once 'src/IOCExtractor.php';
require_once 'src/VirusTotalEnricher.php';
require_once 'src/AbuseIPDBEnricher.php';
require_once 'src/ShodanEnricher.php';
require_once 'src/AlienVaultOTXEnricher.php';
require_once 'src/ThreatFoxEnricher.php';
require_once 'src/URLhausEnricher.php';
require_once 'src/GreyNoiseEnricher.php';
require_once 'src/PhishTankEnricher.php';
require_once 'src/PulsediveEnricher.php';

echo "============================================\n";
echo "  Threat Intelligence Enrichment Test\n";
echo "============================================\n\n";

$config = require 'config.php';
$logger = new Logger($config);
$db = new DatabaseManager($config, $logger);

$services = [
    'VirusTotal' => new VirusTotalEnricher($config, $logger, $db),
    'AbuseIPDB' => new AbuseIPDBEnricher($config, $logger),
    'Shodan' => new ShodanEnricher($config, $logger),
    'AlienVault OTX' => new AlienVaultOTXEnricher($config, $logger, $db),
    'ThreatFox' => new ThreatFoxEnricher($logger, $db),
    'URLhaus' => new URLhausEnricher($logger, $db),
    'GreyNoise' => new GreyNoiseEnricher($config, $logger, $db),
    'PhishTank' => new PhishTankEnricher($config, $logger, $db),
    'Pulsedive' => new PulsediveEnricher($config, $logger, $db),
];

echo "Service Status:\n";
echo "===============\n";

$enabledCount = 0;
foreach ($services as $name => $service) {
    $status = $service->isEnabled() ? '✓ ENABLED' : '✗ DISABLED';
    $color = $service->isEnabled() ? "\033[32m" : "\033[31m";
    echo $color . sprintf("%-20s %s\033[0m\n", $name . ':', $status);
    
    if ($service->isEnabled()) {
        $enabledCount++;
    }
}

echo "\nSummary: $enabledCount out of " . count($services) . " services enabled\n\n";

echo "============================================\n";
echo "  IOC Extraction Test\n";
echo "============================================\n\n";

$testText = "
Security alert! Found suspicious activity from IP 192.0.2.1 and domain evil.com
Malicious URL: hxxp://phishing[.]example[.]com/login
File hash detected: d41d8cd98f00b204e9800998ecf8427e
CVE-2024-1234 vulnerability exploited
Bitcoin wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Email: attacker@malware.net
";

$iocExtractor = new IOCExtractor($logger);
$iocs = $iocExtractor->extract($testText);

echo "Extracted IOCs from test text:\n";
foreach ($iocs as $type => $values) {
    echo "  $type: " . count($values) . " found\n";
    foreach ($values as $value) {
        echo "    - $value\n";
    }
}

echo "\n";

echo "============================================\n";
echo "  Testing API Endpoints (Safe IP: 8.8.8.8)\n";
echo "============================================\n\n";

$testIP = '8.8.8.8';

if ($services['VirusTotal']->isEnabled()) {
    echo "\033[34mTesting VirusTotal...\033[0m\n";
    $result = $services['VirusTotal']->enrichIP($testIP);
    if ($result) {
        echo "  ✓ Success: Malicious: " . ($result['malicious'] ?? 0) . ", Reputation: " . ($result['reputation'] ?? 'N/A') . "\n";
    } else {
        echo "  ✗ No data returned\n";
    }
    echo "\n";
}

if ($services['AbuseIPDB']->isEnabled()) {
    echo "\033[34mTesting AbuseIPDB...\033[0m\n";
    $result = $services['AbuseIPDB']->checkIP($testIP);
    if ($result) {
        echo "  ✓ Success: Abuse Score: " . ($result['abuse_confidence_score'] ?? 0) . ", ISP: " . ($result['isp'] ?? 'N/A') . "\n";
    } else {
        echo "  ✗ No data returned\n";
    }
    echo "\n";
}

if ($services['AlienVault OTX']->isEnabled()) {
    echo "\033[34mTesting AlienVault OTX...\033[0m\n";
    $result = $services['AlienVault OTX']->enrichIP($testIP);
    if ($result) {
        echo "  ✓ Success: Pulse Count: " . ($result['pulse_count'] ?? 0) . "\n";
    } else {
        echo "  ✗ No data returned\n";
    }
    echo "\n";
}

echo "\033[34mTesting ThreatFox (no key needed)...\033[0m\n";
$result = $services['ThreatFox']->getRecentIOCs(5);
if ($result && !empty($result)) {
    echo "  ✓ Success: Retrieved " . count($result) . " recent IOCs\n";
} else {
    echo "  ✗ No recent IOCs or service unavailable\n";
}
echo "\n";

echo "\033[34mTesting URLhaus (no key needed)...\033[0m\n";
$result = $services['URLhaus']->lookupDomain('malware.com');
if ($result) {
    echo "  ✓ Success: URL Count: " . ($result['url_count'] ?? 0) . "\n";
} else {
    echo "  ✗ No data returned\n";
}
echo "\n";

if ($services['GreyNoise']->isEnabled()) {
    echo "\033[34mTesting GreyNoise...\033[0m\n";
    $result = $services['GreyNoise']->enrichIP($testIP);
    if ($result) {
        echo "  ✓ Success: Classification: " . ($result['classification'] ?? 'unknown') . "\n";
    } else {
        echo "  ✗ No data returned\n";
    }
    echo "\n";
} else {
    echo "\033[34mTesting GreyNoise (Community API - no key needed)...\033[0m\n";
    $result = $services['GreyNoise']->quickCheck($testIP);
    if ($result) {
        echo "  ✓ Success: Classification: " . ($result['classification'] ?? 'unknown') . "\n";
    } else {
        echo "  ✗ No data returned\n";
    }
    echo "\n";
}

echo "============================================\n";
echo "  Configuration Recommendations\n";
echo "============================================\n\n";

if ($enabledCount < 3) {
    echo "\033[33m⚠ Warning: Only $enabledCount services enabled\033[0m\n\n";
    echo "To maximize threat detection, consider adding API keys for:\n";
    
    $recommendations = [
        'VirusTotal' => 'VIRUSTOTAL_API_KEY',
        'AbuseIPDB' => 'ABUSEIPDB_API_KEY',
        'AlienVault OTX' => 'ALIENVAULT_OTX_API_KEY',
        'Pulsedive' => 'PULSEDIVE_API_KEY',
    ];
    
    foreach ($recommendations as $name => $envVar) {
        if (!$services[$name]->isEnabled()) {
            echo "  - $name: Set $envVar\n";
        }
    }
    
    echo "\nFree APIs (no key needed):\n";
    echo "  ✓ ThreatFox (already active)\n";
    echo "  ✓ URLhaus (already active)\n";
    echo "  ✓ GreyNoise Community API (already active)\n";
    
} else {
    echo "\033[32m✓ Good configuration! $enabledCount services enabled\033[0m\n";
}

echo "\n";
echo "See API_REFERENCE.md for instructions on obtaining free API keys.\n";
echo "\n";

echo "============================================\n";
echo "  Test Complete\n";
echo "============================================\n";
