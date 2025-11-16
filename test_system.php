<?php
/**
 * Comprehensive System Test
 * 
 * Tests all components of the security monitoring system
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "=== Security Monitoring System - Comprehensive Test ===\n\n";

// Load configuration
require_once __DIR__ . '/config.php';
$config = require __DIR__ . '/config.php';

// Load all classes
require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/HttpClient.php';
require_once __DIR__ . '/src/DatabaseManager.php';
require_once __DIR__ . '/src/TelegramMonitor.php';
require_once __DIR__ . '/src/WebScraper.php';
require_once __DIR__ . '/src/DarkWebMonitor.php';
require_once __DIR__ . '/src/PastebinMonitor.php';
require_once __DIR__ . '/src/RedditMonitor.php';
require_once __DIR__ . '/src/GitHubMonitor.php';
require_once __DIR__ . '/src/Notifier.php';
require_once __DIR__ . '/src/SlackNotifier.php';
require_once __DIR__ . '/src/DiscordNotifier.php';
require_once __DIR__ . '/src/ReputationScorer.php';
require_once __DIR__ . '/src/ThreatCorrelation.php';
require_once __DIR__ . '/src/SummaryReporter.php';

$passed = 0;
$failed = 0;

function test($name, $callback) {
    global $passed, $failed;
    echo "Testing: $name... ";
    try {
        $result = $callback();
        if ($result) {
            echo "✓ PASSED\n";
            $passed++;
        } else {
            echo "✗ FAILED\n";
            $failed++;
        }
    } catch (Exception $e) {
        echo "✗ FAILED: " . $e->getMessage() . "\n";
        $failed++;
    }
}

// Test 1: Configuration loaded
test("Configuration loads correctly", function() use ($config) {
    return is_array($config) && isset($config['monitoring']);
});

// Test 2: Logger initialization
test("Logger initialization", function() use ($config) {
    $logger = new Logger($config);
    return $logger !== null;
});

// Test 3: Database initialization
test("Database initialization", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    return $db !== null;
});

// Test 4: Database tables created
test("Database tables created", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    $dbInstance = $db->getDbInstance();
    
    $tables = ['findings', 'statistics', 'sessions', 'reputation_scores', 'iocs', 'threat_correlations'];
    foreach ($tables as $table) {
        $result = $dbInstance->query("SELECT name FROM sqlite_master WHERE type='table' AND name='$table'");
        $row = $result->fetchArray();
        if (!$row) {
            return false;
        }
    }
    return true;
});

// Test 5: Insert and retrieve finding
test("Insert and retrieve finding", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    
    $finding = [
        'source' => 'Test',
        'title' => 'Test Finding',
        'url' => 'https://test.com',
        'snippet' => 'Test snippet',
        'keywords' => ['test', 'finding'],
        'threat_score' => 50,
        'severity' => 'MEDIUM',
        'iocs' => []
    ];
    
    $id = $db->insertFinding($finding);
    if (!$id) return false;
    
    $findings = $db->getFindings(['limit' => 1]);
    return count($findings) > 0 && $findings[0]['title'] === 'Test Finding';
});

// Test 6: Reputation Scorer
test("Reputation scoring for IP", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    $scorer = new ReputationScorer($db, $logger, $config);
    
    $result = $scorer->scoreEntity('ip', '192.168.1.1', []);
    return isset($result['score']) && isset($result['classification']);
});

// Test 7: Reputation scoring for domain
test("Reputation scoring for domain", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    $scorer = new ReputationScorer($db, $logger, $config);
    
    $result = $scorer->scoreEntity('domain', 'example.com', []);
    return isset($result['score']) && isset($result['classification']);
});

// Test 8: Reputation scoring for malicious domain
test("Reputation scoring for suspicious domain", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    $scorer = new ReputationScorer($db, $logger, $config);
    
    $result = $scorer->scoreEntity('domain', 'phishing-login-verify123.xyz', []);
    return $result['score'] < 50;
});

// Test 9: IOC insertion
test("Insert IOC", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    
    $ioc = [
        'type' => 'ip',
        'value' => '8.8.8.8',
        'severity' => 'LOW',
        'source' => 'Test'
    ];
    
    return $db->insertIOC($ioc) !== false;
});

// Test 10: Threat correlation
test("Threat correlation calculation", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    $correlation = new ThreatCorrelation($db, $logger, $config);
    
    $finding = [
        'title' => 'Database breach with stolen credentials',
        'snippet' => 'Leaked password dump containing user accounts',
        'keywords' => ['breach', 'credentials'],
        'severity' => 'HIGH'
    ];
    
    $score = $correlation->calculateThreatScore($finding);
    return $score > 0 && $score <= 100;
});

// Test 11: HTTP Client
test("HTTP Client initialization", function() use ($config) {
    $logger = new Logger($config);
    $client = new HttpClient($config, $logger);
    return $client !== null;
});

// Test 12: Slack Notifier (configuration check)
test("Slack Notifier initialization", function() use ($config) {
    $logger = new Logger($config);
    $slack = new SlackNotifier($logger, $config);
    return $slack !== null;
});

// Test 13: Discord Notifier (configuration check)
test("Discord Notifier initialization", function() use ($config) {
    $logger = new Logger($config);
    $discord = new DiscordNotifier($logger, $config);
    return $discord !== null;
});

// Test 14: Pastebin Monitor
test("Pastebin Monitor initialization", function() use ($config) {
    $logger = new Logger($config);
    $httpClient = new HttpClient($config, $logger);
    $monitor = new PastebinMonitor($config, $logger, $httpClient);
    return $monitor !== null;
});

// Test 15: Reddit Monitor
test("Reddit Monitor initialization", function() use ($config) {
    $logger = new Logger($config);
    $httpClient = new HttpClient($config, $logger);
    $monitor = new RedditMonitor($config, $logger, $httpClient);
    return $monitor !== null;
});

// Test 16: GitHub Monitor
test("GitHub Monitor initialization", function() use ($config) {
    $logger = new Logger($config);
    $httpClient = new HttpClient($config, $logger);
    $monitor = new GitHubMonitor($config, $logger, $httpClient);
    return $monitor !== null;
});

// Test 17: Summary Reporter
test("Summary Reporter initialization", function() use ($config) {
    $logger = new Logger($config);
    $db = new DatabaseManager($config, $logger);
    $notifier = new Notifier($config, $logger);
    $reporter = new SummaryReporter($db, $logger, $config, $notifier);
    return $reporter !== null;
});

// Test 18: Dashboard API endpoint exists
test("Dashboard API file exists", function() {
    return file_exists(__DIR__ . '/dashboard_api.php');
});

// Test 19: Dashboard file exists
test("Dashboard file exists", function() {
    return file_exists(__DIR__ . '/dashboard.php');
});

// Test 20: Required directories exist
test("Required directories exist", function() use ($config) {
    $dirs = ['logs', 'data', 'cache'];
    foreach ($dirs as $dir) {
        if (!is_dir(__DIR__ . '/' . $dir)) {
            return false;
        }
    }
    return true;
});

// Print summary
echo "\n=== Test Summary ===\n";
echo "Total Tests: " . ($passed + $failed) . "\n";
echo "Passed: $passed ✓\n";
echo "Failed: $failed ✗\n";

if ($failed === 0) {
    echo "\n✓ All tests passed! System is ready for production.\n";
    exit(0);
} else {
    echo "\n✗ Some tests failed. Please review and fix issues.\n";
    exit(1);
}
