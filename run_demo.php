<?php
/**
 * Demo Script - Runs the monitoring system in demo mode
 * 
 * This script demonstrates the monitoring system with simulated findings
 * for demonstration purposes without needing real Telegram bot setup.
 */

echo "=== Security Monitoring System - Demo Mode ===\n\n";
echo "This demo shows how the system works without requiring full setup.\n";
echo "For production use, configure environment variables and run monitor.php\n\n";

// Load config
$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/src/Logger.php';

// Initialize logger
$logger = new Logger($config);

echo "✓ System initialized\n";
echo "✓ Monitoring configuration loaded\n";
echo "✓ " . count($config['clearweb_sources']) . " clear web sources configured\n";
echo "✓ " . count($config['telegram']['channels']) . " Telegram channels configured\n";
echo "✓ " . count($config['keywords']) . " keywords loaded\n\n";

// Simulate a monitoring iteration
echo "=== Simulating Monitoring Iteration ===\n\n";

$logger->info('DEMO', 'Starting demo monitoring iteration');

// Simulate web scraping
echo "Scraping web sources...\n";
$logger->info('DEMO', 'Scraping XSS.is...');
sleep(1);
echo "  ✓ XSS.is checked\n";

$logger->info('DEMO', 'Scraping Exploit.in...');
sleep(1);
echo "  ✓ Exploit.in checked\n";

$logger->info('DEMO', 'Scraping BreachForums...');
sleep(1);
echo "  ✓ BreachForums checked\n";

// Simulate finding
echo "\n🔍 FINDING DETECTED!\n\n";

$demoFinding = [
    'source' => 'Demo: XSS.is',
    'title' => '[LEAK] Example Database Dump - 1M Records',
    'url' => 'https://example.com/thread/12345',
    'snippet' => 'New database leak containing user credentials and email addresses...',
    'keywords' => ['leak', 'database', 'credentials'],
    'timestamp' => date('Y-m-d H:i:s'),
];

$logger->logFinding(
    $demoFinding['source'],
    $demoFinding['title'],
    $demoFinding['url'],
    $demoFinding['snippet']
);

echo "Source:    {$demoFinding['source']}\n";
echo "Title:     {$demoFinding['title']}\n";
echo "URL:       {$demoFinding['url']}\n";
echo "Keywords:  " . implode(', ', $demoFinding['keywords']) . "\n";
echo "Time:      {$demoFinding['timestamp']}\n";

echo "\n✓ Finding logged to: logs/monitors.log\n";
echo "✓ Finding saved to: data/findings.json\n";

echo "\n=== Demo Completed ===\n\n";
echo "To run the full system:\n";
echo "1. Set up Telegram bot token (see SETUP.md)\n";
echo "2. Configure environment variables\n";
echo "3. Run: php monitor.php\n\n";

echo "Check the logs:\n";
echo "  cat logs/monitors.log\n";
echo "  cat data/findings.json\n\n";
