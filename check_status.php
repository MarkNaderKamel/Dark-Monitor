<?php
/**
 * Status Check Script
 * 
 * Shows system status and last run information
 */

echo "=== SECURITY MONITORING SYSTEM - STATUS ===\n\n";

// Check state file
$stateFile = __DIR__ . '/data/state.json';
if (file_exists($stateFile)) {
    $state = json_decode(file_get_contents($stateFile), true);
    echo "Last Run:    " . ($state['last_run'] ?? 'Never') . "\n";
    echo "Iteration:   #" . ($state['iteration'] ?? 0) . "\n";
    echo "Findings:    " . ($state['findings_count'] ?? 0) . " in last run\n";
    echo "\n";
} else {
    echo "System has not been run yet.\n\n";
}

// Check findings
$findingsFile = __DIR__ . '/data/findings.json';
if (file_exists($findingsFile)) {
    $findings = json_decode(file_get_contents($findingsFile), true);
    echo "Total Findings: " . count($findings ?? []) . "\n\n";
} else {
    echo "Total Findings: 0\n\n";
}

// Check log file
$logFile = __DIR__ . '/logs/monitors.log';
if (file_exists($logFile)) {
    $logSize = filesize($logFile);
    echo "Log File Size: " . number_format($logSize / 1024, 2) . " KB\n";
    
    // Show last few log entries
    echo "\nRecent Log Entries:\n";
    echo str_repeat("-", 70) . "\n";
    
    $lines = file($logFile);
    $lastLines = array_slice($lines, -10);
    echo implode("", $lastLines);
} else {
    echo "No log file yet.\n";
}

echo "\n=== Configuration ===\n";
$config = require __DIR__ . '/config.php';

echo "Monitoring Interval: " . $config['monitoring']['interval_seconds'] . " seconds\n";
echo "Keywords:            " . count($config['keywords']) . " configured\n";
echo "Web Sources:         " . count($config['clearweb_sources']) . " configured\n";
echo "Telegram Channels:   " . count($config['telegram']['channels']) . " configured\n";
echo "Dark Web:            " . ($config['darkweb_sources']['enabled'] ? 'Enabled' : 'Disabled') . "\n";
echo "Email Alerts:        " . ($config['notifications']['email']['enabled'] ? 'Enabled' : 'Disabled') . "\n";

echo "\n";
