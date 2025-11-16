<?php
/**
 * View Findings Script
 * 
 * Displays all findings in a readable format
 */

$findingsFile = __DIR__ . '/data/findings.json';

if (!file_exists($findingsFile)) {
    echo "No findings yet. Run the monitor to start collecting data.\n";
    exit(0);
}

$json = file_get_contents($findingsFile);
$findings = json_decode($json, true);

if (empty($findings)) {
    echo "No findings yet.\n";
    exit(0);
}

echo "=== SECURITY FINDINGS ===\n\n";
echo "Total findings: " . count($findings) . "\n\n";

// Display last 20 findings
$recentFindings = array_slice($findings, -20);

foreach (array_reverse($recentFindings) as $i => $finding) {
    echo "Finding #" . ($i + 1) . "\n";
    echo str_repeat("-", 70) . "\n";
    echo "Time:     " . ($finding['timestamp'] ?? 'Unknown') . "\n";
    echo "Source:   " . ($finding['source'] ?? 'Unknown') . "\n";
    echo "Title:    " . ($finding['title'] ?? 'Unknown') . "\n";
    echo "URL:      " . ($finding['url'] ?? 'Unknown') . "\n";
    echo "Snippet:  " . mb_substr($finding['snippet'] ?? '', 0, 100) . "...\n";
    if (isset($finding['keywords'])) {
        echo "Keywords: " . implode(', ', $finding['keywords']) . "\n";
    }
    echo "\n";
}

if (count($findings) > 20) {
    echo "Showing last 20 of " . count($findings) . " total findings.\n";
    echo "Check data/findings.json for full list.\n";
}
