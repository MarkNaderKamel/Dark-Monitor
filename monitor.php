<?php
/**
 * Security Monitoring System - Main Entry Point
 * 
 * This is a comprehensive threat intelligence monitoring system designed for
 * cybersecurity professionals to detect mentions of data leaks and breaches
 * across clear web, dark web, and Telegram channels.
 * 
 * USAGE:
 *   php monitor.php                - Run continuous monitoring
 *   php monitor.php --once         - Run single iteration
 *   php monitor.php --test         - Test configuration
 *   php monitor.php --help         - Show help
 * 
 * SETUP INSTRUCTIONS:
 * 
 * 1. Install PHP 8.x (already available on Replit)
 * 
 * 2. Set up environment variables (in Replit Secrets or .env file):
 *    - TELEGRAM_BOT_TOKEN: Your Telegram bot token from @BotFather
 *    - SMTP_USER: Your email for SMTP (e.g., Gmail)
 *    - SMTP_PASSWORD: Your email password or app-specific password
 *    - NOTIFY_EMAIL: Email address to receive alerts
 *    - DEBUG_MODE: Set to 'true' for verbose logging
 * 
 * 3. Create a Telegram Bot:
 *    - Open Telegram and search for @BotFather
 *    - Send /newbot and follow instructions
 *    - Copy the bot token and add it to TELEGRAM_BOT_TOKEN
 *    - Add your bot to the channels you want to monitor
 * 
 * 4. (Optional) Set up Tor for dark web monitoring:
 *    - Install Tor Browser or tor service
 *    - Ensure SOCKS5 proxy is running on 127.0.0.1:9050
 *    - Enable dark web monitoring in config.php
 * 
 * 5. Configure monitoring sources in config.php
 * 
 * 6. Run the script:
 *    php monitor.php
 * 
 * For Hostinger deployment:
 * - Upload all files via FTP
 * - Set up a cron job: 0 * * * * cd /path/to/monitor && php monitor.php --once
 * - Ensure logs and data directories are writable
 * - Configure environment variables in hosting panel
 * 
 * @author Security Monitoring System
 * @version 1.0
 */

// Error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);
set_time_limit(0); // No time limit for continuous monitoring

// Load configuration
require_once __DIR__ . '/config.php';
$config = require __DIR__ . '/config.php';

// Load classes
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
require_once __DIR__ . '/src/VirusTotalEnricher.php';
require_once __DIR__ . '/src/HIBPChecker.php';
require_once __DIR__ . '/src/GeolocateIP.php';
require_once __DIR__ . '/src/AlertRulesEngine.php';
require_once __DIR__ . '/src/ExportManager.php';
require_once __DIR__ . '/src/AdditionalPasteSites.php';

// Parse command line arguments
$options = parseArguments($argv ?? []);

if ($options['help']) {
    showHelp();
    exit(0);
}

// Initialize system
$logger = new Logger($config);
$db = new DatabaseManager($config, $logger);
$httpClient = new HttpClient($config, $logger);
$telegramMonitor = new TelegramMonitor($config, $logger, $httpClient);
$webScraper = new WebScraper($config, $logger, $httpClient);
$darkWebMonitor = new DarkWebMonitor($config, $logger, $httpClient);
$pastebinMonitor = new PastebinMonitor($config, $logger, $httpClient);
$redditMonitor = new RedditMonitor($config, $logger, $httpClient);
$githubMonitor = new GitHubMonitor($config, $logger, $httpClient);
$notifier = new Notifier($config, $logger);
$slackNotifier = new SlackNotifier($logger, $config);
$discordNotifier = new DiscordNotifier($logger, $config);
$reputationScorer = new ReputationScorer($db, $logger, $config);
$threatCorrelation = new ThreatCorrelation($db, $logger, $config);
$summaryReporter = new SummaryReporter($db, $logger, $config, $notifier);
$virusTotalEnricher = new VirusTotalEnricher($config, $logger, $db);
$hibpChecker = new HIBPChecker($config, $logger, $db);
$geolocateIP = new GeolocateIP($logger, $db);
$alertRulesEngine = new AlertRulesEngine($db, $logger);
$exportManager = new ExportManager($db, $logger, $config);
$additionalPasteSites = new AdditionalPasteSites($httpClient, $logger);

// Create necessary directories
createDirectories($config);

// Show banner
showBanner($logger);

// Test mode
if ($options['test']) {
    runTests($config, $logger, $telegramMonitor);
    exit(0);
}

// Main monitoring loop
$logger->info('SYSTEM', 'Starting Security Monitoring System');
$logger->info('SYSTEM', 'Monitoring interval: ' . $config['monitoring']['interval_seconds'] . ' seconds');

$iteration = 0;
$maxIterations = $options['once'] ? 1 : $config['monitoring']['max_iterations'];

while (true) {
    $iteration++;
    $logger->info('SYSTEM', "=== Starting monitoring iteration #$iteration ===");
    
    try {
        $allFindings = [];

        // 1. Monitor Telegram channels
        if ($telegramMonitor->isEnabled()) {
            $logger->info('SYSTEM', 'Monitoring Telegram channels...');
            $telegramFindings = $telegramMonitor->monitor($config['keywords']);
            $allFindings = array_merge($allFindings, $telegramFindings);
        } else {
            $logger->warning('SYSTEM', 'Telegram monitoring is disabled. Configure TELEGRAM_BOT_TOKEN to enable.');
        }

        // 2. Scrape clear web sources
        $logger->info('SYSTEM', 'Scraping clear web sources...');
        $webFindings = $webScraper->scrapeAll($config['keywords']);
        $allFindings = array_merge($allFindings, $webFindings);

        // 3. Monitor dark web (if enabled)
        if ($darkWebMonitor->isEnabled()) {
            $logger->info('SYSTEM', 'Monitoring dark web sources...');
            $darkWebFindings = $darkWebMonitor->monitor($config['keywords']);
            $allFindings = array_merge($allFindings, $darkWebFindings);
        }

        // 4. Monitor Pastebin (if enabled)
        if ($pastebinMonitor->isEnabled()) {
            $logger->info('SYSTEM', 'Monitoring Pastebin...');
            $pastebinFindings = $pastebinMonitor->monitor($config['keywords']);
            $allFindings = array_merge($allFindings, $pastebinFindings);
        }

        // 5. Monitor Reddit (if enabled)
        if ($redditMonitor->isEnabled()) {
            $logger->info('SYSTEM', 'Monitoring Reddit...');
            $redditFindings = $redditMonitor->monitor($config['keywords']);
            $allFindings = array_merge($allFindings, $redditFindings);
        }

        // 6. Monitor GitHub (if enabled)
        if ($githubMonitor->isEnabled()) {
            $logger->info('SYSTEM', 'Monitoring GitHub...');
            $githubFindings = $githubMonitor->monitor($config['keywords']);
            $allFindings = array_merge($allFindings, $githubFindings);
        }

        // 7. Monitor Additional Paste Sites (if enabled)
        if ($additionalPasteSites->isEnabled() && ($config['additional_paste_sites']['enabled'] ?? false)) {
            $logger->info('SYSTEM', 'Monitoring additional paste sites...');
            $additionalFindings = $additionalPasteSites->monitor($config['keywords']);
            $allFindings = array_merge($allFindings, $additionalFindings);
        }

        // 8. Process findings with threat intelligence
        if (!empty($allFindings)) {
            $logger->info('SYSTEM', "Found " . count($allFindings) . " potential matches");
            
            foreach ($allFindings as &$finding) {
                // Calculate threat score
                $finding['threat_score'] = $threatCorrelation->calculateThreatScore($finding);
                
                // Determine severity
                $score = $finding['threat_score'];
                if ($score >= 80) {
                    $finding['severity'] = 'CRITICAL';
                } elseif ($score >= 60) {
                    $finding['severity'] = 'HIGH';
                } elseif ($score >= 40) {
                    $finding['severity'] = 'MEDIUM';
                } else {
                    $finding['severity'] = 'LOW';
                }
                
                // Score and enrich IOCs if present
                if (!empty($finding['iocs'])) {
                    // Enrich with VirusTotal (if enabled)
                    if ($virusTotalEnricher->isEnabled() && ($finding['severity'] === 'CRITICAL' || $finding['severity'] === 'HIGH')) {
                        $enrichment = $virusTotalEnricher->enrichIOCs($finding['iocs']);
                        $finding['vt_enrichment'] = $enrichment;
                    }
                    
                    // Check emails with HIBP (if enabled)
                    if ($hibpChecker->isEnabled() && !empty($finding['iocs']['emails'])) {
                        $hibpData = $hibpChecker->enrichEmails($finding['iocs']['emails']);
                        $finding['hibp_enrichment'] = $hibpData;
                    }
                    
                    // Geolocate IPs
                    if (!empty($finding['iocs']['ips']) && ($config['geolocation']['enabled'] ?? false)) {
                        $geoData = $geolocateIP->locateMultiple($finding['iocs']['ips']);
                        $finding['geo_enrichment'] = $geoData;
                    }
                    
                    foreach ($finding['iocs'] as $type => $items) {
                        if (!is_array($items)) continue;
                        
                        foreach ($items as $item) {
                            $entityType = ($type === 'ips') ? 'ip' : (($type === 'urls') ? 'url' : 'hash');
                            
                            $reputationScorer->scoreEntity($entityType, $item, [
                                'malicious' => ($finding['severity'] === 'CRITICAL' || $finding['severity'] === 'HIGH')
                            ]);
                            
                            // Store IOC in database
                            $db->insertIOC([
                                'type' => $type,
                                'value' => $item,
                                'severity' => $finding['severity'],
                                'source' => $finding['source']
                            ]);
                        }
                    }
                }
                
                // Store in database
                $findingId = $db->insertFinding($finding);
                
                // Log finding
                $logger->logFinding(
                    $finding['source'],
                    $finding['title'],
                    $finding['url'],
                    $finding['snippet']
                );
                
                // Evaluate alert rules
                $triggeredRules = $alertRulesEngine->evaluateFinding($finding);
                if (!empty($triggeredRules)) {
                    $alertRulesEngine->executeActions($triggeredRules, $finding, [
                        'slack' => $slackNotifier,
                        'discord' => $discordNotifier,
                        'email' => $notifier
                    ]);
                }
                
                // Send notifications for high-severity findings
                if ($finding['severity'] === 'CRITICAL' || $finding['severity'] === 'HIGH') {
                    if ($slackNotifier->isEnabled()) {
                        $slackNotifier->notify($finding);
                    }
                    
                    if ($discordNotifier->isEnabled()) {
                        $discordNotifier->notify($finding);
                    }
                }
            }
            
            // Send standard notifications
            $notifier->notify($allFindings);
            
            // Run correlation analysis
            if (count($allFindings) > 1) {
                $logger->info('SYSTEM', 'Running threat correlation analysis...');
                $correlations = $threatCorrelation->correlateFindings();
                $logger->info('SYSTEM', 'Found ' . count($correlations) . ' threat correlations');
            }
        } else {
            $logger->info('SYSTEM', 'No matches found in this iteration');
        }
        
        // Generate summary report if configured
        if ($iteration % 24 === 0 || ($iteration === 1 && date('H') === '00')) {
            $logger->info('SYSTEM', 'Generating summary report...');
            try {
                $summary = $summaryReporter->generateDailySummary();
                
                if ($slackNotifier->isEnabled()) {
                    $slackNotifier->sendSummary($summary['statistics']);
                }
                
                if ($discordNotifier->isEnabled()) {
                    $discordNotifier->sendSummary($summary['statistics']);
                }
            } catch (Exception $e) {
                $logger->error('SYSTEM', 'Failed to generate summary: ' . $e->getMessage());
            }
        }

        // Save state
        saveState($config, $iteration, count($allFindings));

        $logger->info('SYSTEM', "=== Completed iteration #$iteration ===");

        // Check if we should continue
        if ($maxIterations > 0 && $iteration >= $maxIterations) {
            $logger->info('SYSTEM', 'Reached max iterations, exiting');
            break;
        }

        if ($options['once']) {
            break;
        }

        // Sleep until next iteration
        $sleepTime = $config['monitoring']['interval_seconds'];
        $logger->info('SYSTEM', "Sleeping for $sleepTime seconds until next iteration...");
        sleep($sleepTime);

    } catch (Exception $e) {
        $logger->error('SYSTEM', 'Fatal error in monitoring loop: ' . $e->getMessage());
        $logger->error('SYSTEM', 'Stack trace: ' . $e->getTraceAsString());
        
        // Sleep before retry
        sleep(60);
    }
}

$logger->info('SYSTEM', 'Monitoring system stopped');

// ============================================
// HELPER FUNCTIONS
// ============================================

function parseArguments($argv) {
    $options = [
        'help' => false,
        'test' => false,
        'once' => false,
    ];

    foreach ($argv as $arg) {
        if ($arg === '--help' || $arg === '-h') {
            $options['help'] = true;
        }
        if ($arg === '--test') {
            $options['test'] = true;
        }
        if ($arg === '--once') {
            $options['once'] = true;
        }
    }

    return $options;
}

function showHelp() {
    echo <<<HELP

Security Monitoring System - Help
==================================

USAGE:
  php monitor.php [OPTIONS]

OPTIONS:
  --help, -h     Show this help message
  --test         Test configuration and connectivity
  --once         Run single monitoring iteration and exit
  (no options)   Run continuous monitoring

EXAMPLES:
  php monitor.php              # Start continuous monitoring
  php monitor.php --once       # Run once and exit (good for cron jobs)
  php monitor.php --test       # Test your configuration

SETUP:
  1. Configure environment variables (TELEGRAM_BOT_TOKEN, etc.)
  2. Edit config.php to customize monitoring sources
  3. Run: php monitor.php

For detailed setup instructions, see README.md

HELP;
}

function showBanner($logger) {
    $banner = <<<BANNER

╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║         SECURITY MONITORING SYSTEM v1.0                      ║
║         Threat Intelligence & Leak Detection                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

BANNER;

    echo $banner . PHP_EOL;
    $logger->info('SYSTEM', 'Security Monitoring System v1.0 initialized');
}

function createDirectories($config) {
    $directories = [
        dirname($config['logging']['file']),
        dirname($config['storage']['findings_file']),
        $config['storage']['cache_dir'],
        dirname($config['telegram']['offset_file']),
    ];

    foreach ($directories as $dir) {
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }
    }
}

function saveState($config, $iteration, $findingsCount) {
    $state = [
        'last_run' => date('Y-m-d H:i:s'),
        'iteration' => $iteration,
        'findings_count' => $findingsCount,
        'uptime' => time(),
    ];

    $stateFile = $config['storage']['state_file'];
    $dir = dirname($stateFile);
    
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }

    file_put_contents($stateFile, json_encode($state, JSON_PRETTY_PRINT));
}

function runTests($config, $logger, $telegramMonitor) {
    echo "\n=== Configuration Test ===\n\n";

    // Test 1: Check directories
    echo "✓ Checking directories...\n";
    createDirectories($config);
    echo "  Logs directory: " . dirname($config['logging']['file']) . "\n";
    echo "  Data directory: " . dirname($config['storage']['findings_file']) . "\n";

    // Test 2: Check Telegram configuration
    echo "\n✓ Checking Telegram configuration...\n";
    if ($telegramMonitor->isEnabled()) {
        echo "  Telegram bot token: Configured ✓\n";
        echo "  Channels to monitor: " . count($config['telegram']['channels']) . "\n";
    } else {
        echo "  ⚠ Telegram not configured. Set TELEGRAM_BOT_TOKEN environment variable.\n";
    }

    // Test 3: Check email configuration
    echo "\n✓ Checking email configuration...\n";
    if ($config['notifications']['email']['enabled']) {
        echo "  Email notifications: Enabled ✓\n";
        echo "  SMTP host: " . $config['notifications']['email']['smtp_host'] . "\n";
    } else {
        echo "  Email notifications: Disabled\n";
    }

    // Test 4: Check web sources
    echo "\n✓ Checking web sources...\n";
    $enabledSources = array_filter($config['clearweb_sources'], fn($s) => $s['enabled'] ?? true);
    echo "  Clear web sources: " . count($enabledSources) . " enabled\n";

    // Test 5: Check dark web
    echo "\n✓ Checking dark web configuration...\n";
    if ($config['darkweb_sources']['enabled']) {
        echo "  Dark web monitoring: Enabled ✓\n";
        echo "  Tor proxy: " . $config['darkweb_sources']['tor_proxy'] . "\n";
    } else {
        echo "  Dark web monitoring: Disabled\n";
    }

    // Test 6: Test HTTP connectivity
    echo "\n✓ Testing HTTP connectivity...\n";
    $testUrl = 'https://www.google.com';
    $ch = curl_init($testUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    $result = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode === 200) {
        echo "  HTTP connectivity: OK ✓\n";
    } else {
        echo "  ⚠ HTTP connectivity issue (HTTP $httpCode)\n";
    }

    echo "\n=== Test completed ===\n\n";
    echo "To start monitoring, run: php monitor.php\n\n";
}
