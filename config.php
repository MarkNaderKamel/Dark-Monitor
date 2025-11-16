<?php
/**
 * Security Monitoring System - Configuration File
 * 
 * This file contains all configuration settings for the monitoring system.
 * Edit this file to customize monitoring behavior, notification settings, and source lists.
 * 
 * SECURITY NOTE: This is for threat intelligence and security monitoring purposes only.
 */

return [
    // ============================================
    // GENERAL SETTINGS
    // ============================================
    'monitoring' => [
        'interval_seconds' => 3600, // Run every hour (3600 seconds)
        'max_iterations' => 0, // 0 = infinite loop, or set a number for testing
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'timeout' => 30, // HTTP request timeout in seconds
        'max_retries' => 3, // Number of retries for failed requests
    ],

    // ============================================
    // KEYWORD DETECTION
    // ============================================
    'keywords' => [
        'leak',
        'database',
        'dump',
        'credentials',
        'breach',
        'stolen data',
        'data breach',
        'hacked',
        'compromised',
        'exposed',
        'sql dump',
        'combo',
        'combolist',
        'account',
        'passwords',
    ],

    // ============================================
    // LOGGING SETTINGS
    // ============================================
    'logging' => [
        'file' => __DIR__ . '/logs/monitors.log',
        'level' => 'INFO', // DEBUG, INFO, WARNING, ERROR
        'max_size_mb' => 100, // Max log file size before rotation
        'format' => '[%timestamp%] [%level%] [%source%] %message%',
    ],

    // ============================================
    // NOTIFICATION SETTINGS
    // ============================================
    'notifications' => [
        'email' => [
            'enabled' => false, // Set to true to enable email notifications
            'smtp_host' => 'smtp.gmail.com',
            'smtp_port' => 587,
            'smtp_user' => getenv('SMTP_USER') ?: '',
            'smtp_password' => getenv('SMTP_PASSWORD') ?: '',
            'from_email' => getenv('SMTP_USER') ?: 'monitor@security.local',
            'to_email' => getenv('NOTIFY_EMAIL') ?: '',
            'subject_prefix' => '[SECURITY ALERT]',
        ],
        'webhook' => [
            'enabled' => false,
            'url' => getenv('WEBHOOK_URL') ?: '',
        ],
    ],

    // ============================================
    // TELEGRAM SETTINGS
    // ============================================
    'telegram' => [
        'enabled' => true,
        'bot_token' => getenv('TELEGRAM_BOT_TOKEN') ?: '',
        'api_url' => 'https://api.telegram.org/bot',
        'offset_file' => __DIR__ . '/data/telegram_offset.txt',
        // Channels to monitor (without @)
        'channels' => [
            'mooncloudlogs',
            'observercloud',
            'omegacloud',
            'dataleakmonitoring',
            'bidencash',
            'empchat',
            'daisycloud',
            'bugatticloud',
            'cuckoocloud',
            'redcloudlogs',
            'veterangroup',
            'snatchlogs',
            'hubheadsnatch',
            'baseleak',
            'basebrutesu',
            'crdprocorner',
            'ascardingunderground',
            'canadaunion',
            'qianxunjapan',
            'geniusqijiusi',
            'noname05716',
            'rippersec',
            'darkstormteam',
            'zpentestalliance',
        ],
    ],

    // ============================================
    // CLEAR WEB SOURCES
    // ============================================
    'clearweb_sources' => [
        [
            'name' => 'XSS.is',
            'url' => 'https://xss.is',
            'enabled' => true,
            'selector' => 'latest-posts', // CSS selector or keyword for parsing
        ],
        [
            'name' => 'Exploit.in',
            'url' => 'https://exploit.in',
            'enabled' => true,
            'selector' => 'recent',
        ],
        [
            'name' => 'BHF.io',
            'url' => 'https://bhf.io',
            'enabled' => true,
            'selector' => 'threads',
        ],
        [
            'name' => 'Altenen',
            'url' => 'https://altenen.nz',
            'enabled' => true,
            'selector' => 'latest',
        ],
        [
            'name' => 'Cracked.to',
            'url' => 'https://cracked.to',
            'enabled' => true,
            'selector' => 'recent-threads',
        ],
        [
            'name' => 'Nulled.to',
            'url' => 'https://nulled.to',
            'enabled' => true,
            'selector' => 'latest',
        ],
        [
            'name' => 'Breached.vc',
            'url' => 'https://breached.vc',
            'enabled' => true,
            'selector' => 'threads',
        ],
        [
            'name' => 'DarkForums',
            'url' => 'https://darkforums.st',
            'enabled' => true,
            'selector' => 'latest',
        ],
        [
            'name' => 'Ransomware.live',
            'url' => 'https://ransomware.live',
            'enabled' => true,
            'selector' => 'posts',
        ],
    ],

    // ============================================
    // DARK WEB / TOR SOURCES
    // ============================================
    'darkweb_sources' => [
        'enabled' => false, // Set to true if Tor proxy is available
        'tor_proxy' => '127.0.0.1:9050', // SOCKS5 proxy for Tor
        'sites' => [
            [
                'name' => 'Dread',
                'url' => 'dreaditevldees6.onion', // Example - replace with current address
                'enabled' => false,
            ],
            [
                'name' => 'CryptBB',
                'url' => 'cryptbb.onion', // Example - replace with current address
                'enabled' => false,
            ],
        ],
    ],

    // ============================================
    // ADVANCED SETTINGS
    // ============================================
    'advanced' => [
        'respect_robots_txt' => true,
        'rate_limit_delay' => 2, // Delay between requests in seconds
        'parallel_requests' => false, // Enable parallel processing (experimental)
        'cache_enabled' => true,
        'cache_ttl' => 300, // Cache TTL in seconds (5 minutes)
        'debug_mode' => getenv('DEBUG_MODE') === 'true',
        'verify_ssl' => true, // Enable SSL/TLS certificate verification (recommended)
        'ca_bundle_path' => null, // Optional: Custom CA bundle path if needed
    ],

    // ============================================
    // DATA STORAGE
    // ============================================
    'storage' => [
        'findings_file' => __DIR__ . '/data/findings.json',
        'cache_dir' => __DIR__ . '/cache',
        'state_file' => __DIR__ . '/data/state.json',
    ],
];
