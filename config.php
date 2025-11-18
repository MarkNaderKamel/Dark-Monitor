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
        'database_file' => __DIR__ . '/data/monitoring.db',
        'export_dir' => __DIR__ . '/exports'
    ],

    // ============================================
    // THREAT INTELLIGENCE INTEGRATIONS
    // ============================================
    'virustotal' => [
        'api_key' => getenv('VIRUSTOTAL_API_KEY') ?: '',
        'enabled' => !empty(getenv('VIRUSTOTAL_API_KEY'))
    ],

    'hibp' => [
        'api_key' => getenv('HIBP_API_KEY') ?: '',
        'enabled' => !empty(getenv('HIBP_API_KEY'))
    ],

    'geolocation' => [
        'enabled' => true
    ],

    'additional_paste_sites' => [
        'enabled' => true
    ],

    'alert_rules' => [
        'enabled' => true
    ],

    'export' => [
        'auto_export_daily' => false,
        'formats' => ['json', 'csv', 'stix']
    ],

    // ============================================
    // THREAT INTELLIGENCE APIS
    // ============================================
    'threat_intelligence' => [
        'enabled' => false,
        'hibp_api_key' => getenv('HIBP_API_KEY') ?: '',          // Have I Been Pwned API key
        'virustotal_api_key' => getenv('VIRUSTOTAL_API_KEY') ?: '', // VirusTotal API key
        'abuseipdb_api_key' => getenv('ABUSEIPDB_API_KEY') ?: '',   // AbuseIPDB API key
    ],

    // ============================================
    // ENHANCED NOTIFICATIONS
    // ============================================
    'notifications' => [
        'email' => [
            'enabled' => false,
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
        'slack' => [
            'enabled' => false,
            'webhook_url' => getenv('SLACK_WEBHOOK_URL') ?: '',
        ],
        'discord' => [
            'enabled' => false,
            'webhook_url' => getenv('DISCORD_WEBHOOK_URL') ?: '',
        ],
    ],

    // ============================================
    // ADDITIONAL MONITORING SOURCES
    // ============================================
    'pastebin' => [
        'enabled' => false,
        'sites' => [
            'pastebin.com' => 'https://scrape.pastebin.com/api_scraping.php',
            'ghostbin.co' => 'https://ghostbin.co/browse',
            'justpaste.it' => 'https://justpaste.it/trending',
            'paste.ee' => 'https://paste.ee/recent',
        ],
        'check_interval' => 600, // 10 minutes
    ],

    'reddit' => [
        'enabled' => false,
        'subreddits' => [
            'security',
            'cybersecurity',
            'netsec',
            'privacy',
            'crypto',
            'hacking',
            'DataBreaches',
        ],
    ],

    'github' => [
        'enabled' => false,
        'api_token' => getenv('GITHUB_API_TOKEN') ?: '',
        'search_queries' => [
            // Add your company domain, API keys patterns, etc.
            // Example: 'yourcompany.com password',
            // Example: 'yourcompany api_key',
        ],
    ],

    // ============================================
    // IOC ENRICHMENT APIS
    // ============================================
    'enrichment' => [
        'enabled' => true,
        'cache_ttl' => 86400, // 24 hours
        'batch_size' => 10,
        'timeout' => 15,
        
        'apis' => [
            'virustotal' => [
                'enabled' => !empty(getenv('VIRUSTOTAL_API_KEY')),
                'api_key' => getenv('VIRUSTOTAL_API_KEY') ?: '',
                'base_url' => 'https://www.virustotal.com/api/v3',
                'rate_limit' => 4, // requests per minute for free tier
            ],
            'abuseipdb' => [
                'enabled' => !empty(getenv('ABUSEIPDB_API_KEY')),
                'api_key' => getenv('ABUSEIPDB_API_KEY') ?: '',
                'base_url' => 'https://api.abuseipdb.com/api/v2',
                'rate_limit' => 1000, // requests per day for free tier
            ],
            'shodan' => [
                'enabled' => !empty(getenv('SHODAN_API_KEY')),
                'api_key' => getenv('SHODAN_API_KEY') ?: '',
                'base_url' => 'https://api.shodan.io',
                'rate_limit' => 1, // requests per second for free tier
            ],
            'hibp' => [
                'enabled' => !empty(getenv('HIBP_API_KEY')),
                'api_key' => getenv('HIBP_API_KEY') ?: '',
                'base_url' => 'https://haveibeenpwned.com/api/v3',
                'rate_limit' => 10, // requests per minute
            ],
            'alienvault_otx' => [
                'enabled' => !empty(getenv('ALIENVAULT_OTX_API_KEY')),
                'api_key' => getenv('ALIENVAULT_OTX_API_KEY') ?: '',
                'base_url' => 'https://otx.alienvault.com/api/v1',
                'rate_limit' => 10, // requests per minute for free tier
            ],
            'greynoise' => [
                'enabled' => !empty(getenv('GREYNOISE_API_KEY')),
                'api_key' => getenv('GREYNOISE_API_KEY') ?: '',
                'base_url' => 'https://api.greynoise.io/v3',
                'rate_limit' => 50, // requests per minute for free tier
            ],
            'phishtank' => [
                'enabled' => !empty(getenv('PHISHTANK_API_KEY')),
                'api_key' => getenv('PHISHTANK_API_KEY') ?: '',
                'base_url' => 'https://checkurl.phishtank.com',
                'rate_limit' => 10, // requests per minute
            ],
            'pulsedive' => [
                'enabled' => !empty(getenv('PULSEDIVE_API_KEY')),
                'api_key' => getenv('PULSEDIVE_API_KEY') ?: '',
                'base_url' => 'https://pulsedive.com/api',
                'rate_limit' => 30, // requests per minute for free tier
            ],
        ],
    ],

    // ============================================
    // ML THREAT SCORING
    // ============================================
    'ml' => [
        'enabled' => true,
        'log_features' => true, // Log feature vectors for future training
        'feature_weights' => [
            'ioc_density' => 0.25,
            'keyword_severity' => 0.20,
            'source_reputation' => 0.15,
            'temporal_proximity' => 0.15,
            'correlation_strength' => 0.15,
            'enrichment_risk' => 0.10,
        ],
        'thresholds' => [
            'critical' => 0.85,
            'high' => 0.65,
            'medium' => 0.40,
            'low' => 0.20,
        ],
    ],

    // ============================================
    // STIX/TAXII EXPORT
    // ============================================
    'stix' => [
        'enabled' => true,
        'version' => '2.1',
        'producer' => 'Security Monitoring System',
        'tlp' => 'amber', // white, green, amber, red
        'confidence' => 70, // 0-100
        'validate_schema' => true,
    ],

    // ============================================
    // MITRE ATT&CK MAPPING
    // ============================================
    'mitre' => [
        'enabled' => true,
        'framework_version' => '14.0',
        'mapping_config' => __DIR__ . '/data/mitre_mappings.json',
        'auto_map' => true,
        'confidence_threshold' => 0.5,
    ],

    // ============================================
    // WEBHOOK NOTIFICATIONS
    // ============================================
    'webhooks' => [
        'slack' => [
            'enabled' => !empty(getenv('SLACK_WEBHOOK_URL')),
            'webhook_url' => getenv('SLACK_WEBHOOK_URL') ?: '',
            'channel' => '#security-alerts',
            'username' => 'Security Monitor',
            'icon_emoji' => ':warning:',
        ],
        'discord' => [
            'enabled' => !empty(getenv('DISCORD_WEBHOOK_URL')),
            'webhook_url' => getenv('DISCORD_WEBHOOK_URL') ?: '',
            'username' => 'Security Monitor',
            'avatar_url' => '',
        ],
        'teams' => [
            'enabled' => !empty(getenv('TEAMS_WEBHOOK_URL')),
            'webhook_url' => getenv('TEAMS_WEBHOOK_URL') ?: '',
            'theme_color' => 'FF0000',
        ],
    ],
];
