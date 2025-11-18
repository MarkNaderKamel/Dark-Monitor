# Security Monitoring System - Enhancement Guide

## 🚀 New Features & Capabilities

This document outlines all the advanced features that have been added to the Security Monitoring System.

---

## 📊 Advanced Threat Intelligence Enrichment

### New Enrichment APIs

The system now supports **9 different threat intelligence APIs** for comprehensive IOC analysis:

#### 1. **AlienVault OTX** (Open Threat Exchange)
- **Coverage**: IPs, domains, URLs, file hashes
- **Features**: 19M+ IOCs, pulse tracking, malware family detection
- **Free Tier**: Unlimited queries
- **Setup**: Set `ALIENVAULT_OTX_API_KEY` environment variable
- **Use Case**: Community-powered threat intelligence, real-time threat feeds

#### 2. **ThreatFox** (abuse.ch)
- **Coverage**: Malware infrastructure IOCs
- **Features**: C2 servers, malware families, confidence scoring
- **Free Tier**: Unlimited (no API key required)
- **Use Case**: Fresh malware IOC feeds, botnet tracking

#### 3. **URLhaus** (abuse.ch)
- **Coverage**: Malicious URLs, domains, file hashes
- **Features**: Malware distribution sites, payload analysis
- **Free Tier**: Unlimited (no API key required)
- **Use Case**: Malware distribution tracking, URL threat detection

#### 4. **GreyNoise**
- **Coverage**: IP addresses
- **Features**: Distinguishes malicious from benign scanners, reduces false positives
- **Free Tier**: Community API (no key), Enhanced API requires key
- **Setup**: Set `GREYNOISE_API_KEY` for enhanced features (optional)
- **Use Case**: Filtering internet background noise, identifying true threats

#### 5. **PhishTank**
- **Coverage**: Phishing URLs
- **Features**: Community-verified phishing database
- **Free Tier**: Requires API key (free registration)
- **Setup**: Set `PHISHTANK_API_KEY`
- **Use Case**: Phishing detection and verification

#### 6. **Pulsedive**
- **Coverage**: IPs, domains, URLs with risk scoring
- **Features**: OSINT aggregator, risk assessment, feed integration
- **Free Tier**: Generous limits
- **Setup**: Set `PULSEDIVE_API_KEY`
- **Use Case**: Comprehensive IOC enrichment with context

#### 7. **VirusTotal**
- **Coverage**: Files, URLs, domains, IPs
- **Features**: 70+ AV engines, sandbox analysis
- **Free Tier**: 4 requests/minute
- **Setup**: Set `VIRUSTOTAL_API_KEY`
- **Use Case**: Malware analysis, quick triage

#### 8. **AbuseIPDB**
- **Coverage**: IP addresses
- **Features**: Community IP abuse reporting, blacklist checking
- **Free Tier**: 1,000 checks/day
- **Setup**: Set `ABUSEIPDB_API_KEY`
- **Use Case**: IP reputation checks, abuse detection

#### 9. **Shodan**
- **Coverage**: IP addresses, internet-connected devices
- **Features**: Port scanning, service detection, vulnerability identification
- **Free Tier**: Limited queries
- **Setup**: Set `SHODAN_API_KEY`
- **Use Case**: Asset discovery, exposure detection

---

## 🔍 Advanced IOC Extraction

### Automated Pattern Recognition

The new IOC extraction engine automatically identifies and extracts:

#### Supported IOC Types
- **IPv4 & IPv6 Addresses** (filters private IPs)
- **Domain Names** (validates format, filters common domains)
- **URLs** (HTTP/HTTPS/FTP)
- **Email Addresses** (with validation)
- **File Hashes**: MD5, SHA-1, SHA-256, SHA-512
- **CVE IDs** (CVE-YYYY-NNNNN format)
- **Cryptocurrency Addresses**: Bitcoin, Ethereum
- **Windows Artifacts**:
  - File paths (C:\Windows\...)
  - Registry keys (HKLM\..., HKCU\...)
  - Mutex names (\BaseNamedObjects\...)
- **SSN** (for data breach detection)
- **Credit Cards** (for leak detection)
- **Phone Numbers**

#### Defanging Support
Automatically refangs obfuscated indicators:
- `hxxp` → `http`
- `[dot]` → `.`
- `[:]` → `:`
- `[@]` → `@`

#### Smart Filtering
- Excludes private/RFC1918 IP ranges
- Filters common legitimate domains
- Validates domain structure
- Removes false positives

### Usage Example
```php
$iocExtractor = new IOCExtractor($logger);
$iocs = $iocExtractor->extract($text);

// Returns:
[
    'ips' => ['192.0.2.1', '198.51.100.42'],
    'domains' => ['evil.com', 'malware.net'],
    'urls' => ['http://phishing.example.com/login'],
    'hashes' => ['d41d8cd98f00b204e9800998ecf8427e'],
    'cves' => ['CVE-2024-1234'],
    'crypto_addresses' => ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa']
]
```

---

## 🎯 Enhanced Enrichment Manager

The `EnhancedEnrichmentManager` coordinates all enrichment services:

### Features
- **Automatic IOC Extraction** from findings
- **Multi-Source Enrichment** using all available APIs
- **Intelligent Caching** to reduce API calls
- **Risk Scoring Algorithm** based on multiple factors
- **Threat Indicator Identification**

### Risk Scoring Factors
1. **IOC Density** (20 points max)
2. **IP Reputation**:
   - AbuseIPDB confidence score (25 points)
   - VirusTotal malicious count (15 points)
   - GreyNoise classification (10 points)
3. **Domain Reputation**:
   - VirusTotal detections (15 points)
   - URLhaus URL count (15 points)
4. **URL Analysis**:
   - PhishTank database match (20 points)
   - URLhaus status (15 points)
5. **Hash Analysis**:
   - VirusTotal detections (20 points)
   - ThreatFox confidence (15 points)

**Total Score**: 0-100 (auto-capped)

### Usage
```php
$enrichmentManager = new EnhancedEnrichmentManager($logger, $db, $config);
$result = $enrichmentManager->extractAndEnrichIOCs($finding['snippet']);

// Returns:
[
    'iocs' => [...],  // Extracted IOCs
    'enrichment' => [...],  // Enrichment data from all APIs
    'risk_score' => 85,  // Calculated risk (0-100)
    'threat_indicators' => [
        'Known phishing URL',
        'Known malware: Emotet',
        'File hashes detected'
    ]
]
```

---

## 📤 STIX 2.1 Export

### Enhanced STIX Exporter

Export findings in **STIX 2.1 format** for threat intelligence sharing:

#### Features
- **STIX 2.1 Compliant** bundles
- **TLP Marking** (White, Green, Amber, Red)
- **MITRE ATT&CK Integration**:
  - Attack pattern objects
  - External references
  - Technique mapping
- **IOC Objects**:
  - IPv4/IPv6 addresses
  - Domain names
  - URLs
  - Email addresses
  - File hashes
- **Observed Data** objects with timestamps
- **Indicator** objects with patterns

#### Supported STIX Objects
- `identity` - Producer information
- `indicator` - Detection patterns
- `observed-data` - Actual observations
- `attack-pattern` - MITRE techniques
- `file` - File hash objects
- `marking-definition` - TLP markings

#### Usage
```php
$stixExporter = new EnhancedSTIXExporter($config, $logger, $db);

// Export to JSON string
$stixJSON = $stixExporter->exportFindings($findings);

// Export to file
$filepath = $stixExporter->exportToFile($findings, 'findings_2024-11-18.json');
```

#### Example STIX Output
```json
{
  "type": "bundle",
  "id": "bundle--xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "pattern": "[ipv4-addr:value = '192.0.2.1']",
      "pattern_type": "stix",
      "valid_from": "2024-11-18T10:00:00.000Z"
    }
  ]
}
```

---

## 🔧 Configuration

### Environment Variables

Add these environment variables in Replit Secrets or your `.env` file:

```bash
# Required for Telegram monitoring
TELEGRAM_BOT_TOKEN=your_telegram_bot_token

# Enrichment APIs (all optional, but recommended)
VIRUSTOTAL_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
ALIENVAULT_OTX_API_KEY=your_otx_key
GREYNOISE_API_KEY=your_greynoise_key
PHISHTANK_API_KEY=your_phishtank_key
PULSEDIVE_API_KEY=your_pulsedive_key
HIBP_API_KEY=your_hibp_key

# Notifications (optional)
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
NOTIFY_EMAIL=alerts@yourcompany.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

### Getting API Keys

#### Free APIs (No Key Required)
- **ThreatFox**: No registration needed
- **URLhaus**: No registration needed

#### Free APIs (Registration Required)
1. **VirusTotal**: https://www.virustotal.com/gui/join-us
2. **AbuseIPDB**: https://www.abuseipdb.com/register
3. **AlienVault OTX**: https://otx.alienvault.com/api
4. **PhishTank**: https://www.phishtank.com/api_info.php
5. **Pulsedive**: https://pulsedive.com/register
6. **GreyNoise**: https://www.greynoise.io/plans (Community API free)

#### Paid APIs (Free Tiers Available)
- **Shodan**: https://account.shodan.io/register
- **HIBP**: https://haveibeenpwned.com/API/Key

---

## 📈 Improved Connection Handling

### TelegramMonitor Enhancements
- **Retry Logic**: 3 attempts with exponential backoff
- **SSL Verification**: Enabled by default for security
- **Better Error Messages**: Detailed logging of failures
- **Connection Timeouts**: 10s connect, 40s total
- **Keep-Alive**: Connection pooling for efficiency

### HttpClient Improvements
- **Configurable Retries**: Set `max_retries` in config
- **SSL/TLS Verification**: Enabled with custom CA bundle support
- **Robots.txt Compliance**: Automatic checking (configurable)
- **Rate Limiting**: Delay between requests
- **Tor Proxy Support**: For dark web monitoring

---

## 🧪 Testing the System

### Test IOC Extraction
```php
php -r "
require_once 'src/IOCExtractor.php';
require_once 'src/Logger.php';

\$logger = new Logger(['file' => 'php://stdout', 'level' => 'DEBUG']);
\$extractor = new IOCExtractor(\$logger);

\$text = 'Found malware at hxxp://evil[.]com IP: 192.0.2.1 Hash: d41d8cd98f00b204e9800998ecf8427e';
\$iocs = \$extractor->extract(\$text);

print_r(\$iocs);
"
```

### Test Enrichment
```bash
# Run monitor with enrichment enabled
php monitor.php --once

# View enriched data in database
sqlite3 data/monitoring.db "SELECT * FROM enrichment_data LIMIT 10;"
```

### Export to STIX
```bash
# Export recent findings
php -r "
require_once 'config.php';
require_once 'src/DatabaseManager.php';
require_once 'src/Logger.php';
require_once 'src/EnhancedSTIXExporter.php';

\$config = require 'config.php';
\$logger = new Logger(\$config['logging']);
\$db = new DatabaseManager(\$config, \$logger);
\$exporter = new EnhancedSTIXExporter(\$config, \$logger, \$db);

\$findings = \$db->getRecentFindings(10);
\$filepath = \$exporter->exportToFile(\$findings, 'export_' . date('Y-m-d') . '.json');

echo \"Exported to: \$filepath\n\";
"
```

---

## 🎨 Best Practices

### API Key Management
1. **Never commit API keys** to version control
2. Use environment variables for all secrets
3. Rotate keys regularly
4. Use separate keys for dev/prod

### Rate Limiting
1. Enable caching to reduce API calls
2. Monitor rate limit warnings in logs
3. Prioritize enrichment for high-risk findings
4. Use free APIs (ThreatFox, URLhaus) first

### Performance Optimization
1. Adjust `cache_ttl` based on your needs (default 24h)
2. Limit IOC enrichment per finding (default: 3 IPs, 3 domains, 2 URLs, 2 hashes)
3. Enable parallel processing if supported
4. Use database indexes for faster queries

### Security
1. Keep SSL/TLS verification enabled
2. Validate all enrichment data
3. Sanitize data before export
4. Use TLP markings appropriately

---

## 📚 Additional Resources

- **STIX 2.1 Specification**: https://docs.oasis-open.org/cti/stix/v2.1/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **IOC Extraction Best Practices**: https://github.com/malicialab/iocsearcher
- **Threat Intelligence Platforms**: https://www.misp-project.org/

---

## 🆘 Troubleshooting

### Enrichment Not Working
1. Verify API keys are set correctly: `env | grep API_KEY`
2. Check logs: `tail -f logs/monitors.log`
3. Test individual APIs manually
4. Verify rate limits aren't exceeded

### STIX Export Failing
1. Ensure `exports/` directory exists and is writable
2. Check finding data has required fields
3. Validate STIX output with STIX validator tools

### High Memory Usage
1. Reduce `cache_ttl` to clear cache more frequently
2. Limit number of findings processed per run
3. Disable unused enrichment APIs
4. Increase `monitoring.interval_seconds`

---

## 📝 Changelog

### Version 2.0 - November 2024
- ✅ Added 6 new enrichment APIs (AlienVault OTX, ThreatFox, URLhaus, GreyNoise, PhishTank, Pulsedive)
- ✅ Implemented advanced IOC extraction engine
- ✅ Created enhanced enrichment manager with risk scoring
- ✅ Added STIX 2.1 export with MITRE ATT&CK mapping
- ✅ Improved connection handling with retries and SSL verification
- ✅ Enhanced error handling across all components

---

**For more information, consult the main README.md or open an issue on GitHub.**
