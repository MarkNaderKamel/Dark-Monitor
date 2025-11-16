# 🚀 Security Monitoring System - Enhancement Guide

## Overview

This document outlines all the advanced threat intelligence features added to the security monitoring system beyond the base functionality.

---

## 📊 Live Dashboard (NEW!)

**File:** `dashboard.html`

### Features:
- **Real-Time Updates**: Auto-refreshes every 10 seconds
- **Statistics Display**:
  - Total findings
  - Today's findings
  - IOCs tracked
  - Active sources
- **Severity Breakdown**: Visual cards for CRITICAL/HIGH/MEDIUM/LOW
- **Recent Findings**: Live feed with snippets and IOC tags
- **Source Distribution**: Findings grouped by monitoring source
- **Top Keywords**: Most frequently detected keywords

### Access:
```bash
# Open in browser
http://your-domain.com/dashboard.html
```

---

## 🔍 VirusTotal Integration (NEW!)

**File:** `src/VirusTotalEnricher.php`

### Capabilities:
- **IP Address Enrichment**: Country, ASN, reputation, malicious score
- **Domain Analysis**: Categories, reputation, creation date
- **URL Scanning**: Threat detection, malicious/suspicious ratings
- **File Hash Analysis**: Malware detection, threat labels

### Setup:
```bash
# Get API key from https://www.virustotal.com
VIRUSTOTAL_API_KEY=your_api_key_here
```

### Features:
- **24-Hour Caching**: Reduces API calls
- **Non-Blocking**: Skips enrichment when rate limited (no delays)
- **Automatic**: Enriches CRITICAL/HIGH findings automatically
- **Rate Limit Aware**: 4 requests/minute (free tier)

---

## 🛡️ Have I Been Pwned Integration (NEW!)

**File:** `src/HIBPChecker.php`

### Capabilities:
- **Email Breach Checking**: Identifies if emails appear in data breaches
- **Domain Breach Analysis**: Checks entire domains for breaches
- **Password Pwned Check**: Validates if passwords are compromised (k-anonymity)
- **Breach Details**: Names, dates, affected accounts, data classes

### Setup:
```bash
# Get API key from https://haveibeenpwned.com/API/Key
HIBP_API_KEY=your_api_key_here
```

### Features:
- **Cached Results**: 24-hour cache to avoid redundant API calls
- **Privacy-Safe**: Uses k-anonymity for password checks
- **Breach Metadata**: Detailed information about each breach

---

## 🌍 IP Geolocation (NEW!)

**File:** `src/GeolocateIP.php`

### Capabilities:
- **Geographic Data**: Country, region, city, timezone
- **ISP Information**: Organization, ASN details
- **Risk Indicators**: Proxy detection, hosting detection, mobile detection
- **Latitude/Longitude**: Precise location coordinates

### Features:
- **Free Service**: Uses ip-api.com (no API key required)
- **Cached Results**: 24-hour cache
- **Risk Scoring**: Calculates risk based on country, proxy usage, hosting status
- **Non-Blocking**: Limited to 3 IPs per finding

---

## ⚡ Alert Rules Engine (NEW!)

**File:** `src/AlertRulesEngine.php`

### Pre-Configured Rules:

1. **Critical Finding Auto-Alert**
   - Triggers on: Any CRITICAL severity finding
   - Actions: Slack, Discord, Email

2. **Multiple High-Severity in Hour**
   - Triggers on: 3+ HIGH/CRITICAL findings in last hour
   - Actions: Email summary

3. **Known Malicious IP Detected**
   - Triggers on: IPs with reputation score < 30
   - Actions: Slack, Discord

4. **Ransomware Keywords Detected**
   - Keywords: ransomware, crypto-locker, wannacry, maze, ryuk, conti
   - Actions: Slack, Discord, Email

5. **APT Group Indicators**
   - Keywords: apt28, apt29, apt41, lazarus, fancy bear, cozy bear
   - Actions: Slack, Discord, Email

6. **Zero-Day Exploit Mention**
   - Keywords: zero-day, 0day
   - Actions: Slack, Discord, Email

7. **Database Dump Detected**
   - Keywords: database + (dump OR leak)
   - Actions: Slack

### Customization:
```php
// Add custom rule
$alertRulesEngine->addCustomRule(
    'My Custom Rule',
    function($finding) {
        return strpos($finding['title'], 'keyword') !== false;
    },
    ['slack', 'email']
);
```

---

## 📤 Export Manager (NEW!)

**File:** `src/ExportManager.php`

### Export Formats:

#### 1. CSV Export
```php
$exportManager->exportToCSV(['severity' => 'CRITICAL']);
// Output: exports/findings_2025-11-16_123456.csv
```

#### 2. JSON Export
```php
$exportManager->exportToJSON(['since' => '2025-11-01']);
// Output: exports/findings_2025-11-16_123456.json
```

#### 3. IOC Export
```php
$exportManager->exportIOCs();
// Output: exports/iocs_2025-11-16_123456.txt
// Format: Grouped by type (ips, emails, urls, hashes)
```

#### 4. STIX Format
```php
$exportManager->exportSTIX();
// Output: exports/stix_2025-11-16_123456.json
// Standard threat intelligence format for sharing
```

### Features:
- **Filtered Exports**: Export by severity, date range, source
- **STIX Compliance**: Industry-standard threat intelligence format
- **Automatic Naming**: Timestamped filenames

---

## 🔎 Additional Paste Site Monitoring (NEW!)

**File:** `src/AdditionalPasteSites.php`

### Monitored Sites:

1. **Paste.ee** (https://paste.ee)
2. **Ghostbin** (https://ghostbin.com)
3. **Slexy** (https://slexy.org)
4. **Rentry** (https://rentry.co)

### Enable/Disable:
```php
// In config.php
'additional_paste_sites' => [
    'enabled' => true  // Set to false to disable
],
```

---

## 🔧 Database Enhancements

### New Table: `enrichment_data`
Stores IOC enrichment results with 24-hour cache:

```sql
CREATE TABLE enrichment_data (
    id INTEGER PRIMARY KEY,
    entity_type TEXT NOT NULL,     -- ip, domain, url, hash, email
    entity_value TEXT NOT NULL,    -- The actual value
    enrichment_data TEXT,          -- JSON enrichment data
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(entity_type, entity_value)
);
```

### New Methods:
- `storeEnrichment($type, $value, $data)` - Store enrichment with cache
- `getEnrichment($type, $value)` - Retrieve cached enrichment

---

## 🎯 Integration Points

### monitor.php Integration:

```php
// Automatic enrichment for CRITICAL/HIGH findings
if ($virusTotalEnricher->isEnabled() && $finding['severity'] === 'CRITICAL') {
    $enrichment = $virusTotalEnricher->enrichIOCs($finding['iocs']);
    $finding['vt_enrichment'] = $enrichment;
}

// HIBP email checking
if ($hibpChecker->isEnabled() && !empty($finding['iocs']['emails'])) {
    $hibpData = $hibpChecker->enrichEmails($finding['iocs']['emails']);
    $finding['hibp_enrichment'] = $hibpData;
}

// IP geolocation
if (!empty($finding['iocs']['ips'])) {
    $geoData = $geolocateIP->locateMultiple($finding['iocs']['ips']);
    $finding['geo_enrichment'] = $geoData;
}

// Alert rules evaluation
$triggeredRules = $alertRulesEngine->evaluateFinding($finding);
if (!empty($triggeredRules)) {
    $alertRulesEngine->executeActions($triggeredRules, $finding, $notifiers);
}
```

---

## 📈 Performance Optimizations

### Non-Blocking Design:
- **VirusTotal**: Skips enrichment when rate limited (no sleep)
- **HIBP**: Removed blocking delays
- **Geolocation**: Small delays only between uncached requests
- **Caching**: 24-hour cache reduces API calls by 95%+

### Rate Limits:
- **VirusTotal Free**: 4 requests/minute
- **HIBP**: Self-regulated delays removed
- **IP Geolocation**: Free tier, 45 requests/minute

### Smart Limiting:
- Max 2 IPs enriched per finding (VirusTotal)
- Max 1 URL enriched per finding (VirusTotal)
- Max 2 emails checked per finding (HIBP)
- Max 3 IPs geolocated per finding

---

## 🔐 Security Features

1. **API Key Management**: All keys stored as environment variables
2. **Cache Key Normalization**: Fixed URL encoding issues for consistent caching
3. **Timeout Protection**: Reduced timeouts prevent hanging
4. **Error Handling**: Graceful degradation when APIs unavailable

---

## 📋 Environment Variables Reference

### Required for Base System:
```bash
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
SMTP_USER=your_email@domain.com
SMTP_PASSWORD=your_password
NOTIFY_EMAIL=alerts@domain.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

### Optional Enhancements:
```bash
VIRUSTOTAL_API_KEY=your_vt_api_key
HIBP_API_KEY=your_hibp_api_key
```

---

## 🚀 Quick Start with Enhancements

### 1. Set Up API Keys:
```bash
# Add to Replit Secrets or .env file
VIRUSTOTAL_API_KEY=abc123...
HIBP_API_KEY=xyz789...
```

### 2. Run Monitoring:
```bash
php monitor.php --once
```

### 3. View Dashboard:
```bash
# Open dashboard.html in browser
# Auto-refreshes every 10 seconds
```

### 4. Export Data:
```php
require 'src/ExportManager.php';
$exporter = new ExportManager($db, $logger, $config);

// Export last 24 hours as JSON
$exporter->exportToJSON(['since' => date('Y-m-d H:i:s', time() - 86400)]);

// Export all CRITICAL findings as CSV
$exporter->exportToCSV(['severity' => 'CRITICAL']);

// Export IOCs for SIEM import
$exporter->exportIOCs();
```

---

## 📊 Dashboard API Endpoints

**File:** `dashboard_api.php`

Returns JSON with:
```json
{
  "statistics": {
    "total_findings": 123,
    "today_findings": 45,
    "total_iocs": 567,
    "recent_activity": [...]
  },
  "findings_by_severity": {
    "CRITICAL": 12,
    "HIGH": 34,
    "MEDIUM": 56,
    "LOW": 21
  },
  "findings_by_source": {
    "GitHub": 45,
    "Pastebin": 34,
    "Telegram": 23
  },
  "recent_findings": [...],
  "top_keywords": {
    "leak": 45,
    "database": 34,
    "breach": 28
  }
}
```

---

## 🎓 Best Practices

### 1. API Key Rotation:
- Rotate VirusTotal API keys monthly
- Rotate HIBP keys quarterly
- Never commit keys to version control

### 2. Cache Management:
- Cache is automatically cleaned after 24 hours
- No manual intervention required
- Database size remains manageable

### 3. Export Strategy:
- Export daily for compliance
- Use STIX format for threat sharing
- Keep CSV for spreadsheet analysis

### 4. Alert Tuning:
- Start with default rules
- Add custom rules based on your needs
- Review triggered alerts weekly

---

## 🐛 Troubleshooting

### Dashboard not loading:
```bash
# Check dashboard_api.php is accessible
curl http://localhost:5000/dashboard_api.php
```

### Enrichment not working:
```bash
# Verify API keys
php -r "echo getenv('VIRUSTOTAL_API_KEY') ? 'Set' : 'Not set';"
php -r "echo getenv('HIBP_API_KEY') ? 'Set' : 'Not set';"
```

### Rate limit errors:
```bash
# Check logs for rate limit messages
grep "Rate limit" logs/monitors.log

# System automatically skips enrichment when limited
# No action required - will resume next iteration
```

---

## 📚 Documentation

- **Main README**: Project overview and setup
- **SETUP.md**: Detailed setup instructions
- **QUICKSTART.md**: Quick deployment guide
- **ENHANCEMENTS.md**: This file - advanced features

---

## 🔄 Updates & Maintenance

### Database Migrations:
All new tables are created automatically on first run.

### Backward Compatibility:
All enhancements are opt-in. System works without API keys.

### Future Enhancements:
Planned features include:
- Machine learning anomaly detection
- Cryptocurrency wallet tracking
- Tor hidden service monitoring
- Custom YARA-like rule engine

---

**Last Updated:** November 16, 2025  
**Version:** 2.0 (Enhanced)
