# API Reference - Threat Intelligence Enrichment Services

## Quick Setup Guide

### Getting Your API Keys

This guide will walk you through obtaining free API keys for all supported threat intelligence services.

---

## 🆓 APIs That Don't Require Keys

### 1. ThreatFox (abuse.ch)
**Status**: ✅ **No API key needed**

**What it does**: Tracks malware C2 infrastructure, IOCs, and malware families

**Setup**: None required - works out of the box!

```bash
# No environment variable needed
```

**Rate Limits**: None (community service)

---

### 2. URLhaus (abuse.ch)
**Status**: ✅ **No API key needed**

**What it does**: Tracks malicious URLs distributing malware

**Setup**: None required - works immediately!

```bash
# No environment variable needed
```

**Rate Limits**: None (community service)

---

## 🔑 Free APIs (Registration Required)

### 3. VirusTotal
**Status**: 🔓 **Free tier available**

**What it does**: Aggregates 70+ antivirus engines for file/URL/domain/IP analysis

#### How to Get Your Key:
1. Visit https://www.virustotal.com/gui/join-us
2. Click "Sign Up" (top right)
3. Create account with email
4. Go to your profile → API Key
5. Copy the key

#### Setup:
```bash
VIRUSTOTAL_API_KEY=your_64_character_key_here
```

**Rate Limits**: 4 requests/minute (free), 500 requests/day

**Upgrade**: Premium plans available for higher limits

---

### 4. AbuseIPDB
**Status**: 🔓 **Free tier: 1,000 checks/day**

**What it does**: Community IP abuse reporting and blacklist checking

#### How to Get Your Key:
1. Visit https://www.abuseipdb.com/register
2. Sign up with email
3. Verify your email
4. Go to Account → API
5. Generate an API key

#### Setup:
```bash
ABUSEIPDB_API_KEY=your_80_character_key_here
```

**Rate Limits**: 1,000 checks/day (free tier)

**Upgrade**: Paid plans for 3,000-100,000 checks/day

---

### 5. AlienVault OTX
**Status**: 🔓 **Completely free**

**What it does**: Community-powered threat intelligence with 19M+ IOCs

#### How to Get Your Key:
1. Visit https://otx.alienvault.com/
2. Click "Login/Signup" (top right)
3. Create free account
4. Go to Settings → API Integration
5. Copy your OTX Key

#### Setup:
```bash
ALIENVAULT_OTX_API_KEY=your_64_character_key_here
```

**Rate Limits**: None (unlimited for free users)

**Best Feature**: Pulse tracking for real-time threat campaigns

---

### 6. GreyNoise
**Status**: 🔓 **Community API free** (Enhanced API available)

**What it does**: Identifies benign internet scanners vs. malicious IPs

#### Community API (No Key Required):
```bash
# No key needed for basic functionality
# Uses quickCheck() method automatically
```

#### Enhanced API (Optional):
1. Visit https://www.greynoise.io/plans
2. Sign up for Community account (free)
3. Go to Account → API Key
4. Copy your key

#### Setup for Enhanced Features:
```bash
GREYNOISE_API_KEY=your_key_here
```

**Rate Limits**: 
- Community API: No key required, limited fields
- Free tier: 50 requests/minute with API key

**Best Feature**: Noise reduction - filters out benign scanners

---

### 7. PhishTank
**Status**: 🔓 **Free with registration**

**What it does**: Community-verified phishing URL database

#### How to Get Your Key:
1. Visit https://www.phishtank.com/
2. Click "Join" → "Register"
3. Create account and verify email
4. Go to "Developer Information"
5. Click "Manage Applications"
6. Create new application
7. Copy your API key

#### Setup:
```bash
PHISHTANK_API_KEY=your_key_here
```

**Rate Limits**: 
- 100 queries/hour (free tier)
- No bulk queries on free plan

**Note**: Must wait for application approval (usually instant)

---

### 8. Pulsedive
**Status**: 🔓 **Generous free tier**

**What it does**: OSINT aggregator with risk scoring for IOCs

#### How to Get Your Key:
1. Visit https://pulsedive.com/register
2. Create free account
3. Verify email
4. Go to Account → API
5. Generate API key

#### Setup:
```bash
PULSEDIVE_API_KEY=your_key_here
```

**Rate Limits**: 30 requests/minute (free tier)

**Best Feature**: Comprehensive risk scoring and threat categorization

---

## 💰 Paid APIs with Free Tiers

### 9. Shodan
**Status**: 💵 **Limited free tier**

**What it does**: Internet-wide device scanner, port detection, vulnerability tracking

#### How to Get Your Key:
1. Visit https://account.shodan.io/register
2. Create free account
3. Go to Account
4. Copy your API key from the overview

#### Setup:
```bash
SHODAN_API_KEY=your_32_character_key_here
```

**Rate Limits**: 
- 100 queries/month (free)
- 1 query/second rate limit

**Upgrade**: Membership ($49/lifetime) for unlimited queries

**Best Feature**: Discover exposed assets and vulnerabilities

---

### 10. Have I Been Pwned (HIBP)
**Status**: 💵 **Paid API**

**What it does**: Check emails/passwords against known data breaches

#### How to Get Your Key:
1. Visit https://haveibeenpwned.com/API/Key
2. Purchase API key ($3.50/month)
3. Key sent to your email
4. Enter payment details

#### Setup:
```bash
HIBP_API_KEY=your_key_here
```

**Rate Limits**: 10 requests/minute

**Note**: This is the only truly paid API, supports the project

**Alternative**: Use HIBP Pwned Passwords API (free, no key) for password checking only

---

## 📝 Complete Environment Setup

Once you have your API keys, set them all up:

### For Replit:
1. Click "Secrets" (lock icon) in left sidebar
2. Add each key-value pair:

```
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
ALIENVAULT_OTX_API_KEY=your_otx_key
GREYNOISE_API_KEY=your_greynoise_key
PHISHTANK_API_KEY=your_phishtank_key
PULSEDIVE_API_KEY=your_pulsedive_key
SHODAN_API_KEY=your_shodan_key
```

### For Local Development:
Create a `.env` file in the project root:

```bash
# Telegram Bot
TELEGRAM_BOT_TOKEN=123456:ABC-DEF...

# Enrichment APIs
VIRUSTOTAL_API_KEY=your_vt_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
ALIENVAULT_OTX_API_KEY=your_otx_key
GREYNOISE_API_KEY=your_greynoise_key
PHISHTANK_API_KEY=your_phishtank_key
PULSEDIVE_API_KEY=your_pulsedive_key
SHODAN_API_KEY=your_shodan_key
HIBP_API_KEY=your_hibp_key

# Notifications
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
```

---

## 🎯 Recommended Setup

### Minimum (Free & No Keys):
```bash
TELEGRAM_BOT_TOKEN=your_token
# ThreatFox and URLhaus work automatically!
```

### Recommended (All Free):
```bash
TELEGRAM_BOT_TOKEN=your_token
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
ALIENVAULT_OTX_API_KEY=your_key
PULSEDIVE_API_KEY=your_key
# GreyNoise Community API works without key
# ThreatFox and URLhaus included automatically
```

### Maximum Coverage (Including Paid):
```bash
# All of the above, plus:
SHODAN_API_KEY=your_key
GREYNOISE_API_KEY=your_key  # Enhanced features
PHISHTANK_API_KEY=your_key
HIBP_API_KEY=your_key  # Optional, paid
```

---

## 🧪 Testing Your Setup

### Test Individual APIs:

```bash
# Test VirusTotal
php -r "
require_once 'src/VirusTotalEnricher.php';
require_once 'src/Logger.php';
require_once 'src/DatabaseManager.php';

\$config = require 'config.php';
\$logger = new Logger(\$config['logging']);
\$db = new DatabaseManager(\$config, \$logger);
\$vt = new VirusTotalEnricher(\$config, \$logger, \$db);

echo 'VirusTotal enabled: ' . (\$vt->isEnabled() ? 'YES' : 'NO') . \"\n\";

if (\$vt->isEnabled()) {
    \$result = \$vt->enrichIP('8.8.8.8');
    print_r(\$result);
}
"

# Test AbuseIPDB
php -r "
require_once 'src/AbuseIPDBEnricher.php';
require_once 'src/Logger.php';

\$config = require 'config.php';
\$logger = new Logger(\$config['logging']);
\$abuseipdb = new AbuseIPDBEnricher(\$config, \$logger);

echo 'AbuseIPDB enabled: ' . (\$abuseipdb->isEnabled() ? 'YES' : 'NO') . \"\n\";

if (\$abuseipdb->isEnabled()) {
    \$result = \$abuseipdb->checkIP('8.8.8.8');
    print_r(\$result);
}
"
```

### Check All APIs at Once:
```bash
php test_enrichment.php
```

---

## 📊 Cost Analysis

| Service | Free Tier | Cost to Upgrade | Best For |
|---------|-----------|----------------|----------|
| ThreatFox | ✅ Unlimited | Free forever | Malware IOCs |
| URLhaus | ✅ Unlimited | Free forever | Malicious URLs |
| AlienVault OTX | ✅ Unlimited | Free forever | Threat feeds |
| GreyNoise (Community) | ✅ Unlimited | $0 | Noise filtering |
| AbuseIPDB | 1,000/day | $20/month (3k/day) | IP reputation |
| VirusTotal | 4 req/min | $0 (public), Premium varies | Malware analysis |
| Pulsedive | 30 req/min | Contact for pricing | Risk scoring |
| PhishTank | 100/hour | Free with limits | Phishing detection |
| Shodan | 100/month | $49 lifetime | Asset discovery |
| GreyNoise (Enhanced) | 50 req/min | $50/month | Advanced features |
| HIBP | N/A | $3.50/month | Breach checking |

**Total Monthly Cost (All Free Tiers)**: $0
**Total Monthly Cost (All Paid)**: ~$73.50

---

## 🔒 Security Best Practices

### API Key Security:
1. **Never commit keys to Git**
   - Add `.env` to `.gitignore`
   - Use environment variables only

2. **Rotate keys regularly**
   - Every 90 days minimum
   - Immediately if compromised

3. **Use separate keys for dev/prod**
   - Different keys for testing
   - Different keys for production

4. **Monitor usage**
   - Check API dashboards regularly
   - Set up alerts for unusual activity

### Rate Limit Management:
1. **Enable caching** (24h default)
2. **Prioritize critical findings**
3. **Use free APIs first** (ThreatFox, URLhaus)
4. **Batch requests when possible**

---

## 📞 Support & Resources

### Getting Help:
- **VirusTotal**: https://support.virustotal.com/
- **AbuseIPDB**: support@abuseipdb.com
- **AlienVault**: https://otx.alienvault.com/docs
- **GreyNoise**: https://docs.greynoise.io/
- **Shodan**: https://help.shodan.io/

### Documentation:
- **API Docs**: See individual service websites
- **Rate Limits**: Check each API's documentation
- **Upgrade Plans**: Review pricing on service websites

---

**Need help? Check the logs at `logs/monitors.log` or run `php monitor.php --test`**
