# Quick Start Guide

Get your Security Monitoring System running in 5 minutes!

## For Immediate Testing (Replit)

The system is **already running** in demo mode! Check the console output.

```bash
# View the demo
# (Already running in the workflow)

# Check findings
php view_findings.php

# Check system status
php check_status.php
```

## For Production Use (3 Steps)

### 1. Get a Telegram Bot Token (2 minutes)

1. Open Telegram, search for `@BotFather`
2. Send: `/newbot`
3. Follow instructions (choose name and username)
4. Copy the token (looks like: `123456789:ABCdefGHI...`)

### 2. Set Environment Variables

**On Replit:**
- Click Secrets (🔒 icon)
- Add: `TELEGRAM_BOT_TOKEN` = `your_token_here`

**On Hostinger:**
- Use cPanel or create `.htaccess` (see DEPLOYMENT.md)

**Locally:**
```bash
export TELEGRAM_BOT_TOKEN="your_token_here"
export SMTP_USER="your_email@gmail.com"        # Optional
export SMTP_PASSWORD="your_app_password"       # Optional
export NOTIFY_EMAIL="recipient@example.com"    # Optional
```

### 3. Run the Monitor

```bash
# Test configuration
php monitor.php --test

# Run once (for testing)
php monitor.php --once

# Continuous monitoring
php monitor.php
```

## Customize Keywords (Optional)

Edit `config.php`:

```php
'keywords' => [
    'leak',
    'database',
    'dump',
    'breach',
    'yourcompany.com',    // Add your domain
    'your-product-name',  // Add your product
],
```

## Deploy to Hostinger

1. Upload all files via FTP to `public_html/security-monitor/`
2. Set permissions: `chmod 755 logs data cache`
3. Add cron job in Hostinger cPanel:
   ```
   0 * * * * php ~/public_html/security-monitor/monitor.php --once
   ```
4. Done! Monitor runs every hour automatically.

**Full deployment guide:** See [DEPLOYMENT.md](DEPLOYMENT.md)

## View Results

```bash
# View all findings
php view_findings.php

# Check logs
cat logs/monitors.log

# Check status
php check_status.php
```

## Monitoring Sources

The system automatically monitors:

**Clear Web Forums:**
- XSS.is, Exploit.in, BHF.io, Altenen, Cracked, Nulled
- BreachForums, DarkForums, Ransomware.live

**Telegram Channels:** (24+ channels)
- @mooncloudlogs, @observercloud, @dataleakmonitoring
- @bidencash, @baseleak, and many more

**Dark Web:** (Optional, requires Tor)
- Dread, CryptBB, and other .onion sites

## Troubleshooting

**"Telegram not configured"**
→ Set `TELEGRAM_BOT_TOKEN` environment variable

**"Permission denied on logs"**
→ Run: `chmod 755 logs data cache`

**"Email not sending"**
→ Use Gmail app password, not regular password
→ See SETUP.md for detailed email configuration

## Next Steps

1. ✅ Test: `php monitor.php --test`
2. ✅ Configure: Edit `config.php` for your needs
3. ✅ Deploy: Upload to Hostinger (see DEPLOYMENT.md)
4. ✅ Monitor: Check findings regularly

## Documentation

- **README.md** - Overview and features
- **SETUP.md** - Detailed setup instructions
- **DEPLOYMENT.md** - Hostinger deployment guide
- **CONTRIBUTING.md** - How to contribute
- **config.php** - All configuration options

## Support

Run the test command to diagnose issues:
```bash
php monitor.php --test
```

Check logs for errors:
```bash
cat logs/monitors.log
```

---

**🎯 Your security monitoring system is ready to protect you from data breaches!**

Start with demo mode (already running) → Configure Telegram → Deploy to production
