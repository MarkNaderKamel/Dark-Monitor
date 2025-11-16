# Detailed Setup Guide

This guide provides step-by-step instructions for setting up the Security Monitoring System on different platforms.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Telegram Bot Setup](#telegram-bot-setup)
3. [Email Setup (Gmail)](#email-setup-gmail)
4. [Platform-Specific Setup](#platform-specific-setup)
   - [Replit](#setup-on-replit)
   - [Hostinger](#setup-on-hostinger)
   - [Local Development](#local-development)
5. [Dark Web Monitoring](#dark-web-monitoring-optional)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- PHP 8.1 or higher (included on Replit and most hosting platforms)
- Basic understanding of environment variables
- (Optional) Telegram account for channel monitoring
- (Optional) Email account for notifications

---

## Telegram Bot Setup

Follow these steps to create a Telegram bot for channel monitoring:

### Step 1: Create the Bot

1. Open Telegram on your phone or desktop
2. Search for `@BotFather` (official bot for creating bots)
3. Start a chat with BotFather
4. Send the command: `/newbot`
5. BotFather will ask for a name - enter any name (e.g., "My Monitor Bot")
6. BotFather will ask for a username - must end with 'bot' (e.g., "my_monitor_bot")

### Step 2: Get Your Bot Token

After creating the bot, BotFather will provide a **token** that looks like:
```
123456789:ABCdefGHIjklMNOpqrsTUVwxyz
```

**IMPORTANT:** Keep this token secret! Anyone with this token can control your bot.

### Step 3: Add Bot to Channels

1. Open each Telegram channel you want to monitor
2. Add your bot as a member (click channel name → Add Members → search for your bot)
3. Some channels may require admin approval

### Step 4: Configure Token

Add the token to your environment variables as `TELEGRAM_BOT_TOKEN`.

---

## Email Setup (Gmail)

To receive email alerts using Gmail:

### Step 1: Enable 2-Factor Authentication

1. Go to your Google Account settings
2. Navigate to Security
3. Enable 2-Step Verification

### Step 2: Generate App Password

1. Go to: https://myaccount.google.com/apppasswords
2. Select "Mail" as the app
3. Select "Other" as the device, enter "Monitoring System"
4. Click "Generate"
5. Copy the 16-character password (remove spaces)

### Step 3: Configure Environment Variables

Set these variables:
```
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_16_char_app_password
NOTIFY_EMAIL=where_to_send_alerts@example.com
```

---

## Platform-Specific Setup

### Setup on Replit

#### Step 1: Create a New Repl

1. Go to https://replit.com
2. Click "Create Repl"
3. Select "PHP" as the template
4. Name your repl (e.g., "security-monitor")

#### Step 2: Upload Files

1. Delete the default `index.php` file
2. Upload all project files:
   - `monitor.php`
   - `config.php`
   - `README.md`
   - `src/` folder with all PHP files

Or use Git:
```bash
git clone <your-repo-url> .
```

#### Step 3: Configure Secrets

1. Click the "Secrets" tab (lock icon) in the left sidebar
2. Add your secrets:
   - Key: `TELEGRAM_BOT_TOKEN`, Value: `your_token_here`
   - Key: `SMTP_USER`, Value: `your_email@gmail.com`
   - Key: `SMTP_PASSWORD`, Value: `your_app_password`
   - Key: `NOTIFY_EMAIL`, Value: `recipient@example.com`

#### Step 4: Run the System

In the Shell tab, run:
```bash
php monitor.php --test
```

If the test passes, start monitoring:
```bash
php monitor.php
```

#### Step 5: Keep Repl Always Running (Optional)

Replit free tier may stop idle repls. To keep it running:
1. Use Replit's "Always On" feature (requires paid plan)
2. Or, set up an external ping service to keep it active

---

### Setup on Hostinger

#### Step 1: Upload Files via FTP

1. Connect to your Hostinger account via FTP (use FileZilla or similar)
2. Navigate to `public_html` or your domain folder
3. Create a new folder: `monitor/`
4. Upload all project files to this folder

#### Step 2: Set Directory Permissions

Make sure these directories are writable:
```
chmod 755 logs/
chmod 755 data/
chmod 755 cache/
```

#### Step 3: Configure Environment Variables

**Option A: Using .env file (not recommended for production)**
```bash
# Create .env file
echo "TELEGRAM_BOT_TOKEN=your_token" > .env
echo "SMTP_USER=your_email@gmail.com" >> .env
# etc.
```

**Option B: Using PHP-FPM environment (recommended)**

1. Log into your Hostinger control panel
2. Go to "Advanced" → "PHP Configuration"
3. Add environment variables in the PHP settings

**Option C: Using cron environment**

Set variables directly in crontab:
```
TELEGRAM_BOT_TOKEN=your_token
SMTP_USER=your_email@gmail.com
0 * * * * cd /home/username/public_html/monitor && php monitor.php --once
```

#### Step 4: Set Up Cron Job

1. In Hostinger control panel, go to "Advanced" → "Cron Jobs"
2. Add a new cron job:
   ```
   0 * * * * cd /home/username/public_html/monitor && php monitor.php --once
   ```
   This runs every hour at the top of the hour.

3. For more frequent monitoring (every 30 minutes):
   ```
   */30 * * * * cd /home/username/public_html/monitor && php monitor.php --once
   ```

#### Step 5: Test the Setup

SSH into your server (if available) and run:
```bash
cd /path/to/monitor
php monitor.php --test
```

Or check the logs after the first cron run:
```bash
cat logs/monitors.log
```

---

### Local Development

#### Step 1: Install PHP

**Windows:**
1. Download PHP from https://windows.php.net/download/
2. Extract to `C:\php`
3. Add to PATH

**macOS:**
```bash
brew install php
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install php8.1 php8.1-curl php8.1-mbstring
```

#### Step 2: Clone Repository

```bash
git clone <your-repo-url>
cd security-monitor
```

#### Step 3: Set Environment Variables

**Windows (PowerShell):**
```powershell
$env:TELEGRAM_BOT_TOKEN = "your_token"
$env:SMTP_USER = "your_email@gmail.com"
$env:SMTP_PASSWORD = "your_app_password"
$env:NOTIFY_EMAIL = "recipient@example.com"
```

**Linux/macOS:**
```bash
export TELEGRAM_BOT_TOKEN="your_token"
export SMTP_USER="your_email@gmail.com"
export SMTP_PASSWORD="your_app_password"
export NOTIFY_EMAIL="recipient@example.com"
```

Or create a `.env` file and load it (requires additional code).

#### Step 4: Run the System

```bash
# Test configuration
php monitor.php --test

# Run once
php monitor.php --once

# Continuous monitoring
php monitor.php
```

---

## Dark Web Monitoring (Optional)

To enable dark web monitoring via Tor:

### Step 1: Install Tor

**Windows:**
1. Download Tor Browser from https://www.torproject.org
2. Install and run Tor Browser
3. Tor SOCKS proxy will run on `127.0.0.1:9050`

**Linux:**
```bash
sudo apt install tor
sudo systemctl start tor
sudo systemctl enable tor
```

**macOS:**
```bash
brew install tor
brew services start tor
```

### Step 2: Verify Tor is Running

```bash
# Check if Tor proxy is listening
curl --socks5 127.0.0.1:9050 https://check.torproject.org
```

### Step 3: Enable in Configuration

Edit `config.php`:
```php
'darkweb_sources' => [
    'enabled' => true,
    'tor_proxy' => '127.0.0.1:9050',
],
```

### Step 4: Add .onion URLs

Add sites to monitor:
```php
'sites' => [
    [
        'name' => 'Dread',
        'url' => 'dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion',
        'enabled' => true,
    ],
],
```

**Note:** .onion addresses change frequently. Use dark web search engines like Ahmia.fi to find current addresses.

---

## Testing

### Test Configuration

```bash
php monitor.php --test
```

This will check:
- ✓ Directory permissions
- ✓ Telegram bot configuration
- ✓ Email configuration
- ✓ Web sources
- ✓ HTTP connectivity

### Test Single Run

```bash
php monitor.php --once
```

Check `logs/monitors.log` for results.

### Test Notifications

Edit `config.php` temporarily to lower the keyword threshold or add a common word, then run once. You should receive notifications if configured.

---

## Troubleshooting

### Issue: "Telegram API error: Unauthorized"

**Solution:**
- Check that `TELEGRAM_BOT_TOKEN` is set correctly
- Verify token with BotFather
- Ensure no extra spaces in the token

### Issue: Email not sending

**Causes:**
1. App password not generated correctly
2. Firewall blocking port 587
3. SMTP credentials incorrect

**Solutions:**
- Regenerate Gmail app password
- Test SMTP with a simple PHP mail script
- Check server firewall rules

### Issue: "Permission denied" on logs

**Solution:**
```bash
chmod 755 logs/
chmod 755 data/
chmod 755 cache/
```

### Issue: High memory usage

**Solutions:**
- Increase monitoring interval in `config.php`
- Disable some sources
- Reduce number of Telegram channels

### Issue: Getting banned from sites

**Solutions:**
- Increase `rate_limit_delay` in config
- Reduce monitoring frequency
- Use rotating proxies (advanced)
- Respect robots.txt (enabled by default)

### Issue: No findings detected

**Checks:**
- Are keywords too specific?
- Are sources actually accessible?
- Check `logs/monitors.log` for errors
- Run with `DEBUG_MODE=true` for verbose output

---

## Advanced Configuration

### Custom Keywords

Add domain-specific keywords:
```php
'keywords' => [
    'leak', 'breach', 'dump',
    'yourcompany.com',
    'your-app-name',
    'specific-database-name',
],
```

### Webhook Notifications

Instead of email, send to a webhook:
```php
'notifications' => [
    'webhook' => [
        'enabled' => true,
        'url' => 'https://your-webhook-url.com/endpoint',
    ],
],
```

### Parallel Monitoring (Experimental)

Enable concurrent requests:
```php
'advanced' => [
    'parallel_requests' => true,
],
```

---

## Maintenance

### Log Rotation

Logs automatically rotate when they exceed the configured size (default 100 MB).

Old logs are saved as: `monitors.log.YYYY-MM-DD_HH-MM-SS.bak`

### Data Cleanup

Findings are stored in `data/findings.json`. The system keeps the last 10,000 findings.

To manually clean:
```bash
rm data/findings.json
```

### Updates

To update the system:
1. Backup your `config.php`
2. Pull latest code
3. Restore your config
4. Test with `--test` flag

---

## Security Checklist

- [ ] Environment variables set (no hardcoded secrets)
- [ ] `.env` file (if used) excluded from version control
- [ ] Log files outside web root or protected
- [ ] File permissions set correctly (755 for directories)
- [ ] Robots.txt compliance enabled
- [ ] Rate limiting configured
- [ ] Regular log review scheduled
- [ ] Legitimate use case and authorization

---

## Getting Help

1. Check logs: `cat logs/monitors.log`
2. Run test: `php monitor.php --test`
3. Enable debug: `export DEBUG_MODE=true`
4. Review configuration: `config.php`

---

**You're now ready to start monitoring! Run `php monitor.php` to begin.**
