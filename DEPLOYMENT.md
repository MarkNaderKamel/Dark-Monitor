# Deployment Guide for Hostinger

This guide provides specific instructions for deploying the Security Monitoring System on Hostinger web hosting.

## Pre-Deployment Checklist

- [ ] PHP 8.1+ available on your Hostinger plan
- [ ] Telegram bot token obtained from @BotFather
- [ ] Email account configured for notifications (optional)
- [ ] SSH or FTP access to your Hostinger account
- [ ] Domain/subdomain for the monitoring system (optional)

## Step 1: Upload Files to Hostinger

### Via FTP (FileZilla, etc.)

1. Connect to your Hostinger account via FTP
2. Navigate to `public_html` or your specific domain folder
3. Create a new directory: `security-monitor/`
4. Upload all project files:
   ```
   security-monitor/
   ├── monitor.php
   ├── config.php
   ├── run_demo.php
   ├── view_findings.php
   ├── check_status.php
   ├── src/
   │   ├── Logger.php
   │   ├── HttpClient.php
   │   ├── TelegramMonitor.php
   │   ├── WebScraper.php
   │   ├── DarkWebMonitor.php
   │   └── Notifier.php
   ├── README.md
   ├── SETUP.md
   └── .gitignore
   ```

### Via SSH (if available)

```bash
# Connect via SSH
ssh username@your-domain.com

# Navigate to web directory
cd public_html

# Create directory
mkdir security-monitor
cd security-monitor

# Upload files using git or scp
git clone <your-repository> .
# OR
# Upload files via scp from local machine
```

## Step 2: Set Directory Permissions

Make sure these directories exist and are writable:

```bash
cd ~/public_html/security-monitor

# Create directories
mkdir -p logs data cache

# Set permissions
chmod 755 logs
chmod 755 data
chmod 755 cache

# Ensure PHP files are executable
chmod 644 *.php
chmod 644 src/*.php
```

## Step 3: Configure Environment Variables

### Method 1: Using .htaccess (Recommended for Hostinger)

Create `.htaccess` file in the `security-monitor/` directory:

```apache
# Deny web access to sensitive files
<Files "config.php">
    Require all denied
</Files>

<Files "*.log">
    Require all denied
</Files>

# Set environment variables
SetEnv TELEGRAM_BOT_TOKEN "your_bot_token_here"
SetEnv SMTP_USER "your_email@gmail.com"
SetEnv SMTP_PASSWORD "your_app_password"
SetEnv NOTIFY_EMAIL "recipient@example.com"
SetEnv DEBUG_MODE "false"
```

### Method 2: Using PHP Configuration

Edit `config.php` directly (less secure):

```php
'telegram' => [
    'bot_token' => 'your_bot_token_here', // Direct configuration
],
```

**Note:** Keep config.php outside the web root for better security.

## Step 4: Test the Installation

### Via SSH

```bash
cd ~/public_html/security-monitor

# Test configuration
php monitor.php --test

# Run single iteration
php monitor.php --once

# Check logs
cat logs/monitors.log
cat data/findings.json
```

### Via Web (temporary test script)

Create `test.php` (remove after testing):

```php
<?php
echo "PHP Version: " . phpversion() . "\n";
echo "cURL Available: " . (function_exists('curl_init') ? 'Yes' : 'No') . "\n";
echo "Directory Permissions:\n";
echo "  logs/ : " . (is_writable(__DIR__ . '/logs') ? 'Writable' : 'Not writable') . "\n";
echo "  data/ : " . (is_writable(__DIR__ . '/data') ? 'Writable' : 'Not writable') . "\n";
```

Access: `https://yourdomain.com/security-monitor/test.php`

**Remember to delete test.php after testing!**

## Step 5: Set Up Cron Job

Hostinger provides a cron job interface in the control panel.

### Access Cron Jobs

1. Log into Hostinger hPanel
2. Navigate to "Advanced" → "Cron Jobs"
3. Click "Create Cron Job"

### Configure Cron Job

**For hourly monitoring:**
```
Minute: 0
Hour: *
Day: *
Month: *
Weekday: *
Command: /usr/bin/php ~/public_html/security-monitor/monitor.php --once
```

**For every 30 minutes:**
```
Minute: */30
Hour: *
Day: *
Month: *
Weekday: *
Command: /usr/bin/php ~/public_html/security-monitor/monitor.php --once
```

**For twice daily (8 AM and 8 PM):**
```
Minute: 0
Hour: 8,20
Day: *
Month: *
Weekday: *
Command: /usr/bin/php ~/public_html/security-monitor/monitor.php --once
```

### Find PHP Path

If `/usr/bin/php` doesn't work, find the correct path:

```bash
which php
# Or
whereis php
```

Common Hostinger PHP paths:
- `/usr/bin/php`
- `/opt/alt/php81/usr/bin/php`
- `/opt/alt/php82/usr/bin/php`

## Step 6: Secure the Installation

### 1. Protect Sensitive Directories

Create `.htaccess` in `logs/` directory:

```apache
# Deny all web access
Require all denied
```

Create `.htaccess` in `data/` directory:

```apache
# Deny all web access
Require all denied
```

### 2. Move Outside Web Root (Recommended)

For maximum security, move the entire system outside `public_html`:

```bash
# Create directory outside web root
mkdir ~/security-monitor
mv ~/public_html/security-monitor/* ~/security-monitor/

# Update cron job path
# Command: /usr/bin/php ~/security-monitor/monitor.php --once
```

### 3. Secure File Permissions

```bash
# Restrict access to config file
chmod 600 config.php

# Ensure logs aren't world-readable
chmod 700 logs
chmod 700 data
```

### 4. Enable HTTPS

Ensure your domain uses HTTPS (Hostinger provides free SSL certificates):
1. Go to hPanel → SSL
2. Enable SSL for your domain
3. Force HTTPS in .htaccess (if placing web interface)

## Step 7: Monitoring and Maintenance

### View Findings

Create a simple web interface (password protected):

```php
<?php
// admin.php - Password protected findings viewer
session_start();

$password = 'your_secure_password_here'; // Change this!

if (!isset($_SESSION['authenticated'])) {
    if (isset($_POST['password']) && $_POST['password'] === $password) {
        $_SESSION['authenticated'] = true;
    } else {
        ?>
        <form method="post">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
        <?php
        exit;
    }
}

require 'view_findings.php';
?>
```

### Check System Status

```bash
# Via SSH
cd ~/security-monitor
php check_status.php

# Check cron job logs (Hostinger usually provides cron log)
# Check in hPanel → Cron Jobs → View Logs
```

### Log Rotation

The system automatically rotates logs when they exceed 100 MB. Old logs are saved as backups.

To manually clean old logs:

```bash
cd ~/security-monitor/logs
rm *.bak
```

### Regular Maintenance Tasks

**Weekly:**
- Check logs for errors
- Review findings for false positives
- Verify cron job is running

**Monthly:**
- Update keywords in config.php
- Review and update monitored sources
- Check disk space usage
- Backup findings.json

**As Needed:**
- Update PHP version
- Rotate access credentials
- Add new Telegram channels

## Step 8: Troubleshooting

### Cron Job Not Running

Check:
1. PHP path is correct: `which php`
2. File permissions: `ls -la monitor.php`
3. Cron job syntax is correct
4. View cron job logs in Hostinger hPanel

### Permission Denied Errors

```bash
# Fix permissions
chmod 755 logs data cache
chmod 644 *.php src/*.php

# Check ownership
ls -la

# If needed, change ownership (replace 'username')
chown -R username:username ~/security-monitor
```

### Memory Limit Issues

Create `php.ini` or `.user.ini` in project directory:

```ini
memory_limit = 256M
max_execution_time = 300
```

### SSL Certificate Errors

If you get SSL errors when scraping HTTPS sites:

1. Update CA certificates (contact Hostinger support)
2. Or, as last resort, disable for specific sites in config.php:
   ```php
   'advanced' => [
       'verify_ssl' => false, // Only if necessary
   ],
   ```

### Email Not Sending

For Hostinger, you may need to use Hostinger's SMTP:

```php
'notifications' => [
    'email' => [
        'smtp_host' => 'smtp.hostinger.com',
        'smtp_port' => 587,
        'smtp_user' => 'your@domain.com',
        'smtp_password' => 'your_email_password',
    ],
],
```

## Step 9: Optimization

### Reduce Resource Usage

Edit `config.php`:

```php
'monitoring' => [
    'interval_seconds' => 7200, // Every 2 hours instead of 1
    'timeout' => 20, // Reduce timeout
],

'advanced' => [
    'rate_limit_delay' => 3, // Longer delays between requests
],
```

### Disable Unused Sources

In `config.php`, set `enabled => false` for sources you don't need:

```php
'clearweb_sources' => [
    [
        'name' => 'XSS.is',
        'url' => 'https://xss.is',
        'enabled' => false, // Disable this source
    ],
],
```

## Step 10: Monitoring via Email Reports

Set up daily summary emails by creating a separate cron job:

```bash
# daily_summary.php
<?php
require 'config.php';
require 'src/Logger.php';
require 'src/Notifier.php';

$config = require 'config.php';
$logger = new Logger($config);
$notifier = new Notifier($config, $logger);

// Load findings from last 24 hours
$findings = json_decode(file_get_contents('data/findings.json'), true);
$yesterday = strtotime('-24 hours');
$recent = array_filter($findings, function($f) use ($yesterday) {
    return strtotime($f['timestamp']) > $yesterday;
});

if (!empty($recent)) {
    $notifier->notify($recent);
}
?>
```

Add cron job for daily 9 AM report:

```
Minute: 0
Hour: 9
Day: *
Month: *
Weekday: *
Command: /usr/bin/php ~/security-monitor/daily_summary.php
```

## Backup Strategy

### Manual Backup

```bash
# Create backup
cd ~
tar -czf security-monitor-backup-$(date +%Y%m%d).tar.gz security-monitor/

# Download via FTP or save to another location
```

### Automated Backup (Cron)

```bash
# backup.sh
#!/bin/bash
cd ~
tar -czf backups/monitor-$(date +%Y%m%d).tar.gz security-monitor/data/ security-monitor/logs/
find backups/ -name "monitor-*.tar.gz" -mtime +30 -delete
```

Cron job:

```
Minute: 0
Hour: 2
Day: *
Month: *
Weekday: 0
Command: /bin/bash ~/security-monitor/backup.sh
```

## Support

For Hostinger-specific issues:
- Contact Hostinger support via hPanel
- Check Hostinger knowledge base
- Verify PHP version compatibility

For system-specific issues:
- Check `logs/monitors.log`
- Run `php monitor.php --test`
- Review `SETUP.md` and `README.md`

---

## Quick Reference Commands

```bash
# Test system
php monitor.php --test

# Run once
php monitor.php --once

# View status
php check_status.php

# View findings
php view_findings.php

# Check logs
tail -f logs/monitors.log

# Monitor cron job
grep CRON /var/log/syslog  # If available
```

---

**Your Security Monitoring System is now deployed on Hostinger!**

For questions or issues, refer to README.md and SETUP.md.
