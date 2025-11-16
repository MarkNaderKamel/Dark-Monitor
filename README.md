# Security Monitoring System

A comprehensive threat intelligence monitoring system designed for cybersecurity professionals to detect mentions of data leaks and breaches across clear web forums, dark web sites, and Telegram channels.

## 🎯 Purpose

This system monitors various online sources for keywords related to:
- Database leaks
- Credential dumps
- Data breaches
- Compromised accounts
- Stolen data

It's designed for **security professionals, penetration testers, and threat intelligence teams** to stay informed about potential security threats.

## ✨ Features

- **Multi-Source Monitoring**
  - Clear web forums and websites
  - Telegram channels via Bot API
  - Dark web sites via Tor (optional)

- **Keyword Detection**
  - Configurable keyword list
  - Context-aware matching
  - Snippet extraction

- **Notifications**
  - Email alerts via SMTP
  - Webhook integration
  - Detailed findings log

- **Robust & Reliable**
  - Error handling and retry logic
  - Rate limiting
  - Robots.txt compliance
  - Log rotation

- **100% Free**
  - No paid APIs required
  - Uses only free services
  - Can run on Replit free tier or Hostinger

## 📋 Requirements

- PHP 8.1 or higher
- cURL extension (included in PHP)
- Internet connection
- (Optional) Tor for dark web monitoring

## 🚀 Quick Start

### 1. Clone or Upload Files

Upload all files to your server (Replit, Hostinger, or local machine).

### 2. Configure Environment Variables

Set the following environment variables:

```bash
# Required for Telegram monitoring
TELEGRAM_BOT_TOKEN=your_bot_token_here

# Optional: Email notifications
SMTP_USER=your_email@gmail.com
SMTP_PASSWORD=your_app_password
NOTIFY_EMAIL=recipient@example.com

# Optional: Debug mode
DEBUG_MODE=true
```

#### How to Create a Telegram Bot:

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` and follow the instructions
3. Choose a name and username for your bot
4. Copy the **bot token** provided by BotFather
5. Add the token to your environment variables as `TELEGRAM_BOT_TOKEN`
6. Add your bot to the channels you want to monitor

### 3. Configure Monitoring Sources

Edit `config.php` to customize:
- Keywords to search for
- Web sources to monitor
- Notification settings
- Monitoring interval

### 4. Run the System

```bash
# Test configuration
php monitor.php --test

# Run single iteration
php monitor.php --once

# Start continuous monitoring
php monitor.php
```

## 📁 Project Structure

```
.
├── monitor.php              # Main entry point
├── config.php               # Configuration file
├── README.md               # This file
├── SETUP.md                # Detailed setup guide
├── src/
│   ├── Logger.php          # Logging system
│   ├── HttpClient.php      # HTTP/cURL wrapper
│   ├── TelegramMonitor.php # Telegram monitoring
│   ├── WebScraper.php      # Web scraping
│   ├── DarkWebMonitor.php  # Dark web monitoring
│   └── Notifier.php        # Email/webhook notifications
├── logs/
│   └── monitors.log        # Main log file
├── data/
│   ├── findings.json       # All findings stored here
│   ├── telegram_offset.txt # Telegram update tracking
│   └── state.json          # System state
└── cache/                  # Temporary cache
```

## 🔧 Configuration

### Keywords

Edit the `keywords` array in `config.php`:

```php
'keywords' => [
    'leak',
    'database',
    'dump',
    'credentials',
    'breach',
    // Add your own keywords
],
```

### Monitoring Sources

Enable/disable sources in `config.php`:

```php
'clearweb_sources' => [
    [
        'name' => 'XSS.is',
        'url' => 'https://xss.is',
        'enabled' => true,
    ],
    // Add or remove sources
],
```

### Monitoring Interval

Adjust how often the system checks for updates:

```php
'monitoring' => [
    'interval_seconds' => 3600, // 1 hour
],
```

## 📧 Email Notifications

### Using Gmail SMTP

1. Enable 2-factor authentication in your Google account
2. Generate an **App Password**: https://myaccount.google.com/apppasswords
3. Use the app password as `SMTP_PASSWORD`

### Configuration

```php
'notifications' => [
    'email' => [
        'enabled' => true,
        'smtp_host' => 'smtp.gmail.com',
        'smtp_port' => 587,
    ],
],
```

## 🌐 Deployment

### On Replit

1. Create a new PHP Repl
2. Upload all files
3. Add secrets in the Secrets tab
4. Run: `php monitor.php`

### On Hostinger

1. Upload files via FTP to your web directory
2. Set up environment variables in hosting panel
3. Create a cron job:
   ```
   0 * * * * cd /path/to/monitor && php monitor.php --once
   ```
4. Ensure `logs/` and `data/` directories are writable

### On Local Machine

1. Install PHP 8.1+
2. Set environment variables in terminal or `.env` file
3. Run: `php monitor.php`

## 🌑 Dark Web Monitoring (Advanced)

To monitor .onion sites:

1. Install Tor Browser or Tor service
2. Ensure SOCKS5 proxy runs on `127.0.0.1:9050`
3. Enable in `config.php`:
   ```php
   'darkweb_sources' => [
       'enabled' => true,
   ],
   ```
4. Add .onion URLs to monitor

**Note:** Dark web monitoring requires Tor running locally. Not available on most shared hosting.

## 📊 Viewing Results

### Log Files

- **Main log**: `logs/monitors.log`
- **Findings**: `data/findings.json`

### Example Finding

```json
{
    "timestamp": "2025-11-16 14:30:00",
    "source": "Telegram: @dataleakmonitoring",
    "title": "Message #12345",
    "url": "https://t.me/dataleakmonitoring/12345",
    "snippet": "New database leak discovered...",
    "keywords": ["leak", "database"]
}
```

## 🛠️ Troubleshooting

### Telegram not working

- Verify `TELEGRAM_BOT_TOKEN` is set correctly
- Ensure bot has been added to channels
- Check bot permissions

### Email not sending

- Use Gmail app password, not regular password
- Verify SMTP settings
- Check firewall allows outbound port 587

### Sites not being scraped

- Some sites may block automated access
- Check `logs/monitors.log` for errors
- Adjust `rate_limit_delay` in config
- Some sites require authentication (not supported)

### High resource usage

- Increase `interval_seconds` to reduce frequency
- Disable unused sources
- Enable caching in config

## ⚙️ Command Line Options

```bash
php monitor.php              # Continuous monitoring
php monitor.php --once       # Single iteration (for cron)
php monitor.php --test       # Test configuration
php monitor.php --help       # Show help
```

## 🔒 Security Best Practices

1. **Never commit secrets** to version control
2. Use environment variables for sensitive data
3. Keep logs directory outside web root
4. Regularly review findings
5. Use this tool responsibly and ethically
6. Comply with terms of service of monitored sites
7. Respect robots.txt (enabled by default)

## 📝 Legal & Ethical Considerations

This tool is designed for **legitimate security monitoring and threat intelligence purposes only**, such as:
- Protecting your organization from data breaches
- Monitoring for compromised credentials
- Threat intelligence gathering
- Security research

**Do not use this tool for:**
- Accessing or distributing stolen data
- Illegal activities
- Unauthorized access to systems
- Violating terms of service

Always ensure you have proper authorization and comply with applicable laws.

## 🤝 Contributing

This is a security tool. If you find bugs or have improvements:
1. Test thoroughly
2. Document changes
3. Follow security best practices

## 📄 License

This project is provided for educational and security purposes only. Use at your own risk and responsibility.

## 🆘 Support

For issues or questions:
1. Check `logs/monitors.log` for errors
2. Run `php monitor.php --test` to diagnose issues
3. Review configuration in `config.php`
4. Consult `SETUP.md` for detailed instructions

## 🔄 Updates

Check for updates regularly to:
- Fix bugs
- Add new sources
- Improve detection
- Enhance security

---

**Remember:** This tool is for security professionals to protect organizations and users. Always use responsibly and ethically.
