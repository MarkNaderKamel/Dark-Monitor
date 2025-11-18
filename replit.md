# Security Monitoring System - Replit Configuration

## Overview
This is a comprehensive threat intelligence monitoring system designed for cybersecurity professionals to detect mentions of data leaks and breaches across clear web forums, dark web sites, and Telegram channels.

**Current State**: Development environment setup complete with web dashboard running on port 5000.

## Project Structure

### Core Components
- **Dashboard** (`dashboard.html`, `dashboard.php`, `dashboard_api.php`) - Real-time web interface for viewing findings
- **Monitoring System** (`monitor.php`) - Main monitoring engine
- **Configuration** (`config.php`) - Central configuration file
- **Database** - SQLite database (`data/monitoring.db`) for storing findings

### Directory Layout
```
.
├── src/                    # Core PHP classes
│   ├── DatabaseManager.php
│   ├── TelegramMonitor.php
│   ├── WebScraper.php
│   └── ... (other monitoring classes)
├── logs/                   # Application logs (gitignored)
├── data/                   # Database and state files (gitignored)
├── cache/                  # Temporary cache (gitignored)
├── exports/                # Export files (gitignored)
├── dashboard.html          # Main dashboard UI
├── dashboard_api.php       # Dashboard JSON API
├── monitor.php             # CLI monitoring script
├── config.php              # Configuration
└── server.php              # PHP server router
```

## Recent Changes (Nov 18, 2025)

### Replit Environment Setup
1. Created required directories (logs, data, cache, exports)
2. Configured PHP built-in web server on port 5000
3. Set up workflow to run dashboard server
4. Updated dashboard API to match frontend expectations
5. Configured deployment for autoscale (stateless web app)
6. Database auto-initializes on first run (SQLite)

## Architecture

### Technology Stack
- **Language**: PHP 8.2.23
- **Database**: SQLite (development), easily upgradeable to PostgreSQL for production
- **Web Server**: PHP built-in server (development), can use any PHP-compatible web server in production
- **Frontend**: Vanilla HTML/CSS/JavaScript with real-time updates

### Data Flow
1. Monitor.php scrapes various sources (Telegram, web forums, dark web)
2. Findings stored in SQLite database
3. Dashboard API queries database and serves JSON
4. Frontend fetches API data and updates UI every 10 seconds

## Configuration

### Environment Variables (Optional)
These can be set in Replit Secrets or environment variables:

- `TELEGRAM_BOT_TOKEN` - Required for Telegram channel monitoring
- `SMTP_USER` - Email for SMTP notifications (optional)
- `SMTP_PASSWORD` - SMTP password (optional)
- `NOTIFY_EMAIL` - Recipient email for alerts (optional)
- `DEBUG_MODE` - Set to 'true' for verbose logging
- `VIRUSTOTAL_API_KEY` - VirusTotal API integration (optional)
- `HIBP_API_KEY` - Have I Been Pwned API (optional)

### Monitoring Sources
Edit `config.php` to customize:
- Keywords to search for
- Telegram channels to monitor
- Web sources to scrape
- Notification settings
- Monitoring intervals

## Running the System

### Web Dashboard
The dashboard is automatically running on port 5000 via the workflow.
- Access at: `https://<your-repl>.replit.dev/`
- Auto-refreshes every 10 seconds
- Shows real-time statistics and findings

### CLI Monitoring
To run the monitoring system manually:
```bash
# Test configuration
php monitor.php --test

# Run single iteration
php monitor.php --once

# Continuous monitoring
php monitor.php
```

## Deployment

### Current Configuration
- **Type**: Autoscale (stateless)
- **Port**: 5000 (frontend dashboard)
- **Server**: PHP built-in server

### Production Considerations
1. **Database**: Consider migrating to PostgreSQL for better performance
2. **Cron Jobs**: Set up scheduled monitoring runs
3. **Secrets**: All API keys should be in environment variables
4. **Logging**: Logs auto-rotate when they exceed 100MB
5. **Rate Limiting**: Configured in config.php to respect source limits

## User Preferences

*(No specific preferences recorded yet)*

## Features

### Active Features
- Multi-source monitoring (Telegram, web forums, paste sites)
- Keyword detection with context extraction
- SQLite database for findings storage
- Real-time web dashboard with auto-refresh
- Severity scoring (CRITICAL, HIGH, MEDIUM, LOW)
- IOC (Indicators of Compromise) tracking
- Threat correlation engine
- Export capabilities (JSON, CSV, STIX)

### Optional Features (Require Configuration)
- Email notifications via SMTP
- Slack/Discord webhooks
- Dark web monitoring (requires Tor)
- VirusTotal enrichment
- HIBP (Have I Been Pwned) integration
- GitHub repository monitoring
- Reddit monitoring

## Troubleshooting

### Common Issues

1. **Dashboard not loading**
   - Check workflow is running
   - Verify port 5000 is accessible
   - Check browser console for errors

2. **No findings appearing**
   - Run `php monitor.php --once` to populate database
   - Check logs in `logs/monitors.log`

3. **Telegram not working**
   - Set `TELEGRAM_BOT_TOKEN` in Replit Secrets
   - Verify bot is added to channels

4. **Database errors**
   - Ensure `data/` directory is writable
   - Check `data/monitoring.db` exists and has correct permissions

## Next Steps

To start using the system:
1. Set environment variables (especially `TELEGRAM_BOT_TOKEN`)
2. Review and customize `config.php` keywords and sources
3. Run `php monitor.php --test` to verify configuration
4. Run `php monitor.php --once` to perform first monitoring sweep
5. View results in the web dashboard

## Security Notes

- Never commit `.env` files or secrets to git
- All sensitive data directories are gitignored
- Use this tool responsibly and ethically
- Designed for legitimate security monitoring only
- Always comply with terms of service of monitored sites
