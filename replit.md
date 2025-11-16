# Security Monitoring System - Project Overview

## Project Purpose

This is a comprehensive threat intelligence monitoring system designed for cybersecurity professionals and penetration testers. The system monitors various online sources (clear web, dark web, and Telegram) for mentions of data leaks, breaches, and compromised credentials.

## Recent Changes

**2025-11-16 (Enhanced v2.0):** Major Feature Enhancements
- Added modern live dashboard (dashboard.html) with real-time auto-refresh
- Integrated VirusTotal API for IOC enrichment (IPs, domains, URLs, hashes)
- Integrated Have I Been Pwned API for email/domain breach checking
- Added IP geolocation with country, ISP, proxy detection
- Built alert rules engine with 7 smart rules (ransomware, APT, zero-day detection)
- Created export manager (CSV, JSON, STIX formats)
- Added monitoring for additional paste sites (Paste.ee, Ghostbin, Slexy, Rentry)
- Fixed critical blocking issues with API rate limiting
- Implemented 24-hour caching system for all enrichment APIs
- All enhancements production-ready and fully tested

**2025-11-16:** Initial project creation
- Built complete PHP-based monitoring system
- Created modular architecture with separate classes for different monitoring sources
- Implemented logging and notification systems
- Added comprehensive documentation
- Configured demo workflow

## Project Architecture

### Core Components

1. **monitor.php** - Main entry point and orchestration
2. **config.php** - Centralized configuration
3. **src/Logger.php** - Logging system with rotation
4. **src/HttpClient.php** - HTTP/cURL wrapper with Tor support
5. **src/TelegramMonitor.php** - Telegram Bot API integration
6. **src/WebScraper.php** - Clear web scraping module
7. **src/DarkWebMonitor.php** - Dark web monitoring via Tor
8. **src/Notifier.php** - Email and webhook notifications

### Helper Scripts

- **run_demo.php** - Demo script for testing without full setup
- **view_findings.php** - View discovered findings
- **check_status.php** - System status and health check

### Data Storage

- **logs/monitors.log** - Main activity log
- **data/findings.json** - Discovered leaks/breaches
- **data/state.json** - System state tracking
- **data/telegram_offset.txt** - Telegram update tracking

## Deployment Information

### Designed for Hostinger

The system is optimized for Hostinger web hosting:
- Uses standard PHP 8.x (no special extensions required)
- Cron job compatible (`php monitor.php --once`)
- Minimal resource usage
- File-based storage (no database required)

### Can Also Run On

- **Replit** - Free tier compatible with workflow
- **Local servers** - Any PHP 8.1+ environment
- **VPS** - Full control for dark web monitoring

## Environment Variables

Required for full functionality:
- `TELEGRAM_BOT_TOKEN` - Telegram bot token from @BotFather
- `SMTP_USER` - Email for SMTP notifications
- `SMTP_PASSWORD` - Email password or app password
- `NOTIFY_EMAIL` - Recipient for alerts
- `DEBUG_MODE` - Enable verbose logging

## Security Considerations

This tool is for **legitimate security monitoring only**:
- Monitors public sources for threat intelligence
- Helps organizations detect data breaches early
- Complies with robots.txt by default
- Respects rate limits
- Does not access or distribute stolen data

## Technical Decisions

### Why PHP?
- Widely supported on shared hosting (Hostinger)
- Built-in cURL for HTTP requests
- No compilation required
- Low resource usage

### Why File-Based Storage?
- No database setup required
- Easy to backup and transfer
- Works on any hosting platform
- Sufficient for monitoring use case

### Why Modular Classes?
- Easy to test individual components
- Can disable sources independently
- Clean separation of concerns
- Simple to extend with new sources

## User Preferences

- User is a cybersecurity professional/pentester
- Needs to monitor for leaked databases
- Will deploy on Hostinger
- Wants a complete, production-ready system
- Values comprehensive documentation

## Next Steps for Users

1. Set up Telegram bot token (see SETUP.md)
2. Configure environment variables
3. Customize keywords in config.php
4. Test with: `php monitor.php --test`
5. Run once: `php monitor.php --once`
6. Deploy to Hostinger with cron job
