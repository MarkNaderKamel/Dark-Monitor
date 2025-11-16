# Contributing to Security Monitoring System

Thank you for your interest in improving this security monitoring tool!

## Code of Conduct

This project is for **legitimate security research and threat intelligence only**. By contributing, you agree that your contributions will be used ethically and legally.

## How to Contribute

### Reporting Bugs

If you find a bug:
1. Check if it's already reported in issues
2. Include PHP version and platform (Replit, Hostinger, local)
3. Provide error logs from `logs/monitors.log`
4. Describe steps to reproduce

### Suggesting Enhancements

For new features:
1. Explain the use case
2. Consider if it can be done with free APIs/services
3. Ensure it aligns with the project's security focus

### Code Contributions

#### Adding New Monitoring Sources

To add a new forum or site:

1. Edit `config.php`:
```php
'clearweb_sources' => [
    // ... existing sources
    [
        'name' => 'NewSite',
        'url' => 'https://newsite.com',
        'enabled' => true,
        'selector' => 'threads',
    ],
],
```

2. No code changes needed! The scraper handles new sources automatically.

#### Adding New Keywords

Edit `config.php`:
```php
'keywords' => [
    'leak',
    'your_new_keyword',
    // ...
],
```

#### Improving Scraping Logic

To improve parsing in `src/WebScraper.php`:
1. Test with multiple sites
2. Handle errors gracefully
3. Respect robots.txt
4. Add rate limiting
5. Document any site-specific logic

### Testing

Before submitting changes:

```bash
# Test configuration
php monitor.php --test

# Run single iteration
php monitor.php --once

# Check logs for errors
cat logs/monitors.log
```

### Code Style

- Use clear, descriptive variable names
- Add comments for complex logic
- Follow existing patterns
- Use PHP 8.x features when appropriate
- Handle errors with try-catch

### Documentation

Update documentation when:
- Adding new features
- Changing configuration options
- Modifying setup process
- Adding new dependencies

Files to update:
- `README.md` - High-level overview
- `SETUP.md` - Setup instructions
- `config.php` - Inline comments
- Code comments - Explain why, not what

## Security Guidelines

### Do's ✓

- Monitor public sources only
- Respect robots.txt
- Implement rate limiting
- Handle errors gracefully
- Use environment variables for secrets
- Log security-relevant events

### Don'ts ✗

- Access private/authenticated content without permission
- Bypass rate limits or security measures
- Store credentials in code
- Distribute leaked data
- Violate terms of service
- Create denial-of-service conditions

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Update documentation
6. Submit pull request with clear description

## Questions?

For questions about contributing, check:
1. Existing documentation
2. Code comments
3. Issues section

## License

By contributing, you agree that your contributions will be provided under the same terms as the project (for educational and security purposes).

## Thank You!

Your contributions help make the internet safer by enabling better threat intelligence and breach detection.
