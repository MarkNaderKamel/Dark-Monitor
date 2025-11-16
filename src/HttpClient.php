<?php
/**
 * HTTP Client Class
 * 
 * Handles all HTTP requests with support for Tor/SOCKS5 proxies
 */

class HttpClient {
    private $config;
    private $logger;

    public function __construct($config, $logger) {
        $this->config = $config;
        $this->logger = $logger;
    }

    /**
     * Make HTTP GET request
     */
    public function get($url, $options = []) {
        $useTor = $options['use_tor'] ?? false;
        $timeout = $options['timeout'] ?? $this->config['monitoring']['timeout'];
        $maxRetries = $options['max_retries'] ?? $this->config['monitoring']['max_retries'];

        $attempt = 0;
        $lastError = null;

        while ($attempt < $maxRetries) {
            try {
                $ch = curl_init();
                
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
                curl_setopt($ch, CURLOPT_USERAGENT, $this->config['monitoring']['user_agent']);

                // SSL/TLS verification - enabled by default for security
                $verifySSL = $this->config['advanced']['verify_ssl'] ?? true;
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, $verifySSL);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, $verifySSL ? 2 : 0);

                // Optional custom CA bundle path
                if ($verifySSL && isset($this->config['advanced']['ca_bundle_path'])) {
                    curl_setopt($ch, CURLOPT_CAINFO, $this->config['advanced']['ca_bundle_path']);
                }

                // Add Tor proxy if needed
                if ($useTor && isset($this->config['darkweb_sources']['tor_proxy'])) {
                    $proxy = $this->config['darkweb_sources']['tor_proxy'];
                    curl_setopt($ch, CURLOPT_PROXY, $proxy);
                    // Use SOCKS5_HOSTNAME to allow .onion DNS resolution via Tor
                    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME);
                }

                // Custom headers
                $headers = [
                    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language: en-US,en;q=0.5',
                    'Connection: keep-alive',
                ];
                curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

                $response = curl_exec($ch);
                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $error = curl_error($ch);
                
                curl_close($ch);

                if ($response === false) {
                    throw new Exception("cURL Error: $error");
                }

                if ($httpCode >= 400) {
                    throw new Exception("HTTP Error $httpCode");
                }

                return [
                    'success' => true,
                    'data' => $response,
                    'http_code' => $httpCode,
                ];

            } catch (Exception $e) {
                $lastError = $e->getMessage();
                $attempt++;
                
                if ($attempt < $maxRetries) {
                    $this->logger->warning('HTTP', "Request failed (attempt $attempt/$maxRetries): $lastError - Retrying...");
                    sleep(2);
                }
            }
        }

        return [
            'success' => false,
            'error' => $lastError,
            'http_code' => 0,
        ];
    }

    /**
     * Check robots.txt before scraping
     */
    public function checkRobotsTxt($url) {
        if (!$this->config['advanced']['respect_robots_txt']) {
            return true;
        }

        $parsedUrl = parse_url($url);
        $robotsUrl = $parsedUrl['scheme'] . '://' . $parsedUrl['host'] . '/robots.txt';

        $result = $this->get($robotsUrl, ['timeout' => 10, 'max_retries' => 1]);
        
        if (!$result['success']) {
            return true; // If can't fetch robots.txt, proceed
        }

        // Simple check - look for Disallow: /
        if (stripos($result['data'], 'Disallow: /') !== false) {
            $this->logger->warning('HTTP', "robots.txt disallows scraping for $url");
            return false;
        }

        return true;
    }

    /**
     * Rate limiting
     */
    public function rateLimit() {
        $delay = $this->config['advanced']['rate_limit_delay'] ?? 2;
        sleep($delay);
    }
}
