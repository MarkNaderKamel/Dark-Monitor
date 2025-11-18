<?php

class IOCExtractor {
    private $logger;
    
    private $patterns = [
        'ipv4' => '/\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/',
        'ipv6' => '/\b(?:(?:[0-9a-fA-F]{1,4}\:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}\:){1,7}\:|(?:[0-9a-fA-F]{1,4}\:){1,6}\:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}\:){1,5}(?:\:[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}\:){1,4}(?:\:[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}\:){1,3}(?:\:[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}\:){1,2}(?:\:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}\:(?:(?:\:[0-9a-fA-F]{1,4}){1,6})|(?:\:(?:\:[0-9a-fA-F]{1,4}){1,7}|\:))\b/i',
        'domain' => '/\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i',
        'url' => '/\b(?:https?|ftp)\:\/\/[^\s<>"\']+/i',
        'email' => '/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/',
        'md5' => '/\b[a-f0-9]{32}\b/i',
        'sha1' => '/\b[a-f0-9]{40}\b/i',
        'sha256' => '/\b[a-f0-9]{64}\b/i',
        'cve' => '/CVE-\d{4}-\d{4,7}/i',
        'bitcoin' => '/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/',
        'ethereum' => '/\b0x[a-fA-F0-9]{40}\b/',
        'ssn' => '/\b\d{3}-\d{2}-\d{4}\b/',
        'credit_card' => '/\b(?:\d{4}[-\s]?){3}\d{4}\b/',
        'phone' => '/\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/',
        'windows_path' => '/[A-Za-z]\:\\\\(?:[^\\\\\/\:*?"<>|\r\n]+\\\\)*[^\\\\\/\:*?"<>|\r\n]*/i',
        'registry_key' => '/\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR)\\\\[^\s<>]+/i',
        'mutex' => '/\\\\BaseNamedObjects\\\\[A-Za-z0-9_\-]+/i',
        'file_hash_context' => '/(?:md5|sha1|sha256|hash)[\s\:=]+([a-f0-9]{32,64})/i',
    ];

    private $defangPatterns = [
        '/hxxp/i' => 'http',
        '/hXXp/i' => 'http',
        '/\[dot\]/i' => '.',
        '/\[DOT\]/i' => '.',
        '/\[\.\]/' => '.',
        '/\[\:\]/' => ':',
        '/\[\@\]/' => '@',
    ];

    private $privateIPRanges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8',
        '169.254.0.0/16',
        '::1/128',
        'fe80::/10',
        'fc00::/7',
    ];

    public function __construct($logger) {
        $this->logger = $logger;
    }

    public function extract($text) {
        $text = $this->refang($text);
        
        $iocs = [
            'ips' => [],
            'domains' => [],
            'urls' => [],
            'emails' => [],
            'hashes' => [],
            'cves' => [],
            'crypto_addresses' => [],
            'windows_artifacts' => [],
        ];

        $ipv4s = array_values(array_unique(array_filter(
            $this->extractPattern($text, 'ipv4'),
            [$this, 'isPublicIP']
        )));

        $ipv6s = $this->extractIPv6($text);
        $publicIPv6s = array_values(array_unique(array_filter($ipv6s, [$this, 'isPublicIP'])));

        $iocs['ips'] = array_merge($ipv4s, $publicIPv6s);

        $rawDomains = $this->extractPattern($text, 'domain');
        $iocs['domains'] = array_values(array_unique(array_filter($rawDomains, function($domain) {
            return $this->isValidDomain($domain) && !$this->isCommonDomain($domain);
        })));

        $iocs['urls'] = array_values(array_unique($this->extractPattern($text, 'url')));
        
        $iocs['emails'] = array_values(array_unique(array_filter(
            $this->extractPattern($text, 'email'),
            [$this, 'isValidEmail']
        )));

        $md5s = $this->extractPattern($text, 'md5');
        $sha1s = $this->extractPattern($text, 'sha1');
        $sha256s = $this->extractPattern($text, 'sha256');
        $iocs['hashes'] = array_values(array_unique(array_merge($md5s, $sha1s, $sha256s)));

        $iocs['cves'] = array_values(array_unique($this->extractPattern($text, 'cve')));

        $bitcoins = $this->extractPattern($text, 'bitcoin');
        $ethereums = $this->extractPattern($text, 'ethereum');
        $iocs['crypto_addresses'] = array_values(array_unique(array_merge($bitcoins, $ethereums)));

        $paths = $this->extractPattern($text, 'windows_path');
        $regkeys = $this->extractPattern($text, 'registry_key');
        $mutexes = $this->extractPattern($text, 'mutex');
        $iocs['windows_artifacts'] = array_values(array_unique(array_merge($paths, $regkeys, $mutexes)));

        foreach ($iocs as $key => $values) {
            if (empty($values)) {
                unset($iocs[$key]);
            }
        }

        if (!empty($iocs)) {
            $this->logger->debug('IOC', 'Extracted ' . array_sum(array_map('count', $iocs)) . ' IOCs');
        }

        return $iocs;
    }

    private function extractPattern($text, $patternName) {
        if (!isset($this->patterns[$patternName])) {
            return [];
        }

        preg_match_all($this->patterns[$patternName], $text, $matches);
        return $matches[0] ?? [];
    }

    private function refang($text) {
        foreach ($this->defangPatterns as $pattern => $replacement) {
            $text = preg_replace($pattern, $replacement, $text);
        }
        return $text;
    }

    private function isPublicIP($ip) {
        if (strpos($ip, ':') !== false) {
            return $this->isPublicIPv6($ip);
        }
        
        $longIP = ip2long($ip);
        if ($longIP === false) {
            return false;
        }

        $ipv4PrivateRanges = [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16',
        ];

        foreach ($ipv4PrivateRanges as $range) {
            list($subnet, $mask) = explode('/', $range);
            $subnetLong = ip2long($subnet);
            
            $maskInt = (int)$mask;
            if ($maskInt < 0 || $maskInt > 32) {
                continue;
            }
            
            $maskLong = $maskInt == 0 ? 0 : -1 << (32 - $maskInt);
            
            if (($longIP & $maskLong) == ($subnetLong & $maskLong)) {
                return false;
            }
        }

        return true;
    }

    private function isPublicIPv6($ip) {
        $ipBin = @inet_pton($ip);
        if ($ipBin === false) {
            return false;
        }

        $ipv6PrivateRanges = [
            '::1/128',
            'fe80::/10',
            'fc00::/7',
        ];

        foreach ($ipv6PrivateRanges as $range) {
            list($subnet, $prefixLen) = explode('/', $range);
            $subnetBin = @inet_pton($subnet);
            
            if ($subnetBin === false) {
                continue;
            }

            $bytesToCheck = (int)($prefixLen / 8);
            $bitsInLastByte = $prefixLen % 8;

            for ($i = 0; $i < $bytesToCheck; $i++) {
                if ($ipBin[$i] !== $subnetBin[$i]) {
                    continue 2;
                }
            }

            if ($bitsInLastByte > 0) {
                $mask = 0xFF << (8 - $bitsInLastByte);
                if ((ord($ipBin[$bytesToCheck]) & $mask) !== (ord($subnetBin[$bytesToCheck]) & $mask)) {
                    continue;
                }
            }

            return false;
        }

        return true;
    }

    private function extractIPv6($text) {
        $ipv6s = [];
        $tokens = preg_split('/[\s,;\|\(\)\[\]\{\}<>"\']/', $text);
        
        foreach ($tokens as $token) {
            $token = trim($token, " \t\n\r\0\x0B.!?:;");
            if (strlen($token) > 0 && filter_var($token, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
                $ipv6s[] = $token;
            }
        }
        
        return $ipv6s;
    }

    private function isValidDomain($domain) {
        if (strlen($domain) > 253 || strlen($domain) < 4) {
            return false;
        }

        if (preg_match('/^\d+\.\d+\.\d+\.\d+$/', $domain)) {
            return false;
        }

        if (!preg_match('/\.[a-z]{2,}$/i', $domain)) {
            return false;
        }

        return true;
    }

    private function isValidEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    private function isCommonDomain($domain) {
        $commonDomains = [
            'google.com', 'facebook.com', 'twitter.com', 'youtube.com', 
            'instagram.com', 'linkedin.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'reddit.com', 'wikipedia.org', 'github.com',
            'stackoverflow.com', 'w3.org', 'mozilla.org', 'cloudflare.com',
            'example.com', 'example.org', 'localhost', 'test.com'
        ];

        $domain = strtolower($domain);
        foreach ($commonDomains as $common) {
            if ($domain === $common || str_ends_with($domain, '.' . $common)) {
                return true;
            }
        }

        return false;
    }

    public function calculateIOCDensity($text, $iocs) {
        $totalIOCs = array_sum(array_map('count', $iocs));
        $wordCount = str_word_count($text);
        
        if ($wordCount == 0) {
            return 0;
        }

        return min(($totalIOCs / $wordCount) * 100, 100);
    }
}
