<?php
/**
 * Logger Class
 * 
 * Handles all logging operations for the monitoring system.
 */

class Logger {
    private $config;
    private $logFile;

    public function __construct($config) {
        $this->config = $config['logging'];
        $this->logFile = $this->config['file'];
        
        // Create logs directory if it doesn't exist
        $logDir = dirname($this->logFile);
        if (!is_dir($logDir)) {
            mkdir($logDir, 0755, true);
        }
    }

    /**
     * Log a message
     */
    public function log($level, $source, $message) {
        $levels = ['DEBUG' => 0, 'INFO' => 1, 'WARNING' => 2, 'ERROR' => 3];
        $configLevel = $levels[$this->config['level']] ?? 1;
        $messageLevel = $levels[$level] ?? 1;

        if ($messageLevel < $configLevel) {
            return;
        }

        // Rotate log if needed
        $this->rotateIfNeeded();

        // Format message
        $formattedMessage = str_replace(
            ['%timestamp%', '%level%', '%source%', '%message%'],
            [date('Y-m-d H:i:s'), $level, $source, $message],
            $this->config['format']
        );

        // Write to file
        file_put_contents($this->logFile, $formattedMessage . PHP_EOL, FILE_APPEND | LOCK_EX);

        // Also output to console if debug mode
        if ($this->config['level'] === 'DEBUG' || $level === 'ERROR') {
            echo $formattedMessage . PHP_EOL;
        }
    }

    /**
     * Convenience methods
     */
    public function debug($source, $message) {
        $this->log('DEBUG', $source, $message);
    }

    public function info($source, $message) {
        $this->log('INFO', $source, $message);
    }

    public function warning($source, $message) {
        $this->log('WARNING', $source, $message);
    }

    public function error($source, $message) {
        $this->log('ERROR', $source, $message);
    }

    /**
     * Log a finding (discovered leak/breach mention)
     */
    public function logFinding($source, $title, $url, $snippet) {
        $finding = [
            'timestamp' => date('Y-m-d H:i:s'),
            'source' => $source,
            'title' => $title,
            'url' => $url,
            'snippet' => $snippet,
        ];

        $this->info($source, "FINDING: $title - $url");
        
        // Also save to findings file
        $this->saveFinding($finding);
        
        return $finding;
    }

    /**
     * Save finding to JSON file
     */
    private function saveFinding($finding) {
        $findingsFile = dirname($this->logFile) . '/../data/findings.json';
        $findings = [];

        if (file_exists($findingsFile)) {
            $json = file_get_contents($findingsFile);
            $findings = json_decode($json, true) ?: [];
        }

        $findings[] = $finding;

        // Keep only last 10000 findings
        if (count($findings) > 10000) {
            $findings = array_slice($findings, -10000);
        }

        file_put_contents($findingsFile, json_encode($findings, JSON_PRETTY_PRINT));
    }

    /**
     * Rotate log file if it exceeds max size
     */
    private function rotateIfNeeded() {
        if (!file_exists($this->logFile)) {
            return;
        }

        $maxSizeBytes = $this->config['max_size_mb'] * 1024 * 1024;
        $currentSize = filesize($this->logFile);

        if ($currentSize > $maxSizeBytes) {
            $backupFile = $this->logFile . '.' . date('Y-m-d_H-i-s') . '.bak';
            rename($this->logFile, $backupFile);
            $this->info('LOGGER', "Log rotated to $backupFile");
        }
    }
}
