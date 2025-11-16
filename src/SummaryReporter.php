<?php
/**
 * Summary Reporter Class
 * 
 * Generates and sends automated summary reports
 */

class SummaryReporter {
    private $db;
    private $logger;
    private $config;
    private $notifier;

    public function __construct($db, $logger, $config, $notifier) {
        $this->db = $db;
        $this->logger = $logger;
        $this->config = $config;
        $this->notifier = $notifier;
    }

    /**
     * Generate daily summary report
     */
    public function generateDailySummary() {
        $this->logger->info('REPORTER', 'Generating daily summary report');

        $stats = $this->getDailyStats();
        $topFindings = $this->getTopFindings();
        $iocSummary = $this->getIOCSummary();
        $sourceSummary = $this->getSourceSummary();

        $report = [
            'period' => 'Last 24 hours',
            'generated_at' => date('Y-m-d H:i:s'),
            'statistics' => $stats,
            'top_findings' => $topFindings,
            'ioc_summary' => $iocSummary,
            'source_summary' => $sourceSummary
        ];

        // Save report to file
        $this->saveReport($report);

        // Send email if enabled
        if ($this->config['notifications']['email']['enabled'] ?? false) {
            $this->sendEmailReport($report);
        }

        return $report;
    }

    /**
     * Get daily statistics
     */
    private function getDailyStats() {
        $findings = $this->db->getFindings(['from_date' => date('Y-m-d H:i:s', strtotime('-24 hours'))]);

        $stats = [
            'total' => count($findings),
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'sources' => []
        ];

        foreach ($findings as $finding) {
            $severity = $finding['severity'] ?? 'LOW';
            
            switch ($severity) {
                case 'CRITICAL':
                    $stats['critical']++;
                    break;
                case 'HIGH':
                    $stats['high']++;
                    break;
                case 'MEDIUM':
                    $stats['medium']++;
                    break;
                case 'LOW':
                    $stats['low']++;
                    break;
            }

            $source = $finding['source'];
            if (!isset($stats['sources'][$source])) {
                $stats['sources'][$source] = 0;
            }
            $stats['sources'][$source]++;
        }

        return $stats;
    }

    /**
     * Get top findings by severity
     */
    private function getTopFindings($limit = 10) {
        $findings = $this->db->getFindings([
            'from_date' => date('Y-m-d H:i:s', strtotime('-24 hours')),
            'limit' => $limit
        ]);

        // Sort by severity
        usort($findings, function($a, $b) {
            $severityOrder = ['CRITICAL' => 4, 'HIGH' => 3, 'MEDIUM' => 2, 'LOW' => 1];
            $scoreA = $severityOrder[$a['severity'] ?? 'LOW'];
            $scoreB = $severityOrder[$b['severity'] ?? 'LOW'];
            return $scoreB - $scoreA;
        });

        return array_slice($findings, 0, $limit);
    }

    /**
     * Get IOC summary
     */
    private function getIOCSummary() {
        $iocs = $this->db->getIOCs(null, 100);

        $summary = [
            'total' => count($iocs),
            'by_type' => [],
            'by_severity' => []
        ];

        foreach ($iocs as $ioc) {
            $type = $ioc['ioc_type'];
            $severity = $ioc['severity'];

            if (!isset($summary['by_type'][$type])) {
                $summary['by_type'][$type] = 0;
            }
            $summary['by_type'][$type]++;

            if (!isset($summary['by_severity'][$severity])) {
                $summary['by_severity'][$severity] = 0;
            }
            $summary['by_severity'][$severity]++;
        }

        return $summary;
    }

    /**
     * Get source summary
     */
    private function getSourceSummary() {
        $activity = $this->db->getRecentActivity(24);

        $summary = [];
        foreach ($activity as $item) {
            $source = $item['source'];
            if (!isset($summary[$source])) {
                $summary[$source] = [
                    'count' => 0,
                    'by_severity' => []
                ];
            }

            $summary[$source]['count'] += $item['count'];
            $summary[$source]['by_severity'][$item['severity']] = $item['count'];
        }

        return $summary;
    }

    /**
     * Save report to file
     */
    private function saveReport($report) {
        $reportDir = $this->config['storage']['cache_dir'] . '/reports';
        
        if (!is_dir($reportDir)) {
            mkdir($reportDir, 0755, true);
        }

        $filename = $reportDir . '/summary_' . date('Y-m-d_His') . '.json';
        file_put_contents($filename, json_encode($report, JSON_PRETTY_PRINT));

        $this->logger->info('REPORTER', "Report saved to: $filename");

        // Also save as HTML
        $this->saveHTMLReport($report, $reportDir);
    }

    /**
     * Save HTML version of report
     */
    private function saveHTMLReport($report, $reportDir) {
        $html = $this->generateHTMLReport($report);
        $filename = $reportDir . '/summary_' . date('Y-m-d_His') . '.html';
        file_put_contents($filename, $html);
    }

    /**
     * Generate HTML report
     */
    private function generateHTMLReport($report) {
        $stats = $report['statistics'];
        
        $html = '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Monitoring Summary Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #007bff; color: white; }
        tr:hover { background: #f1f1f1; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Monitoring Summary Report</h1>
        <p><strong>Period:</strong> ' . htmlspecialchars($report['period']) . '</p>
        <p><strong>Generated:</strong> ' . htmlspecialchars($report['generated_at']) . '</p>
        
        <h2>📊 Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div>Total Findings</div>
                <div class="stat-number">' . $stats['total'] . '</div>
            </div>
            <div class="stat-card">
                <div>Critical</div>
                <div class="stat-number critical">' . $stats['critical'] . '</div>
            </div>
            <div class="stat-card">
                <div>High</div>
                <div class="stat-number high">' . $stats['high'] . '</div>
            </div>
            <div class="stat-card">
                <div>Medium</div>
                <div class="stat-number medium">' . $stats['medium'] . '</div>
            </div>
            <div class="stat-card">
                <div>Low</div>
                <div class="stat-number low">' . $stats['low'] . '</div>
            </div>
        </div>
        
        <h2>🎯 Top Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Title</th>
                    <th>Time</th>
                </tr>
            </thead>
            <tbody>';
        
        foreach ($report['top_findings'] as $finding) {
            $severityClass = strtolower($finding['severity'] ?? 'low');
            $html .= '<tr>
                <td><span class="badge ' . $severityClass . '">' . htmlspecialchars($finding['severity'] ?? 'LOW') . '</span></td>
                <td>' . htmlspecialchars($finding['source']) . '</td>
                <td><a href="' . htmlspecialchars($finding['url'] ?? '#') . '" target="_blank">' . htmlspecialchars($finding['title']) . '</a></td>
                <td>' . htmlspecialchars($finding['timestamp']) . '</td>
            </tr>';
        }
        
        $html .= '</tbody>
        </table>
        
        <h2>📍 Sources Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Source</th>
                    <th>Total</th>
                </tr>
            </thead>
            <tbody>';
        
        foreach ($stats['sources'] as $source => $count) {
            $html .= '<tr>
                <td>' . htmlspecialchars($source) . '</td>
                <td>' . $count . '</td>
            </tr>';
        }
        
        $html .= '</tbody>
        </table>
    </div>
</body>
</html>';

        return $html;
    }

    /**
     * Send email report
     */
    private function sendEmailReport($report) {
        $stats = $report['statistics'];
        
        $subject = '[Security Monitor] Daily Summary - ' . $stats['total'] . ' Findings';
        
        $body = $this->generateHTMLReport($report);

        try {
            $this->notifier->sendEmail($subject, $body);
            $this->logger->info('REPORTER', 'Email report sent successfully');
        } catch (Exception $e) {
            $this->logger->error('REPORTER', 'Failed to send email report: ' . $e->getMessage());
        }
    }
}
