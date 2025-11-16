<?php
/**
 * Dashboard API Endpoint
 * 
 * Provides JSON data for the real-time dashboard
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/DatabaseManager.php';

$config = require __DIR__ . '/config.php';
$logger = new Logger($config);
$db = new DatabaseManager($config, $logger);

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

$action = $_GET['action'] ?? 'stats';

try {
    switch ($action) {
        case 'stats':
            $stats = [
                'total_findings' => 0,
                'critical' => 0,
                'high' => 0,
                'medium' => 0,
                'low' => 0,
                'sources' => 0,
                'last_24h' => 0
            ];

            $findings = $db->getFindings(['limit' => 1000]);
            $stats['total_findings'] = count($findings);

            $recent = $db->getFindings(['from_date' => date('Y-m-d H:i:s', strtotime('-24 hours'))]);
            $stats['last_24h'] = count($recent);

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
            }

            $sources = [];
            foreach ($findings as $finding) {
                $sources[$finding['source']] = true;
            }
            $stats['sources'] = count($sources);

            echo json_encode(['success' => true, 'data' => $stats]);
            break;

        case 'recent':
            $limit = $_GET['limit'] ?? 20;
            $findings = $db->getFindings([
                'limit' => $limit,
                'from_date' => date('Y-m-d H:i:s', strtotime('-7 days'))
            ]);

            echo json_encode(['success' => true, 'data' => $findings]);
            break;

        case 'timeline':
            $days = $_GET['days'] ?? 7;
            $timeline = $db->getStatistics($days);
            
            echo json_encode(['success' => true, 'data' => $timeline]);
            break;

        case 'sources':
            $activity = $db->getRecentActivity(24);
            
            $sourceData = [];
            foreach ($activity as $item) {
                if (!isset($sourceData[$item['source']])) {
                    $sourceData[$item['source']] = [
                        'name' => $item['source'],
                        'count' => 0,
                        'severities' => []
                    ];
                }
                $sourceData[$item['source']]['count'] += $item['count'];
                $sourceData[$item['source']]['severities'][$item['severity']] = $item['count'];
            }

            echo json_encode(['success' => true, 'data' => array_values($sourceData)]);
            break;

        case 'iocs':
            $limit = $_GET['limit'] ?? 50;
            $type = $_GET['type'] ?? null;
            $iocs = $db->getIOCs($type, $limit);
            
            echo json_encode(['success' => true, 'data' => $iocs]);
            break;

        case 'search':
            $keyword = $_GET['q'] ?? '';
            if (empty($keyword)) {
                throw new Exception('Search keyword required');
            }

            $results = $db->searchFindings($keyword);
            echo json_encode(['success' => true, 'data' => $results]);
            break;

        default:
            throw new Exception('Invalid action');
    }

} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => $e->getMessage()]);
}
