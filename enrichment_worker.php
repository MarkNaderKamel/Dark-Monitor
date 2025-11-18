<?php
/**
 * Enrichment Queue Worker
 * 
 * Processes IOC enrichment queue asynchronously
 * Run as: php enrichment_worker.php [--once] [--batch=10]
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/DatabaseManager.php';
require_once __DIR__ . '/src/EnrichmentQueue.php';

$config = require __DIR__ . '/config.php';
$logger = new Logger($config);
$db = new DatabaseManager($config, $logger);
$queue = new EnrichmentQueue($db->getConnection(), $config, $logger);

$runOnce = in_array('--once', $argv);
$batchSize = 10;

foreach ($argv as $arg) {
    if (str_starts_with($arg, '--batch=')) {
        $batchSize = (int)explode('=', $arg)[1];
    }
}

$logger->info('ENRICHMENT', "Starting enrichment worker (batch size: $batchSize)");

if ($runOnce) {
    $processed = $queue->processQueue($batchSize);
    $logger->info('ENRICHMENT', "Processed $processed jobs");
    exit(0);
}

$logger->info('ENRICHMENT', 'Running in continuous mode. Press Ctrl+C to stop.');

$iteration = 0;
while (true) {
    try {
        $processed = $queue->processQueue($batchSize);
        
        if ($processed > 0) {
            $logger->info('ENRICHMENT', "Processed $processed jobs");
        }
        
        $iteration++;
        
        if ($iteration % 12 == 0) {
            $stats = $queue->getQueueStats();
            $pending = $stats['pending'] ?? 0;
            $processing = $stats['processing'] ?? 0;
            $failed = $stats['failed'] ?? 0;
            
            $logger->info('ENRICHMENT', "Queue stats - Pending: $pending, Processing: $processing, Failed: $failed");
        }
        
        sleep(30);
        
    } catch (Exception $e) {
        $logger->error('ENRICHMENT', 'Worker error: ' . $e->getMessage());
        sleep(60);
    }
}
