<?php
/**
 * Security Monitoring Dashboard
 * 
 * Web-based dashboard for viewing findings and statistics
 */

// Load config and classes
require_once __DIR__ . '/config.php';
$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/src/Logger.php';
require_once __DIR__ . '/src/DatabaseManager.php';

// Initialize
$logger = new Logger($config);
$db = new DatabaseManager($config, $logger);

// Get filter parameters
$filter = $_GET['filter'] ?? 'all';
$search = $_GET['search'] ?? '';
$severity = $_GET['severity'] ?? '';

// Get findings
if (!empty($search)) {
    $findings = $db->searchFindings($search);
} else {
    $filters = [];
    
    if ($severity) {
        $filters['severity'] = $severity;
    }
    
    if ($filter === 'today') {
        $filters['from_date'] = date('Y-m-d');
    } elseif ($filter === 'week') {
        $filters['from_date'] = date('Y-m-d', strtotime('-7 days'));
    } elseif ($filter === 'month') {
        $filters['from_date'] = date('Y-m-d', strtotime('-30 days'));
    }
    
    $filters['limit'] = 100;
    $findings = $db->getFindings($filters);
}

// Get statistics
$stats = $db->getStatistics(30);
$recentActivity = $db->getRecentActivity(24);

// Calculate totals
$totalFindings = count($findings);
$criticalCount = count(array_filter($findings, fn($f) => $f['severity'] === 'CRITICAL'));
$highCount = count(array_filter($findings, fn($f) => $f['severity'] === 'HIGH'));
$mediumCount = count(array_filter($findings, fn($f) => $f['severity'] === 'MEDIUM'));
$lowCount = count(array_filter($findings, fn($f) => $f['severity'] === 'LOW'));

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Monitoring Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #0a0a0a;
            color: #e0e0e0;
            padding: 20px;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
        }

        header {
            background: linear-gradient(135deg, #1e3a8a 0%, #9333ea 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }

        h1 {
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .subtitle {
            opacity: 0.9;
            font-size: 16px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: #1a1a1a;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid;
        }

        .stat-card.critical { border-left-color: #dc2626; }
        .stat-card.high { border-left-color: #ea580c; }
        .stat-card.medium { border-left-color: #eab308; }
        .stat-card.low { border-left-color: #22c55e; }
        .stat-card.total { border-left-color: #3b82f6; }

        .stat-label {
            font-size: 14px;
            opacity: 0.7;
            margin-bottom: 5px;
        }

        .stat-value {
            font-size: 36px;
            font-weight: 700;
        }

        .controls {
            background: #1a1a1a;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }

        .search-box {
            flex: 1;
            min-width: 250px;
        }

        input, select, button {
            padding: 10px 15px;
            border: 1px solid #333;
            background: #0a0a0a;
            color: #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
        }

        input[type="text"] {
            width: 100%;
        }

        button {
            background: #3b82f6;
            border: none;
            cursor: pointer;
            font-weight: 600;
        }

        button:hover {
            background: #2563eb;
        }

        .findings {
            background: #1a1a1a;
            border-radius: 8px;
            overflow: hidden;
        }

        .finding {
            padding: 20px;
            border-bottom: 1px solid #2a2a2a;
            transition: background 0.2s;
        }

        .finding:hover {
            background: #222;
        }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }

        .finding-title {
            font-size: 18px;
            font-weight: 600;
            color: #fff;
        }

        .severity-badge {
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
        }

        .severity-CRITICAL { background: #dc2626; color: #fff; }
        .severity-HIGH { background: #ea580c; color: #fff; }
        .severity-MEDIUM { background: #eab308; color: #000; }
        .severity-LOW { background: #22c55e; color: #000; }

        .finding-meta {
            font-size: 14px;
            opacity: 0.7;
            margin-bottom: 10px;
        }

        .finding-snippet {
            background: #0a0a0a;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #3b82f6;
            margin-bottom: 10px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.6;
        }

        .finding-footer {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .keyword-tag {
            background: #2a2a2a;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
        }

        .link {
            color: #3b82f6;
            text-decoration: none;
        }

        .link:hover {
            text-decoration: underline;
        }

        .empty-state {
            text-align: center;
            padding: 60px 20px;
            opacity: 0.5;
        }

        .auto-refresh {
            text-align: right;
            font-size: 12px;
            opacity: 0.5;
            margin-top: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Monitoring Dashboard</h1>
            <div class="subtitle">Real-time threat intelligence and breach detection</div>
        </header>

        <div class="stats-grid">
            <div class="stat-card total">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value"><?= $totalFindings ?></div>
            </div>
            <div class="stat-card critical">
                <div class="stat-label">Critical</div>
                <div class="stat-value"><?= $criticalCount ?></div>
            </div>
            <div class="stat-card high">
                <div class="stat-label">High</div>
                <div class="stat-value"><?= $highCount ?></div>
            </div>
            <div class="stat-card medium">
                <div class="stat-label">Medium</div>
                <div class="stat-value"><?= $mediumCount ?></div>
            </div>
            <div class="stat-card low">
                <div class="stat-label">Low</div>
                <div class="stat-value"><?= $lowCount ?></div>
            </div>
        </div>

        <div class="controls">
            <div class="search-box">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search findings..." value="<?= htmlspecialchars($search) ?>">
                </form>
            </div>
            
            <select name="severity" onchange="location.href='?severity='+this.value">
                <option value="">All Severities</option>
                <option value="CRITICAL" <?= $severity === 'CRITICAL' ? 'selected' : '' ?>>Critical</option>
                <option value="HIGH" <?= $severity === 'HIGH' ? 'selected' : '' ?>>High</option>
                <option value="MEDIUM" <?= $severity === 'MEDIUM' ? 'selected' : '' ?>>Medium</option>
                <option value="LOW" <?= $severity === 'LOW' ? 'selected' : '' ?>>Low</option>
            </select>

            <select name="filter" onchange="location.href='?filter='+this.value">
                <option value="all" <?= $filter === 'all' ? 'selected' : '' ?>>All Time</option>
                <option value="today" <?= $filter === 'today' ? 'selected' : '' ?>>Today</option>
                <option value="week" <?= $filter === 'week' ? 'selected' : '' ?>>Last 7 Days</option>
                <option value="month" <?= $filter === 'month' ? 'selected' : '' ?>>Last 30 Days</option>
            </select>

            <button onclick="location.reload()">Refresh</button>
        </div>

        <div class="findings">
            <?php if (empty($findings)): ?>
                <div class="empty-state">
                    <h2>No findings yet</h2>
                    <p>The monitoring system hasn't detected any matches. Check back later!</p>
                </div>
            <?php else: ?>
                <?php foreach ($findings as $finding): ?>
                    <div class="finding">
                        <div class="finding-header">
                            <div class="finding-title"><?= htmlspecialchars($finding['title']) ?></div>
                            <span class="severity-badge severity-<?= $finding['severity'] ?>"><?= $finding['severity'] ?></span>
                        </div>
                        
                        <div class="finding-meta">
                            <strong><?= htmlspecialchars($finding['source']) ?></strong> • 
                            <?= htmlspecialchars($finding['timestamp']) ?> •
                            Score: <?= $finding['threat_score'] ?>
                        </div>

                        <?php if (!empty($finding['snippet'])): ?>
                            <div class="finding-snippet"><?= htmlspecialchars(substr($finding['snippet'], 0, 300)) ?>...</div>
                        <?php endif; ?>

                        <div class="finding-footer">
                            <?php
                            $keywords = is_string($finding['keywords']) ? json_decode($finding['keywords'], true) : $finding['keywords'];
                            if ($keywords):
                                foreach ($keywords as $keyword):
                            ?>
                                <span class="keyword-tag"><?= htmlspecialchars($keyword) ?></span>
                            <?php endforeach; endif; ?>
                            
                            <?php if (!empty($finding['url'])): ?>
                                <a href="<?= htmlspecialchars($finding['url']) ?>" target="_blank" class="link">View Source →</a>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="auto-refresh">
            Auto-refresh every 60 seconds
        </div>
    </div>

    <script>
        // Auto-refresh every 60 seconds
        setTimeout(() => location.reload(), 60000);
    </script>
</body>
</html>
