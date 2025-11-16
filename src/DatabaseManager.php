<?php
/**
 * Database Manager Class
 * 
 * SQLite database layer for better data management and querying
 */

class DatabaseManager {
    private $db;
    private $logger;
    private $dbPath;

    public function __construct($config, $logger) {
        $this->logger = $logger;
        $this->dbPath = $config['storage']['database_file'] ?? __DIR__ . '/../data/monitoring.db';
        
        $this->initDatabase();
    }

    /**
     * Initialize SQLite database
     */
    private function initDatabase() {
        try {
            // Create data directory if needed
            $dir = dirname($this->dbPath);
            if (!is_dir($dir)) {
                mkdir($dir, 0755, true);
            }

            $this->db = new SQLite3($this->dbPath);
            $this->db->busyTimeout(5000);

            // Create tables
            $this->createTables();

            $this->logger->info('DATABASE', 'Database initialized: ' . $this->dbPath);

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to initialize database: ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Create database tables
     */
    private function createTables() {
        // Findings table
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT NOT NULL,
                title TEXT NOT NULL,
                url TEXT,
                snippet TEXT,
                keywords TEXT,
                threat_score INTEGER DEFAULT 0,
                severity TEXT DEFAULT "LOW",
                iocs TEXT,
                status TEXT DEFAULT "new",
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ');

        // Create indexes
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_timestamp ON findings(timestamp)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_source ON findings(source)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_status ON findings(status)');

        // Statistics table
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date DATE NOT NULL,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                sources_checked INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(date)
            )
        ');

        // Monitoring sessions table
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                ended_at DATETIME,
                findings_count INTEGER DEFAULT 0,
                sources_count INTEGER DEFAULT 0,
                errors_count INTEGER DEFAULT 0,
                status TEXT DEFAULT "running"
            )
        ');
    }

    /**
     * Insert a finding
     */
    public function insertFinding($finding) {
        try {
            $stmt = $this->db->prepare('
                INSERT INTO findings 
                (timestamp, source, title, url, snippet, keywords, threat_score, severity, iocs, status)
                VALUES 
                (:timestamp, :source, :title, :url, :snippet, :keywords, :threat_score, :severity, :iocs, :status)
            ');

            $stmt->bindValue(':timestamp', $finding['timestamp'] ?? date('Y-m-d H:i:s'), SQLITE3_TEXT);
            $stmt->bindValue(':source', $finding['source'], SQLITE3_TEXT);
            $stmt->bindValue(':title', $finding['title'], SQLITE3_TEXT);
            $stmt->bindValue(':url', $finding['url'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(':snippet', $finding['snippet'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(':keywords', json_encode($finding['keywords'] ?? []), SQLITE3_TEXT);
            $stmt->bindValue(':threat_score', $finding['threat_score'] ?? 0, SQLITE3_INTEGER);
            $stmt->bindValue(':severity', $finding['severity'] ?? 'LOW', SQLITE3_TEXT);
            $stmt->bindValue(':iocs', json_encode($finding['iocs'] ?? []), SQLITE3_TEXT);
            $stmt->bindValue(':status', $finding['status'] ?? 'new', SQLITE3_TEXT);

            $result = $stmt->execute();
            $findingId = $this->db->lastInsertRowID();

            $this->logger->debug('DATABASE', "Inserted finding ID: $findingId");
            
            return $findingId;

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to insert finding: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get findings with filters
     */
    public function getFindings($filters = []) {
        $sql = 'SELECT * FROM findings WHERE 1=1';
        $params = [];

        if (isset($filters['severity'])) {
            $sql .= ' AND severity = :severity';
            $params[':severity'] = $filters['severity'];
        }

        if (isset($filters['source'])) {
            $sql .= ' AND source LIKE :source';
            $params[':source'] = '%' . $filters['source'] . '%';
        }

        if (isset($filters['status'])) {
            $sql .= ' AND status = :status';
            $params[':status'] = $filters['status'];
        }

        if (isset($filters['from_date'])) {
            $sql .= ' AND timestamp >= :from_date';
            $params[':from_date'] = $filters['from_date'];
        }

        if (isset($filters['to_date'])) {
            $sql .= ' AND timestamp <= :to_date';
            $params[':to_date'] = $filters['to_date'];
        }

        $sql .= ' ORDER BY timestamp DESC';

        if (isset($filters['limit'])) {
            $sql .= ' LIMIT :limit';
        }

        try {
            $stmt = $this->db->prepare($sql);
            
            foreach ($params as $key => $value) {
                $stmt->bindValue($key, $value);
            }

            if (isset($filters['limit'])) {
                $stmt->bindValue(':limit', (int)$filters['limit'], SQLITE3_INTEGER);
            }

            $result = $stmt->execute();
            $findings = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $row['keywords'] = json_decode($row['keywords'], true);
                $row['iocs'] = json_decode($row['iocs'], true);
                $findings[] = $row;
            }

            return $findings;

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to get findings: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get statistics
     */
    public function getStatistics($days = 30) {
        try {
            $stmt = $this->db->prepare('
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN severity = "CRITICAL" THEN 1 ELSE 0 END) as critical,
                    SUM(CASE WHEN severity = "HIGH" THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN severity = "MEDIUM" THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN severity = "LOW" THEN 1 ELSE 0 END) as low,
                    COUNT(DISTINCT source) as sources,
                    DATE(timestamp) as date
                FROM findings
                WHERE timestamp >= date("now", "-" || :days || " days")
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
            ');

            $stmt->bindValue(':days', $days, SQLITE3_INTEGER);
            $result = $stmt->execute();

            $stats = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $stats[] = $row;
            }

            return $stats;

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to get statistics: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Update finding status
     */
    public function updateFindingStatus($id, $status) {
        try {
            $stmt = $this->db->prepare('
                UPDATE findings 
                SET status = :status, updated_at = CURRENT_TIMESTAMP 
                WHERE id = :id
            ');

            $stmt->bindValue(':status', $status, SQLITE3_TEXT);
            $stmt->bindValue(':id', $id, SQLITE3_INTEGER);

            return $stmt->execute();

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to update status: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Search findings by keyword
     */
    public function searchFindings($keyword) {
        try {
            $stmt = $this->db->prepare('
                SELECT * FROM findings 
                WHERE title LIKE :keyword 
                   OR snippet LIKE :keyword 
                   OR url LIKE :keyword
                ORDER BY timestamp DESC
                LIMIT 100
            ');

            $searchTerm = '%' . $keyword . '%';
            $stmt->bindValue(':keyword', $searchTerm, SQLITE3_TEXT);

            $result = $stmt->execute();
            $findings = [];

            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $row['keywords'] = json_decode($row['keywords'], true);
                $row['iocs'] = json_decode($row['iocs'], true);
                $findings[] = $row;
            }

            return $findings;

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to search findings: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Get recent activity summary
     */
    public function getRecentActivity($hours = 24) {
        try {
            $stmt = $this->db->prepare('
                SELECT 
                    COUNT(*) as count,
                    severity,
                    source
                FROM findings
                WHERE timestamp >= datetime("now", "-" || :hours || " hours")
                GROUP BY severity, source
                ORDER BY count DESC
            ');

            $stmt->bindValue(':hours', $hours, SQLITE3_INTEGER);
            $result = $stmt->execute();

            $activity = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $activity[] = $row;
            }

            return $activity;

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to get activity: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Close database connection
     */
    public function close() {
        if ($this->db) {
            $this->db->close();
        }
    }
}
