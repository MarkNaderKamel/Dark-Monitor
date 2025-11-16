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

        // Reputation scores table for IPs, domains, URLs
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS reputation_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entity_type TEXT NOT NULL,
                entity_value TEXT NOT NULL,
                score INTEGER DEFAULT 50,
                classification TEXT DEFAULT "unknown",
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                occurrences INTEGER DEFAULT 1,
                malicious_count INTEGER DEFAULT 0,
                metadata TEXT,
                UNIQUE(entity_type, entity_value)
            )
        ');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_reputation_entity ON reputation_scores(entity_type, entity_value)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_reputation_score ON reputation_scores(score)');

        // IOCs (Indicators of Compromise) table
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                threat_type TEXT,
                severity TEXT DEFAULT "MEDIUM",
                confidence INTEGER DEFAULT 50,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                description TEXT,
                tags TEXT,
                UNIQUE(ioc_type, ioc_value)
            )
        ');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)');
        $this->db->exec('CREATE INDEX IF NOT EXISTS idx_ioc_severity ON iocs(severity)');

        // Threat correlations table
        $this->db->exec('
            CREATE TABLE IF NOT EXISTS threat_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id_1 INTEGER,
                finding_id_2 INTEGER,
                correlation_score REAL DEFAULT 0.0,
                common_iocs TEXT,
                mitre_techniques TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(finding_id_1) REFERENCES findings(id),
                FOREIGN KEY(finding_id_2) REFERENCES findings(id)
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
     * Get database instance for direct queries
     */
    public function getDbInstance() {
        return $this->db;
    }

    /**
     * Insert IOC (Indicator of Compromise)
     */
    public function insertIOC($ioc) {
        try {
            $stmt = $this->db->prepare('
                INSERT OR REPLACE INTO iocs 
                (ioc_type, ioc_value, threat_type, severity, confidence, source, description, tags, last_seen)
                VALUES (:type, :value, :threat_type, :severity, :confidence, :source, :description, :tags, CURRENT_TIMESTAMP)
            ');

            $stmt->bindValue(':type', $ioc['type'], SQLITE3_TEXT);
            $stmt->bindValue(':value', $ioc['value'], SQLITE3_TEXT);
            $stmt->bindValue(':threat_type', $ioc['threat_type'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(':severity', $ioc['severity'] ?? 'MEDIUM', SQLITE3_TEXT);
            $stmt->bindValue(':confidence', $ioc['confidence'] ?? 50, SQLITE3_INTEGER);
            $stmt->bindValue(':source', $ioc['source'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(':description', $ioc['description'] ?? '', SQLITE3_TEXT);
            $stmt->bindValue(':tags', json_encode($ioc['tags'] ?? []), SQLITE3_TEXT);

            return $stmt->execute();

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to insert IOC: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Get IOCs by type
     */
    public function getIOCs($type = null, $limit = 100) {
        try {
            if ($type) {
                $stmt = $this->db->prepare('
                    SELECT * FROM iocs 
                    WHERE ioc_type = :type 
                    ORDER BY last_seen DESC 
                    LIMIT :limit
                ');
                $stmt->bindValue(':type', $type, SQLITE3_TEXT);
            } else {
                $stmt = $this->db->prepare('
                    SELECT * FROM iocs 
                    ORDER BY last_seen DESC 
                    LIMIT :limit
                ');
            }

            $stmt->bindValue(':limit', $limit, SQLITE3_INTEGER);
            $result = $stmt->execute();
            
            $iocs = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                $row['tags'] = json_decode($row['tags'], true);
                $iocs[] = $row;
            }

            return $iocs;

        } catch (Exception $e) {
            $this->logger->error('DATABASE', 'Failed to get IOCs: ' . $e->getMessage());
            return [];
        }
    }

    /**
     * Store enrichment data (VT, HIBP, Geo)
     */
    public function storeEnrichment($type, $value, $data) {
        try {
            $stmt = $this->db->prepare('
                INSERT OR REPLACE INTO enrichment_data (entity_type, entity_value, enrichment_data, updated_at)
                VALUES (:type, :value, :data, CURRENT_TIMESTAMP)
            ');
            
            $stmt->bindValue(':type', $type, SQLITE3_TEXT);
            $stmt->bindValue(':value', $value, SQLITE3_TEXT);
            $stmt->bindValue(':data', json_encode($data), SQLITE3_TEXT);
            
            return $stmt->execute();
        } catch (Exception $e) {
            // If table doesn't exist, create it
            $this->db->exec('
                CREATE TABLE IF NOT EXISTS enrichment_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    entity_value TEXT NOT NULL,
                    enrichment_data TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(entity_type, entity_value)
                )
            ');
            $this->db->exec('CREATE INDEX IF NOT EXISTS idx_enrichment ON enrichment_data(entity_type, entity_value)');
            
            // Retry
            $stmt = $this->db->prepare('
                INSERT OR REPLACE INTO enrichment_data (entity_type, entity_value, enrichment_data, updated_at)
                VALUES (:type, :value, :data, CURRENT_TIMESTAMP)
            ');
            
            $stmt->bindValue(':type', $type, SQLITE3_TEXT);
            $stmt->bindValue(':value', $value, SQLITE3_TEXT);
            $stmt->bindValue(':data', json_encode($data), SQLITE3_TEXT);
            
            return $stmt->execute();
        }
    }

    /**
     * Get enrichment data (cached for 24 hours)
     */
    public function getEnrichment($type, $value) {
        try {
            $stmt = $this->db->prepare('
                SELECT enrichment_data, updated_at 
                FROM enrichment_data 
                WHERE entity_type = :type AND entity_value = :value
            ');
            
            $stmt->bindValue(':type', $type, SQLITE3_TEXT);
            $stmt->bindValue(':value', $value, SQLITE3_TEXT);
            
            $result = $stmt->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            
            if ($row) {
                // Check if data is less than 24 hours old
                $updatedAt = strtotime($row['updated_at']);
                if (time() - $updatedAt < 86400) {
                    return json_decode($row['enrichment_data'], true);
                }
            }
            
            return null;
        } catch (Exception $e) {
            return null;
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
