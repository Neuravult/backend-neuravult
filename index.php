<?php
/**
 * Neuravult AI Platform - Advanced PHP Backend
 * Complete integrated system with enhanced features, performance, and automation
 */

// ==================== CONFIGURATION ====================
class AdvancedConfig {
    // Database Configuration
    const DB_HOST = 'localhost';
    const DB_NAME = 'neuravult';
    const DB_USER = 'root';
    const DB_PASS = '';
    const DB_CHARSET = 'utf8mb4';
    
    // Advanced Security
    const JWT_SECRET = 'neuravult_advanced_secret_2024_' . uniqid();
    const JWT_ALGORITHM = 'HS256';
    const ENCRYPTION_KEY = 'neuravult_encryption_key_2024';
    const CSRF_SECRET = 'neuravult_csrf_protection_2024';
    
    // Performance & Caching
    const REDIS_ENABLED = true;
    const REDIS_HOST = '127.0.0.1';
    const REDIS_PORT = 6379;
    const CACHE_TTL = 3600; // 1 hour
    const RATE_LIMIT_REQUESTS = 100; // requests per minute
    const RATE_LIMIT_WINDOW = 60; // seconds
    
    // API & System
    const API_VERSION = 'v2';
    const CORS_ORIGINS = ['http://localhost:3000', 'https://neuravult.com'];
    const MAX_FILE_SIZE = 10485760; // 10MB
    const ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'svg', 'webp'];
    
    // Email & Notifications
    const SMTP_HOST = 'smtp.gmail.com';
    const SMTP_PORT = 587;
    const SMTP_USER = 'noreply@neuravult.com';
    const SMTP_PASS = 'your_secure_smtp_password';
    
    // AI & Automation
    const OPENAI_API_KEY = 'your_openai_key';
    const GEMINI_API_KEY = 'your_gemini_key';
    const AUTOMATION_ENABLED = true;
    
    // Monitoring & Analytics
    const ANALYTICS_ENABLED = true;
    const LOG_LEVEL = 'DEBUG'; // DEBUG, INFO, WARN, ERROR
    const PERFORMANCE_MONITORING = true;
}

// ==================== ADVANCED DATABASE LAYER ====================
class AdvancedDatabase {
    private $pdo;
    private $redis;
    private static $instance = null;
    private $queryLog = [];
    private $performanceStats = [];

    private function __construct() {
        $this->connectDatabase();
        if (AdvancedConfig::REDIS_ENABLED) {
            $this->connectRedis();
        }
    }

    private function connectDatabase() {
        try {
            $dsn = "mysql:host=" . AdvancedConfig::DB_HOST . ";dbname=" . AdvancedConfig::DB_NAME . ";charset=" . AdvancedConfig::DB_CHARSET;
            $this->pdo = new PDO($dsn, AdvancedConfig::DB_USER, AdvancedConfig::DB_PASS, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::ATTR_PERSISTENT => true,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET time_zone='+00:00', sql_mode='STRICT_TRANS_TABLES'"
            ]);
            
            // Performance optimization
            $this->pdo->exec("SET SESSION query_cache_type = ON");
            $this->pdo->exec("SET SESSION innodb_buffer_pool_size = 134217728"); // 128MB
            
        } catch (PDOException $e) {
            throw new Exception("Advanced database connection failed: " . $e->getMessage());
        }
    }

    private function connectRedis() {
        try {
            $this->redis = new Redis();
            $this->redis->connect(AdvancedConfig::REDIS_HOST, AdvancedConfig::REDIS_PORT, 2.5);
            $this->redis->setOption(Redis::OPT_SERIALIZER, Redis::SERIALIZER_PHP);
        } catch (Exception $e) {
            error_log("Redis connection failed: " . $e->getMessage());
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    // Advanced Caching System
    public function cacheGet($key) {
        if (!$this->redis || !AdvancedConfig::REDIS_ENABLED) {
            return false;
        }
        try {
            return $this->redis->get("neuravult:" . $key);
        } catch (Exception $e) {
            error_log("Redis get error: " . $e->getMessage());
            return false;
        }
    }

    public function cacheSet($key, $value, $ttl = null) {
        if (!$this->redis || !AdvancedConfig::REDIS_ENABLED) {
            return false;
        }
        try {
            return $this->redis->setex("neuravult:" . $key, $ttl ?? AdvancedConfig::CACHE_TTL, $value);
        } catch (Exception $e) {
            error_log("Redis set error: " . $e->getMessage());
            return false;
        }
    }

    public function cacheDelete($key) {
        if (!$this->redis || !AdvancedConfig::REDIS_ENABLED) {
            return false;
        }
        try {
            return $this->redis->del("neuravult:" . $key);
        } catch (Exception $e) {
            error_log("Redis delete error: " . $e->getMessage());
            return false;
        }
    }

    public function cacheClear($pattern = null) {
        if (!$this->redis || !AdvancedConfig::REDIS_ENABLED) {
            return false;
        }
        try {
            $keys = $this->redis->keys("neuravult:" . ($pattern ?: "*"));
            if (!empty($keys)) {
                return $this->redis->del($keys);
            }
        } catch (Exception $e) {
            error_log("Redis clear error: " . $e->getMessage());
        }
        return false;
    }

    // Enhanced Query Methods with Performance Monitoring
    public function query($sql, $params = [], $useCache = false) {
        $startTime = microtime(true);
        $cacheKey = $useCache ? 'query_' . md5($sql . serialize($params)) : null;
        
        if ($useCache && $cacheKey) {
            $cached = $this->cacheGet($cacheKey);
            if ($cached !== false) {
                $this->logPerformance($sql, 0, true); // Cache hit
                return $cached;
            }
        }

        try {
            $stmt = $this->pdo->prepare($sql);
            $stmt->execute($params);
            $result = $stmt->fetchAll();
            
            $executionTime = microtime(true) - $startTime;
            $this->logPerformance($sql, $executionTime, false);
            
            if ($useCache && $cacheKey) {
                $this->cacheSet($cacheKey, $result);
            }
            
            $this->queryLog[] = [
                'sql' => $sql,
                'params' => $params,
                'time' => $executionTime,
                'cached' => false
            ];
            
            return $result;
        } catch (PDOException $e) {
            $this->logError('Database Query Error', [
                'sql' => $sql,
                'params' => $params,
                'error' => $e->getMessage()
            ]);
            throw new Exception("Query execution failed: " . $e->getMessage());
        }
    }

    public function fetch($sql, $params = [], $useCache = false) {
        $result = $this->query($sql, $params, $useCache);
        return $result[0] ?? null;
    }

    public function fetchAll($sql, $params = [], $useCache = false) {
        return $this->query($sql, $params, $useCache);
    }

    public function insert($table, $data, $ignoreDuplicate = false) {
        $columns = implode(', ', array_keys($data));
        $placeholders = ':' . implode(', :', array_keys($data));
        $command = $ignoreDuplicate ? 'INSERT IGNORE' : 'INSERT';
        
        $sql = "$command INTO $table ($columns) VALUES ($placeholders)";
        $this->query($sql, $data);
        
        // Clear relevant cache
        $this->cacheClear("{$table}_*");
        
        return $this->pdo->lastInsertId();
    }

    public function update($table, $data, $where, $whereParams = [], $limit = null) {
        $setParts = [];
        foreach (array_keys($data) as $column) {
            $setParts[] = "$column = :$column";
        }
        $setClause = implode(', ', $setParts);
        
        $sql = "UPDATE $table SET $setClause WHERE $where";
        if ($limit) {
            $sql .= " LIMIT " . intval($limit);
        }
        
        $params = array_merge($data, $whereParams);
        $affected = $this->query($sql, $params);
        
        // Clear relevant cache
        $this->cacheClear("{$table}_*");
        
        return count($affected);
    }

    public function delete($table, $where, $params = [], $limit = null) {
        $sql = "DELETE FROM $table WHERE $where";
        if ($limit) {
            $sql .= " LIMIT " . intval($limit);
        }
        
        $result = $this->query($sql, $params);
        
        // Clear relevant cache
        $this->cacheClear("{$table}_*");
        
        return count($result);
    }

    // Transaction Management with Retry Logic
    public function beginTransaction() {
        $retries = 3;
        while ($retries-- > 0) {
            try {
                return $this->pdo->beginTransaction();
            } catch (Exception $e) {
                if ($retries === 0) throw $e;
                usleep(100000); // 100ms delay
            }
        }
    }

    public function commit() {
        return $this->pdo->commit();
    }

    public function rollBack() {
        return $this->pdo->rollBack();
    }

    // Performance Monitoring
    private function logPerformance($sql, $time, $cached) {
        if (AdvancedConfig::PERFORMANCE_MONITORING) {
            $this->performanceStats[] = [
                'query' => $sql,
                'execution_time' => $time,
                'cached' => $cached,
                'timestamp' => microtime(true)
            ];
            
            // Log slow queries
            if ($time > 1.0) { // More than 1 second
                $this->logWarning('Slow Query Detected', [
                    'query' => $sql,
                    'execution_time' => $time,
                    'cached' => $cached
                ]);
            }
        }
    }

    public function getPerformanceStats() {
        return $this->performanceStats;
    }

    public function getQueryLog() {
        return $this->queryLog;
    }

    // Advanced Logging System
    private function logError($message, $context = []) {
        $this->log('ERROR', $message, $context);
    }

    private function logWarning($message, $context = []) {
        $this->log('WARN', $message, $context);
    }

    private function log($level, $message, $context = []) {
        if ($this->shouldLog($level)) {
            $logEntry = [
                'timestamp' => date('Y-m-d H:i:s'),
                'level' => $level,
                'message' => $message,
                'context' => $context,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ];
            
            file_put_contents(
                __DIR__ . '/logs/advanced_system.log', 
                json_encode($logEntry) . PHP_EOL,
                FILE_APPEND | LOCK_EX
            );
        }
    }

    private function shouldLog($level) {
        $levels = ['DEBUG' => 1, 'INFO' => 2, 'WARN' => 3, 'ERROR' => 4];
        $configLevel = AdvancedConfig::LOG_LEVEL;
        return $levels[$level] >= ($levels[$configLevel] ?? 3);
    }
}

// ==================== ADVANCED SECURITY & AUTHENTICATION ====================
class AdvancedSecurity {
    private static $encryptionMethod = 'AES-256-CBC';
    private static $hashAlgorithm = 'sha256';

    public static function encrypt($data) {
        $key = hash(self::$hashAlgorithm, AdvancedConfig::ENCRYPTION_KEY, true);
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(self::$encryptionMethod));
        $encrypted = openssl_encrypt($data, self::$encryptionMethod, $key, 0, $iv);
        return base64_encode($encrypted . '::' . $iv);
    }

    public static function decrypt($data) {
        $key = hash(self::$hashAlgorithm, AdvancedConfig::ENCRYPTION_KEY, true);
        list($encrypted_data, $iv) = explode('::', base64_decode($data), 2);
        return openssl_decrypt($encrypted_data, self::$encryptionMethod, $key, 0, $iv);
    }

    public static function generateCSRFToken($userId) {
        $token = bin2hex(random_bytes(32));
        $expires = time() + 3600; // 1 hour
        $data = $userId . '|' . $token . '|' . $expires;
        $hash = hash_hmac('sha256', $data, AdvancedConfig::CSRF_SECRET);
        
        return base64_encode($data . '|' . $hash);
    }

    public static function validateCSRFToken($token, $userId) {
        $decoded = base64_decode($token);
        $parts = explode('|', $decoded);
        
        if (count($parts) !== 4) return false;
        
        list($tokenUserId, $tokenValue, $expires, $hash) = $parts;
        
        if ($tokenUserId != $userId) return false;
        if ($expires < time()) return false;
        
        $data = $tokenUserId . '|' . $tokenValue . '|' . $expires;
        $expectedHash = hash_hmac('sha256', $data, AdvancedConfig::CSRF_SECRET);
        
        return hash_equals($hash, $expectedHash);
    }

    public static function sanitizeInput($input) {
        if (is_array($input)) {
            return array_map([self::class, 'sanitizeInput'], $input);
        }
        
        $input = trim($input);
        $input = stripslashes($input);
        $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        return $input;
    }

    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function validateURL($url) {
        return filter_var($url, FILTER_VALIDATE_URL) !== false;
    }

    public static function generateStrongPassword($length = 12) {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-=+';
        $password = '';
        $charsLength = strlen($chars) - 1;
        
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, $charsLength)];
        }
        
        return $password;
    }
}

class AdvancedJWTHandler {
    private static $secret;
    
    public static function init() {
        self::$secret = AdvancedConfig::JWT_SECRET;
    }

    public static function generateToken($payload, $expiryHours = 24) {
        self::init();
        
        $header = json_encode(['typ' => 'JWT', 'alg' => AdvancedConfig::JWT_ALGORITHM, 'ver' => '2.0']);
        $payload['iat'] = time();
        $payload['exp'] = time() + ($expiryHours * 3600);
        $payload['jti'] = bin2hex(random_bytes(16)); // Unique token ID
        $payload = json_encode($payload);

        $base64UrlHeader = self::base64UrlEncode($header);
        $base64UrlPayload = self::base64UrlEncode($payload);

        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, self::$secret, true);
        $base64UrlSignature = self::base64UrlEncode($signature);

        $token = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;

        // Store token in cache for blacklisting capability
        $db = AdvancedDatabase::getInstance();
        $db->cacheSet("jwt_" . $payload['jti'], $token, $expiryHours * 3600);

        return $token;
    }

    public static function validateToken($token) {
        self::init();
        
        if (!$token) {
            return false;
        }

        try {
            $tokenParts = explode('.', $token);
            if (count($tokenParts) != 3) {
                return false;
            }

            // Check if token is blacklisted
            $payload = json_decode(self::base64UrlDecode($tokenParts[1]), true);
            $db = AdvancedDatabase::getInstance();
            if ($db->cacheGet("jwt_blacklist_" . $payload['jti'])) {
                return false;
            }

            $header = self::base64UrlDecode($tokenParts[0]);
            $payload = self::base64UrlDecode($tokenParts[1]);
            $signatureProvided = $tokenParts[2];

            $base64UrlHeader = self::base64UrlEncode($header);
            $base64UrlPayload = self::base64UrlEncode($payload);
            $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, self::$secret, true);
            $base64UrlSignature = self::base64UrlEncode($signature);

            if (!hash_equals($base64UrlSignature, $signatureProvided)) {
                return false;
            }

            $payload = json_decode($payload, true);

            // Check expiration
            if (isset($payload['exp']) && $payload['exp'] < time()) {
                return false;
            }

            return $payload;
        } catch (Exception $e) {
            return false;
        }
    }

    public static function invalidateToken($token) {
        $payload = self::validateToken($token);
        if ($payload && isset($payload['jti'])) {
            $db = AdvancedDatabase::getInstance();
            $db->cacheSet("jwt_blacklist_" . $payload['jti'], true, $payload['exp'] - time());
            return true;
        }
        return false;
    }

    private static function base64UrlEncode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}

// ==================== ENHANCED MIDDLEWARE SYSTEM ====================
class AdvancedMiddleware {
    private static $rateLimitStore = [];

    public static function authenticate($requiredRole = null) {
        $headers = apache_request_headers();
        $token = null;

        // Get token from Authorization header
        if (isset($headers['Authorization'])) {
            $authHeader = $headers['Authorization'];
            if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
                $token = $matches[1];
            }
        }

        // Fallback to GET parameter
        if (!$token && isset($_GET['token'])) {
            $token = $_GET['token'];
        }

        if (!$token) {
            AdvancedResponse::json(['error' => 'Authentication token required', 'code' => 'AUTH_REQUIRED'], 401);
            exit;
        }

        $payload = AdvancedJWTHandler::validateToken($token);
        
        if (!$payload) {
            AdvancedResponse::json(['error' => 'Invalid or expired token', 'code' => 'INVALID_TOKEN'], 401);
            exit;
        }

        if ($requiredRole && $payload['role'] !== $requiredRole && $payload['role'] !== 'admin') {
            AdvancedResponse::json(['error' => 'Insufficient permissions', 'code' => 'INSUFFICIENT_PERMISSIONS'], 403);
            exit;
        }

        return $payload;
    }

    public static function optionalAuth() {
        $headers = apache_request_headers();
        $token = null;

        if (isset($headers['Authorization'])) {
            $authHeader = $headers['Authorization'];
            if (preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
                $token = $matches[1];
            }
        }

        if ($token) {
            return AdvancedJWTHandler::validateToken($token);
        }

        return null;
    }

    public static function requireRole($requiredRole) {
        $user = self::authenticate();
        
        if ($user['role'] !== $requiredRole && $user['role'] !== 'admin') {
            AdvancedResponse::json(['error' => 'Insufficient permissions', 'code' => 'INSUFFICIENT_PERMISSIONS'], 403);
            exit;
        }

        return $user;
    }

    public static function requireAdmin() {
        return self::requireRole('admin');
    }

    public static function rateLimit($key, $maxRequests = null, $window = null) {
        $maxRequests = $maxRequests ?? AdvancedConfig::RATE_LIMIT_REQUESTS;
        $window = $window ?? AdvancedConfig::RATE_LIMIT_WINDOW;
        $userIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        $rateKey = "rate_limit:{$key}:{$userIP}";
        $db = AdvancedDatabase::getInstance();
        
        $current = $db->cacheGet($rateKey);
        if (!$current) {
            $current = ['count' => 1, 'reset_time' => time() + $window];
        } else {
            if (time() > $current['reset_time']) {
                $current = ['count' => 1, 'reset_time' => time() + $window];
            } else {
                $current['count']++;
            }
        }
        
        $db->cacheSet($rateKey, $current, $window);
        
        $remaining = max(0, $maxRequests - $current['count']);
        $resetTime = $current['reset_time'];
        
        header("X-RateLimit-Limit: $maxRequests");
        header("X-RateLimit-Remaining: $remaining");
        header("X-RateLimit-Reset: $resetTime");
        
        if ($current['count'] > $maxRequests) {
            AdvancedResponse::json([
                'error' => 'Rate limit exceeded',
                'code' => 'RATE_LIMIT_EXCEEDED',
                'retry_after' => $resetTime - time()
            ], 429);
            exit;
        }
        
        return true;
    }

    public static function validateCSRF() {
        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        $userId = self::authenticate()['user_id'] ?? null;
        
        if (!$token || !$userId || !AdvancedSecurity::validateCSRFToken($token, $userId)) {
            AdvancedResponse::json(['error' => 'Invalid CSRF token', 'code' => 'INVALID_CSRF'], 403);
            exit;
        }
        
        return true;
    }
}

// ==================== ADVANCED RESPONSE HANDLER ====================
class AdvancedResponse {
    public static function json($data, $statusCode = 200, $cacheControl = null) {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        header('Access-Control-Allow-Origin: ' . implode(',', AdvancedConfig::CORS_ORIGINS));
        header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token, X-Requested-With');
        header('Access-Control-Allow-Credentials: true');
        
        if ($cacheControl) {
            header("Cache-Control: $cacheControl");
        } else {
            header('Cache-Control: no-cache, no-store, must-revalidate');
        }
        
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            exit(0);
        }
        
        // Add performance headers
        if (AdvancedConfig::PERFORMANCE_MONITORING) {
            header('X-Response-Time: ' . (microtime(true) - $_SERVER['REQUEST_TIME_FLOAT']));
        }
        
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    public static function success($data = null, $message = 'Success', $meta = []) {
        $response = [
            'success' => true,
            'message' => $message,
            'data' => $data,
            'timestamp' => time(),
            'version' => AdvancedConfig::API_VERSION
        ];
        
        if (!empty($meta)) {
            $response['meta'] = $meta;
        }
        
        self::json($response);
    }

    public static function error($message = 'Error', $statusCode = 400, $errors = [], $code = null) {
        $response = [
            'success' => false,
            'message' => $message,
            'code' => $code,
            'errors' => $errors,
            'timestamp' => time(),
            'version' => AdvancedConfig::API_VERSION
        ];
        
        self::json($response, $statusCode);
    }

    public static function paginated($data, $total, $page, $limit, $additionalMeta = []) {
        $totalPages = ceil($total / $limit);
        $meta = array_merge([
            'pagination' => [
                'total' => $total,
                'count' => count($data),
                'per_page' => $limit,
                'current_page' => $page,
                'total_pages' => $totalPages,
                'has_more' => $page < $totalPages
            ]
        ], $additionalMeta);
        
        self::success($data, 'Data retrieved successfully', $meta);
    }

    public static function notFound($message = 'Resource not found') {
        self::error($message, 404, [], 'RESOURCE_NOT_FOUND');
    }

    public static function unauthorized($message = 'Unauthorized') {
        self::error($message, 401, [], 'UNAUTHORIZED');
    }

    public static function forbidden($message = 'Forbidden') {
        self::error($message, 403, [], 'FORBIDDEN');
    }

    public static function file($filePath, $filename = null, $contentType = 'application/octet-stream') {
        if (!file_exists($filePath)) {
            self::notFound('File not found');
        }

        $filename = $filename ?? basename($filePath);
        $fileSize = filesize($filePath);

        header('Content-Type: ' . $contentType);
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . $fileSize);
        header('Cache-Control: public, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');

        readfile($filePath);
        exit;
    }
}

// ==================== AI & AUTOMATION ENGINE ====================
class AIAutomationEngine {
    private $db;
    private $openaiKey;
    private $geminiKey;

    public function __construct() {
        $this->db = AdvancedDatabase::getInstance();
        $this->openaiKey = AdvancedConfig::OPENAI_API_KEY;
        $this->geminiKey = AdvancedConfig::GEMINI_API_KEY;
    }

    // AI-Powered Content Generation
    public function generateToolDescription($toolName, $category, $features = []) {
        $prompt = "Generate a compelling description for an AI tool called \"{$toolName}\" in the {$category} category.";
        
        if (!empty($features)) {
            $featuresList = implode(', ', $features);
            $prompt .= " Key features include: {$featuresList}.";
        }
        
        $prompt .= " Make it engaging for potential users, highlight benefits, and keep it under 200 words.";

        return $this->callOpenAI($prompt, 150);
    }

    public function generateCategoryDescription($categoryName) {
        $prompt = "Write a comprehensive description for the AI tools category: \"{$categoryName}\". ";
        $prompt .= "Explain what types of AI tools belong here, common use cases, and why this category is important. ";
        $prompt .= "Keep it informative and engaging, around 150 words.";

        return $this->callGemini($prompt);
    }

    public function generateBlogPost($topic, $keywords = []) {
        $keywordsStr = !empty($keywords) ? "Include these keywords: " . implode(', ', $keywords) . "." : "";
        
        $prompt = "Write a comprehensive blog post about: \"{$topic}\" related to AI tools and technology. ";
        $prompt .= "{$keywordsStr} Make it engaging, informative, and include practical insights. ";
        $prompt .= "Structure it with introduction, main content, and conclusion. Target length: 800-1000 words.";

        return $this->callOpenAI($prompt, 800);
    }

    public function analyzeToolTrends($timeframe = '30 days') {
        // Analyze tool performance and trends
        $sql = "
            SELECT 
                c.name as category,
                COUNT(t.id) as tool_count,
                AVG(t.rating) as avg_rating,
                AVG(t.views) as avg_views,
                SUM(t.views) as total_views
            FROM tools t
            JOIN categories c ON t.category_id = c.id
            WHERE t.created_at >= DATE_SUB(NOW(), INTERVAL {$timeframe})
            AND t.status = 'approved'
            GROUP BY c.id
            ORDER BY total_views DESC
        ";

        $trends = $this->db->fetchAll($sql, [], true);

        $analysis = "Based on data from the last {$timeframe}, here are the AI tool trends:\n\n";
        
        foreach ($trends as $trend) {
            $analysis .= "• {$trend['category']}: {$trend['tool_count']} tools, ";
            $analysis .= "average rating: " . round($trend['avg_rating'], 2) . ", ";
            $analysis .= "total views: {$trend['total_views']}\n";
        }

        $analysis .= "\nRecommendation: Consider adding more tools in high-performing categories.";

        return $analysis;
    }

    public function autoTagTools() {
        // Automatically generate tags for tools based on their descriptions
        $sql = "SELECT id, name, description FROM tools WHERE status = 'approved'";
        $tools = $this->db->fetchAll($sql);

        $updated = 0;
        foreach ($tools as $tool) {
            $prompt = "Generate 5-7 relevant tags for an AI tool called \"{$tool['name']}\" with this description: {$tool['description']}. ";
            $prompt .= "Return only comma-separated tags, no explanations.";

            $tags = $this->callOpenAI($prompt, 50);
            if ($tags) {
                $tagArray = array_map('trim', explode(',', $tags));
                $tagArray = array_slice($tagArray, 0, 7); // Limit to 7 tags
                
                // Update tool tags
                $this->db->delete('tool_tags', 'tool_id = :tool_id', ['tool_id' => $tool['id']]);
                
                foreach ($tagArray as $tag) {
                    $this->db->insert('tool_tags', [
                        'tool_id' => $tool['id'],
                        'tag' => $tag
                    ]);
                }
                
                $updated++;
            }
        }

        return $updated;
    }

    public function smartRecommendations($userId, $limit = 5) {
        // AI-powered personalized tool recommendations
        $userInterests = $this->getUserInterests($userId);
        
        $sql = "
            SELECT t.*, c.name as category_name,
                   (SELECT GROUP_CONCAT(tag) FROM tool_tags WHERE tool_id = t.id) as tags
            FROM tools t
            JOIN categories c ON t.category_id = c.id
            WHERE t.status = 'approved'
            ORDER BY t.rating DESC, t.views DESC
            LIMIT 50
        ";

        $tools = $this->db->fetchAll($sql, [], true);
        $scoredTools = [];

        foreach ($tools as $tool) {
            $score = $this->calculateRecommendationScore($tool, $userInterests);
            $scoredTools[] = ['tool' => $tool, 'score' => $score];
        }

        // Sort by score and return top recommendations
        usort($scoredTools, function($a, $b) {
            return $b['score'] <=> $a['score'];
        });

        return array_slice(array_column($scoredTools, 'tool'), 0, $limit);
    }

    private function getUserInterests($userId) {
        // Analyze user behavior to determine interests
        $sql = "
            SELECT 
                c.id as category_id,
                c.name as category_name,
                COUNT(DISTINCT uf.tool_id) as favorite_count,
                COUNT(DISTINCT tr.tool_id) as review_count,
                AVG(tr.rating) as avg_rating
            FROM users u
            LEFT JOIN user_favorites uf ON u.id = uf.user_id
            LEFT JOIN tools t ON uf.tool_id = t.id
            LEFT JOIN categories c ON t.category_id = c.id
            LEFT JOIN tool_reviews tr ON u.id = tr.user_id AND tr.tool_id = t.id
            WHERE u.id = :user_id
            GROUP BY c.id, c.name
            ORDER BY favorite_count DESC, review_count DESC
        ";

        return $this->db->fetchAll($sql, ['user_id' => $userId]);
    }

    private function calculateRecommendationScore($tool, $userInterests) {
        $score = $tool['rating'] * 20; // Base score from rating
        
        // Boost score based on user interests
        foreach ($userInterests as $interest) {
            if ($tool['category_name'] === $interest['category_name']) {
                $score += $interest['favorite_count'] * 10;
                $score += $interest['review_count'] * 5;
                $score += $interest['avg_rating'] * 15;
            }
        }
        
        // Consider tool popularity
        $score += min($tool['views'] / 100, 50); // Cap popularity boost
        
        return $score;
    }

    private function callOpenAI($prompt, $maxTokens = 150) {
        if (!$this->openaiKey || $this->openaiKey === 'your_openai_key') {
            return null;
        }

        try {
            $data = [
                'model' => 'gpt-3.5-turbo',
                'messages' => [
                    ['role' => 'user', 'content' => $prompt]
                ],
                'max_tokens' => $maxTokens,
                'temperature' => 0.7
            ];

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => 'https://api.openai.com/v1/chat/completions',
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => json_encode($data),
                CURLOPT_HTTPHEADER => [
                    'Content-Type: application/json',
                    'Authorization: Bearer ' . $this->openaiKey
                ],
                CURLOPT_TIMEOUT => 30
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode === 200) {
                $result = json_decode($response, true);
                return trim($result['choices'][0]['message']['content'] ?? '');
            }
        } catch (Exception $e) {
            error_log("OpenAI API error: " . $e->getMessage());
        }

        return null;
    }

    private function callGemini($prompt) {
        if (!$this->geminiKey || $this->geminiKey === 'your_gemini_key') {
            return null;
        }

        // Implementation for Gemini API would go here
        // Similar structure to OpenAI call
        return null;
    }
}

// ==================== ENHANCED MODELS WITH ADVANCED FEATURES ====================

class AdvancedUser {
    private $db;
    private $table = 'users';
    private $aiEngine;

    public function __construct() {
        $this->db = AdvancedDatabase::getInstance();
        $this->aiEngine = new AIAutomationEngine();
    }

    public function create($data) {
        // Enhanced validation
        $required = ['name', 'email', 'password'];
        foreach ($required as $field) {
            if (empty($data[$field])) {
                throw new Exception("$field is required");
            }
        }

        if (!AdvancedSecurity::validateEmail($data['email'])) {
            throw new Exception("Invalid email format");
        }

        if ($this->findByEmail($data['email'])) {
            throw new Exception("Email already registered");
        }

        // Enhanced password strength
        if (strlen($data['password']) < 8) {
            throw new Exception("Password must be at least 8 characters long");
        }

        $data['password'] = password_hash($data['password'], PASSWORD_DEFAULT);
        
        if (isset($data['affiliate_optin']) && $data['affiliate_optin']) {
            $data['affiliate_id'] = $this->generateAffiliateId();
        }

        // Add security fields
        $data['email_verification_token'] = bin2hex(random_bytes(32));
        $data['created_at'] = date('Y-m-d H:i:s');
        $data['updated_at'] = date('Y-m-d H:i:s');

        unset($data['affiliate_optin']);

        $userId = $this->db->insert($this->table, $data);

        // Trigger welcome email
        $this->sendWelcomeEmail($data['email'], $data['name']);

        return $userId;
    }

    public function findByEmail($email) {
        $cacheKey = "user_email_" . md5($email);
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $sql = "SELECT * FROM {$this->table} WHERE email = :email AND is_active = 1";
        $user = $this->db->fetch($sql, ['email' => $email]);
        
        if ($user) {
            $this->db->cacheSet($cacheKey, $user, 300); // Cache for 5 minutes
        }

        return $user;
    }

    public function findById($id, $includeSensitive = false) {
        $cacheKey = "user_{$id}" . ($includeSensitive ? '_full' : '');
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $fields = $includeSensitive ? '*' : 'id, name, email, role, affiliate_id, bio, avatar, last_login, created_at';
        $sql = "SELECT {$fields} FROM {$this->table} WHERE id = :id AND is_active = 1";
        $user = $this->db->fetch($sql, ['id' => $id]);
        
        if ($user) {
            $this->db->cacheSet($cacheKey, $user, 600); // Cache for 10 minutes
        }

        return $user;
    }

    public function update($id, $data) {
        if (isset($data['password'])) {
            if (strlen($data['password']) < 8) {
                throw new Exception("Password must be at least 8 characters long");
            }
            $data['password'] = password_hash($data['password'], PASSWORD_DEFAULT);
        }
        
        $data['updated_at'] = date('Y-m-d H:i:s');
        
        $result = $this->db->update($this->table, $data, 'id = :id', ['id' => $id]);
        
        // Clear user cache
        $this->db->cacheClear("user_{$id}*");
        
        return $result;
    }

    public function verifyPassword($email, $password) {
        $user = $this->findByEmail($email);
        if ($user && password_verify($password, $user['password'])) {
            // Check if password needs rehashing
            if (password_needs_rehash($user['password'], PASSWORD_DEFAULT)) {
                $this->update($user['id'], ['password' => $password]);
            }
            return $user;
        }
        return false;
    }

    public function updateLastLogin($id) {
        $sql = "UPDATE {$this->table} SET last_login = NOW() WHERE id = :id";
        $this->db->query($sql, ['id' => $id]);
        
        // Clear cache
        $this->db->cacheClear("user_{$id}*");
    }

    private function generateAffiliateId() {
        do {
            $affiliateId = 'NV' . strtoupper(substr(md5(uniqid()), 0, 8)); // Increased to 8 chars
            $exists = $this->db->fetch("SELECT id FROM {$this->table} WHERE affiliate_id = :affiliate_id", 
                                     ['affiliate_id' => $affiliateId]);
        } while ($exists);
        
        return $affiliateId;
    }

    public function getDashboardStats($userId) {
        $cacheKey = "user_stats_{$userId}";
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $stats = [];
        
        // Favorites count
        $sql = "SELECT COUNT(*) as count FROM user_favorites WHERE user_id = :user_id";
        $stats['favorites_count'] = $this->db->fetch($sql, ['user_id' => $userId])['count'];

        // Tools submitted count
        $sql = "SELECT COUNT(*) as count FROM tools WHERE submitted_by = :user_id";
        $stats['tools_count'] = $this->db->fetch($sql, ['user_id' => $userId])['count'];

        // Courses count
        $sql = "SELECT COUNT(*) as count FROM courses WHERE submitted_by = :user_id";
        $stats['courses_count'] = $this->db->fetch($sql, ['user_id' => $userId])['count'];

        // Affiliate earnings
        $sql = "SELECT COALESCE(SUM(commission), 0) as earnings 
                FROM affiliate_conversions 
                WHERE affiliate_id = (SELECT affiliate_id FROM users WHERE id = :user_id) 
                AND status = 'approved'";
        $stats['earnings'] = $this->db->fetch($sql, ['user_id' => $userId])['earnings'];

        // Recent activity
        $sql = "
            (SELECT 'favorite' as type, t.name, uf.created_at 
             FROM user_favorites uf 
             JOIN tools t ON uf.tool_id = t.id 
             WHERE uf.user_id = :user_id 
             ORDER BY uf.created_at DESC LIMIT 5)
            UNION
            (SELECT 'review' as type, t.name, tr.created_at 
             FROM tool_reviews tr 
             JOIN tools t ON tr.tool_id = t.id 
             WHERE tr.user_id = :user_id 
             ORDER BY tr.created_at DESC LIMIT 5)
            ORDER BY created_at DESC 
            LIMIT 10
        ";
        $stats['recent_activity'] = $this->db->fetchAll($sql, ['user_id' => $userId]);

        // AI-powered recommendations
        if (AdvancedConfig::AUTOMATION_ENABLED) {
            $stats['recommendations'] = $this->aiEngine->smartRecommendations($userId, 3);
        }

        $this->db->cacheSet($cacheKey, $stats, 300); // Cache for 5 minutes

        return $stats;
    }

    public function searchUsers($filters = [], $page = 1, $limit = 20) {
        $where = ['is_active = 1'];
        $params = [];
        $offset = ($page - 1) * $limit;

        if (!empty($filters['search'])) {
            $where[] = '(name LIKE :search OR email LIKE :search)';
            $params['search'] = '%' . $filters['search'] . '%';
        }

        if (!empty($filters['role'])) {
            $where[] = 'role = :role';
            $params['role'] = $filters['role'];
        }

        $whereClause = implode(' AND ', $where);

        $sql = "SELECT id, name, email, role, affiliate_id, last_login, created_at 
                FROM {$this->table} 
                WHERE {$whereClause} 
                ORDER BY created_at DESC 
                LIMIT :limit OFFSET :offset";

        $params['limit'] = $limit;
        $params['offset'] = $offset;

        $users = $this->db->fetchAll($sql, $params);

        // Get total count
        $countSql = "SELECT COUNT(*) as total FROM {$this->table} WHERE {$whereClause}";
        $total = $this->db->fetch($countSql, $params)['total'];

        return [
            'users' => $users,
            'total' => $total,
            'page' => $page,
            'limit' => $limit,
            'total_pages' => ceil($total / $limit)
        ];
    }

    private function sendWelcomeEmail($email, $name) {
        // Enhanced email sending with template
        $subject = "Welcome to Neuravult AI Platform!";
        $message = "
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background: #f9f9f9; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='header'>
                        <h1>Welcome to Neuravult!</h1>
                    </div>
                    <div class='content'>
                        <p>Hi {$name},</p>
                        <p>Thank you for joining the Neuravult AI Platform! We're excited to have you on board.</p>
                        <p>Get started by exploring our extensive collection of AI tools, courses, and resources.</p>
                        <p>If you have any questions, don't hesitate to reach out to our support team.</p>
                    </div>
                    <div class='footer'>
                        <p>&copy; 2024 Neuravult AI Platform. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
        ";

        return $this->sendEmail($email, $subject, $message);
    }

    private function sendEmail($to, $subject, $body) {
        // Enhanced email sending implementation
        $headers = [
            'MIME-Version: 1.0',
            'Content-type: text/html; charset=utf-8',
            'From: Neuravult <noreply@neuravult.com>',
            'X-Mailer: PHP/' . phpversion()
        ];

        return mail($to, $subject, $body, implode("\r\n", $headers));
    }
}

class AdvancedTool {
    private $db;
    private $table = 'tools';
    private $aiEngine;

    public function __construct() {
        $this->db = AdvancedDatabase::getInstance();
        $this->aiEngine = new AIAutomationEngine();
    }

    public function getAll($filters = [], $page = 1, $limit = 12) {
        $cacheKey = 'tools_' . md5(serialize($filters) . "_page{$page}_limit{$limit}");
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $where = ['t.status = "approved"'];
        $params = [];
        $offset = ($page - 1) * $limit;

        // Enhanced filtering
        if (!empty($filters['category'])) {
            $where[] = 'c.slug = :category';
            $params['category'] = $filters['category'];
        }

        if (!empty($filters['pricing'])) {
            $where[] = 't.pricing = :pricing';
            $params['pricing'] = $filters['pricing'];
        }

        if (!empty($filters['search'])) {
            $where[] = '(t.name LIKE :search OR t.description LIKE :search OR t.short_description LIKE :search)';
            $params['search'] = '%' . $filters['search'] . '%';
        }

        if (!empty($filters['featured'])) {
            $where[] = 't.featured = 1';
        }

        if (!empty($filters['tags'])) {
            $tags = is_array($filters['tags']) ? $filters['tags'] : explode(',', $filters['tags']);
            $tagConditions = [];
            foreach ($tags as $index => $tag) {
                $tagConditions[] = 'EXISTS (SELECT 1 FROM tool_tags tt WHERE tt.tool_id = t.id AND tt.tag LIKE :tag' . $index . ')';
                $params['tag' . $index] = '%' . trim($tag) . '%';
            }
            if (!empty($tagConditions)) {
                $where[] = '(' . implode(' OR ', $tagConditions) . ')';
            }
        }

        if (!empty($filters['min_rating'])) {
            $where[] = 't.rating >= :min_rating';
            $params['min_rating'] = floatval($filters['min_rating']);
        }

        $whereClause = implode(' AND ', $where);

        // Base query with enhanced fields
        $sql = "SELECT t.*, c.name as category_name, c.slug as category_slug, 
                       u.name as submitted_by_name, u.avatar as submitted_by_avatar,
                       (SELECT GROUP_CONCAT(tag) FROM tool_tags WHERE tool_id = t.id) as tags,
                       (SELECT GROUP_CONCAT(feature) FROM tool_features WHERE tool_id = t.id) as features,
                       (SELECT COUNT(*) FROM user_favorites WHERE tool_id = t.id) as favorite_count,
                       (SELECT COUNT(*) FROM tool_reviews WHERE tool_id = t.id AND status = 'approved') as review_count
                FROM {$this->table} t
                LEFT JOIN categories c ON t.category_id = c.id
                LEFT JOIN users u ON t.submitted_by = u.id
                WHERE {$whereClause}";

        // Enhanced sorting
        $sort = $filters['sort'] ?? 'popular';
        switch ($sort) {
            case 'rating':
                $sql .= " ORDER BY t.rating DESC, t.review_count DESC";
                break;
            case 'newest':
                $sql .= " ORDER BY t.created_at DESC";
                break;
            case 'name':
                $sql .= " ORDER BY t.name ASC";
                break;
            case 'featured':
                $sql .= " ORDER BY t.featured DESC, t.rating DESC";
                break;
            case 'popular':
            default:
                $sql .= " ORDER BY t.views DESC, t.rating DESC";
                break;
        }

        // Add pagination
        $sql .= " LIMIT :limit OFFSET :offset";
        $params['limit'] = $limit;
        $params['offset'] = $offset;

        $tools = $this->db->fetchAll($sql, $params);

        // Get total count for pagination
        $countSql = "SELECT COUNT(DISTINCT t.id) as total 
                     FROM {$this->table} t
                     LEFT JOIN categories c ON t.category_id = c.id
                     LEFT JOIN tool_tags tt ON t.id = tt.tool_id
                     WHERE {$whereClause}";
        $total = $this->db->fetch($countSql, $params)['total'];

        $result = [
            'tools' => $tools,
            'total' => $total,
            'page' => $page,
            'limit' => $limit,
            'total_pages' => ceil($total / $limit)
        ];

        $this->db->cacheSet($cacheKey, $result, 300); // Cache for 5 minutes

        return $result;
    }

    public function getFeatured($limit = 6) {
        $cacheKey = "featured_tools_{$limit}";
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $sql = "SELECT t.*, c.name as category_name, c.slug as category_slug,
                       (SELECT GROUP_CONCAT(tag) FROM tool_tags WHERE tool_id = t.id) as tags,
                       (SELECT COUNT(*) FROM user_favorites WHERE tool_id = t.id) as favorite_count
                FROM {$this->table} t
                LEFT JOIN categories c ON t.category_id = c.id
                WHERE t.featured = 1 AND t.status = 'approved'
                ORDER BY t.rating DESC, t.views DESC, t.featured DESC
                LIMIT :limit";
        
        $tools = $this->db->fetchAll($sql, ['limit' => $limit]);
        $this->db->cacheSet($cacheKey, $tools, 600); // Cache for 10 minutes
        
        return $tools;
    }

    public function findById($id) {
        $cacheKey = "tool_{$id}";
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $sql = "SELECT t.*, c.name as category_name, c.slug as category_slug,
                       u.name as submitted_by_name, u.email as submitted_by_email, u.avatar as submitted_by_avatar,
                       (SELECT GROUP_CONCAT(tag) FROM tool_tags WHERE tool_id = t.id) as tags,
                       (SELECT GROUP_CONCAT(feature) FROM tool_features WHERE tool_id = t.id) as features,
                       (SELECT COUNT(*) FROM user_favorites WHERE tool_id = t.id) as favorite_count,
                       (SELECT COUNT(*) FROM tool_reviews WHERE tool_id = t.id AND status = 'approved') as review_count
                FROM {$this->table} t
                LEFT JOIN categories c ON t.category_id = c.id
                LEFT JOIN users u ON t.submitted_by = u.id
                WHERE t.id = :id AND t.status = 'approved'";
        
        $tool = $this->db->fetch($sql, ['id' => $id]);
        
        if ($tool) {
            // Increment view count
            $this->incrementViews($id);
            
            // Cache the tool
            $this->db->cacheSet($cacheKey, $tool, 900); // Cache for 15 minutes
        }
        
        return $tool;
    }

    public function create($data) {
        $this->db->beginTransaction();
        
        try {
            // AI-enhanced description generation
            if (empty($data['short_description']) && AdvancedConfig::AUTOMATION_ENABLED) {
                $category = $this->db->fetch("SELECT name FROM categories WHERE id = :id", 
                                           ['id' => $data['category_id']]);
                $features = $data['features'] ?? [];
                
                $aiDescription = $this->aiEngine->generateToolDescription(
                    $data['name'], 
                    $category['name'] ?? 'AI', 
                    $features
                );
                
                if ($aiDescription) {
                    $data['short_description'] = $aiDescription;
                }
            }

            // Insert tool
            $toolId = $this->db->insert($this->table, $data);
            
            // Auto-generate tags if not provided
            if (empty($data['tags']) && AdvancedConfig::AUTOMATION_ENABLED) {
                $prompt = "Generate relevant tags for AI tool: {$data['name']}. Description: {$data['description']}";
                $aiTags = $this->aiEngine->callOpenAI($prompt, 50);
                if ($aiTags) {
                    $data['tags'] = explode(',', $aiTags);
                }
            }

            // Insert tags
            if (!empty($data['tags'])) {
                $tags = is_array($data['tags']) ? $data['tags'] : explode(',', $data['tags']);
                foreach ($tags as $tag) {
                    $tag = trim($tag);
                    if (!empty($tag)) {
                        $this->db->insert('tool_tags', [
                            'tool_id' => $toolId,
                            'tag' => $tag
                        ]);
                    }
                }
            }
            
            // Insert features
            if (!empty($data['features'])) {
                $features = is_array($data['features']) ? $data['features'] : explode(',', $data['features']);
                foreach ($features as $feature) {
                    $feature = trim($feature);
                    if (!empty($feature)) {
                        $this->db->insert('tool_features', [
                            'tool_id' => $toolId,
                            'feature' => $feature
                        ]);
                    }
                }
            }
            
            // Create submission record
            $this->db->insert('user_submissions', [
                'user_id' => $data['submitted_by'],
                'type' => 'tool',
                'item_id' => $toolId
            ]);

            // Update category tool count
            $this->updateCategoryToolCount($data['category_id']);
            
            $this->db->commit();

            // Clear relevant caches
            $this->db->cacheClear('tools_*');
            $this->db->cacheClear('featured_tools_*');
            $this->db->cacheClear("category_{$data['category_id']}_*");

            return $toolId;
            
        } catch (Exception $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    public function incrementViews($id) {
        $sql = "UPDATE {$this->table} SET views = views + 1 WHERE id = :id";
        $this->db->query($sql, ['id' => $id]);
        
        // Update cache if exists
        $cachedTool = $this->db->cacheGet("tool_{$id}");
        if ($cachedTool) {
            $cachedTool['views']++;
            $this->db->cacheSet("tool_{$id}", $cachedTool, 900);
        }
    }

    public function updateRating($id) {
        $sql = "UPDATE {$this->table} t
                SET rating = (
                    SELECT AVG(rating) FROM tool_reviews 
                    WHERE tool_id = :id AND status = 'approved'
                ),
                review_count = (
                    SELECT COUNT(*) FROM tool_reviews 
                    WHERE tool_id = :id AND status = 'approved'
                )
                WHERE id = :id";
        
        $this->db->query($sql, ['id' => $id]);
        
        // Clear cache
        $this->db->cacheClear("tool_{$id}");
    }

    public function getSimilarTools($toolId, $categoryId, $limit = 4) {
        $cacheKey = "similar_tools_{$toolId}_{$limit}";
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $sql = "SELECT t.*, c.name as category_name, c.slug as category_slug,
                       (SELECT GROUP_CONCAT(tag) FROM tool_tags WHERE tool_id = t.id) as tags
                FROM {$this->table} t
                LEFT JOIN categories c ON t.category_id = c.id
                WHERE t.category_id = :category_id 
                AND t.id != :tool_id 
                AND t.status = 'approved'
                ORDER BY t.rating DESC, t.views DESC, t.featured DESC
                LIMIT :limit";
        
        $tools = $this->db->fetchAll($sql, [
            'category_id' => $categoryId,
            'tool_id' => $toolId,
            'limit' => $limit
        ]);

        $this->db->cacheSet($cacheKey, $tools, 1800); // Cache for 30 minutes
        
        return $tools;
    }

    public function getTrendingTools($limit = 8, $timeframe = '7 DAY') {
        $cacheKey = "trending_tools_{$limit}_{$timeframe}";
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $sql = "SELECT t.*, c.name as category_name, c.slug as category_slug,
                       (SELECT GROUP_CONCAT(tag) FROM tool_tags WHERE tool_id = t.id) as tags,
                       COUNT(DISTINCT uf.id) as recent_favorites,
                       COUNT(DISTINCT tr.id) as recent_reviews
                FROM tools t
                LEFT JOIN categories c ON t.category_id = c.id
                LEFT JOIN user_favorites uf ON t.id = uf.tool_id AND uf.created_at >= DATE_SUB(NOW(), INTERVAL {$timeframe})
                LEFT JOIN tool_reviews tr ON t.id = tr.tool_id AND tr.created_at >= DATE_SUB(NOW(), INTERVAL {$timeframe})
                WHERE t.status = 'approved'
                GROUP BY t.id
                ORDER BY (recent_favorites * 2 + recent_reviews * 1.5 + t.views * 0.1) DESC
                LIMIT :limit";
        
        $tools = $this->db->fetchAll($sql, ['limit' => $limit]);
        $this->db->cacheSet($cacheKey, $tools, 1800); // Cache for 30 minutes
        
        return $tools;
    }

    public function getToolAnalytics($toolId) {
        $cacheKey = "tool_analytics_{$toolId}";
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $analytics = [];

        // Daily views for the last 30 days
        $sql = "
            SELECT DATE(created_at) as date, COUNT(*) as views 
            FROM tool_views 
            WHERE tool_id = :tool_id AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date
        ";
        $analytics['daily_views'] = $this->db->fetchAll($sql, ['tool_id' => $toolId]);

        // Favorite growth
        $sql = "
            SELECT DATE(created_at) as date, COUNT(*) as favorites 
            FROM user_favorites 
            WHERE tool_id = :tool_id
            GROUP BY DATE(created_at)
            ORDER BY date
        ";
        $analytics['favorite_growth'] = $this->db->fetchAll($sql, ['tool_id' => $toolId]);

        // Review statistics
        $sql = "
            SELECT rating, COUNT(*) as count 
            FROM tool_reviews 
            WHERE tool_id = :tool_id AND status = 'approved'
            GROUP BY rating
            ORDER BY rating
        ";
        $analytics['rating_distribution'] = $this->db->fetchAll($sql, ['tool_id' => $toolId]);

        $this->db->cacheSet($cacheKey, $analytics, 3600); // Cache for 1 hour
        
        return $analytics;
    }

    private function updateCategoryToolCount($categoryId) {
        $sql = "UPDATE categories SET tool_count = (
                    SELECT COUNT(*) FROM tools 
                    WHERE category_id = :category_id AND status = 'approved'
                ) WHERE id = :category_id";
        
        $this->db->query($sql, ['category_id' => $categoryId]);
        $this->db->cacheClear("category_{$categoryId}_*");
    }
}

// ==================== ADVANCED CONTROLLERS ====================

class AdvancedAuthController {
    private $userModel;
    private $aiEngine;

    public function __construct() {
        $this->userModel = new AdvancedUser();
        $this->aiEngine = new AIAutomationEngine();
    }

    public function login() {
        AdvancedMiddleware::rateLimit('login', 5, 60); // 5 attempts per minute
        
        $input = json_decode(file_get_contents('php://input'), true);
        $input = AdvancedSecurity::sanitizeInput($input);
        
        if (empty($input['email']) || empty($input['password'])) {
            AdvancedResponse::error('Email and password are required', 400, [], 'MISSING_CREDENTIALS');
        }

        $user = $this->userModel->verifyPassword($input['email'], $input['password']);
        
        if (!$user) {
            AdvancedResponse::error('Invalid email or password', 401, [], 'INVALID_CREDENTIALS');
        }

        // Check if account is active
        if (!$user['is_active']) {
            AdvancedResponse::error('Account deactivated. Please contact support.', 403, [], 'ACCOUNT_DEACTIVATED');
        }

        // Update last login
        $this->userModel->updateLastLogin($user['id']);

        // Generate JWT token with enhanced payload
        $token = AdvancedJWTHandler::generateToken([
            'user_id' => $user['id'],
            'email' => $user['email'],
            'role' => $user['role'],
            'name' => $user['name']
        ], 24); // 24 hours

        // Generate CSRF token
        $csrfToken = AdvancedSecurity::generateCSRFToken($user['id']);

        // Remove password from response
        unset($user['password']);

        AdvancedResponse::success([
            'user' => $user,
            'token' => $token,
            'csrf_token' => $csrfToken,
            'expires_in' => 24 * 60 * 60
        ], 'Login successful');
    }

    public function register() {
        AdvancedMiddleware::rateLimit('register', 3, 300); // 3 attempts per 5 minutes
        
        $input = json_decode(file_get_contents('php://input'), true);
        $input = AdvancedSecurity::sanitizeInput($input);
        
        try {
            $userId = $this->userModel->create($input);
            
            // Get created user
            $user = $this->userModel->findById($userId);
            
            // Generate JWT token
            $token = AdvancedJWTHandler::generateToken([
                'user_id' => $user['id'],
                'email' => $user['email'],
                'role' => $user['role'],
                'name' => $user['name']
            ]);

            // Generate CSRF token
            $csrfToken = AdvancedSecurity::generateCSRFToken($user['id']);

            AdvancedResponse::success([
                'user' => $user,
                'token' => $token,
                'csrf_token' => $csrfToken,
                'expires_in' => 24 * 60 * 60
            ], 'Registration successful', 201);
            
        } catch (Exception $e) {
            AdvancedResponse::error($e->getMessage(), 400, [], 'REGISTRATION_FAILED');
        }
    }

    public function profile() {
        $user = AdvancedMiddleware::authenticate();
        $userData = $this->userModel->findById($user['user_id']);
        
        AdvancedResponse::success(['user' => $userData]);
    }

    public function updateProfile() {
        $user = AdvancedMiddleware::authenticate();
        $input = json_decode(file_get_contents('php://input'), true);
        $input = AdvancedSecurity::sanitizeInput($input);
        
        try {
            // Remove sensitive fields that shouldn't be updated via this endpoint
            unset($input['password'], $input['email'], $input['role'], $input['affiliate_id']);
            
            $this->userModel->update($user['user_id'], $input);
            $updatedUser = $this->userModel->findById($user['user_id']);
            
            AdvancedResponse::success(['user' => $updatedUser], 'Profile updated successfully');
            
        } catch (Exception $e) {
            AdvancedResponse::error($e->getMessage(), 400, [], 'PROFILE_UPDATE_FAILED');
        }
    }

    public function refreshToken() {
        $user = AdvancedMiddleware::authenticate();
        
        $newToken = AdvancedJWTHandler::generateToken([
            'user_id' => $user['user_id'],
            'email' => $user['email'],
            'role' => $user['role'],
            'name' => $user['name']
        ]);

        $newCsrfToken = AdvancedSecurity::generateCSRFToken($user['user_id']);

        AdvancedResponse::success([
            'token' => $newToken,
            'csrf_token' => $newCsrfToken,
            'expires_in' => 24 * 60 * 60
        ], 'Token refreshed');
    }

    public function logout() {
        $user = AdvancedMiddleware::authenticate();
        $token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        
        if (preg_match('/Bearer\s(\S+)/', $token, $matches)) {
            AdvancedJWTHandler::invalidateToken($matches[1]);
        }
        
        AdvancedResponse::success([], 'Logout successful');
    }

    public function changePassword() {
        $user = AdvancedMiddleware::authenticate();
        $input = json_decode(file_get_contents('php://input'), true);
        $input = AdvancedSecurity::sanitizeInput($input);
        
        if (empty($input['current_password']) || empty($input['new_password'])) {
            AdvancedResponse::error('Current password and new password are required', 400, [], 'MISSING_PASSWORDS');
        }

        // Verify current password
        $userData = $this->userModel->findById($user['user_id'], true);
        if (!password_verify($input['current_password'], $userData['password'])) {
            AdvancedResponse::error('Current password is incorrect', 400, [], 'INCORRECT_PASSWORD');
        }

        // Update to new password
        try {
            $this->userModel->update($user['user_id'], ['password' => $input['new_password']]);
            AdvancedResponse::success([], 'Password changed successfully');
        } catch (Exception $e) {
            AdvancedResponse::error($e->getMessage(), 400, [], 'PASSWORD_CHANGE_FAILED');
        }
    }
}

class AdvancedToolsController {
    private $toolModel;
    private $categoryModel;
    private $aiEngine;

    public function __construct() {
        $this->toolModel = new AdvancedTool();
        $this->categoryModel = new AdvancedCategory();
        $this->aiEngine = new AIAutomationEngine();
    }

    public function index() {
        AdvancedMiddleware::rateLimit('tools_list', 60, 60); // 60 requests per minute
        
        $filters = [
            'category' => $_GET['category'] ?? null,
            'pricing' => $_GET['pricing'] ?? null,
            'search' => $_GET['search'] ?? null,
            'featured' => $_GET['featured'] ?? null,
            'tags' => $_GET['tags'] ?? null,
            'min_rating' => $_GET['min_rating'] ?? null,
            'sort' => $_GET['sort'] ?? 'popular'
        ];

        $page = max(1, intval($_GET['page'] ?? 1));
        $limit = min(100, max(1, intval($_GET['limit'] ?? 12)));

        $result = $this->toolModel->getAll($filters, $page, $limit);
        AdvancedResponse::paginated($result['tools'], $result['total'], $page, $limit);
    }

    public function featured() {
        $limit = min(20, max(1, intval($_GET['limit'] ?? 6)));
        $tools = $this->toolModel->getFeatured($limit);
        
        AdvancedResponse::success(['tools' => $tools]);
    }

    public function trending() {
        $limit = min(20, max(1, intval($_GET['limit'] ?? 8)));
        $timeframe = $_GET['timeframe'] ?? '7 DAY';
        $tools = $this->toolModel->getTrendingTools($limit, $timeframe);
        
        AdvancedResponse::success(['tools' => $tools]);
    }

    public function show($id) {
        AdvancedMiddleware::rateLimit('tool_view', 30, 60); // 30 requests per minute
        
        $tool = $this->toolModel->findById($id);
        
        if (!$tool) {
            AdvancedResponse::notFound('Tool not found');
        }

        // Get similar tools
        $similarTools = $this->toolModel->getSimilarTools($id, $tool['category_id'], 4);
        
        // Get tool analytics (for tool owners/admins)
        $user = AdvancedMiddleware::optionalAuth();
        $analytics = null;
        if ($user && ($user['role'] === 'admin' || $tool['submitted_by'] == $user['user_id'])) {
            $analytics = $this->toolModel->getToolAnalytics($id);
        }
        
        AdvancedResponse::success([
            'tool' => $tool,
            'similar_tools' => $similarTools,
            'analytics' => $analytics
        ]);
    }

    public function create() {
        $user = AdvancedMiddleware::authenticate();
        AdvancedMiddleware::rateLimit('tool_submit', 10, 3600); // 10 submissions per hour
        
        $input = json_decode(file_get_contents('php://input'), true);
        $input = AdvancedSecurity::sanitizeInput($input);
        
        // Validate required fields
        $required = ['name', 'description', 'category_id', 'pricing', 'website'];
        foreach ($required as $field) {
            if (empty($input[$field])) {
                AdvancedResponse::error("$field is required", 400, [], 'MISSING_REQUIRED_FIELD');
            }
        }

        // Validate URL
        if (!AdvancedSecurity::validateURL($input['website'])) {
            AdvancedResponse::error('Invalid website URL', 400, [], 'INVALID_URL');
        }

        // Add submitted_by
        $input['submitted_by'] = $user['user_id'];
        
        try {
            $toolId = $this->toolModel->create($input);
            AdvancedResponse::success(['id' => $toolId], 'Tool submitted successfully', 201);
        } catch (Exception $e) {
            AdvancedResponse::error($e->getMessage(), 400, [], 'TOOL_SUBMISSION_FAILED');
        }
    }

    public function categories() {
        $categories = $this->categoryModel->getAll();
        AdvancedResponse::success(['categories' => $categories]);
    }

    public function categoryTools($slug) {
        $filters = [
            'pricing' => $_GET['pricing'] ?? null,
            'search' => $_GET['search'] ?? null,
            'min_rating' => $_GET['min_rating'] ?? null,
            'sort' => $_GET['sort'] ?? 'popular'
        ];

        $page = max(1, intval($_GET['page'] ?? 1));
        $limit = min(50, max(1, intval($_GET['limit'] ?? 12));

        $result = $this->categoryModel->getWithTools($slug, $filters, $page, $limit);
        
        if (!$result) {
            AdvancedResponse::notFound('Category not found');
        }

        AdvancedResponse::paginated($result['tools'], $result['total'], $page, $limit, [
            'category' => $result['category']
        ]);
    }

    public function generateDescription() {
        $user = AdvancedMiddleware::authenticate();
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (empty($input['name']) || empty($input['category'])) {
            AdvancedResponse::error('Tool name and category are required', 400);
        }

        $description = $this->aiEngine->generateToolDescription(
            $input['name'],
            $input['category'],
            $input['features'] ?? []
        );

        if ($description) {
            AdvancedResponse::success(['description' => $description], 'Description generated successfully');
        } else {
            AdvancedResponse::error('Failed to generate description', 500);
        }
    }

    public function analyzeTrends() {
        AdvancedMiddleware::requireAdmin();
        
        $timeframe = $_GET['timeframe'] ?? '30 days';
        $analysis = $this->aiEngine->analyzeToolTrends($timeframe);
        
        AdvancedResponse::success(['analysis' => $analysis], 'Trend analysis completed');
    }
}

// ==================== ADVANCED API ROUTER ====================

class AdvancedAPIRouter {
    private $routes = [];
    private $middleware = [];
    private $db;

    public function __construct() {
        $this->db = AdvancedDatabase::getInstance();
        $this->setupRoutes();
    }

    private function setupRoutes() {
        // Authentication routes
        $this->addRoute('POST', '/auth/login', 'AdvancedAuthController', 'login');
        $this->addRoute('POST', '/auth/register', 'AdvancedAuthController', 'register');
        $this->addRoute('GET', '/auth/profile', 'AdvancedAuthController', 'profile', ['auth']);
        $this->addRoute('PUT', '/auth/profile', 'AdvancedAuthController', 'updateProfile', ['auth']);
        $this->addRoute('POST', '/auth/refresh', 'AdvancedAuthController', 'refreshToken', ['auth']);
        $this->addRoute('POST', '/auth/logout', 'AdvancedAuthController', 'logout', ['auth']);
        $this->addRoute('POST', '/auth/change-password', 'AdvancedAuthController', 'changePassword', ['auth']);

        // Tools routes
        $this->addRoute('GET', '/tools', 'AdvancedToolsController', 'index');
        $this->addRoute('GET', '/tools/featured', 'AdvancedToolsController', 'featured');
        $this->addRoute('GET', '/tools/trending', 'AdvancedToolsController', 'trending');
        $this->addRoute('POST', '/tools', 'AdvancedToolsController', 'create', ['auth']);
        $this->addRoute('GET', '/tools/categories', 'AdvancedToolsController', 'categories');
        $this->addRoute('GET', '/tools/category/([a-z0-9-]+)', 'AdvancedToolsController', 'categoryTools');
        $this->addRoute('POST', '/tools/generate-description', 'AdvancedToolsController', 'generateDescription', ['auth']);
        $this->addRoute('GET', '/tools/analyze-trends', 'AdvancedToolsController', 'analyzeTrends', ['admin']);
        $this->addRoute('GET', '/tools/(\d+)', 'AdvancedToolsController', 'show');

        // System routes
        $this->addRoute('GET', '/health', 'AdvancedSystemController', 'health');
        $this->addRoute('GET', '/stats', 'AdvancedSystemController', 'stats', ['admin']);
        $this->addRoute('POST', '/cache/clear', 'AdvancedSystemController', 'clearCache', ['admin']);
    }

    public function addRoute($method, $pattern, $controller, $action, $middleware = []) {
        $this->routes[] = [
            'method' => $method,
            'pattern' => $pattern,
            'controller' => $controller,
            'action' => $action,
            'middleware' => $middleware
        ];
    }

    public function route() {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        $basePath = '/api/' . AdvancedConfig::API_VERSION;
        
        // Remove base path from request path
        if (strpos($path, $basePath) === 0) {
            $path = substr($path, strlen($basePath));
        }

        // Find matching route
        foreach ($this->routes as $route) {
            if ($route['method'] !== $method) {
                continue;
            }

            $pattern = '#^' . $route['pattern'] . '$#';
            if (preg_match($pattern, $path, $matches)) {
                array_shift($matches); // Remove full match

                // Apply middleware
                foreach ($route['middleware'] as $mw) {
                    switch ($mw) {
                        case 'auth':
                            AdvancedMiddleware::authenticate();
                            break;
                        case 'admin':
                            AdvancedMiddleware::requireAdmin();
                            break;
                        case 'csrf':
                            AdvancedMiddleware::validateCSRF();
                            break;
                    }
                }

                // Execute controller action
                $controller = new $route['controller']();
                call_user_func_array([$controller, $route['action']], $matches);
                return;
            }
        }

        // No route found
        AdvancedResponse::notFound('Endpoint not found');
    }
}

// ==================== SYSTEM CONTROLLER ====================

class AdvancedSystemController {
    private $db;

    public function __construct() {
        $this->db = AdvancedDatabase::getInstance();
    }

    public function health() {
        $status = [
            'status' => 'healthy',
            'timestamp' => time(),
            'version' => AdvancedConfig::API_VERSION,
            'environment' => 'production'
        ];

        // Check database connectivity
        try {
            $this->db->query('SELECT 1');
            $status['database'] = 'connected';
        } catch (Exception $e) {
            $status['database'] = 'disconnected';
            $status['status'] = 'degraded';
        }

        // Check Redis connectivity
        if (AdvancedConfig::REDIS_ENABLED) {
            try {
                $this->db->cacheSet('health_check', 'ok', 10);
                $status['redis'] = 'connected';
            } catch (Exception $e) {
                $status['redis'] = 'disconnected';
                $status['status'] = 'degraded';
            }
        }

        // System info
        $status['system'] = [
            'php_version' => PHP_VERSION,
            'memory_usage' => memory_get_usage(true),
            'memory_peak' => memory_get_peak_usage(true),
            'load_average' => function_exists('sys_getloadavg') ? sys_getloadavg() : null
        ];

        AdvancedResponse::success($status, 'System health check');
    }

    public function stats() {
        $stats = [];

        // User statistics
        $stats['users'] = $this->db->fetch("
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 DAY) THEN 1 END) as last_24h,
                COUNT(CASE WHEN role = 'admin' THEN 1 END) as admins,
                COUNT(CASE WHEN affiliate_id IS NOT NULL THEN 1 END) as affiliates
            FROM users
            WHERE is_active = 1
        ");

        // Tool statistics
        $stats['tools'] = $this->db->fetch("
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
                COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved,
                COUNT(CASE WHEN featured = 1 THEN 1 END) as featured,
                AVG(rating) as avg_rating,
                SUM(views) as total_views
            FROM tools
        ");

        // Category statistics
        $stats['categories'] = $this->db->fetchAll("
            SELECT c.name, COUNT(t.id) as tool_count, AVG(t.rating) as avg_rating
            FROM categories c
            LEFT JOIN tools t ON c.id = t.category_id AND t.status = 'approved'
            GROUP BY c.id, c.name
            ORDER BY tool_count DESC
        ");

        // Recent activity
        $stats['recent_activity'] = [
            'new_tools' => $this->db->fetch("
                SELECT COUNT(*) as count FROM tools 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ")['count'],
            'new_users' => $this->db->fetch("
                SELECT COUNT(*) as count FROM users 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ")['count'],
            'new_reviews' => $this->db->fetch("
                SELECT COUNT(*) as count FROM tool_reviews 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ")['count']
        ];

        // Performance statistics
        if (AdvancedConfig::PERFORMANCE_MONITORING) {
            $performanceStats = $this->db->getPerformanceStats();
            $stats['performance'] = [
                'total_queries' => count($performanceStats),
                'average_query_time' => array_sum(array_column($performanceStats, 'execution_time')) / count($performanceStats),
                'slow_queries' => array_filter($performanceStats, function($query) {
                    return $query['execution_time'] > 1.0;
                })
            ];
        }

        AdvancedResponse::success($stats, 'System statistics');
    }

    public function clearCache() {
        $pattern = $_POST['pattern'] ?? null;
        $cleared = $this->db->cacheClear($pattern);

        AdvancedResponse::success([
            'cleared' => $cleared,
            'pattern' => $pattern
        ], 'Cache cleared successfully');
    }
}

// ==================== ADVANCED CATEGORY MODEL ====================

class AdvancedCategory {
    private $db;
    private $table = 'categories';
    private $aiEngine;

    public function __construct() {
        $this->db = AdvancedDatabase::getInstance();
        $this->aiEngine = new AIAutomationEngine();
    }

    public function getAll() {
        $cacheKey = 'all_categories';
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $sql = "SELECT c.*, COUNT(t.id) as tool_count, 
                       AVG(t.rating) as avg_rating,
                       SUM(t.views) as total_views
                FROM {$this->table} c
                LEFT JOIN tools t ON c.id = t.category_id AND t.status = 'approved'
                WHERE c.is_active = 1
                GROUP BY c.id
                ORDER BY c.name";
        
        $categories = $this->db->fetchAll($sql);
        $this->db->cacheSet($cacheKey, $categories, 1800); // Cache for 30 minutes
        
        return $categories;
    }

    public function findBySlug($slug) {
        $cacheKey = "category_slug_{$slug}";
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $sql = "SELECT * FROM {$this->table} WHERE slug = :slug AND is_active = 1";
        $category = $this->db->fetch($sql, ['slug' => $slug]);
        
        if ($category) {
            $this->db->cacheSet($cacheKey, $category, 3600); // Cache for 1 hour
        }
        
        return $category;
    }

    public function getWithTools($slug, $filters = [], $page = 1, $limit = 12) {
        $cacheKey = "category_tools_{$slug}_" . md5(serialize($filters) . "_page{$page}_limit{$limit}";
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $category = $this->findBySlug($slug);
        if (!$category) {
            return null;
        }

        $where = ['t.category_id = :category_id', 't.status = "approved"'];
        $params = ['category_id' => $category['id']];
        $offset = ($page - 1) * $limit;

        // Apply filters
        if (!empty($filters['pricing'])) {
            $where[] = 't.pricing = :pricing';
            $params['pricing'] = $filters['pricing'];
        }

        if (!empty($filters['search'])) {
            $where[] = '(t.name LIKE :search OR t.description LIKE :search)';
            $params['search'] = '%' . $filters['search'] . '%';
        }

        if (!empty($filters['min_rating'])) {
            $where[] = 't.rating >= :min_rating';
            $params['min_rating'] = floatval($filters['min_rating']);
        }

        $whereClause = implode(' AND ', $where);

        // Get tools with enhanced sorting
        $sort = $filters['sort'] ?? 'popular';
        $orderBy = 't.featured DESC, ';
        switch ($sort) {
            case 'rating':
                $orderBy .= 't.rating DESC, t.review_count DESC';
                break;
            case 'newest':
                $orderBy .= 't.created_at DESC';
                break;
            case 'name':
                $orderBy .= 't.name ASC';
                break;
            case 'popular':
            default:
                $orderBy .= 't.views DESC, t.rating DESC';
                break;
        }

        $sql = "SELECT t.*, 
                       (SELECT GROUP_CONCAT(tag) FROM tool_tags WHERE tool_id = t.id) as tags,
                       (SELECT COUNT(*) FROM user_favorites WHERE tool_id = t.id) as favorite_count
                FROM tools t
                WHERE {$whereClause}
                ORDER BY {$orderBy}
                LIMIT :limit OFFSET :offset";
        
        $params['limit'] = $limit;
        $params['offset'] = $offset;

        $tools = $this->db->fetchAll($sql, $params);

        // Get total count
        $countSql = "SELECT COUNT(*) as total FROM tools t WHERE {$whereClause}";
        $total = $this->db->fetch($countSql, $params)['total'];

        $result = [
            'category' => $category,
            'tools' => $tools,
            'total' => $total,
            'page' => $page,
            'limit' => $limit,
            'total_pages' => ceil($total / $limit)
        ];

        $this->db->cacheSet($cacheKey, $result, 300); // Cache for 5 minutes

        return $result;
    }

    public function getCategoryStats() {
        $cacheKey = 'category_stats';
        $cached = $this->db->cacheGet($cacheKey);
        
        if ($cached !== false) {
            return $cached;
        }

        $sql = "
            SELECT 
                c.id,
                c.name,
                c.slug,
                COUNT(t.id) as tool_count,
                AVG(t.rating) as avg_rating,
                SUM(t.views) as total_views,
                COUNT(DISTINCT uf.user_id) as unique_favoriters
            FROM categories c
            LEFT JOIN tools t ON c.id = t.category_id AND t.status = 'approved'
            LEFT JOIN user_favorites uf ON t.id = uf.tool_id
            WHERE c.is_active = 1
            GROUP BY c.id, c.name, c.slug
            ORDER BY tool_count DESC
        ";

        $stats = $this->db->fetchAll($sql);
        $this->db->cacheSet($cacheKey, $stats, 3600); // Cache for 1 hour
        
        return $stats;
    }
}

// ==================== INITIALIZATION & EXECUTION ====================

// Create necessary directories
if (!is_dir(__DIR__ . '/logs')) {
    mkdir(__DIR__ . '/logs', 0755, true);
}
if (!is_dir(__DIR__ . '/uploads')) {
    mkdir(__DIR__ . '/uploads', 0755, true);
}
if (!is_dir(__DIR__ . '/cache')) {
    mkdir(__DIR__ . '/cache', 0755, true);
}

// Handle the request
try {
    $router = new AdvancedAPIRouter();
    $router->route();
} catch (Exception $e) {
    error_log("Advanced API Error: " . $e->getMessage());
    AdvancedResponse::error('Internal server error', 500, [], 'INTERNAL_ERROR');
}

// ==================== AUTOMATION SCRIPTS ====================

class AdvancedAutomationManager {
    private $db;
    private $aiEngine;

    public function __construct() {
        $this->db = AdvancedDatabase::getInstance();
        $this->aiEngine = new AIAutomationEngine();
    }

    public function runScheduledTasks() {
        $tasks = [
            'update_tool_ratings' => 'Update all tool ratings based on reviews',
            'generate_trending_list' => 'Generate trending tools list',
            'cleanup_old_data' => 'Clean up old temporary data',
            'send_digest_emails' => 'Send weekly digest emails',
            'auto_tag_tools' => 'Automatically tag tools using AI'
        ];

        $results = [];
        foreach ($tasks as $task => $description) {
            $results[$task] = $this->runTask($task);
        }

        return $results;
    }

    private function runTask($taskName) {
        switch ($taskName) {
            case 'update_tool_ratings':
                return $this->updateAllToolRatings();
                
            case 'generate_trending_list':
                return $this->generateTrendingList();
                
            case 'cleanup_old_data':
                return $this->cleanupOldData();
                
            case 'send_digest_emails':
                return $this->sendDigestEmails();
                
            case 'auto_tag_tools':
                return $this->aiEngine->autoTagTools();
                
            default:
                return "Unknown task: $taskName";
        }
    }

    private function updateAllToolRatings() {
        $sql = "SELECT id FROM tools WHERE status = 'approved'";
        $tools = $this->db->fetchAll($sql);
        
        $updated = 0;
        foreach ($tools as $tool) {
            $this->db->query("
                UPDATE tools 
                SET rating = (
                    SELECT AVG(rating) FROM tool_reviews 
                    WHERE tool_id = :tool_id AND status = 'approved'
                ),
                review_count = (
                    SELECT COUNT(*) FROM tool_reviews 
                    WHERE tool_id = :tool_id AND status = 'approved'
                )
                WHERE id = :tool_id
            ", ['tool_id' => $tool['id']]);
            
            $updated++;
        }
        
        // Clear tools cache
        $this->db->cacheClear('tools_*');
        $this->db->cacheClear('featured_tools_*');
        
        return "Updated ratings for $updated tools";
    }

    private function generateTrendingList() {
        // This would generate and cache trending tools
        $trendingTools = $this->aiEngine->analyzeToolTrends('7 days');
        $this->db->cacheSet('trending_analysis', $trendingTools, 86400); // Cache for 24 hours
        
        return "Generated trending tools analysis";
    }

    private function cleanupOldData() {
        // Clean up old password reset tokens (older than 1 hour)
        $this->db->query("
            DELETE FROM password_resets 
            WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ");
        
        // Clean up old sessions (older than 30 days)
        $this->db->query("
            DELETE FROM user_sessions 
            WHERE last_activity < DATE_SUB(NOW(), INTERVAL 30 DAY)
        ");
        
        return "Cleaned up old temporary data";
    }

    private function sendDigestEmails() {
        // Get users who want digest emails
        $users = $this->db->fetchAll("
            SELECT id, email, name 
            FROM users 
            WHERE email_verified = 1 
            AND is_active = 1
            AND digest_emails = 1
        ");
        
        $sent = 0;
        foreach ($users as $user) {
            if ($this->sendWeeklyDigest($user)) {
                $sent++;
            }
        }
        
        return "Sent weekly digest to $sent users";
    }

    private function sendWeeklyDigest($user) {
        // Get weekly highlights
        $newTools = $this->db->fetchAll("
            SELECT name, short_description 
            FROM tools 
            WHERE status = 'approved' 
            AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            ORDER BY rating DESC, views DESC 
            LIMIT 5
        ");
        
        $popularTools = $this->db->fetchAll("
            SELECT name, short_description, views 
            FROM tools 
            WHERE status = 'approved'
            ORDER BY views DESC 
            LIMIT 5
        ");
        
        // Create email content
        $subject = "Your Neuravult Weekly Digest";
        $message = $this->generateDigestEmail($user, $newTools, $popularTools);
        
        return $this->sendEmail($user['email'], $subject, $message);
    }

    private function generateDigestEmail($user, $newTools, $popularTools) {
        // Generate beautiful HTML email
        return "
            <html>
            <head>
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }
                    .content { padding: 20px; background: #f9f9f9; }
                    .section { margin-bottom: 30px; }
                    .tool { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                </style>
            </head>
            <body>
                <div class='container'>
                    <div class='header'>
                        <h1>Your Weekly AI Tools Digest</h1>
                        <p>Hello {$user['name']}, here's what's new this week!</p>
                    </div>
                    <div class='content'>
                        <div class='section'>
                            <h2>🔥 New Tools This Week</h2>
                            " . $this->generateToolList($newTools) . "
                        </div>
                        <div class='section'>
                            <h2>👑 Most Popular Tools</h2>
                            " . $this->generateToolList($popularTools) . "
                        </div>
                    </div>
                    <div class='footer'>
                        <p>&copy; 2024 Neuravult AI Platform. All rights reserved.</p>
                        <p><a href='https://neuravult.com/unsubscribe'>Unsubscribe</a> from these emails</p>
                    </div>
                </div>
            </body>
            </html>
        ";
    }

    private function generateToolList($tools) {
        $html = '';
        foreach ($tools as $tool) {
            $html .= "
                <div class='tool'>
                    <h3>{$tool['name']}</h3>
                    <p>{$tool['short_description']}</p>
                </div>
            ";
        }
        return $html;
    }

    private function sendEmail($to, $subject, $body) {
        $headers = [
            'MIME-Version: 1.0',
            'Content-type: text/html; charset=utf-8',
            'From: Neuravult Digest <digest@neuravult.com>',
            'X-Mailer: PHP/' . phpversion()
        ];

        return mail($to, $subject, $body, implode("\r\n", $headers));
    }
}

// ==================== CRON JOB EXECUTION ====================

if (php_sapi_name() === 'cli' && isset($argv[1]) && $argv[1] === 'run-automation') {
    $automation = new AdvancedAutomationManager();
    $results = $automation->runScheduledTasks();
    
    echo "Automation Tasks Completed:\n";
    foreach ($results as $task => $result) {
        echo "• $task: $result\n";
    }
}

?>
 
