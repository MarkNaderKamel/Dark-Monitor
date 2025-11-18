<?php
/**
 * PHP Built-in Server Router
 * 
 * This file routes requests to the appropriate PHP files
 * when using PHP's built-in web server
 */

$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$file = __DIR__ . $uri;

// Serve static files
if ($uri !== '/' && file_exists($file) && !is_dir($file)) {
    return false;
}

// Route to dashboard by default
if ($uri === '/' || $uri === '/index.php') {
    require __DIR__ . '/dashboard.html';
    return true;
}

// Route specific PHP files
if (preg_match('/\.php$/', $uri)) {
    $phpFile = __DIR__ . $uri;
    if (file_exists($phpFile)) {
        require $phpFile;
        return true;
    }
}

// Fallback to dashboard
require __DIR__ . '/dashboard.html';
