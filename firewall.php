<?php

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

define('RISK_THRESHOLD', 15);
define('SUSPICION_THRESHOLD', 20);
define('TIME_WINDOW', 60);
define('BLOCK_DURATION', 300);

if (isset($_SESSION['is_blocked']) && $_SESSION['is_blocked'] === true) {
    if (time() - $_SESSION['block_time'] < BLOCK_DURATION) {
        header('Location: request_blocked.html');
        exit();
    } else {
        unset($_SESSION['is_blocked']);
        unset($_SESSION['block_time']);
        unset($_SESSION['suspicion_counter']);
    }
}


$attack_patterns = [

    ['pattern' => '/(sqlite_master|information_schema)/i', 'score' => 20, 'type' => 'Metadata Access'],
    ['pattern' => '/(union|select|insert|delete|update|order by|--|#)/i', 'score' => 8, 'type' => 'SQLi Keyword'],
    ['pattern' => '/\s(and|or)\s+[0-9a-z\s]+\s*(=|<|>|like|is|not)/i', 'score' => 6, 'type' => 'SQLi Logic'],
    ['pattern' => '/(load_file|outfile|benchmark|char|concat|sleep|user|database|version|sqlite_version)/i', 'score' => 9, 'type' => 'SQLi Function'],


    ['pattern' => '/<\s*[a-zA-Z0-9]+/', 'score' => 4, 'type' => 'XSS Generic Tag'],
    

    ['pattern' => '/\s+on[a-zA-Z]+\s*=/i', 'score' => 9, 'type' => 'XSS Generic Event'],


    ['pattern' => '/(javascript:|data:|vbscript:)/i', 'score' => 10, 'type' => 'XSS Protocol'],


    ['pattern' => '/(alert|prompt|confirm|document\.cookie|eval|setTimeout|setInterval)/i', 'score' => 7, 'type' => 'XSS Keyword'],
];



function normalize_input($input) {
    $normalized = $input;
    $normalized = urldecode($normalized);
    $normalized = urldecode($normalized);
    $normalized = preg_replace('/\/\*.*?\*\//s', '', $normalized);
    $normalized = preg_replace('/(--|#).*/', '', $normalized);
    $normalized = preg_replace('/\s+/', ' ', $normalized);
    $normalized = strtolower($normalized);
    return $normalized;
}

$total_risk_score = 0;
$detected_patterns = [];

foreach ($_REQUEST as $key => $value) {
    if (is_string($value)) {
        $normalized_value = normalize_input($value);
        foreach ($attack_patterns as $rule) {
            if (preg_match($rule['pattern'], $normalized_value)) {
                $total_risk_score += $rule['score'];
                $detected_patterns[] = "[Type: {$rule['type']}, Score: {$rule['score']}]";
            }
        }
    }
}

if ($total_risk_score >= RISK_THRESHOLD) {
    $ip = $_SERVER['REMOTE_ADDR'];
    $log_message = "IMMEDIATE BLOCK: High-risk request from IP: $ip | Score: $total_risk_score | Patterns: " . implode(', ', $detected_patterns) . "\n";
    error_log($log_message);
    header('Location: request_blocked.html');
    exit();
}

if ($total_risk_score > 0) {
    if (!isset($_SESSION['suspicion_counter'])) {
        $_SESSION['suspicion_counter'] = 0;
        $_SESSION['first_suspicion_time'] = time();
    }
    $_SESSION['suspicion_counter']++;
    if (time() - $_SESSION['first_suspicion_time'] > TIME_WINDOW) {
        $_SESSION['suspicion_counter'] = 1;
        $_SESSION['first_suspicion_time'] = time();
    }
    if ($_SESSION['suspicion_counter'] >= SUSPICION_THRESHOLD) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $log_message = "BEHAVIORAL BLOCK: Suspicious activity from IP: $ip | Suspicion Count: {$_SESSION['suspicion_counter']} in " . (time() - $_SESSION['first_suspicion_time']) . "s\n";
        error_log($log_message);
        $_SESSION['is_blocked'] = true;
        $_SESSION['block_time'] = time();
        header('Location: request_blocked.html');
        exit();
    }
}
?>

