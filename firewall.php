<?php

if (!defined('PREVENT_DIRECT_ACCESS')) {
    http_response_code(403);
    exit('Direct access not allowed.');
}

class Firewall {
    private $log_dir;
    private $block_file;
    private $suspicion_file;
    
    private $whitelist = []; 
    
    const RISK_THRESHOLD = 15;       // امتیاز برای بلاک آنی
    const SUSPICION_THRESHOLD = 20;  // امتیاز برای بلاک رفتاری
    const TIME_WINDOW = 60;          // پنجره زمانی (ثانیه)
    const BLOCK_DURATION = 300;      // مدت مسدودی (۵ دقیقه)
    
    public function __construct() {
        $this->log_dir = __DIR__ . '/waf_storage';
        $this->block_file = $this->log_dir . '/blocked_ips.json';
        $this->suspicion_file = $this->log_dir . '/suspicion_log.json';
        
        if (!file_exists($this->log_dir)) {
            mkdir($this->log_dir, 0700, true);
        }

        $htaccess_path = $this->log_dir . '/.htaccess';
        if (!file_exists($htaccess_path)) {
            file_put_contents($htaccess_path, "Order Allow,Deny\nDeny from all\n<FilesMatch \"\.(json|log)$\">\nOrder Deny,Allow\nDeny from all\n</FilesMatch>");
        }
        
        $index_path = $this->log_dir . '/index.php';
        if (!file_exists($index_path)) {
            file_put_contents($index_path, "<?php http_response_code(403); exit('Access Denied'); ?>");
        }
    }

    public function run() {
        $ip = $_SERVER['REMOTE_ADDR'];

        if (in_array($ip, $this->whitelist)) {
            return;
        }

        if ($this->isBlocked($ip)) {
            $this->renderBlockPage();
            exit();
        }

        $all_inputs = $this->gatherAndFlattenInputs();
        
        $risk_score = 0;
        $detected_patterns = [];

        foreach ($all_inputs as $key => $value) {
            $result = $this->analyzeInput($value);
            if ($result['score'] > 0) {
                $risk_score += $result['score'];
                foreach($result['patterns'] as $p) {
                    $detected_patterns[] = "Input [$key]: $p";
                }
            }
        }

        if ($risk_score >= self::RISK_THRESHOLD) {
            $this->blockIP($ip, "Immediate Block (Score: $risk_score)");
            $this->logAttack($ip, $risk_score, $detected_patterns);
            $this->renderBlockPage();
            exit();
        }

        if ($risk_score > 0) {
            $this->trackSuspicion($ip, $risk_score);
        }
    }

    private function gatherAndFlattenInputs() {
        $data = $_REQUEST; 
        
        $input_raw = file_get_contents('php://input');
        if (!empty($input_raw)) {
            $json = json_decode($input_raw, true);
            if (is_array($json)) {
                $data = array_merge($data, $json);
            }
        }

        if (isset($_SERVER['HTTP_USER_AGENT'])) {
            $data['User-Agent'] = $_SERVER['HTTP_USER_AGENT'];
        }
        return $this->flattenArray($data);
    }

    private function flattenArray(array $array, $prefix = '') {
        $result = [];
        foreach ($array as $key => $value) {
            $new_key = $prefix . ($prefix ? '.' : '') . $key;
            if (is_array($value)) {
                $result = array_merge($result, $this->flattenArray($value, $new_key));
            } else {
                $result[$new_key] = (string)$value;
            }
        }
        return $result;
    }

    private function analyzeInput($input) {
        $normalized = urldecode($input); 
        $normalized = strtolower($normalized);
        
        $score = 0;
        $patterns_found = [];

        $rules = [
            ['pattern' => '/<\s*(details|summary|svg|math|object|iframe|embed|audio|video|keygen|marquee)/i', 'score' => 20, 'type' => 'Critical HTML Tag'],
            
            ['pattern' => '/(alert|prompt|confirm|print)\s*[`]/', 'score' => 20, 'type' => 'JS Backtick Exec'],

            ['pattern' => '/[\'"]\s*;\s*/', 'score' => 10, 'type' => 'Context Break'],

            ['pattern' => '/<script.*?>.*?<\/script>/is', 'score' => 25, 'type' => 'Script Tag'],
            ['pattern' => '/\bon[a-z]+\s*=/i', 'score' => 15, 'type' => 'Event Handler'], // ontoggle, onerror, etc.
            ['pattern' => '/(javascript:|vbscript:|data:text)/i', 'score' => 20, 'type' => 'Protocol Handler'],
            ['pattern' => '/(alert|prompt|confirm|eval)\s*(\(|%28)/i', 'score' => 15, 'type' => 'JS Function'],
            ['pattern' => '/\b(union\s+select|information_schema)\b/i', 'score' => 20, 'type' => 'Critical SQLi'],
            ['pattern' => '/[\'"]\s*(or|and)\s+[\'"]?.*?(=|<|>)/i', 'score' => 20, 'type' => 'SQLi Tautology'], // ' OR '1'='1
            ['pattern' => '/(--|#|\/\*)/', 'score' => 5, 'type' => 'SQLi Comment'],

            ['pattern' => '/(\.\.\/|\.\.\\\)/', 'score' => 15, 'type' => 'Path Traversal'],
            ['pattern' => '/(^|[;&|])\s*(cat|nc|wget|curl|bash|sh)\s+/i', 'score' => 25, 'type' => 'Command Injection'],
        ];

        foreach ($rules as $rule) {
            if (preg_match($rule['pattern'], $normalized)) {
                $score += $rule['score'];
                $patterns_found[] = $rule['type'];
            }
        }

        return ['score' => $score, 'patterns' => $patterns_found];
    }


    private function isBlocked($ip) {
        $data = $this->loadJson($this->block_file);
        if (isset($data[$ip])) {
            if (time() < $data[$ip]['expires']) {
                return true;
            } else {
                unset($data[$ip]);
                $this->saveJson($this->block_file, $data);
            }
        }
        return false;
    }

    private function blockIP($ip, $reason) {
        $data = $this->loadJson($this->block_file);
        $data[$ip] = [
            'expires' => time() + self::BLOCK_DURATION,
            'reason' => $reason,
            'time' => date('Y-m-d H:i:s')
        ];
        $this->saveJson($this->block_file, $data);
    }

    private function trackSuspicion($ip, $score) {
        $data = $this->loadJson($this->suspicion_file);
        
        if (!isset($data[$ip])) {
            $data[$ip] = ['score' => 0, 'start_time' => time()];
        }

        if (time() - $data[$ip]['start_time'] > self::TIME_WINDOW) {
            $data[$ip] = ['score' => 0, 'start_time' => time()];
        }

        $data[$ip]['score'] += $score;

        if ($data[$ip]['score'] >= self::SUSPICION_THRESHOLD) {
            $this->blockIP($ip, "Behavioral Block (Accumulated Score: {$data[$ip]['score']})");
            unset($data[$ip]); 
        } else {
            $this->saveJson($this->suspicion_file, $data);
        }
    }

    private function loadJson($file) {
        if (!file_exists($file)) return [];
        $content = file_get_contents($file);
        $data = json_decode($content, true);
        return is_array($data) ? $data : [];
    }

    private function saveJson($file, $data) {
        file_put_contents($file, json_encode($data, JSON_PRETTY_PRINT));
    }

    private function logAttack($ip, $score, $patterns) {
        $msg = date('Y-m-d H:i:s') . " | IP: $ip | Score: $score | Patterns: " . implode(', ', $patterns) . PHP_EOL;
        error_log($msg, 3, $this->log_dir . '/attacks.log');
    }

    private function renderBlockPage() {
        http_response_code(403);
        echo '<!DOCTYPE html><html><body style="text-align:center;padding:50px;font-family:sans-serif;">';
        echo '<h1 style="color:red;">Access Denied</h1>';
        echo '<p>Your activity has been flagged as suspicious.</p>';
        echo '<small>IP: ' . htmlspecialchars($_SERVER['REMOTE_ADDR']) . '</small>';
        echo '</body></html>';
    }
}
$firewall = new Firewall();
$firewall->run();
?>
