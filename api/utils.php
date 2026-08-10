<?php
define('USERS_FILE', __DIR__ . '/../users.json');
define('TOKENS_FILE', __DIR__ . '/../sessions.json');
define('SMTP_CONFIG_FILE', __DIR__ . '/../smtp-config.json');
define('UPLOADS_DIR', __DIR__ . '/../uploads');
define('SHARED_DIR', __DIR__ . '/../shared');
define('ADMIN_EMAIL', 'admin@fileshare.com');
define('ADMIN_PASSWORD', 'admin123');

$DEFAULT_SMTP = ['host' => 'smtp.gmail.com', 'port' => '587', 'user' => '', 'pass' => '', 'fromName' => 'Abdullah File Share', 'fromEmail' => ''];

function sendEmail($userId, $to, $subject, $htmlBody, $textBody, $attachments = []) {
    $smtpCfg = getUserSmtpConfig($userId);
    return sendDirectSmtpEmail($smtpCfg, $to, $subject, $htmlBody, $textBody, $attachments);
}

function sendDirectSmtpEmail($cfg, $to, $subject, $htmlBody, $textBody, $attachments = []) {
    $host = $cfg['host'] ?? 'smtp.gmail.com';
    $port = intval($cfg['port'] ?? 587);
    $user = $cfg['user'] ?? '';
    $pass = $cfg['pass'] ?? '';
    $fromName = !empty($cfg['fromName']) ? $cfg['fromName'] : 'Abdullah File Share';
    $fromEmail = !empty($cfg['fromEmail']) ? $cfg['fromEmail'] : $user;

    if (empty($host) || empty($user) || empty($pass)) {
        throw new Exception('Incomplete SMTP configuration (Host, User, and Password are required).');
    }

    $isSSL = ($port === 465 || !empty($cfg['secure']));
    $remote = ($isSSL ? 'ssl://' : 'tcp://') . $host . ':' . $port;
    
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true
        ]
    ]);

    $socket = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $context);
    if (!$socket) {
        throw new Exception("SMTP Connection Failed to $host:$port ($errno): $errstr");
    }

    stream_set_timeout($socket, 15);

    $read = function() use ($socket) {
        $res = '';
        while ($line = fgets($socket, 512)) {
            $res .= $line;
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        return $res;
    };

    $cmd = function($c, $expectedCode = 250) use ($socket, $read) {
        fputs($socket, $c . "\r\n");
        $res = $read();
        $code = intval(substr($res, 0, 3));
        if ($code !== $expectedCode) {
            throw new Exception("SMTP Error ($c): " . trim($res));
        }
        return $res;
    };

    $greeting = $read();
    if (intval(substr($greeting, 0, 3)) !== 220) {
        fclose($socket);
        throw new Exception("SMTP Greeting Error: " . trim($greeting));
    }

    $cmd("EHLO " . gethostname(), 250);

    if (!$isSSL && ($port === 587 || $port === 25 || strpos($greeting, 'STARTTLS') !== false)) {
        fputs($socket, "STARTTLS\r\n");
        $starttlsRes = $read();
        if (intval(substr($starttlsRes, 0, 3)) === 220) {
            $cryptoRes = @stream_socket_enable_crypto(
                $socket, 
                true, 
                STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT | STREAM_CRYPTO_METHOD_TLS_CLIENT
            );
            if (!$cryptoRes) {
                fclose($socket);
                throw new Exception("SMTP TLS Handshake Failed");
            }
            $cmd("EHLO " . gethostname(), 250);
        }
    }

    $cmd("AUTH LOGIN", 334);
    $cmd(base64_encode($user), 334);
    $cmd(base64_encode($pass), 235);

    $cmd("MAIL FROM: <$fromEmail>", 250);
    $cmd("RCPT TO: <$to>", 250);
    $cmd("DATA", 354);

    $mixedBoundary = "----=_MixedPart_" . md5(uniqid(time()));
    $altBoundary   = "----=_AltPart_" . md5(uniqid(time()));

    $headers  = "From: =?UTF-8?B?" . base64_encode($fromName) . "?= <$fromEmail>\r\n";
    $headers .= "To: <$to>\r\n";
    $headers .= "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\n";
    $headers .= "Date: " . date('r') . "\r\n";
    $headers .= "MIME-Version: 1.0\r\n";

    if (!empty($attachments)) {
        $headers .= "Content-Type: multipart/mixed; boundary=\"$mixedBoundary\"\r\n";

        $body  = "--$mixedBoundary\r\n";
        $body .= "Content-Type: multipart/alternative; boundary=\"$altBoundary\"\r\n\r\n";
        $body .= "--$altBoundary\r\n";
        $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
        $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
        $body .= chunk_split(base64_encode($textBody)) . "\r\n";
        $body .= "--$altBoundary\r\n";
        $body .= "Content-Type: text/html; charset=UTF-8\r\n";
        $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
        $body .= chunk_split(base64_encode($htmlBody)) . "\r\n";
        $body .= "--$altBoundary--\r\n";

        foreach ($attachments as $att) {
            $filename = $att['filename'] ?? 'attachment';
            $mime = $att['contentType'] ?? 'application/octet-stream';
            $data = $att['content'] ?? '';
            $filenameEnc = "=?UTF-8?B?" . base64_encode($filename) . "?=";

            $body .= "\r\n--$mixedBoundary\r\n";
            $body .= "Content-Type: $mime; name=\"$filenameEnc\"\r\n";
            $body .= "Content-Disposition: attachment; filename=\"$filenameEnc\"\r\n";
            $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
            $body .= chunk_split(base64_encode($data)) . "\r\n";
        }
        $body .= "--$mixedBoundary--\r\n";
    } else {
        $headers .= "Content-Type: multipart/alternative; boundary=\"$altBoundary\"\r\n";

        $body  = "--$altBoundary\r\n";
        $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
        $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
        $body .= chunk_split(base64_encode($textBody)) . "\r\n";
        $body .= "--$altBoundary\r\n";
        $body .= "Content-Type: text/html; charset=UTF-8\r\n";
        $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
        $body .= chunk_split(base64_encode($htmlBody)) . "\r\n";
        $body .= "--$altBoundary--\r\n";
    }

    $cmd($headers . "\r\n" . $body . "\r\n.", 250);
    $cmd("QUIT", 221);

    fclose($socket);
    return true;
}

if (!file_exists(UPLOADS_DIR)) mkdir(UPLOADS_DIR, 0777, true);
if (!file_exists(SHARED_DIR)) mkdir(SHARED_DIR, 0777, true);

function loadJson($file) {
    if (!file_exists($file)) return [];
    $fp = fopen($file, 'r');
    if (!$fp) return [];
    flock($fp, LOCK_SH);
    $contents = stream_get_contents($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return json_decode($contents, true) ?: [];
}

function saveJson($file, $data) {
    $fp = fopen($file, 'c');
    if (!$fp) return false;
    flock($fp, LOCK_EX);
    ftruncate($fp, 0);
    fwrite($fp, json_encode($data, JSON_PRETTY_PRINT));
    flock($fp, LOCK_UN);
    fclose($fp);
    return true;
}

function hashPassword($password, $salt = null) {
    if (!$salt) $salt = bin2hex(random_bytes(16));
    $hash = hash_pbkdf2('sha512', $password, $salt, 10000, 128, false);
    return ['salt' => $salt, 'hash' => $hash];
}

function verifyPassword($password, $salt, $hash) {
    $result = hash_pbkdf2('sha512', $password, $salt, 10000, 128, false);
    return hash_equals($hash, $result);
}

function uuidv4() {
    $data = random_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function createToken($userId) {
    $tokens = loadJson(TOKENS_FILE);
    $token = uuidv4();
    $tokens[$token] = ['userId' => $userId, 'createdAt' => date('c')];
    saveJson(TOKENS_FILE, $tokens);
    return $token;
}

function getUserFromToken($token) {
    if (!$token) return null;
    $tokens = loadJson(TOKENS_FILE);
    if (!isset($tokens[$token])) return null;
    $session = $tokens[$token];
    $users = loadJson(USERS_FILE);
    if (!isset($users[$session['userId']])) return null;
    $user = $users[$session['userId']];
    return [
        'id' => $session['userId'],
        'username' => $user['username'],
        'email' => $user['email'],
        'role' => $user['role'] ?? 'user',
        'totpEnabled' => $user['totpEnabled'] ?? false
    ];
}

function getAuthToken() {
    $headers = function_exists('apache_request_headers') ? apache_request_headers() : [];
    if (isset($headers['Authorization'])) {
        return str_replace('Bearer ', '', $headers['Authorization']);
    } elseif (isset($_SERVER['HTTP_AUTHORIZATION'])) {
        return str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION']);
    }
    if (isset($_COOKIE['token'])) {
        return $_COOKIE['token'];
    }
    if (isset($_GET['token'])) {
        return $_GET['token'];
    }
    return null;
}

function requireAuth() {
    $token = getAuthToken();
    $user = getUserFromToken($token);
    if (!$user) {
        http_response_code(401);
        echo json_encode(['success' => false, 'error' => 'Authentication required']);
        exit;
    }
    return $user;
}

function requireAdmin($user) {
    if ($user['role'] !== 'admin') {
        http_response_code(403);
        echo json_encode(['success' => false, 'error' => 'Admin access required']);
        exit;
    }
}

function loadMetadata($userId) {
    $userId = preg_replace('/[^a-zA-Z0-9-]/', '', $userId);
    $dir = SHARED_DIR . '/' . $userId;
    if (!file_exists($dir)) mkdir($dir, 0777, true);
    return loadJson($dir . '/files.json');
}

function saveMetadata($userId, $data) {
    $userId = preg_replace('/[^a-zA-Z0-9-]/', '', $userId);
    $dir = SHARED_DIR . '/' . $userId;
    if (!file_exists($dir)) mkdir($dir, 0777, true);
    saveJson($dir . '/files.json', $data);
}

function loadAllMetadata() {
    $allFiles = [];
    $users = loadJson(USERS_FILE);
    foreach ($users as $userId => $user) {
        $metadata = loadMetadata($userId);
        foreach ($metadata as $f) {
            $f['uploadedBy'] = $user['username'] ?? 'Unknown';
            $f['uploadedByEmail'] = $user['email'] ?? '';
            $allFiles[] = $f;
        }
    }
    usort($allFiles, function($a, $b) {
        return strtotime($b['uploadDate']) - strtotime($a['uploadDate']);
    });
    return $allFiles;
}

function loadDocuments($userId) {
    $userId = preg_replace('/[^a-zA-Z0-9-]/', '', $userId);
    $dir = SHARED_DIR . '/' . $userId;
    if (!file_exists($dir)) mkdir($dir, 0777, true);
    return loadJson($dir . '/documents.json');
}

function saveDocuments($userId, $data) {
    $userId = preg_replace('/[^a-zA-Z0-9-]/', '', $userId);
    $dir = SHARED_DIR . '/' . $userId;
    if (!file_exists($dir)) mkdir($dir, 0777, true);
    saveJson($dir . '/documents.json', $data);
}

function loadAllDocuments() {
    $allDocs = [];
    $users = loadJson(USERS_FILE);
    foreach ($users as $userId => $user) {
        $docs = loadDocuments($userId);
        foreach ($docs as $d) {
            $d['author'] = $user['username'] ?? 'Unknown';
            $allDocs[] = $d;
        }
    }
    usort($allDocs, function($a, $b) {
        return strtotime($b['updatedAt']) - strtotime($a['updatedAt']);
    });
    return $allDocs;
}

function sendDirectSmtpEmail($cfg, $to, $subject, $htmlBody, $textBody) {
    $host = $cfg['host'] ?? 'smtp.gmail.com';
    $port = intval($cfg['port'] ?? 587);
    $user = $cfg['user'] ?? '';
    $pass = $cfg['pass'] ?? '';
    $fromName = !empty($cfg['fromName']) ? $cfg['fromName'] : 'Abdullah File Share';
    $fromEmail = !empty($cfg['fromEmail']) ? $cfg['fromEmail'] : $user;

    if (empty($host) || empty($user) || empty($pass)) {
        throw new Exception('Incomplete SMTP configuration (Host, User, and Password are required).');
    }

    $isSSL = ($port === 465 || !empty($cfg['secure']));
    $remote = ($isSSL ? 'ssl://' : 'tcp://') . $host . ':' . $port;
    
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
            'allow_self_signed' => true
        ]
    ]);

    $socket = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $context);
    if (!$socket) {
        throw new Exception("SMTP Connection Failed to $host:$port ($errno): $errstr");
    }

    stream_set_timeout($socket, 15);

    $read = function() use ($socket) {
        $res = '';
        while ($line = fgets($socket, 512)) {
            $res .= $line;
            if (isset($line[3]) && $line[3] === ' ') break;
        }
        return $res;
    };

    $cmd = function($c, $expectedCode = 250) use ($socket, $read) {
        fputs($socket, $c . "\r\n");
        $res = $read();
        $code = intval(substr($res, 0, 3));
        if ($code !== $expectedCode) {
            throw new Exception("SMTP Error ($c): " . trim($res));
        }
        return $res;
    };

    $greeting = $read();
    if (intval(substr($greeting, 0, 3)) !== 220) {
        fclose($socket);
        throw new Exception("SMTP Greeting Error: " . trim($greeting));
    }

    $cmd("EHLO " . gethostname(), 250);

    if (!$isSSL && ($port === 587 || $port === 25 || strpos($greeting, 'STARTTLS') !== false)) {
        fputs($socket, "STARTTLS\r\n");
        $starttlsRes = $read();
        if (intval(substr($starttlsRes, 0, 3)) === 220) {
            $cryptoRes = @stream_socket_enable_crypto(
                $socket, 
                true, 
                STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT | STREAM_CRYPTO_METHOD_TLS_CLIENT
            );
            if (!$cryptoRes) {
                fclose($socket);
                throw new Exception("SMTP TLS Handshake Failed");
            }
            $cmd("EHLO " . gethostname(), 250);
        }
    }

    $cmd("AUTH LOGIN", 334);
    $cmd(base64_encode($user), 334);
    $cmd(base64_encode($pass), 235);

    $cmd("MAIL FROM: <$fromEmail>", 250);
    $cmd("RCPT TO: <$to>", 250);
    $cmd("DATA", 354);

    $boundary = "----=_NextPart_" . md5(uniqid(time()));
    $headers  = "From: =?UTF-8?B?" . base64_encode($fromName) . "?= <$fromEmail>\r\n";
    $headers .= "To: <$to>\r\n";
    $headers .= "Subject: =?UTF-8?B?" . base64_encode($subject) . "?=\r\n";
    $headers .= "Date: " . date('r') . "\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: multipart/alternative; boundary=\"$boundary\"\r\n";

    $body  = "--$boundary\r\n";
    $body .= "Content-Type: text/plain; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
    $body .= chunk_split(base64_encode($textBody)) . "\r\n";

    $body .= "--$boundary\r\n";
    $body .= "Content-Type: text/html; charset=UTF-8\r\n";
    $body .= "Content-Transfer-Encoding: base64\r\n\r\n";
    $body .= chunk_split(base64_encode($htmlBody)) . "\r\n";

    $body .= "--$boundary--\r\n";

    $cmd($headers . "\r\n" . $body . "\r\n.", 250);
    $cmd("QUIT", 221);

    fclose($socket);
    return true;
}

function getUserSmtpConfig($userId = null) {
    global $DEFAULT_SMTP;
    $users = loadJson(USERS_FILE);
    $globalSmtp = loadJson(SMTP_CONFIG_FILE);
    
    if ($userId && isset($users[$userId]['smtpConfig'])) {
        $userCfg = array_filter($users[$userId]['smtpConfig']);
        if (!empty($userCfg)) {
            return array_merge($DEFAULT_SMTP, $globalSmtp, $userCfg);
        }
    }
    
    foreach ($users as $u) {
        if (($u['role'] ?? '') === 'admin' && !empty($u['smtpConfig'])) {
            $adminCfg = array_filter($u['smtpConfig']);
            if (!empty($adminCfg)) {
                $merged = array_merge($DEFAULT_SMTP, $globalSmtp, $adminCfg);
                if ($userId && isset($users[$userId]['username'])) {
                    $merged['fromName'] = $users[$userId]['username'] . ' via Abdullah File Share';
                }
                return $merged;
            }
        }
    }
    
    return array_merge($DEFAULT_SMTP, $globalSmtp);
}

function saveUserSmtpConfig($userId, $data) {
    global $DEFAULT_SMTP;
    $users = loadJson(USERS_FILE);
    if (!isset($users[$userId])) return;
    $users[$userId]['smtpConfig'] = array_merge($DEFAULT_SMTP, $data);
    saveJson(USERS_FILE, $users);
}

// Ensure admin exists
$users = loadJson(USERS_FILE);
$adminExists = false;
foreach ($users as $u) {
    if (isset($u['role']) && $u['role'] === 'admin') {
        $adminExists = true;
        break;
    }
}
if (!$adminExists) {
    $userId = uuidv4();
    $pw = hashPassword(ADMIN_PASSWORD);
    $users[$userId] = [
        'username' => 'admin',
        'email' => ADMIN_EMAIL,
        'salt' => $pw['salt'],
        'hash' => $pw['hash'],
        'role' => 'admin',
        'createdAt' => date('c')
    ];
    saveJson(USERS_FILE, $users);
}
