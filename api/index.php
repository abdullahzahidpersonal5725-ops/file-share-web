<?php
require_once __DIR__ . '/utils.php';
require_once __DIR__ . '/totp.php';

header('Content-Type: application/json');

$route = isset($_GET['route']) ? rtrim($_GET['route'], '/') : '';
$method = $_SERVER['REQUEST_METHOD'];

$input = json_decode(file_get_contents('php://input'), true) ?: [];
if (empty($input) && !empty($_POST)) $input = $_POST;

function sendError($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(['success' => false, 'error' => $msg]);
    exit;
}

function sendSuccess($data = []) {
    echo json_encode(array_merge(['success' => true], $data));
    exit;
}

function formatSheetToHtmlPhp($sheetsData) {
    if (empty($sheetsData)) return '<p><i>(Empty spreadsheet)</i></p>';
    $maxRow = 1; $maxCol = 0;
    foreach ($sheetsData as $k => $v) {
        if (preg_match('/([A-Z]+)(\d+)/', $k, $m)) {
            $maxRow = max($maxRow, intval($m[2]));
            $colIdx = 0;
            for ($i = 0; $i < strlen($m[1]); $i++) {
                $colIdx = $colIdx * 26 + (ord($m[1][$i]) - 64);
            }
            $maxCol = max($maxCol, $colIdx);
        }
    }
    $getColName = function($idx) {
        $name = '';
        while ($idx > 0) {
            $rem = ($idx - 1) % 26;
            $name = chr(65 + $rem) . $name;
            $idx = intval(($idx - 1) / 26);
        }
        return $name;
    };
    $html = '<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;background:#1a1a28;color:#e2e2f0;border-color:#2a2a3a;font-family:sans-serif;"><thead><tr style="background:#12121a;color:#a29bfe;"><th>#</th>';
    for ($c = 1; $c <= $maxCol; $c++) {
        $html .= '<th>' . $getColName($c) . '</th>';
    }
    $html .= '</tr></thead><tbody>';
    for ($r = 1; $r <= $maxRow; $r++) {
        $html .= '<tr><td style="background:#12121a;font-weight:bold;text-align:center;">' . $r . '</td>';
        for ($c = 1; $c <= $maxCol; $c++) {
            $cellId = $getColName($c) . $r;
            $cell = $sheetsData[$cellId] ?? [];
            $val = $cell['value'] ?? $cell['formula'] ?? '';
            $style = '';
            if (!empty($cell['bold'])) $style .= 'font-weight:bold;';
            if (!empty($cell['italic'])) $style .= 'font-style:italic;';
            if (!empty($cell['color'])) $style .= 'color:' . $cell['color'] . ';';
            if (!empty($cell['bg'])) $style .= 'background:' . $cell['bg'] . ';';
            $html .= '<td style="' . $style . '">' . htmlspecialchars($val) . '</td>';
        }
        $html .= '</tr>';
    }
    $html .= '</tbody></table>';
    return $html;
}

function formatSheetToTextPhp($sheetsData) {
    if (empty($sheetsData)) return '(Empty spreadsheet)';
    $maxRow = 1; $maxCol = 0;
    foreach ($sheetsData as $k => $v) {
        if (preg_match('/([A-Z]+)(\d+)/', $k, $m)) {
            $maxRow = max($maxRow, intval($m[2]));
            $colIdx = 0;
            for ($i = 0; $i < strlen($m[1]); $i++) {
                $colIdx = $colIdx * 26 + (ord($m[1][$i]) - 64);
            }
            $maxCol = max($maxCol, $colIdx);
        }
    }
    $getColName = function($idx) {
        $name = '';
        while ($idx > 0) {
            $rem = ($idx - 1) % 26;
            $name = chr(65 + $rem) . $name;
            $idx = intval(($idx - 1) / 26);
        }
        return $name;
    };
    $text = '';
    for ($r = 1; $r <= $maxRow; $r++) {
        $rowVals = [];
        for ($c = 1; $c <= $maxCol; $c++) {
            $cellId = $getColName($c) . $r;
            $cell = $sheetsData[$cellId] ?? [];
            $rowVals[] = $cell['value'] ?? $cell['formula'] ?? '';
        }
        $text .= implode("\t", $rowVals) . "\n";
    }
    return $text;
}

if ($method === 'POST' && $route === 'auth/register') {
    $username = $input['username'] ?? '';
    $email = $input['email'] ?? '';
    $password = $input['password'] ?? '';

    if (!$username || !$email || !$password) sendError('All fields are required');
    if (strlen($username) < 3) sendError('Username must be at least 3 characters');
    if (strlen($password) < 6) sendError('Password must be at least 6 characters');
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) sendError('Invalid email format');

    $users = loadJson(USERS_FILE);
    foreach ($users as $u) {
        if (strtolower($u['username']) === strtolower($username)) sendError('Username already taken');
        if (strtolower($u['email']) === strtolower($email)) sendError('Email already registered');
    }

    $userId = uuidv4();
    $pw = hashPassword($password);
    $users[$userId] = [
        'username' => $username,
        'email' => $email,
        'salt' => $pw['salt'],
        'hash' => $pw['hash'],
        'role' => 'user',
        'createdAt' => date('c')
    ];
    saveJson(USERS_FILE, $users);

    $token = createToken($userId);
    sendSuccess(['token' => $token, 'user' => ['id' => $userId, 'username' => $username, 'email' => $email, 'role' => 'user']]);
}

if ($method === 'POST' && $route === 'auth/login') {
    $login = $input['login'] ?? '';
    $password = $input['password'] ?? '';

    if (!$login || !$password) sendError('All fields are required');

    $users = loadJson(USERS_FILE);
    $foundUser = null;
    $foundUserId = null;
    foreach ($users as $id => $u) {
        if (strtolower($u['username']) === strtolower($login) || strtolower($u['email']) === strtolower($login)) {
            $foundUser = $u;
            $foundUserId = $id;
            break;
        }
    }

    if (!$foundUser || !verifyPassword($password, $foundUser['salt'], $foundUser['hash'])) {
        sendError('Invalid credentials', 401);
    }

    $token = createToken($foundUserId);
    sendSuccess([
        'token' => $token, 
        'user' => [
            'id' => $foundUserId, 
            'username' => $foundUser['username'], 
            'email' => $foundUser['email'], 
            'role' => $foundUser['role'] ?? 'user', 
            'totpEnabled' => $foundUser['totpEnabled'] ?? false
        ]
    ]);
}

if ($method === 'POST' && $route === 'auth/logout') {
    $token = getAuthToken();
    if ($token) {
        $tokens = loadJson(TOKENS_FILE);
        unset($tokens[$token]);
        saveJson(TOKENS_FILE, $tokens);
    }
    sendSuccess();
}

if ($method === 'GET' && $route === 'auth/me') {
    $user = requireAuth();
    sendSuccess(['user' => $user]);
}

if ($method === 'POST' && $route === '2fa/setup') {
    $user = requireAuth();
    $users = loadJson(USERS_FILE);
    $u = &$users[$user['id']];

    if (!empty($u['totpEnabled']) && !empty($u['totpSecret'])) sendError('2FA is already enabled');

    $secret = generateTOTPSecret();
    $u['totpSecret'] = $secret;
    $u['totpEnabled'] = false;
    saveJson(USERS_FILE, $users);

    $uri = getTOTPURI($user['email'], $secret);
    $qrCode = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" . urlencode($uri);

    sendSuccess(['secret' => $secret, 'qrCode' => $qrCode]);
}

if ($method === 'POST' && $route === '2fa/verify') {
    $user = requireAuth();
    $token = $input['token'] ?? '';
    $users = loadJson(USERS_FILE);
    $u = &$users[$user['id']];

    if (empty($u['totpSecret'])) sendError('2FA not setup');

    if (!verifyTOTP($u['totpSecret'], $token)) sendError('Invalid code');

    $u['totpEnabled'] = true;
    saveJson(USERS_FILE, $users);
    sendSuccess(['message' => '2FA enabled successfully']);
}

if ($method === 'POST' && $route === '2fa/disable') {
    $user = requireAuth();
    $password = $input['password'] ?? '';
    $token = $input['token'] ?? '';
    
    $users = loadJson(USERS_FILE);
    $u = &$users[$user['id']];

    if (empty($u['totpEnabled'])) sendError('2FA is not enabled');
    if (!verifyPassword($password, $u['salt'], $u['hash'])) sendError('Invalid password', 401);
    if (!verifyTOTP($u['totpSecret'], $token)) sendError('Invalid 2FA code');

    unset($u['totpSecret']);
    unset($u['totpEnabled']);
    saveJson(USERS_FILE, $users);
    sendSuccess(['message' => '2FA disabled successfully']);
}

// File Upload
if ($method === 'POST' && $route === 'upload') {
    $user = requireAuth();
    $metadata = loadMetadata($user['id']);
    $uploaded = [];

    if (!empty($_FILES['files'])) {
        $files = $_FILES['files'];
        $count = is_array($files['name']) ? count($files['name']) : 1;
        
        for ($i = 0; $i < $count; $i++) {
            $name = is_array($files['name']) ? $files['name'][$i] : $files['name'];
            $tmpName = is_array($files['tmp_name']) ? $files['tmp_name'][$i] : $files['tmp_name'];
            $size = is_array($files['size']) ? $files['size'][$i] : $files['size'];
            $type = is_array($files['type']) ? $files['type'][$i] : $files['type'];

            $id = uuidv4();
            $ext = pathinfo($name, PATHINFO_EXTENSION);
            $storedName = uuidv4() . ($ext ? ".$ext" : "");
            
            if (move_uploaded_file($tmpName, UPLOADS_DIR . '/' . $storedName)) {
                $fileInfo = [
                    'id' => $id,
                    'userId' => $user['id'],
                    'originalName' => $name,
                    'storedName' => $storedName,
                    'size' => $size,
                    'mimeType' => $type ?: 'application/octet-stream',
                    'uploadDate' => date('c'),
                    'shareToken' => uuidv4(),
                    'downloads' => 0,
                    'expiresAt' => null
                ];
                $metadata[$id] = $fileInfo;
                $uploaded[] = $fileInfo;
            }
        }
        saveMetadata($user['id'], $metadata);
    }
    sendSuccess(['files' => $uploaded]);
}

if ($method === 'GET' && $route === 'files') {
    $user = requireAuth();
    if ($user['role'] === 'admin') {
        $files = array_filter(loadAllMetadata(), function($f) { return empty($f['trashedAt']); });
        sendSuccess(['files' => array_values($files), 'isAdmin' => true]);
    } else {
        $metadata = loadMetadata($user['id']);
        $files = array_filter(array_values($metadata), function($f) { return empty($f['trashedAt']); });
        usort($files, function($a, $b) { return strtotime($b['uploadDate']) - strtotime($a['uploadDate']); });
        sendSuccess(['files' => $files, 'isAdmin' => false]);
    }
}

if ($method === 'GET' && preg_match('#^files/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    if ($user['role'] === 'admin') {
        $files = loadAllMetadata();
        $file = null;
        foreach ($files as $f) { if ($f['id'] === $id) { $file = $f; break; } }
        if (!$file) sendError('File not found', 404);
        sendSuccess(['file' => $file]);
    } else {
        $metadata = loadMetadata($user['id']);
        if (!isset($metadata[$id])) sendError('File not found', 404);
        sendSuccess(['file' => $metadata[$id]]);
    }
}

if ($method === 'GET' && preg_match('#^download/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $file = null; $fileUserId = null;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $m = loadMetadata($uid);
            if (isset($m[$id])) { $file = $m[$id]; $fileUserId = $uid; break; }
        }
    } else {
        $m = loadMetadata($user['id']);
        if (isset($m[$id])) { $file = $m[$id]; $fileUserId = $user['id']; }
    }
    if (!$file) sendError('File not found', 404);
    if (!empty($file['expiresAt']) && strtotime($file['expiresAt']) < time()) sendError('File link expired', 410);
    $path = UPLOADS_DIR . '/' . $file['storedName'];
    if (!file_exists($path)) sendError('File missing from disk', 404);
    
    $m = loadMetadata($fileUserId);
    $m[$id]['downloads'] = ($m[$id]['downloads'] ?? 0) + 1;
    saveMetadata($fileUserId, $m);

    $safeFilename = str_replace(['"', "\r", "\n"], ['_', '', ''], basename($file['originalName']));
    header('Content-Description: File Transfer');
    header('Content-Type: ' . $file['mimeType']);
    header('Content-Disposition: attachment; filename="' . $safeFilename . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($path));
    readfile($path);
    exit;
}

if ($method === 'GET' && preg_match('#^preview/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $file = null;
    if ($user['role'] === 'admin') {
        $files = loadAllMetadata();
        foreach ($files as $f) { if ($f['id'] === $id) { $file = $f; break; } }
    } else {
        $m = loadMetadata($user['id']);
        if (isset($m[$id])) $file = $m[$id];
    }
    if (!$file) sendError('File not found', 404);
    if (!empty($file['expiresAt']) && strtotime($file['expiresAt']) < time()) sendError('File link expired', 410);
    $path = UPLOADS_DIR . '/' . $file['storedName'];
    if (!file_exists($path)) sendError('File missing from disk', 404);
    
    $safeFilename = str_replace(['"', "\r", "\n"], ['_', '', ''], basename($file['originalName']));
    header('Content-Type: ' . $file['mimeType']);
    header('Content-Disposition: inline; filename="' . $safeFilename . '"');
    readfile($path);
    exit;
}

if ($method === 'GET' && preg_match('#^thumbnail/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $file = null;
    if ($user['role'] === 'admin') {
        $files = loadAllMetadata();
        foreach ($files as $f) { if ($f['id'] === $id) { $file = $f; break; } }
    } else {
        $m = loadMetadata($user['id']);
        if (isset($m[$id])) $file = $m[$id];
    }
    if (!$file) sendError('File not found', 404);
    $path = UPLOADS_DIR . '/' . $file['storedName'];
    if (!file_exists($path)) sendError('File missing from disk', 404);
    
    header('Content-Type: ' . $file['mimeType']);
    header('Cache-Control: private, max-age=3600');
    readfile($path);
    exit;
}

if ($method === 'DELETE' && preg_match('#^files/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $file = null; $fileUserId = null; $metadata = [];
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $m = loadMetadata($uid);
            if (isset($m[$id])) { $file = $m[$id]; $fileUserId = $uid; $metadata = $m; break; }
        }
    } else {
        $metadata = loadMetadata($user['id']);
        if (isset($metadata[$id])) { $file = $metadata[$id]; $fileUserId = $user['id']; }
    }
    if (!$file) sendError('File not found', 404);
    $metadata[$id]['trashedAt'] = date('c');
    saveMetadata($fileUserId, $metadata);
    sendSuccess(['message' => 'File moved to trash']);
}

if ($method === 'GET' && $route === 'files-trash') {
    $user = requireAuth();
    if ($user['role'] === 'admin') {
        $files = array_filter(loadAllMetadata(), function($f) { return !empty($f['trashedAt']); });
    } else {
        $files = array_filter(array_values(loadMetadata($user['id'])), function($f) { return !empty($f['trashedAt']); });
    }
    usort($files, function($a, $b) { return strtotime($b['trashedAt']) - strtotime($a['trashedAt']); });
    sendSuccess(['files' => array_values($files)]);
}

if ($method === 'POST' && preg_match('#^files/([a-z0-9-]+)/restore$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $fileUserId = null; $metadata = []; $found = false;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $m = loadMetadata($uid);
            if (isset($m[$id])) { $fileUserId = $uid; $metadata = $m; $found = true; break; }
        }
    } else {
        $metadata = loadMetadata($user['id']);
        if (isset($metadata[$id])) { $fileUserId = $user['id']; $found = true; }
    }
    if (!$found || empty($metadata[$id]['trashedAt'])) sendError('File not found in trash', 404);
    unset($metadata[$id]['trashedAt']);
    saveMetadata($fileUserId, $metadata);
    sendSuccess(['message' => 'File restored']);
}

if ($method === 'DELETE' && preg_match('#^files/([a-z0-9-]+)/permanent$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $fileUserId = null; $metadata = []; $found = false;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $m = loadMetadata($uid);
            if (isset($m[$id])) { $fileUserId = $uid; $metadata = $m; $found = true; break; }
        }
    } else {
        $metadata = loadMetadata($user['id']);
        if (isset($metadata[$id])) { $fileUserId = $user['id']; $found = true; }
    }
    if (!$found) sendError('File not found', 404);
    
    $path = UPLOADS_DIR . '/' . $metadata[$id]['storedName'];
    if (file_exists($path)) unlink($path);
    unset($metadata[$id]);
    saveMetadata($fileUserId, $metadata);
    sendSuccess(['message' => 'File permanently deleted']);
}

if ($method === 'PUT' && preg_match('#^files/([a-z0-9-]+)/expire$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $fileUserId = null; $metadata = []; $found = false;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $m = loadMetadata($uid);
            if (isset($m[$id])) { $fileUserId = $uid; $metadata = $m; $found = true; break; }
        }
    } else {
        $metadata = loadMetadata($user['id']);
        if (isset($metadata[$id])) { $fileUserId = $user['id']; $found = true; }
    }
    if (!$found) sendError('File not found', 404);
    
    $hours = intval($input['hours'] ?? 0);
    if ($hours > 0) {
        $metadata[$id]['expiresAt'] = date('c', time() + $hours * 3600);
    } else {
        $metadata[$id]['expiresAt'] = null;
    }
    saveMetadata($fileUserId, $metadata);
    sendSuccess(['file' => $metadata[$id]]);
}

if ($method === 'GET' && $route === 'search') {
    $user = requireAuth();
    $q = $_GET['q'] ?? '';
    if (!$q) sendSuccess(['files' => []]);
    if ($user['role'] === 'admin') {
        $files = array_filter(loadAllMetadata(), function($f) use ($q) {
            return stripos($f['originalName'], $q) !== false && empty($f['trashedAt']);
        });
    } else {
        $metadata = loadMetadata($user['id']);
        $files = array_filter(array_values($metadata), function($f) use ($q) {
            return stripos($f['originalName'], $q) !== false && empty($f['trashedAt']);
        });
        usort($files, function($a, $b) { return strtotime($b['uploadDate']) - strtotime($a['uploadDate']); });
    }
    sendSuccess(['files' => array_values($files)]);
}

if ($method === 'GET' && $route === 'stats') {
    $user = requireAuth();
    $files = $user['role'] === 'admin' ? loadAllMetadata() : array_values(loadMetadata($user['id']));
    $totalSize = 0; $totalDownloads = 0; $recentUploads = 0;
    $dayAgo = time() - 86400;
    foreach ($files as $f) {
        $totalSize += $f['size'] ?? 0;
        $totalDownloads += $f['downloads'] ?? 0;
        if (strtotime($f['uploadDate']) > $dayAgo) $recentUploads++;
    }
    sendSuccess(['stats' => [
        'totalFiles' => count($files),
        'totalSize' => $totalSize,
        'totalDownloads' => $totalDownloads,
        'recentUploads' => $recentUploads
    ]]);
}

if ($method === 'GET' && $route === 'admin/users') {
    $user = requireAuth();
    requireAdmin($user);
    $users = loadJson(USERS_FILE);
    $userList = [];
    foreach ($users as $id => $u) {
        $m = loadMetadata($id);
        $userList[] = [
            'id' => $id,
            'username' => $u['username'],
            'email' => $u['email'],
            'role' => $u['role'] ?? 'user',
            'createdAt' => $u['createdAt'] ?? '',
            'fileCount' => count($m)
        ];
    }
    sendSuccess(['users' => $userList]);
}

if ($method === 'DELETE' && preg_match('#^admin/users/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    requireAdmin($user);
    $id = $matches[1];
    if ($id === $user['id']) sendError('Cannot delete yourself');
    
    $users = loadJson(USERS_FILE);
    if (!isset($users[$id])) sendError('User not found', 404);
    
    $metadata = loadMetadata($id);
    foreach ($metadata as $f) {
        $path = UPLOADS_DIR . '/' . $f['storedName'];
        if (file_exists($path)) unlink($path);
    }
    $dir = SHARED_DIR . '/' . $id;
    if (file_exists($dir . '/files.json')) unlink($dir . '/files.json');
    if (file_exists($dir . '/documents.json')) unlink($dir . '/documents.json');
    if (is_dir($dir)) rmdir($dir);
    
    unset($users[$id]);
    saveJson(USERS_FILE, $users);
    sendSuccess(['message' => 'User deleted successfully']);
}

if ($method === 'GET' && $route === 'admin/all-files') {
    $user = requireAuth();
    requireAdmin($user);
    $files = loadAllMetadata();
    sendSuccess(['files' => $files]);
}

if ($method === 'GET' && $route === 'admin/stats') {
    $user = requireAuth();
    requireAdmin($user);
    $users = loadJson(USERS_FILE);
    $files = loadAllMetadata();
    
    $totalSize = 0; $totalDownloads = 0;
    foreach ($files as $f) {
        $totalSize += $f['size'] ?? 0;
        $totalDownloads += $f['downloads'] ?? 0;
    }
    
    sendSuccess(['stats' => [
        'totalUsers' => count($users),
        'totalFiles' => count($files),
        'totalSize' => $totalSize,
        'totalDownloads' => $totalDownloads
    ]]);
}

if ($method === 'POST' && $route === 'auth/forgot-password') {
    $email = $input['email'] ?? '';
    if (!$email) sendError('Email is required');
    
    $users = loadJson(USERS_FILE);
    $foundId = null; $foundUser = null;
    foreach ($users as $id => $u) {
        if (strtolower($u['email']) === strtolower($email)) {
            $foundId = $id; $foundUser = $u; break;
        }
    }
    
    if (!$foundUser) sendSuccess(['message' => 'If the email exists, you will receive reset instructions']);
    
    if (!empty($foundUser['totpEnabled']) && !empty($foundUser['totpSecret'])) {
        sendSuccess([
            'message' => 'Enter your Google Authenticator code to reset password',
            'totpRequired' => true,
            'email' => $foundUser['email']
        ]);
    } else {
        $code = sprintf('%06d', random_int(100000, 999999));
        $users[$foundId]['resetCode'] = $code;
        $users[$foundId]['resetExpires'] = time() + 900;
        saveJson(USERS_FILE, $users);
        
        try {
            $html = "<div style='font-family:sans-serif;padding:20px;background:#12121a;color:#e2e2f0;border-radius:8px'>"
                  . "<h2 style='color:#a29bfe'>Password Reset Code</h2>"
                  . "<p>Your verification code to reset your password is:</p>"
                  . "<h1 style='color:#00cec9;letter-spacing:4px'>$code</h1>"
                  . "<p style='color:#8888a0;font-size:12px'>This code expires in 15 minutes.</p></div>";
            sendEmail($foundId, $foundUser['email'], "Password Reset Code - $code", $html, "Your password reset code is: $code");
        } catch (Exception $e) {}
        
        sendSuccess([
            'message' => 'Verification code sent to your email',
            'totpRequired' => false,
            'email' => $foundUser['email']
        ]);
    }
}

if ($method === 'POST' && $route === 'auth/reset-password') {
    $email = $input['email'] ?? '';
    $code = $input['code'] ?? $input['totpToken'] ?? '';
    $newPassword = $input['newPassword'] ?? '';
    
    if (!$email || !$newPassword) sendError('All fields are required');
    if (strlen($newPassword) < 6) sendError('Password must be at least 6 characters');
    if (!$code) sendError('Verification code is required');
    
    $users = loadJson(USERS_FILE);
    $foundId = null; $foundUser = null;
    foreach ($users as $id => $u) {
        if (strtolower($u['email']) === strtolower($email)) {
            $foundId = $id; $foundUser = $u; break;
        }
    }
    if (!$foundId) sendError('User not found', 404);
    
    if (!empty($foundUser['totpEnabled']) && !empty($foundUser['totpSecret'])) {
        if (!verifyTOTP($foundUser['totpSecret'], $code)) sendError('Invalid 2FA code');
    } else {
        if (empty($foundUser['resetCode']) || empty($foundUser['resetExpires']) || time() > $foundUser['resetExpires']) {
            sendError('Reset code expired or invalid. Please request a new one.');
        }
        if (trim((string)$code) !== trim((string)$foundUser['resetCode'])) {
            sendError('Invalid reset code');
        }
        unset($users[$foundId]['resetCode'], $users[$foundId]['resetExpires']);
    }
    
    $pw = hashPassword($newPassword);
    $users[$foundId]['salt'] = $pw['salt'];
    $users[$foundId]['hash'] = $pw['hash'];
    saveJson(USERS_FILE, $users);
    
    $tokens = loadJson(TOKENS_FILE);
    foreach ($tokens as $t => $sess) {
        if ($sess['userId'] === $foundId) unset($tokens[$t]);
    }
    saveJson(TOKENS_FILE, $tokens);
    sendSuccess(['message' => 'Password reset successfully']);
}

if ($method === 'POST' && $route === 'auth/change-password') {
    $user = requireAuth();
    $currentPassword = $input['currentPassword'] ?? '';
    $newPassword = $input['newPassword'] ?? '';
    
    if (!$currentPassword || !$newPassword) sendError('Current and new password are required');
    if (strlen($newPassword) < 6) sendError('New password must be at least 6 characters');
    
    $users = loadJson(USERS_FILE);
    $u = &$users[$user['id']];
    if (!verifyPassword($currentPassword, $u['salt'], $u['hash'])) sendError('Current password is incorrect');
    
    $pw = hashPassword($newPassword);
    $u['salt'] = $pw['salt'];
    $u['hash'] = $pw['hash'];
    saveJson(USERS_FILE, $users);
    
    $currentToken = getAuthToken();
    $tokens = loadJson(TOKENS_FILE);
    foreach ($tokens as $t => $sess) {
        if ($sess['userId'] === $user['id'] && $t !== $currentToken) unset($tokens[$t]);
    }
    saveJson(TOKENS_FILE, $tokens);
    sendSuccess(['message' => 'Password changed successfully']);
}

if ($method === 'GET' && $route === 'documents') {
    $user = requireAuth();
    if ($user['role'] === 'admin') {
        $docs = array_filter(loadAllDocuments(), function($d) { return empty($d['trashedAt']); });
        sendSuccess(['documents' => array_values($docs), 'isAdmin' => true]);
    } else {
        $docs = loadDocuments($user['id']);
        $docList = array_filter(array_values($docs), function($d) { return empty($d['trashedAt']); });
        usort($docList, function($a, $b) { return strtotime($b['updatedAt']) - strtotime($a['updatedAt']); });
        sendSuccess(['documents' => $docList, 'isAdmin' => false]);
    }
}

if ($method === 'GET' && preg_match('#^documents/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    if ($user['role'] === 'admin') {
        $docs = loadAllDocuments();
        $doc = null;
        foreach ($docs as $d) { if ($d['id'] === $id) { $doc = $d; break; } }
        if (!$doc) sendError('Document not found', 404);
        sendSuccess(['document' => $doc]);
    } else {
        $docs = loadDocuments($user['id']);
        if (!isset($docs[$id])) sendError('Document not found', 404);
        sendSuccess(['document' => $docs[$id]]);
    }
}

if ($method === 'POST' && $route === 'documents') {
    $user = requireAuth();
    $title = $input['title'] ?? 'Untitled Document';
    $content = $input['content'] ?? '';
    $docs = loadDocuments($user['id']);
    $id = uuidv4();
    $doc = [
        'id' => $id,
        'userId' => $user['id'],
        'title' => $title,
        'content' => $content,
        'isStarred' => false,
        'createdAt' => date('c'),
        'updatedAt' => date('c')
    ];
    $docs[$id] = $doc;
    saveDocuments($user['id'], $docs);
    sendSuccess(['document' => $doc]);
}

if ($method === 'PUT' && preg_match('#^documents/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $docs = []; $doc = null; $docUserId = null;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $d = loadDocuments($uid);
            if (isset($d[$id])) { $docs = $d; $doc = $d[$id]; $docUserId = $uid; break; }
        }
    } else {
        $docs = loadDocuments($user['id']);
        if (isset($docs[$id])) { $doc = $docs[$id]; $docUserId = $user['id']; }
    }
    if (!$doc) sendError('Document not found', 404);
    
    if (isset($input['title'])) $doc['title'] = $input['title'];
    if (isset($input['content'])) $doc['content'] = $input['content'];
    if (isset($input['isStarred'])) $doc['isStarred'] = (bool)$input['isStarred'];
    $doc['updatedAt'] = date('c');
    
    $docs[$id] = $doc;
    saveDocuments($docUserId, $docs);
    sendSuccess(['document' => $doc]);
}

if ($method === 'POST' && preg_match('#^documents/([a-z0-9-]+)/star$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $docs = []; $doc = null; $docUserId = null;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $d = loadDocuments($uid);
            if (isset($d[$id])) { $docs = $d; $doc = $d[$id]; $docUserId = $uid; break; }
        }
    } else {
        $docs = loadDocuments($user['id']);
        if (isset($docs[$id])) { $doc = $docs[$id]; $docUserId = $user['id']; }
    }
    if (!$doc) sendError('Document not found', 404);
    
    $doc['isStarred'] = empty($doc['isStarred']);
    $doc['updatedAt'] = date('c');
    $docs[$id] = $doc;
    saveDocuments($docUserId, $docs);
    sendSuccess(['document' => $doc]);
}

if ($method === 'DELETE' && preg_match('#^documents/([a-z0-9-]+)$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $docs = []; $docUserId = null;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $d = loadDocuments($uid);
            if (isset($d[$id])) { $docs = $d; $docUserId = $uid; break; }
        }
    } else {
        $docs = loadDocuments($user['id']);
        if (isset($docs[$id])) $docUserId = $user['id'];
    }
    if (!$docUserId) sendError('Document not found', 404);
    
    $docs[$id]['trashedAt'] = date('c');
    $docs[$id]['updatedAt'] = date('c');
    saveDocuments($docUserId, $docs);
    sendSuccess(['message' => 'Document moved to trash']);
}

if ($method === 'GET' && $route === 'documents-trash') {
    $user = requireAuth();
    if ($user['role'] === 'admin') {
        $docs = array_filter(loadAllDocuments(), function($d) { return !empty($d['trashedAt']); });
    } else {
        $docs = array_filter(array_values(loadDocuments($user['id'])), function($d) { return !empty($d['trashedAt']); });
    }
    usort($docs, function($a, $b) { return strtotime($b['trashedAt']) - strtotime($a['trashedAt']); });
    sendSuccess(['documents' => array_values($docs)]);
}

if ($method === 'POST' && preg_match('#^documents/([a-z0-9-]+)/restore$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $docs = []; $docUserId = null;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $d = loadDocuments($uid);
            if (isset($d[$id])) { $docs = $d; $docUserId = $uid; break; }
        }
    } else {
        $docs = loadDocuments($user['id']);
        if (isset($docs[$id])) $docUserId = $user['id'];
    }
    if (!$docUserId || empty($docs[$id]['trashedAt'])) sendError('Document not found in trash', 404);
    
    unset($docs[$id]['trashedAt']);
    $docs[$id]['updatedAt'] = date('c');
    saveDocuments($docUserId, $docs);
    sendSuccess(['message' => 'Document restored']);
}

if ($method === 'DELETE' && preg_match('#^documents/([a-z0-9-]+)/permanent$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $docs = []; $docUserId = null;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $d = loadDocuments($uid);
            if (isset($d[$id])) { $docs = $d; $docUserId = $uid; break; }
        }
    } else {
        $docs = loadDocuments($user['id']);
        if (isset($docs[$id])) $docUserId = $user['id'];
    }
    if (!$docUserId) sendError('Document not found', 404);
    
    unset($docs[$id]);
    saveDocuments($docUserId, $docs);
    sendSuccess(['message' => 'Document permanently deleted']);
}

if ($method === 'GET' && $route === 'documents-search') {
    $user = requireAuth();
    $q = $_GET['q'] ?? '';
    if (!$q) sendSuccess(['documents' => []]);
    if ($user['role'] === 'admin') {
        $docs = array_filter(loadAllDocuments(), function($d) use ($q) {
            return stripos($d['title'], $q) !== false && empty($d['trashedAt']);
        });
    } else {
        $docs = loadDocuments($user['id']);
        $docList = array_filter(array_values($docs), function($d) use ($q) {
            return stripos($d['title'], $q) !== false && empty($d['trashedAt']);
        });
        usort($docList, function($a, $b) { return strtotime($b['updatedAt']) - strtotime($a['updatedAt']); });
        $docs = $docList;
    }
    sendSuccess(['documents' => array_values($docs)]);
}

if ($method === 'GET' && $route === 'smtp-settings') {
    $user = requireAuth();
    sendSuccess(['config' => getUserSmtpConfig($user['id'])]);
}

if ($method === 'PUT' && $route === 'smtp-settings') {
    $user = requireAuth();
    saveUserSmtpConfig($user['id'], $input);
    sendSuccess(['message' => 'SMTP settings saved', 'config' => getUserSmtpConfig($user['id'])]);
}

if ($method === 'POST' && $route === 'smtp-test') {
    $user = requireAuth();
    $to = $input['to'] ?? $user['email'];
    if (!$to) sendError('Valid email address is required');
    try {
        sendEmail(
            $user['id'],
            $to,
            'SMTP Test Connection',
            '<h2>SMTP Test Successful!</h2><p>Your email settings are correctly configured for Abdullah File Share.</p>',
            'SMTP Test Successful! Your email settings are correctly configured.'
        );
        sendSuccess(['message' => "Test email sent successfully to $to!"]);
    } catch (Exception $e) {
        sendError('Test failed: ' . $e->getMessage());
    }
}

if ($method === 'GET' && preg_match('#^share/([a-z0-9-]+)$#', $route, $matches)) {
    $token = $matches[1];
    $file = null;
    $users = loadJson(USERS_FILE);
    foreach (array_keys($users) as $uid) {
        $m = loadMetadata($uid);
        foreach ($m as $f) {
            if ($f['shareToken'] === $token && empty($f['trashedAt'])) {
                $file = $f; break 2;
            }
        }
    }
    if (!$file) sendError('Link invalid or expired', 404);
    if (!empty($file['expiresAt']) && strtotime($file['expiresAt']) < time()) sendError('Link invalid or expired', 404);
    sendSuccess(['file' => $file]);
}

if ($method === 'GET' && preg_match('#^share-download/([a-z0-9-]+)$#', $route, $matches)) {
    $token = $matches[1];
    $file = null; $fileUserId = null; $m = [];
    $users = loadJson(USERS_FILE);
    foreach (array_keys($users) as $uid) {
        $m = loadMetadata($uid);
        foreach ($m as $f) {
            if ($f['shareToken'] === $token && empty($f['trashedAt'])) {
                $file = $f; $fileUserId = $uid; break 2;
            }
        }
    }
    if (!$file) sendError('Link invalid or expired', 404);
    if (!empty($file['expiresAt']) && strtotime($file['expiresAt']) < time()) sendError('Link invalid or expired', 404);
    
    $path = UPLOADS_DIR . '/' . $file['storedName'];
    if (!file_exists($path)) sendError('File missing from disk', 404);
    
    $m[$file['id']]['downloads'] = ($m[$file['id']]['downloads'] ?? 0) + 1;
    saveMetadata($fileUserId, $m);

    header('Content-Description: File Transfer');
    header('Content-Type: ' . $file['mimeType']);
    header('Content-Disposition: attachment; filename="' . basename($file['originalName']) . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($path));
    readfile($path);
    exit;
}

if ($method === 'POST' && preg_match('#^files/([a-z0-9-]+)/share-email$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $to = $input['to'] ?? '';
    $message = $input['message'] ?? '';
    if (!$to) sendError('Valid email address is required');
    
    $file = null;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $m = loadMetadata($uid);
            if (isset($m[$id])) { $file = $m[$id]; break; }
        }
    } else {
        $file = loadMetadata($user['id'])[$id] ?? null;
    }
    if (!$file) sendError('File not found', 404);
    
    $path = UPLOADS_DIR . '/' . $file['storedName'];
    if (!file_exists($path)) sendError('File missing from disk', 404);

    $sizeStr = $file['size'] < 1024 ? $file['size'] . ' B' : ($file['size'] < 1048576 ? round($file['size'] / 1024, 1) . ' KB' : round($file['size'] / 1048576, 1) . ' MB');

    $htmlBody = "
      <div style='font-family:-apple-system,sans-serif;max-width:700px;margin:0 auto;padding:30px;background:#12121a;color:#e2e2f0;border-radius:12px'>
        <h2 style='color:#a29bfe;border-bottom:1px solid #2a2a3a;padding-bottom:12px'>📎 {$file['originalName']}</h2>
        " . ($message ? "<p style='color:#8888a0;font-style:italic;border-left:3px solid #6c5ce7;padding-left:12px;margin:16px 0'>" . htmlspecialchars($message) . "</p>" : '') . "
        <div style='background:#1a1a28;padding:20px;border-radius:8px;border:1px solid #2a2a3a;margin:16px 0'>
          <p style='margin:0 0 8px 0'><strong style='color:#a29bfe'>File:</strong> {$file['originalName']}</p>
          <p style='margin:0 0 8px 0'><strong style='color:#a29bfe'>Size:</strong> $sizeStr</p>
          <p style='margin:0 0 8px 0'><strong style='color:#a29bfe'>Type:</strong> {$file['mimeType']}</p>
        </div>
        <p style='color:#8888a0;font-size:12px;margin-top:20px;border-top:1px solid #2a2a3a;padding-top:12px'>
          Shared by <strong>{$user['username']}</strong> via Abdullah File Share
        </p>
      </div>";

    $textBody = "{$file['originalName']}\n\n" . ($message ? $message . "\n\n" : '') . "---\nShared by {$user['username']} via Abdullah File Share";

    $attachments = [];
    if (file_exists($path)) {
        $attachments[] = [
            'filename' => $file['originalName'],
            'contentType' => $file['mimeType'] ?? 'application/octet-stream',
            'content' => file_get_contents($path)
        ];
    }

    try {
        sendEmail($user['id'], $to, "📎 " . $file['originalName'], $htmlBody, $textBody, $attachments);
        sendSuccess(['message' => "Shared with $to successfully!"]);
    } catch (Exception $e) {
        sendError('Failed to send: ' . $e->getMessage());
    }
}

if ($method === 'POST' && preg_match('#^documents/([a-z0-9-]+)/share-email$#', $route, $matches)) {
    $user = requireAuth();
    $id = $matches[1];
    $to = $input['to'] ?? '';
    $message = $input['message'] ?? '';
    if (!$to) sendError('Valid email address is required');
    
    $doc = null;
    if ($user['role'] === 'admin') {
        $users = loadJson(USERS_FILE);
        foreach (array_keys($users) as $uid) {
            $d = loadDocuments($uid);
            if (isset($d[$id])) { $doc = $d[$id]; break; }
        }
    } else {
        $doc = loadDocuments($user['id'])[$id] ?? null;
    }
    if (!$doc) sendError('Document not found', 404);

    $isSheet = (($doc['docType'] ?? '') === 'sheet');
    $subject = ($isSheet ? "📊 " : "📄 ") . $doc['title'];
    $attachments = [];

    if ($isSheet) {
        $contentHtml = formatSheetToHtmlPhp($doc['sheetsData'] ?? []);
        $contentText = formatSheetToTextPhp($doc['sheetsData'] ?? []);
        $attachments[] = [
            'filename' => ($doc['title'] ?? 'Spreadsheet') . '.csv',
            'contentType' => 'text/csv; charset=utf-8',
            'content' => $contentText
        ];
    } else {
        $contentEscaped = htmlspecialchars($doc['content'] ?? '(Empty document)');
        $contentHtml = "<pre style='white-space:pre-wrap;line-height:1.8;color:#e2e2f0;font-size:14px;background:#1a1a28;padding:20px;border-radius:8px;border:1px solid #2a2a3a'>$contentEscaped</pre>";
        $contentText = strip_tags($doc['content'] ?? '(Empty document)');
        $docFullHtml = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>" . htmlspecialchars($doc['title']) . "</title><style>body{font-family:sans-serif;max-width:800px;margin:40px auto;padding:20px;line-height:1.8;color:#111;background:#fff}</style></head><body><h1>" . htmlspecialchars($doc['title']) . "</h1><div>" . ($doc['content'] ?? '') . "</div></body></html>";
        $attachments[] = [
            'filename' => ($doc['title'] ?? 'Document') . '.html',
            'contentType' => 'text/html; charset=utf-8',
            'content' => $docFullHtml
        ];
    }

    $htmlBody = "
      <div style='font-family:-apple-system,sans-serif;max-width:800px;margin:0 auto;padding:30px;background:#12121a;color:#e2e2f0;border-radius:12px'>
        <h2 style='color:#a29bfe;border-bottom:1px solid #2a2a3a;padding-bottom:12px'>" . htmlspecialchars($doc['title']) . "</h2>
        " . ($message ? "<p style='color:#8888a0;font-style:italic;border-left:3px solid #6c5ce7;padding-left:12px;margin:16px 0'>" . htmlspecialchars($message) . "</p>" : '') . "
        $contentHtml
        <p style='color:#8888a0;font-size:12px;margin-top:20px;border-top:1px solid #2a2a3a;padding-top:12px'>
          Shared by <strong>" . htmlspecialchars($user['username']) . "</strong> via Abdullah File Share
        </p>
      </div>";

    $textBody = "{$doc['title']}\n\n" . ($message ? $message . "\n\n" : '') . $contentText . "\n\n---\nShared by {$user['username']} via Abdullah File Share";

    try {
        sendEmail($user['id'], $to, $subject, $htmlBody, $textBody, $attachments);
        sendSuccess(['message' => "Shared with $to successfully!"]);
    } catch (Exception $e) {
        sendError('Failed to send: ' . $e->getMessage());
    }
}

// Default 404
sendError('API Route Not Found', 404);
