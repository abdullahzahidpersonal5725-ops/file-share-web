<?php
class Base32 {
    private static $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    public static function decode($input) {
        if (empty($input)) return '';
        $input = strtoupper(preg_replace('/[^A-Z2-7]/', '', $input));
        $v = 0; $vbits = 0; $res = '';
        for ($i = 0; $i < strlen($input); $i++) {
            $v = ($v << 5) | strpos(self::$map, $input[$i]);
            $vbits += 5;
            if ($vbits >= 8) {
                $vbits -= 8;
                $res .= chr(($v >> $vbits) & 0xFF);
            }
        }
        return $res;
    }
    public static function encode($input) {
        if (empty($input)) return '';
        $v = 0; $vbits = 0; $res = '';
        for ($i = 0; $i < strlen($input); $i++) {
            $v = ($v << 8) | ord($input[$i]);
            $vbits += 8;
            while ($vbits >= 5) {
                $vbits -= 5;
                $res .= self::$map[($v >> $vbits) & 0x1F];
            }
        }
        if ($vbits > 0) {
            $res .= self::$map[($v << (5 - $vbits)) & 0x1F];
        }
        $padding = (8 - (strlen($res) % 8)) % 8;
        $res .= str_repeat('=', $padding);
        return $res;
    }
}

function generateTOTPSecret() {
    return rtrim(Base32::encode(random_bytes(20)), '=');
}

function getTOTPURI($email, $secret) {
    $issuer = rawurlencode('Abdullah File Share');
    $label = rawurlencode($email);
    return "otpauth://totp/$issuer:$label?secret=$secret&issuer=$issuer&algorithm=SHA1&digits=6&period=30";
}

function verifyTOTP($secret, $code, $window = 1) {
    $decoded = Base32::decode($secret);
    if (strlen($decoded) === 0) return false;
    $t = floor(time() / 30);
    $code = str_pad(trim((string)$code), 6, '0', STR_PAD_LEFT);
    for ($i = -$window; $i <= $window; $i++) {
        $time = pack('N*', 0, $t + $i); // 64-bit big endian integer
        $hash = hash_hmac('sha1', $time, $decoded, true);
        $offset = ord($hash[19]) & 0xf;
        $otp = (
            ((ord($hash[$offset+0]) & 0x7f) << 24 ) |
            ((ord($hash[$offset+1]) & 0xff) << 16 ) |
            ((ord($hash[$offset+2]) & 0xff) << 8 ) |
            (ord($hash[$offset+3]) & 0xff)
        ) % 1000000;
        if (str_pad($otp, 6, '0', STR_PAD_LEFT) === $code) return true;
    }
    return false;
}
