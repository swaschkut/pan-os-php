<?php
/**
 * ISC License
 *
 * Copyright (c) 2024, Sven Waschkut - pan-os-php@waschkut.net
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

class PanosCrypto
{
    private const KDF_SALT = "\x75\xb8\x49\x83\x90\xbc\x2a\x65\x9c\x56\x93\xe7\xe5\xc5\xf0\x24";
    private const DEFAULT_KEY = "p1a2l3o4a5l6t7o8";

    /**
     * Derives the AES-256 key using MD5 doubling as per the Rust source.
     */
    private function deriveKey(?string $masterKey): string
    {
        $key = (empty($masterKey)) ? self::DEFAULT_KEY : $masterKey;

        $input = $key . self::KDF_SALT;
        $digest = md5($input, true);

        // Concat MD5 result with itself to get 32 bytes for AES-256
        return $digest . $digest;
    }

    /**
     * Encrypts a string into the PAN-OS format.
     */
    public function encrypt(string $input, ?string $masterKey = null): string
    {
        if (empty($input)) {
            throw new Exception("Input data cannot be empty.");
        }

        $derivedKey = $this->deriveKey($masterKey);
        $iv = str_repeat("\0", 16);

        $ciphertext = openssl_encrypt($input, 'aes-256-cbc', $derivedKey, OPENSSL_RAW_DATA, $iv);

        $version = base64_encode("\x01");
        $hash    = base64_encode(sha1($input, true));
        $ctBase64 = base64_encode($ciphertext);

        return "-" . $version . $hash . $ctBase64;
    }

    /**
     * Decrypts a PAN-OS formatted string.
     */
    public function decrypt(string $input, ?string $masterKey = null): string
    {
        try {
            if (strpos($input, '-') !== 0) {
                throw new Exception("Invalid format: Input must start with '-'");
            }

            // Version is 4 chars of Base64 (after the '-')
            $versionRaw = base64_decode(substr($input, 1, 4));
            if ($versionRaw !== "\x01") {
                throw new Exception("Incompatible version detected.");
            }

            // Integrity hash is the next 28 chars
            $expectedHash = base64_decode(substr($input, 5, 28));

            // Ciphertext is everything from index 33 onwards
            $ciphertext = base64_decode(substr($input, 33));

            if (!$ciphertext || strlen($ciphertext) % 16 !== 0) {
                throw new Exception("Invalid ciphertext length.");
            }

            $derivedKey = $this->deriveKey($masterKey);
            $iv = str_repeat("\0", 16);

            $cleartext = openssl_decrypt($ciphertext, 'aes-256-cbc', $derivedKey, OPENSSL_RAW_DATA, $iv);

            if ($cleartext === false) {
                throw new Exception("OpenSSL decryption failed.");
            }

            if (sha1($cleartext, true) !== $expectedHash) {
                throw new Exception("Integrity check failed. The Master Key is likely incorrect.");
            }

            return $cleartext;
        }
        catch (Exception $e) {
            return false; // Return false instead of crashing
        }
    }
}

/*
// --- CLI Runner ---

if (php_sapi_name() === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    if ($argc < 3) {
        echo "Usage: php " . $argv[0] . " [encrypt|decrypt] [data] [optional_key]\n";
        exit(1);
    }

    $crypto = new PanosCrypto();
    $action = $argv[1];
    $data   = $argv[2];
    $key    = $argv[3] ?? null;

    try {
        if ($action === 'encrypt') {
            echo $crypto->encrypt($data, $key) . "\n";
        } elseif ($action === 'decrypt') {
            echo $crypto->decrypt($data, $key) . "\n";
        } else {
            echo "Error: Action must be 'encrypt' or 'decrypt'.\n";
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        exit(1);
    }
}
*/

/*
<?php

require_once 'PanosCrypto.php';

//-AQ==gpw4BEAbByf3D3PUQV4WJADL5Xs=2O5eYT0SPI8DxcU7xNouZA==
//dummy

$palo = new PanosCrypto();
$secret = $palo->encrypt("mypassword");
print $palo->decrypt($secret)."\n";


print "DECRYPT: ".$palo->decrypt("-AQ==gpw4BEAbByf3D3PUQV4WJADL5Xs=2O5eYT0SPI8DxcU7xNouZA==")."\n";
print "encrypt: ".$palo->encrypt("dummy")."\n";
 */
