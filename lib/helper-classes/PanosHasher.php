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

class PanosHasher
{
    /**
     * Verifies if a cleartext password matches a given PAN-OS phash.
     * * @param string $password The cleartext password guess.
     * @param string $phash    The hash string from the PAN-OS configuration.
     * @return bool            True if matches, false otherwise.
     */
    public function verify(string $password, string $phash): bool
    {
        // crypt() automatically identifies the algorithm (SHA-512, MD5, etc.)
        // by the prefix in the $phash string.
        $result = crypt($password, $phash);

        // Use hash_equals to prevent timing attacks
        return hash_equals($phash, $result);
    }
}

/*
<?php
require_once 'PanosHasher.php';


//php phash_verify.php 'Admin1234!' '$5$ueabrxsu$fDGv/W7mep9WCGNe3x8Kqs7tuNlKOZRRwaTSyCMnOV7'
//php phash_verify.php "admin" '$1$mhjmawpq$o4uaiPKXzsJ7AlUcgKvqK0'
//php phash_verify.php 'admin' 'fnRL/G5lXVMug'


// --- CLI Runner Logic ---

if (php_sapi_name() === 'cli' && basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    if ($argc < 3) {
        echo "Usage: php " . $argv[0] . " <password_guess> <phash_string>\n";
        echo "Example: php " . $argv[0] . " 'admin' '\$1\$mhjmawpq\$o4uaiPKXzsJ7AlUcgKvqK0'\n";
        exit(1);
    }

    $hasher = new PanosHasher();
    $passwordGuess = $argv[1];
    $phashString = $argv[2];

    if ($hasher->verify($passwordGuess, $phashString)) {
        echo "MATCH! The password is: " . $passwordGuess . "\n";
        exit(0);
    } else {
        echo "NO MATCH.\n";
        exit(1);
    }
}
 */