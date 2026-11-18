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

require_once dirname(__FILE__) . '/ConfigSecrets.php';

/**
 * type=master-key actions=scrub: make a configuration loadable on a lab device that does not have the master key of
 * the source - every master-key encrypted value is REPLACED (nothing is decrypted, the master key of the source is not
 * needed, the format of the source value - AES-256-CBC, AES-256-GCM, unknown - does not matter):
 *   - secrets (pre-shared keys, passwords, ...): a placeholder, encrypted with the target master key (AES-256-CBC)
 *   - certificates with a private key: a new certificate with the same name and subject and a new key pair
 * The real secrets are gone afterwards - the result is for a lab (commit validation), never for production.
 */
class ConfigSecretsScrub
{
    const PLACEHOLDER = 'placeholder';
    const CERTIFICATE = 'certificate-replaced';
    const CERTIFICATE_CHILD = 'certificate-reissued';
    const FAILED = 'failed';

    /** placeholder: 16 characters, satisfies the usual minimum lengths (e.g. SNMPv3 passwords: 8) */
    const DEFAULT_PLACEHOLDER = 'Dummy-1234567890';

    /**
     * @param string $placeholder clear text that replaces every secret
     * @param string|null $targetKey master key of the target device (null = default master key)
     * @return array list of array( xpath, location, field, status, detail )
     */
    public static function scrub( DOMDocument $doc, $placeholder = self::DEFAULT_PLACEHOLDER, $targetKey = null )
    {
        $crypto = new PanosCrypto();
        $targetKey = $targetKey === '' ? null : $targetKey;
        $encPlaceholder = $crypto->encrypt( $placeholder, $targetKey );
        $out = array();
        $x = new DOMXPath( $doc );

        // 1. certificates: entries with an encrypted private key, then the certificates they issued
        $certDone = array();    // spl_object_id of entry => TRUE
        $replaced = array();    // subject DN => array( cert PEM, key ) of replaced certificates (issuers for the next round)
        $byOriginal = array();  // md5 of the original certificate => its replacement
        $pending = array();
        foreach( $x->query('//certificate/entry[private-key]') as $e )
            $pending[] = $e;
        $all = iterator_to_array( $x->query('//certificate/entry[public-key]') );

        $guard = 0;
        while( count($pending) && $guard++ < 50 )
        {
            // issuers first: a certificate whose issuer is still pending waits for the next round
            $next = array();
            $progress = FALSE;
            foreach( $pending as $e )
            {
                $info = self::certInfo( $e );
                $hasKey = DH::findFirstElement( 'private-key', $e ) !== FALSE;
                list( $location, $field ) = ConfigSecrets::locate( $e );
                $item = array( 'xpath' => DH::elementToPanXPath( $e ), 'location' => $location, 'field' => $field,
                    'status' => self::FAILED, 'detail' => '' );
                if( $info === null )
                {
                    $item['detail'] = 'public-key is no readable certificate - entry unchanged';
                    $out[] = $item;
                    $certDone[spl_object_id($e)] = TRUE;
                    $progress = TRUE;
                    continue;
                }
                $issuer = null;
                if( !$info['selfsigned'] )
                {
                    if( isset($replaced[$info['issuerDn']]) )
                        $issuer = $replaced[$info['issuerDn']];
                    elseif( self::issuerPending( $info['issuerDn'], $pending, $e ) )
                    {
                        $next[] = $e;
                        continue;
                    }
                }
                // copies of one certificate (e.g. the same CA in several templates) get the same new certificate
                $origId = md5( trim( DH::findFirstElement( 'public-key', $e )->textContent ) );
                $new = isset($byOriginal[$origId]) ? $byOriginal[$origId] : self::newCertificate( $info, $issuer );
                if( $new !== null )
                    $byOriginal[$origId] = $new;
                $certDone[spl_object_id($e)] = TRUE;
                $progress = TRUE;
                if( $new === null )
                {
                    $item['detail'] = 'new certificate could not be generated (openssl) - entry unchanged';
                    $out[] = $item;
                    continue;
                }
                self::writeCertificate( $e, $new, $info, $issuer !== null, $hasKey ? $crypto->encrypt( $new['keyPem'], $targetKey ) : null );
                $replaced[$info['subjectDn']] = $new;
                $item['status'] = $hasKey ? self::CERTIFICATE : self::CERTIFICATE_CHILD;
                $item['detail'] = $info['keyText'] . ', subject ' . $info['subjectDn']
                    . ( $issuer !== null ? ', signed by the replaced certificate ' . $info['issuerDn']
                        : ( $info['selfsigned'] ? ', self-signed' : ', self-signed (issuer ' . $info['issuerDn'] . ' has no private key in the configuration)' ) );
                $out[] = $item;
            }
            // certificates without private key that were issued by a certificate replaced in this round
            foreach( $all as $e )
            {
                if( isset($certDone[spl_object_id($e)]) || in_array( $e, $next, TRUE ) )
                    continue;
                $info = self::certInfo( $e );
                if( $info !== null && !$info['selfsigned'] && isset($replaced[$info['issuerDn']]) )
                {
                    $next[] = $e;
                    $progress = TRUE;
                }
            }
            $pending = $next;
            if( !$progress )
                break;
        }
        foreach( $pending as $e )
        {
            list( $location, $field ) = ConfigSecrets::locate( $e );
            $out[] = array( 'xpath' => DH::elementToPanXPath( $e ), 'location' => $location, 'field' => $field,
                'status' => self::FAILED, 'detail' => 'certificate chain could not be resolved - entry unchanged' );
        }

        // 2. every other encrypted value: placeholder
        foreach( iterator_to_array( $x->query('//text()[starts-with(normalize-space(.),"-")]') ) as $t )
        {
            $value = trim( $t->nodeValue );
            if( ConfigSecrets::parse( $value ) === null )
                continue;
            $el = $t->parentNode;
            if( $el === null || $el->nodeType != XML_ELEMENT_NODE || DH::firstChildElement($el) !== FALSE )
                continue;
            // private keys of certificate entries: written in step 1 (or listed there as failed)
            if( $el->nodeName == 'private-key' && $el->parentNode !== null && isset($certDone[spl_object_id($el->parentNode)]) )
                continue;
            list( $location, $field ) = ConfigSecrets::locate( $el );
            DH::setDomNodeText( $el, $encPlaceholder );
            $out[] = array( 'xpath' => DH::elementToPanXPath( $el ), 'location' => $location, 'field' => $field,
                'status' => self::PLACEHOLDER,
                'detail' => $el->nodeName == 'private-key' ? 'private key outside a certificate entry - the placeholder is no valid key' : '' );
        }
        return $out;
    }

    /** is a certificate with subject $dn (other than $self) still waiting in $pending? */
    private static function issuerPending( $dn, array $pending, $self )
    {
        foreach( $pending as $e )
        {
            if( $e === $self )
                continue;
            $i = self::certInfo( $e );
            if( $i !== null && $i['subjectDn'] === $dn )
                return TRUE;
        }
        return FALSE;
    }

    /** DN as text: /C=DE/O=x/CN=y */
    private static function dnText( array $dn )
    {
        $t = '';
        foreach( $dn as $k => $v )
            foreach( (array)$v as $one )
                $t .= '/' . $k . '=' . $one;
        return $t;
    }

    /** what is needed of the existing certificate (public data only), or null */
    public static function certInfo( DOMElement $entry )
    {
        static $cache = array();
        $id = spl_object_id( $entry );
        $pub = DH::findFirstElement( 'public-key', $entry );
        if( $pub === FALSE )
            return null;
        $pem = trim( $pub->textContent );
        $key = $id . ':' . md5( $pem );
        if( array_key_exists( $key, $cache ) )
            return $cache[$key];

        $parsed = @openssl_x509_parse( $pem );
        $pk = $parsed ? @openssl_pkey_get_public( $pem ) : FALSE;
        if( !$parsed || !$pk )
            return $cache[$key] = null;
        $det = openssl_pkey_get_details( $pk );
        $info = array(
            'subject' => $parsed['subject'], 'subjectDn' => self::dnText( $parsed['subject'] ), 'issuerDn' => self::dnText( $parsed['issuer'] ),
            'validTo' => (int)$parsed['validTo_time_t'],
            'ca' => isset($parsed['extensions']['basicConstraints']) && stripos( $parsed['extensions']['basicConstraints'], 'CA:TRUE' ) !== FALSE,
            'san' => isset($parsed['extensions']['subjectAltName']) ? $parsed['extensions']['subjectAltName'] : null,
            'digest' => stripos( (string)$parsed['signatureTypeSN'], 'SHA512' ) !== FALSE ? 'sha512' : ( stripos( (string)$parsed['signatureTypeSN'], 'SHA384' ) !== FALSE ? 'sha384' : 'sha256' ),
        );
        $info['selfsigned'] = $info['subjectDn'] === $info['issuerDn'];
        if( $det['type'] == OPENSSL_KEYTYPE_EC && isset($det['ec']['curve_name']) )
        {
            $info['keyArgs'] = array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $det['ec']['curve_name'] );
            $info['keyText'] = 'EC ' . $det['ec']['curve_name'];
        }
        else
        {
            $bits = $det['type'] == OPENSSL_KEYTYPE_RSA ? max( 2048, (int)$det['bits'] ) : 2048;
            $info['keyArgs'] = array( 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits );
            $info['keyText'] = 'RSA ' . $bits;
        }
        return $cache[$key] = $info;
    }

    /**
     * new key pair + certificate with the subject, key type, CA flag and subject alternative names of $info;
     * signed by $issuer (array of newCertificate()) or self-signed
     * @return array|null array( certPem, keyPem, key, validFrom, validTo )
     */
    public static function newCertificate( array $info, $issuer = null )
    {
        $key = @openssl_pkey_new( $info['keyArgs'] );
        if( $key === FALSE )
            return null;

        $ext = "basicConstraints=critical,CA:" . ( $info['ca'] ? 'TRUE' : 'FALSE' ) . "\nsubjectKeyIdentifier=hash\n";
        $ext .= $info['ca'] ? "keyUsage=critical,digitalSignature,keyCertSign,cRLSign\n" : "keyUsage=critical,digitalSignature,keyEncipherment\n";
        if( $info['san'] !== null )
        {
            // "DNS:a, IP Address:1.2.3.4, email:x" -> openssl.cnf syntax
            $san = array();
            foreach( explode( ',', $info['san'] ) as $p )
            {
                $p = trim( $p );
                if( preg_match( '/^(DNS|email|URI):(.+)$/', $p, $m ) )
                    $san[] = $m[1] . ':' . $m[2];
                elseif( preg_match( '/^IP Address:(.+)$/', $p, $m ) )
                    $san[] = 'IP:' . $m[1];
            }
            if( count($san) )
                $ext .= "subjectAltName=" . implode( ',', $san ) . "\n";
        }
        $cnf = tempnam( sys_get_temp_dir(), 'panosphp-cnf' );
        file_put_contents( $cnf, "[req]\ndistinguished_name=dn\n[dn]\n[v3]\n" . $ext );
        $opts = array( 'config' => $cnf, 'digest_alg' => $info['digest'], 'x509_extensions' => 'v3' );

        // openssl_csr_new() takes one value per attribute
        $dn = array();
        foreach( $info['subject'] as $k => $v )
            $dn[$k] = is_array($v) ? (string)reset($v) : (string)$v;
        if( count($dn) == 0 )
            $dn = array( 'CN' => 'pan-os-php scrub' );

        $days = (int)ceil( ( $info['validTo'] - time() ) / 86400 );
        if( $days < 365 )
            $days = 365;    // expired / nearly expired certificates: valid for a year, the lab commit should not fail on the date
        if( $days > 7300 )
            $days = 7300;

        $csr = @openssl_csr_new( $dn, $key, $opts );
        $cert = $csr === FALSE ? FALSE : @openssl_csr_sign( $csr, $issuer !== null ? $issuer['certPem'] : null, $issuer !== null ? $issuer['key'] : $key, $days, $opts, random_int( 1, PHP_INT_MAX ) );
        $ok = $cert !== FALSE && openssl_x509_export( $cert, $certPem ) && @openssl_pkey_export( $key, $keyPem, null, array( 'config' => $cnf ) );
        @unlink( $cnf );
        if( !$ok )
            return null;
        $p = openssl_x509_parse( $certPem );
        return array( 'certPem' => trim($certPem), 'keyPem' => self::traditionalKeyPem( trim($keyPem) ), 'key' => $key,
            'validFrom' => (int)$p['validFrom_time_t'], 'validTo' => (int)$p['validTo_time_t'] );
    }

    /**
     * PAN-OS stores RSA keys as "BEGIN RSA PRIVATE KEY" (PKCS#1); OpenSSL 3 exports "BEGIN PRIVATE KEY" (PKCS#8).
     * RSA: unwrap the PKCS#1 key from the PKCS#8 structure. Other key types / already PKCS#1: unchanged.
     */
    public static function traditionalKeyPem( $pem )
    {
        if( strpos( $pem, '-----BEGIN PRIVATE KEY-----' ) !== 0 )
            return $pem;
        $der = base64_decode( preg_replace( '/-----[A-Z ]+-----|\s+/', '', $pem ), TRUE );
        if( $der === FALSE )
            return $pem;
        // PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithm SEQUENCE { OID, ... }, privateKey OCTET STRING }
        $pos = 0;
        $seq = self::der( $der, $pos );
        if( $seq === null || $seq[0] != 0x30 )
            return $pem;
        $body = $seq[1]; $p = 0;
        $version = self::der( $body, $p );
        $alg = self::der( $body, $p );
        $octets = self::der( $body, $p );
        if( $version === null || $alg === null || $octets === null || $alg[0] != 0x30 || $octets[0] != 0x04 )
            return $pem;
        $ap = 0;
        $oid = self::der( $alg[1], $ap );
        // 1.2.840.113549.1.1.1 rsaEncryption
        if( $oid === null || $oid[0] != 0x06 || bin2hex($oid[1]) !== '2a864886f70d010101' )
            return $pem;
        return "-----BEGIN RSA PRIVATE KEY-----\n" . chunk_split( base64_encode($octets[1]), 64, "\n" ) . "-----END RSA PRIVATE KEY-----";
    }

    /** one DER element at $pos: array( tag, content ), $pos moves behind it */
    private static function der( $data, &$pos )
    {
        if( $pos + 2 > strlen($data) )
            return null;
        $tag = ord( $data[$pos++] );
        $len = ord( $data[$pos++] );
        if( $len & 0x80 )
        {
            $n = $len & 0x7f;
            if( $n < 1 || $n > 4 || $pos + $n > strlen($data) )
                return null;
            $len = 0;
            for( $i = 0; $i < $n; $i++ )
                $len = ( $len << 8 ) | ord( $data[$pos++] );
        }
        if( $pos + $len > strlen($data) )
            return null;
        $content = substr( $data, $pos, $len );
        $pos += $len;
        return array( $tag, $content );
    }

    /** "Nov  7 10:30:46 2027 GMT" */
    private static function panDate( $ts )
    {
        return gmdate( 'M', $ts ) . ' ' . str_pad( gmdate( 'j', $ts ), 2, ' ', STR_PAD_LEFT ) . ' ' . gmdate( 'H:i:s Y', $ts ) . ' GMT';
    }

    /** writes the new certificate into the entry; name, subject, common-name, algorithm, ca stay */
    private static function writeCertificate( DOMElement $entry, array $new, array $info, $signedByReplacedIssuer, $encryptedKey )
    {
        $set = function( $name, $text ) use ( $entry ) {
            $n = DH::findFirstElement( $name, $entry );
            if( $n !== FALSE )
                DH::setDomNodeText( $n, $text );
        };
        $set( 'public-key', $new['certPem'] );
        if( $encryptedKey !== null )
            $set( 'private-key', $encryptedKey );
        $set( 'not-valid-before', self::panDate( $new['validFrom'] ) );
        $set( 'not-valid-after', self::panDate( $new['validTo'] ) );
        $set( 'expiry-epoch', (string)$new['validTo'] );
        // issuer unchanged when it was self-signed or is signed by the replaced issuer (same DN); otherwise now self-signed
        if( !$info['selfsigned'] && !$signedByReplacedIssuer )
        {
            $subject = DH::findFirstElement( 'subject', $entry );
            $subjectHash = DH::findFirstElement( 'subject-hash', $entry );
            if( $subject !== FALSE )
                $set( 'issuer', trim($subject->textContent) );
            if( $subjectHash !== FALSE )
                $set( 'issuer-hash', trim($subjectHash->textContent) );
        }
    }
}
