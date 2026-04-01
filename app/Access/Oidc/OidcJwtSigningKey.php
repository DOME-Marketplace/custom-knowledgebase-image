<?php

namespace BookStack\Access\Oidc;

use phpseclib3\Crypt\Common\PublicKey;
use phpseclib3\Crypt\EC;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Math\BigInteger;

class OidcJwtSigningKey
{
    /**
     * @var PublicKey
     */
    protected $key;

    /**
     * Can be created either from a JWK parameter array or local file path to load a certificate from.
     * Examples:
     * 'file:///var/www/cert.pem'
     * ['kty' => 'RSA', 'alg' => 'RS256', 'n' => 'abc123...'].
     *
     * @param array|string $jwkOrKeyPath
     *
     * @throws OidcInvalidKeyException
     */
    public function __construct($jwkOrKeyPath)
    {
        if (is_array($jwkOrKeyPath)) {
            $this->loadFromJwkArray($jwkOrKeyPath);
        } elseif (is_string($jwkOrKeyPath) && strpos($jwkOrKeyPath, 'file://') === 0) {
            $this->loadFromPath($jwkOrKeyPath);
        } else {
            throw new OidcInvalidKeyException('Unexpected type of key value provided');
        }
    }

    /**
     * @throws OidcInvalidKeyException
     */
    protected function loadFromPath(string $path)
    {
        try {
            $key = PublicKeyLoader::load(
                file_get_contents($path)
            );
        } catch (\Exception $exception) {
            throw new OidcInvalidKeyException("Failed to load key from file path with error: {$exception->getMessage()}");
        }

        if (!$key instanceof RSA) {
            throw new OidcInvalidKeyException('Key loaded from file path is not an RSA key as expected');
        }

        $this->key = $key->withPadding(RSA::SIGNATURE_PKCS1);
    }

    /**
     * @throws OidcInvalidKeyException
     */
    protected function loadFromJwkArray(array $jwk)
    {
        // 'use' is optional for a JWK but we assume 'sig' where no value exists since that's what
        // the OIDC discovery spec infers since 'sig' MUST be set if encryption keys come into play.
        $use = $jwk['use'] ?? 'sig';
        if ($use !== 'sig') {
            throw new OidcInvalidKeyException("Only signature keys are currently supported. Found key for use {$jwk['use']}");
        }

        $kty = $jwk['kty'] ?? '';

        if ($kty === 'RSA') {
            $this->loadRsaFromJwk($jwk);
        } elseif ($kty === 'EC') {
            $this->loadEcFromJwk($jwk);
        } else {
            $alg = $jwk['alg'] ?? $kty;
            throw new OidcInvalidKeyException("Only RSA (RS256) and EC P-256 (ES256) keys are supported. Found key type {$alg}");
        }
    }

    /**
     * @throws OidcInvalidKeyException
     */
    protected function loadRsaFromJwk(array $jwk): void
    {
        // 'alg' is optional for a JWK, but we will still attempt to validate if
        // it exists otherwise presume it will be compatible.
        $alg = $jwk['alg'] ?? null;
        if (!(is_null($alg) || $alg === 'RS256')) {
            throw new OidcInvalidKeyException("Only RS256 RSA keys are supported. Found key using {$alg}");
        }

        if (empty($jwk['e'])) {
            throw new OidcInvalidKeyException('An "e" parameter on the provided RSA key is expected');
        }

        if (empty($jwk['n'])) {
            throw new OidcInvalidKeyException('A "n" parameter on the provided RSA key is expected');
        }

        $n = strtr($jwk['n'] ?? '', '-_', '+/');

        try {
            $key = PublicKeyLoader::load([
                'e' => new BigInteger(base64_decode($jwk['e']), 256),
                'n' => new BigInteger(base64_decode($n), 256),
            ]);
        } catch (\Exception $exception) {
            throw new OidcInvalidKeyException("Failed to load RSA key from JWK parameters with error: {$exception->getMessage()}");
        }

        if (!$key instanceof RSA) {
            throw new OidcInvalidKeyException('Key loaded from JWK is not an RSA key as expected');
        }

        $this->key = $key->withPadding(RSA::SIGNATURE_PKCS1);
    }

    /**
     * @throws OidcInvalidKeyException
     */
    protected function loadEcFromJwk(array $jwk): void
    {
        $crv = $jwk['crv'] ?? '';
        if ($crv !== 'P-256') {
            throw new OidcInvalidKeyException("Only P-256 EC keys are supported. Found curve {$crv}");
        }

        if (empty($jwk['x']) || empty($jwk['y'])) {
            throw new OidcInvalidKeyException('EC key is missing required "x" or "y" coordinate');
        }

        try {
            $key = EC::loadFormat('JWK', json_encode([
                'kty' => 'EC',
                'crv' => 'P-256',
                'x'   => $jwk['x'],
                'y'   => $jwk['y'],
            ]));
        } catch (\Exception $exception) {
            throw new OidcInvalidKeyException("Failed to load EC key from JWK parameters with error: {$exception->getMessage()}");
        }

        // ES256 JWT signatures use IEEE P1363 format (raw r||s bytes), not DER/ASN.1.
        $this->key = $key->withSignatureFormat('IEEE')->withHash('sha256');
    }

    /**
     * Use this key to sign the given content and return the signature.
     */
    public function verify(string $content, string $signature): bool
    {
        return $this->key->verify($content, $signature);
    }

    /**
     * Convert the key to a PEM encoded key string.
     */
    public function toPem(): string
    {
        return $this->key->toString('PKCS8');
    }
}
