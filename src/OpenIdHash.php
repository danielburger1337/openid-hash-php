<?php declare(strict_types=1);

namespace danielburger1337\OpenIdHash;

use Base64Url\Base64Url;
use danielburger1337\SHA3Shake\SHA3Shake;

class OpenIdHash
{
    private readonly string $hashAlgorithm;

    /**
     * @param string      $algorithm The algorithm that is used to sign the ID token.
     * @param string|null $curve     [optional] Required if the ID token was signed with the EdDSA algorithm.
     *
     * @throws \InvalidArgumentException If the given algorithm is not supported.
     * @throws \InvalidArgumentException If the EdDSA curve is missing or not supported.
     */
    public function __construct(string $algorithm, ?string $curve = null)
    {
        $this->hashAlgorithm = $this->getHashAlgorithm($algorithm, $curve);
    }

    /**
     * Create the "at_hash" verification hash.
     *
     * @param string $accessToken The access token to verify.
     */
    public function createAccessTokenHash(string $accessToken): string
    {
        return $this->createHash($accessToken);
    }

    /**
     * Verify an "at_hash" claim.
     *
     * This method always returns false when either value is an empty string.
     *
     * @param string $accessToken The access token to verify.
     * @param string $atHash      The "at_hash" claim.
     */
    public function verifyAccessTokenHash(string $accessToken, string $atHash): bool
    {
        return $this->verifyHash($accessToken, $atHash);
    }

    /**
     * Create the "c_hash" verification hash.
     *
     * @param string $code The authorization code to verify.
     */
    public function createCodeHash(string $code): string
    {
        return $this->createHash($code);
    }

    /**
     * Verify a "c_hash" claim.
     *
     * This method always returns false when either value is an empty string.
     *
     * @param string $code  The authorization code to verify.
     * @param string $cHash The "c_hash" claim.
     */
    public function verifyCodeHash(string $code, string $cHash): bool
    {
        return $this->verifyHash($code, $cHash);
    }

    /**
     * Create the "s_hash" verification hash.
     *
     * @param string $state The state to verify.
     */
    public function createStateHash(string $state): string
    {
        return $this->createHash($state);
    }

    /**
     * Verify a "s_hash" claim.
     *
     * This method always returns false when either value is an empty string.
     *
     * @param string $state The state to verify.
     * @param string $sHash The "s_hash" claim.
     */
    public function verifyStateHash(string $state, string $sHash): bool
    {
        return $this->verifyHash($state, $sHash);
    }

    private function createHash(string $string): string
    {
        if ($this->hashAlgorithm === 'shake256-114') {
            $hash = SHA3Shake::shake256($string, 114, true);
        } else {
            $hash = \hash($this->hashAlgorithm, $string, true);
            $hash = \substr($hash, 0, (int) (\strlen($hash) / 2));
        }

        return Base64Url::encode($hash);
    }

    private function verifyHash(string $string, string $hash): bool
    {
        $string = \trim($string);
        $hash = \trim($hash);

        if ('' === $hash || '' === $string) {
            return false;
        }

        return \hash_equals($this->createHash($string), $hash);
    }

    /**
     * @throws \InvalidArgumentException If the given algorithm is not supported.
     * @throws \InvalidArgumentException If the EdDSA curve is missing or not supported.
     */
    private function getHashAlgorithm(string $algorithm, ?string $curve = null): string
    {
        switch (\strtolower($algorithm)) {
            case 'hs256':
            case 'rs256':
            case 'ps256':
            case 'es256':
            case 'es256k':
                return 'sha256';

            case 'hs384':
            case 'rs384':
            case 'ps384':
            case 'es384':
                return 'sha384';

            case 'hs512':
            case 'rs512':
            case 'ps512':
            case 'es512':
                return 'sha512';

            case 'eddsa':
                return match (\strtolower($curve ?? '')) {
                    'ed25519' => 'sha512',
                    'ed448' => 'shake256-114', // @see https://bitbucket.org/openid/connect/issues/1125
                    default => throw new \InvalidArgumentException(\sprintf('The "EdDSA" algorithm is not supported with the "%s" "crv".', $curve)),
                };

            default:
                throw new \InvalidArgumentException(\sprintf('The "%s" signature algorithm is not supported by this library.', $algorithm));
        }
    }
}
