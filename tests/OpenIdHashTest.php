<?php declare(strict_types=1);

namespace danielburger1337\OpenIdHash\Tests;

use danielburger1337\OpenIdHash\OpenIdHash;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(OpenIdHash::class)]
class OpenIdHashTest extends TestCase
{
    private const TOKEN = 'YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL';
    private const OTHER_TOKEN = 'anhfgwoahnfowiabnfwiafwioafnwiaonfaiwo';
    private const UNEXPECTED_HASH = 'wahfoifwj9fnviww92w';

    /** @see https://bitbucket.org/openid/connect/issues/1125 */
    private const EXPECTED_HASH_SHAKE256_114 = 'sB_U72jyb0WgtX8TsVoqJnm6CD295W9gfSDRxkilB3LAL7REi9JYutRW_s1yE4lD8cOfMZf83gi4';
    private const EXPECTED_HASH_SHA256 = 'xsZZrUssMXjL3FBlzoSh2g';
    private const EXPECTED_HASH_SHA384 = 'adt46pcdiB-l6eTNifgoVM-5AIJAxq84';
    private const EXPECTED_HASH_SHA512 = 'p2LHG4H-8pYDc0hyVOo3iIHvZJUqe9tbj3jESOuXbkY';

    #[Test]
    #[DataProvider('createHashDataProvider')]
    public function createAccessTokenHashReturnsExpected(string $algorithm, ?string $curve, string $expected): void
    {
        $instance = new OpenIdHash($algorithm, $curve);
        $returnValue = $instance->createAccessTokenHash(self::TOKEN);

        $this->assertEquals($expected, $returnValue);
    }

    #[Test]
    #[DataProvider('createHashDataProvider')]
    public function createCodeHashReturnsExpected(string $algorithm, ?string $curve, string $expected): void
    {
        $instance = new OpenIdHash($algorithm, $curve);
        $returnValue = $instance->createCodeHash(self::TOKEN);

        $this->assertEquals($expected, $returnValue);
    }

    #[Test]
    #[DataProvider('createHashDataProvider')]
    public function createStateHashReturnsExpected(string $algorithm, ?string $curve, string $expected): void
    {
        $instance = new OpenIdHash($algorithm, $curve);
        $returnValue = $instance->createStateHash(self::TOKEN);

        $this->assertEquals($expected, $returnValue);
    }

    #[Test]
    #[DataProvider('verifyHashDataProvider')]
    public function verifyAccessTokenHashReturnsExpected(string $algorithm, ?string $curve, string $token, string $hash, bool $expected): void
    {
        $instance = new OpenIdHash($algorithm, $curve);
        $returnValue = $instance->verifyAccessTokenHash($token, $hash);

        $this->assertEquals($expected, $returnValue);
    }

    #[Test]
    public function verifyAccessTokenHashEmptyTokenReturnsFalse(): void
    {
        $instance = new OpenIdHash('HS256');
        $returnValue = $instance->verifyAccessTokenHash('', 'hash');

        $this->assertFalse($returnValue);
    }

    #[Test]
    public function verifyAccessTokenHashEmptyHashReturnsFalse(): void
    {
        $instance = new OpenIdHash('HS256');
        $returnValue = $instance->verifyAccessTokenHash(self::TOKEN, '');

        $this->assertFalse($returnValue);
    }

    #[Test]
    #[DataProvider('verifyHashDataProvider')]
    public function verifyCodeHashReturnsExpected(string $algorithm, ?string $curve, string $token, string $hash, bool $expected): void
    {
        $instance = new OpenIdHash($algorithm, $curve);
        $returnValue = $instance->verifyCodeHash($token, $hash);

        $this->assertEquals($expected, $returnValue);
    }

    #[Test]
    public function verifyCodeHashEmptyTokenReturnsFalse(): void
    {
        $instance = new OpenIdHash('HS256');
        $returnValue = $instance->verifyCodeHash('', 'hash');

        $this->assertFalse($returnValue);
    }

    #[Test]
    public function verifyCodeHashEmptyHashReturnsFalse(): void
    {
        $instance = new OpenIdHash('HS256');
        $returnValue = $instance->verifyCodeHash(self::TOKEN, '');

        $this->assertFalse($returnValue);
    }

    #[Test]
    #[DataProvider('verifyHashDataProvider')]
    public function verifyStateHashReturnsExpected(string $algorithm, ?string $curve, string $token, string $hash, bool $expected): void
    {
        $instance = new OpenIdHash($algorithm, $curve);
        $returnValue = $instance->verifyStateHash($token, $hash);

        $this->assertEquals($expected, $returnValue);
    }

    #[Test]
    public function verifyStateHashEmptyTokenReturnsFalse(): void
    {
        $instance = new OpenIdHash('HS256');
        $returnValue = $instance->verifyStateHash('', 'hash');

        $this->assertFalse($returnValue);
    }

    #[Test]
    public function verifyStateHashEmptyHashReturnsFalse(): void
    {
        $instance = new OpenIdHash('HS256');
        $returnValue = $instance->verifyStateHash(self::TOKEN, '');

        $this->assertFalse($returnValue);
    }

    #[Test]
    public function unsupportedHashAlgorithmThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The "HS1024" signature algorithm is not supported by this library.');

        new OpenIdHash('HS1024');
    }

    #[Test]
    public function eddsaMissingCurveThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The "EdDSA" algorithm is not supported with the "" "crv"');

        new OpenIdHash('EdDSA', null);
    }

    #[Test]
    public function eddsaInvalidCurveThrowsException(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The "EdDSA" algorithm is not supported with the "abc" "crv"');

        new OpenIdHash('EdDSA', 'abc');
    }

    #[Test]
    public function hashAlgorithmCurveAreCaseInsensitive(): void
    {
        $instance = new OpenIdHash('EDdSa', 'eD448');
        $returnValue = $instance->createAccessTokenHash(self::TOKEN);
        $this->assertEquals(self::EXPECTED_HASH_SHAKE256_114, $returnValue);
    }

    /**
     * @return array<array{0: string, 1: string|null, 2: string}>
     */
    public static function createHashDataProvider(): array
    {
        return [
            ['HS256', null, self::EXPECTED_HASH_SHA256],
            ['RS256', null, self::EXPECTED_HASH_SHA256],
            ['PS256', null, self::EXPECTED_HASH_SHA256],
            ['ES256', null, self::EXPECTED_HASH_SHA256],
            ['ES256K', null, self::EXPECTED_HASH_SHA256],

            ['HS384', null, self::EXPECTED_HASH_SHA384],
            ['RS384', null, self::EXPECTED_HASH_SHA384],
            ['PS384', null, self::EXPECTED_HASH_SHA384],
            ['ES384', null, self::EXPECTED_HASH_SHA384],

            ['HS512', null, self::EXPECTED_HASH_SHA512],
            ['RS512', null, self::EXPECTED_HASH_SHA512],
            ['PS512', null, self::EXPECTED_HASH_SHA512],
            ['ES512', null, self::EXPECTED_HASH_SHA512],

            ['EdDSA', 'Ed25519', self::EXPECTED_HASH_SHA512],
            ['EdDSA', 'Ed448', self::EXPECTED_HASH_SHAKE256_114],
        ];
    }

    /**
     * @return array<array{0: string, 1: string|null, 2: string, 3: string, 4: bool}>
     */
    public static function verifyHashDataProvider(): array
    {
        return [
            ['HS256', null, self::TOKEN, self::EXPECTED_HASH_SHA256, true],
            ['HS256', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['HS256', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA256, false],

            ['RS256', null, self::TOKEN, self::EXPECTED_HASH_SHA256, true],
            ['RS256', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['RS256', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA256, false],

            ['PS256', null, self::TOKEN, self::EXPECTED_HASH_SHA256, true],
            ['PS256', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['PS256', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA256, false],

            ['ES256', null, self::TOKEN, self::EXPECTED_HASH_SHA256, true],
            ['ES256', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['ES256', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA256, false],

            ['ES256K', null, self::TOKEN, self::EXPECTED_HASH_SHA256, true],
            ['ES256K', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['ES256K', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA256, false],

            ['HS384', null, self::TOKEN, self::EXPECTED_HASH_SHA384, true],
            ['HS384', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['HS384', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA384, false],

            ['RS384', null, self::TOKEN, self::EXPECTED_HASH_SHA384, true],
            ['RS384', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['RS384', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA384, false],

            ['PS384', null, self::TOKEN, self::EXPECTED_HASH_SHA384, true],
            ['PS384', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['PS384', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA384, false],

            ['ES384', null, self::TOKEN, self::EXPECTED_HASH_SHA384, true],
            ['ES384', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['ES384', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA384, false],

            ['HS512', null, self::TOKEN, self::EXPECTED_HASH_SHA512, true],
            ['HS512', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['HS512', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA512, false],

            ['RS512', null, self::TOKEN, self::EXPECTED_HASH_SHA512, true],
            ['RS512', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['RS512', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA512, false],

            ['PS512', null, self::TOKEN, self::EXPECTED_HASH_SHA512, true],
            ['PS512', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['PS512', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA512, false],

            ['ES512', null, self::TOKEN, self::EXPECTED_HASH_SHA512, true],
            ['ES512', null, self::TOKEN, self::UNEXPECTED_HASH, false],
            ['ES512', null, self::OTHER_TOKEN, self::EXPECTED_HASH_SHA512, false],

            ['EdDSA', 'Ed25519', self::TOKEN, self::EXPECTED_HASH_SHA512, true],
            ['EdDSA', 'Ed25519', self::TOKEN, self::UNEXPECTED_HASH, false],
            ['EdDSA', 'Ed25519', self::OTHER_TOKEN, self::EXPECTED_HASH_SHA512, false],

            ['EdDSA', 'Ed448', self::TOKEN, self::EXPECTED_HASH_SHAKE256_114, true],
            ['EdDSA', 'Ed448', self::TOKEN, self::UNEXPECTED_HASH, false],
            ['EdDSA', 'Ed448', self::OTHER_TOKEN, self::EXPECTED_HASH_SHAKE256_114, false],
        ];
    }
}
