# openid-hash

Create and/or verify OpenID Connect 1.0 ID Token hashes (`at_hash`, `c_hash`, `s_hash`).

This library is [PSR-4](https://www.php-fig.org/psr/psr-4/) compatible and can be installed via PHP's dependency manager [Composer](https://getcomposer.org).

```shell
composer require danielburger1337/openid-hash
```

This library requires a 64-bit version of PHP.

---

## **How To Use**

The constructor takes two arguments. The first argument is the [JWA](https://datatracker.ietf.org/doc/html/rfc7518) algorithm the ID Token is signed with. This value can usally be found in the `alg` header parameter of the ID Token.

The second argument is only required when the ID Token is signed with the `EdDSA` algorithm. This argument must then contain the `crv` of the [JWK](https://datatracker.ietf.org/doc/html/rfc7517) that was used to sign the ID Token. This value can usually be found in the `crv` header parameter of the ID Token or in the `jwks_uri` document of the OP.

---

To verify a hash, you can use the `verify*Hash` methods:

```php
<?php
    use danielburger1337\OpenIdHash\OpenIdHash;

    $instance = new OpenIdHash('RS256');
    // see also "verifyCodeHash", "verifyStateHash"
    $isValid = $instance->verifyAccessTokenHash('access token', 'The "at_hash" claim of the ID Token');
    // bool
```

To create a verification hash, you can use the `create*Hash` methods:

```php
<?php
    use danielburger1337\OpenIdHash\OpenIdHash;

    $instance = new OpenIdHash('EdDSA', 'Ed448');
    // see also "createCodeHash", "createStateHash"
    $hash = $instance->createAccessTokenHash('YmJiZTAwYmYtMzgyOC00NzhkLTkyOTItNjJjNDM3MGYzOWIy9sFhvH8K_x8UIHj1osisS57f5DduL');

    print $hash; // sB_U72jyb0WgtX8TsVoqJnm6CD295W9gfSDRxkilB3LAL7REi9JYutRW_s1yE4lD8cOfMZf83gi4
```
