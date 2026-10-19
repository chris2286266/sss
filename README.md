# PHP Shamir's Secret Sharing

A dependency-light PHP implementation of Shamir's Secret Sharing that is compatible with the 8-bit share format used by [Ian Coleman's Shamir tool](https://iancoleman.io/shamir/).

Split a secret into multiple shares and set the minimum number of shares required to reconstruct it. For example, a 3-of-5 split creates five shares, any three of which can recover the secret.

## Requirements

- PHP with `mbstring` enabled for the text helpers.
- No Composer packages are required.

The hexadecimal API does not require `mbstring`.

## Getting started

Include [`lib_sss.php`](./lib_sss.php) in your PHP application:

```php
require_once __DIR__ . '/lib_sss.php';

$secret = 'my very secret text';
$shares = shamir_split_text($secret, 5, 3);

// Keep any three shares; the remaining shares are not needed to recover it.
$recovered = shamir_combine_text([
    $shares[0],
    $shares[2],
    $shares[4],
]);

echo $recovered; // my very secret text
```

`shamir_split_text()` returns an array of share strings. Each share can be stored or transferred separately; pass the required number of shares to `shamir_combine_text()` to reconstruct the text.

## API

### Text

```php
shamir_split_text(string $secret, int $numShares, int $threshold): array
shamir_combine_text(array $shares): string
```

Text shares use the same conversion and share representation as Ian Coleman's UI. The conversion is intended for ordinary text (including ASCII and BMP characters). For arbitrary binary data or exact control over the hexadecimal representation, use the hex API.

### Hexadecimal

```php
shamir_share(
    string $hexSecret,
    int $numShares,
    int $threshold,
    int $padLength = 128
): array

shamir_combine(array $shares): string
```

`shamir_share()` accepts a non-empty hexadecimal string and returns compatible share strings. `shamir_combine()` returns the reconstructed secret as hexadecimal. The default padding length is 128 bits, matching `secrets.js`; set `padLength` to `0` to disable padding.

The implementation supports 2–255 total shares and requires a threshold between 2 and the total number of shares. Combining requires at least two unique shares. Invalid input and unsupported share formats throw exceptions.

## Compatibility

- Uses GF(2^8), the `0x11d` reduction polynomial, and 8-bit shares.
- Shares can be exchanged with Ian Coleman's Shamir tool.
- The PHP implementation can combine compatible 8-bit shares; other field sizes are not supported.

Run [`sss_test.php`](./sss_test.php) for examples that combine shares from Ian Coleman's tool, split and recover text, and print shares for use in the browser tool:

```sh
php sss_test.php
```

## Security notes

Shamir's Secret Sharing divides a secret; it does not encrypt shares or authenticate them. Protect shares as sensitive data, distribute them through appropriately secure channels, and avoid placing all shares in the same storage location. Anyone who obtains the threshold number of shares can reconstruct the secret.

## License

This project is licensed under the [MIT License](./LICENSE).
