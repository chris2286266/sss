<?php

/*
 * Compatible with:
 * https://github.com/iancoleman/shamir
 * src/js/secrets.js
 *
 * Default:
 *   bits      = 8
 *   GF(2^8)
 *   polynomial = 0x11d
 *   padding   = 128 bits
 *
 * Public functions:
 *
 *   shamir_share(string $hexSecret, int $numShares, int $threshold): array
 *   shamir_combine(array $shares): string
 *
 * For Ian Coleman's UI text format:
 *
 *   shamir_split_text(string $text, int $numShares, int $threshold): array
 *   shamir_combine_text(array $shares): string
 */


/* ============================================================
 * Configuration
 * ============================================================ */

function shamir_config(): array
{
    return [
        'bits' => 8,
        'size' => 256,
        'maxShares' => 255,
        'primitive' => 0x11d,
    ];
}


/* ============================================================
 * Public API - exact secrets.js hex interface
 * ============================================================ */

/**
 * Equivalent to:
 *
 *     secrets.share($secret, $numShares, $threshold)
 *
 * $secret MUST be hexadecimal.
 */
function shamir_share(
    string $secret,
    int $numShares,
    int $threshold,
    int $padLength = 128
): array {
    $cfg = shamir_config();

    $secret = strtolower(trim($secret));

    if ($secret === '') {
        throw new InvalidArgumentException('Secret must not be empty.');
    }

    if (!preg_match('/^[0-9a-f]+$/', $secret)) {
        throw new InvalidArgumentException(
            'Secret must be a hexadecimal string.'
        );
    }

    if ($numShares < 2 || $numShares > $cfg['maxShares']) {
        throw new InvalidArgumentException(
            'Number of shares must be between 2 and 255.'
        );
    }

    if ($threshold < 2 || $threshold > $numShares) {
        throw new InvalidArgumentException(
            'Threshold must be between 2 and the number of shares.'
        );
    }

    /*
     * Ian Coleman / secrets.js:
     *
     *     secret = "1" + hex2bin(secret)
     *
     * The leading 1 is a marker allowing leading zeroes to survive
     * reconstruction.
     */
    $binary = '1' . shamir_hex2bin($secret);

    /*
     * Default secrets.js behavior is to pad to 128-bit multiples.
     */
    if ($padLength > 0) {
        $binary = shamir_pad_left_multiple($binary, $padLength);
    }

    /*
     * VERY IMPORTANT:
     *
     * secrets.js returns the chunks RIGHT-TO-LEFT.
     *
     * parts[0] = least-significant/rightmost 8 bits.
     */
    $secretParts = shamir_split_num_string($binary, $cfg['bits']);

    $x = [];
    $y = [];

    foreach ($secretParts as $secretPart) {
        $subShares = shamir_get_shares(
            $secretPart,
            $numShares,
            $threshold
        );

        for ($j = 0; $j < $numShares; $j++) {
            if (!isset($x[$j])) {
                $x[$j] = dechex($subShares[$j]['x']);
            }

            /*
             * This exactly mirrors:
             *
             * y[j] =
             *     padLeft(subShares[j].y.toString(2))
             *     + (y[j] || "");
             *
             * i.e. PREPEND each new field element.
             */
            $binY = str_pad(
                decbin($subShares[$j]['y']),
                $cfg['bits'],
                '0',
                STR_PAD_LEFT
            );

            $y[$j] = $binY . ($y[$j] ?? '');
        }
    }

    $result = [];

    for ($i = 0; $i < $numShares; $i++) {
        $data = shamir_bin2hex($y[$i]);

        $result[] = shamir_construct_share(
            $cfg['bits'],
            hexdec($x[$i]),
            $data
        );
    }

    return $result;
}


/**
 * Equivalent to:
 *
 *     secrets.combine(shares)
 *
 * Returns the recovered secret as HEX.
 */
function shamir_combine(array $shares): string
{
    if (count($shares) < 2) {
        throw new InvalidArgumentException(
            'At least two shares are required.'
        );
    }

    $x = [];
    $y = [];

    $setBits = null;

    foreach ($shares as $rawShare) {

        if (!is_string($rawShare)) {
            throw new InvalidArgumentException(
                'Each share must be a string.'
            );
        }

        /*
         * Ian Coleman's textarea has one share per line, so accepting
         * surrounding whitespace here is useful.
         */
        $rawShare = trim($rawShare);

        $share = shamir_extract_share_components($rawShare);

        if ($setBits === null) {
            $setBits = $share['bits'];
        } elseif ($share['bits'] !== $setBits) {
            throw new InvalidArgumentException(
                'Mismatched shares: different bit settings.'
            );
        }

        if ($share['bits'] !== 8) {
            throw new InvalidArgumentException(
                'This PHP implementation supports 8-bit Ian Coleman shares.'
            );
        }

        /*
         * secrets.js silently ignores duplicate IDs.
         */
        if (in_array($share['id'], $x, true)) {
            continue;
        }

        $x[] = $share['id'];

        /*
         * Again, split RIGHT-TO-LEFT exactly like secrets.js.
         */
        $splitShare = shamir_split_num_string(
            shamir_hex2bin($share['data']),
            8
        );

        foreach ($splitShare as $j => $part) {
            if (!isset($y[$j])) {
                $y[$j] = [];
            }

            $y[$j][count($x) - 1] = $part;
        }
    }

    if (count($x) < 2) {
        throw new InvalidArgumentException(
            'At least two unique shares are required.'
        );
    }

    $result = '';

    /*
     * secrets.js:
     *
     * result =
     *   padLeft(lagrange(...).toString(2))
     *   + result;
     *
     * Again PREPENDING.
     */
    foreach ($y as $values) {

        ksort($values);
        $values = array_values($values);

        $value = shamir_lagrange(0, $x, $values);

        $result =
            str_pad(decbin($value), 8, '0', STR_PAD_LEFT)
            . $result;
    }

    /*
     * Strip zero padding and marker bit exactly like:
     *
     * result.slice(result.indexOf("1") + 1)
     */
    $marker = strpos($result, '1');

    if ($marker === false) {
        return '';
    }

    $result = substr($result, $marker + 1);

    return shamir_bin2hex($result);
}


/* ============================================================
 * Ian Coleman UI string conversion
 * ============================================================ */

/**
 * Ian Coleman's secrets.js str2hex() defaults to TWO bytes per JS
 * UTF-16 character and builds the hex string in reverse order.
 *
 * For ordinary ASCII / BMP text this reproduces the browser behavior.
 */
function shamir_str2hex(string $str): string
{
    /*
     * PHP strings are UTF-8 rather than UTF-16, so convert to UTF-16BE.
     */
    $utf16 = mb_convert_encoding($str, 'UTF-16BE', 'UTF-8');

    $units = str_split($utf16, 2);

    $result = '';

    foreach ($units as $unit) {
        $result = bin2hex($unit) . $result;
    }

    return strtolower($result);
}


function shamir_hex2str(string $hex): string
{
    $hex = strtolower(trim($hex));

    /*
     * secrets.js pads to bytesPerChar = 2 bytes = 4 hex chars.
     */
    $remainder = strlen($hex) % 4;

    if ($remainder !== 0) {
        $hex = str_repeat('0', 4 - $remainder) . $hex;
    }

    $units = [];

    for ($i = 0; $i < strlen($hex); $i += 4) {
        $units[] = substr($hex, $i, 4);
    }

    /*
     * secrets.js prepends each decoded character.
     */
    $units = array_reverse($units);

    $utf16 = '';

    foreach ($units as $unit) {
        $bytes = hex2bin($unit);

        if ($bytes === false) {
            throw new RuntimeException('Invalid reconstructed hex.');
        }

        $utf16 .= $bytes;
    }

    return mb_convert_encoding($utf16, 'UTF-8', 'UTF-16BE');
}


/**
 * Split normal text exactly the way Ian Coleman's UI does.
 */
function shamir_split_text(
    string $secret,
    int $numShares,
    int $threshold
): array {
    return shamir_share(
        shamir_str2hex($secret),
        $numShares,
        $threshold
    );
}


/**
 * Combine Ian Coleman shares and return normal text.
 */
function shamir_combine_text(array $shares): string
{
    return shamir_hex2str(
        shamir_combine($shares)
    );
}


/* ============================================================
 * Share format
 * ============================================================ */

function shamir_construct_share(
    int $bits,
    int $id,
    string $data
): string {
    $max = (1 << $bits) - 1;

    if ($id < 1 || $id > $max) {
        throw new InvalidArgumentException(
            'Invalid share ID.'
        );
    }

    /*
     * Number of field bits encoded as ONE base36 character.
     *
     * 8 => "8"
     */
    $bitsBase36 = strtoupper(
        base_convert((string)$bits, 10, 36)
    );

    $idLength = strlen(dechex($max));

    $idHex = str_pad(
        dechex($id),
        $idLength,
        '0',
        STR_PAD_LEFT
    );

    return $bitsBase36 . $idHex . strtolower($data);
}


/**
 * Exact Ian Coleman / secrets.js share parser semantics.
 */
function shamir_extract_share_components(string $share): array
{
    $share = trim($share);

    if ($share === '') {
        throw new InvalidArgumentException('Invalid share.');
    }

    /*
     * First character is field size encoded base36.
     */
    $bits = intval(
        base_convert(substr($share, 0, 1), 36, 10)
    );

    if ($bits < 3 || $bits > 20) {
        throw new InvalidArgumentException(
            'Invalid share: number of bits must be between 3 and 20.'
        );
    }

    $max = (1 << $bits) - 1;

    /*
     * Same calculation as JS:
     *
     * (2^bits - 1).toString(16).length
     */
    $idLength = strlen(dechex($max));

    /*
     * Ian Coleman's regex:
     *
     * ^([a-kA-K3-9]{1})
     *   ([a-fA-F0-9]{idLen})
     *   ([a-fA-F0-9]+)$
     *
     * Notice: payload does NOT have to have an even number
     * of hex characters.
     */
    $regex =
        '/^([a-kA-K3-9])' .
        '([a-fA-F0-9]{' . $idLength . '})' .
        '([a-fA-F0-9]+)$/';

    if (!preg_match($regex, $share, $m)) {
        throw new InvalidArgumentException(
            'Invalid share: ' . $share
        );
    }

    $id = hexdec($m[2]);

    if ($id < 1 || $id > $max) {
        throw new InvalidArgumentException(
            'Invalid share ID.'
        );
    }

    return [
        'bits' => $bits,
        'id'   => $id,
        'data' => strtolower($m[3]),
    ];
}


/* ============================================================
 * secrets.js numeric splitting
 * ============================================================ */

/**
 * Equivalent to secrets.js splitNumStringToIntArray().
 *
 * Rightmost chunk FIRST.
 */
function shamir_split_num_string(
    string $binary,
    int $bits = 8
): array {
    $parts = [];

    for ($i = strlen($binary); $i > $bits; $i -= $bits) {
        $parts[] = bindec(
            substr($binary, $i - $bits, $bits)
        );
    }

    /*
     * Whatever remains on the left.
     */
    $remaining = strlen($binary) % $bits;

    if ($remaining === 0) {
        $remaining = $bits;
    }

    $parts[] = bindec(
        substr($binary, 0, $remaining)
    );

    return $parts;
}


/* ============================================================
 * Polynomial generation
 * ============================================================ */

function shamir_get_shares(
    int $secret,
    int $numShares,
    int $threshold
): array {
    $coeffs = [$secret];

    for ($i = 1; $i < $threshold; $i++) {
        /*
         * Ian Coleman's RNG refuses all-zero output.
         * Therefore coefficients are 1..255, not 0..255.
         */
        $coeffs[$i] = random_int(1, 255);
    }

    $shares = [];

    for ($x = 1; $x <= $numShares; $x++) {
        $shares[] = [
            'x' => $x,
            'y' => shamir_horner($x, $coeffs),
        ];
    }

    return $shares;
}


function shamir_horner(int $x, array $coeffs): int
{
    $fx = 0;

    for ($i = count($coeffs) - 1; $i >= 0; $i--) {

        if ($fx !== 0) {
            $fx =
                shamir_gf_mul($fx, $x)
                ^ $coeffs[$i];
        } else {
            $fx = $coeffs[$i];
        }
    }

    return $fx;
}


/* ============================================================
 * Lagrange interpolation
 * ============================================================ */

function shamir_lagrange(
    int $at,
    array $x,
    array $y
): int {
    $sum = 0;

    $len = count($x);

    for ($i = 0; $i < $len; $i++) {

        if ($y[$i] === 0) {
            continue;
        }

        $product = $y[$i];

        for ($j = 0; $j < $len; $j++) {

            if ($i === $j) {
                continue;
            }

            /*
             * At x=0 this becomes:
             *
             *   xj / (xi XOR xj)
             */
            $numerator = $at ^ $x[$j];

            if ($numerator === 0) {
                $product = 0;
                break;
            }

            $denominator = $x[$i] ^ $x[$j];

            if ($denominator === 0) {
                throw new RuntimeException(
                    'Duplicate share IDs.'
                );
            }

            $product = shamir_gf_mul(
                $product,
                shamir_gf_div(
                    $numerator,
                    $denominator
                )
            );
        }

        $sum ^= $product;
    }

    return $sum;
}


/* ============================================================
 * GF(256)
 *
 * Ian Coleman primitive polynomial for bits=8 is decimal 29
 * in its table, which corresponds to reduction polynomial
 * x^8 + x^4 + x^3 + x^2 + 1 = 0x11d.
 * ============================================================ */

function shamir_gf_mul(int $a, int $b): int
{
    $a &= 0xff;
    $b &= 0xff;

    $result = 0;

    while ($b > 0) {

        if ($b & 1) {
            $result ^= $a;
        }

        $a <<= 1;

        if ($a & 0x100) {
            $a ^= 0x11d;
        }

        $a &= 0xff;

        $b >>= 1;
    }

    return $result & 0xff;
}


function shamir_gf_pow(int $a, int $power): int
{
    $result = 1;

    while ($power > 0) {

        if ($power & 1) {
            $result = shamir_gf_mul(
                $result,
                $a
            );
        }

        $a = shamir_gf_mul($a, $a);

        $power >>= 1;
    }

    return $result;
}


function shamir_gf_inverse(int $a): int
{
    if ($a === 0) {
        throw new DivisionByZeroError(
            'Cannot invert zero in GF(256).'
        );
    }

    return shamir_gf_pow($a, 254);
}


function shamir_gf_div(int $a, int $b): int
{
    if ($b === 0) {
        throw new DivisionByZeroError(
            'Division by zero in GF(256).'
        );
    }

    if ($a === 0) {
        return 0;
    }

    return shamir_gf_mul(
        $a,
        shamir_gf_inverse($b)
    );
}


/* ============================================================
 * Binary / hex helpers
 * ============================================================ */

function shamir_hex2bin(string $hex): string
{
    $result = '';

    for ($i = 0; $i < strlen($hex); $i++) {

        $n = hexdec($hex[$i]);

        $result .= str_pad(
            decbin($n),
            4,
            '0',
            STR_PAD_LEFT
        );
    }

    return $result;
}


function shamir_bin2hex(string $binary): string
{
    if ($binary === '') {
        return '';
    }

    /*
     * secrets.js padLeft(str, 4)
     */
    $rem = strlen($binary) % 4;

    if ($rem !== 0) {
        $binary =
            str_repeat('0', 4 - $rem)
            . $binary;
    }

    $result = '';

    for ($i = 0; $i < strlen($binary); $i += 4) {
        $result .= dechex(
            bindec(substr($binary, $i, 4))
        );
    }

    return strtolower($result);
}


function shamir_pad_left_multiple(
    string $str,
    int $multiple
): string {
    if ($multiple <= 1) {
        return $str;
    }

    $missing = strlen($str) % $multiple;

    if ($missing !== 0) {
        return
            str_repeat('0', $multiple - $missing)
            . $str;
    }

    return $str;
}

