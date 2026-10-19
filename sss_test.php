<?php
/*
* This is a test script for the shamir secret sharing implementation in PHP.
* It demonstrates how to split a secret into shares and then combine them back to recover the original secret.
* The shares can also be used with Ian Coleman's Shamir tool: https://iancoleman.io/shamir/
*
* Note: This script requires the 'lib_sss.php' file which contains the implementation of the Shamir's Secret Sharing algorithm.
*
* Version: 1.0, 14.10.2026
* Copyright (c) 2026 c.baumann@baumann.at
* License: MIT
*/

require_once 'lib_sss.php';

/*
Test 1: Input from Ian Coleman's Shamir tool https://iancoleman.io/shamir/
*/

$shares = [
    '8018e37f2838aaf3ee99d47dcee81f7b47b7dbf23331c625c8ac739e4ef68dbefd0640c33e5fbbaeccc19885402af519b11a64422a9e395582962fc74a853601d3a9e077935077bcf258ad64b624a13c8c37135d32d3930189aa846b9585c88b929561c7a5cccf7a1216d6dcdb2120c52da9d9c73b7f41dfda0acacfce1ebebf1ed',
    '8023be4f8fc88764fe5db6b9bb28682b54a4e0169257b05f7eff88a64feed365735191374ecb8ab62cac73776a0213c6054484bf3a742d694dff874b441c0f8b7c8160017098b8c5cf3cb5b71701001f98a77910d90b2bf18c404dec384f081a0987fc221199ed583412172981d5b78fa9298f45f5d1919089d2039b2c2a5177d79',
    '803b5d30a7f02d9710c462c475c0775013133be4a166767ab653fb2803f8580b8807d6b477a43688e75de9f22c58e03fb2cee64d160a136cc9e9aebc0c993fdaa9a88736e1c8c9193b941ad3a665a61312c06d0de9d8bee007eaceb7ab5ac2919c229b75b2d527622404c3e55cb4918a83a05072cbded24f5528cf94e4f4e998cdc',
];

$secret = shamir_combine_text($shares);

echo $secret;
echo "\n------------------------------------------\n";


// If instead you are using secrets.js directly with a hexadecimal secret:
$hex = shamir_combine($shares);
echo $hex;
echo "\n------------------------------------------\n";


/*
Test 2: 
* Calculate the shares from a given input (secret text)
* Then combine the shares to recover the original text
* The shares can also be combined with Ian Coleman's Shamir tool https://iancoleman.io/shamir/
*/

$secretText = 'my very secret text abc def ghi 1234567890 ';
$longSecretText = str_repeat($secretText, 10) . 'TheEnd'; 

$shares = shamir_split_text(
    $longSecretText,
    5, // total shares
    3  // threshold
);

print_r($shares);
echo "\n------------------------------------------\n";

$secret = shamir_combine_text([
    $shares[0],
    $shares[2],
    $shares[4],
]);

echo $secret;
echo "\n------------------------------------------\n";

echo("copy/paste three arbitrary shares of the following shares into Ian Coleman's tool to combine:\n");
foreach ($shares as $share) {
    echo $share . "\n\n";
}
echo "\n------------------------------------------\n";
