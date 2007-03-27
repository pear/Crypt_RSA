<?php
/**
 * Crypt_RSA allows to do following operations:
 *     - key pair generation
 *     - encryption and decryption
 *     - signing and sign validation
 *
 * This module requires the PHP BCMath extension.
 * See http://us2.php.net/manual/en/ref.bc.php for details.
 *
 * PHP versions 4 and 5
 *
 * LICENSE: This source file is subject to version 3.0 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_0.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 *
 * @category   Encryption
 * @package    Crypt_RSA
 * @author     Alexander Valyalkin <valyala@gmail.com>
 * @copyright  2005, 2006 Alexander Valyalkin
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @version    1.2.0b
 * @link       http://pear.php.net/package/Crypt_RSA
 */

/**
 * this is a test script, which checks functionality of
 * Crypt_RSA package with different math wrappers. It
 * checks such things as:
 *  - key generation,
 *  - encryption / decryption
 *  - signing / sign validation
 */

require_once 'Crypt/RSA.php';

/*
    uncomment one of the following lines to define math library,
    which will be used by Crypt_RSA.
    BCMath and BigInt are implemented now.
    It is easy to implement support of other math libraries.
    See contents of /RSA/MathClasses folder for examples.
    BigInt is much faster than BCMath.
*/
//define('MATH_LIBRARY', 'GMP');
//define('MATH_LIBRARY', 'BigInt');
//define('MATH_LIBRARY', 'BCMath');

$errors = array();

echo "Start of testing Crypt_RSA package with [", MATH_LIBRARY, "] math library...\n";

///////////////////////////////////////////////
// test all functionality of Crypt_RSA_KeyPair class
///////////////////////////////////////////////
$key_pair = new Crypt_RSA_KeyPair(128, MATH_LIBRARY, 'check_error');

$public_key = $key_pair->getPublicKey();
$private_key = $key_pair->getPrivateKey();
$key_length = $key_pair->getKeyLength();

if ($key_length != 128) {
    $errors[] = "wrong result returned from Crypt_RSA_KeyPair::getKeyLength() function";
}

// check fromPEMString() and toPEMString() functions of Crypt_RSA_KeyPair class
$str_in = "
-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAKSLT0KZTXYxHr6U/9GYBbnV8vxGkIleDE4aiVMRxuofOjcHDCoI
qsrVjgP78BrVqWMAAeQ9i0dXxz9zhy0+h7MCAwEAAQJBAI6OL1Yo0Uaj2doN5vDk
f5l4dfMBA7ovZAPK08zHawlsLvZTzxOQJhKquN01aIJA2wpzixcC9T2PgI6XW6jx
HkECIQDOEVpVZcE2tSnU3TwulVAC8V82akNAEH8ht6eqsEVWkwIhAMxqMc4Av7hs
ioAs1H9NvkF01xYVhyiEc4rzgVlmjp5hAiEAi53AOYnmvd1CyWFXrCwn+MZ2/xRC
Gj7TFBItvH0PjZcCIBi9kaGZPZsYp/qzclSmGCzb81xc5qrkvQdISZOEciaBAiEA
vLq0MTN4jkO2DOC4qxvKc1l4383nks1g/cljSO/y0pw=
-----END RSA PRIVATE KEY-----
";

$key_pair = Crypt_RSA_KeyPair::fromPEMString($str_in, MATH_LIBRARY, 'check_error');

$public_key = $key_pair->getPublicKey();
$private_key = $key_pair->getPrivateKey();
$key_length = $key_pair->getKeyLength();

if ($key_length != 512) {
    $errors[] = "incorrect key length retrieved from PEM string";
}

$rsa_obj = new Crypt_RSA(array(), MATH_LIBRARY, 'check_error');

$text = 'test text';
$enc_text = $rsa_obj->encrypt($text, $public_key);
$dec_text = $rsa_obj->decrypt($enc_text, $private_key);

if ($dec_text != $text) {
    $errors[] = "decrypted text differs from encrypted text in Crypt_RSA_KeyPair::fromPEMString() check";
}

$str_out = $key_pair->toPEMString();

$str_in = str_replace($str_in, array("\r", "\n"), '');
$str_out = str_replace($str_out, array("\r", "\n"), '');
if ($str_in != $str_out) {
    $errors[] = "PEM strings handling seems to be broken";
}

// try to generate 256-bit keypair and convert it to PEM string,
// then convert this string to another keypair and compare them
$key_pair->generate(256);

$str1 = $key_pair->toPEMString();
$key_pair2 = $key_pair->fromPEMString($str1);
if (!$key_pair->isEqual($key_pair2) || !$key_pair2->isEqual($key_pair)) {
    $errors[] = "RSA_KeyPair::isEqual() is broken";
}

///////////////////////////////////////////////
// test all functionality of Crypt_RSA_Key class
///////////////////////////////////////////////
$rsa_obj = new Crypt_RSA(array(), MATH_LIBRARY, 'check_error');
$key_pair = new Crypt_RSA_KeyPair(32, MATH_LIBRARY, 'check_error'); // extra small key pair (32-bit)

$public_key = $key_pair->getPublicKey();
$private_key = $key_pair->getPrivateKey();

// check the length of public key
if ($public_key->getKeyLength() != 32) {
    $errors[] = "wrong result returned from Crypt_RSA_Key::getKeyLength() function";
}

// construct copy of $public_key
$public_key1 = new Crypt_RSA_Key($public_key->getModulus(), $public_key->getExponent(), $public_key->getKeyType(), MATH_LIBRARY, 'check_error');

// serialize $private_key
$private_key_str = $private_key->toString();

// try to use $public_key1 for encryption and unserialized form
// $private_key_str key for decryption

$text = '1234567890';
$enc_text = $rsa_obj->encrypt($text, $public_key1);

$private_key = Crypt_RSA_Key::fromString($private_key_str, MATH_LIBRARY, 'check_error');
$text1 = $rsa_obj->decrypt($enc_text, $private_key);

if ($text != $text1) {
    $errors[] = "error in Crypt_RSA_Key class methods";
}

///////////////////////////////////////////////
// test all functionality of Crypt_RSA class
///////////////////////////////////////////////
// create Crypt_RSA object
$rsa_obj = new Crypt_RSA(array(), MATH_LIBRARY, 'check_error');

// create Crypt_RSA_KeyPair object
$key_pair = new Crypt_RSA_KeyPair(256, MATH_LIBRARY, 'check_error');

// check encrypting/decrypting function's behaviour
$params = array(
    'enc_key' => $key_pair->getPublicKey(),
    'dec_key' => $key_pair->getPrivateKey(),
);
$rsa_obj->setParams($params);

$text = '1234567890';
$enc_text = $rsa_obj->encrypt($text);
$text1 = $rsa_obj->decrypt($enc_text);

if ($text != $text1) {
    $errors[] = "error in encrypting/decrypting functions";
}

// check signing/sign validating
$params = array(
    'public_key' => $key_pair->getPublicKey(),
    'private_key' => $key_pair->getPrivateKey(),
);
$rsa_obj->setParams($params);

$text = '1234567890';
$sign = $rsa_obj->createSign($text);

if (!$rsa_obj->validateSign($text, $sign)) {
    $errors[] = "error in signing/sign validating functions with default hash function";
}

// check signing/sign validating with specific hash function
$params = array(
    'hash_func' => create_function('$text', 'return 0x1234;'), // silly hash function :)
);
$rsa_obj->setParams($params);
$text = '1234567890';
$sign = $rsa_obj->createSign($text);
if (!$rsa_obj->validateSign($text, $sign)) {
    $errors[] = "error in signing/sign validating functions with user specific hash function";
}

///////////////////////////////////////////////
// generate key with user-defined random generator.
///////////////////////////////////////////////
// use mt_rand function ( http://php.net/mt_rand ) as random generator
$key_pair->setRandomGenerator('mt_rand');
$key_pair->generate();

// try to encrypt/decrypt data with new keys
$params = array(
    'enc_key' => $key_pair->getPublicKey(),
    'dec_key' => $key_pair->getPrivateKey(),
);
$rsa_obj->setParams($params);

$text = '1234567890';
$enc_text = $rsa_obj->encrypt($text);
$text1 = $rsa_obj->decrypt($enc_text);
if ($text != $text1) {
    $errors[] = "error in encrypting/decrypting functions";
}

echo "end\n";

$errors_cnt = sizeof($errors);
echo "\nTotal number of errors: {$errors_cnt}\n";
if ($errors_cnt) {
    foreach ($errors as $key => $value) {
        echo "    {$value}\n";
    }
}
exit;

/**************************************/
function check_error(&$obj)
{
    if ($obj->isError()) {
        $error = $obj->getLastError();
        echo "error: ", $error->getMessage(), "\n";
//        var_dump($error->getBacktrace());
        exit;
    }
}

?>