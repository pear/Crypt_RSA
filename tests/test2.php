<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

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
 * @copyright  2005 Alexander Valyalkin
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @version    1.0.0
 * @link       http://pear.php.net/package/Crypt_RSA
 */

/**
 * this test script checks factory() methods functionality
 * for Crypt_RSA, Crypt_RSA_Key and Crypt_RSA_KeyPair classes
 */

require_once 'Crypt/RSA.php';

echo "Start of testing factory() methods...\n";

// try to create a Crypt_RSA object using factory() static call
$obj = &Crypt_RSA::factory();
if (PEAR::isError($obj)) {
    echo 'error in Crypt_RSA factory(): ', $obj->getMessage(), "\n";
}

// try to create a Crypt_RSA_KeyPair object using factory() static call
$obj = &Crypt_RSA_KeyPair::factory(128);
if (PEAR::isError($obj)) {
    echo 'error in Crypt_RSA_KeyPair factory(): ', $obj->getMessage(), "\n";
}
$key = $obj->getPrivateKey();

// try to create a Crypt_RSA_Key object using factory() static call
$obj = &Crypt_RSA_Key::factory($key->getModulus(), $key->getExponent(), $key->getKeyType());
if (PEAR::isError($obj)) {
    echo 'error in Crypt_RSA_KeyPair factory(): ', $obj->getMessage(), "\n";
}

echo "end\n";

?>