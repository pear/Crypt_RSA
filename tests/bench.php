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
 * This script tries to generate 4096-bit keys by using different math wrappers
 */

require_once 'Crypt/RSA.php';

define('KEY_LENGTH', 2048);

echo "key length: " . KEY_LENGTH . " bit\n";
go('GMP');
go('BigInt');
go('BCMath');


function getmicrotime() 
{
   list($usec, $sec) = explode(" ", microtime());
   return ((float)$usec + (float)$sec);
}

function go($math_wrapper)
{
    echo "Test $math_wrapper: ";
    mt_srand(1);
    $start = getmicrotime();
    $keypair = &Crypt_RSA_KeyPair::factory(KEY_LENGTH, $math_wrapper, '', 'mt_rand');
    if (PEAR::isError($obj)) {
        echo 'failed: ', $obj->getMessage(), "\n";
        return;
    }
    $time = getmicrotime() - $start;
    printf("done. Time: %.3f seconds\n", $time);
}

?>