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
require_once 'PHPUnit/Framework/TestCase.php';

class Crypt_RSA_KeyTest extends PHPUnit_Framework_TestCase {

    /**
     * Load one or more drivers.
     */
    public static function drivers() {
        $drivers = array();
        if (extension_loaded('GMP')) {
            $drivers[] = array('GMP');
        }
        if (extension_loaded('big_int')) {
            $drivers[] = array('BigInt');
        }

        
        $drivers[] = array('BCMath');
        

        return $drivers;
    }

    /**
     * @dataProvider drivers
     */
    public function testCrypt_RSA_Key($driver) {
        $errors = array();
        ///////////////////////////////////////////////
        // test all functionality of Crypt_RSA_Key class
        ///////////////////////////////////////////////
        $rsa_obj = new Crypt_RSA(array(), $driver, 'check_error');
        $key_pair = new Crypt_RSA_KeyPair(32, $driver, 'check_error'); // extra small key pair (32-bit)

        $public_key = $key_pair->getPublicKey();
        $private_key = $key_pair->getPrivateKey();

        // check the length of public key
        if ($public_key->getKeyLength() != 32) {
            $errors[] = "wrong result returned from Crypt_RSA_Key::getKeyLength() function";
        }

        // construct copy of $public_key
        $public_key1 = new Crypt_RSA_Key($public_key->getModulus(), $public_key->getExponent(), $public_key->getKeyType(), $driver, 'check_error');

        // serialize $private_key
        $private_key_str = $private_key->toString();

        // try to use $public_key1 for encryption and unserialized form
        // $private_key_str key for decryption

        $text = '1234567890';
        $enc_text = $rsa_obj->encrypt($text, $public_key1);

        $private_key = Crypt_RSA_Key::fromString($private_key_str, $driver, 'check_error');
        $text1 = $rsa_obj->decrypt($enc_text, $private_key);

        if ($text != $text1) {
            $errors[] = "error in Crypt_RSA_Key class methods";
        }

        $this->assertTrue(empty($errors), print_r($errors, true));
    }

}








/**************************************/
if (!function_exists('check_error')) {
    function check_error(&$obj)
    {
        if ($obj->isError()) {
            $error = $obj->getLastError();
            echo "error: ", $error->getMessage(), "\n";
    //        var_dump($error->getBacktrace());

        }
    }
}

?>
