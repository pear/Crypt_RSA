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

class Crypt_RSA_DriverTest extends PHPUnit_Framework_TestCase {

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
    public function testCrypt_RSA($driver) {
        $errors = array();
        ///////////////////////////////////////////////
        // test all functionality of Crypt_RSA class
        ///////////////////////////////////////////////
        // create Crypt_RSA object
        $rsa_obj = new Crypt_RSA(array(), $driver, 'check_error');

        // create Crypt_RSA_KeyPair object
        $key_pair = new Crypt_RSA_KeyPair(256, $driver, 'check_error');

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
