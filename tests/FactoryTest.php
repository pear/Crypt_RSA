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
 * this test script checks factory() methods functionality
 * for Crypt_RSA, Crypt_RSA_Key and Crypt_RSA_KeyPair classes
 */

require_once 'Crypt/RSA.php';
require_once 'PHPUnit/Framework/TestCase.php';

class Crypt_RSA_FactoryTest extends PHPUnit_Framework_TestCase {

    // try to create a Crypt_RSA object using factory() static call
    public function testShouldMakeAnObject() {
        $obj = Crypt_RSA::factory();

        $this->assertFalse(PEAR::isError($obj), 'error in Crypt_RSA factory()');
    }

    public function testShouldCreateAKeyPair() {
        $obj = Crypt_RSA_KeyPair::factory(128);

        $this->assertFalse(PEAR::isError($obj), 'error in Crypt_RSA_KeyPair factory(): ');
    }

    public function testShouldMakeAKey() {
        $obj = Crypt_RSA_KeyPair::factory(128);
        $key = $obj->getPrivateKey();

        // try to create a Crypt_RSA_Key object using factory() static call
        $obj = Crypt_RSA_Key::factory($key->getModulus(), $key->getExponent(), $key->getKeyType());

        $this->assertFalse(PEAR::isError($obj), 'error in Crypt_RSA_Key factory(): ');
    }

}

