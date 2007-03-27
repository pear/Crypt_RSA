<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Crypt_RSA allows to do following operations:
 *     - key pair generation
 *     - encryption and decryption
 *     - signing and sign validation
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
 * RSA error handling facilities
 */
require_once 'Crypt/RSA/ErrorHandler.php';

/**
 * loader for RSA math wrappers
 */
require_once 'Crypt/RSA/MathLoader.php';

/**
 * helper class for single key managing
 */
require_once 'Crypt/RSA/Key.php';

/**
 * Crypt_RSA_KeyPair class, derived from Crypt_RSA_ErrorHandler
 *
 * Provides the following functions:
 *  - generate($key) - generates new key pair
 *  - getPublicKey() - returns public key
 *  - getPrivateKey() - returns private key
 *  - getKeyLength() - returns bit key length
 *  - setRandomGenerator($func_name) - sets random generator to $func_name
 *
 * Example usage:
 *    // create new 1024-bit key pair
 *    $key_pair = new Crypt_RSA_KeyPair(1024);
 *
 *    // error check
 *    if ($key_pair->isError()) {
 *        echo "error while initializing Crypt_RSA_KeyPair object:\n";
 *        $erorr = $key_pair->getLastError();
 *        echo $error->getMessage(), "\n";
 *    }
 *
 *    // get public key
 *    $public_key = $key_pair->getPublicKey();
 * 
 *    // get private key
 *    $private_key = $key_pair->getPrivateKey();
 * 
 *    // generate new 512-bit key pair
 *    $key_pair->generate(512);
 *
 *    // error check
 *    if ($key_pair->isError()) {
 *        echo "error while generating key pair:\n";
 *        $erorr = $key_pair->getLastError();
 *        echo $error->getMessage(), "\n";
 *    }
 *
 *    // get key pair length
 *    $length = $key_pair->getKeyLength();
 *
 *    // set random generator to $func_name, where $func_name
 *    // consists name of random generator function. See comments
 *    // befor setRandomGenerator() method for details
 *    $key_pair->setRandomGenerator($func_name);
 *
 *    // error check
 *    if ($key_pair->isError()) {
 *        echo "error while changing random generator:\n";
 *        $erorr = $key_pair->getLastError();
 *        echo $error->getMessage(), "\n";
 *    }
 *
 *    // using factory() method instead of constructor (it returns PEAR_Error object on failure)
 *    $rsa_obj = &Crypt_RSA_KeyPair::factory($key_len);
 *    if (PEAR::isError($rsa_obj)) {
 *        echo "error: ", $rsa_obj->getMessage(), "\n";
 *    }
 *
 * @category   Encryption
 * @package    Crypt_RSA
 * @author     Alexander Valyalkin <valyala@gmail.com>
 * @copyright  2005 Alexander Valyalkin
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @link       http://pear.php.net/package/Crypt_RSA
 * @version    @package_version@
 * @access     public
 */
class Crypt_RSA_KeyPair extends Crypt_RSA_ErrorHandler
{
    /**
     * Reference to math wrapper object, which is used to
     * manipulate large integers in RSA algorithm.
     *
     * @var object of Crypt_RSA_Math_* class
     * @access private
     */
    var $_math_obj;

    /**
     * length of each key in the key pair
     *
     * @var int
     * @access private
     */
    var $_key_len;

    /**
     * public key
     *
     * @var object of Crypt_RSA_KEY class
     * @access private
     */
    var $_public_key;

    /**
     * private key
     *
     * @var object of Crypt_RSA_KEY class
     * @access private
     */
    var $_private_key;

    /**
     * name of function, which is used as random generator
     *
     * @var string
     * @access private
     */
    var $_random_generator;

    /**
     * Crypt_RSA_KeyPair constructor.
     *
     * @param int $key_len bit length of key pair, which will be generated in constructor
     * @param string $wrapper_name
     *        Name of math wrapper, which will be used to
     *        perform different operations with big integers.
     *        See contents of Crypt/RSA/Math folder for examples of wrappers.
     *        Read docs/Crypt_RSA/docs/math_wrappers.txt for details.
     *
     * @param string $error_handler   name of error handler function
     *
     * @access public
     */
    function Crypt_RSA_KeyPair($key_len, $wrapper_name = 'default', $error_handler = '')
    {
        // set error handler
        $this->setErrorHandler($error_handler);
        // try to load math wrapper
        $obj = &Crypt_RSA_MathLoader::loadWrapper($wrapper_name);
        if (PEAR::isError($obj)) {
            // error during loading of math wrapper
            $this->pushError($obj);
            return;
        }
        $this->_math_obj = &$obj;

        // set default random generator
        if (!$this->setRandomGenerator()) {
            // error in setRandomGenerator() function
            return;
        }

        // generate key pair
        if (!$this->generate($key_len)) {
            // error during generating key pair
            return;
        }
    }

    /**
     * Crypt_RSA_KeyPair factory.
     *
     * @param int $key_len bit length of key pair, which will be generated in constructor
     * @param string $wrapper_name
     *        Name of math wrapper, which will be used to
     *        perform different operations with big integers.
     *        See contents of Crypt/RSA/Math folder for examples of wrappers.
     *        Read docs/Crypt_RSA/docs/math_wrappers.txt for details.
     *
     * @return object   new Crypt_RSA_KeyPair object on success or PEAR_Error object on failure
     * @access public
     */
    function &factory($key_len, $wrapper_name = 'default')
    {
        $obj = &new Crypt_RSA_KeyPair($key_len, $wrapper_name);
        if ($obj->isError()) {
            // error during creating a new object. Retrurn PEAR_Error object
            return $obj->getLastError();
        }
        // object created successfully. Return it
        return $obj;
    }

    /**
     * Generates new Crypt_RSA key pair with length $key_len.
     * If $key_len is missed, use an old key length from $this->_key_len
     *
     * @param int $key_len  bit length of key pair, which will be generated
     * @return bool         true on success or false on error
     * @access public
     */
    function generate($key_len = null)
    {
        if (is_null($key_len)) {
            // use an old key length
            $key_len = $this->_key_len;
            if (is_null($key_len)) {
                $obj = PEAR::raiseError('missing key_len parameter', CRYPT_RSA_ERROR_MISSING_KEY_LEN);
                $this->pushError($obj);
                return false;
            }
        }
        // align $key_len to 8 bits
        if ($key_len & 7) {
            $key_len += 8 - ($key_len % 8);
        }
        // store key length in the _key_len property
        $this->_key_len = $key_len;

        // generate two primes p and q
        $p_len = (int) ($key_len / 2) + 1;
        $q_len = $key_len - $p_len;
        $p = $this->_math_obj->getRand($p_len, $this->_random_generator, true);
        $p = $this->_math_obj->nextPrime($p);
        do {
            do {
                $q = $this->_math_obj->getRand($q_len, $this->_random_generator, true);
                $tmp_len = $this->_math_obj->bitLen($this->_math_obj->mul($p, $q));
                if ($tmp_len < $key_len) $q_len++;
                elseif ($tmp_len > $key_len) $q_len--;
            } while ($tmp_len != $key_len);
            $q = $this->_math_obj->nextPrime($q);
            $tmp = $this->_math_obj->mul($p, $q);
        } while ($this->_math_obj->bitLen($tmp) != $key_len);
        // $n - is shared modulus
        $n = $this->_math_obj->mul($p, $q);
        // generate public ($e) and private ($d) keys
        $pq = $this->_math_obj->mul($this->_math_obj->dec($p), $this->_math_obj->dec($q));
        do {
            $e = $this->_math_obj->getRand($q_len, $this->_random_generator);
            if ($this->_math_obj->isZero($e) || $this->_math_obj->isZero($this->_math_obj->dec($e))) {
                // exponent cannot be equal to 0 or 1
                continue;
            }
            if ($this->_math_obj->isZero($this->_math_obj->dec($this->_math_obj->gcd($e, $pq)))) {
                // exponent is found
                break;
            }
        } while (true);
        $d = $this->_math_obj->invmod($e, $pq);

        $modulus = $this->_math_obj->int2bin($n);
        $public_exp = $this->_math_obj->int2bin($e);
        $private_exp = $this->_math_obj->int2bin($d);

        // try to create public key object
        $obj = &new Crypt_RSA_Key(
            $modulus,
            $public_exp,
            'public',
            $this->_math_obj->getWrapperName(),
            $this->_error_handler
        );
        if ($obj->isError()) {
            // error during creating public object
            $this->pushError($obj->getLastError());
            return false;
        }
        $this->_public_key = &$obj;

        // try to create private key object
        $obj = &new Crypt_RSA_Key(
            $modulus,
            $private_exp,
            'private',
            $this->_math_obj->getWrapperName(),
            $this->_error_handler
        );
        if ($obj->isError()) {
            // error during creating private key object
            $this->pushError($obj->getLastError());
            return false;
        }
        $this->_private_key = &$obj;

        return true; // key pair successfully generated
    }

    /**
     * Returns public key from the pair
     *
     * @return object  public key object of class Crypt_RSA_Key
     * @access public
     */
    function getPublicKey()
    {
        return $this->_public_key;
    }

    /**
     * Returns private key from the pair
     *
     * @return object   private key object of class Crypt_RSA_Key
     * @access public
     */
    function getPrivateKey()
    {
        return $this->_private_key;
    }

    /**
     * Sets name of random generator function for key generation.
     * If parameter is skipped, then sets to default random generator.
     *
     * Random generator function must return integer with at least 8 lower
     * significant bits, which will be used as random values.
     *
     * @param string $random_generator  name of random generator function
     * @return bool                     true on success or false on error
     * @access public
     */
    function setRandomGenerator($random_generator = null)
    {
        static $default_random_generator = null;

        if (is_string($random_generator)) {
            // set user's random generator
            if (!function_exists($random_generator)) {
                $obj = PEAR::raiseError("can't find random generator function with name [{$random_generator}]");
                $this->pushError($obj);
                return false;
            }
            $this->_random_generator = $random_generator;
        } else {
            // set default random generator
            $this->_random_generator = is_null($default_random_generator) ?
                ($default_random_generator = create_function('', '$a=explode(" ",microtime());return(int)($a[0]*1000000);')) :
                $default_random_generator;
        }
        return true;
    }

    /**
     * Returns length of each key in the key pair
     *
     * @return int  bit length of each key in key pair
     * @access public
     */
    function getKeyLength()
    {
        return $this->_key_len;
    }
}

?>