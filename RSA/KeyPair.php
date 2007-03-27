<?php
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
 * @copyright  2005, 2006 Alexander Valyalkin
 * @license    http://www.php.net/license/3_0.txt  PHP License 3.0
 * @version    1.1.0
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
 *  - fromPEMString($str) - retrieves key pair from PEM-encoded string
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
 *    // read key pair from PEM-encoded string:
 *    $str = "-----BEGIN RSA PRIVATE KEY-----"
 *         . "MCsCAQACBHr5LDkCAwEAAQIEBc6jbQIDAOCfAgMAjCcCAk3pAgJMawIDAL41"
 *         . "-----END RSA PRIVATE KEY-----";
 *    $keypair = Crypt_RSA_KeyPair::fromPEMString($str);
 *
 *    // read key pair from .pem file 'private.pem':
 *    $str = file_get_contents('private.pem');
 *    $keypair = Crypt_RSA_KeyPair::fromPEMString($str);
 *
 * @category   Encryption
 * @package    Crypt_RSA
 * @author     Alexander Valyalkin <valyala@gmail.com>
 * @copyright  2005, 2006 Alexander Valyalkin
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
     * Parse ASN.1 string [$str] starting form position [$pos].
     * Returns tag and string value of parsed object.
     *
     * @param string $str
     * @param int $pos
     * @param object $err_handler
     *
     * @return mixed    Array('tag' => ..., 'str' => ...) on success, PEAR_Error object on error
     * @access private
     */
    function _ASN1Parse($str, &$pos, $err_handler)
    {
        $max_pos = strlen($str);
        if ($max_pos < 2) {
            $err = PEAR::raiseError("ASN.1 string too short");
            $err_handler->pushError($err);
            return $err;
        }

        // get ASN.1 tag value
        $tag = ord($str[$pos++]) & 0x1f;
        if ($tag == 0x1f) {
            $tag = 0;
            do {
                $n = ord($str[$pos++]);
                $tag <<= 7;
                $tag |= $n & 0x7f;
            } while (($n & 0x80) && $pos < $max_pos);
        }
        if ($pos >= $max_pos) {
            $err = PEAR::raiseError("ASN.1 string too short");
            $err_handler->pushError($err);
            return $err;
        }

        // get ASN.1 object length
        $len = ord($str[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $max_pos) {
                $len <<= 8;
                $len |= ord($in[$pos++]);
            }
        }
        if ($pos >= $max_pos || $len > $max_pos - $pos) {
            $err = PEAR::raiseError("ASN.1 string too short");
            $err_handler->pushError($err);
            return $err;
        }

        // get string value of ASN.1 object
        $str = substr($str, $pos, $len);

        return array(
            'tag' => $tag,
            'str' => $str,
        );
    }

    /**
     * Parse ASN.1 sting [$str] starting from position [$pos].
     * Returns string representation of number, which can be passed
     * in bin2int() function of math wrapper.
     *
     * @param string $str
     * @param int $pos
     * @param object $err_handler
     *
     * @return mixed   string representation of parsed number on success, PEAR_Error object on error
     * @access private
     */
    function _ASN1ParseInt($str, &$pos, $err_handler)
    {
        $tmp = Crypt_RSA_KeyPair::_ASN1Parse($str, $pos, $err_handler);
        if (PEAR::isError($tmp)) {
            return $tmp;
        }
        if ($tmp['tag'] != 0x02) {
            $errstr = sprintf("wrong ASN tag value: 0x%02x. Expected 0x02 (INTEGER)", $tmp['tag']);
            $err = PEAR::raiseError($errstr);
            $err_handler->pushError($err);
            return $err;
        }
        $pos += strlen($tmp['str']);

        return strrev($tmp['str']);
    }

    /**
     * Crypt_RSA_KeyPair constructor.
     *
     * @param int $key_len bit length of key pair, which will be generated in constructor
     * @param string $wrapper_name
     *        Name of math wrapper, which will be used to
     *        perform different operations with big integers.
     *        See contents of Crypt/RSA/Math folder for examples of wrappers.
     *        Read docs/Crypt_RSA/docs/math_wrappers.txt for details.
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

        if (is_array($key_len)) {
            // ugly BC hack - it is possible to pass array of [n, e, d] instead of key length
            list($n, $e, $d) = $key_len;

            // check 2^(e*d) = 2 (mod n)
            $a_int = $this->_math_obj->bin2int("\x02");
            $n_int = $this->_math_obj->bin2int($n);
            $e_int = $this->_math_obj->bin2int($e);
            $d_int = $this->_math_obj->bin2int($d);
            $b_int = $this->_math_obj->powMod($a_int, $e_int, $n_int);
            $b_int = $this->_math_obj->powMod($b_int, $d_int, $n_int);
            if ($this->_math_obj->cmpAbs($a_int, $b_int)) {
                $this->pushError(PEAR::raiseError("Incorrect [n, e, d] numbers"));
                return;
            }

            // try to create public key object
            $public_key = &new Crypt_RSA_Key($n, $e, 'public');
            if ($public_key->isError()) {
                // error during creating public object
                $this->pushError($public_key->getLastError());
                return;
            }

            // try to create private key object
            $private_key = &new Crypt_RSA_Key($n, $d, 'private');
            if ($private_key->isError()) {
                // error during creating private key object
                $this->pushError($private_key->getLastError());
                return;
            }

            $this->_public_key = $public_key;
            $this->_private_key = $private_key;
            $this->_key_len = $public_key->getKeyLength();
        }
        else {
            // generate key pair
            if (!$this->generate($key_len)) {
                // error during generating key pair
                return;
            }
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
     * @param string $error_handler   name of error handler function
     *
     * @return object   new Crypt_RSA_KeyPair object on success or PEAR_Error object on failure
     * @access public
     */
    function &factory($key_len, $wrapper_name = 'default', $error_handler = '')
    {
        $obj = &new Crypt_RSA_KeyPair($key_len, $wrapper_name, $error_handler);
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

        // set [e] to 0x10001 (65537)
        $e = $this->_math_obj->bin2int("\x01\x00\x01");

        // generate [p], [q] and [n]
        $p_len = intval(($key_len + 1) / 2);
        $q_len = $key_len - $p_len;
        $p1 = $q1 = 0;
        do {
            // generate prime number [$p] with length [$p_len] with the following condition:
            // GCD($e, $p - 1) = 1
            do {
                $p = $this->_math_obj->getPrime($p_len, $this->_random_generator);
                $p1 = $this->_math_obj->dec($p);
                $tmp = $this->_math_obj->GCD($e, $p1);
            } while (!$this->_math_obj->isOne($tmp));
            // generate prime number [$q] with length [$q_len] with the following conditions:
            // GCD($e, $q - 1) = 1
            // $q != $p
            do {
                $q = $this->_math_obj->getPrime($q_len, $this->_random_generator);
                $q1 = $this->_math_obj->dec($q);
                $tmp = $this->_math_obj->GCD($e, $q1);
            } while (!$this->_math_obj->isOne($tmp) && !$this->_math_obj->cmpAbs($q, $p));
            // if (p < q), then exchange them
            if ($this->_math_obj->cmpAbs($p, $q) < 0) {
                $tmp = $p;
                $p = $q;
                $q = $tmp;
            }
            // calculate n = p * q
            $n = $this->_math_obj->mul($p, $q);
        } while ($this->_math_obj->bitLen($n) != $key_len);

        // calculate d = 1/e mod (p - 1) * (q - 1)
        $pq = $this->_math_obj->mul($p1, $q1);
        $d = $this->_math_obj->invmod($e, $pq);

        // convert [n], [e] and [d] into binary representation
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

    /**
     * Retrieve RSA keypair from PEM-encoded string, containing RSA private key.
     * Example of such string:
     * -----BEGIN RSA PRIVATE KEY-----
     * MCsCAQACBHtvbSECAwEAAQIEeYrk3QIDAOF3AgMAjCcCAmdnAgJMawIDALEk
     * -----END RSA PRIVATE KEY-----
     *
     * @param string $str PEM-encoded string
     * @param string $wrapper_name
     *        Name of math wrapper, which will be used to
     *        perform different operations with big integers.
     *        See contents of Crypt/RSA/Math folder for examples of wrappers.
     *        Read docs/Crypt_RSA/docs/math_wrappers.txt for details.
     * @param string $error_handler   name of error handler function
     *
     * @return Crypt_RSA_KeyPair object on success, PEAR_Error object on error
     * @access public
     */
    function &fromPEMString($str, $wrapper_name = 'default', $error_handler = '')
    {
        // search for base64-encoded private key
        $err_handler = &new Crypt_RSA_ErrorHandler;
        $err_handler->setErrorHandler($error_handler);

        if (!preg_match('/-----BEGIN RSA PRIVATE KEY-----[\\r\\n]+([^-]+)-----END RSA PRIVATE KEY-----/', $str, $matches)) {
            $err = PEAR::raiseError("can't find RSA private key in the string [{$str}]");
            $err_handler->pushError($err);
            return $err;
        }

        // parse private key. It is ASN.1-encoded
        $str = base64_decode($matches[1]);
        $pos = 0;
        $tmp = Crypt_RSA_KeyPair::_ASN1Parse($str, $pos, $err_handler);
        if (PEAR::isError($tmp)) {
            return $tmp;
        }
        if ($tmp['tag'] != 0x10) {
            $errstr = sprintf("wrong ASN tag value: 0x%02x. Expected 0x10 (SEQUENCE)", $tmp['tag']);
            $err = PEAR::raiseError($errstr);
            $err_handler->pushError($err);
            return $err;
        }

        // skip [version] field
        $tmp = Crypt_RSA_KeyPair::_ASN1ParseInt($str, $pos, $err_handler);
        if (PEAR::isError($tmp)) {
            return $tmp;
        }

        // get [n]
        $n = Crypt_RSA_KeyPair::_ASN1ParseInt($str, $pos, $err_handler);
        if (PEAR::isError($n)) {
            return $n;
        }

        // get [e]
        $e = Crypt_RSA_KeyPair::_ASN1ParseInt($str, $pos, $err_handler);
        if (PEAR::isError($e)) {
            return $e;
        }

        // get [d]
        $d = Crypt_RSA_KeyPair::_ASN1ParseInt($str, $pos, $err_handler);
        if (PEAR::isError($d)) {
            return $d;
        }

        // create Crypt_RSA_KeyPair object.
        $obj = &new Crypt_RSA_KeyPair(array($n, $e, $d), $wrapper_name, $error_handler);
        if ($obj->isError()) {
            return $obj->getLastError();
        }

        return $obj;
    }
}

?>