<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * Crypt_RSA allows to do following operations:
 *     - key pair generation
 *     - encryption and decryption
 *     - signing and sign validation
 *
 * This module requires the big_int PECL package, which is available at
 *     http://pecl.php.net/packages/big_int
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
 * this is a sample script, which shows the usage of Crypt_RSA package
 */

require_once 'Crypt/RSA.php';


$task = isset($_GET['task']) ? $_GET['task'] : '';

session_start();
switch ($task) {
case 'generate_key_pair' : generate_key_pair(); break;
case 'create_sign' : create_sign(); break;
case 'validate_sign' : validate_sign(); break;
case 'encrypt' : encrypt(); break;
case 'decrypt' : decrypt(); break;
}

print_layout();

exit;

/***********************************************************/
function generate_key_pair()
{
    $key_length = $_POST['key_length'];

    $key_pair = new Crypt_RSA_KeyPair($key_length);
    check_error($key_pair);

    $public_key = $key_pair->getPublicKey();
    $private_key = $key_pair->getPrivateKey();
    $_SESSION['public_key'] = $public_key->toString();
    $_SESSION['private_key'] = $private_key->toString();
    $_SESSION['enc_text'] = '';
    $_SESSION['signature'] = '';
    $_SESSION['is_sign_valid'] = 'undefined';
    header('Location: ' . $_SERVER['PHP_SELF']);
}

function create_sign()
{
    $document = $_POST['document'];
    $private_key = $_POST['private_key'];

    $rsa_obj = new Crypt_RSA(
        array(
            'private_key' => Crypt_RSA_Key::fromString($private_key),
        )
    );
    check_error($rsa_obj);

    $_SESSION['document'] = $document;
    $_SESSION['private_key'] = $private_key;
    $_SESSION['signature'] = $rsa_obj->createSign($document);
    check_error($rsa_obj);
    header('Location: ' . $_SERVER['PHP_SELF']);
}

function validate_sign()
{
    $document = $_POST['document'];
    $signature = $_POST['signature'];
    $public_key = $_POST['public_key'];

    $key = Crypt_RSA_Key::fromString($public_key);
    check_error($key);
    $rsa_obj = new Crypt_RSA;
    check_error($rsa_obj);

    $_SESSION['is_sign_valid'] = $rsa_obj->validateSign($document, $signature, $key) ? 'valid' : 'invalid';
    check_error($rsa_obj);
    $_SESSION['document'] = $document;
    $_SESSION['public_key'] = $public_key;
    $_SESSION['signature'] = $signature;
    header('Location: ' . $_SERVER['PHP_SELF']);
}

function encrypt()
{
    $plain_text = $_POST['plain_text'];
    $public_key = $_POST['public_key'];
    
    $key = Crypt_RSA_Key::fromString($public_key);
    check_error($key);
    $rsa_obj = new Crypt_RSA;
    check_error($rsa_obj);

    $_SESSION['plain_text'] = $plain_text;
    $_SESSION['public_key'] = $public_key;
    $_SESSION['enc_text'] = $rsa_obj->encrypt($plain_text, $key);
    check_error($rsa_obj);
    header('Location: ' . $_SERVER['PHP_SELF']);
}

function decrypt()
{
    $enc_text = $_POST['enc_text'];
    $private_key = $_POST['private_key'];

    $key = Crypt_RSA_Key::fromString($private_key);
    check_error($key);
    $rsa_obj = new Crypt_RSA;
    check_error($rsa_obj);
    $rsa_obj->setParams(array('dec_key' => $key));
    check_error($rsa_obj);

    $_SESSION['plain_text'] = $rsa_obj->decrypt($enc_text);
    check_error($rsa_obj);
    $_SESSION['private_key'] = $private_key;
    $_SESSION['enc_text'] = $enc_text;
    header('Location: ' . $_SERVER['PHP_SELF']);
}

function print_layout()
{
    $php_self = $_SERVER['PHP_SELF'];
    $public_key = get_session_var('public_key', true);
    $private_key = get_session_var('private_key', true);
    $document = get_session_var('document', true);
    $signature = get_session_var('signature', true);
    $plain_text = get_session_var('plain_text', true);
    $enc_text = get_session_var('enc_text', true);
    $is_sign_valid = get_session_var('is_sign_valid', true);

    echo <<<END

<html>
<head>
    <title>Crypt_RSA example of usage</title>
    <style type="text/css">
        form { margin: 10px; padding: 10px; background: #ccc; border: 1px solid; }
        textarea { margin-bottom: 10px; }
    </style>
</head>

<body>
<h1>Crypt_RSA example of usage</h1>
<form action="{$php_self}?task=generate_key_pair" method="POST">
    <div>
        <h1>Key generation</h1>

        Select key length:
        <select name="key_length">
            <option value="32">32 bit</option>
            <option value="64">64 bit</option>
            <option value="128">128 bit</option>
            <option value="256">256 bit</option>
            <option value="512">512 bit</option>
            <option value="1024">1024 bit</option>
            <option value="2048">2048 bit</option>
        </select><br/>

        Public key:<br/>
        <textarea style="height:100px;width:90%">{$public_key}</textarea><br/>

        Private key:<br/>
        <textarea style="height:100px;width:90%">{$private_key}</textarea><br/>

        <input type="submit" value="Start">
    </div>
</form>

<form action="{$php_self}?task=create_sign" method="POST">
    <div>
        <h1>Signing document</h1>

        Document:<br/>
        <textarea style="height:100px;width:90%" name="document">{$document}</textarea><br/>

        Private key:<br/>
        <textarea style="height:100px;width:90%" name="private_key">{$private_key}</textarea><br/>

        Signature:<br/>
        <textarea style="height:100px;width:90%">{$signature}</textarea><br/>

        <input type="submit" value="Sign">
    </div>
</form>

<form action="{$php_self}?task=validate_sign" method="POST">
    <div>
        <h1>Validating document sign</h1>

        Document:<br/>
        <textarea style="height:100px;width:90%" name="document">{$document}</textarea><br/>

        Signature:<br/>
        <textarea style="height:100px;width:90%" name="signature">{$signature}</textarea><br/>

        Public key:<br/>
        <textarea style="height:100px;width:90%" name="public_key">{$public_key}</textarea><br/>

        Result: <span style="font-size:2em">{$is_sign_valid}</span><br/>

        <input type="submit" value="Validate">
    </div>
</form>

<form action="{$php_self}?task=encrypt" method="POST">
    <div>
        <h1>Encrypting</h1>

        Plain text:<br/>
        <textarea style="height:100px;width:90%" name="plain_text">{$plain_text}</textarea><br/>

        Public key:<br/>
        <textarea style="height:100px;width:90%" name="public_key">{$public_key}</textarea><br/>

        Encrypted text:<br/>
        <textarea style="height:100px;width:90%">{$enc_text}</textarea><br/>

        <input type="submit" value="Encrypt">
    </div>
</form>

<form action="{$php_self}?task=decrypt" method="POST">
    <div>
        <h1>Decrypting</h1>

        Encrypted text:<br/>
        <textarea style="height:100px;width:90%" name="enc_text">{$enc_text}</textarea><br/>

        Private key:<br/>
        <textarea style="height:100px;width:90%" name="private_key">{$private_key}</textarea><br/>

        Plain text:<br/>
        <textarea style="height:100px;width:90%">{$plain_text}</textarea><br/>

        <input type="submit" value="Decrypt">
    </div>
</form>
END;

}

function get_session_var($name, $is_html_encode)
{
    $value = '';
    if (isset($_SESSION[$name])) {
        $value = $_SESSION[$name];
    }
    $_SESSION[$name] = $value;

    return $is_html_encode ? htmlspecialchars($value) : $value;
}

// error handler
function check_error(&$obj)
{
    if ($obj->isError()) {
        $error = $obj->getLastError();
        switch ($error->getCode()) {
        case CRYPT_RSA_ERROR_WRONG_TAIL :
            // nothing to do
            break;
        default:
            // echo error message and exit
            echo 'error: ', $error->getMessage();
            exit;
        }
    }
}

?>