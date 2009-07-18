<?php
if (!defined('PHPUnit_MAIN_METHOD')) {
    define('PHPUnit_MAIN_METHOD', 'Crypt_RSA_AllTests::main');
}

require_once 'PHPUnit/TextUI/TestRunner.php';
require_once 'PHPUnit/Framework/TestSuite.php';

require_once 'FactoryTest.php';
require_once 'DriverTest.php';

class Crypt_RSA_AllTests {

    public static function main() {
        PHPUnit_TextUI_TestRunner::run(self::suite());
    }

    public static function suite() {
        $suite = new PHPUnit_Framework_TestSuite( "Crypt_RSA Tests");
        $suite->addTestSuite('Crypt_RSA_DriverTest');
        $suite->addTestSuite('Crypt_RSA_FactoryTest');
        return $suite;
    }

}

if (PHPUnit_MAIN_METHOD == 'Crypt_RSA_AllTests::main') {
    Crypt_RSA_AllTests::main();
}

