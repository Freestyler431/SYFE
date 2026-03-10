<?php

// Define constant to prevent config.php from executing completely
define('SYFE_LOAD_ENV_TEST', true);

// Include the function to test
require_once __DIR__ . '/../config.php';

// Test runner state
$testsPassed = 0;
$testsFailed = 0;

function runTest($name, $fn) {
    global $testsPassed, $testsFailed;

    // Backup environment state
    $backupEnv = $_ENV;
    $backupServer = $_SERVER;
    // Track keys added via putenv during the test
    $initialEnvVars = getenv();

    try {
        $fn();
        echo "✅ PASS: $name\n";
        $testsPassed++;
    } catch (Exception $e) {
        echo "❌ FAIL: $name\n";
        echo "   " . $e->getMessage() . "\n";
        $testsFailed++;
    }

    // Restore environment state
    $_ENV = $backupEnv;
    $_SERVER = $backupServer;

    // Clean up putenv additions
    $currentEnvVars = getenv();
    foreach ($currentEnvVars as $key => $value) {
        if (!array_key_exists($key, $initialEnvVars)) {
            // Remove the environment variable added during test
            putenv($key);
        }
    }
}

function assertStrictEqual($actual, $expected, $message = '') {
    if ($actual !== $expected) {
        $actualStr = is_bool($actual) ? ($actual ? 'true' : 'false') : (is_null($actual) ? 'null' : print_r($actual, true));
        $expectedStr = is_bool($expected) ? ($expected ? 'true' : 'false') : (is_null($expected) ? 'null' : print_r($expected, true));
        throw new Exception(trim("$message - Expected: $expectedStr, but got: $actualStr"));
    }
}

function assertArrayHasKey($key, $array, $message = '') {
    if (!array_key_exists($key, $array)) {
        throw new Exception(trim("$message - Expected array to have key: $key"));
    }
}

function assertArrayNotHasKey($key, $array, $message = '') {
    if (array_key_exists($key, $array)) {
        throw new Exception(trim("$message - Expected array to NOT have key: $key"));
    }
}

echo "Starting loadEnv() tests...\n\n";

// Helper function to create a temporary file with specific content
function createTempEnvFile($content) {
    $tempFile = tempnam(sys_get_temp_dir(), 'env_test_');
    file_put_contents($tempFile, $content);
    return $tempFile;
}

// Ensure the tests run
runTest("Test runner sanity check", function() {
    assertStrictEqual(1, 1, "One should equal one");
});

runTest("Non-existent file", function() {
    $nonExistentPath = sys_get_temp_dir() . '/does_not_exist_' . time() . '.env';

    // Should not throw or die
    loadEnv($nonExistentPath);

    // Check that some random key doesn't get set
    assertArrayNotHasKey('RANDOM_TEST_KEY', $_ENV, "Environment shouldn't have arbitrary keys added");
});

runTest("Valid environment variables", function() {
    $content = "TEST_KEY_1=value1\nTEST_KEY_2=value2";
    $tempFile = createTempEnvFile($content);

    loadEnv($tempFile);

    // Check $_ENV
    assertArrayHasKey('TEST_KEY_1', $_ENV, "\$_ENV should have TEST_KEY_1");
    assertStrictEqual($_ENV['TEST_KEY_1'], 'value1', "Value of TEST_KEY_1 in \$_ENV should be correct");

    assertArrayHasKey('TEST_KEY_2', $_ENV, "\$_ENV should have TEST_KEY_2");
    assertStrictEqual($_ENV['TEST_KEY_2'], 'value2', "Value of TEST_KEY_2 in \$_ENV should be correct");

    // Check $_SERVER
    assertArrayHasKey('TEST_KEY_1', $_SERVER, "\$_SERVER should have TEST_KEY_1");
    assertStrictEqual($_SERVER['TEST_KEY_1'], 'value1', "Value of TEST_KEY_1 in \$_SERVER should be correct");

    // Check getenv()
    assertStrictEqual(getenv('TEST_KEY_1'), 'value1', "Value of TEST_KEY_1 via getenv() should be correct");

    unlink($tempFile);
});

runTest("Comments and empty lines", function() {
    $content = "# This is a comment\n\nTEST_KEY_3=value3\n  # This comment has leading spaces\n\nTEST_KEY_4=value4\n# Another comment\n";
    $tempFile = createTempEnvFile($content);

    loadEnv($tempFile);

    assertArrayHasKey('TEST_KEY_3', $_ENV, "Should load key after empty lines and comments");
    assertStrictEqual($_ENV['TEST_KEY_3'], 'value3');

    assertArrayHasKey('TEST_KEY_4', $_ENV, "Should load key after trailing spaces and comments");
    assertStrictEqual($_ENV['TEST_KEY_4'], 'value4');

    assertArrayNotHasKey('#', $_ENV, "Should not treat comment hash as a key");
    assertArrayNotHasKey('', $_ENV, "Should not have empty string keys");

    unlink($tempFile);
});

runTest("Existing variables are not overwritten", function() {
    // Pre-set a variable
    $_ENV['EXISTING_KEY'] = 'original_value';
    $_SERVER['EXISTING_KEY'] = 'original_value';
    putenv('EXISTING_KEY=original_value');

    $content = "EXISTING_KEY=new_value\nNEW_KEY=new_value";
    $tempFile = createTempEnvFile($content);

    loadEnv($tempFile);

    assertStrictEqual($_ENV['EXISTING_KEY'], 'original_value', "\$_ENV should not be overwritten");
    assertStrictEqual($_SERVER['EXISTING_KEY'], 'original_value', "\$_SERVER should not be overwritten");
    assertStrictEqual(getenv('EXISTING_KEY'), 'original_value', "getenv() should not be overwritten");

    assertStrictEqual($_ENV['NEW_KEY'], 'new_value', "New keys should still be added");

    // Cleanup putenv since our test runner restores getenv() differently
    putenv('EXISTING_KEY');
    unlink($tempFile);
});

runTest("Trimming and equals sign in values", function() {
    $content = "   SPACED_KEY   =   spaced_value   \nEQUALS_KEY=value=with=equals";
    $tempFile = createTempEnvFile($content);

    loadEnv($tempFile);

    assertArrayHasKey('SPACED_KEY', $_ENV, "Key should be trimmed");
    assertStrictEqual($_ENV['SPACED_KEY'], 'spaced_value', "Value should be trimmed");

    assertArrayHasKey('EQUALS_KEY', $_ENV, "Key should be loaded");
    assertStrictEqual($_ENV['EQUALS_KEY'], 'value=with=equals', "Value can contain equals signs");

    unlink($tempFile);
});

echo "\nTest Summary: $testsPassed passed, $testsFailed failed\n";
if ($testsFailed > 0) {
    exit(1);
} else {
    exit(0);
}
