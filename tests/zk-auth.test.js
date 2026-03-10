const ZKAuth = require('../js/zk-auth.js');

// Simple test runner
let testsPassed = 0;
let testsFailed = 0;

function runTest(name, fn) {
    try {
        fn();
        console.log(`✅ PASS: ${name}`);
        testsPassed++;
    } catch (error) {
        console.error(`❌ FAIL: ${name}`);
        console.error(error.message);
        testsFailed++;
    }
}

function assertStrictEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(`${message} - Expected: ${expected}, but got: ${actual}`);
    }
}

// Run the tests
console.log("Starting ZKAuth.checkStrength tests...\n");

runTest("Password length exactly 12 (Boundary condition)", () => {
    assertStrictEqual(ZKAuth.checkStrength("123456789012"), true, "Should be true for length 12");
});

runTest("Password length 11 (Boundary condition)", () => {
    assertStrictEqual(ZKAuth.checkStrength("12345678901"), false, "Should be false for length 11");
});

runTest("Password length greater than 12", () => {
    assertStrictEqual(ZKAuth.checkStrength("1234567890123"), true, "Should be true for length > 12");
});

runTest("Password length less than 12", () => {
    assertStrictEqual(ZKAuth.checkStrength("12345"), false, "Should be false for length < 12");
});

runTest("Empty string", () => {
    assertStrictEqual(ZKAuth.checkStrength(""), false, "Should be false for empty string");
});

runTest("Whitespace characters only", () => {
    assertStrictEqual(ZKAuth.checkStrength("            "), true, "Should be true for 12 spaces");
    assertStrictEqual(ZKAuth.checkStrength("           "), false, "Should be false for 11 spaces");
});

runTest("Null input should throw", () => {
    let threw = false;
    try {
        ZKAuth.checkStrength(null);
    } catch (e) {
        threw = true;
    }
    assertStrictEqual(threw, true, "Should throw on null input since it attempts .length");
});

runTest("Undefined input should throw", () => {
    let threw = false;
    try {
        ZKAuth.checkStrength(undefined);
    } catch (e) {
        threw = true;
    }
    assertStrictEqual(threw, true, "Should throw on undefined input");
});

// Since checkStrength just checks .length, what about an array or object with a length property?
// It will actually return true/false based on the property. We should probably test that if we want to be thorough.
runTest("Object with length property >= 12", () => {
    assertStrictEqual(ZKAuth.checkStrength({ length: 12 }), true, "Should be true for object with length >= 12");
});

console.log(`\nTest Summary: ${testsPassed} passed, ${testsFailed} failed`);
if (testsFailed > 0) {
    process.exit(1);
} else {
    process.exit(0);
}
