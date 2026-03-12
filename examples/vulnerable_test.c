/**
 * @file vulnerable_test.c
 * @brief Test file with intentional buffer overflow vulnerabilities
 *
 * This file contains various buffer overflow vulnerabilities for
 * testing the BufferOverflowDetector.
 *
 * WARNING: This code is intentionally vulnerable. DO NOT use in production!
 */

#include <stdio.h>
#include <string.h>

void test_gets_vulnerability() {
    char buffer[64];

    printf("Enter your name: ");
    gets(buffer);  // CRITICAL: gets() has no bounds checking

    printf("Hello, %s!\n", buffer);
}

void test_strcpy_vulnerability() {
    char dest[32];
    char *src = "This is a very long string that will overflow the destination buffer";

    strcpy(dest, src);  // HIGH: strcpy() has no bounds checking

    printf("Copied: %s\n", dest);
}

void test_strcat_vulnerability() {
    char buffer[16] = "Hello ";
    char *append = "World! This will overflow!";

    strcat(buffer, append);  // HIGH: strcat() has no bounds checking

    printf("Result: %s\n", buffer);
}

void test_sprintf_vulnerability() {
    char buffer[32];
    char *user_input = "This is a very long user input that will overflow";

    sprintf(buffer, "User said: %s", user_input);  // HIGH: sprintf() has no bounds checking

    printf("%s\n", buffer);
}

void test_scanf_vulnerability() {
    char username[16];

    printf("Enter username: ");
    scanf("%s", username);  // HIGH: unbounded %s can overflow

    printf("Username: %s\n", username);
}

int main() {
    printf("=== Buffer Overflow Vulnerability Tests ===\n");
    printf("WARNING: This code is intentionally vulnerable!\n\n");

    // Uncomment to test (will crash!)
    // test_gets_vulnerability();
    // test_strcpy_vulnerability();
    // test_strcat_vulnerability();
    // test_sprintf_vulnerability();
    // test_scanf_vulnerability();

    printf("All tests defined but not executed.\n");
    printf("Run SentinelX to detect these vulnerabilities!\n");

    return 0;
}
