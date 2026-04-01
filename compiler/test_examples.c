/*
 * ==========================================
 * C SECURITY VULNERABILITY EXAMPLES
 * ==========================================
 * Use these code samples to test your Security Aware Compiler
 * Each section demonstrates different vulnerability types
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// ------------------------------------------
// 1. BUFFER OVERFLOW VULNERABILITIES
// ------------------------------------------

// VULNERABLE: gets() function - classic buffer overflow
void vulnerable_gets() {
    char buffer[10];
    printf("Enter your name: ");
    gets(buffer);  // DANGEROUS: No bounds checking
    printf("Hello %s\n", buffer);
}

// VULNERABLE: strcpy() without bounds checking
void vulnerable_strcpy() {
    char dest[10];
    char *src = "This string is way too long for the destination buffer";
    strcpy(dest, src);  // DANGEROUS: Buffer overflow
    printf("Copied: %s\n", dest);
}

// VULNERABLE: strcat() without bounds checking
void vulnerable_strcat() {
    char dest[10] = "Hello";
    char *src = " World, this is too long";
    strcat(dest, src);  // DANGEROUS: Buffer overflow
    printf("Concatenated: %s\n", dest);
}

// VULNERABLE: sprintf() without size limit
void vulnerable_sprintf() {
    char buffer[10];
    int value = 123456;
    sprintf(buffer, "Value: %d", value);  // DANGEROUS: Buffer overflow
    printf("Formatted: %s\n", buffer);
}

// VULNERABLE: scanf() without width specification
void vulnerable_scanf() {
    char buffer[10];
    printf("Enter text: ");
    scanf("%s", buffer);  // DANGEROUS: No width limit
    printf("You entered: %s\n", buffer);
}

// VULNERABLE: gets() with loop
void vulnerable_gets_loop() {
    char names[5][10];
    int i;
    
    printf("Enter 5 names:\n");
    for (i = 0; i < 5; i++) {
        printf("Name %d: ", i + 1);
        gets(names[i]);  // DANGEROUS: Buffer overflow in loop
    }
    
    for (i = 0; i < 5; i++) {
        printf("Name %d: %s\n", i + 1, names[i]);
    }
}

// SAFE: fgets() with proper bounds checking
void safe_fgets() {
    char buffer[10];
    printf("Enter your name: ");
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        // Remove newline if present
        buffer[strcspn(buffer, "\n")] = '\0';
        printf("Hello %s\n", buffer);
    }
}

// SAFE: strncpy() with null termination
void safe_strncpy() {
    char dest[10];
    char *src = "Hello";
    strncpy(dest, src, sizeof(dest) - 1);  // SAFE: Bounded copy
    dest[sizeof(dest) - 1] = '\0';  // Ensure null termination
    printf("Copied safely: %s\n", dest);
}

// SAFE: strncat() with bounds checking
void safe_strncat() {
    char dest[10] = "Hello";
    char *src = " Hi";
    strncat(dest, src, sizeof(dest) - strlen(dest) - 1);  // SAFE: Bounded
    printf("Concatenated safely: %s\n", dest);
}

// SAFE: snprintf() with size limit
void safe_snprintf() {
    char buffer[10];
    int value = 123;
    snprintf(buffer, sizeof(buffer), "Val: %d", value);  // SAFE: Bounded
    printf("Formatted safely: %s\n", buffer);
}

// SAFE: scanf() with width specification
void safe_scanf() {
    char buffer[10];
    printf("Enter text: ");
    scanf("%9s", buffer);  // SAFE: Width limit (9 + null terminator)
    printf("You entered: %s\n", buffer);
}

// ------------------------------------------
// 2. FORMAT STRING VULNERABILITIES
// ------------------------------------------

// VULNERABLE: User input as format string
void vulnerable_format_string() {
    char input[100];
    printf("Enter your name: ");
    fgets(input, sizeof(input), stdin);
    
    // DANGEROUS: User input used as format string
    printf(input);  // VULNERABLE: Format string attack
}

// VULNERABLE: sprintf with user format
void vulnerable_sprintf_format() {
    char buffer[100];
    char user_format[50];
    
    printf("Enter format string: ");
    fgets(user_format, sizeof(user_format), stdin);
    
    // DANGEROUS: User-controlled format string
    sprintf(buffer, user_format, "Hello", "World");
    printf("Result: %s\n", buffer);
}

// SAFE: Fixed format strings
void safe_format_string() {
    char input[100];
    printf("Enter your name: ");
    fgets(input, sizeof(input), stdin);
    
    // SAFE: Fixed format string
    printf("Hello, %s", input);  // SAFE: No user-controlled format
}

// ------------------------------------------
// 3. INTEGER OVERFLOW VULNERABILITIES
// ------------------------------------------

// VULNERABLE: Integer overflow in allocation
void vulnerable_integer_overflow() {
    int size = 1000000000;  // Large number
    int multiplier = 10;
    
    // DANGEROUS: Integer overflow
    int total = size * multiplier;  // May overflow
    
    char *buffer = (char *)malloc(total);  // May allocate too little
    if (buffer) {
        strcpy(buffer, "This is a test");
        printf("Buffer allocated and filled\n");
        free(buffer);
    }
}

// VULNERABLE: Signed integer overflow
void vulnerable_signed_overflow() {
    int x = 2147483647;  // INT_MAX
    int y = 1;
    
    // DANGEROUS: Signed integer overflow (undefined behavior)
    int result = x + y;
    printf("Result: %d\n", result);  // May wrap around
}

// SAFE: Check for overflow before operations
void safe_integer_overflow() {
    int size = 1000000000;
    int multiplier = 10;
    
    // SAFE: Check for overflow before multiplication
    if (size > 0 && multiplier > 0 && size > INT_MAX / multiplier) {
        printf("Integer overflow would occur!\n");
        return;
    }
    
    int total = size * multiplier;
    char *buffer = (char *)malloc(total);
    if (buffer) {
        strcpy(buffer, "This is a test");
        printf("Buffer allocated safely\n");
        free(buffer);
    }
}

// ------------------------------------------
// 4. USE-AFTER-FREE VULNERABILITIES
// ------------------------------------------

// VULNERABLE: Use after free
void vulnerable_use_after_free() {
    char *ptr = (char *)malloc(100);
    strcpy(ptr, "Important data");
    printf("Data: %s\n", ptr);
    
    free(ptr);  // Memory freed
    
    // DANGEROUS: Using freed memory
    printf("After free: %s\n", ptr);  // VULNERABLE
    ptr[0] = 'X';  // VULNERABLE: Writing to freed memory
}

// SAFE: Set pointer to NULL after free
void safe_use_after_free() {
    char *ptr = (char *)malloc(100);
    strcpy(ptr, "Important data");
    printf("Data: %s\n", ptr);
    
    free(ptr);
    ptr = NULL;  // SAFE: Set to NULL after free
    
    if (ptr) {
        printf("After free: %s\n", ptr);  // Won't execute
    } else {
        printf("Memory properly freed\n");
    }
}

// ------------------------------------------
// 5. DOUBLE FREE VULNERABILITIES
// ------------------------------------------

// VULNERABLE: Double free
void vulnerable_double_free() {
    char *ptr = (char *)malloc(100);
    strcpy(ptr, "Test data");
    printf("Data: %s\n", ptr);
    
    free(ptr);  // First free
    
    // DANGEROUS: Double free
    free(ptr);  // VULNERABLE: Double free
}

// SAFE: Prevent double free
void safe_double_free() {
    char *ptr = (char *)malloc(100);
    strcpy(ptr, "Test data");
    printf("Data: %s\n", ptr);
    
    free(ptr);
    ptr = NULL;  // SAFE: Set to NULL
    
    // This won't cause double free
    if (ptr) {
        free(ptr);
    }
}

// ------------------------------------------
// 6. UNINITIALIZED MEMORY VULNERABILITIES
// ------------------------------------------

// VULNERABLE: Using uninitialized memory
void vulnerable_uninitialized() {
    char buffer[10];  // Uninitialized
    char *ptr;
    
    // DANGEROUS: Using uninitialized memory
    printf("Uninitialized data: %s\n", buffer);  // VULNERABLE
    
    ptr = (char *)malloc(10);
    // DANGEROUS: Using uninitialized malloc memory
    printf("Uninitialized malloc: %s\n", ptr);  // VULNERABLE
    
    free(ptr);
}

// SAFE: Initialize memory properly
void safe_uninitialized() {
    char buffer[10] = {0};  // Initialized to zeros
    char *ptr;
    
    printf("Initialized data: %s\n", buffer);  // SAFE
    
    ptr = (char *)calloc(10, 1);  // SAFE: calloc zeros memory
    printf("Initialized malloc: %s\n", ptr);  // SAFE
    
    free(ptr);
}

// ------------------------------------------
// 7. RACE CONDITIONS (Basic examples)
// ------------------------------------------

// VULNERABLE: Time-of-check-time-of-use (TOCTOU)
void vulnerable_toctou() {
    char filename[] = "important_file.txt";
    FILE *file;
    
    // Check if file exists
    if (access(filename, F_OK) == 0) {
        // Time window where file could be replaced
        sleep(1);  // Simulate delay
        
        // Use file (may be different file now)
        file = fopen(filename, "r");
        if (file) {
            printf("File opened\n");
            fclose(file);
        }
    }
}

// SAFE: Open file directly, check after
void safe_toctou() {
    char filename[] = "important_file.txt";
    FILE *file;
    
    // SAFE: Open file directly
    file = fopen(filename, "r");
    if (file) {
        // Now we know we have the file
        printf("File opened safely\n");
        fclose(file);
    } else {
        printf("File not accessible\n");
    }
}

// ------------------------------------------
// 8. COMMAND INJECTION VULNERABILITIES
// ------------------------------------------

// VULNERABLE: system() with user input
void vulnerable_system() {
    char filename[100];
    printf("Enter filename to list: ");
    fgets(filename, sizeof(filename), stdin);
    
    // Remove newline
    filename[strcspn(filename, "\n")] = '\0';
    
    // DANGEROUS: Command injection possible
    char command[200];
    sprintf(command, "ls -la %s", filename);  // VULNERABLE
    system(command);
}

// VULNERABLE: popen() with user input
void vulnerable_popen() {
    char search_term[100];
    printf("Enter search term: ");
    fgets(search_term, sizeof(search_term), stdin);
    
    // Remove newline
    search_term[strcspn(search_term, "\n")] = '\0';
    
    // DANGEROUS: Command injection
    char command[200];
    sprintf(command, "grep %s /etc/passwd", search_term);  // VULNERABLE
    FILE *pipe = popen(command, "r");
    
    if (pipe) {
        char line[256];
        while (fgets(line, sizeof(line), pipe)) {
            printf("%s", line);
        }
        pclose(pipe);
    }
}

// SAFE: Use execv() instead of system()
void safe_exec() {
    char filename[100];
    printf("Enter filename to list: ");
    fgets(filename, sizeof(filename), stdin);
    
    // Remove newline
    filename[strcspn(filename, "\n")] = '\0';
    
    // SAFE: Use execv with explicit arguments
    char *args[] = {"ls", "-la", filename, NULL};
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        execv("/bin/ls", args);
        exit(1);  // Should not reach here
    } else if (pid > 0) {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
    }
}

// ------------------------------------------
// 9. SAFE CODE EXAMPLES
// ------------------------------------------

// SAFE: Proper bounds checking and validation
void safe_input_validation() {
    char input[100];
    int number;
    
    printf("Enter a number (1-100): ");
    if (fgets(input, sizeof(input), stdin) != NULL) {
        // Validate input is a number
        if (sscanf(input, "%d", &number) == 1) {
            if (number >= 1 && number <= 100) {
                printf("Valid number: %d\n", number);
            } else {
                printf("Number out of range\n");
            }
        } else {
            printf("Invalid input\n");
        }
    }
}

// SAFE: Proper memory management
void safe_memory_management() {
    char *buffer = NULL;
    size_t size = 0;
    
    // Allocate memory
    size = 100;
    buffer = (char *)malloc(size);
    if (!buffer) {
        printf("Memory allocation failed\n");
        return;
    }
    
    // Use memory
    strncpy(buffer, "Safe string", size - 1);
    buffer[size - 1] = '\0';  // Ensure null termination
    
    printf("Buffer content: %s\n", buffer);
    
    // Clean up
    free(buffer);
    buffer = NULL;  // Prevent use-after-free
}

// SAFE: Proper error handling
void safe_error_handling() {
    FILE *file = fopen("nonexistent.txt", "r");
    
    if (!file) {
        perror("Error opening file");  // SAFE: Proper error reporting
        return;
    }
    
    // Process file safely
    char buffer[100];
    while (fgets(buffer, sizeof(buffer), file)) {
        printf("%s", buffer);
    }
    
    fclose(file);
}

// ------------------------------------------
// 10. MAIN FUNCTION FOR TESTING
// ------------------------------------------

int main() {
    printf("C Security Vulnerability Examples\n");
    printf("==================================\n");
    printf("Uncomment function calls to test specific vulnerabilities\n\n");
    
    // Test vulnerable functions (uncomment to use):
    // vulnerable_gets();
    // vulnerable_strcpy();
    // vulnerable_format_string();
    // vulnerable_system();
    
    // Test safe functions:
    safe_fgets();
    safe_strncpy();
    safe_format_string();
    safe_input_validation();
    safe_memory_management();
    safe_error_handling();
    
    printf("\nTesting completed\n");
    return 0;
}
