# ==========================================
# SECURITY VULNERABILITY EXAMPLES
# ==========================================
# Use these code samples to test your Security Aware Compiler
# Each section demonstrates different vulnerability types

# ------------------------------------------
# 1. SQL INJECTION VULNERABILITIES
# ------------------------------------------

# VULNERABLE: Direct string concatenation
def vulnerable_sql_injection():
    username = input("Enter username: ")
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)  # DANGEROUS: SQL injection

# VULNERABLE: f-string SQL
def vulnerable_sql_fstring():
    user_id = input("Enter ID: ")
    query = f"SELECT * FROM accounts WHERE id = {user_id}"
    cursor.execute(query)  # DANGEROUS: SQL injection

# VULNERABLE: % formatting
def vulnerable_sql_percent():
    email = input("Enter email: ")
    query = "SELECT * FROM users WHERE email = '%s'" % email
    cursor.execute(query)  # DANGEROUS: SQL injection

# SAFE: Parameterized queries
def safe_sql():
    username = input("Enter username: ")
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (username,))  # SAFE: Parameterized

# SAFE: ORM usage
def safe_orm():
    username = input("Enter username: ")
    User.objects.filter(name=username)  # SAFE: ORM handles escaping

# ------------------------------------------
# 2. BUFFER OVERFLOW VULNERABILITIES (C)
# ------------------------------------------

/*
// VULNERABLE: gets() function
#include <stdio.h>
#include <string.h>

void vulnerable_gets() {
    char buffer[10];
    printf("Enter your name: ");
    gets(buffer);  // DANGEROUS: No bounds checking
    printf("Hello %s\n", buffer);
}

// VULNERABLE: strcpy() function
void vulnerable_strcpy() {
    char dest[10];
    char src[] = "This string is too long for the destination buffer";
    strcpy(dest, src);  // DANGEROUS: Buffer overflow
}

// VULNERABLE: strcat() function
void vulnerable_strcat() {
    char dest[10] = "Hello";
    char src[] = " World";
    strcat(dest, src);  // DANGEROUS: Buffer overflow
}

// VULNERABLE: sprintf() function
void vulnerable_sprintf() {
    char buffer[10];
    int value = 123456;
    sprintf(buffer, "Value: %d", value);  // DANGEROUS: Potential overflow
}

// VULNERABLE: scanf() without width
void vulnerable_scanf() {
    char buffer[10];
    scanf("%s", buffer);  // DANGEROUS: No width limit
}

// SAFE: fgets() function
void safe_fgets() {
    char buffer[10];
    printf("Enter your name: ");
    fgets(buffer, sizeof(buffer), stdin);  // SAFE: Bounded input
}

// SAFE: strncpy() function
void safe_strncpy() {
    char dest[10];
    char src[] = "Hello";
    strncpy(dest, src, sizeof(dest) - 1);  // SAFE: Bounded copy
    dest[sizeof(dest) - 1] = '\0';  // Ensure null termination
}

// SAFE: snprintf() function
void safe_snprintf() {
    char buffer[10];
    int value = 123;
    snprintf(buffer, sizeof(buffer), "Value: %d", value);  // SAFE: Bounded
}
*/

# ------------------------------------------
# 3. HARDCODED SECRETS VULNERABILITIES
# ------------------------------------------

# VULNERABLE: Hardcoded passwords
def vulnerable_hardcoded_password():
    password = "admin123"  # DANGEROUS: Hardcoded password
    db_password = "secret_db_pass"  # DANGEROUS: Hardcoded database password
    api_key = "sk-1234567890abcdef"  # DANGEROUS: Hardcoded API key

# VULNERABLE: Hardcoded credentials
def vulnerable_hardcoded_credentials():
    username = "admin"
    passwd = "P@ssw0rd!"  # DANGEROUS: Hardcoded credentials
    connect_to_database(username, passwd)

# VULNERABLE: Hardcoded tokens
def vulnerable_hardcoded_tokens():
    jwt_secret = "my_secret_key_123"  # DANGEROUS: Hardcoded JWT secret
    encryption_key = "0123456789abcdef"  # DANGEROUS: Hardcoded encryption key

# SAFE: Environment variables
def safe_environment_vars():
    import os
    password = os.environ.get("DB_PASSWORD")  # SAFE: From environment
    api_key = os.environ.get("API_KEY")  # SAFE: From environment
    jwt_secret = os.environ.get("JWT_SECRET")  # SAFE: From environment

# SAFE: Configuration files
def safe_config_files():
    import configparser
    config = configparser.ConfigParser()
    config.read('config.ini')  # SAFE: External config
    password = config.get('database', 'password')

# ------------------------------------------
# 4. UNSAFE EVAL/EXEC VULNERABILITIES
# ------------------------------------------

# VULNERABLE: eval() with user input
def vulnerable_eval():
    user_input = input("Enter expression: ")
    result = eval(user_input)  # DANGEROUS: Code injection
    print("Result:", result)

# VULNERABLE: exec() with user input
def vulnerable_exec():
    code = input("Enter Python code: ")
    exec(code)  # DANGEROUS: Code execution

# VULNERABLE: eval() with string concatenation
def vulnerable_eval_concat():
    operation = input("Enter operation (+, -, *, /): ")
    num1 = input("Enter first number: ")
    num2 = input("Enter second number: ")
    result = eval(num1 + operation + num2)  # DANGEROUS: Indirect eval

# SAFE: ast.literal_eval()
def safe_literal_eval():
    import ast
    user_input = input("Enter list (e.g., [1,2,3]): ")
    try:
        result = ast.literal_eval(user_input)  # SAFE: Only literals
        print("Result:", result)
    except:
        print("Invalid input")

# SAFE: Specific operations
def safe_specific_ops():
    operation = input("Enter operation (+, -, *, /): ")
    num1 = float(input("Enter first number: "))
    num2 = float(input("Enter second number: "))
    
    if operation == "+":
        result = num1 + num2  # SAFE: Direct operation
    elif operation == "-":
        result = num1 - num2  # SAFE: Direct operation
    else:
        result = "Unsupported operation"
    
    print("Result:", result)

# ------------------------------------------
# 5. WEAK CRYPTOGRAPHY VULNERABILITIES
# ------------------------------------------

# VULNERABLE: Weak hash algorithms
def weak_crypto():
    import hashlib
    password = "user_password"
    
    # DANGEROUS: MD5 is cryptographically broken
    md5_hash = hashlib.md5(password.encode()).hexdigest()
    
    # DANGEROUS: SHA1 is considered weak
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()
    
    print(f"MD5: {md5_hash}")
    print(f"SHA1: {sha1_hash}")

# VULNERABLE: No salt usage
def weak_no_salt():
    import hashlib
    password = "user_password"
    # DANGEROUS: No salt - vulnerable to rainbow table attacks
    hashed = hashlib.sha256(password.encode()).hexdigest()
    print(f"Hashed without salt: {hashed}")

# SAFE: Strong hash algorithms with salt
def strong_crypto():
    import hashlib
    import os
    
    password = "user_password"
    salt = os.urandom(32)  # SAFE: Random salt
    
    # SAFE: SHA-256 with salt
    hashed = hashlib.pbkdf2_hmac('sha256', 
                                 password.encode('utf-8'), 
                                 salt, 
                                 100000)  # SAFE: Key stretching
    
    print(f"Strongly hashed: {hashed.hex()}")

# SAFE: Use bcrypt
def safe_bcrypt():
    import bcrypt
    password = "user_password"
    # SAFE: Automatic salt generation and key stretching
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    print(f"Bcrypt hashed: {hashed}")

# ------------------------------------------
# 6. UNSAFE DESERIALIZATION VULNERABILITIES
# ------------------------------------------

# VULNERABLE: pickle.loads() with user input
def vulnerable_pickle():
    import pickle
    user_data = input("Enter pickled data: ")
    # DANGEROUS: Can execute arbitrary code
    obj = pickle.loads(user_data.encode())  
    print("Deserialized:", obj)

# VULNERABLE: pickle.load() from file
def vulnerable_pickle_file():
    import pickle
    filename = input("Enter filename: ")
    # DANGEROUS: Can execute arbitrary code from file
    with open(filename, 'rb') as f:
        obj = pickle.load(f)
    print("Deserialized:", obj)

# SAFE: JSON deserialization
def safe_json():
    import json
    user_data = input("Enter JSON data: ")
    try:
        # SAFE: JSON only handles data, not code
        obj = json.loads(user_data)
        print("Deserialized:", obj)
    except json.JSONDecodeError:
        print("Invalid JSON")

# SAFE: YAML safe loading
def safe_yaml():
    import yaml
    user_data = input("Enter YAML data: ")
    try:
        # SAFE: yaml.safe_load prevents code execution
        obj = yaml.safe_load(user_data)
        print("Deserialized:", obj)
    except yaml.YAMLError:
        print("Invalid YAML")

# ------------------------------------------
# 7. COMMAND INJECTION VULNERABILITIES
# ------------------------------------------

# VULNERABLE: os.system() with user input
def vulnerable_command_injection():
    import os
    filename = input("Enter filename: ")
    # DANGEROUS: Command injection possible
    os.system(f"ls -la {filename}")  

# VULNERABLE: subprocess with shell=True
def vulnerable_subprocess():
    import subprocess
    user_input = input("Enter command: ")
    # DANGEROUS: Shell injection
    subprocess.run(user_input, shell=True)  

# VULNERABLE: String concatenation in commands
def vulnerable_concat_command():
    import os
    directory = input("Enter directory: ")
    # DANGEROUS: Command injection via directory name
    os.system("tar -czf backup.tar.gz " + directory)

# SAFE: subprocess without shell
def safe_subprocess():
    import subprocess
    filename = input("Enter filename: ")
    # SAFE: No shell, direct execution
    result = subprocess.run(['ls', '-la', filename], capture_output=True)
    print(result.stdout.decode())

# SAFE: Input validation
def safe_validated_command():
    import os
    import re
    
    filename = input("Enter filename: ")
    # SAFE: Strict input validation
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        print("Invalid filename!")
        return
    
    # SAFE: Validated input
    os.system(f"ls -la '{filename}'")

# ------------------------------------------
# 8. PATH TRAVERSAL VULNERABILITIES
# ------------------------------------------

# VULNERABLE: Direct file access with user input
def vulnerable_path_traversal():
    filename = input("Enter filename to read: ")
    # DANGEROUS: Can access any file on system
    with open(filename, 'r') as f:
        content = f.read()
    print(content)

# VULNERABLE: Directory traversal
def vulnerable_directory_traversal():
    import os
    user_path = input("Enter relative path: ")
    # DANGEROUS: Can escape intended directory
    full_path = os.path.join("/var/www", user_path)
    with open(full_path, 'r') as f:
        return f.read()

# SAFE: Path validation
def safe_path_validation():
    import os
    import re
    
    filename = input("Enter filename: ")
    # SAFE: Validate filename doesn't contain path traversal
    if '..' in filename or '/' in filename or '\\' in filename:
        print("Invalid filename!")
        return
    
    # SAFE: Restrict to specific directory
    safe_dir = "/safe/directory"
    full_path = os.path.join(safe_dir, filename)
    
    # SAFE: Ensure path is within safe directory
    if not full_path.startswith(safe_dir):
        print("Access denied!")
        return
    
    with open(full_path, 'r') as f:
        print(f.read())

# ------------------------------------------
# 9. SAFE CODE EXAMPLES (No Vulnerabilities)
# ------------------------------------------

# SAFE: Proper input validation and sanitization
def safe_user_input():
    import re
    
    username = input("Enter username: ")
    # SAFE: Validate input format
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        print("Invalid username format!")
        return None
    
    # SAFE: Use parameterized queries
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()

# SAFE: Proper error handling
def safe_error_handling():
    try:
        # Some operation that might fail
        result = 10 / 0
    except ZeroDivisionError:
        print("Cannot divide by zero!")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
    else:
        return result

# SAFE: Secure file operations
def safe_file_operations():
    import os
    import tempfile
    
    # SAFE: Use temporary files
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("Sensitive data")
        temp_filename = f.name
    
    try:
        # Process the file
        with open(temp_filename, 'r') as f:
            data = f.read()
        print("File processed successfully")
    finally:
        # SAFE: Clean up temporary files
        os.unlink(temp_filename)

# SAFE: Proper logging without sensitive data
def safe_logging():
    import logging
    
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    username = input("Enter username: ")
    password = input("Enter password: ")
    
    # SAFE: Log username but not password
    logger.info(f"User login attempt: {username}")
    # DANGEROUS: Never log passwords or sensitive data
    # logger.info(f"Password: {password}")  # DON'T DO THIS
    
    # SAFE: Log generic success/failure
    if authenticate_user(username, password):
        logger.info("Authentication successful")
    else:
        logger.warning("Authentication failed")

# Helper function for safe logging example
def authenticate_user(username, password):
    # Dummy authentication
    return username == "admin" and password == "correct_password"

# ------------------------------------------
# 10. MIXED EXAMPLES (Multiple Issues)
# ------------------------------------------

# VULNERABLE: Multiple security issues
def vulnerable_multiple_issues():
    import os
    import hashlib
    
    # Issue 1: Hardcoded password
    password = "admin123"
    
    # Issue 2: Weak hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    # Issue 3: SQL injection
    username = input("Enter username: ")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    
    # Issue 4: Command injection
    filename = input("Enter filename: ")
    os.system(f"cat {filename}")
    
    # Issue 5: Unsafe eval
    expression = input("Enter math expression: ")
    result = eval(expression)
    
    print(f"Hashed password: {hashed}")
    print(f"Query: {query}")
    print(f"Result: {result}")

# SAFE: Properly secured version
def safe_multiple_fixes():
    import os
    import hashlib
    import bcrypt
    import sqlite3
    import re
    import ast
    
    # Fix 1: Password from environment
    import os
    password = os.environ.get("USER_PASSWORD", "")
    
    # Fix 2: Strong hashing with salt
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Fix 3: Parameterized query
    username = input("Enter username: ")
    if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        print("Invalid username!")
        return
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    
    # Fix 4: Safe subprocess
    filename = input("Enter filename: ")
    if not re.match(r'^[a-zA-Z0-9._-]+$', filename):
        print("Invalid filename!")
        return
    
    result = subprocess.run(['cat', filename], capture_output=True, text=True)
    
    # Fix 5: Safe expression evaluation
    expression = input("Enter math expression: ")
    try:
        # Only allow safe mathematical expressions
        safe_result = ast.literal_eval(expression)
        if isinstance(safe_result, (int, float)):
            print(f"Result: {safe_result}")
        else:
            print("Only numbers are allowed!")
    except:
        print("Invalid expression!")
    
    print("All operations completed safely!")

if __name__ == "__main__":
    print("Security Vulnerability Examples")
    print("================================")
    print("Use these examples to test your Security Aware Compiler")
    print("Each function demonstrates different vulnerability types")
    print("Run individual functions to test specific scenarios")
