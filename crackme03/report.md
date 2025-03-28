# Crackme03 Analysis Report

## Overview

This report documents the analysis of the `crackme03.elf` binary, a password-checking program. The goal was to understand how the program validates passwords and to determine the correct password.

## Analysis Steps

### 1. Initial Examination

The program takes a single command-line argument (the password) and checks if it's correct. If no argument is provided or more than one argument is provided, it displays "Need exactly one argument."

### 2. Main Function Analysis

The main function was analyzed first:

- It checks if exactly one argument is provided
- It initializes a key string "lAmBdA"
- It initializes a numeric key with the value 50463490 (bytes: 02 03 02 03 00 00 00 00)
- It initializes an additional key with the value 5 (bytes: 05 00)
- It checks if the input password is 6 characters long
- It calls the check_pw function with the input password, key string, and numeric key
- Based on the result, it prints a success or failure message

### 3. Check Password Function Analysis

The check_pw function was analyzed next:

- It iterates through each character of the input password
- For each character, it checks if the character equals the sum of the corresponding character in the key string "lAmBdA" and the corresponding byte in the numeric key
- The numeric key is treated as an array of bytes, and the function accesses it byte by byte
- The loop continues until either a mismatch is found (returning 0) or until the end of the key string or input password is reached (returning 1)

### 4. Password Calculation

Based on the analysis, the password was calculated as follows:

1. 'l' (ASCII 108) + 02 = 110 (ASCII 'n')
2. 'A' (ASCII 65) + 03 = 68 (ASCII 'D')
3. 'm' (ASCII 109) + 02 = 111 (ASCII 'o')
4. 'B' (ASCII 66) + 03 = 69 (ASCII 'E')
5. 'd' (ASCII 100) + 05 = 105 (ASCII 'i')
6. 'A' (ASCII 65) + 00 = 65 (ASCII 'A')

Therefore, the password is "nDoEiA".

### 5. Verification

The password was verified by running the crackme with the calculated password:

```
$ ./run-crackme.sh nDoEiA
Yes, nDoEiA is correct!
```

## Improvements Made to the Binary Analysis

During the analysis, several improvements were made to the IDA Pro database:

1. Added descriptive comments to the main and check_pw functions
2. Renamed variables to be more descriptive:
   - Changed function parameters in check_pw to input_password, key_string, and numeric_key
   - Changed local variables in main to key_string, numeric_key, additional_key, etc.
3. Fixed variable types to be more accurate
4. Added detailed comments explaining the password checking algorithm

## Conclusion

The crackme03 binary implements a simple password checking algorithm where each character of the password must equal the sum of the corresponding character in a key string and a corresponding byte in a numeric key. By understanding this algorithm, we were able to determine that the correct password is "nDoEiA".