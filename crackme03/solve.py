#!/usr/bin/env python3

# Key string from the main function
key_string = "lAmBdA"

# Numeric key bytes from the main function
# numeric_key = 50463490 (bytes: 02 03 02 03 00 00 00 00)
# additional_key = 5 (bytes: 05 00)
numeric_key_bytes = [0x02, 0x03, 0x02, 0x03, 0x05, 0x00]

# Calculate the password
password = ""
for i in range(len(key_string)):
    # Each character of the password must equal the sum of the corresponding character
    # in key_string and the corresponding byte in numeric_key
    password_char = chr(ord(key_string[i]) + numeric_key_bytes[i])
    password += password_char
    print(f"Position {i}: '{key_string[i]}' (ASCII {ord(key_string[i])}) + {numeric_key_bytes[i]} = '{password_char}' (ASCII {ord(password_char)})")

print(f"\nThe password is: {password}")