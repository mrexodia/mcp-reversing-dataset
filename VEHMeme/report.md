# VEHMeme.exe Crackme Analysis

## Overview

VEHMeme.exe is a crackme that uses Vectored Exception Handling (VEH) for obfuscated control flow. The program asks for a flag input, checks its length, and then verifies it using code loaded from a resource.

## Key Components

### TlsCallback_0

This function runs before the main entry point and sets up the exception handling mechanism:

- Registers a Vectored Exception Handler (Handler)
- Allocates 0x1000 bytes of memory for verification state
- Initializes the memory with zeros

### Handler Function

The Handler function implements obfuscated control flow using exceptions:

- Processes different exception types (illegal instruction, breakpoint, single step, etc.)
- Uses exceptions to manipulate program flow
- Maintains a call stack for function calls
- Updates a verification buffer based on flag correctness

### Main Function

The main function:

1. Loads verification code from a resource (ID 0x69, type 0xA)
2. Prompts the user to enter a flag
3. Checks if the flag is exactly 41 characters long (including newline)
4. If the length is correct, it:
   - Allocates executable memory
   - Copies the resource data to this memory
   - Executes the verification code

### Result Handling

The `print_result_and_exit` function:
- Checks if the verification buffer at the current position is zero (success) or non-zero (failure)
- Prints "Yay, you did it!" for success or "Wrong flag..." for failure
- Exits the program

## Exception-Based Control Flow

The crackme uses various exception types to implement control flow:

- STATUS_ILLEGAL_INSTRUCTION (0xC000001D): Decrements byte at current position and skips instruction
- STATUS_BREAKPOINT (0x80000003): Increments counter and skips instruction
- STATUS_SINGLE_STEP (0x80000004): Reads next byte from Buffer and stores at current position
- STATUS_ACCESS_VIOLATION (0xC0000005): Implements function calls and returns
- STATUS_PRIVILEGED_INSTRUCTION (0xC0000096): Decrements counter and skips instruction
- STATUS_INTEGER_DIVIDE_BY_ZERO (0xC0000094): Increments byte at current position and skips instruction

## Flag Verification

The flag verification process:

1. The flag must be exactly 41 characters long (including newline)
2. The verification code loaded from the resource processes each character
3. The verification state is tracked in the allocated memory buffer
4. If the verification buffer at the final position is zero, the flag is correct

## Solving Strategies

To solve this crackme, several approaches can be used:

### Dynamic Analysis

1. **Debugging with Exception Handling**:
   - Configure a debugger to handle the exceptions without breaking execution
   - Set breakpoints in the Handler function to monitor how exceptions are processed
   - Track changes to the verification buffer to understand the flag checking logic

2. **Memory Monitoring**:
   - Monitor the allocated memory buffer (qword_140005678) during execution
   - Observe how each character of the input affects the verification state
   - Identify patterns that indicate correct vs. incorrect characters

### Code Instrumentation

1. **Logging Exception Handling**:
   - Modify the Handler function to log each exception and its effect
   - Track the execution path through the obfuscated code
   - Reconstruct the verification algorithm from the logs

2. **Brute Force Approach**:
   - Instrument the code to try different characters at each position
   - Monitor the verification buffer to identify correct characters
   - Build the flag character by character based on feedback

### Binary Patching

1. **Bypass Verification**:
   - Patch the `print_result_and_exit` function to always show success
   - Alternatively, patch the verification buffer check to always return zero

2. **Extract Verification Logic**:
   - Extract the resource containing the verification code
   - Analyze it separately to understand the verification algorithm
   - Reverse engineer the expected flag

### Recommended Approach

The most effective strategy would be a combination of:

1. First, use dynamic analysis to understand the general flow of the verification
2. Instrument the Handler function to log exception handling and memory changes
3. Create a script that tries different characters and monitors the verification state
4. Use the feedback from the verification process to construct the correct flag

This approach allows for methodical solving without needing to fully understand all the obfuscated code, focusing instead on the observable effects of the verification process.

## Conclusion

This crackme uses advanced obfuscation techniques with Vectored Exception Handling to make analysis difficult. The verification code is loaded from a resource and uses exceptions to implement control flow, making it challenging to trace the execution path. The correct flag must be 41 characters long and pass the verification checks implemented in the obfuscated code.