# crackme03

This is [`crackme03.c`](https://github.com/NoraCodes/crackmes/blob/b3353f2392a87a39a3e1997ffeb913037d86e35c/crackme03.c) compiled with GCC 11.4.0 on Ubuntu 22.04.

## Prompt

You task is to analyze a crackme in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:
- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types if necessary (especially pointer and array types)
- Change function names to be more descriptive
- If more details are necessary, disassemble the function and add comments with your findings
- NEVER convert number bases yourself. Use the convert_number MCP tool if needed!
- Do not attempt brute forcing, derive any solutions purely from the disassembly and simple python scripts
- Create a report.md with your findings and steps taken at the end
- When you find a solution, prompt to user for feedback with the password you found

## Input

- crackme03.elf
- run-crackme.sh

## Model

Claude 3.7 Sonnet (Roo Cline)
