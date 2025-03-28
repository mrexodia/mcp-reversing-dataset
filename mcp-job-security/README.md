# mcp-job-security

This is a modified version of [mcp-job-security](https://github.com/thebabush/mcp-job-security), as suggested by [babush](https://linktr.ee/thebabush) on X: https://x.com/pmontesel/status/1905403998896611760.

## Prompt

You task is to analyze a binary in IDA Pro. You can use the MCP tools to retrieve information. In general use the following strategy:
- Makes sure to analyze all entry points
- Inspect the decompilation and add comments with your findings
- Rename variables to more sensible names
- Change the variable and argument types (especially pointer and array types)
- Change function names to be more descriptive
- For each function analyzed add a comment at the start address describing the purpose of the function
- NEVER convert number bases yourself. Use the convert_number MCP tool if needed!
- Create a report.md with your findings and steps taken at the end

## Input

- transformed.elf

## Model

Claude 3.7 Sonnet (Roo Code)
