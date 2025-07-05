# devnull
An extremely simple discord bot for assembling and disassembling through keystone and capstone.

## Commands
There are two (slash) commands:
- `/asm` for assembling the assembly instructions into binary code.
Targets Supported: ARM, Thumb, x86 (16/32/64), MIPS (32/64), PPC (32/64), SPARC, ARM64, Hexagon, SystemZ.

- `/disasm` for disassembling the binary into relevant assembly.
Targets Supported: ARM, Thumb, x86 (32/64), MIPS (32/64), PPC (32/64), ARM64.

## Usage Instructions
1. Make a Bot Application on Discord Developer Portal. Copy the token and set it as an environment variable with the key `BOT_TOKEN`.
2. Install the application on your server. (Make sure it has `applications.commands` scope enabled.)
3. Clone this repository and enter into its root directory.
4. Run `poetry install` if you use poetry or `pip install .`.
5. Open `__main__.py` file from `devnull` directory in a text editor and update the `GUILDS` list with the id(s) of your own server(s). (The variable should be on top, under the imports.)
6. Save and run.

PRs/Issues are welcomed.

