![GitHub release (latest by date)](https://img.shields.io/github/v/release/Silva97/pei)
[
  ![Build status](https://travis-ci.com/Silva97/pei.svg?branch=master)
](https://travis-ci.com/github/Silva97/pei)
# pei - PE Injector
Command-line tool for inject code and manipulate PE32 (32-bit) and PE32+ (64-bit) executables.  

With `pei` you can:
- Display informations about the executable like COFF header, sections and more.
- Get individual values from fields of the headers to manipulate the values by scripts. Example:  
  `pei get test.exe optional.entry_point '0x%x'` - Will print `0x12345`
- Edit individual fields. Example:  
  `pei edit test.exe optional.entry_point = 0xabcd`
- Manipulate memory access permissions to sections of the executable.
- Find zeroed blocks of data on the sections of the executable.
- Inject code to be executed before the OEP of the executable.

## Compilation and installation
Just run the commands below to compile the project:
```bash
git clone https://github.com/Silva97/pei
cd pei
make
```

Done! `pei` has no dependencies other than libc. To install, just run:
```bash
sudo make install
```

If you doesn't want more `pei` on your system, run `sudo make uninstall`. :(

# How it injects code
With `pei` you can specify the section to inject the code or leave the tool to select the
section with the biggest zeroed block of data. You can run `pei z test.exe` to gets a list of
blocks from all sections of the executable.  
The entry point of the executable will be updated to point the injected code, and at end of the
code a [absolute jump] to OEP (Original Entry Point) will be added.

**Note**: After `pei` writes the code on the section, these as been marked with permission to
execute code and the dynamic base of the executable will be disabled.

# Basic Usage
```bash
pei [options] <operation> <executable> [argument]
```

|   Argument   | Descrption                                                       |
| :----------: | :--------------------------------------------------------------- |
| `operation`  | First letter or full name of the operation to do with executable |
| `executable` | PE32 or PE32+ executable                                         |

**Note**: You can run `pei -h` to get full help about usage of the tool.  



### Examples
```bash
pei s test.exe         # Show general informations about the executable
pei -vs0 s test.exe s  # Show first section in verbose mode
pei s test.exe d       # Show all data directories
pei s test.exe gc      # Show general informations and COFF header

pei g test.exe optional.entry_point '%x'         # Entrypoint in hexadecimal
pei g test.exe optional.iat.virtual_address '%x' # Virtual address of IAT structure
pei g test.exe section.0.name '%s'               # Name of the first section

pei e test.exe section.0.name = .code            # Edit the name of the first section
pei e test.exe optional.entry_point = 0xaabb1234 # Edit the entry point

# Inject code from `payload` raw binary file to `test.exe` entry point
pei -f payload i test.exe
```

**Tip 1**: For see the name of the fields to use with `get` operation, just use `show` operation
to see all fields of the given structure. Example:

```bash
pei show test.exe o
```

After run the command above, you can see all (except data directories) fields of the optional header.  

**Tip 2**: Remember that the data directories are in the optional header.


[absolute jump]: https://en.wikipedia.org/wiki/JMP_(x86_instruction)
