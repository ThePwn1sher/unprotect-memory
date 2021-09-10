# UnprotectMemory

Tool which decrypt a password encrypted with `CryptProtectMemory` using `CRYPTPROTECTMEMORY_SAME_PROCESS`.

## Compilation

1. Open project in Visual Studio 2019
2. Project > `unprotect` Properties > Configuration Properties > Advanced > Use of MFC: **Use MFC in Static Library**
3. Ctrl+Shift+B

## Usage

```
.\unprotect.exe
Usage: .\unprotect.exe PROCESS_PID PASSWORD_HEX
Example: .\unprotect.exe 5820 eece029075166d89496439c46c125b14bcc571884a1370c834d742c79fac2c4f
```

* `PROCESS_PID`: PID of the process that encrypted the password.
* `PASSWORD_HEX`: Encrypted blob in hexadecimal format.

## Acknowledgments

[@skelsec](https://github.com/skelsec/pypykatz) for [Pypykatz](https://github.com/skelsec/pypykatz/) (and his [shellcode](https://github.com/skelsec/pypykatz/blob/master/pypykatz/commons/readers/local/process.py))
