## Simple Trampoline hooking PoC

### What is this?
This PoC shows how easy it is to hook the functions we need. \
This method is used to hook a function by redirecting its calls to a custom function. \
In this concept, only data is intercepted and subsequently written to a file, for the convenience of debugging and analysis in memory, for example, a mapped DLL.

### How's this works?
- It takes the target function, an original prologue, and the hook function as input.
- It temporarily changes the memory protection of the target function to make it writable.
- It creates a trampoline by copying the initial bytes of the original function and modifying it to jump back to the target function.
- It saves the original prologue and replaces it with a jump to the hook function.
- It restores the original memory protection of the target function.
- It returns a pointer to the trampoline function.

### Features:
- [x] CreateRemoteThread & WriteProcessMemory & VirtualAlloc(-Ex) & NtWriteVirtualMemory & LoadLibraryA hooking
- [x] Recording the most important data that the original function transmits
- [x] Auto dump and save written image into the process

### How to use?
- Inject hooker into target process before invoke EP
- After calling the calls we need, the Log.txt file will be created
- Go to the necessary addresses in the memory of the target or child process

### For correct using hook CreateRemoteThread you need to set BP in CreateRemoteThreadEx (call)
![pic](https://i.imgur.com/xKyEaE6.png)

### After hit BP you get address of your mapped image into memory
![pic](https://i.imgur.com/fVbwT2Y.png)

### Log example:
![pic](https://i.imgur.com/ZzGJXE1.png)

contributions are welcome.

### Credits:
[@notcpuid](https://github.com/notcpuid/)
[@thomas-0xd1](https://github.com/thomas-0xd1/)
