# hemato-encephalic compiler kit (heck)

The _hemato-encephalic compiler kit_ is a WIP compiler for the programming language _brainfuck_ (to be extended to its derivates).

Heck compiles brainfuck code to _hemato-encephalic byte code_ (hebc), which can be rapidly translated to x86_x64 machine code, without any external compilers, assemblers, or linkers. The result is a compiler that copes well both with tight loops and huge program files.

The implementation is currently limited to x86_64 \*nix that support the _mprotect_ syscall and has only been tested on Linux. The tape has a fixed size of 1 GiB minus enough buffer to catch an out-of-bounds memory pointer with no impact on performance; the head starts at the middle to provide a double-ended tape. The cells are 8 bits wide and use modular arithmetic.
