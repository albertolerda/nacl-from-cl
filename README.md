# Use NaCl from Common Lisp using CFFI
NaCl is a popular cryptography library, known for the simple interface it provides.
Using CFFI, one can use the C library from the Common Lisp code.

To run the example you must have `libnacl.so` installed and then you can run
```bash
sbcl --eval '(ql:quickload :cffi)' --load package.lisp --load main.lisp
```
