# SVF Failure Example

Included in the repo is the following:
- heap-exfil-3/ - The entire user-space example we have been working with thus far
- simple-example/ - A small subset of heap-exfil focusing in on the point of failure for SVF
  - build/ - the LLVM for the simple example, compiled with `clang -g -O0 -emit-llvm -c x.c -o x.ll`, then linked with `llvm-link 1.ll 2.ll -o prog.ll`
- prog-svf.txt - Output from SVF.

Output shared comes from command `wpa -ander -svf-main -print-all-pts prog.ll`. I tried a variety of options (-flow-bg, -ctx, etc) without more success,
so I won't iterate them all here.

The simple example creates a pool of memory `zc_on_heap`, and returns a pointer into that memory pool using the function `zc_get_buffer()`. We are 
looking for `zc_on_heap` to be a part of the points-to set for `buf2`. It seems to me that SVF, at least using the commands I have tried, was not able
to make that relation, only relating `buf2` to the `malloc` call in 1.c.
