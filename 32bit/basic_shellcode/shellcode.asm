
xor eax, eax
cdq
push eax
push long 0x68732f6e
push long 0x69622f2f
mov esp, ebx
push eax
push ebx
mov exp, esp
mov al, 0x0b
int 0x80