# UniTaint

Quick PoC for a taint based attack on VMProtect

Takes a protected x64 binary, traces the vmprotected function with unicorn and taints the input using bea disassembler and a custom tainter

Tested on simple functions without any branches.

# Example

# Protected C Function

__declspec(dllexport) uint64_t DoXor(uint64_t a, uint64_t b) {
    return a ^ b;
}


# Tainted instructions during trace

T push r8 // 4FC0

T push rcx // 4F80

T push rdx // 4F70

T mov rbx, qword ptr [r13] // RSP 4DE0 0: 0 1: 4F70

T mov qword ptr [rsp + r14], rbx // RSP 4DE0 0: 4E58 1: 2222222222221111

T mov rbx, qword ptr [r13] // RSP 4DE0 0: 0 1: 4F80

T mov qword ptr [rsp + r14], rbx // RSP 4DE0 0: 4E38 1: 1111111111111111

T mov rbx, qword ptr [r13] // RSP 4DE0 0: 0 1: 4FC0

T mov qword ptr [rsp + r14], rbx // RSP 4DE0 0: 4E48 1: 777

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 5E 1: 4E58

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FF8 1: 2222222222221111

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 0 1: 4E58

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FF0 1: 2222222222221111

T mov r10, qword ptr [r13] // RSP 4DE0 0: 0 1: 4FF0

T mov r15, qword ptr [r13 + 8] // RSP 4DE0 0: 4F20 1: 4FF8

T not r10 // RSP 4DE0 0: 2222222222221111 1: DEADBEEF

T not r15 // RSP 4DE0 0: 2222222222221111 1: DEADBEEF

T and r10, r15 // RSP 4DE0 0: DDDDDDDDDDDDEEEE 1: DDDDDDDDDDDDEEEE

T mov qword ptr [r13 + 8], r10 // RSP 4DE0 0: 4FF8 1: DDDDDDDDDDDDEEEE

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 5D330000 1: 4E38

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FF0 1: 1111111111111111

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 808E31 1: 4E38

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FE8 1: 1111111111111111

T mov r11, qword ptr [r13] // RSP 4DE0 0: 5000 1: 4FE8

T mov rdx, qword ptr [r13 + 8] // RSP 4DE0 0: 2FCF8 1: 4FF0

T not r11 // RSP 4DE0 0: 1111111111111111 1: DEADBEEF

T not rdx // RSP 4DE0 0: 1111111111111111 1: DEADBEEF

T or r11, rdx // RSP 4DE0 0: EEEEEEEEEEEEEEEE 1: EEEEEEEEEEEEEEEE

T mov qword ptr [r13 + 8], r11 // RSP 4DE0 0: 4FF0 1: EEEEEEEEEEEEEEEE

T mov r10, qword ptr [r13] // RSP 4DE0 0: DDDDDDDDDDDDEEEE 1: 4FF0

T mov r15, qword ptr [r13 + 8] // RSP 4DE0 0: 4F20 1: 4FF8

T not r10 // RSP 4DE0 0: EEEEEEEEEEEEEEEE 1: DEADBEEF

T not r15 // RSP 4DE0 0: DDDDDDDDDDDDEEEE 1: DEADBEEF

T and r10, r15 // RSP 4DE0 0: 1111111111111111 1: 2222222222221111

T mov qword ptr [r13 + 8], r10 // RSP 4DE0 0: 4FF8 1: 1111

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 2A220000 1: 4E58

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FF0 1: 2222222222221111

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 4A00 1: 4E38

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FE8 1: 1111111111111111

T mov r10, qword ptr [r13] // RSP 4DE0 0: 1111 1: 4FE8

T mov r15, qword ptr [r13 + 8] // RSP 4DE0 0: 4F20 1: 4FF0

T not r10 // RSP 4DE0 0: 1111111111111111 1: DEADBEEF

T not r15 // RSP 4DE0 0: 2222222222221111 1: DEADBEEF

T and r10, r15 // RSP 4DE0 0: EEEEEEEEEEEEEEEE 1: DDDDDDDDDDDDEEEE

T mov qword ptr [r13 + 8], r10 // RSP 4DE0 0: 4FF0 1: CCCCCCCCCCCCEEEE

T mov r10, qword ptr [r13] // RSP 4DE0 0: CCCCCCCCCCCCEEEE 1: 4FF0

T mov r15, qword ptr [r13 + 8] // RSP 4DE0 0: DDDDDDDDDDDDEE00 1: 4FF8

T not r10 // RSP 4DE0 0: CCCCCCCCCCCCEEEE 1: DEADBEEF

T not r15 // RSP 4DE0 0: 1111 1: DEADBEEF

T and r10, r15 // RSP 4DE0 0: 3333333333331111 1: FFFFFFFFFFFFEEEE

T mov qword ptr [r13 + 8], r10 // RSP 4DE0 0: 4FF8 1: 3333333333330000

T mov rbx, qword ptr [r13] // RSP 4DE0 0: 4 1: 4FF8

T mov qword ptr [rsp + r14], rbx // RSP 4DE0 0: 4E68 1: 3333333333330000

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: EE250AB7 1: 4E68

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FE0 1: 3333333333330000

T mov r11, qword ptr [r13 + 8] // RSP 4DE0 0: EEEEEEEEEEEEEE00 1: 4FE0

T add rsi, r11 // RSP 4DE0 0: 23523 1: 3333333333330000

T mov qword ptr [r13 + 8], rsi // RSP 4DE0 0: 4FE0 1: 3333333333353523

T cmp r8, r11 // RSP 4DE0 0: 1400DCD67 1: 3333333333330000

// Not implemented opcode : cmp

T push r8 // 4DD8

T mov rbx, qword ptr [r13] // RSP 4DE0 0: 0 1: 4FE0

T mov qword ptr [rsp + r14], rbx // RSP 4DE0 0: 4DF0 1: 3333333333353523

T cmp r11, rsi // RSP 4DE0 0: 3333333333330000 1: 3333333333353523

// Not implemented opcode : cmp

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 0 1: 4E48

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FD0 1: 777

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 8000000 1: 4DF0

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4FB8 1: 3333333333353523

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 3F260AB7 1: 4E68

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4F90 1: 3333333333330000

T mov r15, qword ptr [rsp + r14] // RSP 4DE0 0: 35D7 1: 4E58

T mov qword ptr [r13], r15 // RSP 4DE0 0: 4F80 1: 2222222222221111

T cmp r11, rsi // RSP 4DE0 0: 3333333333330000 1: 3333333333353523

// Not implemented opcode : cmp

T pop rdx //4F80 V: 2222222222221111

T pop rcx //4F90 V: 3333333333330000

T pop rax //4FB8 V: 3333333333353523

T pop r8 //4FD0 V: 777

Result (RAX) = 3333333333353523

Result (R8)  = 777


# Translated instruction into C code

```c
uint64_t S_0;

uint64_t S_1;

uint64_t S_2;

uint64_t S_3;

uint64_t S_4;

uint64_t S_5;

uint64_t S_6;

uint64_t S_7;

uint64_t S_8;

uint64_t S_9;

uint64_t S_10;

uint64_t S_11;

uint64_t S_12;

uint64_t S_13;

uint64_t S_14;

uint64_t S_15;

S_0 = r8;

S_1 = rcx;

S_2 = rdx;

rbx = S_2;

S_3 = rbx;

rbx = S_1;

S_4 = rbx;

rbx = S_0;

S_5 = rbx;

r15 = S_3;

S_6 = r15;

r15 = S_3;

S_7 = r15;

r10 = S_7;

r15 = S_6;

r10 = ~r10;

r15 = ~r15;

r10 = r10 & r15;

S_6 = r10;

r15 = S_4;

S_7 = r15;

r15 = S_4;

S_8 = r15;

r11 = S_8;

rdx = S_7;

r11 = ~r11;

rdx = ~rdx;

r11 = r11 | rdx;

S_7 = r11;

r10 = S_7;

r15 = S_6;

r10 = ~r10;

r15 = ~r15;

r10 = r10 & r15;

S_6 = r10;

r15 = S_3;

S_7 = r15;

r15 = S_4;

S_8 = r15;

r10 = S_8;

r15 = S_7;

r10 = ~r10;

r15 = ~r15;

r10 = r10 & r15;

S_7 = r10;

r10 = S_7;

r15 = S_6;

r10 = ~r10;

r15 = ~r15;

r10 = r10 & r15;

S_6 = r10;

rbx = S_6;

S_9 = rbx;

r15 = S_9;

S_10 = r15;

r11 = S_10;

rsi = rsi + r11;

S_10 = rsi;

S_11 = r8;

rbx = S_10;

S_12 = rbx;

r15 = S_5;

S_13 = r15;

r15 = S_12;

S_14 = r15;

r15 = S_9;

S_15 = r15;

r15 = S_3;

S_1 = r15;

rdx = S_1;

rcx = S_15;

rax = S_14;

r8 = S_13;
´´´

# Compile and optimize with Clang and O3

```c
#include <stdio.h>
#include <stdint.h>

	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;	
	uint64_t rdx;
	uint64_t rbp;
	uint64_t rsp;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;

__declspec(dllexport) void RXor() {
uint64_t S_0;
uint64_t S_1;
uint64_t S_2;
uint64_t S_3;
uint64_t S_4;
uint64_t S_5;
uint64_t S_6;
uint64_t S_7;
uint64_t S_8;
uint64_t S_9;
uint64_t S_10;
uint64_t S_11;
uint64_t S_12;
uint64_t S_13;
uint64_t S_14;
uint64_t S_15;

S_0 = r8;
S_1 = rcx;
S_2 = rdx;
rbx = S_2;
S_3 = rbx;
rbx = S_1;
S_4 = rbx;
rbx = S_0;
S_5 = rbx;
r15 = S_3;
S_6 = r15;
r15 = S_3;
S_7 = r15;
r10 = S_7;
r15 = S_6;
r10 = ~r10;
r15 = ~r15;
r10 = r10 & r15;
S_6 = r10;
r15 = S_4;
S_7 = r15;
r15 = S_4;
S_8 = r15;
r11 = S_8;
rdx = S_7;
r11 = ~r11;
rdx = ~rdx;
r11 = r11 | rdx;
S_7 = r11;
r10 = S_7;
r15 = S_6;
r10 = ~r10;
r15 = ~r15;
r10 = r10 & r15;
S_6 = r10;
r15 = S_3;
S_7 = r15;
r15 = S_4;
S_8 = r15;
r10 = S_8;
r15 = S_7;
r10 = ~r10;
r15 = ~r15;
r10 = r10 & r15;
S_7 = r10;
r10 = S_7;
r15 = S_6;
r10 = ~r10;
r15 = ~r15;
r10 = r10 & r15;
S_6 = r10;
rbx = S_6;
S_9 = rbx;
r15 = S_9;
S_10 = r15;
r11 = S_10;
rsi = rsi + r11;
S_10 = rsi;
S_11 = r8;
rbx = S_10;
S_12 = rbx;
r15 = S_5;
S_13 = r15;
r15 = S_12;
S_14 = r15;
r15 = S_9;
S_15 = r15;
r15 = S_3;
S_1 = r15;
rdx = S_1;
rcx = S_15;
rax = S_14;
r8 = S_13;
}

int main() {
	rcx = 0x1111222200000000;
	rdx = 0x0000000033334444;

	RXor();
	printf("RXor: %016llX\n", rax);

	return 0;
}
```c

# Output LLVM IR

```
; Function Attrs: norecurse nounwind uwtable
define dso_local void @_Z4RXorv() local_unnamed_addr #0 {
  %1 = load i64, i64* @rcx, align 8, !tbaa !2
  %2 = load i64, i64* @rdx, align 8, !tbaa !2
  %3 = xor i64 %2, %1
  store i64 %3, i64* @r10, align 8, !tbaa !2
  store i64 %3, i64* @r11, align 8, !tbaa !2
  %4 = load i64, i64* @rsi, align 8, !tbaa !2
  %5 = add i64 %4, %3
  store i64 %5, i64* @rsi, align 8, !tbaa !2
  store i64 %5, i64* @rbx, align 8, !tbaa !2
  store i64 %2, i64* @r15, align 8, !tbaa !2
  store i64 %2, i64* @rdx, align 8, !tbaa !2
  store i64 %3, i64* @rcx, align 8, !tbaa !2
  store i64 %5, i64* @rax, align 8, !tbaa !2
  ret void
```
