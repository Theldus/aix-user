	.file	"hello_world.c"
	.toc
	.csect .text[PR],5
	.align 2
	.lglobl .strtoimax
	.csect strtoimax[DS]
strtoimax:
	.long .strtoimax, TOC[tc0], 0
	.csect .text[PR],5
.strtoimax:
	mflr 0
	stw 0,8(1)
	stw 31,-4(1)
	stwu 1,-64(1)
	mr 31,1
	stw 3,88(31)
	stw 4,92(31)
	stw 5,96(31)
	lwz 5,96(31)
	lwz 4,92(31)
	lwz 3,88(31)
	bl .__strtollmax
	nop
	mr 11,4
	mr 10,3
	mr 3,10
	mr 4,11
	addi 1,31,64
	lwz 0,8(1)
	mtlr 0
	lwz 31,-4(1)
	blr
LT..strtoimax:
	.long 0
	.byte 0,0,32,97,128,1,3,1
	.long 0
	.long LT..strtoimax-.strtoimax
	.short 13
	.byte "strtoimax[DS]"
	.byte 31
	.align 2
	.csect _helloworld.rop_[RO],4
	.align 2
LC..0:
	.byte "Output: Hello, World! <placeholder>"
	.byte 0
	.toc
LC..1:
	.tc LC..0[TC],LC..0
	.csect .text[PR],5
	.align 2
	.globl main[DS]
	.globl .main
	.csect main[DS]
main:
	.long .main, TOC[tc0], 0
	.csect .text[PR],5
.main:
	mflr 0
	stw 0,8(1)
	stw 31,-4(1)
	stwu 1,-64(1)
	mr 31,1
	lwz 3,LC..1(2)
	bl .puts
	nop
	li 9,0
	mr 3,9
	addi 1,31,64
	lwz 0,8(1)
	mtlr 0
	lwz 31,-4(1)
	blr
LT..main:
	.long 0
	.byte 0,0,32,97,128,1,0,1
	.long LT..main-.main
	.short 8
	.byte "main[DS]"
	.byte 31
	.align 2
_section_.text:
	.csect .data[RW],4
	.long _section_.text
