.code

do_syscall PROC
	
	add rsp, 10h
	mov rax, [ rsp + 18h ]
	mov eax, [ rax ]
	mov r10, rcx
	syscall
	sub rsp, 10h
	ret

do_syscall ENDP

end