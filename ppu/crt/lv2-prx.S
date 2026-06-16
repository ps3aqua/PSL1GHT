.align 2
.section ".sys_proc_prx_param","a"
	.long 0x28            # header size
	.long 0x1b434cec      # magic
	.long 2               # header version
	.long 0               # sdk version
	.long __libentstart   # exports start
	.long __libentend     # exports end
	.long __libstubstart  # imports start
	.long __libstubend    # imports end
	.byte 1               # minor version
	.byte 1               # major version
	.short 0              # padding
	.long 0               # padding
