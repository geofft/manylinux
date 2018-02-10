#set follow-fork-mode child
set detach-on-fork off
set non-stop on

#python
#def exit_handler(event):
#    if not any(i.threads() for i in gdb.inferiors()):
#        gdb.execute("quit")
#
#gdb.events.exited.connect(exit_handler)
#end

catch signal SIGSEGV
commands
  silent
  if $_siginfo.si_code != 1
    continue
  end
  if $_siginfo._sifields._sigfault.si_addr != $rip
      continue
  end
  if $rip == 0xffffffffff600000
    set $syscall = 96
  else
    if $rip == 0xffffffffff600400
      set $syscall = 201
    else
      if $rip == 0xffffffffff600800
        set $syscall = 309
      else
        continue
      end
    end
  end
  set $rdx = $rsi
  set $rsi = $rdi
  set $rdi = $syscall
  set $rip = syscall
  signal 0
end

run
