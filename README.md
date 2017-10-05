
## Overview

Adun is a PoC tool used to inject shellcode to the processes. This technique might be used by malicous programs to: hide it's process/ infect other processes on the system/ migrate to other process. In this moment Audn uses 3 techniques of injecting shellcode, which are: direct change of execution flow, spawning a process, spawning a thread. The last one might be the most interesting, as it doesn't harm process we inject to, and also makes the running shellcode well hidden. The whole injection is based on ptrace, and on most systems doesn't require root priviledges.  Also the process/thread creation is done on raw syscalls which means, that the process we inject to doesn't even have to be linked to libc. 


## Usage

A quick demo of usage:

![demo](demo.gif)

```
./inject PID [-d -p]

```

There are 3 available injection techniques:
* Direct shellcode execution in process - the 'victim' process execution will jump to shellcode 
* Spawnning new process 
* Spawning new thread

You can choose technique by giving parameter -d to use direct or -p to use process, the default technique is thread.

## Building
```
git clone https://github.com/Srakai/Adun
cd Adun
make
```

## Author

* @Srakai

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE.md file for details
