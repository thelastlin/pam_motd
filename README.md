# pam_motd
Porting Debian flavor of pam_motd (a part of Linux-PAM) to OpenPAM used by FreeBSD, macOS, and some Linux distros.

# Build&Install

```shell
$ mkdir build && cd build
$ cmake .. && make 
$ sudo make install # Root priviledge required.
```