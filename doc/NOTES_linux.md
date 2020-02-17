# Linux Notes in Preparation for Interviews

A cheatsheet of topics compiled in preparation of linux
focused interviews. Primarily to refresh knowledge and
touch upon more advanced concepts.

### Resources

Everything you need to know about Linux kernel.
  https://cse.yeditepe.edu.tr/~kserdaroglu/spring2014/cse331/termproject/BOOKS/ProfessionalLinuxKernelArchitecture-WolfgangMauerer.pdf

A good introduction to Bash:
  https://guide.bash.academy/expansions/


### Interview Notes

### Docker

  **Containers**
    Share the host kernel, use kernal ability to group processes, ensure isolation through namespaces

  **Language**
    used to rely on LXC library now has it's own lib written in GO

  **Arch**
  Docker Engine essentially combines namespaces, control groups, and UnionFS
  into a wrapper called a container format. Default is libcontainer.

    * namespaces provide isolated workspaces. 

    * Control group for system resource allocation/isolation. cgroups limit processes
      to specific resources.

    * UnionFS for file system. Creates lightweight and fast layers

  Security is provided for with AppArmor, Seccomp, Capabilities

    * AppArmor (default Kernel Security Module) 
      Allows restriction of program capabilities with per-program profiles

    * Seccomp (Kernel Security Facility) 
      Filters syscalls issued by programs

    * Capabilities performs permissions check to avoid vulnerabilities in SetUID programs

### Linux

  Current stable kernel 5.5.2
  Bionic Beaver (Ubuntu 8 currnetly on 4.15 - 5.0/5.3)

  **Kernel**
    Intermediary layer between hardware and software. 
    Can be viewed as a Low-Level Driver, Enhanced Machine, Resource Manager, Library
    Two Paradigms: microkernels, **monolithic kernels** (Linux supplements with DKMS (Dyn Kern Mod Sup)

  **Processes**
    Kernel starts the `init` process that is the mother of all others. `pstree`

  **Namespaces**
    Partition resources so sets of processes see different sets of resources.

    There are seven kinds of namespaces (as of 4.10)
      * Mount
        On creation, all mounts copied from current mount NS. Mounts will not propogate
        between mount NSes after copy.

      * PID
        PID NSes are nested. Meaning original PID NS will be able to see all processes
        within other PID NSes but with a different PID. The first process in a new PID
        NS is given PID 1 and treated like the `init` process

      * Network
        Network NS virtualize the network stack. Only loopback IF exists when first created
        Each network IF exists in exactly 1 NS and can be moved between Network NSes.
        Each namespace has it's own set of IP addresses, routing table, sockets, firewall, etc.

      * IPC (Inter-Process Communication)
        Isolates Shared memory from other IPC namespaces. Each process can use same shared
        mem identifiers to refer to two different regions of memory

      * UTS (Unix Time Sharing)
        Each process can have a separate copy of the hostname/domain name so it can be set
        to something different without effecting the rest of the system.

      * UID (User ID)
        UID NSes are nested. Each new NS is a child of it's creator User NS.
        Contains a table converting UIDs from the container's point of view to the system's view.

      * cgroup (Control Group)
        Enables hiding of the identity of control groups of which the process is a member.

    Each process is associated with namespaces and can only see the resources attached
    to those namespaces (or descendant namespaces). 

    See /proc/<PID>/ns/


  **Of Interest**
    
    * setuid, setgid, sticky (writable only by owners)
       `drwsrwsrwt`


    * iptables
        firewall management

### Load Balancing

  * L4-LBs (Layer 4 Load Balancer) TCP
    Balances at packet/segment level.
    Physical Implementation (ASIC)
    Faster than L7-LB due to no packet manipulation/inspection

    1. Pass Through LB
      Does not terminate TCP connection, but allows the connection to continue to the backend with connection tracking.
      Not subject to TCP Congestion Control. 

    2. Termination LB
      Terminates the TCP Connection (Responds to SYN with ACK) when recieving payload. Then opens connection to backend

    Easy to trace packets as they go through 1-to-1.

  * L7-LBs (Layer 7 Load Balancer) HTTP(S)
    Typically implemented in software. Flexible and scaleable.
    Acts as a proxy between external router and backend services.
    Packet arrives and is assembled, processed, and manipulated - Time Overhead
    Able to inspect packets and balance based on content (i.e. Video processing vs Text Processing)
    Can terminate SSL by having CA Certs installed. Places encrypt/decrypt load on balancer instead of backend.
    Stickiness.
    Richer Logging.
  

### OSI Layers:

  7 - Application   End User. Browsers, Skype, Outlook, Office, etc.
                    HTTP, FTP, IRC, SSH, DNS
  6 - Presentation  Syntax. Encryption/Decryption. Data formatting and translation
                    SSL, SSH, IMAP, FTP, MPEG, JPEG
  5 - Session       Manages the connections between two machines. Initiates, maintains, terminates.
                    Synch & Send to port, reconnection, and authentication
                    APIs, Sockets
  4 - Transport     End-to-End (Segment). Manages delivery and error checking of data packets (size, sequencing, transfer)
                    TCP/UDP
  3 - Network       Packets. Delivering layer 2 frames to intended dest based on IP. Routers
                    IP, ICMP, IPSec, IGMP
  2 - Data Link     Frame transmission, MAC & LLC for node-to-node flow control and correcting layer 1 errors
                    Ethernet, PPP, Switch, Bridge
  1 - Physical      Signal Transmission/ Electo-Optical Transmission of bits
                    Specifications on pin layouts, voltages, cabling, frequencies, etc
                    Hubs, cables, repeaters, adapters, modems

### Programming

  **MEMORY**

  When a program is executed, the kernel allocates memory for it:
  
    ```bash
    _______________________ 000000000
    |       Text          | Actual Instructions/Static Data
    |_____________________|
  A |       Heap  |       | All user alloc memory (Grows from low to high) malloc(), free()
  r |_____________v_______|
  e |     (unalloc)       |
  n |_____________________|
  a .                     .
    .                     .
    .                     .
  S ______________________|
  t |     (unalloc)       |
  a |_____________________|
  c |       Stack ^       | Function states saved on stack (From high to low)
  k |_____________|_______|
                            C00000000
    ```
    brk() is called to request additional memory from kernel.
    Check /proc/<pid>/maps to view current mem of a process.

    Memory Bugs:
      1. "Freed" memory still in use. When reallocated, two processed will be looking at same chunk
      2. Trampling over the memory preamble
      3. Usage of unallocated memory within the Arena but outside the Heap
      4. Usage of memory outside the Arena and scope results in SIGSEGV
      5. Corrupted Stack (VERY DIFFICULT TO FIND). Local vars, regs, prev frams, return addresses
         are corrupted. Impossible to debug conventionally, need something like `libsafe`

      Techniques:
      1. `MALLOC_CHECK_` env variable can be set to `1` or `2` to enable debugging
      2. Electric Fence program used within GDB
      3. libsafe to catch stack frame boundary violations
      4. debauch, memprof
    

### API

  URI (uniform resource identifier)
  Idempotence - Can perform the same call repeatedly without changing the result.
      PUT and DELETE methods are idemp.
      GET, HEAD, OPTIONS, TRACE methods are safe too (idemp.)

  CRUD:
    POST/Create
    GET/Read
    PUT/Update(Rep)
    PATCH/Update(Mod)
    DELETE/delete

  HTTP Requst
    GET /my/resource.html HTTP/1.1

  HTTP Response
    HTTP/1.1 200 OK \r\n
    Content-Type: text/ html; charset=xxx\r\n
    Date: xx xx xx xx
    Content-Length: xxxx\r\n
    Connection: Keep-Alive\r\n

  Essentially a design for web APIs that exploit the architecture of the web to their advantage 
  **REST**
    1. Client-Server
      Separate user interface from data storage

    2. Stateless
      Each request must contain all info to process request

    3. Cacheable
      Each request to be labelled Cacheable/Non-cacheable.

    4. Uniform Interface
      Identification of resources; manipulation of resources through 
      representation; self-descriptive message; hypermedia as the engine of appication state
      
    5. Layered System
      Hierarchical layers - contrain components behavior such that each cannot see beyond the 
      immediate layer with which they are interacting

    6. Code on Demand (optional)
      Allow clients function to be extended by downloading and executing code (scripts).
      Reduces the number of features required to be pre-implemented


### Questions:

  1. What is the most interesting thing you've learned about during your time here?

  2. The Weirdest problem you've ever had to solve?

  3. One piece of knowledge or tool that has proved invaluable to your day to day?

  4. How code intensive is the job?

  5. Every job has fun and interesting aspects but also the slower more painstaking task.
     What are the highlights and lowlights of your job?


### BASH

  Globs:  *           (zero or more chars)
          ?           (one char)
          [char]      (set of chars)
          [[:class:]] (class of characters)

  Redirection: 
    FD0 input stream
    FD1 standard output
    FD2 standard error

    1>  2>  >   <       standard i/o redirect

    2>&1                Point FD2 to FD1

    &>                  Redirect both FD1 and FD2 to same place

    <<[-] EOF           Here Doc

    <<<                 Here String

    exec [x]>&[y]       Create [x] if it doesn't exist

    [x]>&-              Close [x]

    [x]>&-[y]           Copy [y] to [x] and close [y]

    [x]<>file           [x] for reading and writing to file (sockets)

  Parameter Expansion:  ${}
    ${time%.*}  Delete the period and all characters following from expanded var
    ${time#*.}  Delete all characters up to and including the period after expansion
    ${PATH//:/, } Replace every `:` char in PATH with `,`

  Command Substitution: $()

  Positionals:
    ${0}    The name of the process
    ${1}    1st argument
    $*      Expands all positionals as a list
    $#      number of positional parameters
    $?      Exit code of the last command the executed (0=success)
    $-      expands all option flags for the shell
    $$      The PID of the shell parsing the code
    $!      Expands the PID of the last process that was started in the background
    $_      Expand last arg of previous command

  Arrays:
    =( )        Space separated array
    +=( )       Append to array
    ${var[0]}   Access array element0
    ${var[@]}   Expand all array elements as distinc args (Change IFS to modify delimiter)
                ex. `( IFS=","; echo "&{var[@]}"; )`

  Conditionals:
    [ ]     Test command (Obsolete) (Spaces required)
    [[ ]]   New test, incompatible with sh 
            =~ regex test
            capable of && and ||
            -f    file exists
            -d    dir exists
            -eq, -ne, -lt, -le, -gt, -ge for number
            =, <, > for string`
    (())    Performs arithmetic. Returns exit code of zero (true) if nonzero)
    ()      Run command in subshell and return exit code.

  Flow Control:
    ```bash
    # IF Statements
    if [ exp ] ; then
    elif
    else
    fi 

    # ex.
    if rm hello.txt; then
      echo "Success!"
    else
      echo "Failure" >&2; exit;
    fi
    ```

    ```bash
    # For statement
    for (( i=1; i<5; i++ )); 
    do
      echo $i
    done

    for i in 1 2 3 4 5
    do
      echo $i
    done

    # While Statement
    while check; do
    done

    # Case statement
    case $animal in
      horse | dog | cat) echo -n "four";;
      man | kangaroo ) echo -n "two";;
      *) echo -n "unknown";;
    esac

    # Select generates a menu
    select fname in *;
    do
      echo "you picked file: \($REPLY\)
      break;
    done

    ```






