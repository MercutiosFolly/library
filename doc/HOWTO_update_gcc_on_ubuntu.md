# HOWTO: Update gcc on Ubuntu
```
@file    HOWTO_update_gcc_on_ubuntu.md
@author  James Hind
@date    10/02/2016
@ver     1.0
```

## Table of Contents
  1. [Overview](#Overview)
  2. [Issues](#Issues)
  3. [Explaination](#Explaination)
  4. [Solution](#Solution)

## Overview

  Use a different gcc/g++ than the one installed by default

## Issues
  - Need support for newer language features (c++17 for example)
  - You've install newer gcc but CMake fails with:
  ```
  -- The C compiler identification is GNU 8.4.0
  -- The CXX compiler identification is unknown   <------- This specifically means the test program failed to compile

    The C++ compiler
                                                                                          
      "/usr/bin/gcc-8"
                                                                                                                                                                                                              
    is not able to compile a simple test program.
    It fails with the following output:                                                                                                                                                                                                                                                                                                                  
  ```

## Explaination

## Solution

1. Install newer compiler. It is important the you install the g++ version alongisde or CMake will be unable to compile CXX
  ```bash
  sudo apt-get install gcc-8 g++-8
  ```

2. Update the symbolic links used by the systm (they are in `/usr/bin` so best practice is not to change them manually)

  ```bash
  sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-8 80 --slave /usr/bin/g++ g++ /usr/bin/g++8
  ```
