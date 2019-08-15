file    HOWTO_tmux-256-color.md
author  James Hind
date    10/02/2016
ver     1.0

## Table of Contents
  1. [Overview](#Overview)
  2. [Issues](#Issues)
  3. [Explaination](#Explaination)
  4. [Solution](#Solution)

## Overview

  This HOWTO explains how to get full color support in tmux

## Issues
    - tmux prompt is colorless
    - tmux prompt has no git information
    - vim colorschemes do not load or load incorrectly

## Explaination
  The reasons for these issues is the tmux default terminal is not
  using (or does not support) the 256 color palette required. For
  the prompt issue in particular, the default `.bashrc` for ubuntu
  contains the following:

  ```bash
  case "$TERM" in
      xterm-color|*-256color) color_prompt=yes;;
  esac
  ```
  Which is used to configure the prompt ($PS1) later on. As you
  can see, it checks if the current terminal supports 256 color.

## Solution
**ATTENTION:** Make a backup of the files to be edited or double check
that you are using the append operator `>>`

  1. Configure tmux to use a 256 color terminal (You can deduce
     which to use by running `echo $TERM` in your normal terminal that
     supports color)

     ```bash
     echo "set -g default-terminal \"screen-256color\"" >> ~/.tmux.conf
     ```

  2. Launch tmux with the `-2` option. This can be aliased in the `.bashrc`

    ```bash
    echo "alias tmux=\'tmux -2\'" >> ~/.bashrc
    source ~/.bashrc
    ```
