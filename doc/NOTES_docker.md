# Docker Containerization

## Installation Notes

### Linux
On linux, follow the guide as you may want to add the docker group to your system to prevent
you from having to use `sudo` for everything. You will also need to download the different tools
like `swarm` `docker-compose` separately.

### MacOS
On MacOS, you may run into weird issues by installing through a web browser. At least MacOS 10.15.3
with docker 19.03 seemed to have fatal issues on launching. You will want to install the app
through `homebrew`:

```bash
brew cask install docker # Missing the app without the cask keyword
```

Then launch the app, give it permissions and sign in.

### Windows
You're on your own ;)

## Docker Command Overview

    * docker run [--name name] [-it] [--rm] [-d] [-P|-p] <container>
    you know what it be foo. `-it` will open an interactive tty for multiple commands. `--rm` will
    delete containers after the run is done. `-d` will detach the terminal session allowing you to perform
    other tasks while the container runs. `-P` will publish to random ports; see `docker port <container>` 
    to discover which ones exactly. `-p <publicport:privateport>` will allow you to specify where the ports
    are published. `--name` will name the container

    * docker stop {<containerID>|<containerNumber>} ...
    Stop a specific container from running. Used primarily for when a container is detached
    More than 1 argument may be supplied

    * docker start <containerID>

    * docker exec <containerID> <command>

    * docker top <containerID>

    * docker logs <containerID>

    * docker attach <containerID>
      ^P^Q is the escape sequence and ^c will terminate the process

    * docker inspect [--format='{{}}'] <containerID>
    List the details of the container in JSON format

    * docker rm {<contaienrID>} ...
    Remove a container that has stopped (see `docker ps -a` or `docker container ls`). More than 1
    argument may be supplied.

    * docker images
    List the images installed on your system

    * docker ps [-a]
    See what containers are running on your system. `a` switch will give you a container execution
    history

    * docker network [ls|inspect]
    `ls` lists the networks started by docker. `inspect <network` gives details about the network config

    * docker pull <user/container>
    pull down a docker repo from the registry

    * docker push <user/container>
    Push container to registry

    * docker commit <containerID> <name>:<version>

    * docker login
    Log into your dockerhub account through the command line

    * docker search <searchterm>
    Search the registry for a docker image directly from the command line

    * docker build [-t <user/containerName>]
    Build a container out of a docker file

## Docker Useful Commands

    * docker container prune
    Remove all exited containers

    * docker rm $(docker ps -a -q -f status=exited)
    Remove all exited containers. Good for general cleanup. `docker containr prune` achieves the same effect

## Docker-Compose Commands
For the most part, the syntax is the same as `docker`

    * docker-compose up [-d]
    Run the docker-compose.yaml in your current directroy. `-d` runs in detached mode

    * docker-compose ps
    Displayed running docker compositions

    * docker-compose run <serviceName> <command>
    Run services declared in our docker-compose.yml

## Docker-Compose yaml

    * build: .
    Build the docker container from the current directory instead of using an already made docker image

    * environment:
    Configure environment variables for your services


    







