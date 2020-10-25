# Docker: Getting Started Guide
This is an introductory guide to docker and its family of tools. It should equip you with enough
knowledge to work comfortably on small projects. As always, if there are any questions: please
refer to the [docker documentaion] (https://docs.docker.com/).

## Table of Contents
1. [Installation](#Installation)
2. [Introduction](#Introduction)
3. [The Basics](#The-Basics)
4. [Dockerfile](#Dockerfile)
5. [Docker-Compose](#Docker-Compose)

## Installation
Refer to  [Install Docker on windows](https://docs.docker.com/docker-for-windows/install/)
for installation instruction on Windows. Please read the page carefully as there may
be additional step such as enabling hyper-V.

## Introduction
Docker is probably one of the most well known containerization softwares out there. Essentially,
it leverages kernel features to run processes in an isolated environment. Containers are not
to be confused with VMs. Although, at first glance, they appear similar containers provide 
a way to _virtualize_ the OS so you can run multiple containers on a single OS instance. 
VMs, on the other hand, virtualize the hardware and run multiple OS instances. This leads
to VMs having a lot of overhead and wasted resources while containers are quicker and more
lightweight. VMs are treated like "pets", while continers are "livestock"

For any docker commands, you can run the `--help` option to get more information:
```bash
docker run --help
docker container stop --help
docker network inspect --help
```

## The Basics
If you search on [docker hub](hub.docker.com) you will find a registry of what are called
`docker images` these images range from officially maintained Ubuntu images to minor images
put together by users like you or me. We can pull down images, much like we pull down
git repos:

`docker pull hello-world`

This  searches to docker registry for the `hello-world` image (try `docker search hello-world`to locate
the image before pulling). Note that images not prefixed by a user name (ex. johndoe/hello-world) 
are "official" images.

Check that the pull was successfull by seeing the images you have locally:

`docker image ls`

You can run images with:

`docker run [options] <image> <command to send to image>`

```bash
# examples:
docker run hello-world
docker run busybox echo "hello from busybox"
```

You don't have to pull the images first. If you try to run an image that you don't have locally,
docker engine will search for the image in the registry.

You can see what containers you have on your system by using the `docker ps` or `docker contianer ls`
commands. The `-a` flag will show _all_ containers, not just the currently running ones:

```bash
docker container ls -a
docker ps
```

If you want to run a container (busybox in this example) interactively:

`docker container run -it busybox bash`

This will give you a command prompt on the container. The `-i` flag tells docker you want to 
run the container interactively. The `-t` flag maeans you want a TTY (as opposed to running a
script interactively). Bash is the command you are telling the busybox container to run.
Play around all you want the `exit` or `ctrl-d` to quit. Once a container is exited, all changes
you made to it are deleted and the next container you spawn from the image will begin afresh.

When you're done with a container, you can stop or kill them with:

```bash
docker container ls -a    # to get containerIDs
docker stop <containerID> # try to shutdown nicely (send SIGTERM)
docker kill <containerID> # force a shutdown (send SIGKILL)
```

you can delete them with:

`docker rm <containerID> <containerID> ...`

You can obtain the <containerID>s with `docker container ls -a` or `docker ps -a` (They are the
same). To remove all exited containers:

`docker rm $(docker ps -aq -f status=exited)`

The `-q` flag means to only return the container names while the `-f` flag will filter the output.

This command will remove the container automatically after the process exits:

`docker run --rm <image>:<version>`

This command will publish the container's port 5000 to the host port 80 and name the container
`my_application1`. Without the name flag, docker engine will generate a random name:

`docker run -p 80:5000 --name my_application <image>:<version>`

## Dockerfile
The `Dockerfile` is a set of instruction on how to build an image. It typically starts with a
base image (Ubuntu18.04 or Alpine Linux for example) and then installs the necessary components, 
configures the working directories, copies files over, opens ports, etc. This allows anyone with 
the Dockerfile to reproduce the same environment and give an overview of your application based
on what is inside of it. There is a lot more to it, like multi-target Dockerfiles and scratch
builds but that information can be found on docs.docker.com. Some images could take a while
to build but once they're built, the "layers" are stored by docker so only the portions 
changed in the `Dockerfile` will need to be rebuilt. The docker file is used when the
`docker container build -t <name>:<tag> .` command is run.

## Docker-Compose
Docker-Compose is a tool for coordinating multiple containers. For example, you have a container
hosting your web-app and another container for your database. Docker-compose will handle the
volume management, container networking, secret sharing, port exposing, etc. instead of requiring
you to set all of this up by hand through the command line. 

Docker-Compose uses `docker-compose.yaml` files. It is a layer on top of your `Dockerfiles` and
build images. While `Dockerfiles` are used to configure images, `docker-compose.yaml` files are 
used to coordinate the images. They can call your `Dockerfiles` to build your containers. 


* If you change the docker file, `docker-compose up` will not **re**build the image. You have to
run `docker-compose build` otherwise it will just bring up the stopped container. This is by
design








