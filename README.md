dnsproxy
========

A simple Dns-Over-Https proxy server


## Simple tutorial

use the below commands to build and deploy the Dns-Over-Https proxy server.

```bash
$ docker build . -t dnsproxy
$ docker-compose -f ./docker-compose.yaml up
```

now, dnsproxy docker container will be up and ready for use. set your default DNS to the loopback(127.0.0.1) address and enjoy doh-to-dns proxy server.

## Setting the parameters
you can set your desired DoH server at the scripts/run.sh file, and also you should set your Default dns server in the docker-compose.yaml file.

