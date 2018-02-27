FROM ubuntu:16.04

MAINTAINER "LeanNet" <info@leannet.eu>
# Containerize the Prometheus ovs-exporter 

RUN apt-get update 
RUN apt-get install -y openvswitch-common

COPY ovs-exporter ./
RUN chmod 744 ovs-exporter

ENTRYPOINT ["./ovs-exporter"]
