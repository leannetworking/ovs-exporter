package main

//This script listens on a given TCP port for
//HTTP REST Get messages than scraps the given
//Open vSwtich entry and gives back the stats
//in Prometheus compatible format

//Written by Megyo @ LeanNet 

import (
    "log"
    "net/http"
)

//the TCP port that this scripts listens
var listenPort string = ":8081"

func main() {

    router := NewRouter()

    log.Fatal(http.ListenAndServe(listenPort, router))
}

