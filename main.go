package main

//This script listens on a given TCP port for
//HTTP REST Get messages than scraps the given
//Open vSwtich entry and gives back the stats
//in Prometheus compatible format

//Written by Megyo @ LeanNet

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//the TCP port that this scripts listens
var listenPort string = ":8081"

func handler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query()["target"][0]
	if target == "" {
		http.Error(w, "Bad request!\nCorrect format is: http://<IP>:<Port>/flows?target=<targetIP>", 400)
		return
	}
	c := collector{ip: target, port: ovsPort}
	registry := prometheus.NewRegistry()
	registry.MustRegister(c)
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func main() {
	http.HandleFunc("/test", handler)
	log.Fatal(http.ListenAndServe(listenPort, nil))
}
