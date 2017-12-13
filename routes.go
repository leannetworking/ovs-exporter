package main

import "net/http"

type Route struct {
    Name        string
    Method      string
    Pattern     string
    HandlerFunc http.HandlerFunc
}

type Routes []Route

var routes = Routes{
    Route{
        "FlowStats",
        "GET",
        "/flows",
        GetFlows,
    },
    Route{
        "PortStats",
        "GET",
        "/ports",
        GetPorts,
    },
    Route{
        "GroupStats",
        "GET",
        "/groups",
        GetGroups,
    },
}
