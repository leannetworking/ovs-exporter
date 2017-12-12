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
        "/flows/{ovsIP}",
        GetFlows,
    },
    Route{
        "PortStats",
        "GET",
        "/ports/{ovsIP}",
        GetPorts,
    },
    Route{
        "GroupStats",
        "GET",
        "/groups/{ovsIP}",
        GetGroups,
    },
}
