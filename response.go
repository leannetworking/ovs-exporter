package main

//This file contains the JSON response object (structs)

//Written by Megyo @ LeanNet 

//import "time"

type Flow struct {
    Cookie    	string    	`json:"cookie"`
    Duration  	string   	`json:"duration"`
    Table     	string 		`json:"table"`
    Packets   	string		`json:"packets"`
    Bytes     	string		`json:"bytes"`
    IdleTimeout string		`json:"idletimeout"` 
    IdleAge		string		`json:"idleage"`
    Priority	string		`json:"proirity"`
    Match		string		`json:"match"`
    Action		string		`json:"action"`
}

type Flows []Flow

type Port struct {
    PortNumber   string    	`json:"portnumber"`
    RxPackets  	 string   	`json:"rxpackets"`
    TxPackets    string 	`json:"txpackets"`
    RxBytes   	 string		`json:"rxbytes"`
    TxBytes      string		`json:"txbytes"`
    RxDrops	 	 string		`json:"rxdrops"` 
    TxDrops		 string		`json:"txdrops"`
    RxErrors	 string		`json:"rxerrors"`
    TxErrors	 string		`json:"txerrors"`
    RxFrameErr	 string		`json:"rxframeerr"`
    RxOverruns	 string		`json:"rxovverruns"`
    RxCrcErrors	 string		`json:"rxcrcerrors"`
    TxCollisions string		`json:"txcollisions"`
}

type Ports []Port

type Group struct {
    GroupId   string    `json:"groupid"`
    GroupType string   	`json:"grouptype"`
    Buckets   string 	`json:"buckets"` //TODO: this should be an arry of bucket entries...
    Duration  string	`json:"duration"`
}

type Groups []Group

