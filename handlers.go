package main

import (
//    "encoding/json"
    "fmt"
    "net/http"
    "os/exec"
    "regexp"
    "strings"

//    "github.com/gorilla/mux"
)

//the passive TCP port where OVS entries are listening
//for OpenFlow commands
var ovsPort string = "6655"

func GetFlows(w http.ResponseWriter, r *http.Request) {
    //vars := mux.Vars(r)
    //ovsIP := vars["ovsIP"]
    ovsIP := r.URL.Query()["target"][0]
    
    if ovsIP == "" {
    	fmt.Fprintln(w, "Bad request!\nCorrect format is: http://<IP>:<Port>/flows?tartget=<targetIP>")
    }
    
    //creating ovs-ofctl command
    cmd := exec.Command("ovs-ofctl", "dump-flows", "tcp:" + ovsIP + ":" + ovsPort)
    out, err := cmd.Output()
	outString := string(out)
	//if error was occured we return
	if err != nil {
		fmt.Fprintln(w, "Error is: ", err, "\nOutput was:", outString)
		return
	}
    //if command was succesfull we further parse the output
    
    
    lines := strings.Split(outString, "\n")
    //skip the first and last lines, since it is just a response header and an empty line
    lines = lines[1:(len(lines)-1)]
    flowEntries := make([]Flow, len(lines))
    for i, entry := range lines {
    	re := regexp.MustCompile("")
    	
    	//Cookie
    	re = regexp.MustCompile("cookie=(.*?),")
    	subMatch := re.FindStringSubmatch(entry)
    	if len(subMatch) > 1 {
    		flowEntries[i].Cookie = subMatch[1]
    	}

    	//Duration
    	re = regexp.MustCompile("duration=(.*?)s,")
    	subMatch = re.FindStringSubmatch(entry)
    	if len(subMatch) > 1 {
    		flowEntries[i].Duration = subMatch[1]
    	}

    	//Table
    	re = regexp.MustCompile("table=(.*?),")
    	subMatch = re.FindStringSubmatch(entry)
    	if len(subMatch) > 1 {
    		flowEntries[i].Table = subMatch[1]
    	}

    	//Packets
    	re = regexp.MustCompile("packets=(.*?),")
    	subMatch = re.FindStringSubmatch(entry)
    	if len(subMatch) > 1 {
    		flowEntries[i].Packets = subMatch[1]
    	}
    	
    	//Bytes
    	re = regexp.MustCompile("bytes=(.*?),")
    	subMatch = re.FindStringSubmatch(entry)
    	if len(subMatch) > 1 {
    		flowEntries[i].Bytes = subMatch[1]
    	}
    	
    	//Idle Timeout
    	re = regexp.MustCompile("idle_timeout=(.*?),")
    	subMatch = re.FindStringSubmatch(entry)
    	if len(subMatch) > 1 {
    		flowEntries[i].IdleTimeout = subMatch[1]
    	}

    	//Idle Age
    	re = regexp.MustCompile("idle_age=(.*?),")
    	subMatch = re.FindStringSubmatch(entry)
    	if len(subMatch) > 1 {
    		flowEntries[i].IdleAge = subMatch[1]
    	}
    	    	
    	//Priority & Match rule
    	re = regexp.MustCompile("priority=(.*?),(.*?) ")
    	subMatch = re.FindStringSubmatch(entry)
    	if len(subMatch) > 2 {
    		flowEntries[i].Priority = subMatch[1]
    		flowEntries[i].Match    = subMatch[2]
    	}

    	//Action
    	re = regexp.MustCompile("actions=(.*)")
    	subMatch = re.FindStringSubmatch(entry)
    	if len(subMatch) > 1 {
    		flowEntries[i].Action = subMatch[1]
    	}
    	
    }
    
    //fmt.Fprintln(w, "Output is: ", lines)
    //use this to create just a simple JSON response
    //w.Header().Set("Content-Type", "application/json; charset=UTF-8")
    //w.WriteHeader(http.StatusOK)
    //if err := json.NewEncoder(w).Encode(flowEntries); err != nil {
    //    panic(err)
    //}
    
    
    //Creating Prometheus compatible output for:
    //	- number of packets as "flowPackets" type Counter
    //	- number of bytes as "flowBytes" type Counter
    //	- age of the flow as "flowAge" type Gauge
    //	- idle time as "flowIdleTime" type Gauge
    
    //flowPackets
    fmt.Fprintln(w, "HELP flowPackets The number of packets matched for the given OpenFlow entry")
    fmt.Fprintln(w, "TYPE flowPackets counter")
    for _,entry := range flowEntries {
    	fmt.Fprintln(w, 
    		"flowPackets{match=\""  + entry.Match + 
    		"\",action=\""	 		+ entry.Action +
    		"\",table=\"" 			+ entry.Table +
    		"\",priority=\""		+ entry.Priority +
    		"\"} "					+ entry.Packets)    		 
    }
     
    //flowBytes
    fmt.Fprintln(w, "HELP flowBytes The number of bytes matched for the given OpenFlow entry")
    fmt.Fprintln(w, "TYPE flowBytes counter")
    for _,entry := range flowEntries {
    	fmt.Fprintln(w, 
    		"flowBytes{match=\"" 	+ entry.Match + 
    		"\",action=\""	 		+ entry.Action +
    		"\",table=\"" 			+ entry.Table +
    		"\",priority=\""		+ entry.Priority +
    		"\"} "					+ entry.Bytes)    		 
    }
    
    //flowAge
    fmt.Fprintln(w, "HELP flowAge The number of seconds have passed since the given OpenFlow entry was created")
    fmt.Fprintln(w, "TYPE flowAge gauge")
    for _,entry := range flowEntries {
    	fmt.Fprintln(w, 
    		"flowAge{match=\""	 	+ entry.Match + 
    		"\",action=\""	 		+ entry.Action +
    		"\",table=\"" 			+ entry.Table +
    		"\",priority=\""		+ entry.Priority +
    		"\"} "					+ entry.Duration)    		 
    }
    
    //flowIdleTime
    fmt.Fprintln(w, "HELP flowIdleTime The number of seconds have passed since the last packet has seen for the given OpenFlow entry")
    fmt.Fprintln(w, "TYPE flowIdleTime gauge")
    for _,entry := range flowEntries {
    	fmt.Fprintln(w, 
    		"flowIdleTime{match=\""	+ entry.Match + 
    		"\",action=\""	 		+ entry.Action +
    		"\",table=\"" 			+ entry.Table +
    		"\",priority=\""		+ entry.Priority +
    		"\"} "					+ entry.IdleAge)    		 
    }
}

func GetPorts(w http.ResponseWriter, r *http.Request) {
    //vars := mux.Vars(r)
    //ovsIP := vars["ovsIP"]
    ovsIP := r.URL.Query()["target"][0]
    
    if ovsIP == "" {
    	fmt.Fprintln(w, "Bad request!\nCorrect format is: http://<IP>:<Port>/ports?tartget=<targetIP>")
    }
    
    //creating ovs-ofctl command
    cmd := exec.Command("ovs-ofctl", "dump-ports", "tcp:" + ovsIP + ":" + ovsPort)
    out, err := cmd.Output()
	outString := string(out)
	//if error was occured we return
	if err != nil {
		fmt.Fprintln(w, "Error is: ", err, "\nOutput was:", outString, "\nOVS IP is: ", ovsIP)
		return
	}
    //if command was succesfull we further parse the output
    
    
    lines := strings.Split(outString, "\n")
    //skip the first and last lines, since it is just a response header and an empty line
    lines = lines[1:(len(lines)-1)]
    portEntries := make([]Port, int(len(lines)/2))
    for i:=0; i<len(lines); i+=2 {
    	twoLines := lines[i] + lines[i+1]
    	
    	//We search every entry in one line as the following (there is no new line charachter between them):
    	//  port 1: rx pkts=1148284, bytes=76073652, drop=0, errs=0, frame=0, over=0, crc=0
        //          tx pkts=1814122, bytes=90439143776, drop=0, errs=0, coll=0
    	re := regexp.MustCompile("port +(.*?): rx pkts=(.*?), bytes=(.*?), drop=(.*?), errs=(.*?), frame=(.*?), over=(.*?), crc=(.*?) .*tx pkts=(.*?), bytes=(.*?), drop=(.*?), errs=(.*?), coll=(.*)")
    	subMatch := re.FindStringSubmatch(twoLines)
    	if len(subMatch) > 13 {
    		portEntries[int(i/2)].PortNumber   = subMatch[1]
			portEntries[int(i/2)].RxPackets    = subMatch[2]
			portEntries[int(i/2)].RxBytes      = subMatch[3]
			portEntries[int(i/2)].RxDrops      = subMatch[4]
			portEntries[int(i/2)].RxErrors     = subMatch[5]
			portEntries[int(i/2)].RxFrameErr   = subMatch[6]
			portEntries[int(i/2)].RxOverruns   = subMatch[7]
			portEntries[int(i/2)].RxCrcErrors  = subMatch[8]
			portEntries[int(i/2)].TxPackets    = subMatch[9]
			portEntries[int(i/2)].TxBytes      = subMatch[10]
			portEntries[int(i/2)].TxDrops      = subMatch[11]
			portEntries[int(i/2)].TxErrors     = subMatch[12]
			portEntries[int(i/2)].TxCollisions = subMatch[13]
    	} else {
    		fmt.Fprintln(w, "Output is: ", subMatch, twoLines)
    		return
    	}
    }
    
    //fmt.Fprintln(w, "Output is: ", lines)
    //use this to create just a simple JSON response
    //w.Header().Set("Content-Type", "application/json; charset=UTF-8")
    //w.WriteHeader(http.StatusOK)
    //if err := json.NewEncoder(w).Encode(portEntries); err != nil {
    //    panic(err)
    //}
       
    //Creating Prometheus compatible output for every stat with portNumber identifyer:
    
    //portRxPackets
    fmt.Fprintln(w, "HELP portRxPackets The number of packet that was recieved by a given port")
    fmt.Fprintln(w, "TYPE portRxPackets counter")
    for _,entry := range portEntries {
    	fmt.Fprintln(w, 
    		"portRxPackets{portNumber=\"" + entry.PortNumber + 
    		"\"} "					      + entry.RxPackets)    		 
    }
 
    //portTxPackets
    fmt.Fprintln(w, "HELP portTxPackets The number of packet that was sent by a given port")
    fmt.Fprintln(w, "TYPE portTxPackets counter")
    for _,entry := range portEntries {
    	fmt.Fprintln(w, 
    		"portTxPackets{portNumber=\"" + entry.PortNumber + 
    		"\"} "					      + entry.TxPackets)    		 
    }

    //portRxBytes
    fmt.Fprintln(w, "HELP portRxBytes The number of bytes that was recieved by a given port")
    fmt.Fprintln(w, "TYPE portRxBytes counter")
    for _,entry := range portEntries {
    	fmt.Fprintln(w, 
    		"portRxBytes{portNumber=\"" + entry.PortNumber + 
    		"\"} "					    + entry.RxBytes)    		 
    }
 
    //portTxBytes
    fmt.Fprintln(w, "HELP portTxBytes The number of bytes that was sent by a given port")
    fmt.Fprintln(w, "TYPE portTxBytes counter")
    for _,entry := range portEntries {
    	fmt.Fprintln(w, 
    		"portTxBytes{portNumber=\"" + entry.PortNumber + 
    		"\"} "					    + entry.TxBytes)    		 
    }

    //portRxDrops
    fmt.Fprintln(w, "HELP portRxDrops The number of packets that was dropped on receive side by a given port")
    fmt.Fprintln(w, "TYPE portRxDrops counter")
    for _,entry := range portEntries {
    	fmt.Fprintln(w, 
    		"portRxDrops{portNumber=\"" + entry.PortNumber + 
    		"\"} "					    + entry.RxDrops)    		 
    }
 
    //portTxDrops
    fmt.Fprintln(w, "HELP portTxDrops The number of packets that was dropped on sending side by a given port")
    fmt.Fprintln(w, "TYPE portTxDrops counter")
    for _,entry := range portEntries {
    	fmt.Fprintln(w, 
    		"portTxDrops{portNumber=\"" + entry.PortNumber + 
    		"\"} "					    + entry.TxDrops)    		 
    }
}

func GetGroups(w http.ResponseWriter, r *http.Request) {
    //vars := mux.Vars(r)
    //ovsIP := vars["ovsIP"]
    ovsIP := r.URL.Query()["target"][0]
    
    if ovsIP == "" {
    	fmt.Fprintln(w, "Bad request!\nCorrect format is: http://<IP>:<Port>/groups?tartget=<targetIP>")
    }
    
    //creating ovs-ofctl command
    cmd := exec.Command("ovs-ofctl", "-O", "openflow13", "dump-groups", "tcp:" + ovsIP + ":" + ovsPort)
    out, err := cmd.Output()
	outString := string(out)
	//if error was occured we return
	if err != nil {
		fmt.Fprintln(w, "Error is: ", err, "\nOutput was:", outString)
		return
	}
    //if command was succesfull we further parse the output
    
       
    fmt.Fprintln(w, "Output is: ", outString)
    //use this to create just a simple JSON response
    //w.Header().Set("Content-Type", "application/json; charset=UTF-8")
    //w.WriteHeader(http.StatusOK)
    //if err := json.NewEncoder(w).Encode(groupEntries); err != nil {
    //    panic(err)
    //}
       
    //Creating Prometheus compatible output for every stat with portNumber identifyer:
}

