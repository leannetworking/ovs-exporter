package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

//the passive TCP port where OVS entries are listening
//for OpenFlow commands
var ovsPort int = 16633
var ofReader OvsOfStatReader = ofcli{}


func GetMetrics(w http.ResponseWriter, r *http.Request) {
	ovsIP := r.URL.Query()["target"][0]

	if ovsIP == "" {
		fmt.Fprintln(w, "Bad request!\nCorrect format is: http://<IP>:<Port>/flows?tartget=<targetIP>")
	}

	lines, err := ofReader.DumpFlows(ovsIP, ovsPort)
	//if error was occured we return
	if err != nil {
		fmt.Fprintln(w, "Error is: ", err, "\nOutput was:", lines)
		return
	}
	//if command was succesfull we further parse the output
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
			flowEntries[i].Match = subMatch[2]
		}

		//Action
		re = regexp.MustCompile("actions=(.*)")
		subMatch = re.FindStringSubmatch(entry)
		if len(subMatch) > 1 {
			flowEntries[i].Action = subMatch[1]
		}

	}

	//Creating Prometheus compatible output for:
	//	- number of packets as "flowPackets" type Counter
	//	- number of bytes as "flowBytes" type Counter
	//	- age of the flow as "flowAge" type Gauge
	//	- idle time as "flowIdleTime" type Gauge

	//flowPackets
	fmt.Fprintln(w, "# HELP flowPackets The number of packets matched for the given OpenFlow entry")
	fmt.Fprintln(w, "# TYPE flowPackets counter")
	for _, entry := range flowEntries {
		fmt.Fprintln(w,
			"flowPackets{match=\""+entry.Match+
				"\",action=\""+entry.Action+
				"\",table=\""+entry.Table+
				"\",priority=\""+entry.Priority+
				"\"} "+entry.Packets)
	}

	//flowBytes
	fmt.Fprintln(w, "# HELP flowBytes The number of bytes matched for the given OpenFlow entry")
	fmt.Fprintln(w, "# TYPE flowBytes counter")
	for _, entry := range flowEntries {
		fmt.Fprintln(w,
			"flowBytes{match=\""+entry.Match+
				"\",action=\""+entry.Action+
				"\",table=\""+entry.Table+
				"\",priority=\""+entry.Priority+
				"\"} "+entry.Bytes)
	}

	//flowAge
	fmt.Fprintln(w, "# HELP flowAge The number of seconds have passed since the given OpenFlow entry was created")
	fmt.Fprintln(w, "# TYPE flowAge gauge")
	for _, entry := range flowEntries {
		fmt.Fprintln(w,
			"flowAge{match=\""+entry.Match+
				"\",action=\""+entry.Action+
				"\",table=\""+entry.Table+
				"\",priority=\""+entry.Priority+
				"\"} "+entry.Duration)
	}

	//flowIdleTime
	fmt.Fprintln(w, "# HELP flowIdleTime The number of seconds have passed since the last packet has seen for the given OpenFlow entry")
	fmt.Fprintln(w, "# TYPE flowIdleTime gauge")
	for _, entry := range flowEntries {
		fmt.Fprintln(w,
			"flowIdleTime{match=\""+entry.Match+
				"\",action=\""+entry.Action+
				"\",table=\""+entry.Table+
				"\",priority=\""+entry.Priority+
				"\"} "+entry.IdleAge)
	}

	lines, err = ofReader.DumpPorts(ovsIP, ovsPort)
	//if error was occured we return
	if err != nil {
		fmt.Fprintln(w, "Error is: ", err, "\nOutput was:", lines, "\nOVS IP is: ", ovsIP)
		return
	}
	//if command was succesfull we further parse the output
	portEntries := make([]Port, int(len(lines)/2))
	for i := 0; i < len(lines); i += 2 {
		twoLines := lines[i] + lines[i+1]

		//Searching every entry in one line as the following (there is no new line charachter between them):
		//  port 1: rx pkts=1148284, bytes=76073652, drop=0, errs=0, frame=0, over=0, crc=0
		//          tx pkts=1814122, bytes=90439143776, drop=0, errs=0, coll=0
		re := regexp.MustCompile("port +(.*?): rx pkts=(.*?), bytes=(.*?), drop=(.*?), errs=(.*?), frame=(.*?), over=(.*?), crc=(.*?) .*tx pkts=(.*?), bytes=(.*?), drop=(.*?), errs=(.*?), coll=(.*)")
		subMatch := re.FindStringSubmatch(twoLines)
		if len(subMatch) > 13 {
			portEntries[int(i/2)].PortNumber = noQuestionMark(subMatch[1])
			portEntries[int(i/2)].RxPackets = noQuestionMark(subMatch[2])
			portEntries[int(i/2)].RxBytes = noQuestionMark(subMatch[3])
			portEntries[int(i/2)].RxDrops = noQuestionMark(subMatch[4])
			portEntries[int(i/2)].RxErrors = noQuestionMark(subMatch[5])
			portEntries[int(i/2)].RxFrameErr = noQuestionMark(subMatch[6])
			portEntries[int(i/2)].RxOverruns = noQuestionMark(subMatch[7])
			portEntries[int(i/2)].RxCrcErrors = noQuestionMark(subMatch[8])
			portEntries[int(i/2)].TxPackets = noQuestionMark(subMatch[9])
			portEntries[int(i/2)].TxBytes = noQuestionMark(subMatch[10])
			portEntries[int(i/2)].TxDrops = noQuestionMark(subMatch[11])
			portEntries[int(i/2)].TxErrors = noQuestionMark(subMatch[12])
			portEntries[int(i/2)].TxCollisions = noQuestionMark(subMatch[13])
		} else {
			fmt.Fprintln(w, "Output is: ", subMatch, twoLines)
			return
		}
	}

	//Creating Prometheus compatible output for every stat with portNumber identifyer:
	//	- number of packets recieved by the given OpenFlow port as "portRxPackets" type Counter
	//	- number of packets sent by the given OpenFlow port as "portTxPackets" type Counter
	//	- number of bytes recieved by the given OpenFlow port as "portRxBytes" type Counter
	//	- number of bytes sent by the given OpenFlow port as "portTxBytes" type Counter
	//	- number of packet drops in recieve side by the given OpenFlow port as "portRxDrops" type Counter
	//	- number of packet drops in sending side by the given OpenFlow port as "portTxDrops" type Counter

	//portRxPackets
	fmt.Fprintln(w, "# HELP portRxPackets The number of packet that was recieved by a given port")
	fmt.Fprintln(w, "# TYPE portRxPackets counter")
	for _, entry := range portEntries {
		fmt.Fprintln(w,
			"portRxPackets{portNumber=\""+entry.PortNumber+
				"\"} "+entry.RxPackets)
	}

	//portTxPackets
	fmt.Fprintln(w, "# HELP portTxPackets The number of packet that was sent by a given port")
	fmt.Fprintln(w, "# TYPE portTxPackets counter")
	for _, entry := range portEntries {
		fmt.Fprintln(w,
			"portTxPackets{portNumber=\""+entry.PortNumber+
				"\"} "+entry.TxPackets)
	}

	//portRxBytes
	fmt.Fprintln(w, "# HELP portRxBytes The number of bytes that was recieved by a given port")
	fmt.Fprintln(w, "# TYPE portRxBytes counter")
	for _, entry := range portEntries {
		fmt.Fprintln(w,
			"portRxBytes{portNumber=\""+entry.PortNumber+
				"\"} "+entry.RxBytes)
	}

	//portTxBytes
	fmt.Fprintln(w, "# HELP portTxBytes The number of bytes that was sent by a given port")
	fmt.Fprintln(w, "# TYPE portTxBytes counter")
	for _, entry := range portEntries {
		fmt.Fprintln(w,
			"portTxBytes{portNumber=\""+entry.PortNumber+
				"\"} "+entry.TxBytes)
	}

	//portRxDrops
	fmt.Fprintln(w, "# HELP portRxDrops The number of packets that was dropped on receive side by a given port")
	fmt.Fprintln(w, "# TYPE portRxDrops counter")
	for _, entry := range portEntries {
		fmt.Fprintln(w,
			"portRxDrops{portNumber=\""+entry.PortNumber+
				"\"} "+entry.RxDrops)
	}

	//portTxDrops
	fmt.Fprintln(w, "# HELP portTxDrops The number of packets that was dropped on sending side by a given port")
	fmt.Fprintln(w, "# TYPE portTxDrops counter")
	for _, entry := range portEntries {
		fmt.Fprintln(w,
			"portTxDrops{portNumber=\""+entry.PortNumber+
				"\"} "+entry.TxDrops)
	}

	lines, err = ofReader.DumpGroups(ovsIP, ovsPort)
	//if error was occured we return
	if err != nil {
		fmt.Fprintln(w, "Error is: ", err, "\nOutput was:", lines)
		return
	}
	//if command was succesfull we further parse the output
	groupEntries := make([]Group, len(lines))
	for i, entry := range lines {
		re := regexp.MustCompile("")

		//Group Type
		re = regexp.MustCompile("group_id=(.*?),")
		subMatch := re.FindStringSubmatch(entry)
		if len(subMatch) > 1 {
			groupEntries[i].GroupId = subMatch[1]
		}

		//Group Type
		re = regexp.MustCompile("type=(.*?),")
		subMatch = re.FindStringSubmatch(entry)
		if len(subMatch) > 1 {
			groupEntries[i].GroupType = subMatch[1]
		}

		//Split the group line into buckets
		buckets := strings.Split(entry, "bucket=")
		bucketEntries := make([]Bucket, len(buckets)-1)
		for j := 1; j < len(buckets); j++ {
			re = regexp.MustCompile("actions=(.*?),?$")
			subMatch = re.FindStringSubmatch(buckets[j])
			if len(subMatch) > 1 {
				bucketEntries[j-1].Actions = subMatch[1]
			}
		}
		groupEntries[i].Buckets = bucketEntries
	}

	lines, err = ofReader.DumpGroupStats(ovsIP, ovsPort)
	//if error was occured we return
	if err != nil {
		fmt.Fprintln(w, "Error is: ", err, "\nOutput was:", lines)
		return
	}
	for _, entry := range lines {
		re := regexp.MustCompile("")

		groupIndex := -1

		//Get the matching Group ID
		re = regexp.MustCompile("group_id=(.*?),")
		subMatch := re.FindStringSubmatch(entry)
		if len(subMatch) > 1 {
			for j, group := range groupEntries {
				if group.GroupId == subMatch[1] {
					groupIndex = j
				}
			}
		}

		//Duration
		re = regexp.MustCompile("duration=(.*?)s,")
		subMatch = re.FindStringSubmatch(entry)
		if len(subMatch) > 1 {
			groupEntries[groupIndex].Duration = subMatch[1]
		}

		//Bucket byte and packet stat
		buckets := strings.Split(entry, ":")
		//The 0th element in this split should contain the aggregated packet/byte counter for the whole group
		re = regexp.MustCompile("packet_count=([0-9]+)")
		subMatch = re.FindStringSubmatch(buckets[0])
		if len(subMatch) > 1 {
			groupEntries[groupIndex].Packets = subMatch[1]
		}

		re = regexp.MustCompile("byte_count=([0-9]+)")
		subMatch = re.FindStringSubmatch(buckets[0])
		if len(subMatch) > 1 {
			groupEntries[groupIndex].Bytes = subMatch[1]
		}

		//The others should contain bucket data
		for j := 1; j < len(buckets); j++ {
			re = regexp.MustCompile("packet_count=([0-9]+)")
			subMatch = re.FindStringSubmatch(buckets[j])
			if len(subMatch) > 1 {
				groupEntries[groupIndex].Buckets[j-1].Packets = subMatch[1]
			}

			re = regexp.MustCompile("byte_count=([0-9]+)")
			subMatch = re.FindStringSubmatch(buckets[j])
			if len(subMatch) > 1 {
				groupEntries[groupIndex].Buckets[j-1].Bytes = subMatch[1]
			}
		}
	}

	//Creating Prometheus compatible output for every group stat with groupId label:
	//	- number of packets that was forwarded by a group rule as "groupPackets" type Counter
	//	- number of bytes that was forwarded by a group rule as "groupBytes" type Counter
	//	- number of second that passed since a group rule was added as "groupPackets" type Gauge
	//	- number of packets that was forwarded by a bucket in a group rule as "groupBucketPackets" type Counter
	//	- number of bytes that was forwarded by a bucket in a group rule as "groupBucketBytes" type Counter

	//groupPackets
	fmt.Fprintln(w, "# HELP groupPackets The number of packet that was sent by a given group")
	fmt.Fprintln(w, "# TYPE groupPackets counter")
	for _, entry := range groupEntries {
		fmt.Fprintln(w,
			"groupPackets{groupId=\""+entry.GroupId+
				"\",groupType=\""+entry.GroupType+
				"\"} "+entry.Packets)
	}

	//groupBytes
	fmt.Fprintln(w, "# HELP groupBytes The number of bytes that was sent by a given group")
	fmt.Fprintln(w, "# TYPE groupBytes counter")
	for _, entry := range groupEntries {
		fmt.Fprintln(w,
			"groupBytes{groupId=\""+entry.GroupId+
				"\",groupType=\""+entry.GroupType+
				"\"} "+entry.Bytes)
	}

	//groupDuration
	fmt.Fprintln(w, "# HELP groupDuration The number of seconds passed since the group entry was added")
	fmt.Fprintln(w, "# TYPE groupDuration gauge")
	for _, entry := range groupEntries {
		fmt.Fprintln(w,
			"groupDuration{groupId=\""+entry.GroupId+
				"\",groupType=\""+entry.GroupType+
				"\"} "+entry.Duration)
	}

	//groupBucketPackets
	fmt.Fprintln(w, "# HELP groupBucketPackets The number of packet that was sent by a given group bucket")
	fmt.Fprintln(w, "# TYPE groupBucketPackets counter")
	for _, entry := range groupEntries {
		for _, bucket := range entry.Buckets {
			fmt.Fprintln(w,
				"groupBucketPackets{groupId=\""+entry.GroupId+
					"\",groupType=\""+entry.GroupType+
					"\",bucketActions=\""+bucket.Actions+
					"\"} "+bucket.Packets)
		}
	}

	//groupBucketBytes
	fmt.Fprintln(w, "# HELP groupBucketBytes The number of bytes that was sent by a given group bucket")
	fmt.Fprintln(w, "# TYPE groupBucketBytes counter")
	for _, entry := range groupEntries {
		for _, bucket := range entry.Buckets {
			fmt.Fprintln(w,
				"groupBucketBytes{groupId=\""+entry.GroupId+
					"\",groupType=\""+entry.GroupType+
					"\",bucketActions=\""+bucket.Actions+
					"\"} "+bucket.Bytes)
		}
	}

}

func noQuestionMark(s string) string {
	if s == "?" {
		return "0"
	}
	return s
}
