package ovs

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type OvsDumpSource interface {
	DumpFlows(ip string, port int) ([]string, error)
	DumpPorts(ip string, port int) ([]string, error)
	DumpGroups(ip string, port int) ([]string, error)
	DumpGroupStats(ip string, port int) ([]string, error)
}

type OvsDumpReader struct {
	dumpSource OvsDumpSource
}

var (
	flowLine       *regexp.Regexp = regexp.MustCompile("cookie=(?P<cookie>[^,]*), duration=(?P<duration>[^,]*)s, table=(?P<table>[^,]*), n_packets=(?P<packets>[^,]*), n_bytes=(?P<bytes>[^,]*),( idle_timeout=(?P<idle_timeout>[^,]*),)? idle_age=(?P<idle_age>[^,]*), priority=(?P<priority>[^,]*)(,(?P<match>[^ ]*))? actions=(?P<actions>.*)")
	portLine       *regexp.Regexp = regexp.MustCompile(`port\s*(?P<port>[^:]*):\srx\spkts=(?P<rxpackets>[^,]*),\sbytes=(?P<rxbytes>[^,]*),\sdrop=(?P<rxdrops>[^,]*),\serrs=(?P<rxerrors>[^,]*),\sframe=(?P<rxframerr>[^,]*),\sover=(?P<rxoverruns>[^,]*),\scrc=(?P<rxcrcerrors>[^,]*)\s.*tx\spkts=(?P<txpackets>[^,]*),\sbytes=(?P<txbytes>[^,]*),\sdrop=(?P<txdrops>[^,]*),\serrs=(?P<txerrors>[^,]*),\scoll=(?P<txcollisions>.*)`)
	groupsLine     *regexp.Regexp = regexp.MustCompile(`group_id=(?P<groupid>.*?),\s*type=(?P<type>[^,]*),bucket=(?P<buckets>.*$)`)
	bucketAction   *regexp.Regexp = regexp.MustCompile("actions=(.*?),?$")
	groupStatsLine *regexp.Regexp = regexp.MustCompile(`group_id=(?P<groupid>.*?),duration=(?P<duration>[^,]*)s,(?P<counts>.*$)`)
	countLine      *regexp.Regexp = regexp.MustCompile("ref_count=(?P<ref_count>[0-9]+),packet_count=(?P<packet_count>[0-9]+),byte_count=(?P<byte_count>[0-9]+).*")
	CliDumpReader  OvsDumpReader  = OvsDumpReader{OvsDumpSourceTest{}}
)

func getRegexpMap(match []string, names []string) map[string]string {
	result := make(map[string]string, len(names))
	for i, name := range names {
		result[name] = match[i]
	}
	return result
}

func parseOpenFlowFlowDumpLine(line string) Flow {
	match := flowLine.FindStringSubmatch(line)
	result := getRegexpMap(match, flowLine.SubexpNames())
	duration, _ := strconv.ParseFloat(result["duration"], 64)
	packets, _ := strconv.Atoi(result["packets"])
	bytes, _ := strconv.Atoi(result["bytes"])
	idleAge, _ := strconv.Atoi(result["idle_age"])

	flow := Flow{
		Cookie:      result["cookie"],
		Duration:    duration,
		Table:       result["table"],
		Packets:     packets,
		Bytes:       bytes,
		IdleTimeout: result["idle_timeout"],
		IdleAge:     idleAge,
		Priority:    result["priority"],
		Match:       result["match"],
		Action:      result["actions"],
	}
	return flow
}

func parseOpenFlowPortDumpLine(line string) Port {
	line = strings.Replace(line, "=?", "=0", -1)
	fmt.Println(line)
	match := portLine.FindStringSubmatch(line)
	result := getRegexpMap(match, portLine.SubexpNames())
	rxpackets, _ := strconv.Atoi(result["rxpackets"])
	txpackets, _ := strconv.Atoi(result["txpackets"])
	rxbytes, _ := strconv.Atoi(result["rxbytes"])
	txbytes, _ := strconv.Atoi(result["txbytes"])
	rxdrops, _ := strconv.Atoi(result["rxdrops"])
	txdrops, _ := strconv.Atoi(result["txdrops"])
	fmt.Println(result["port"])

	port := Port{
		PortNumber:   result["port"],
		RxPackets:    rxpackets,
		TxPackets:    txpackets,
		RxBytes:      rxbytes,
		TxBytes:      txbytes,
		RxDrops:      rxdrops,
		TxDrops:      txdrops,
		RxErrors:     result["rxerrors"],
		TxErrors:     result["txerrors"],
		RxFrameErr:   result["rxframerr"],
		RxOverruns:   result["rxoverruns"],
		RxCrcErrors:  result["rxcrcerrors"],
		TxCollisions: result["txcollisions"],
	}
	return port
}

func parseOpenFlowGroupsDumpLine(line string) Group {
	match := groupsLine.FindStringSubmatch(line)
	result := getRegexpMap(match, groupsLine.SubexpNames())

	group := Group{
		GroupId:   result["groupid"],
		GroupType: result["type"],
	}

	//Split the group line into buckets
	buckets := strings.Split(result["buckets"], "bucket=")
	bucketEntries := make([]Bucket, len(buckets))
	for idx, bucket := range buckets {
		subMatch := bucketAction.FindStringSubmatch(bucket)
		if len(subMatch) > 1 {
			bucketEntries[idx].Actions = subMatch[1]
		}
	}

	group.Buckets = bucketEntries
	return group
}

func parseOpenFlowGroupStatsDumpLine(line string, groupIdMap map[string]*Group) {
	match := groupStatsLine.FindStringSubmatch(line)
	result := getRegexpMap(match, groupStatsLine.SubexpNames())

	var group *Group = groupIdMap[result["groupid"]]
	group.Duration, _ = strconv.Atoi(result["duration"])
	bucketCounts := strings.Split(result["counts"], ":")

	//The 0th element in this split should contain the aggregated packet/byte counter for the whole group
	subMatch := countLine.FindStringSubmatch(bucketCounts[0])
	subResult := getRegexpMap(subMatch, countLine.SubexpNames())
	group.Packets, _ = strconv.Atoi(subResult["packet_count"])
	group.Bytes, _ = strconv.Atoi(subResult["byte_count"])

	//The others should contain bucket data
	for j := 1; j < len(bucketCounts); j++ {
		bucketMatch := countLine.FindStringSubmatch(bucketCounts[0])
		bucketResult := getRegexpMap(bucketMatch, countLine.SubexpNames())
		group.Buckets[j-1].Packets, _ = strconv.Atoi(bucketResult["packet_count"])
		group.Buckets[j-1].Bytes, _ = strconv.Atoi(bucketResult["byte_count"])
	}
}

func (o OvsDumpReader) Flows(ip string, port int) ([]Flow, error) {
	lines, err := o.dumpSource.DumpFlows(ip, port)
	//if error was occured we return
	if err != nil {
		return nil, err
	}
	entrySet := make([]Flow, len(lines))
	for i, entry := range lines {
		flowEntry := parseOpenFlowFlowDumpLine(entry)
		entrySet[i] = flowEntry
	}
	return entrySet, nil
}

func (o OvsDumpReader) Ports(ip string, port int) ([]Port, error) {
	lines, err := o.dumpSource.DumpPorts(ip, port)
	//if error was occured we return
	if err != nil {
		return nil, err
	}

	entrySet := make([]Port, int(len(lines)/2))
	for i := 0; i < len(lines); i += 2 {
		twoLines := lines[i] + lines[i+1]
		entry := parseOpenFlowPortDumpLine(twoLines)
		entrySet[int(i/2)] = entry
	}
	fmt.Println(entrySet)

	return entrySet, nil
}

func (o OvsDumpReader) Groups(ip string, port int) ([]Group, error) {
	groupLines, err := o.dumpSource.DumpGroups(ip, port)

	//if error was occured we return
	if err != nil {
		return nil, err
	}

	groupStatLines, err := o.dumpSource.DumpGroupStats(ip, port)
	//if error was occured we return
	if err != nil {
		return nil, err
	}

	//if command was succesfull we further parse the output
	groupEntries := make([]Group, len(groupLines))
	groupIdMap := make(map[string]*Group)

	for i, line := range groupLines {
		groupEntry := parseOpenFlowGroupsDumpLine(line)
		groupEntries[i] = groupEntry
		groupIdMap[groupEntry.GroupId] = &groupEntries[i]
	}

	for _, line := range groupStatLines {
		parseOpenFlowGroupStatsDumpLine(line, groupIdMap)
	}

	return groupEntries, nil
}
