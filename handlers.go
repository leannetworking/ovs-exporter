package main

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
)

type collector struct {
	ip   string
	port int
}

var (
	//the passive TCP port where OVS entries are listening
	//for OpenFlow commands
	ovsPort        int             = 16633
	ofReader       OvsOfStatReader = ofcli{}
	FlowLine       *regexp.Regexp  = regexp.MustCompile("cookie=(?P<cookie>[^,]*), duration=(?P<duration>[^,]*)s, table=(?P<table>[^,]*), n_packets=(?P<packets>[^,]*), n_bytes=(?P<bytes>[^,]*),( idle_timeout=(?P<idle_timeout>[^,]*),)? idle_age=(?P<idle_age>[^,]*), priority=(?P<priority>[^,]*)(,(?P<match>[^ ]*))? actions=(?P<actions>.*)")
	PortLine       *regexp.Regexp  = regexp.MustCompile(`port\s*(?P<port>[^:]*):\srx\spkts=(?P<rxpackets>[^,]*),\sbytes=(?P<rxbytes>[^,]*),\sdrop=(?P<rxdrops>[^,]*),\serrs=(?P<rxerrors>[^,]*),\sframe=(?P<rxframerr>[^,]*),\sover=(?P<rxoverruns>[^,]*),\scrc=(?P<rxcrcerrors>[^,]*)\s.*tx\spkts=(?P<txpackets>[^,]*),\sbytes=(?P<txbytes>[^,]*),\sdrop=(?P<txdrops>[^,]*),\serrs=(?P<txerrors>[^,]*),\scoll=(?P<txcollisions>.*)`)
	GroupsLine     *regexp.Regexp  = regexp.MustCompile(`group_id=(?P<groupid>.*?),\s*type=(?P<type>[^,]*),bucket=(?P<buckets>.*$)`)
	BucketAction   *regexp.Regexp  = regexp.MustCompile("actions=(.*?),?$")
	GroupStatsLine *regexp.Regexp  = regexp.MustCompile(`group_id=(?P<groupid>.*?),duration=(?P<duration>[^,]*)s,(?P<counts>.*$)`)
	CountLine      *regexp.Regexp  = regexp.MustCompile("ref_count=(?P<ref_count>[0-9]+),packet_count=(?P<packet_count>[0-9]+),byte_count=(?P<byte_count>[0-9]+).*")

	flowPacketsDesc = prometheus.NewDesc(
		"flowPackets",
		"The number of packets matched for the given OpenFlow entry.",
		[]string{"match", "action", "table", "priority"},
		nil)

	flowBytesDesc = prometheus.NewDesc(
		"flowBytes",
		"The number of bytes matched for the given OpenFlow entry",
		[]string{"match", "action", "table", "priority"},
		nil)

	flowAgeDesc = prometheus.NewDesc(
		"flowAge",
		"The number of seconds have passed since the given OpenFlow entry was created",
		[]string{"match", "action", "table", "priority"},
		nil)

	flowIdleTimeDesc = prometheus.NewDesc(
		"flowIdleTime",
		"The number of seconds have passed since the last packet has seen for the given OpenFlow entry",
		[]string{"match", "action", "table", "priority"},
		nil)

	portRxPacketsDesc = prometheus.NewDesc(
		"portRxPackets",
		"The number of packet that was recieved by a given port",
		[]string{"portNumber"},
		nil)

	portTxPackets = prometheus.NewDesc(
		"portTxPackets",
		"The number of packet that was sent by a given port",
		[]string{"portNumber"},
		nil)

	portRxBytesDesc = prometheus.NewDesc(
		"portRxBytes",
		"The number of bytes that was recieved by a given port",
		[]string{"portNumber"},
		nil)

	portTxBytes = prometheus.NewDesc(
		"portTxBytes",
		"The number of bytes that was sent by a given port",
		[]string{"portNumber"},
		nil)

	portRxDropsDesc = prometheus.NewDesc(
		"portRxDrops",
		"The number of packets that was dropped on receive side by a given port",
		[]string{"portNumber"},
		nil)

	portTxDropsDesc = prometheus.NewDesc(
		"portTxDrops",
		"The number of packets that was dropped on sending side by a given port",
		[]string{"portNumber"},
		nil)

	groupPacketsDesc = prometheus.NewDesc(
		"groupPackets",
		"The number of packet that was sent by a given group",
		[]string{"groupId", "groupType"},
		nil)

	groupBytesDesc = prometheus.NewDesc(
		"groupBytes",
		"The number of bytes that was sent by a given group",
		[]string{"groupId", "groupType"},
		nil)

	groupDurationDesc = prometheus.NewDesc(
		"groupDuration",
		"The number of seconds passed since the group entry was added",
		[]string{"groupId", "groupType"},
		nil)

	groupBucketPacketsDesc = prometheus.NewDesc(
		"groupBucketPackets",
		"The number of packet that was sent by a given group bucket",
		[]string{"groupId", "groupType", "bucketActions"},
		nil)

	groupBucketBytesDesc = prometheus.NewDesc(
		"groupBucketBytes",
		"The number of bytes that was sent by a given group bucket",
		[]string{"groupId", "groupType", "bucketActions"},
		nil)
)

func getRegexpMap(match []string, names []string) map[string]string {
	result := make(map[string]string, len(names))
	for i, name := range names {
		result[name] = match[i]
	}
	return result
}

func parseOpenFlowFlowDumpLine(line string) Flow {
	match := FlowLine.FindStringSubmatch(line)
	result := getRegexpMap(match, FlowLine.SubexpNames())
	duration, _ := strconv.Atoi(result["duration"])
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
	match := PortLine.FindStringSubmatch(line)
	result := getRegexpMap(match, PortLine.SubexpNames())
	rxpackets, _ := strconv.Atoi(result["rxpackets"])
	txpackets, _ := strconv.Atoi(result["txpackets"])
	rxbytes, _ := strconv.Atoi(result["rxbytes"])
	txbytes, _ := strconv.Atoi(result["txbytes"])
	rxdrops, _ := strconv.Atoi(result["rxdrops"])
	txdrops, _ := strconv.Atoi(result["txdrops"])

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
	match := GroupsLine.FindStringSubmatch(line)
	result := getRegexpMap(match, GroupsLine.SubexpNames())

	group := Group{
		GroupId:   result["groupid"],
		GroupType: result["type"],
	}

	//Split the group line into buckets
	buckets := strings.Split(result["buckets"], "bucket=")
	bucketEntries := make([]Bucket, len(buckets))
	for idx, bucket := range buckets {
		subMatch := BucketAction.FindStringSubmatch(bucket)
		if len(subMatch) > 1 {
			bucketEntries[idx].Actions = subMatch[1]
		}
	}

	group.Buckets = bucketEntries
	return group
}

func parseOpenFlowGroupStatsDumpLine(line string, groupIdMap map[string]*Group) {
	match := GroupStatsLine.FindStringSubmatch(line)
	result := getRegexpMap(match, GroupStatsLine.SubexpNames())

	var group *Group = groupIdMap[result["groupid"]]
	group.Duration, _ = strconv.Atoi(result["duration"])
	bucketCounts := strings.Split(result["counts"], ":")

	//The 0th element in this split should contain the aggregated packet/byte counter for the whole group
	subMatch := CountLine.FindStringSubmatch(bucketCounts[0])
	subResult := getRegexpMap(subMatch, CountLine.SubexpNames())
	group.Packets, _ = strconv.Atoi(subResult["packet_count"])
	group.Bytes, _ = strconv.Atoi(subResult["byte_count"])

	//The others should contain bucket data
	for j := 1; j < len(bucketCounts); j++ {
		bucketMatch := CountLine.FindStringSubmatch(bucketCounts[0])
		bucketResult := getRegexpMap(bucketMatch, CountLine.SubexpNames())
		group.Buckets[j-1].Packets, _ = strconv.Atoi(bucketResult["packet_count"])
		group.Buckets[j-1].Bytes, _ = strconv.Atoi(bucketResult["byte_count"])
	}
}

// Describe implements Prometheus.Collector.
func (c collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("dummy", "dummy", nil, nil)
}

// Collect implements Prometheus.Collector.
func (c collector) Collect(ch chan<- prometheus.Metric) {
	if c.ip == "" {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("ovsof_error", "Error scraping target. Correct format is: http://<IP>:<Port>/flows?target=<targetIP>", nil, nil), nil)
		return
	}

	lines, err := ofReader.DumpFlows(c.ip, c.port)
	//if error was occured we return
	if err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("ovsof_error", "Error parsing flow dump", nil, nil), err)
		return
	}
	//if command was succesfull we further parse the output
	flowEntries := make([]Flow, len(lines))
	for i, entry := range lines {
		flowEntries[i] = parseOpenFlowFlowDumpLine(entry)
	}

	//Creating Prometheus compatible output for:
	//	- number of packets as "flowPackets" type Counter
	//	- number of bytes as "flowBytes" type Counter
	//	- age of the flow as "flowAge" type Gauge
	//	- idle time as "flowIdleTime" type Gauge

	for _, entry := range flowEntries {
		ch <- prometheus.MustNewConstMetric(
			flowPacketsDesc,
			prometheus.CounterValue,
			float64(entry.Packets),
			entry.Match,
			entry.Action,
			entry.Table,
			entry.Priority)

		ch <- prometheus.MustNewConstMetric(
			flowBytesDesc,
			prometheus.CounterValue,
			float64(entry.Bytes),
			entry.Match,
			entry.Action,
			entry.Table,
			entry.Priority)

		ch <- prometheus.MustNewConstMetric(
			flowAgeDesc,
			prometheus.GaugeValue,
			float64(entry.Duration),
			entry.Match,
			entry.Action,
			entry.Table,
			entry.Priority)

		ch <- prometheus.MustNewConstMetric(
			flowIdleTimeDesc,
			prometheus.GaugeValue,
			float64(entry.IdleAge),
			entry.Match,
			entry.Action,
			entry.Table,
			entry.Priority)
	}

	lines, err = ofReader.DumpPorts(c.ip, c.port)
	//if error was occured we return
	if err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("ovsof_error", "Error parsing port dump", nil, nil), err)
		return
	}
	//if command was succesfull we further parse the output
	portEntries := make([]Port, int(len(lines)/2))
	for i := 0; i < len(lines); i += 2 {
		twoLines := lines[i] + lines[i+1]
		portEntries[int(i/2)] = parseOpenFlowPortDumpLine(twoLines)
	}

	//Creating Prometheus compatible output for every stat with portNumber identifyer:
	//	- number of packets recieved by the given OpenFlow port as "portRxPackets" type Counter
	//	- number of packets sent by the given OpenFlow port as "portTxPackets" type Counter
	//	- number of bytes recieved by the given OpenFlow port as "portRxBytes" type Counter
	//	- number of bytes sent by the given OpenFlow port as "portTxBytes" type Counter
	//	- number of packet drops in recieve side by the given OpenFlow port as "portRxDrops" type Counter
	//	- number of packet drops in sending side by the given OpenFlow port as "portTxDrops" type Counter

	for _, entry := range portEntries {
		ch <- prometheus.MustNewConstMetric(
			portRxPacketsDesc,
			prometheus.CounterValue,
			float64(entry.RxPackets),
			entry.PortNumber)

		ch <- prometheus.MustNewConstMetric(
			portTxPackets,
			prometheus.CounterValue,
			float64(entry.TxPackets),
			entry.PortNumber)

		ch <- prometheus.MustNewConstMetric(
			portRxBytesDesc,
			prometheus.CounterValue,
			float64(entry.RxBytes),
			entry.PortNumber)

		ch <- prometheus.MustNewConstMetric(
			portTxBytes,
			prometheus.CounterValue,
			float64(entry.TxBytes),
			entry.PortNumber)

		ch <- prometheus.MustNewConstMetric(
			portRxDropsDesc,
			prometheus.CounterValue,
			float64(entry.RxDrops),
			entry.PortNumber)

		ch <- prometheus.MustNewConstMetric(
			portTxDropsDesc,
			prometheus.CounterValue,
			float64(entry.TxDrops),
			entry.PortNumber)
	}

	lines, err = ofReader.DumpGroups(c.ip, c.port)
	//if error was occured we return
	if err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("ovsof_error", "Error parsing group dump", nil, nil), err)
		return
	}
	//if command was succesfull we further parse the output
	groupEntries := make([]*Group, len(lines))
	groupIdMap := make(map[string]*Group)
	for i, line := range lines {
		groupEntry := parseOpenFlowGroupsDumpLine(line)
		groupEntries[i] = &groupEntry
		groupIdMap[groupEntry.GroupId] = &groupEntry
	}

	lines, err = ofReader.DumpGroupStats(c.ip, c.port)
	//if error was occured we return
	if err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("ovsof_error", "Error parsing group stat dump", nil, nil), err)
		return
	}
	for _, line := range lines {
		parseOpenFlowGroupStatsDumpLine(line, groupIdMap)
	}

	//Creating Prometheus compatible output for every group stat with groupId label:
	//	- number of packets that was forwarded by a group rule as "groupPackets" type Counter
	//	- number of bytes that was forwarded by a group rule as "groupBytes" type Counter
	//	- number of second that passed since a group rule was added as "groupPackets" type Gauge
	//	- number of packets that was forwarded by a bucket in a group rule as "groupBucketPackets" type Counter
	//	- number of bytes that was forwarded by a bucket in a group rule as "groupBucketBytes" type Counter

	for _, entry := range groupEntries {

		ch <- prometheus.MustNewConstMetric(
			groupPacketsDesc,
			prometheus.CounterValue,
			float64(entry.Packets),
			entry.GroupId,
			entry.GroupType)

		ch <- prometheus.MustNewConstMetric(
			groupBytesDesc,
			prometheus.CounterValue,
			float64(entry.Bytes),
			entry.GroupId,
			entry.GroupType)

		ch <- prometheus.MustNewConstMetric(
			groupDurationDesc,
			prometheus.CounterValue,
			float64(entry.Duration),
			entry.GroupId,
			entry.GroupType)

		for _, bucket := range entry.Buckets {
			ch <- prometheus.MustNewConstMetric(
				groupBucketPacketsDesc,
				prometheus.CounterValue,
				float64(bucket.Packets),
				entry.GroupId,
				entry.GroupType,
				bucket.Actions)

			ch <- prometheus.MustNewConstMetric(
				groupBucketBytesDesc,
				prometheus.CounterValue,
				float64(bucket.Bytes),
				entry.GroupId,
				entry.GroupType,
				bucket.Actions)
		}
	}
}
