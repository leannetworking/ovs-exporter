package main

import (
	"github.com/leannetworking/ovs-exporter/ovs"
	"github.com/prometheus/client_golang/prometheus"
)

type OvsPromCollector struct {
	ip        string
	port      int
	ovsReader ovs.OvsStatReader
}

var (
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

	urlParsingErrorDesc = prometheus.NewDesc(
		"ovs_error",
		"Error scraping target. Correct format is: http://<IP>:<Port>/flows?target=<targetIP>",
		nil, nil)
)

// Describe implements Prometheus.Collector.
func (c OvsPromCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("dummy", "dummy", nil, nil)
}

// Collect implements Prometheus.Collector.
func (c OvsPromCollector) Collect(ch chan<- prometheus.Metric) {
	if c.ip == "" {
		ch <- prometheus.NewInvalidMetric(urlParsingErrorDesc, nil)
		return
	}

	//Creating Prometheus compatible output for:
	//	- number of packets as "flowPackets" type Counter
	//	- number of bytes as "flowBytes" type Counter
	//	- age of the flow as "flowAge" type Gauge
	//	- idle time as "flowIdleTime" type Gauge

	flowEntries, err := c.ovsReader.Flows(c.ip, c.port)

	if err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("ovs_error", "Error parsing flow dump", nil, nil), err)
		return
	}

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

	portEntries, err := c.ovsReader.Ports(c.ip, c.port)
	//if error was occured we return
	if err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("ovs_error", "Error parsing port dump", nil, nil), err)
		return
	}
	//if command was succesfull we further parse the output
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

	groupEntries, err := c.ovsReader.Groups(c.ip, c.port)
	//if error was occured we return
	if err != nil {
		ch <- prometheus.NewInvalidMetric(prometheus.NewDesc("ovs_error", "Error parsing group dump", nil, nil), err)
		return
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
