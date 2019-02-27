package main

import (
	"io/ioutil"
	"strings"
)

const (
	FLOWS       = "resources/test/dump-flows.txt"
	PORTS       = "resources/test/dump-ports.txt"
	GROUPS      = "resources/test/dump-groups.txt"
	GROUP_STATS = "resources/test/dump-group-stats.txt"
)

type ofdummy struct {
}

func fileToLines(fname string) ([]string, error) {
	content, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	outString := string(content)
	lines := strings.Split(outString, "\n")
	return lines, nil
}

func (o ofdummy) DumpFlows(ip string, port int) ([]string, error) {
	return fileToLines(FLOWS)
}

func (o ofdummy) DumpPorts(ip string, port int) ([]string, error) {
	return fileToLines(PORTS)
}

func (o ofdummy) DumpGroups(ip string, port int) ([]string, error) {
	return fileToLines(GROUPS)
}

func (o ofdummy) DumpGroupStats(ip string, port int) ([]string, error) {
	return fileToLines(GROUP_STATS)
}
