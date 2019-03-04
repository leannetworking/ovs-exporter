package ovs

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

type OvsDumpSourceTest struct{}

func fileToLines(fname string) ([]string, error) {
	content, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	outString := string(content)
	lines := strings.Split(outString, "\n")
	lines = lines[1:(len(lines) - 1)]
	return lines, nil
}

func (o OvsDumpSourceTest) DumpFlows(ip string, port int) ([]string, error) {
	return fileToLines(FLOWS)
}

func (o OvsDumpSourceTest) DumpPorts(ip string, port int) ([]string, error) {
	return fileToLines(PORTS)
}

func (o OvsDumpSourceTest) DumpGroups(ip string, port int) ([]string, error) {
	return fileToLines(GROUPS)
}

func (o OvsDumpSourceTest) DumpGroupStats(ip string, port int) ([]string, error) {
	return fileToLines(GROUP_STATS)
}
