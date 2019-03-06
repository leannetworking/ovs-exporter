package ovs

import (
	"os/exec"
	"strconv"
	"strings"
)

type OvsDumpSourceCLI struct{}

func ovsCtlRun(params ...string) ([]string, error) {
	cmd := exec.Command("ovs-ofctl", params...)
	out, err := cmd.Output()
	outString := string(out)
	//if error was occured we return
	if err != nil {
		return nil, err
	}
	//if command was succesfull we further parse the output

	lines := strings.Split(outString, "\n")
	//skip the first and last lines, since it is just a response header and an empty line
	lines = lines[1:(len(lines) - 1)]
	return lines, nil
}

func (o OvsDumpSourceCLI) DumpFlows(ip string, port int) ([]string, error) {
	return ovsCtlRun("dump-flows", "tcp:"+ip+":"+strconv.Itoa(port))
}

func (o OvsDumpSourceCLI) DumpPorts(ip string, port int) ([]string, error) {
	return ovsCtlRun("dump-ports", "tcp:"+ip+":"+strconv.Itoa(port))
}

func (o OvsDumpSourceCLI) DumpGroups(ip string, port int) ([]string, error) {
	return ovsCtlRun("-O", "openflow13", "dump-groups", "tcp:"+ip+":"+strconv.Itoa(port))
}

func (o OvsDumpSourceCLI) DumpGroupStats(ip string, port int) ([]string, error) {
	return ovsCtlRun("-O", "openflow13", "dump-group-stats", "tcp:"+ip+":"+strconv.Itoa(port))
}
