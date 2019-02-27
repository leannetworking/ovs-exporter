package main

import (
	"os/exec"
	"strconv"
	"strings"
)

type OvsOfStatReader interface {
	DumpFlows(ip string, port int) ([]string, error)
	DumpPorts(ip string, port int) ([]string, error)
	DumpGroups(ip string, port int) ([]string, error)
	DumpGroupStats(ip string, port int) ([]string, error)
}

type ofcli struct {
}

func ovsOfCtlRun(params ...string) ([]string, error) {
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

func (o ofcli) DumpFlows(ip string, port int) ([]string, error) {
	return ovsOfCtlRun("dump-flows", "tcp:"+ip+":"+strconv.Itoa(port))
}

func (o ofcli) DumpPorts(ip string, port int) ([]string, error) {
	return ovsOfCtlRun("dump-ports", "tcp:"+ip+":"+strconv.Itoa(port))
}

func (o ofcli) DumpGroups(ip string, port int) ([]string, error) {
	return ovsOfCtlRun("-O", "openflow13", "dump-groups", "tcp:"+ip+":"+strconv.Itoa(port))
}

func (o ofcli) DumpGroupStats(ip string, port int) ([]string, error) {
	return ovsOfCtlRun("-O", "openflow13", "dump-group-stats", "tcp:"+ip+":"+strconv.Itoa(port))
}
