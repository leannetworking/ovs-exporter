package ovs

import "testing"

func TestGetRegexpMap(t *testing.T) {
	match := []string{"a", "b", "c"}
	names := []string{"na", "nb", "nc"}
	res := getRegexpMap(match, names)

	for i, name := range names {
		if res[name] != match[i] {
			t.Errorf("RegexpMapper error. Assumed %s at res[%s] but got %s",
				match[i],
				name,
				res[name])
		}
	}
}

func TestParseOpenFlowFlowDumpLine(t *testing.T) {
	tests := [...]struct {
		testLine   string
		testResult Flow
	}{
		{"cookie=0x0, duration=588.593s, table=0, n_packets=0, n_bytes=0, idle_age=588, priority=41000,arp actions=NORMAL",
			Flow{"0x0", 588.593, "0", 0, 0, "", 588, "41000", "arp", "NORMAL"}},
	}

	for _, test := range tests {
		res := parseOpenFlowFlowDumpLine(test.testLine)
		if res != test.testResult {
			t.Errorf("Failed to parse <%v> flow line. Expected: \n%+v\n got \n%+v",
				test.testLine,
				test.testResult,
				res)
		}
	}
}
