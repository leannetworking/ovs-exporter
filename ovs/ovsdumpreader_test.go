package ovs

import "testing"

func TestGetRegexpMap(t *testing.T) {
	tests := []struct {
		match []string
		names []string
	}{
		{[]string{"a", "b", "c"}, []string{"na", "nb", "nc"}},
		{[]string{}, []string{"na", "nb", "nc"}},
	}

	for _, test := range tests {
		res := getRegexpMap(test.match, test.names)

		if len(res) != len(test.match) {
			t.Errorf("Result length mismatch. Got %d but wanted %d",
				len(res),
				len(test.match),
			)
		}

		for i := range test.match {
			name := test.names[i]
			if res[name] != test.match[i] {
				t.Errorf("RegexpMapper error. Assumed %s at res[%s] but got %s",
					test.match[i],
					name,
					res[name])
			}
		}
	}
}

func TestParseOpenFlowFlowDumpLine(t *testing.T) {
	tests := [...]struct {
		testLine   string
		testResult Flow
		testDesc   string
	}{
		{"cookie=0x0, duration=588.593s, table=0, n_packets=0, n_bytes=0, idle_age=588, priority=41000,arp actions=NORMAL",
			Flow{"0x0", 588.593, "0", 0, 0, "", 588, "41000", "arp", "NORMAL"},
			"Checking parsing on a realistic, well formatted string"},
		{"dummy line",
			Flow{"", 0.0, "", 0, 0, "", 0, "", "", ""},
			"Checking parsing on a completly irrelevant string"},
		{"cookie=0x0, duration=588.593s, table=0, n_packets=0, n_bytes=0, idle_age=588, priority=41000,arp malformed end",
			Flow{"", 0.0, "", 0, 0, "", 0, "", "", ""},
			"Checking parsing when part of the string in a required part is malformed"},
		{"cookie=0x0, duration=588.593s, table=0, n_packets=0, n_bytes=0, idle_age=588, priority=41000 actions=NORMAL",
			Flow{"0x0", 588.593, "0", 0, 0, "", 588, "41000", "", "NORMAL"},
			"Checking parsing when the optional <match> part is missing"},

		//TODO: consider if this is a bug or feature
		{"cookie=0x0, duration=NOTNUMBERs, table=0, n_packets=NOTNUMBER, n_bytes=NOTNUMBER, idle_age=NOTNUMBER, priority=41000 actions=NORMAL",
			Flow{"0x0", 0, "0", 0, 0, "", 0, "41000", "", "NORMAL"},
			"Checking non numerical parsings"},
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
