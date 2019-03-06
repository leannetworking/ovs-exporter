package ovs

import (
	"reflect"
	"testing"
)

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
		t.Log(test.testDesc)
		res := parseOpenFlowFlowDumpLine(test.testLine)
		if res != test.testResult {
			t.Errorf("Failed to parse <%v> flow line. Expected: \n%+v\n got \n%+v",
				test.testLine,
				test.testResult,
				res)
		}
	}
}
func TestParseOpenFlowPortDumpLine(t *testing.T) {
	tests := [...]struct {
		// In port dump one port stat splitted in two lines
		firstLine   string
		secondLine  string
		result      Port
		description string
	}{
		{"port PRT: rx pkts=1, bytes=2, drop=3, errs=4, frame=5, over=6, crc=7",
			"tx pkts=8, bytes=9, drop=10, errs=11, coll=12",
			Port{"PRT", 1, 8, 2, 9, 3, 10, "4", "11", "5", "6", "7", "12"},
			"Checking parsing on a realistic, well formatted string"},
		{"dummy line 1", "dummy line 2",
			Port{"", 0, 0, 0, 0, 0, 0, "", "", "", "", "", ""},
			"Checking parsing on a completly irrelevant string"},
		{"port PRT: rx pkts=1, bytes=2, drop=3, errs=4, frame=5, malformed",
			"tx pkts=8, bytes=9, drop=10, errs=11, coll=12",
			Port{"", 0, 0, 0, 0, 0, 0, "", "", "", "", "", ""},
			"Checking parsing when part of the string in a required part is malformed"},
		{"port PRT: rx pkts=1, bytes=?, drop=3, errs=4, frame=5, over=6, crc=7",
			"tx pkts=?, bytes=9, drop=10, errs=11, coll=12",
			Port{"PRT", 1, 0, 0, 9, 3, 10, "4", "11", "5", "6", "7", "12"},
			"Checking parsing when ? is presented in counters"},

		//TODO: consider if this is a bug or feature
		{"port PRT: rx pkts=str, bytes=2, drop=3, errs=4, frame=5, over=6, crc=7",
			"tx pkts=8, bytes=9, drop=str, errs=11, coll=12",
			Port{"PRT", 0, 8, 2, 9, 3, 0, "4", "11", "5", "6", "7", "12"},
			"Checking non numerical parsings"},
		{"",
			"tx pkts=?, bytes=9, drop=10, errs=11, coll=12",
			Port{"", 0, 0, 0, 0, 0, 0, "", "", "", "", "", ""},
			"Checking when first line is empty"},
		{"port PRT: rx pkts=1, bytes=?, drop=3, errs=4, frame=5, over=6, crc=7",
			"",
			Port{"", 0, 0, 0, 0, 0, 0, "", "", "", "", "", ""},
			"Checking when second line is empty"},
	}

	for _, test := range tests {
		t.Log(test.description)
		res := parseOpenFlowPortDumpLine(test.firstLine+"\n", test.secondLine+"\n")
		if res != test.result {
			t.Errorf("Failed to parse <%v> flow line. Expected: \n%+v\n got \n%+v",
				test.firstLine+test.secondLine,
				test.result,
				res)
		}
	}
}

func TestParseOpenFlowGroupsDumpLine(t *testing.T) {
	tests := [...]struct {
		testline    string
		result      Group
		description string
	}{
		{"group_id=1011,type=gt,bucket=actions=b1f1:b1v1,b1f2:b1v2,bucket=actions=b2f1:b2v1,b2f2:b2v2",
			Group{GroupId: "1011", GroupType: "gt",
				Buckets: []Bucket{
					{Actions: "b1f1:b1v1,b1f2:b1v2"},
					{Actions: "b2f1:b2v1,b2f2:b2v2"},
				}},
			"Checking parsing on a realistic, well formatted string"},
		{"dummy string",
			Group{GroupId: "", GroupType: "", Buckets: nil},
			"Checking parsing on a completly irrelevant string"},
		{"group_id=1011,type=gt,malformed=actions=b1f1:b1v1,b1f2:b1v2,bucket=actions=b2f1:b2v1,b2f2:b2v2",
			Group{GroupId: "", GroupType: "", Buckets: nil},
			"Checking parsing when part of the string in a required part is malformed"},
	}

	for _, test := range tests {
		t.Log(test.description)
		res := parseOpenFlowGroupsDumpLine(test.testline)
		if !reflect.DeepEqual(res, test.result) {
			t.Errorf("Failed to parse <%#v> flow line. Expected: \n%+#v\n got \n%+#v",
				test.testline,
				test.result,
				res)
		}
	}

}
