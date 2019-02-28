package main

import (
	"io/ioutil"
	"net/http/httptest"
	"testing"
)

const HANDLER_OUTPUT = `# HELP flowPackets The number of packets matched for the given OpenFlow entry
# TYPE flowPackets counter
flowPackets{match="arp",action="NORMAL",table="0",priority="41000"} 0
flowPackets{match="ip",action="LOCAL",table="0",priority="10"} 460
flowPackets{match="ip,nw_dst=10.244.7.1",action="mod_dl_dst:0a:58:0a:f4:07:01,LOCAL",table="0",priority="90"} 0
flowPackets{match="ip,nw_dst=10.96.0.1",action="LOCAL",table="0",priority="70"} 630
flowPackets{match="in_port=1",action="resubmit(,5)",table="0",priority="50"} 0
flowPackets{match="ip,nw_src=10.244.0.0/16,nw_dst=192.168.0.0/16",action="resubmit(,2)",table="0",priority="33"} 8
flowPackets{match="ip,nw_src=172.16.0.0/16,nw_dst=192.168.0.0/16",action="resubmit(,2)",table="0",priority="33"} 0
flowPackets{match="ip,nw_src=10.244.0.0/16,nw_dst=10.96.0.0/12",action="resubmit(,3)",table="0",priority="33"} 118
flowPackets{match="ip,nw_dst=10.244.0.0/16",action="resubmit(,4)",table="0",priority="30"} 0
flowPackets{match="udp,nw_src=10.244.7.3,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 8
flowPackets{match="udp,nw_src=10.244.7.2,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.3,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.2,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.4,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.109.186.133,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.5,tp_src=3306",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.110.235.87,mod_tp_src:3306,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.7,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.6,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.98.153.149,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.8,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.108.104.82,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.9,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.111.233.21,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.10,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.109.119.135,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.11,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.105.230.145,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.12,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.101.235.60,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.13,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.101.140.235,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.14,tp_src=5672",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.104.140.235,mod_tp_src:5672,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.17,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.15,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.97.137.63,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.18,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="tcp,nw_src=10.244.7.16,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.98.168.141,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 0
flowPackets{match="ip",action="resubmit(,4)",table="2",priority="1"} 0
# HELP flowBytes The number of bytes matched for the given OpenFlow entry
# TYPE flowBytes counter
flowBytes{match="arp",action="NORMAL",table="0",priority="41000"} 0
flowBytes{match="ip",action="LOCAL",table="0",priority="10"} 45580
flowBytes{match="ip,nw_dst=10.244.7.1",action="mod_dl_dst:0a:58:0a:f4:07:01,LOCAL",table="0",priority="90"} 0
flowBytes{match="ip,nw_dst=10.96.0.1",action="LOCAL",table="0",priority="70"} 46620
flowBytes{match="in_port=1",action="resubmit(,5)",table="0",priority="50"} 0
flowBytes{match="ip,nw_src=10.244.0.0/16,nw_dst=192.168.0.0/16",action="resubmit(,2)",table="0",priority="33"} 1290
flowBytes{match="ip,nw_src=172.16.0.0/16,nw_dst=192.168.0.0/16",action="resubmit(,2)",table="0",priority="33"} 0
flowBytes{match="ip,nw_src=10.244.0.0/16,nw_dst=10.96.0.0/12",action="resubmit(,3)",table="0",priority="33"} 11136
flowBytes{match="ip,nw_dst=10.244.0.0/16",action="resubmit(,4)",table="0",priority="30"} 0
flowBytes{match="udp,nw_src=10.244.7.3,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 1290
flowBytes{match="udp,nw_src=10.244.7.2,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.3,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.2,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.4,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.109.186.133,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.5,tp_src=3306",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.110.235.87,mod_tp_src:3306,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.7,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.6,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.98.153.149,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.8,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.108.104.82,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.9,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.111.233.21,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.10,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.109.119.135,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.11,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.105.230.145,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.12,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.101.235.60,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.13,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.101.140.235,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.14,tp_src=5672",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.104.140.235,mod_tp_src:5672,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.17,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.15,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.97.137.63,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.18,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="tcp,nw_src=10.244.7.16,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.98.168.141,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 0
flowBytes{match="ip",action="resubmit(,4)",table="2",priority="1"} 0
# HELP flowAge The number of seconds have passed since the given OpenFlow entry was created
# TYPE flowAge gauge
flowAge{match="arp",action="NORMAL",table="0",priority="41000"} 588.593
flowAge{match="ip",action="LOCAL",table="0",priority="10"} 588.591
flowAge{match="ip,nw_dst=10.244.7.1",action="mod_dl_dst:0a:58:0a:f4:07:01,LOCAL",table="0",priority="90"} 588.592
flowAge{match="ip,nw_dst=10.96.0.1",action="LOCAL",table="0",priority="70"} 588.590
flowAge{match="in_port=1",action="resubmit(,5)",table="0",priority="50"} 588.592
flowAge{match="ip,nw_src=10.244.0.0/16,nw_dst=192.168.0.0/16",action="resubmit(,2)",table="0",priority="33"} 588.592
flowAge{match="ip,nw_src=172.16.0.0/16,nw_dst=192.168.0.0/16",action="resubmit(,2)",table="0",priority="33"} 588.592
flowAge{match="ip,nw_src=10.244.0.0/16,nw_dst=10.96.0.0/12",action="resubmit(,3)",table="0",priority="33"} 588.592
flowAge{match="ip,nw_dst=10.244.0.0/16",action="resubmit(,4)",table="0",priority="30"} 588.591
flowAge{match="udp,nw_src=10.244.7.3,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 588.591
flowAge{match="udp,nw_src=10.244.7.2,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 588.591
flowAge{match="tcp,nw_src=10.244.7.3,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 588.590
flowAge{match="tcp,nw_src=10.244.7.2,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 588.590
flowAge{match="tcp,nw_src=10.244.7.4,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.109.186.133,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 103.409
flowAge{match="tcp,nw_src=10.244.7.5,tp_src=3306",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.110.235.87,mod_tp_src:3306,resubmit(,4)",table="2",priority="100"} 97.361
flowAge{match="tcp,nw_src=10.244.7.7,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 92.215
flowAge{match="tcp,nw_src=10.244.7.6,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.98.153.149,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 86.171
flowAge{match="tcp,nw_src=10.244.7.8,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.108.104.82,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 82.834
flowAge{match="tcp,nw_src=10.244.7.9,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.111.233.21,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 81.776
flowAge{match="tcp,nw_src=10.244.7.10,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.109.119.135,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 76.290
flowAge{match="tcp,nw_src=10.244.7.11,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.105.230.145,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 73.383
flowAge{match="tcp,nw_src=10.244.7.12,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.101.235.60,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 69.049
flowAge{match="tcp,nw_src=10.244.7.13,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.101.140.235,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 63.654
flowAge{match="tcp,nw_src=10.244.7.14,tp_src=5672",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.104.140.235,mod_tp_src:5672,resubmit(,4)",table="2",priority="100"} 44.216
flowAge{match="tcp,nw_src=10.244.7.17,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 38.034
flowAge{match="tcp,nw_src=10.244.7.15,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.97.137.63,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 37.079
flowAge{match="tcp,nw_src=10.244.7.18,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 36.956
flowAge{match="tcp,nw_src=10.244.7.16,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.98.168.141,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 6.549
flowAge{match="ip",action="resubmit(,4)",table="2",priority="1"} 588.590
# HELP flowIdleTime The number of seconds have passed since the last packet has seen for the given OpenFlow entry
# TYPE flowIdleTime gauge
flowIdleTime{match="arp",action="NORMAL",table="0",priority="41000"} 588
flowIdleTime{match="ip",action="LOCAL",table="0",priority="10"} 3
flowIdleTime{match="ip,nw_dst=10.244.7.1",action="mod_dl_dst:0a:58:0a:f4:07:01,LOCAL",table="0",priority="90"} 588
flowIdleTime{match="ip,nw_dst=10.96.0.1",action="LOCAL",table="0",priority="70"} 0
flowIdleTime{match="in_port=1",action="resubmit(,5)",table="0",priority="50"} 588
flowIdleTime{match="ip,nw_src=10.244.0.0/16,nw_dst=192.168.0.0/16",action="resubmit(,2)",table="0",priority="33"} 49
flowIdleTime{match="ip,nw_src=172.16.0.0/16,nw_dst=192.168.0.0/16",action="resubmit(,2)",table="0",priority="33"} 588
flowIdleTime{match="ip,nw_src=10.244.0.0/16,nw_dst=10.96.0.0/12",action="resubmit(,3)",table="0",priority="33"} 0
flowIdleTime{match="ip,nw_dst=10.244.0.0/16",action="resubmit(,4)",table="0",priority="30"} 588
flowIdleTime{match="udp,nw_src=10.244.7.3,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 49
flowIdleTime{match="udp,nw_src=10.244.7.2,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 588
flowIdleTime{match="tcp,nw_src=10.244.7.3,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 588
flowIdleTime{match="tcp,nw_src=10.244.7.2,tp_src=53",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.96.0.10,mod_tp_src:53,resubmit(,4)",table="2",priority="100"} 588
flowIdleTime{match="tcp,nw_src=10.244.7.4,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.109.186.133,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 103
flowIdleTime{match="tcp,nw_src=10.244.7.5,tp_src=3306",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.110.235.87,mod_tp_src:3306,resubmit(,4)",table="2",priority="100"} 97
flowIdleTime{match="tcp,nw_src=10.244.7.7,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 92
flowIdleTime{match="tcp,nw_src=10.244.7.6,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.98.153.149,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 86
flowIdleTime{match="tcp,nw_src=10.244.7.8,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.108.104.82,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 82
flowIdleTime{match="tcp,nw_src=10.244.7.9,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.111.233.21,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 81
flowIdleTime{match="tcp,nw_src=10.244.7.10,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.109.119.135,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 76
flowIdleTime{match="tcp,nw_src=10.244.7.11,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.105.230.145,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 73
flowIdleTime{match="tcp,nw_src=10.244.7.12,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.101.235.60,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 69
flowIdleTime{match="tcp,nw_src=10.244.7.13,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.101.140.235,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 63
flowIdleTime{match="tcp,nw_src=10.244.7.14,tp_src=5672",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.104.140.235,mod_tp_src:5672,resubmit(,4)",table="2",priority="100"} 44
flowIdleTime{match="tcp,nw_src=10.244.7.17,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 38
flowIdleTime{match="tcp,nw_src=10.244.7.15,tp_src=80",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.97.137.63,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 37
flowIdleTime{match="tcp,nw_src=10.244.7.18,tp_src=8079",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.103.85.83,mod_tp_src:80,resubmit(,4)",table="2",priority="100"} 36
flowIdleTime{match="tcp,nw_src=10.244.7.16,tp_src=27017",action="load:0xaf4->NXM_OF_IP_DST[16..31],mod_nw_src:10.98.168.141,mod_tp_src:27017,resubmit(,4)",table="2",priority="100"} 6
flowIdleTime{match="ip",action="resubmit(,4)",table="2",priority="1"} 588
# HELP portRxPackets The number of packet that was recieved by a given port
# TYPE portRxPackets counter
portRxPackets{portNumber="LOCAL"} 0
portRxPackets{portNumber="8"} 26
portRxPackets{portNumber="10"} 8
portRxPackets{portNumber="14"} 0
portRxPackets{portNumber="18"} 16
portRxPackets{portNumber="17"} 16
portRxPackets{portNumber="11"} 0
portRxPackets{portNumber="13"} 34
portRxPackets{portNumber="16"} 0
portRxPackets{portNumber="5"} 0
portRxPackets{portNumber="9"} 0
portRxPackets{portNumber="12"} 8
portRxPackets{portNumber="15"} 0
portRxPackets{portNumber="7"} 22
portRxPackets{portNumber="6"} 12
portRxPackets{portNumber="4"} 0
portRxPackets{portNumber="1"} 0
portRxPackets{portNumber="2"} 585
portRxPackets{portNumber="3"} 595
# HELP portTxPackets The number of packet that was sent by a given port
# TYPE portTxPackets counter
portTxPackets{portNumber="LOCAL"} 0
portTxPackets{portNumber="8"} 19
portTxPackets{portNumber="10"} 11
portTxPackets{portNumber="14"} 11
portTxPackets{portNumber="18"} 9
portTxPackets{portNumber="17"} 9
portTxPackets{portNumber="11"} 10
portTxPackets{portNumber="13"} 11
portTxPackets{portNumber="16"} 11
portTxPackets{portNumber="5"} 11
portTxPackets{portNumber="9"} 11
portTxPackets{portNumber="12"} 11
portTxPackets{portNumber="15"} 11
portTxPackets{portNumber="7"} 11
portTxPackets{portNumber="6"} 11
portTxPackets{portNumber="4"} 11
portTxPackets{portNumber="1"} 0
portTxPackets{portNumber="2"} 41
portTxPackets{portNumber="3"} 49
# HELP portRxBytes The number of bytes that was recieved by a given port
# TYPE portRxBytes counter
portRxBytes{portNumber="LOCAL"} 0
portRxBytes{portNumber="8"} 2416
portRxBytes{portNumber="10"} 760
portRxBytes{portNumber="14"} 0
portRxBytes{portNumber="18"} 1536
portRxBytes{portNumber="17"} 1536
portRxBytes{portNumber="11"} 0
portRxBytes{portNumber="13"} 3162
portRxBytes{portNumber="16"} 0
portRxBytes{portNumber="5"} 0
portRxBytes{portNumber="9"} 0
portRxBytes{portNumber="12"} 752
portRxBytes{portNumber="15"} 0
portRxBytes{portNumber="7"} 2112
portRxBytes{portNumber="6"} 1128
portRxBytes{portNumber="4"} 0
portRxBytes{portNumber="1"} 0
portRxBytes{portNumber="2"} 49290
portRxBytes{portNumber="3"} 50968
# HELP portTxBytes The number of bytes that was sent by a given port
# TYPE portTxBytes counter
portTxBytes{portNumber="LOCAL"} 0
portTxBytes{portNumber="8"} 2156
portTxBytes{portNumber="10"} 866
portTxBytes{portNumber="14"} 866
portTxBytes{portNumber="18"} 726
portTxBytes{portNumber="17"} 726
portTxBytes{portNumber="11"} 796
portTxBytes{portNumber="13"} 866
portTxBytes{portNumber="16"} 866
portTxBytes{portNumber="5"} 866
portTxBytes{portNumber="9"} 866
portTxBytes{portNumber="12"} 866
portTxBytes{portNumber="15"} 866
portTxBytes{portNumber="7"} 866
portTxBytes{portNumber="6"} 866
portTxBytes{portNumber="4"} 866
portTxBytes{portNumber="1"} 0
portTxBytes{portNumber="2"} 3403
portTxBytes{portNumber="3"} 4135
# HELP portRxDrops The number of packets that was dropped on receive side by a given port
# TYPE portRxDrops counter
portRxDrops{portNumber="LOCAL"} 1157
portRxDrops{portNumber="8"} 0
portRxDrops{portNumber="10"} 0
portRxDrops{portNumber="14"} 0
portRxDrops{portNumber="18"} 0
portRxDrops{portNumber="17"} 0
portRxDrops{portNumber="11"} 0
portRxDrops{portNumber="13"} 0
portRxDrops{portNumber="16"} 0
portRxDrops{portNumber="5"} 0
portRxDrops{portNumber="9"} 0
portRxDrops{portNumber="12"} 0
portRxDrops{portNumber="15"} 0
portRxDrops{portNumber="7"} 0
portRxDrops{portNumber="6"} 0
portRxDrops{portNumber="4"} 0
portRxDrops{portNumber="1"} 0
portRxDrops{portNumber="2"} 0
portRxDrops{portNumber="3"} 0
# HELP portTxDrops The number of packets that was dropped on sending side by a given port
# TYPE portTxDrops counter
portTxDrops{portNumber="LOCAL"} 0
portTxDrops{portNumber="8"} 0
portTxDrops{portNumber="10"} 0
portTxDrops{portNumber="14"} 0
portTxDrops{portNumber="18"} 0
portTxDrops{portNumber="17"} 0
portTxDrops{portNumber="11"} 0
portTxDrops{portNumber="13"} 0
portTxDrops{portNumber="16"} 0
portTxDrops{portNumber="5"} 0
portTxDrops{portNumber="9"} 0
portTxDrops{portNumber="12"} 0
portTxDrops{portNumber="15"} 0
portTxDrops{portNumber="7"} 0
portTxDrops{portNumber="6"} 0
portTxDrops{portNumber="4"} 0
portTxDrops{portNumber="1"} 0
portTxDrops{portNumber="2"} 0
portTxDrops{portNumber="3"} 0
# HELP groupPackets The number of packet that was sent by a given group
# TYPE groupPackets counter
groupPackets{groupId="1011",groupType="select"} 0
groupPackets{groupId="1013",groupType="select"} 0
groupPackets{groupId="1004",groupType="select"} 0
groupPackets{groupId="1014",groupType="select"} 0
groupPackets{groupId="1002",groupType="select"} 0
groupPackets{groupId="1003",groupType="select"} 0
groupPackets{groupId="1001",groupType="select"} 0
groupPackets{groupId="1008",groupType="select"} 0
groupPackets{groupId="1006",groupType="select"} 0
groupPackets{groupId="1007",groupType="select"} 0
groupPackets{groupId="1009",groupType="select"} 0
groupPackets{groupId="1000",groupType="select"} 0
groupPackets{groupId="1010",groupType="select"} 0
groupPackets{groupId="1005",groupType="select"} 0
groupPackets{groupId="1012",groupType="select"} 0
groupPackets{groupId="",groupType=""} 
# HELP groupBytes The number of bytes that was sent by a given group
# TYPE groupBytes counter
groupBytes{groupId="1011",groupType="select"} 0
groupBytes{groupId="1013",groupType="select"} 0
groupBytes{groupId="1004",groupType="select"} 0
groupBytes{groupId="1014",groupType="select"} 0
groupBytes{groupId="1002",groupType="select"} 0
groupBytes{groupId="1003",groupType="select"} 0
groupBytes{groupId="1001",groupType="select"} 0
groupBytes{groupId="1008",groupType="select"} 0
groupBytes{groupId="1006",groupType="select"} 0
groupBytes{groupId="1007",groupType="select"} 0
groupBytes{groupId="1009",groupType="select"} 0
groupBytes{groupId="1000",groupType="select"} 0
groupBytes{groupId="1010",groupType="select"} 0
groupBytes{groupId="1005",groupType="select"} 0
groupBytes{groupId="1012",groupType="select"} 0
groupBytes{groupId="",groupType=""} 
# HELP groupDuration The number of seconds passed since the group entry was added
# TYPE groupDuration gauge
groupDuration{groupId="1011",groupType="select"} 113.489
groupDuration{groupId="1013",groupType="select"} 87.005
groupDuration{groupId="1004",groupType="select"} 142.068
groupDuration{groupId="1014",groupType="select"} 56.481
groupDuration{groupId="1002",groupType="select"} 153.283
groupDuration{groupId="1003",groupType="select"} 147.180
groupDuration{groupId="1001",groupType="select"} 638.372
groupDuration{groupId="1008",groupType="select"} 126.376
groupDuration{groupId="1006",groupType="select"} 132.689
groupDuration{groupId="1007",groupType="select"} 131.596
groupDuration{groupId="1009",groupType="select"} 123.263
groupDuration{groupId="1000",groupType="select"} 638.372
groupDuration{groupId="1010",groupType="select"} 119.089
groupDuration{groupId="1005",groupType="select"} 135.980
groupDuration{groupId="1012",groupType="select"} 94.307
groupDuration{groupId="",groupType=""} 
# HELP groupBucketPackets The number of packet that was sent by a given group bucket
# TYPE groupBucketPackets counter
groupBucketPackets{groupId="1011",groupType="select",bucketActions="set_field:10.244.7.18->ip_dst,set_field:8079->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1011",groupType="select",bucketActions="set_field:10.244.7.7->ip_dst,set_field:8079->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1011",groupType="select",bucketActions="set_field:10.244.7.17->ip_dst,set_field:8079->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1013",groupType="select",bucketActions="set_field:10.244.7.9->ip_dst,set_field:27017->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1004",groupType="select",bucketActions="set_field:10.244.7.16->ip_dst,set_field:27017->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1014",groupType="select",bucketActions="set_field:10.244.7.13->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1002",groupType="select",bucketActions="set_field:10.244.7.4->ip_dst,set_field:27017->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1003",groupType="select",bucketActions="set_field:10.244.7.10->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1001",groupType="select",bucketActions="set_field:10.244.7.14->ip_dst,set_field:5672->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1008",groupType="select",bucketActions="set_field:10.244.7.3->ip_dst,set_field:53->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1008",groupType="select",bucketActions="set_field:10.244.7.2->ip_dst,set_field:53->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1006",groupType="select",bucketActions="set_field:10.244.7.8->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1007",groupType="select",bucketActions="set_field:10.244.7.3->ip_dst,set_field:53->udp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1007",groupType="select",bucketActions="set_field:10.244.7.2->ip_dst,set_field:53->udp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1009",groupType="select",bucketActions="set_field:10.244.7.6->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1000",groupType="select",bucketActions="set_field:10.244.7.12->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1010",groupType="select",bucketActions="set_field:10.244.7.11->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1005",groupType="select",bucketActions="set_field:10.244.7.15->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketPackets{groupId="1012",groupType="select",bucketActions="set_field:10.244.7.5->ip_dst,set_field:3306->tcp_dst,resubmit(,4)"} 0
# HELP groupBucketBytes The number of bytes that was sent by a given group bucket
# TYPE groupBucketBytes counter
groupBucketBytes{groupId="1011",groupType="select",bucketActions="set_field:10.244.7.18->ip_dst,set_field:8079->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1011",groupType="select",bucketActions="set_field:10.244.7.7->ip_dst,set_field:8079->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1011",groupType="select",bucketActions="set_field:10.244.7.17->ip_dst,set_field:8079->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1013",groupType="select",bucketActions="set_field:10.244.7.9->ip_dst,set_field:27017->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1004",groupType="select",bucketActions="set_field:10.244.7.16->ip_dst,set_field:27017->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1014",groupType="select",bucketActions="set_field:10.244.7.13->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1002",groupType="select",bucketActions="set_field:10.244.7.4->ip_dst,set_field:27017->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1003",groupType="select",bucketActions="set_field:10.244.7.10->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1001",groupType="select",bucketActions="set_field:10.244.7.14->ip_dst,set_field:5672->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1008",groupType="select",bucketActions="set_field:10.244.7.3->ip_dst,set_field:53->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1008",groupType="select",bucketActions="set_field:10.244.7.2->ip_dst,set_field:53->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1006",groupType="select",bucketActions="set_field:10.244.7.8->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1007",groupType="select",bucketActions="set_field:10.244.7.3->ip_dst,set_field:53->udp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1007",groupType="select",bucketActions="set_field:10.244.7.2->ip_dst,set_field:53->udp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1009",groupType="select",bucketActions="set_field:10.244.7.6->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1000",groupType="select",bucketActions="set_field:10.244.7.12->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1010",groupType="select",bucketActions="set_field:10.244.7.11->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1005",groupType="select",bucketActions="set_field:10.244.7.15->ip_dst,set_field:80->tcp_dst,resubmit(,4)"} 0
groupBucketBytes{groupId="1012",groupType="select",bucketActions="set_field:10.244.7.5->ip_dst,set_field:3306->tcp_dst,resubmit(,4)"} 0
`

func TestGetMetrics(t *testing.T) {
	ofReader = ofdummy{}
	w := httptest.NewRecorder()
	GetMetrics(w, httptest.NewRequest("GET", "http://localhost:1234/flows?target=127.0.0.1", nil))
	resp := w.Result()
	raw_body, _ := ioutil.ReadAll(resp.Body)
	body := string(raw_body)
	if body != HANDLER_OUTPUT {
		t.Errorf("Handler output mismatch, assumed length: %d, got length %d", len(HANDLER_OUTPUT), len(body))
	}
}
