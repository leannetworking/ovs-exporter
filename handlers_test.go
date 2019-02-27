package main

import (
	"io/ioutil"
	"net/http/httptest"
	"testing"
)

const HANDLER_OUTPUT = `# HELP flowPackets The number of packets matched for the given OpenFlow entry
# TYPE flowPackets counter
flowPackets{match="",action="",table="",priority=""} 
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
flowPackets{match="",action="",table="",priority=""} 
# HELP flowBytes The number of bytes matched for the given OpenFlow entry
# TYPE flowBytes counter
flowBytes{match="",action="",table="",priority=""} 
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
flowBytes{match="",action="",table="",priority=""} 
# HELP flowAge The number of seconds have passed since the given OpenFlow entry was created
# TYPE flowAge gauge
flowAge{match="",action="",table="",priority=""} 
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
flowAge{match="",action="",table="",priority=""} 
# HELP flowIdleTime The number of seconds have passed since the last packet has seen for the given OpenFlow entry
# TYPE flowIdleTime gauge
flowIdleTime{match="",action="",table="",priority=""} 
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
flowIdleTime{match="",action="",table="",priority=""} 
Output is:  [] OFPST_PORT reply (xid=0x2): 19 ports  port LOCAL: rx pkts=0, bytes=0, drop=1157, errs=0, frame=0, over=0, crc=0
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
