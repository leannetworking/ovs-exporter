# Prometheus statistics exporter for Open vSwitch

Open vSwitch is popular virutal switch that enables high performance software defined networking. Since our aim is to use it along with Kuberentes, we creted this exporter that Prometheus can use to scrap stats directly from the OVS entries running on Kubernetes nodes. Currently we support 3 types of metrics: i) port statistics that lets you collect the traffic of every port (thus traffic of every container attached to the switches and internode communation via VxLAN ports), ii) flow rule statistics, and iii) group rule statistics that let you see some insight on which services and enpoints are addressed on a specific node.

The current implementaion uses simple ``ovs-ofctl`` commands to get the given statistics. Future releases might include usage of direct OpenFlow libraries, but for now for the sake of simplicity we stick to ``cmd`` commands.

The code is highly experimental, use it with caution!

Happy coding :-)

LeanNet
