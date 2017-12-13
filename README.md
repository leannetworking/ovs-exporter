# Prometheus statistics exporter for Open vSwitch

Open vSwitch is popular virutal switch that enables high performance software defined networking. Since our aim is to use it along with Kuberentes, we creted this exporter that Prometheus can use to scrap stats directly from the OVS entries running on Kubernetes nodes. Currently we support 3 types of metrics: i) port statistics that lets you collect the traffic of every port (thus traffic of every container attached to the switches and internode communation via VxLAN ports), ii) flow rule statistics, and iii) group rule statistics that let you see some insight on which services and enpoints are addressed on a specific node.

The current implementaion uses simple ``ovs-ofctl`` commands to get the given statistics. Future releases might include usage of direct OpenFlow libraries, but for now for the sake of simplicity we stick to ``cmd`` commands.

To run on 64-bit Linux machines simply type ``./ovs-exporter``. For other architectures comply the GO code.

To integrate into Prometheus, add e.g. the following lines to the Prometheus config file (assuming you have two nodes with OVS having management IP at 192.168.0.10 and 192.168.0.20):

      - job_name: 'ports'
        static_configs:
          - targets: ['192.168.0.10', '192.168.0.20']
        metrics_path: /ports
        relabel_configs:
          - source_labels: [__address__]
            target_label: __param_target
          - source_labels: [__param_target]
            target_label: instance
          - target_label: __address__
            replacement: 127.0.0.1:8081  # OVS exporter.
    
      - job_name: 'flows'
        static_configs:
          - targets: ['192.168.0.10', '192.168.0.20']
        metrics_path: /flows
        relabel_configs:
          - source_labels: [__address__]
            target_label: __param_target
          - source_labels: [__param_target]
            target_label: instance
          - target_label: __address__
            replacement: 127.0.0.1:8081  # OVS exporter.

The code is highly experimental, use it with caution!

Happy coding :-)

LeanNet
