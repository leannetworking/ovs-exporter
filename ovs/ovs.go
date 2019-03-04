package ovs

//the passive TCP port where OVS entries are listening
//for OpenFlow commands
const OvsDefaultPort int = 16633

type OvsStatReader interface {
	Flows(ip string, port int) ([]Flow, error)
	Ports(ip string, port int) ([]Port, error)
	Groups(ip string, port int) ([]Group, error)
}

var (
	OvsDefaultReader OvsStatReader = OvsDumpReader{}
)
