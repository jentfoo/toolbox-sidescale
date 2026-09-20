package adapter

// Flow direction tags shared by the protocol adapters.
const (
	DirBidirectional  = "bidirectional"
	DirClientToServer = "client_to_server"
	DirServerToClient = "server_to_client"
)

// AnnInjected marks a flow originated by injection.
const AnnInjected = "injected"

// AnnDisturbsLiveNode marks an originated flow that rode a live client's tunnel and may pause its session.
const AnnDisturbsLiveNode = "disturbs_live_node"

// Field* are map field keys for log and tool payloads.
const (
	FieldError    = "error"
	FieldStream   = "stream"
	FieldFlowID   = "flow_id"
	FieldTunnelID = "tunnel_id"
	FieldMethod   = "method"
	FieldPath     = "path"
)
