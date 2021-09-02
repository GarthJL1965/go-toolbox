module go.imperva.dev/toolbox

go 1.16

require (
	github.com/ProtonMail/gopenpgp/v2 v2.2.2
	go.imperva.dev/zerolog v1.24.1
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/apimachinery v0.22.1
	k8s.io/client-go v0.22.1
)

// TODO: remove this after development
replace go.imperva.dev/zerolog => /home/josh/workspace/src/github.com/imperva-marketing/zerolog
