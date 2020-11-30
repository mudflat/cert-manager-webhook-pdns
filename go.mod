module mudflat.io/cert-manager-webhook-pdns

go 1.13

require (
	github.com/jetstack/cert-manager v1.1.0
	github.com/onsi/ginkgo v1.14.2 // indirect
	github.com/rs/zerolog v1.20.0
	github.com/stretchr/testify v1.6.1
	k8s.io/apimachinery v0.19.4
	k8s.io/client-go v11.0.0+incompatible
)

replace (
	k8s.io/api => k8s.io/api v0.19.4
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.19.4
	k8s.io/apimachinery => k8s.io/apimachinery v0.19.4
	k8s.io/apiserver => k8s.io/apiserver v0.19.4
	k8s.io/client-go => k8s.io/client-go v0.19.4
)

exclude github.com/zachomedia/cert-manager-webhook-pdns v0.0.0-20200523183424-2db0e84219e7 // indirect
