module authelia.com/provider/saml/example/idp

go 1.27

require (
	authelia.com/provider/saml v0.0.0
	github.com/beevik/etree v1.8.1
	github.com/stretchr/testify v1.12.1
	golang.org/x/crypto v0.59.0
)

require go.yaml.in/yaml/v3 v3.0.5 // indirect

replace authelia.com/provider/saml => ../..
