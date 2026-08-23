// Package fixtures embeds GRIEFER's synthetic demo data.
//
// Every byte here is invented: reserved documentation domains, RFC 5737
// TEST-NET addresses and a fictional organisation. Nothing in this package
// describes a real environment, and no file contains a credential value.
package fixtures

import "embed"

// FS holds the synthetic fixture tree.
//
//go:embed synthetic/*.json
var FS embed.FS

// Well-known fixture paths.
const (
	InventoryPath = "synthetic/asset-inventory.json"
	ScenarioOne   = "synthetic/scenario-01-identity-compromise.json"
)
