package main

import (
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

type gem struct {
	Name    string
	Version string
}

type depsOut struct {
	Project  string
	Platform string
	Gems     *[]gem
}

type config struct {
	MendApiKey      string
	MendUserKey     string
	MendURL         string
	ProductName     string
	ProjectName     string
	SkipProjects    []string
	SkipPlatforms   []string
	GithubWorkspace string
	Debug           bool
	Branch          string
}

type RunStatus struct {
	Project  string
	Platform string
	Failure  bool
}

type VulnReport struct {
	PackageName string
	Version     string
	VulnString  string
}

type processOut struct {
	hasGems  bool
	project  string
	platform string
	path     string
}

func (v *VulnReport) String() string {
	return fmt.Sprintf("%s-%s: %s", v.PackageName, v.Version, v.VulnString)
}

func NewVulnReport(vuln gjson.Result) VulnReport {
	// get package name
	packageName := vuln.Get("packageName").String()
	if packageName == "" {
		packageName = vuln.Get("moduleName").String()
		if packageName == "" {
			packageName = ""
		}
	}
	// get version
	version := vuln.Get("version").String()
	if version == "" {
		version = "UNKNOWN"
	}
	// vuln ID
	vulnArray := vuln.Get("identifiers.CVE").Array()
	vulnString := ""
	for _, v := range vulnArray {
		vulnString += fmt.Sprintf(", %s", v.String())
	}
	vulnString = strings.Replace(vulnString, ", ", "", 1)
	return VulnReport{
		PackageName: packageName,
		Version:     version,
		VulnString:  vulnString,
	}
}
