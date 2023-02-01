package main

import (
	"os"
	"testing"
)

func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func TestGetEnvVar(t *testing.T) {
	os.Setenv("INPUT_MENDAPIKEY", "apikey")
	defer os.Unsetenv("INPUT_MENDAPIKEY")

	os.Setenv("INPUT_MENDTOKEN", "token")
	defer os.Unsetenv("INPUT_MENDTOKEN")

	os.Setenv("INPUT_MENDURL", "url")
	defer os.Unsetenv("INPUT_MENDURL")

	os.Setenv("INPUT_PRODUCTNAME", "pname")
	defer os.Unsetenv("INPUT_PRODUCTNAME")

	os.Setenv("INPUT_PROJECTNAME", "proj")
	defer os.Unsetenv("INPUT_PROJECTNAME")

	os.Setenv("GITHUB_WORKSPACE", "/var/foo")
	defer os.Unsetenv("GITHUB_WORKSPACE")

	os.Setenv("INPUT_SKIPPLATFORMS", "foo,bar,baz")
	defer os.Unsetenv("INPUT_SKIPPLATFORMS")

	os.Setenv("INPUT_SKIPPROJECTS", "abc,def,hij")
	defer os.Unsetenv("INPUT_SKIPPROJECTS")

	os.Setenv("INPUT_SVDEBUG", "true")
	defer os.Unsetenv("INPUT_SVDEBUG")

	os.Setenv("INPUT_BRANCH", "foobarbaz123")
	defer os.Unsetenv("INPUT_BRANCH")

	conf, err := getEnvVar()
	if err != nil {
		t.Errorf("Error running getEnvVar: %s", err)
	}
	if conf.MendApiKey != "apikey" {
		t.Errorf("mend api key value wrong. Got: %s", conf.MendApiKey)
	}
	if conf.MendUserKey != "token" {
		t.Errorf("mend user key value wrong. Got: %s", conf.MendUserKey)
	}
	if conf.MendURL != "url" {
		t.Errorf("mend url wrong. Got: %s", conf.MendURL)
	}
	if conf.ProductName != "pname" {
		t.Errorf("mend product name wrong. Got: %s", conf.ProductName)
	}
	if conf.ProjectName != "proj" {
		t.Errorf("mend project name wrong. Got: %s", conf.MendURL)
	}
	if conf.GithubWorkspace != "/var/foo" {
		t.Errorf("workspace value wrong. Got: %s", conf.GithubWorkspace)
	}
	plat_tvals := []string{"foo", "bar", "baz"}
	for _, v := range plat_tvals {
		if !contains(conf.SkipPlatforms, v) {
			t.Errorf("SkipPlatforms did not have val: %s", v)
		}
	}
	proj_tvals := []string{"abc", "def", "hij"}
	for _, v := range proj_tvals {
		if !contains(conf.SkipProjects, v) {
			t.Errorf("SkipProjects did not have val: %s", v)
		}
	}
	if !conf.Debug {
		t.Errorf("Debug should have been true")
	}
	if conf.Branch != "foobarbaz1" {
		t.Errorf("branch value wrong. Got: %s", conf.Branch)
	}

}
