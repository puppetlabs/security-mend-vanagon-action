package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var LOCKFILE_DIR string = "gen_lockfile"
var DIR_MUTEX = &sync.Mutex{}

var MAX_V_DEPS = 20

func getRequiredVar(confVal *string, varName, errorMessage string) {
	varVal := os.Getenv(varName)
	if varVal == "" {
		log.Fatal(errorMessage)
	}
	*confVal = varVal
}

func getOptionalEnvVar(confVal *string, varName, defaultVal, errorMessage string) {
	varVal := os.Getenv(varName)
	if varVal == "" {
		varVal = defaultVal
	}
	*confVal = varVal
}

func getEnvVar() (*config, error) {
	conf := config{}
	// apikey
	getRequiredVar(&conf.MendApiKey, "INPUT_MENDAPIKEY", "no mend API key set!")
	// user key
	getRequiredVar(&conf.MendUserKey, "INPUT_MENDTOKEN", "no mend User Token set!")
	// mend URL
	getRequiredVar(&conf.MendURL, "INPUT_MENDURL", "no mend URL set!")
	// Get the product name and the base project name
	getRequiredVar(&conf.ProductName, "INPUT_PRODUCTNAME", "no product name set")
	getRequiredVar(&conf.ProjectName, "INPUT_PROJECTNAME", "no base project name set")
	// override workspace as required
	workspace := os.Getenv("GITHUB_WORKSPACE")
	if workspace == "" {
		return nil, errors.New("no github workspace set")
	}
	conf.GithubWorkspace = workspace
	// skip projects and platforms are not, don't fail on it
	// platforms
	skipp := os.Getenv("INPUT_SKIPPLATFORMS")
	if skipp != "" {
		splitstring := strings.Split(skipp, ",")
		for i := range splitstring {
			splitstring[i] = strings.TrimSpace(splitstring[i])
		}
		conf.SkipPlatforms = splitstring
	} else {
		conf.SkipPlatforms = []string{}
	}
	//projects
	skipr := os.Getenv("INPUT_SKIPPROJECTS")
	if skipr != "" {
		splitstring := strings.Split(skipr, ",")
		for i := range splitstring {
			splitstring[i] = strings.TrimSpace(splitstring[i])
		}
		conf.SkipProjects = splitstring
	} else {
		conf.SkipProjects = []string{}
	}

	// add a debug flag
	debug := os.Getenv("INPUT_SVDEBUG")
	conf.Debug = debug != ""

	branch := os.Getenv("INPUT_BRANCH")
	if branch != "" {
		if len(branch) > 10 {
			branch = branch[0:10]
		}
		reg, err := regexp.Compile("[^a-zA-Z0-9-]+")
		if err != nil {
			log.Fatal(err)
		}
		branch = reg.ReplaceAllString(branch, "")
		conf.Branch = branch
	}
	// return
	return &conf, nil
}

func vulnExists(totalVulns []VulnReport, vuln VulnReport) bool {
	for _, v := range totalVulns {
		if v.PackageName == vuln.PackageName && v.Version == vuln.Version {
			return true
		}
	}
	return false
}

// buildGemFile builds a gemfile and a gemfile.lock
func buildGemFile(project, platform string, gems *[]gem) (string, error) {
	// build the gemfile
	gemfile := "source ENV['GEM_SOURCE'] || \"https://rubygems.org\"\n"
	for _, gem := range *gems {
		gemfile += fmt.Sprintf("gem \"%s\", %s\n", gem.Name, gem.Version)
	}
	// make sure the output dir exists (creating if it doesn't) then write to a lockfile
	DIR_MUTEX.Lock()
	defer DIR_MUTEX.Unlock()
	err := os.MkdirAll(LOCKFILE_DIR, os.ModePerm)
	if err != nil {
		log.Println("couldn't create LOCKFILE_DIR", err)
		return "", err
	}
	oFolder := fmt.Sprintf("%s_%s", project, platform)
	lOutpath := filepath.Join(LOCKFILE_DIR, oFolder)
	err = os.MkdirAll(lOutpath, os.ModePerm)
	if err != nil {
		log.Printf("couldn't create lockfile output path on %s %s. %s", project, platform, err)
		return "", err
	}
	// write the gemfile to the output dir
	fPath := filepath.Join(LOCKFILE_DIR, oFolder, "Gemfile")
	err = os.WriteFile(fPath, []byte(gemfile), 0644)
	if err != nil {
		log.Println("couldn't write gemfile!", err)
		return "", err
	}
	//log.Printf("wrote Gemfile for %s %s", project, platform)
	cdir, err := os.Getwd()
	defer os.Chdir(cdir)
	if err != nil {
		log.Println("Couldn't get cdir!", err)
		return "", err
	}
	err = os.Chdir(lOutpath)
	if err != nil {
		log.Println("couldn't change to gemfile path", err)
		return "", err
	}
	err = exec.Command("bundle", "lock").Run()
	if err != nil {
		log.Println("Error generating lockfile from gemfile", err)
		return "", err
	}
	err = os.Chdir(cdir)
	if err != nil {
		log.Println("Error changing back to previous directory", err)
		return "", err
	}
	return lOutpath, nil
}

func processProjPlat(deps depsOut, results chan processOut) {
	// if there are gems, write a gemfile and run snyk
	if len(*deps.Gems) > 0 {
		path, err := buildGemFile(deps.Project, deps.Platform, deps.Gems)
		if err != nil {
			log.Printf("error writing gemfile on: %s %s. Error: %s", deps.Project, deps.Platform, err)
			results <- processOut{}
			return
		}
		results <- processOut{
			hasGems:  true,
			project:  deps.Project,
			platform: deps.Platform,
			path:     path,
		}
	} else {
		log.Printf("no gems on %s %s. Creating blank Gemfile", deps.Project, deps.Platform)
		path, err := buildGemFile(deps.Project, deps.Platform, deps.Gems)
		if err != nil {
			log.Printf("error writing gemfile on: %s %s. Error: %s", deps.Project, deps.Platform, err)
			results <- processOut{}
			return
		}
		results <- processOut{
			hasGems:  false,
			project:  deps.Project,
			platform: deps.Platform,
			path:     path,
		}
	}
}

func runMend(p processOut, conf *config, sem chan int, results chan RunStatus) {
	log.Printf("running mend on %s %s", p.project, p.platform)
	log.Printf("Finished running snyk on %s %s", p.project, p.platform)
}

func main() {
	conf, err := getEnvVar()
	if err != nil {
		log.Fatal("couldn't setup the env vars", err)
	}
	if conf.Debug {
		log.Println("===DEBUG IS ON===")
	}
	// change to the working directory
	os.Chdir(conf.GithubWorkspace)
	// get the projects and platforms
	projects, platforms := getProjPlats(conf)
	// get all the vanagon dependencies
	log.Println("running vanagon deps")
	vDeps := runVanagonDeps(projects, platforms, conf.Debug)
	// build gemfiles and run snyk on it
	log.Println("building gemfiles")
	// results := make(chan processOut, len(vDeps))
	results := make(chan processOut)
	toProcess := 0
	for _, dep := range vDeps {
		log.Printf("going to process %s %s", dep.Project, dep.Platform)
		toProcess += 1
		go processProjPlat(dep, results)
	}
	// collect all the processOuts
	p := []processOut{}
	for i := 0; i < toProcess; i++ {
		po := <-results
		p = append(p, po)
	}
	// foreach processOut run snyk
	sem := make(chan int, MAX_V_DEPS)
	sresults := make(chan RunStatus)
	toProcess = 0
	DIR_MUTEX.Lock()
	for _, po := range p {
		toProcess = toProcess + 1
		sem <- 1
		if conf.Debug {
			log.Printf("calling runMend on: %s %s", po.project, po.platform)
		}
		go runMend(po, conf, sem, sresults)
	}
	hasFailures := false
	for i := 0; i < toProcess; i++ {
		result := <-sresults
		if result.Failure {
			hasFailures = true
			log.Printf("Got a failure on %s-%s. See mend console for details", result.Project, result.Platform)
		}
		if !result.Failure && conf.Debug {
			log.Printf("Success on %s-%s", result.Project, result.Platform)
		}
	}
	if hasFailures {
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
