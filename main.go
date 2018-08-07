package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/privacybydesign/irmago"
)

// Flags parsed at program startup and never modified afterwards.
var (
	tmpDir          string
	certDir         string
	configDir       string
	serverStaticDir string
	enableDebug     bool
	keepOutput      bool
)

type Config struct {
	InitialsAttributes    []irma.AttributeTypeIdentifier `json:"initials_attributes"`
	FamilyNameAttributes  []irma.AttributeTypeIdentifier `json:"familyname_attributes"`
	DateOfBirthAttributes []irma.AttributeTypeIdentifier `json:"dateofbirth_attributes"`
}

var config Config

func readConfig() error {
	data, err := readFile(configDir + "/config.json")
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &config)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s <command> [args...]\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Available commands: help, read, server")
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
	}

	flag.StringVar(&tmpDir, "tmpdir", "tmp", "Where to put temporary files for the pdf2htmlEX command")
	flag.StringVar(&certDir, "certs", "certs", "Parent certificate directory (*.der)")
	flag.StringVar(&configDir, "config", "config", "Directory with configuration files")
	flag.StringVar(&serverStaticDir, "static", "static", "Static files to serve")
	flag.BoolVar(&enableDebug, "debug", false, "Enable debug logging")
	flag.BoolVar(&keepOutput, "keepoutput", false, "Do not remove temporary files")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Please provide a command")
		return
	}
	switch flag.Arg(0) {
	case "help", "usage":
		flag.Usage()
	case "read", "extract": // not sure what to call this
		if flag.NArg() < 2 {
			fmt.Fprintln(flag.CommandLine.Output(), "Provide at least one PDF path to \"read\".")
			flag.Usage()
			return
		}
		cmdReadPDFs(flag.Args()[1:])
	case "server":
		if flag.NArg() != 2 {
			fmt.Fprintln(flag.CommandLine.Output(), "Provide a host:port to bind to for \"server\".")
			flag.Usage()
			return
		}
		err := readConfig()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Could not read config file: "+err.Error())
			return
		}
		cmdServe(flag.Arg(1))
	default:
		fmt.Fprintln(flag.CommandLine.Output(), "Unknown command:", flag.Arg(0))
		flag.Usage()
	}
}
