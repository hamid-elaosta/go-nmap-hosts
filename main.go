package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
)

type finishedStats struct {
	Time       int64   `xml:"time,attr"`
	TimeString string  `xml:"timestr,attr"`
	Elapsed    float32 `xml:"elapsed,attr"`
	Summary    string  `xml:"summary,attr"`
	Exit       string  `xml:"exit,attr"`
}

type countStats struct {
	UpCount   int `xml:"up,attr"`
	DownCount int `xml:"down,attr"`
	Total     int `xml:"total,attr"`
}

type xmlHosts struct {
	Hosts     []xmlHost     `xml:"host"`
	Runstats  finishedStats `xml:"runstats>finished"`
	Hoststats countStats    `xml:"runstats>hosts"`
}

type xmlAddr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type xmlName struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xmlHostname struct {
	Hostname []xmlName `xml:"hostname"`
}

type xmlHost struct {
	Hostnames xmlHostname `xml:"hostnames"`
	Addrs     []xmlAddr   `xml:"address"`
}

type host struct {
	Hostname string
	IP       string
	Mac      string `json:",omitempty"`
}

func scanHostsOnSubnet(subnet string, verbose bool) (io.Reader, error) {

	var result *exec.Cmd

	if verbose == true {
		result = exec.Command("nmap", "-v", "-sn", subnet, "-oX", "-")
	} else {
		result = exec.Command("nmap", "-sn", subnet, "-oX", "-")
	}

	out, err := result.Output()

	if err != nil {
		return nil, fmt.Errorf("Execute failed, is nmap installed?")
	}

	return bytes.NewReader(out), nil
}

func parseXML(reader io.Reader) (hosts []host, err error) {
	output := xmlHosts{}

	decoder := xml.NewDecoder(reader)
	decErr := decoder.Decode(&output)
	if decErr != nil {
		fmt.Println("Decode error")
		fmt.Println("Error: " + decErr.Error())
		return hosts, decErr
	}

	for _, xHost := range output.Hosts {
		h := host{}
		for _, xAddr := range xHost.Addrs {
			switch {
			case xAddr.Type == "ipv4":
				h.IP = xAddr.Addr
			case xAddr.Type == "mac":
				h.Mac = xAddr.Addr
			}

			if len(xHost.Hostnames.Hostname) > 0 {
				h.Hostname = xHost.Hostnames.Hostname[0].Name
			}
		}

		if h.IP != "" {
			if h.Hostname == "" {
				h.Hostname = "unknown"
			}

			hosts = append(hosts, h)
		}
	}

	return
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println(os.Args[0] + " [-h -help] [-b -bare] <subnet>")
	fmt.Println("-h -help	Print this usage text")
	fmt.Println("-b -bare	Output bare insead of JSON format")
	fmt.Println("NOTE: MAC addresses will only be returned if run as privileged user")
}

func main() {

	help := flag.Bool("help", false, "Print the help text")
	helpShort := flag.Bool("h", false, "Print ths help text"+" (shorthand)")

	verbose := flag.Bool("verbose", false, "Verbose output, for debugging")
	verboseShort := flag.Bool("v", false, "Verbose output, for debugging"+" (shorthand)")

	bare := flag.Bool("bare", false, "Output the bare text strings for display")
	bareShort := flag.Bool("b", false, "Output the bare text strings for display"+"(shorthand)")

	flag.Parse()

	args := flag.Args()
	var subnet string

	if len(args) < 1 {
		printUsage()
		os.Exit(1)
	} else {
		subnet = args[0]
	}

	if subnet == "" {
		fmt.Println("Error: You must provide a subnet to scan.")
		os.Exit(2)
	}

	if *help == true || *helpShort == true {
		fmt.Println("Help")
		printUsage()
		os.Exit(0)
	}

	_, net, err := net.ParseCIDR(subnet)
	if err != nil {
		fmt.Println("You have not input a valid CIDR notation subnet. Try again.")
		fmt.Println("Error: " + err.Error())
		os.Exit(3)
	}

	if *verbose == true || *verboseShort == true {
		fmt.Printf("Network : %v\n", net)
	}

	reader, err := scanHostsOnSubnet(subnet, *verbose)
	if err != nil {
		fmt.Println("Host scan failed.")
		fmt.Println("Error: " + err.Error())
		os.Exit(4)
	}

	hosts, err := parseXML(reader)
	if err != nil {
		fmt.Println("Parsing failed. Bye")
		fmt.Println("Error: " + err.Error())
		os.Exit(5)
	}

	if *bare == true || *bareShort == true {
		for index, host := range hosts {
			fmt.Println(host.Hostname)
			fmt.Println(host.IP)
			if host.Mac != "" {
				fmt.Println(host.Mac)
			}
			if index < len(hosts) {
				fmt.Println("")
			}
		}
		os.Exit(0)
	} else {
		b, err := json.Marshal(hosts)

		if err != nil {
			fmt.Println("Failed to convert to JSON.")
			fmt.Println("Error: " + err.Error())
			os.Exit(6)
		}
		fmt.Println(string(b))
	}

	os.Exit(0)
}
