package main

import (
	"os"
	"os/exec"
	"fmt"
	"io"
	"encoding/xml"
	"encoding/json"
	"bytes"
	"flag"
	"net"
)

type finished_stats struct {
	Time int64 `xml:"time,attr"`
	TimeString string `xml:"timestr,attr"`
	Elapsed float32 `xml:"elapsed,attr"`
	Summary string `xml:"summary,attr"`
	Exit string `xml:"exit,attr"`
}

type count_stats struct {
	UpCount int `xml:"up,attr"`
	DownCount int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

type xml_hosts struct {
	Hosts []xml_host `xml:"host"`
	Runstats finished_stats `xml:"runstats>finished"`
	Hoststats count_stats `xml:"runstats>hosts"`
}

type xml_addr struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type xml_name struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type xml_hostname struct {
	Hostname []xml_name `xml:"hostname"`
}

type xml_host struct {
	Hostnames xml_hostname `xml:"hostnames"`
	Addrs []xml_addr `xml:"address"`
}

type Host struct {
	Hostname string
	Ip string
	Mac string
}

func scan_hosts_on(subnet string, verbose bool) (error, io.Reader) {

	var result *exec.Cmd

	if verbose == true {
		result = exec.Command("nmap", "-v", "-sP", subnet, "-oX", "-")
	} else {
		result = exec.Command("nmap", "-sP", subnet, "-oX", "-")
	}

	out, err := result.Output()

	if err != nil {
		return fmt.Errorf("Not executed. Is nmap installed?"), nil
	}

	return nil, bytes.NewReader(out)
}

func parse_xml(reader io.Reader) (err error, hosts []Host) {
	output := xml_hosts{}

	decoder := xml.NewDecoder(reader)
	dec_err := decoder.Decode(&output)
	if dec_err != nil {
		fmt.Errorf("Decode error")
		fmt.Errorf("Error: " + dec_err.Error())
		return dec_err, hosts
	}

	for _,x_host  := range output.Hosts {
		h := Host{}
		for _,x_addr := range x_host.Addrs {
			switch {
			case x_addr.Type == "ipv4":
				h.Ip = x_addr.Addr
			case x_addr.Type == "mac":
				h.Mac = x_addr.Addr
			}

			if len(x_host.Hostnames.Hostname) > 0 {
				h.Hostname = x_host.Hostnames.Hostname[0].Name
			}
		}

		if h.Ip != "" {
			if h.Hostname == "" {
				h.Hostname = "unknown"
			}

			hosts = append(hosts,h)
		}
	}

	return
}

func print_usage() {
	fmt.Println("Usage:")
	fmt.Println(os.Args[0] + " [-h -help] [-b -bare] <subnet>")
	fmt.Println("-h -help	Print this usage text")
	fmt.Println("-b -bare	Output bare insead of JSON format")
	fmt.Println("NOTE: MAC addresses will only be returned if run as privileges user")
}

func main() {

	help := flag.Bool("help", false, "Print the help text")
	helpShort := flag.Bool("h", false, "Print ths help text" + " (shorthand)")

	verbose := flag.Bool("verbose", false, "Verbose output, for debugging")
	verboseShort := flag.Bool("v", false, "Verbose output, for debugging" + " (shorthand)")

	bare := flag.Bool("bare", false, "Output the bare text strings for display")
	bareShort := flag.Bool("b", false, "Output the bare text strings for display" + "(shorthand)")

	flag.Parse()

	args := flag.Args()
	var subnet string

	if len(args) < 1 {
		print_usage()
		os.Exit(1)
	} else {
		subnet = args[0]
	}

	if subnet == "" {
		fmt.Errorf("You must provide a subnet to scan")
		os.Exit(2)
	}

	if *help == true || *helpShort == true {
		fmt.Println("Help")
		print_usage()
		os.Exit(0)
	}

	ip,net,err := net.ParseCIDR(subnet)
	if err != nil {
		fmt.Errorf("You have not input a valid CIDR notation subnet. Try again.")
		os.Exit(3)
	}

	if *verbose == true || *verboseShort == true {
		fmt.Sprintf("IP : %v", ip)
		fmt.Sprintf("NET: %v", net)
	}

	err, reader := scan_hosts_on(subnet, *verbose)
	if err != nil {
		fmt.Errorf("Host scan failed")
		fmt.Errorf("Error: " + err.Error())
		os.Exit(4)
	}

	err, hosts := parse_xml(reader)
	if err != nil {
		fmt.Errorf("Parsing failed. Bye")
		os.Exit(5)
	}

	if *bare == true || *bareShort == true {
		for index,host := range hosts {
			fmt.Println(host.Hostname)
			fmt.Println(host.Ip)
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
			fmt.Errorf("Failed to convert to JSON")
			os.Exit(6)
		}
		fmt.Println(string(b))
	}

	os.Exit(0)
}