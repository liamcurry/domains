package main

import (
	"flag"
	"fmt"

	"github.com/liamcurry/domains"
)

func main() {
	flag.Parse()
	args := flag.Args()
	c := domains.NewChecker()
	if len(args) == 0 {
		fmt.Println("usage: <domain>")
		return
	}

	if c.IsTaken(args[0]) {
		fmt.Println("not available")
	} else {
		fmt.Println("available")
	}
	//w := NewWhoisChecker(defaultServers)
	//w.printRespondingServers()
}
