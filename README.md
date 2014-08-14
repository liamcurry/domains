domains
=======

`domains` is a minimal go library for checking domain name availablity. The API
isn't finalized yet and will probably change at some point.

INSTALLATION
------------

```bash
go get github.com/liamcurry/domains
```

USAGE
-----

```golang
package main

import "github.com/liamcurry/domains"

func main() {
	c := domains.NewChecker()
	println(c.IsTaken("hello.com"))
}
```

CLI
---

```bash
domains <domain>
```
