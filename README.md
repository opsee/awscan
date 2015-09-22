AWS can
=======

![this is a can](./can.jpg)

A scanner for aws resources. You can use the discovery package to get a channel of resources:

```go
import (
        "github.com/opsee/awscan/scanner"
        "github.com/opsee/awscan/discovery"
)

scanner := scanner.NewScanner(&scanner.Config{AccessKeyId: "YOURID", SecretKey: "YOURSECRET", Region: "us-west-1"})
disco := discovery.NewDiscoverer(scanner)

for event := range disco.Discover() {
	if event.Err != nil {
		fmt.Println("whoops: ", event.Err.Error())
	} else {
		fmt.Println("yay: ", event.Result)
	}
}
```
