package tracker

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tc.bpf.c -- -I../headers

// unauthorizedEntry represents the structure of the BPF map value for unauthorized attempts
type unauthorizedEntry struct {
	SrcIP  uint32
	DestIP uint32
	Count  uint32
}

func StartEbpfw() {
	// Look up the network interface by name (hardcoded here for "enp0s20f0u1u3").
	iface, err := net.InterfaceByName("enp0s20f0u1u3")
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", "enp0s20f0u1u3", err)
	}

	// Load pre-compiled eBPF objects into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer func() {
		if err := objs.Close(); err != nil {
			log.Printf("error closing eBPF objects: %s", err)
		}
	}()

	// Attach the program to Ingress TC.
	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressProgFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program to ingress: %s", err)
	}
	defer func() {
		if err := ingressLink.Close(); err != nil {
			log.Printf("error detaching ingress link: %s", err)
		}
	}()
	log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)

	// Attach the program to Egress TC.
	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressProgFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program to egress: %s", err)
	}
	defer func() {
		if err := egressLink.Close(); err != nil {
			log.Printf("error detaching egress link: %s", err)
		}
	}()
	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)

	// Monitor the unauthorized attempts map periodically
	go monitorUnauthorizedAttempts(&objs)

	log.Printf("Press Ctrl-C to exit and remove the program")

	// Setup signal handling to allow for graceful exit
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Printf("Detaching programs and exiting")
}

// monitorUnauthorizedAttempts reads from the unauthorized attempts map and logs entries
func monitorUnauthorizedAttempts(objs *bpfObjects) {
	// https://github.com/cilium/ebpf/blob/main/examples/kprobe_percpu/main.go
    if objs.UnauthorizedAttempts == nil {
        log.Fatalf("UnauthorizedAttempts map is not loaded correctly")
        return
    }

    ticker := time.NewTicker(10 * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        var srcIPKey uint32
        iter := objs.UnauthorizedAttempts.Iterate()
        
        if iter == nil {
            log.Fatalf("Failed to start iterating over UnauthorizedAttempts map")
            return
        }

        for iter.Next(&srcIPKey, nil) {
            // Retrieve per-CPU values using a slice
            var perCPUEntries []unauthorizedEntry
            if err := objs.UnauthorizedAttempts.Lookup(srcIPKey, &perCPUEntries); err != nil {
                log.Printf("Error reading per-CPU unauthorized attempts: %s", err)
                continue
            }

            // Aggregate counts across all CPUs
            totalCount := uint32(0)
            var exampleEntry unauthorizedEntry
            for _, cpuEntry := range perCPUEntries {
                totalCount += cpuEntry.Count
                exampleEntry = cpuEntry // Get an example entry to extract DestIP
            }

            // Convert IPs to human-readable form
            srcIP := net.IPv4(byte(srcIPKey>>24), byte(srcIPKey>>16), byte(srcIPKey>>8), byte(srcIPKey))
            destIP := net.IPv4(byte(exampleEntry.DestIP>>24), byte(exampleEntry.DestIP>>16), byte(exampleEntry.DestIP>>8), byte(exampleEntry.DestIP))
            log.Printf("Unauthorized attempt from %s to %s, total count: %d\n", srcIP, destIP, totalCount)
        }
        if err := iter.Err(); err != nil {
            log.Printf("Error reading unauthorized attempts: %s", err)
        }
    }
}


