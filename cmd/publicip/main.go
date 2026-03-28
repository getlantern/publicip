// Command publicip detects the caller's public IP using multiple redundant methods.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/getlantern/publicip"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Println("Detecting public IP using multiple methods...")
	fmt.Println()

	result, err := publicip.Detect(ctx, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Public IP:   %s\n", result.IP)
	fmt.Printf("Confidence:  %.0f%% (%d/%d methods agree)\n", result.Confidence*100, len(result.Sources), len(result.All))
	fmt.Printf("Sources:     %v\n", result.Sources)
	if result.Geo != nil {
		if result.Geo.Country != "" {
			fmt.Printf("Country:     %s\n", result.Geo.Country)
		}
		if result.Geo.City != "" {
			fmt.Printf("City:        %s\n", result.Geo.City)
		}
		if result.Geo.Org != "" {
			fmt.Printf("Org:         %s\n", result.Geo.Org)
		}
	}
	if result.IsCGNAT {
		fmt.Println("CGNAT:       detected (gateway IP differs from public IP)")
	}

	fmt.Println()
	fmt.Println("All results:")
	for _, r := range result.All {
		fmt.Printf("  %-35s  %s  (%dms)\n", r.Source, r.IP, r.Latency.Milliseconds())
	}
}
