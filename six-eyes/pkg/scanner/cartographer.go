package scanner

import (
	"context"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

type Cartographer struct {
	Concurrency int
	Timeout     time.Duration
}

func NewCartographer(concurrency int, timeout time.Duration) *Cartographer {
	return &Cartographer{
		Concurrency: concurrency,
		Timeout:     timeout,
	}
}

// ExpandCIDR parses a CIDR block (e.g. "104.16.0.0/14") into individual IPs
func ExpandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ips = append(ips, ip.String())
	}
	// Omit network and broadcast addresses if needed
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Run executes the worker pool against expanded targets
func (c *Cartographer) Run(ctx context.Context, targetIPs []string, workerHost string) *IntelligenceReport {
	tasks := make(chan ProbeTask, len(targetIPs)*len(FingerprintMap))
	results := make(chan *ProbeResult, cap(tasks))
	var wg sync.WaitGroup

	log.Infof("Launching Six Eyes Cartographer v10 [Concurrency: %d, Target IPs: %d]", c.Concurrency, len(targetIPs))

	// 1. Spawn Worker Pool
	for i := 0; i < c.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range tasks {
				select {
				case <-ctx.Done():
					return
				default:
					res, _ := DialStealthProbe(ctx, task)
					results <- res
				}
			}
		}()
	}

	// 2. Queue Tasks (IP x Fingerprint x FragMode)
	totalTasks := 0
	for _, ip := range targetIPs {
		for fpName, fpID := range FingerprintMap {
			tasks <- ProbeTask{
				IP:          ip,
				TargetSNI:   workerHost,
				Fingerprint: fpName,
				ClientHello: fpID,
				Mode:        ModeTLSMicroFrag,
				Timeout:     c.Timeout,
			}
			totalTasks++
		}
	}
	close(tasks)

	// 3. Wait for Workers and close Results
	go func() {
		wg.Wait()
		close(results)
	}()

	// 4. Build Intelligence Report
	report := &IntelligenceReport{
		Timestamp:    time.Now(),
		WorkerHost:   workerHost,
		TotalScanned: totalTasks,
		CleanEdges:   []ProbeResult{},
	}

	for res := range results {
		if res.Success {
			report.Verified101++
			report.CleanEdges = append(report.CleanEdges, *res)
			log.Infof("[+] Edge Verified: %s | Mode: %s | Fingerprint: %s | Latency: %dms",
				res.IP, res.Mode, res.Fingerprint, res.Latency)
		}
	}

	return report
}
