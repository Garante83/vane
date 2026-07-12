package trace

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"vane/pkg/util"
)

// HopStats tracks the real-time statistics of a discovered gateway or routing hop
type HopStats struct {
	Index   int
	IP      string
	Sent    int
	Recv    int
	Last    time.Duration
	Best    time.Duration
	Worst   time.Duration
	Sum     time.Duration
	History []time.Duration
}

// PerformTrace executes the interactive traceroute and latency monitor (MTR clone)
func PerformTrace(target string) error {
	// 1. Resolve host IP if it's a domain name
	ips, err := net.LookupIP(target)
	var targetIP string
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() != nil {
				targetIP = ip.String()
				break
			}
		}
	}
	if targetIP == "" {
		targetIP = target
	}

	fmt.Printf("┌────────────────────────────────────────────────────────────────────┐\033[K\n")
	fmt.Printf("│  vane trace ─ Resolving path to: %-32s  │\033[K\n", util.TruncateStr(target, 32))
	fmt.Printf("└────────────────────────────────────────────────────────────────────┘\033[K\n")
	// Start interactive background spinner to show activity during hop discovery
	doneChan := make(chan struct{})
	var spinnerWg sync.WaitGroup
	spinnerWg.Add(1)
	go func() {
		defer spinnerWg.Done()
		spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		idx := 0
		for {
			select {
			case <-doneChan:
				return
			default:
				fmt.Printf("\r  %s Finding intermediate gateways (hops) via native traceroute...\033[K", spinner[idx])
				idx = (idx + 1) % len(spinner)
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()

	// 2. Discover hops
	hopIPs, err := discoverHops(targetIP)
	close(doneChan)
	spinnerWg.Wait()

	// Erase the spinner line cleanly and move to next line
	fmt.Print("\r\033[K\n")

	if err != nil {
		return fmt.Errorf("hop discovery failed: %w", err)
	}

	// 3. Initialize statistics map
	statsList := make([]*HopStats, len(hopIPs))
	for i, ip := range hopIPs {
		statsList[i] = &HopStats{
			Index:   i + 1,
			IP:      ip,
			History: make([]time.Duration, 0, 8),
		}
	}

	// 4. Handle exit cleanly
	exitChan := make(chan os.Signal, 1)
	signal.Notify(exitChan, os.Interrupt, syscall.SIGTERM)

	// Clean screen code
	fmt.Print("\033[?25l")       // Hide cursor
	defer fmt.Print("\033[?25h") // Restore cursor

	// Visual header length for cursor resetting (unified box top is 3 lines, header is 3 lines, table footer is 1 line, bottom is 1 line)
	headerLines := len(statsList) + 6

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	// Print the initial grid immediately so the user sees the table structure instantly
	printStatsGrid(target, targetIP, statsList)

	// Interactivity Loop
	run := true
	for run {
		// Trigger concurrent pings
		var wg sync.WaitGroup
		for _, hs := range statsList {
			if hs.IP == "*" || hs.IP == "──" {
				continue
			}
			wg.Add(1)
			go func(h *HopStats) {
				defer wg.Done()
				h.Sent++
				rtt, err := pingHop(h.IP)
				if err == nil {
					h.Recv++
					h.Last = rtt
					h.Sum += rtt
					if h.Best == 0 || rtt < h.Best {
						h.Best = rtt
					}
					if rtt > h.Worst {
						h.Worst = rtt
					}

					// Maintain sparkline history (last 8 probes)
					h.History = append(h.History, rtt)
					if len(h.History) > 8 {
						h.History = h.History[1:]
					}
				} else {
					// Add zero to history for packets lost to visually reflect loss in the sparkline
					h.History = append(h.History, 0)
					if len(h.History) > 8 {
						h.History = h.History[1:]
					}
				}
			}(hs)
		}

		wg.Wait()

		// Move cursor back up to redraw the table in-place
		fmt.Printf("\033[%dA", headerLines)
		// Print live statistics grid
		printStatsGrid(target, targetIP, statsList)

		select {
		case <-exitChan:
			run = false
			fmt.Print("\r\033[K") // Clear the line containing "^C"
			fmt.Println("  Trace terminated by user.")
		case <-ticker.C:
			// Loop to trigger next pings
		}
	}

	return nil
}

// printStatsGrid draws the visually stunning, aligned terminal dashboard
func printStatsGrid(target, targetIP string, stats []*HopStats) {
	info := fmt.Sprintf("%s (%s)", target, targetIP)
	fmt.Printf("\r┌────────────────────────────────────────────────────────────────────┐\033[K\n")
	fmt.Printf("│  vane trace ─ Target: %-43s  │\033[K\n", util.TruncateStr(info, 43))
	fmt.Printf("└────────────────────────────────────────────────────────────────────┘\033[K\n")
	fmt.Printf("  %-3s %-15s %-6s %-7s %-7s %-7s %-7s %s\033[K\n", "HOP", "IP ADDRESS", "LOSS%", "LAST", "AVG", "BEST", "WRST", "JITTER")
	fmt.Printf(" ────────────────────────────────────────────────────────────────────\033[K\n")

	for _, h := range stats {
		// Calculate loss percentage
		lossPct := 100.0
		if h.Sent > 0 {
			lossPct = float64(h.Sent-h.Recv) / float64(h.Sent) * 100.0
		}

		lossStr := fmt.Sprintf("%.1f%%", lossPct)
		var lossColored string
		if lossPct == 0.0 {
			lossColored = "\x1b[1;32m" + fmt.Sprintf("%-6s", lossStr) + "\x1b[0m" // Green for no loss
		} else if lossPct < 20.0 {
			lossColored = "\x1b[1;33m" + fmt.Sprintf("%-6s", lossStr) + "\x1b[0m" // Yellow warning for low loss
		} else {
			lossColored = "\x1b[1;31m" + fmt.Sprintf("%-6s", lossStr) + "\x1b[0m" // Red alert for heavy packet loss
		}

		lastStr := "──"
		avgStr := "──"
		bestStr := "──"
		worstStr := "──"

		if h.Recv > 0 {
			lastStr = formatDuration(h.Last)
			avgStr = formatDuration(h.Sum / time.Duration(h.Recv))
			bestStr = formatDuration(h.Best)
			worstStr = formatDuration(h.Worst)
		}

		// Draw live sparklines / detect firewalled hops
		spark := renderSparkline(h.History)
		sparkRunes := []rune(spark)
		if len(sparkRunes) < 8 {
			spark = spark + strings.Repeat(" ", 8-len(sparkRunes))
		}
		var sparkColored string
		if lossPct == 100.0 {
			sparkColored = "\x1b[1;31m* no ICMP\x1b[0m"
		} else if lossPct > 50.0 {
			sparkColored = "\x1b[1;31m" + spark + "\x1b[0m" // Red spark for terrible line quality
		} else {
			sparkColored = "\x1b[1;32m" + spark + "\x1b[0m" // Green spark for healthy packets
		}

		ipDisplay := h.IP
		if ipDisplay == "*" {
			ipDisplay = "* (No Response)"
		}

		fmt.Printf("  %-3d %-15s %s %-7s %-7s %-7s %-7s %s\033[K\n", h.Index, ipDisplay, lossColored, lastStr, avgStr, bestStr, worstStr, sparkColored)
	}
	fmt.Printf(" ────────────────────────────────────────────────────────────────────\033[K\n")
	fmt.Print("  [Ctrl+C] to exit. Monitoring latency in real-time...\033[K")
}

// truncateStr ensures text fields never overflow the visually aligned box borders
// formatDuration formats RTT values cleanly for fixed-width columns
func formatDuration(d time.Duration) string {
	ms := float64(d) / float64(time.Millisecond)
	return fmt.Sprintf("%.1fms", ms)
}

// renderSparkline transforms latency history dynamically into active visual sparklines
func renderSparkline(history []time.Duration) string {
	if len(history) == 0 {
		return ""
	}
	var min, max time.Duration = 99999 * time.Hour, 0
	hasValidProbes := false

	for _, d := range history {
		if d == 0 {
			continue // skip lost packets in scaling calculations
		}
		hasValidProbes = true
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}

	blocks := []rune{' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'}
	var sb strings.Builder
	for _, d := range history {
		if d == 0 {
			sb.WriteRune('✖') // mark packet loss visually inside the sparkline
			continue
		}
		if !hasValidProbes || max == min {
			sb.WriteRune('▄')
			continue
		}
		val := float64(d-min) / float64(max-min)
		idx := int(val * 7)
		if idx < 0 {
			idx = 0
		}
		if idx > 7 {
			idx = 7
		}
		sb.WriteRune(blocks[idx])
	}
	return sb.String()
}

// pingHop executes standard non-privileged OS ping command
func pingHop(ip string) (time.Duration, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", "800", ip)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("unreachable")
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "time=") {
			idx := strings.Index(line, "time=")
			sub := line[idx+5:]
			spaceIdx := strings.Index(sub, " ")
			if spaceIdx != -1 {
				valStr := sub[:spaceIdx]
				val, err := strconv.ParseFloat(valStr, 64)
				if err == nil {
					return time.Duration(val * float64(time.Millisecond)), nil
				}
			}
		}
	}
	return 0, fmt.Errorf("parsing failed")
}

// discoverHops runs a low-hop-count traceroute to pre-populate intermediate routers
func discoverHops(target string) ([]string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("tracert", "-d", "-h", "15", target)
	} else {
		cmd = exec.Command("traceroute", "-n", "-m", "15", "-q", "1", "-w", "1", target)
	}

	out, err := cmd.Output()
	if err != nil {
		// Fallback to Linux tracepath
		cmd = exec.Command("tracepath", "-n", "-m", "15", target)
		out, err = cmd.Output()
		if err != nil {
			// Complete fallback: monitor target directly if routing engines aren't installed
			return []string{target}, nil
		}
	}

	var hops []string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		for _, f := range fields {
			f = strings.Trim(f, "()")
			if ip := net.ParseIP(f); ip != nil {
				// Prevent duplicate sequential hops (loop protection)
				if len(hops) == 0 || hops[len(hops)-1] != ip.String() {
					hops = append(hops, ip.String())
				}
				break
			}
		}
	}

	if len(hops) == 0 {
		hops = append(hops, target)
	}
	return hops, nil
}
