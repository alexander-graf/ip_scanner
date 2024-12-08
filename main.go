package main

import (
    "context"
    "encoding/csv"
    "fmt"
    "net"
    "os"
    "sort"
    "strings"
    "sync"
    "time"

    "fyne.io/fyne/v2"
    "fyne.io/fyne/v2/app"
    "fyne.io/fyne/v2/container"
    "fyne.io/fyne/v2/data/binding"
    "fyne.io/fyne/v2/dialog"
    "fyne.io/fyne/v2/theme"
    "fyne.io/fyne/v2/widget"
    "fyne.io/fyne/v2/layout"
)

type ScanResult struct {
    IP          string
    Hostname    string
    PingTime    string
    IsUp        bool
    OpenPorts   []int
    LastSeen    time.Time
    FromCache   bool
    MAC         string
    Vendor      string
}

// IPEntry is a custom entry widget with wider minimum size
type IPEntry struct {
    widget.Entry
}

func NewIPEntry() *IPEntry {
    entry := &IPEntry{}
    entry.ExtendBaseWidget(entry)
    return entry
}

func (e *IPEntry) MinSize() fyne.Size {
    return fyne.NewSize(200, e.Entry.MinSize().Height)
}

type ScanConfig struct {
    ShowOffline   bool
    CommonPorts   bool
    AllPorts      bool
    PortRange     [2]int
    ScanDelay     time.Duration
    Timeout       time.Duration
    MaxGoroutines int
}

func main() {
    myApp := app.New()
    myWindow := myApp.NewWindow("Enhanced IP Scanner")
    myWindow.Resize(fyne.NewSize(1000, 700))

    // Create data bindings
    startIP := binding.NewString()
    endIP := binding.NewString()
    var results []ScanResult
    var resultsMutex sync.Mutex
    
    // Get default IP range
    defaultStart, defaultEnd := getDefaultIPRange()
    startIP.Set(defaultStart)
    endIP.Set(defaultEnd)

    // Create input fields
    startIPEntry := NewIPEntry()
    endIPEntry := NewIPEntry()
    startIPEntry.Bind(startIP)
    endIPEntry.Bind(endIP)
    
    // Create progress bar
    progress := widget.NewProgressBar()
    progress.Hide()

    // Create configuration
    config := &ScanConfig{
        ShowOffline:   true,
        CommonPorts:   true,
        AllPorts:      false,
        PortRange:     [2]int{1, 1024},
        ScanDelay:     time.Millisecond * 10,
        Timeout:       time.Millisecond * 500,
        MaxGoroutines: 100,
    }

    // Create results table
    table := widget.NewTable(
        func() (int, int) { return 0, 8 },
        func() fyne.CanvasObject {
            return widget.NewLabel("Template")
        },
        func(i widget.TableCellID, o fyne.CanvasObject) {
            label := o.(*widget.Label)
            label.SetText("")
        })
    
    // Set column widths
    table.SetColumnWidth(0, 120)  // IP
    table.SetColumnWidth(1, 200)  // Hostname
    table.SetColumnWidth(2, 80)   // Ping
    table.SetColumnWidth(3, 200)  // Ports
    table.SetColumnWidth(4, 80)   // Status
    table.SetColumnWidth(5, 150)  // Last Seen
    table.SetColumnWidth(6, 120)  // MAC
    table.SetColumnWidth(7, 150)  // Vendor

    updateTable := func() {
        table.UpdateHeader = func(id widget.TableCellID, template fyne.CanvasObject) {
            label := template.(*widget.Label)
            switch id.Col {
            case 0:
                label.SetText("IP Address")
            case 1:
                label.SetText("Hostname")
            case 2:
                label.SetText("Ping")
            case 3:
                label.SetText("Open Ports")
            case 4:
                label.SetText("Status")
            case 5:
                label.SetText("Last Seen")
            case 6:
                label.SetText("MAC")
            case 7:
                label.SetText("Vendor")
            }
        }
        
        table.Length = func() (int, int) {
            return len(results), 8
        }
        
        table.UpdateCell = func(id widget.TableCellID, template fyne.CanvasObject) {
            label := template.(*widget.Label)
            if id.Row < len(results) {
                switch id.Col {
                case 0:
                    label.SetText(results[id.Row].IP)
                case 1:
                    label.SetText(results[id.Row].Hostname)
                case 2:
                    label.SetText(results[id.Row].PingTime)
                case 3:
                    ports := ""
                    if len(results[id.Row].OpenPorts) > 0 {
                        for _, port := range results[id.Row].OpenPorts {
                            ports += fmt.Sprintf("%d, ", port)
                        }
                        ports = strings.TrimSuffix(ports, ", ")
                    }
                    label.SetText(ports)
                case 4:
                    status := "Online"
                    if !results[id.Row].IsUp {
                        status = "Offline"
                    }
                    if results[id.Row].FromCache {
                        status += " (Cache)"
                    }
                    label.SetText(status)
                case 5:
                    if !results[id.Row].LastSeen.IsZero() {
                        label.SetText(results[id.Row].LastSeen.Format("15:04:05 02.01.06"))
                    } else {
                        label.SetText("-")
                    }
                case 6:
                    label.SetText(results[id.Row].MAC)
                case 7:
                    label.SetText(results[id.Row].Vendor)
                }
            }
        }
        table.Refresh()
    }

    // Create configuration panel
    showOfflineCheck := widget.NewCheck("Show Offline", func(show bool) {
        config.ShowOffline = show
        updateTable()
    })
    showOfflineCheck.SetChecked(config.ShowOffline)

    // Initialize checkboxes without handlers first
    commonPortsCheck := widget.NewCheck("Common Ports", nil)
    allPortsCheck := widget.NewCheck("All Ports (1-1024)", nil)

    // Then set up the handlers
    commonPortsCheck.OnChanged = func(common bool) {
        if common {
            config.CommonPorts = true
            config.AllPorts = false
            allPortsCheck.SetChecked(false)
        } else {
            config.CommonPorts = false
        }
    }

    allPortsCheck.OnChanged = func(all bool) {
        if all {
            config.AllPorts = true
            config.CommonPorts = false
            commonPortsCheck.SetChecked(false)
        } else {
            config.AllPorts = false
        }
    }

    // Set initial states
    commonPortsCheck.SetChecked(config.CommonPorts)
    allPortsCheck.SetChecked(config.AllPorts)

    // Export button
    exportBtn := widget.NewButton("Export CSV", func() {
        if len(results) == 0 {
            dialog.ShowInformation("Export", "No results to export", myWindow)
            return
        }

        saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
            if err != nil {
                dialog.ShowError(err, myWindow)
                return
            }
            if writer == nil {
                return
            }
            defer writer.Close()

            csvWriter := csv.NewWriter(writer)
            defer csvWriter.Flush()

            // Write header
            csvWriter.Write([]string{"IP", "Hostname", "Ping", "Open Ports", "Status", "Last Seen", "MAC", "Vendor"})

            // Write data
            for _, r := range results {
                ports := strings.Trim(strings.Join(strings.Fields(fmt.Sprint(r.OpenPorts)), ","), "[]")
                status := "Online"
                if !r.IsUp {
                    status = "Offline"
                }
                if r.FromCache {
                    status += " (Cache)"
                }
                lastSeen := "-"
                if !r.LastSeen.IsZero() {
                    lastSeen = r.LastSeen.Format("15:04:05 02.01.06")
                }
                csvWriter.Write([]string{
                    r.IP,
                    r.Hostname,
                    r.PingTime,
                    ports,
                    status,
                    lastSeen,
                    r.MAC,
                    r.Vendor,
                })
            }
        }, myWindow)
        saveDialog.SetFileName("scan_results_" + time.Now().Format("20060102_150405") + ".csv")
        saveDialog.Show()
    })

    var scanContext context.Context
    var cancelScan context.CancelFunc

    // Create scan button
    scanBtn := widget.NewButtonWithIcon("Start Scan", theme.MediaPlayIcon(), nil)
    
    scanBtn.OnTapped = func() {
        if scanBtn.Text == "Start Scan" {
            start, _ := startIP.Get()
            end, _ := endIP.Get()

            if !isValidIPRange(start, end) {
                dialog.ShowError(fmt.Errorf("Invalid IP range"), myWindow)
                return
            }

            results = nil
            updateTable()
            progress.Show()
            progress.SetValue(0)
            
            scanBtn.SetText("Stop Scan")
            scanBtn.SetIcon(theme.MediaStopIcon())
            
            scanContext, cancelScan = context.WithCancel(context.Background())
            
            go func() {
                startIPNum := ip2int(net.ParseIP(start))
                endIPNum := ip2int(net.ParseIP(end))
                total := float64(endIPNum - startIPNum + 1)
                current := float64(0)

                var wg sync.WaitGroup
                semaphore := make(chan struct{}, config.MaxGoroutines)

                for ipNum := startIPNum; ipNum <= endIPNum; ipNum++ {
                    if scanContext.Err() != nil {
                        break
                    }

                    wg.Add(1)
                    semaphore <- struct{}{} // Acquire
                    
                    go func(ip string) {
                        defer wg.Done()
                        defer func() { <-semaphore }() // Release

                        result := scanIP(ip, config)
                        
                        if result.IsUp || config.ShowOffline {
                            resultsMutex.Lock()
                            results = append(results, result)
                            // Sort results by IP
                            sort.Slice(results, func(i, j int) bool {
                                return ip2int(net.ParseIP(results[i].IP)) < ip2int(net.ParseIP(results[j].IP))
                            })
                            resultsMutex.Unlock()
                        }
                        
                        current++
                        progress.SetValue(current / total)
                        updateTable()
                        
                        // Apply scan delay
                        time.Sleep(config.ScanDelay)
                    }(int2ip(ipNum).String())
                }

                wg.Wait()
                
                if scanContext.Err() == nil {
                    progress.SetValue(1)
                }
                
                scanBtn.SetText("Start Scan")
                scanBtn.SetIcon(theme.MediaPlayIcon())
                cancelScan = nil
            }()
        } else {
            if cancelScan != nil {
                cancelScan()
            }
            scanBtn.SetText("Start Scan")
            scanBtn.SetIcon(theme.MediaPlayIcon())
            progress.Hide()
        }
    }

    // Layout
    configBox := container.NewHBox(
        showOfflineCheck,
        widget.NewSeparator(),
        commonPortsCheck,
        allPortsCheck,
        layout.NewSpacer(),
        exportBtn,
    )

    inputs := container.NewHBox(
        widget.NewLabel("Start IP:"),
        startIPEntry,
        widget.NewLabel("End IP:"),
        endIPEntry,
        layout.NewSpacer(),
        scanBtn,
    )

    content := container.NewBorder(
        container.NewVBox(inputs, configBox, progress),
        nil, nil, nil,
        table,
    )

    myWindow.SetContent(content)
    myWindow.ShowAndRun()
}

func scanIP(ip string, config *ScanConfig) ScanResult {
    result := ScanResult{
        IP:        ip,
        LastSeen:  time.Now(),
        FromCache: false,
    }

    // Try to get MAC address and vendor
    if mac, vendor := getMACAndVendor(ip); mac != "" {
        result.MAC = mac
        result.Vendor = vendor
    }

    // Resolve hostname (includes cache check)
    if hosts, err := net.LookupAddr(ip); err == nil && len(hosts) > 0 {
        result.Hostname = hosts[0]
        result.FromCache = true // Might be from cache
    }

    // Check if host is up using TCP instead of ICMP
    start := time.Now()
    // Try common ports for availability check
    commonCheckPorts := []int{80, 443, 22, 445, 139}
    isUp := false
    for _, port := range commonCheckPorts {
        conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), config.Timeout)
        if err == nil {
            conn.Close()
            isUp = true
            break
        }
    }
    
    if isUp {
        result.IsUp = true
        result.PingTime = time.Since(start).Round(time.Millisecond).String()
        result.FromCache = false // Actually responded
    } else {
        result.PingTime = "Timeout"
        // Only return if we want to skip offline hosts and it's not in cache
        if !config.ShowOffline && !result.FromCache {
            return result
        }
    }

    // Port scanning
    var portsToScan []int
    if config.AllPorts {
        for i := 1; i <= 1024; i++ {
            portsToScan = append(portsToScan, i)
        }
    } else if config.CommonPorts {
        portsToScan = []int{
            20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1723, 3306, 3389, 5900, 8080, 8443,
        }
    }

    for _, port := range portsToScan {
        address := fmt.Sprintf("%s:%d", ip, port)
        conn, err := net.DialTimeout("tcp", address, config.Timeout)
        if err == nil {
            result.OpenPorts = append(result.OpenPorts, port)
            conn.Close()
        }
    }

    sort.Ints(result.OpenPorts)
    return result
}

func getMACAndVendor(ip string) (string, string) {
    // This is a simplified version. For a full implementation,
    // you would need to:
    // 1. Use ARP to get MAC (requires root/admin privileges)
    // 2. Query a MAC vendor database
    
    // For now, we'll just try to get the MAC from the ARP cache
    // Note: This only works for Linux/Unix systems
    file, err := os.ReadFile("/proc/net/arp")
    if err != nil {
        return "", ""
    }

    lines := strings.Split(string(file), "\n")
    for _, line := range lines {
        fields := strings.Fields(line)
        if len(fields) >= 4 && fields[0] == ip {
            mac := fields[3]
            // In a real implementation, you would query a vendor database here
            return mac, "Unknown Vendor"
        }
    }

    return "", ""
}

func ip2int(ip net.IP) uint32 {
    if len(ip) == 16 {
        ip = ip[12:16]
    }
    var n uint32
    for i := range ip {
        n = (n << 8) + uint32(ip[i])
    }
    return n
}

func int2ip(n uint32) net.IP {
    ip := make(net.IP, 4)
    for i := range ip {
        ip[3-i] = byte(n & 0xFF)
        n >>= 8
    }
    return ip
}

func isValidIPRange(start, end string) bool {
    startIP := net.ParseIP(start)
    endIP := net.ParseIP(end)
    
    if startIP == nil || endIP == nil {
        return false
    }
    
    return ip2int(startIP) <= ip2int(endIP)
}

func getDefaultIPRange() (string, string) {
    addrs, err := net.InterfaceAddrs()
    if err != nil {
        return "192.168.1.1", "192.168.1.254"
    }

    for _, addr := range addrs {
        if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
            if ipv4 := ipnet.IP.To4(); ipv4 != nil {
                // Get network address
                network := ipnet.IP.Mask(ipnet.Mask)
                
                // Calculate start and end IPs
                start := make(net.IP, len(network))
                copy(start, network)
                start[len(start)-1] = 1

                end := make(net.IP, len(network))
                copy(end, network)
                for i := len(end) - 1; i >= 0; i-- {
                    end[i] = ^ipnet.Mask[i] | network[i]
                }
                end[len(end)-1]--

                return start.String(), end.String()
            }
        }
    }
    
    return "192.168.1.1", "192.168.1.254"
}
