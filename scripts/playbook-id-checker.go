package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type PlaybookInfo struct {
	ID       int
	FilePath string
}

type IDChecker struct {
	idMap    map[int][]string // ID -> list of file paths
	allIDs   []int
	minRange int
	maxRange int
	startID  int
	mu       sync.RWMutex
}

func NewIDChecker() *IDChecker {
	return &IDChecker{
		idMap:    make(map[int][]string),
		minRange: 1000000,
		maxRange: 1999999,
		startID:  1200001,
	}
}

func (ic *IDChecker) addID(id int, filePath string) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	
	ic.idMap[id] = append(ic.idMap[id], filePath)
	ic.allIDs = append(ic.allIDs, id)
}

func (ic *IDChecker) processFile(filePath string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file %s: %v\n", filePath, err)
		return
	}
	defer file.Close()
	
	// Regex to match "id: <number>" at the beginning of a line
	idRegex := regexp.MustCompile(`^id:\s*(\d+)\s*$`)
	
	scanner := bufio.NewScanner(file)
	lineNum := 0
	
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		
		if matches := idRegex.FindStringSubmatch(line); matches != nil {
			if id, err := strconv.Atoi(matches[1]); err == nil {
				ic.addID(id, filePath)
				return // Found ID, no need to continue scanning this file
			}
		}
		
		// Optimization: only scan first 50 lines (ID should be near top)
		if lineNum > 50 {
			break
		}
	}
	
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error scanning file %s: %v\n", filePath, err)
	}
}

func (ic *IDChecker) findYAMLFiles(rootDir string) ([]string, error) {
	var yamlFiles []string
	
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip temp directories and hidden files
		if strings.Contains(path, "/temp/") || strings.Contains(path, "/.") {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		
		if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			yamlFiles = append(yamlFiles, path)
		}
		
		return nil
	})
	
	return yamlFiles, err
}

func (ic *IDChecker) scanPlaybooks(rootDir string, silent bool) error {
	if !silent {
		fmt.Printf("Scanning for YAML files in %s...\n", rootDir)
	}
	
	yamlFiles, err := ic.findYAMLFiles(rootDir)
	if err != nil {
		return fmt.Errorf("error finding YAML files: %v", err)
	}
	
	if !silent {
		fmt.Printf("Found %d YAML files. Processing...\n", len(yamlFiles))
	}
	
	// Use worker pool for concurrent processing
	const numWorkers = 10
	filesChan := make(chan string, len(yamlFiles))
	var wg sync.WaitGroup
	
	// Start workers
	for i := 0; i < numWorkers; i++ {
		go func() {
			for filePath := range filesChan {
				ic.processFile(filePath, &wg)
			}
		}()
	}
	
	// Send files to workers
	for _, filePath := range yamlFiles {
		wg.Add(1)
		filesChan <- filePath
	}
	
	close(filesChan)
	wg.Wait()
	
	return nil
}

func (ic *IDChecker) findDuplicates() []int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	
	var duplicates []int
	for id, files := range ic.idMap {
		if len(files) > 1 {
			duplicates = append(duplicates, id)
		}
	}
	
	sort.Ints(duplicates)
	return duplicates
}

func (ic *IDChecker) findNextAvailableID() int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	
	// Create a set of used IDs in the target range
	usedIDs := make(map[int]bool)
	for id := range ic.idMap {
		if id >= ic.minRange && id <= ic.maxRange {
			usedIDs[id] = true
		}
	}
	
	// Find the first available ID starting from startID
	for id := ic.startID; id <= ic.maxRange; id++ {
		if !usedIDs[id] {
			return id
		}
	}
	
	return -1 // No available ID found
}

func (ic *IDChecker) findNextNIDSID() int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	
	// NIDS range: 1,200,001 - 1,499,999
	nidsStart := 1200001
	nidsEnd := 1499999
	
	usedIDs := make(map[int]bool)
	for id := range ic.idMap {
		if id >= nidsStart && id <= nidsEnd {
			usedIDs[id] = true
		}
	}
	
	// Find the first available ID in NIDS range
	for id := nidsStart; id <= nidsEnd; id++ {
		if !usedIDs[id] {
			return id
		}
	}
	
	return -1 // No available ID found
}

func (ic *IDChecker) findNextSigmaID() int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	
	// Sigma range: 1,500,001 - 1,599,999
	sigmaStart := 1500001
	sigmaEnd := 1599999
	
	usedIDs := make(map[int]bool)
	for id := range ic.idMap {
		if id >= sigmaStart && id <= sigmaEnd {
			usedIDs[id] = true
		}
	}
	
	// Find the first available ID in Sigma range
	for id := sigmaStart; id <= sigmaEnd; id++ {
		if !usedIDs[id] {
			return id
		}
	}
	
	return -1 // No available ID found
}

func (ic *IDChecker) getIDsInRange() []int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	
	var idsInRange []int
	for id := range ic.idMap {
		if id >= ic.minRange && id <= ic.maxRange {
			idsInRange = append(idsInRange, id)
		}
	}
	
	sort.Ints(idsInRange)
	return idsInRange
}

func (ic *IDChecker) getIDsOutsideRange() []int {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	
	var idsOutside []int
	for id := range ic.idMap {
		if id < ic.minRange || id > ic.maxRange {
			idsOutside = append(idsOutside, id)
		}
	}
	
	sort.Ints(idsOutside)
	return idsOutside
}

type IDRange struct {
	Start int
	End   int
	Count int
}

func (ic *IDChecker) detectRanges() []IDRange {
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	
	// Get all IDs in range and sort them
	var sortedIDs []int
	for id := range ic.idMap {
		if id >= ic.minRange && id <= ic.maxRange {
			sortedIDs = append(sortedIDs, id)
		}
	}
	sort.Ints(sortedIDs)
	
	if len(sortedIDs) == 0 {
		return []IDRange{}
	}
	
	var ranges []IDRange
	currentRange := IDRange{Start: sortedIDs[0], End: sortedIDs[0], Count: 1}
	
	// Define gap threshold - if gap is larger than this, it's a new range
	const gapThreshold = 75000 // 75k gap indicates new range
	
	for i := 1; i < len(sortedIDs); i++ {
		gap := sortedIDs[i] - sortedIDs[i-1]
		
		if gap > gapThreshold {
			// Large gap detected - finalize current range and start new one
			ranges = append(ranges, currentRange)
			currentRange = IDRange{Start: sortedIDs[i], End: sortedIDs[i], Count: 1}
		} else {
			// Continue current range - just update the end, don't increment count
			currentRange.End = sortedIDs[i]
		}
	}
	
	// Set the final count correctly by counting IDs in the last range
	lastRangeCount := 1
	for j := len(sortedIDs) - 2; j >= 0; j-- {
		if sortedIDs[j+1] - sortedIDs[j] <= gapThreshold {
			lastRangeCount++
		} else {
			break
		}
	}
	currentRange.Count = lastRangeCount
	
	// Add the final range
	ranges = append(ranges, currentRange)
	
	// Now fix the counts for all ranges properly
	for i := range ranges {
		count := 0
		for _, id := range sortedIDs {
			if id >= ranges[i].Start && id <= ranges[i].End {
				count++
			}
		}
		ranges[i].Count = count
	}
	
	return ranges
}

func (ic *IDChecker) printReport() {
	totalIDs := len(ic.idMap)
	duplicates := ic.findDuplicates()
	idsInRange := ic.getIDsInRange()
	idsOutside := ic.getIDsOutsideRange()
	nextID := ic.findNextAvailableID()
	ranges := ic.detectRanges()
	
	ic.mu.RLock()
	defer ic.mu.RUnlock()
	
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("PLAYBOOK ID ANALYSIS REPORT")
	fmt.Println(strings.Repeat("=", 80))
	
	fmt.Printf("Total unique IDs found: %d\n", totalIDs)
	fmt.Printf("IDs in range (%d-%d): %d\n", ic.minRange, ic.maxRange, len(idsInRange))
	fmt.Printf("IDs outside range: %d\n", len(idsOutside))
	fmt.Printf("Duplicate IDs found: %d\n", len(duplicates))
	
	if nextID != -1 {
		fmt.Printf("Next available ID: %d\n", nextID)
	} else {
		fmt.Println("No available IDs in range!")
	}
	
	// Report duplicates
	if len(duplicates) > 0 {
		fmt.Println("\n" + strings.Repeat("-", 40))
		fmt.Println("DUPLICATE IDs:")
		fmt.Println(strings.Repeat("-", 40))
		
		for _, id := range duplicates {
			files := ic.idMap[id]
			fmt.Printf("ID %d appears in %d files:\n", id, len(files))
			for _, file := range files {
				fmt.Printf("  - %s\n", file)
			}
			fmt.Println()
		}
	}
	
	// Report IDs outside range (first 20)
	if len(idsOutside) > 0 {
		fmt.Println(strings.Repeat("-", 40))
		fmt.Println("IDs OUTSIDE RECOMMENDED RANGE:")
		fmt.Println(strings.Repeat("-", 40))
		
		displayCount := len(idsOutside)
		if displayCount > 20 {
			displayCount = 20
		}
		
		for i := 0; i < displayCount; i++ {
			id := idsOutside[i]
			files := ic.idMap[id]
			fmt.Printf("ID %d in: %s\n", id, files[0])
		}
		
		if len(idsOutside) > 20 {
			fmt.Printf("... and %d more IDs outside range\n", len(idsOutside)-20)
		}
		fmt.Println()
	}
	
	// Show detected ranges
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("DETECTED ID RANGES:")
	fmt.Println(strings.Repeat("-", 40))
	
	if len(ranges) > 0 {
		for i, r := range ranges {
			density := float64(r.Count) / float64(r.End-r.Start+1) * 100
			fmt.Printf("Range %d: %d - %d\n", i+1, r.Start, r.End)
			fmt.Printf("  IDs used: %d\n", r.Count)
			fmt.Printf("  Span: %d numbers\n", r.End-r.Start+1)
			fmt.Printf("  Density: %.1f%%\n", density)
			fmt.Println()
		}
	}
	
	// Show overall coverage
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("OVERALL COVERAGE ANALYSIS:")
	fmt.Println(strings.Repeat("-", 40))
	
	if len(idsInRange) > 0 {
		minUsed := idsInRange[0]
		maxUsed := idsInRange[len(idsInRange)-1]
		
		fmt.Printf("Lowest ID in range: %d\n", minUsed)
		fmt.Printf("Highest ID in range: %d\n", maxUsed)
		fmt.Printf("Total span used: %d-%d (%d numbers)\n", minUsed, maxUsed, maxUsed-minUsed+1)
		fmt.Printf("Total ranges detected: %d\n", len(ranges))
		
		// Calculate gaps
		gaps := 0
		for i := minUsed; i <= maxUsed; i++ {
			if _, exists := ic.idMap[i]; !exists {
				gaps++
			}
		}
		fmt.Printf("Gaps in total span: %d\n", gaps)
	}
	
	fmt.Println(strings.Repeat("=", 80))
}

func main() {
	start := time.Now()
	
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run playbook-id-checker.go <path-to-playbooks-directory> [options]")
		fmt.Println("Example: go run playbook-id-checker.go /path/to/securityonion-resources-playbooks")
		fmt.Println("Options:")
		fmt.Println("  -next nids    Show next available NIDS ID only")
		fmt.Println("  -next sigma   Show next available Sigma ID only")
		os.Exit(1)
	}
	
	rootDir := os.Args[1]
	
	// Check for -next parameter
	nextMode := ""
	if len(os.Args) >= 4 && os.Args[2] == "-next" {
		nextMode = strings.ToLower(os.Args[3])
		if nextMode != "nids" && nextMode != "sigma" {
			fmt.Println("Error: -next parameter must be 'nids' or 'sigma'")
			os.Exit(1)
		}
	}
	
	if _, err := os.Stat(rootDir); os.IsNotExist(err) {
		fmt.Printf("Error: Directory %s does not exist\n", rootDir)
		os.Exit(1)
	}
	
	checker := NewIDChecker()
	
	// Silent mode when using -next parameter
	silent := nextMode != ""
	
	if err := checker.scanPlaybooks(rootDir, silent); err != nil {
		fmt.Printf("Error scanning playbooks: %v\n", err)
		os.Exit(1)
	}
	
	// Check if any playbooks were found
	totalIDs := len(checker.idMap)
	if totalIDs == 0 {
		fmt.Fprintf(os.Stderr, "Error: No playbooks found in %s\n", rootDir)
		os.Exit(1)
	}
	
	// Handle -next mode
	if nextMode != "" {
		var nextID int
		switch nextMode {
		case "nids":
			nextID = checker.findNextNIDSID()
		case "sigma":
			nextID = checker.findNextSigmaID()
		}
		
		if nextID == -1 {
			fmt.Fprintf(os.Stderr, "Error: No available %s IDs found\n", strings.ToUpper(nextMode))
			os.Exit(1)
		} else {
			fmt.Printf("%d\n", nextID)
		}
		return
	}
	
	checker.printReport()
	
	fmt.Printf("\nCompleted in %v\n", time.Since(start))
}