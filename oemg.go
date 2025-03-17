package main

import (
    "bufio"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/hex"
    "flag"
    "fmt"
    "hash/crc32"
    "math/rand"
    "os"
    "regexp"
    "runtime"
    "strings"
    "sync"
    "time"
)

// HashType definition - supported hash types
type HashType string

const (
    MD5           HashType = "md5"
    MD5_MD5       HashType = "md5md5"
    SHA1          HashType = "sha1"
    SHA1_SHA1     HashType = "sha1sha1"
    SHA256        HashType = "sha256"
    SHA256_SHA256 HashType = "sha256sha256"
    CRC32         HashType = "crc32"
)

// Config structure holds all settings
type Config struct {
    baseString     string
    charset        string
    batchSize      int
    minLength      int
    maxLength      int
    prependRandom  bool // true: random + baseString, false: baseString + random
    numThreads     int
    hashType       HashType
}

// Default values - no longer fixed, can be changed with flags
var config = Config{
    baseString:     "lodos2005",
    charset:        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_=+[]{}|;:,.<>?/",
    batchSize:      100000,
    minLength:      10,
    maxLength:      50,
    prependRandom:  false, // default baseString + random (suffix mode)
    numThreads:     runtime.NumCPU(),
    hashType:       MD5,
}

// Hash calculation functions
func calculateMD5(input string) string {
    hash := md5.Sum([]byte(input))
    return hex.EncodeToString(hash[:])
}

func calculateSHA1(input string) string {
    hash := sha1.Sum([]byte(input))
    return hex.EncodeToString(hash[:])
}

func calculateSHA256(input string) string {
    hash := sha256.Sum256([]byte(input))
    return hex.EncodeToString(hash[:])
}

func calculateCRC32(input string) string {
    hash := crc32.ChecksumIEEE([]byte(input))
    return fmt.Sprintf("%08x", hash) // 8 character hex format
}

// Calculates hash based on selected hash type
func calculateHash(input string, hashType HashType) string {
    switch hashType {
    case MD5:
        return calculateMD5(input)
    case MD5_MD5:
        return calculateMD5(calculateMD5(input))
    case SHA1:
        return calculateSHA1(input)
    case SHA1_SHA1:
        return calculateSHA1(calculateSHA1(input))
    case SHA256:
        return calculateSHA256(input)
    case SHA256_SHA256:
        return calculateSHA256(calculateSHA256(input))
    case CRC32:
        return calculateCRC32(input)
    default:
        return calculateMD5(input) // Use MD5 as default for unknown types
    }
}

// Hash validation - does it start with "0e" or "00e" and continue with only digits?
func isValidHash(hash string, hashType HashType) bool {
    // For MD5 and derivatives (new hash algorithms can be added)
    if hashType == MD5 || hashType == MD5_MD5 || 
       hashType == SHA1 || hashType == SHA1_SHA1 || 
       hashType == SHA256 || hashType == SHA256_SHA256 || 
       hashType == CRC32 {
        // Does it start with "0e" or any number of 0s followed by e (e.g., "00e", "000e", etc.)?
        if !regexp.MustCompile(`^0+e`).MatchString(hash) {
            return false
        }

        // The part after the prefix must consist only of digits
        parts := regexp.MustCompile(`^(0+e)([0-9]*)$`).FindStringSubmatch(hash)
        if len(parts) < 3 || parts[2] == "" {
            return false
        }
        
        return true
    }
    
    return false
}

// Random string generation - more efficient algorithm
func randomString(length int, charset string) string {
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Intn(len(charset))]
    }
    return string(b)
}

// Worker function
func worker(id int, wg *sync.WaitGroup, resultChan chan<- struct {
    key  string
    hash string
}, stopChan <-chan struct{}, statusChan chan<- struct {
    key  string
    hash string
}, cfg Config) {
    defer wg.Done()

    localRand := rand.New(rand.NewSource(time.Now().UnixNano() + int64(id)))
    
    for {
            select {
            case <-stopChan:
                    return
            default:
            }

            randomLength := localRand.Intn(cfg.maxLength-cfg.minLength+1) + cfg.minLength
            randomPart := randomString(randomLength, cfg.charset)
            
            // Use random part as suffix or prefix according to config
            var key string
            if cfg.prependRandom {
                key = randomPart + cfg.baseString // random + baseString (prefix mode)
            } else {
                key = cfg.baseString + randomPart // baseString + random (suffix mode)
            }

            hash := calculateHash(key, cfg.hashType)

            select {
            case statusChan <- struct {
                    key  string
                    hash string
            }{key, hash}:
            default:
            }

            if isValidHash(hash, cfg.hashType) {
                    resultChan <- struct {
                            key  string
                            hash string
                    }{key, hash}
                    return
            }
    }
}

// Helper function to create single-line progress bar
func clearLine() {
    fmt.Print("\r\033[K") // Clear terminal line
}

// Display help text
func showHelp() {
    fmt.Println("Type Juggling Finder")
    fmt.Println("-------------------")
    fmt.Println("Tool for finding hash type juggling vulnerabilities")
    fmt.Println()
    fmt.Println("Usage:")
		fmt.Printf("  %s [options] [command]\n", os.Args[0][strings.LastIndex(os.Args[0], "/")+1:])
    fmt.Println()
    fmt.Println("Commands:")
    fmt.Println("  check - Check MD5 hash of a string")
    fmt.Println("  run   - Start searching for jugglings")
    fmt.Println()
    fmt.Println("Options:")
    fmt.Println("  -base string")
    fmt.Printf("        Base string (default \"%s\")\n", config.baseString)
    fmt.Println("  -batch int")
    fmt.Printf("        Batch size for each thread (default %d)\n", config.batchSize)
    fmt.Println("  -charset string")
    fmt.Printf("        Character set to use (default \"%s\")\n", config.charset[:10] + "...")
    fmt.Println("  -hash string")
    fmt.Printf("        Hash algorithm: md5, md5md5, sha1, sha1sha1, sha256, sha256sha256, crc32 (default \"%s\")\n", config.hashType)
    fmt.Println("  -max int")
    fmt.Printf("        Maximum random character length (default %d)\n", config.maxLength)
    fmt.Println("  -min int")
    fmt.Printf("        Minimum random character length (default %d)\n", config.minLength)
    fmt.Println("  -mode string")
    fmt.Println("        Mode: 'prefix' (random+base) or 'suffix' (base+random) (default \"suffix\")")
    fmt.Println("  -threads int")
    fmt.Printf("        Number of threads to use (default: number of CPUs = %d)\n", runtime.NumCPU())
    fmt.Println()
		fmt.Println("Examples:")
		fmt.Printf("  %s run\n", os.Args[0][strings.LastIndex(os.Args[0], "/")+1:])
		fmt.Printf("  %s -hash sha1 -mode prefix -base test123 run\n", os.Args[0][strings.LastIndex(os.Args[0], "/")+1:])
		fmt.Printf("  %s -hash md5md5 -min 3 -max 10 check\n", os.Args[0][strings.LastIndex(os.Args[0], "/")+1:])
}

// Mode selection for user interaction
func selectMode() (string, error) {
    fmt.Println("Type Juggling Finder")
    fmt.Println("-------------------")
    fmt.Println("1. check - Check a string's hash")
    fmt.Println("2. run   - Start searching for jugglings")
    fmt.Print("\nYour choice (check/run): ")

    reader := bufio.NewReader(os.Stdin)
    input, err := reader.ReadString('\n')
    if err != nil {
        return "", err
    }

    input = strings.TrimSpace(strings.ToLower(input))
    if input != "check" && input != "run" && input != "1" && input != "2" {
        return "", fmt.Errorf("invalid selection: %s (should be check or run)", input)
    }

    return input, nil
}

// Check mode: Get a string and check its hash
func checkMode(cfg Config) error {
    reader := bufio.NewReader(os.Stdin)
    
    var prompt string
    if cfg.prependRandom {
        prompt = fmt.Sprintf("Enter string to append to '%s': ", cfg.baseString)
    } else {
        prompt = fmt.Sprintf("Enter string to prepend to '%s': ", cfg.baseString)
    }
    
    fmt.Print(prompt)
    
    input, err := reader.ReadString('\n')
    if err != nil {
        return err
    }
    
    input = strings.TrimSpace(input)
    
    var fullString string
    if cfg.prependRandom {
        fullString = input + cfg.baseString
    } else {
        fullString = cfg.baseString + input
    }
    
    hash := calculateHash(fullString, cfg.hashType)
    
    fmt.Printf("\nString: %s\n", fullString)
    fmt.Printf("%s Hash: %s\n", strings.ToUpper(string(cfg.hashType)), hash)
    
    if isValidHash(hash, cfg.hashType) {
        fmt.Println("\n🎉 This string creates a valid type juggling vulnerability!")
        fmt.Println("Hash starts with '" + regexp.MustCompile(`^(0+e)`).FindString(hash) + "' and continues with only digits.")
        fmt.Println("This hash would be evaluated as the number '0' in languages like PHP due to type juggling.")
    } else if regexp.MustCompile(`^0+e`).MatchString(hash) {
        fmt.Println("\n❌ This string does not create a type juggling vulnerability.")
        fmt.Println("Hash starts with '" + regexp.MustCompile(`^(0+e)`).FindString(hash) + "', but doesn't continue with only digits.")
    } else {
        fmt.Println("\n❌ This string does not create a type juggling vulnerability.")
        fmt.Println("Hash doesn't start with '0e' or similar pattern.")
    }
    
    return nil
}

func main() {
    // Define flags
    basePtr := flag.String("base", config.baseString, "Base string")
    charsetPtr := flag.String("charset", config.charset, "Character set to use")
    batchSizePtr := flag.Int("batch", config.batchSize, "Batch size for each thread")
    minLenPtr := flag.Int("min", config.minLength, "Minimum random character length")
    maxLenPtr := flag.Int("max", config.maxLength, "Maximum random character length")
    modePtr := flag.String("mode", "suffix", "Mode: 'prefix' (random+base) or 'suffix' (base+random)")
    threadsPtr := flag.Int("threads", config.numThreads, "Number of threads to use (default: number of CPUs)")
    hashTypePtr := flag.String("hash", string(config.hashType), 
        "Hash algorithm: md5, md5md5, sha1, sha1sha1, sha256, sha256sha256, crc32")
    
    // Parse flags
    flag.Parse()
    
    // Update config
    config.baseString = *basePtr
    config.charset = *charsetPtr
    config.batchSize = *batchSizePtr
    config.minLength = *minLenPtr
    config.maxLength = *maxLenPtr
    config.numThreads = *threadsPtr
    
    // Check and set hash type
    switch strings.ToLower(*hashTypePtr) {
    case string(MD5):
        config.hashType = MD5
    case string(MD5_MD5):
        config.hashType = MD5_MD5
    case string(SHA1):
        config.hashType = SHA1
    case string(SHA1_SHA1):
        config.hashType = SHA1_SHA1
    case string(SHA256):
        config.hashType = SHA256
    case string(SHA256_SHA256):
        config.hashType = SHA256_SHA256
    case string(CRC32):
        config.hashType = CRC32
    default:
        fmt.Printf("Error: Invalid hash type '%s'. Supported types: md5, md5md5, sha1, sha1sha1, sha256, sha256sha256, crc32\n", 
            *hashTypePtr)
        os.Exit(1)
    }
    
    // Check mode selection
    if *modePtr == "prefix" {
        config.prependRandom = true
    } else if *modePtr == "suffix" {
        config.prependRandom = false
    } else {
        fmt.Printf("Error: Invalid mode '%s'. Use 'prefix' or 'suffix'.\n", *modePtr)
        os.Exit(1)
    }
    
    // Set random seed
    rand.Seed(time.Now().UnixNano())
    
    // If no arguments or command provided, show help
    args := flag.Args()
    if len(args) == 0 {
        showHelp()
        return
    }
    
    // If argument exists, run modes directly
    if args[0] == "check" {
        if err := checkMode(config); err != nil {
            fmt.Printf("Error: %v\n", err)
            os.Exit(1)
        }
    } else if args[0] == "run" {
        runJugglingFinder(config)
    } else {
        fmt.Printf("Unknown command: %s\n\n", args[0])
        showHelp()
        os.Exit(1)
    }
}

// Main juggling search function
func runJugglingFinder(cfg Config) {
    // Configure thread settings
    runtime.GOMAXPROCS(cfg.numThreads)
    
    // Prepare mode info
    modText := "suffix"
    if cfg.prependRandom {
        modText = "prefix"
    }
    
    fmt.Printf("Running with %d threads on %d CPU cores\n", cfg.numThreads, runtime.NumCPU())
    fmt.Printf("Hash algorithm: %s\n", strings.ToUpper(string(cfg.hashType)))
    fmt.Printf("Base string: %s\n", cfg.baseString)
    fmt.Printf("Mode: %s (random part is %s)\n", modText, modText)
    fmt.Printf("Charset: %s\n", cfg.charset) 
    fmt.Printf("Starting type juggling search (random character length: %d-%d)...\n", 
        cfg.minLength, cfg.maxLength)

    var wg sync.WaitGroup
    resultChan := make(chan struct {
        key  string
        hash string
    }, 1)
    
    stopChan := make(chan struct{})
    done := make(chan struct{})
    
    // Channel for carrying last tried hash info
    statusChan := make(chan struct {
        key  string
        hash string
    }, 1)
    
    // Start workers
    for i := 0; i < cfg.numThreads; i++ {
        wg.Add(1)
        go worker(i, &wg, resultChan, stopChan, statusChan, cfg)
    }
    
    // Process monitor - tqdm-like progress indicator
    go func() {
        hashCount := 0
        lastHashCount := 0
        startTime := time.Now()
        lastKey := ""
        lastHash := ""
        ticker := time.NewTicker(100 * time.Millisecond)
        statusTicker := time.NewTicker(30 * time.Second) // Show statistics every 30 seconds
        defer ticker.Stop()
        defer statusTicker.Stop()

        for {
            select {
            case <-done:
                return
            case status := <-statusChan:
                lastKey = status.key
                lastHash = status.hash
                hashCount++
            case <-ticker.C:
                elapsed := time.Since(startTime)
                hps := float64(hashCount) / elapsed.Seconds()
                
                // Shortened key (if too long)
                displayKey := lastKey
                if len(displayKey) > 25 {
                    displayKey = displayKey[:22] + "..."
                }
                
                // Progress bar
                progressBar := "[" + strings.Repeat("=", min(hashCount/1000000, 20)) + 
                    strings.Repeat(" ", max(0, 20-hashCount/1000000)) + "]"
                
                // Single line progress indicator
                clearLine()
                fmt.Printf("\r%s %.2f hash/s | Key: %s | %s: %s", 
                    progressBar, hps, displayKey, strings.ToUpper(string(cfg.hashType)), lastHash)
            case <-statusTicker.C:
                // Show statistics
                elapsed := time.Since(startTime)
                totalHashes := hashCount
                avgHps := float64(totalHashes) / elapsed.Seconds()
                
                // Speed in last period
                lastPerHps := float64(hashCount - lastHashCount) / 30.0 // 30 second period
                lastHashCount = hashCount
                
                clearLine()
                fmt.Printf("\nTotal hashes: %d (%s elapsed)\n", 
                    totalHashes, formatDuration(elapsed))
                fmt.Printf("Average speed: %.2f hash/s\n", avgHps)
                fmt.Printf("Last period speed: %.2f hash/s\n", lastPerHps)
            }
        }
    }()

    // Wait for result
    result := <-resultChan
    close(done)

    // Clear last progress info
    clearLine()
    
    fmt.Println("\n\n🎉 Type juggling vulnerability found!")
    fmt.Println("Key:", result.key)
    fmt.Printf("%s: %s\n", strings.ToUpper(string(cfg.hashType)), result.hash)

    // Send termination signal to other workers
    close(stopChan)
    wg.Wait()

    os.Exit(0)
}

// Helper functions
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}

func max(a, b int) int {
    if a > b {
        return a
    }
    return b
}

// Helper function to format duration
func formatDuration(d time.Duration) string {
    d = d.Round(time.Second)
    h := d / time.Hour
    d -= h * time.Hour
    m := d / time.Minute
    d -= m * time.Minute
    s := d / time.Second
    
    if h > 0 {
        return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
    }
    return fmt.Sprintf("%02d:%02d", m, s)
}
