package main

import (
	"fmt"
	"math/bits"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var WORKERS_AMOUNT = runtime.NumCPU()     // 512 MB RAM for each worker. Using max threads - increases performance
var WORKERS_SUM_AMOUNT = runtime.NumCPU() // Doesn't affect RAM or CPU

// max value for 24 byte number / 64. For uint64
// 32 - 8 = 24 -> 2^24 = 16 777 216 -> / 64
const BITMAP_SEGMENT_SIZE = 262144
const OCTET_MAX_VALUE = 256

type Bitmap struct {
	segments [OCTET_MAX_VALUE][BITMAP_SEGMENT_SIZE]uint64
}

var bitmap = &Bitmap{}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ip_parser.go <filename>")
		os.Exit(1)
	}

	startTime := time.Now()
	count := countUniqueIPs(os.Args[1])
	timeElapsed := time.Since(startTime)

	fmt.Println("Unique IP addresses amount: ", count)
	fmt.Println("Time elapsed: ", timeElapsed)
}

func countUniqueIPs(filename string) uint64 {
	data, closeFile := getMmapDataFromFilename(filename)
	defer closeFile()

	offsets := getChunkOffsets(data)

	var wg sync.WaitGroup

	wg.Add(WORKERS_AMOUNT)
	for i := 0; i < WORKERS_AMOUNT; i++ {
		go func(start, end int) {
			defer wg.Done()
			processChunk(data, start, end, bitmap)
		}(offsets[i], offsets[i+1])
	}
	wg.Wait()

	return countBitsParallel(bitmap)
}

func getChunkOffsets(data []byte) []int {
	offsets := make([]int, WORKERS_AMOUNT+1)
	offsets[0] = 0
	offsets[WORKERS_AMOUNT] = len(data)

	chunkSizePerWorker := (len(data) + WORKERS_AMOUNT - 1) / WORKERS_AMOUNT

	for i := 1; i < WORKERS_AMOUNT; i++ {
		proposed := i * chunkSizePerWorker
		if proposed >= len(data) {
			for k := i; k < WORKERS_AMOUNT; k++ {
				offsets[k] = len(data)
			}
			break
		}

		idx := -1

		for j := proposed; j < len(data); j++ {
			if data[j] == '\n' {
				idx = j - proposed
				break
			}
		}

		offsets[i] = proposed + idx + 1
	}

	return offsets
}

// Handling data chuck from mmap file
func processChunk(data []byte, start, end int, bitmap *Bitmap) {
	lineStart := start

	// Parsing IP inline avoiding double checking - does not improve performance
	for i := start; i < end; i++ {
		if data[i] == '\n' {
			first, rest := parseIPv4(data, lineStart, i)
			setBitLocal(bitmap, first, rest)
			lineStart = i + 1
			i += 7 // skip forward
		}
	}

	if lineStart < end {
		first, rest := parseIPv4(data, lineStart, end)
		setBitLocal(bitmap, first, rest)
	}
}

// Mark in bitmap as existing
func setBitLocal(bitmap *Bitmap, bitmapShardIndex byte, rest uint32) {
	wordIdx := rest >> 6
	bitIdx := rest & 63

	// Atomic doesn't affect performance
	atomic.OrUint64(&bitmap.segments[bitmapShardIndex][wordIdx], uint64(1)<<bitIdx)
}

func countBitsParallel(bitmap *Bitmap) uint64 {
	segmentsPerWorker := (OCTET_MAX_VALUE + WORKERS_SUM_AMOUNT - 1) / WORKERS_SUM_AMOUNT

	counts := make([]uint64, WORKERS_SUM_AMOUNT)
	var wg sync.WaitGroup

	wg.Add(WORKERS_SUM_AMOUNT)
	for w := 0; w < WORKERS_SUM_AMOUNT; w++ {
		go func(workerIndex int) {
			defer wg.Done()
			start := workerIndex * segmentsPerWorker
			end := min(start+segmentsPerWorker, OCTET_MAX_VALUE)

			localCount := uint64(0)
			for i := start; i < end; i++ {
				for j := 0; j < BITMAP_SEGMENT_SIZE; j++ {
					localCount += uint64(bits.OnesCount64(bitmap.segments[i][j]))
				}
			}
			counts[workerIndex] = localCount
		}(w)
	}
	wg.Wait()

	total := uint64(0)
	for _, c := range counts {
		total += c
	}
	return total
}

// Faster than net.IP without extra allocations
func parseIPv4(data []byte, start, end int) (firstOctet byte, restOctets uint32) {
	var currentOctet uint32

	octetIndex := 0

	for i := start; i < end; i++ {
		if data[i] == '.' {
			if octetIndex == 0 {
				firstOctet = byte(currentOctet)
			} else {
				restOctets = (restOctets << 8) | currentOctet
			}

			currentOctet = 0
			octetIndex++
			continue
		}

		currentOctet = currentOctet*10 + uint32(data[i]-'0')
	}

	restOctets = (restOctets << 8) | currentOctet
	return firstOctet, restOctets
}

func getMmapDataFromFilename(filename string) ([]byte, func()) {
	file, err := os.Open(filename)
	if err != nil {
		panic(err.Error())
	}

	fileInfo, _ := file.Stat()
	fileSize := fileInfo.Size()

	// Faster than scanner (2min) or reader( 4min ) with simple inline reading
	data, err := syscall.Mmap(int(file.Fd()), 0, int(fileSize), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		panic(err.Error())
	}

	return data, func() {
		syscall.Munmap(data)
		file.Close()
	}
}
