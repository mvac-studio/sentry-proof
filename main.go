package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var processId int

// parse arguments from CLI in main looking for -t as target executable
// if -t is not found, return an error
func main() {
	target := flag.String("t", "", "target executable")
	flag.Parse()
	if *target == "" {
		panic("No target executable specified")
	}
	fmt.Printf("Calling from PID: %d\n", os.Getpid())
	err := os.Chown(*target, os.Getuid(), os.Getgid())
	fmt.Printf("Starting %s\n", *target)

	// start the target executable and keep track of the process ID
	cmd := exec.Command(*target)
	cmd.Stdout = os.Stdout
	_ = cmd.Start()

	processId = cmd.Process.Pid
	fmt.Printf("\nStarted %s with PID %d\n", *target, processId)

	time.Sleep(500 * time.Millisecond)
	fmt.Printf("Finding sockets for process %d\n", processId)
	findSockets(processId)

	// wait for the target executable to finish
	err = cmd.Wait()
	if err != nil {
		panic(err)
	}
}

func findSockets(id int) {
	processDirectory := fmt.Sprintf("/proc/%d/fd", id)
	files, err := os.ReadDir(processDirectory)
	if err != nil {
		panic(err)
	}
	foundLine := ""

	for _, file := range files {
		link, err := os.Readlink(fmt.Sprintf("%s/%s", processDirectory, file.Name()))

		if strings.HasPrefix(link, "socket:") {

			devices, err := pcap.FindAllDevs()
			device := devices[0]
			print("listening on ", device.Name)
			handle, err := pcap.OpenLive(device.Name, int32(1024), false, 30*time.Second)
			_ = handle.SetBPFFilter("tcp and port 54321")
			source := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range source.Packets() {
				fmt.Println(packet)
			}
			path := fmt.Sprintf("%s/%s", processDirectory, file.Name())
			conn, err := net.Dial("unix", path)
			if err != nil {
				fmt.Printf("Error connecting to %s\n", path)
				continue
			}
			println(conn.LocalAddr())

			fmt.Printf("Found socket: %s\n", link)
			inodeStr := strings.Trim(link[8:], "[]")
			inode, _ := strconv.ParseUint(inodeStr, 10, 64)

			foundLine = findValue(inode, fmt.Sprintf("/proc/%d/net/tcp", id))
			if foundLine == "" {
				fmt.Printf("Socket %d not found in /proc/%d/net/tcp\nTrying /proc/%d/net/tcp6\n", inode, id, id)
				foundLine = findValue(inode, fmt.Sprintf("/proc/%d/net/tcp6", id))
			}
		}
		if err != nil {
			panic(err)
		}
	}
	if foundLine == "" {
		fmt.Printf("No sockets found for process %d\n", id)
	} else {
		fmt.Printf("Found socket %s\n", foundLine)

	}
}

func findValue(inode uint64, path string) string {
	file, _ := os.Open(path)
	scanner := bufio.NewScanner(file)
	fmt.Printf("Searching for socket %d in %s\n", inode, path)
	foundLine := ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, fmt.Sprintf("%d", inode)) {
			foundLine = line
		}
	}
	return foundLine
}
