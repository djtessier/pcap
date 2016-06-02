package main

import (
	//huh
	"bufio"
	"bytes"
	"encoding/json" // so we can ignore our non root CA on EH appliance
	"flag"
	"fmt" // for printing stuff
	"io/ioutil"
	"log"      // Output
	"net/http" // for making HTTP requests
	"os"       // for getting input from user
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/tonyHuinker/ehop"
)

var (
	count     = 0
	keyfile   = flag.String("k", "keys", "location of keyfile that contains hostname and APIKey")
	set       = make(map[string]string)
	triggerID = -1
	ehops     = make(map[string]string)
	APIKey    = "none"
	Path      = "none"
)

// cleanup attempts to delete any created trigger
func cleanup() {
	if triggerID != -1 {
		ehop.CreateEhopRequest("DELETE", "triggers/"+fmt.Sprint(float64(triggerID)), "none", APIKey, Path)
	}
}
func getKeys() {
	keyfile, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		terminatef("Could not find keys file", err.Error())
	} else if err := json.NewDecoder(bytes.NewReader(keyfile)).Decode(&ehops); err != nil {
		terminatef("Keys file is in wrong format", err.Error())
	} else {
		for key, value := range ehops {
			APIKey = "ExtraHop apikey=" + value
			Path = "https://" + key + "/api/v1/"
			ehops[key] = value
		}
	}
}

// terminate prints a fatal log message after attempting to delete any created
// trigger.
func terminate(message string) {
	cleanup()
	log.Fatal(message)
}
func terminatef(message string, v ...interface{}) {
	cleanup()
	log.Fatalf(message, v...)
}
func PrettyPrint(data interface{}) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Unable to pretty print results: %q", err.Error())
	}
	log.Printf("Results:\n%s", string(b))
}

func ConvertResponseToJSONArray(resp *http.Response) []map[string]interface{} {
	// Depending on the request, you may not need an array
	//var results = make(map[string]interface{})
	var mapp = make([]map[string]interface{}, 0)
	if err := json.NewDecoder(resp.Body).Decode(&mapp); err != nil {
		terminatef("Could not parse results: %q", err.Error())
	}
	defer resp.Body.Close()
	return mapp
}

func GetPcaps(sessionName string, finish <-chan bool) {
	ticker := time.NewTicker(time.Second * 2).C
	for {
		select {
		case <-finish:
			return
		case <-ticker:
			response, err := ehop.CreateEhopRequest("GET", "packetcaptures", "none", APIKey, Path)
			if err != nil {
				terminate(err.Error())
			}
			results := ConvertResponseToJSONArray(response)
			for _, value := range results {
				if value["name"] == sessionName && set[value["id"].(string)] == "" {
					set[value["id"].(string)] = value["ipaddr1"].(string) + " " + fmt.Sprint(float64(value["port1"].(float64))) + " --- " + value["ipaddr2"].(string) + " " + fmt.Sprint(float64(value["port2"].(float64))) + " " + value["l7proto"].(string)
					count++
					fmt.Printf("%d %s \n", count, set[value["id"].(string)])
				}
			}
		}
	}
}

// askForInput prompts the reader for a string input then thanks them for their
// cooperation. The result is stripped of leading or trailing whitespace.
func askForInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(prompt)
	response, _ := reader.ReadString('\n')
	fmt.Println("\nThank You")
	return strings.TrimSpace(response)
}

// createTrigger executes a POST request to create a trigger and returns the
// resulting triggerID. If there was an error the triggerID is set to -1
func createTrigger(script, sessionName string) int {
	ehop.CreateEhopRequest("POST", "triggers", script, APIKey, Path)
	response, err := ehop.CreateEhopRequest("GET", "triggers", "none", APIKey, Path)
	if err != nil {
		terminate(err.Error())
	}
	results := ConvertResponseToJSONArray(response)
	for _, value := range results {
		if value["name"] == sessionName {
			return int(value["id"].(float64))
		}
	}
	return -1
}

func main() {
	flag.Parse()
	getKeys()
	reader := bufio.NewReader(os.Stdin)
	sessionName := askForInput("Please enter a name to be used for this session. (Single Word Only Please)")
	fmt.Println("A -- > To capture all packets to a single IP address")
	fmt.Println("B -- > To capture all packets sent between 2 IP addresses")
	answer5, _ := reader.ReadString('\n')

	if strings.TrimSpace(answer5) == "A" {
		firstIP := askForInput("Please enter the IP address of the server you would like to do a packet capture on")
		code := `if(Flow.client.ipaddr.toString() == '` + firstIP + `' || Flow.server.ipaddr.toString() == '` + firstIP + `'){\nFlow.captureStart('` + sessionName + `');\n}`
		script := `{ "apply_all": true, "author": "GO", "debug": false, "description": "Scripted PCAP", "disabled": false, "event": "FLOW_CLASSIFY", "hints": {"packetCapture": true}, "name": "` + sessionName + `", "priority": 0, "script": "` + code + `" }`
		triggerID = createTrigger(script, sessionName)
	} else if strings.TrimSpace(answer5) == "B" {
		firstIP := askForInput("Please enter the first IP address of the server you would like to do a packet capture on")
		secondIP := ("Please enter the second IP address of the server you would like to do a packet capture on")
		code := `if(Flow.client.ipaddr.toString() == '` + firstIP + `' && Flow.server.ipaddr.toString() == '` + secondIP + `'){\nFlow.captureStart('` + sessionName + `');\n}\nif(Flow.client.ipaddr.toString() == '` + secondIP + `' && Flow.server.ipaddr.toString() == '` + firstIP + `'){\nFlow.captureStart('` + sessionName + `');\n }`
		script := `{ "apply_all": true, "author": "GO", "debug": false, "description": "Scripted PCAP", "disabled": false, "event": "FLOW_CLASSIFY", "hints": {"packetCapture": true}, "name": "` + sessionName + `", "priority": 0, "script": "` + code + `" }`
		triggerID = createTrigger(script, sessionName)
	} else {
		terminate("Need to select either A or B")
	}
	if triggerID < 0 {
		terminate("Could not create new trigger for packet captures")
	}

	fmt.Printf("Waiting a bit for captures to show up... Press 1 to Quit\n")
	finish := make(chan bool)
	go GetPcaps(sessionName, finish)
	for {
		killsignal, _ := reader.ReadString('\n')
		if strings.TrimSpace(killsignal) == "1" {
			finish <- true
			break
		}
	}
	filename := ""
	counter := 1
	os.Mkdir("."+string(filepath.Separator)+"pcap", 0777)
	for value := range set {
		filename = set[value]
		response, err := ehop.CreateEhopRequest("GET", "packetcaptures/"+value, "none", APIKey, Path)
		if err != nil {
			terminate(err.Error())
		}
		fmt.Println("Downloading... " + filename)
		filename += strconv.Itoa(counter) + ".pcap"
		counter++
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)
		ioutil.WriteFile("."+string(filepath.Separator)+"pcap"+string(filepath.Separator)+filename, buf.Bytes(), 0777)
		response.Body.Close()
	}
	fmt.Println("Download successful.... attempting to merge")
	mergecap := ""
	installed := false
	if strings.Index(runtime.GOOS, "windows") > -1 {
		if _, err := os.Stat("C:\\Program Files\\Wireshark\\mergecap.exe"); err == nil {
			mergecap = "C:\\Program Files\\Wireshark\\mergecap.exe"
			installed = true
		}
	} else {
		_, err := exec.LookPath("mergecap")
		if err != nil {
			installed = false
		} else {
			installed = true
			mergecap = "mergecap"
		}
	}
	if installed != true {
		log.Fatal("If you would like to have all the packet captures combined into a single one.. please install wireshark")
	} else {
		var out bytes.Buffer
		var stderr bytes.Buffer
		os.Chdir("pcap")
		files, _ := ioutil.ReadDir("." + string(filepath.Separator))
		bigstring := "-w,combined.pcap"
		for _, f := range files {
			if strings.Index(f.Name(), "pcap") > -1 {
				bigstring = bigstring + "," + f.Name()
			}
		}
		args := strings.SplitAfter(bigstring, ",")
		for y := range args {
			if strings.Index(args[y], ",") > -1 {
				args[y] = args[y][:len(args[y])-1]
			}
		}
		//		cmd := exec.Command("mergecap", "-w", "combined.pcap", "pcap"+string(filepath.Separator)+"*")
		cmd := exec.Command(mergecap, args...)
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		//test
		err := cmd.Run()
		if err != nil {
			terminate("Failed during merge process...")
			fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		} else {
			fmt.Println("Successfully combined pcaps")
		}
	}
	cleanup()
}
