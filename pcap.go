package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json" // so we can ignore our non root CA on EH appliance
	"fmt"           // for printing stuff
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
)

const (
	//e
	APIKey string = "ExtraHop apikey=d886220a756f4f22847d58b17e269dea"
	Path   string = "https://192.168.1.120/api/v1/"

//	ApiKey string = "ExtraHop apikey=7cc91b5554ae42afbeab2f1b1edb57a8"
//	Path   string = "https://10.6.105.231/api/v1/"
)

// PrettyPrint is an example of what can be the done with the results
var clear map[string]func() //create a map for storing clear funcs

func init() {
	clear = make(map[string]func()) //Initialize it
	clear["linux"] = func() {
		cmd := exec.Command("clear") //Linux example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	clear["darwin"] = func() {
		cmd := exec.Command("clear") //Linux example, its tested
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
	clear["windows"] = func() {
		cmd := exec.Command("cls") //Windows example it is untested, but I think its working
		cmd.Stdout = os.Stdout
		cmd.Run()
	}
}

func CallClear() {
	fmt.Println(runtime.GOOS)
	value, ok := clear[runtime.GOOS] //runtime.GOOS -> linux, windows, darwin etc.
	if ok {                          //if we defined a clear func for that platform:
		value() //we execute it
	} else { //unsupported platform
		panic("Your platform is unsupported! I can't clear terminal screen :(")
	}
}
func PrettyPrint(data interface{}) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Unable to pretty print results: %q", err.Error())
	}
	log.Printf("Results:\n%s", string(b))
}

func CreateEhopRequest(method string, call string, payload string) *http.Response {
	//Create a 'transport' object... this is necessary if we want to ignore
	//the EH insecure CA.  Similar to '--insecure' option for curl
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	//Crate a new client object... and pass him the parameters of the transport object
	//we created above

	client := http.Client{Transport: tr}
	postBody := []byte(payload)
	req, err := http.NewRequest(method, Path+call, bytes.NewBuffer(postBody))
	if err != nil {
		log.Fatalf("Failed to create HTTP request: %q", err.Error())
	}

	//Add some header stuff to make it EH friendly
	req.Header.Add("Authorization", APIKey)
	req.Header.Add("Content-Type", " application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to perform HTTP request: %q", err.Error())
	}
	//	defer resp.Body.Close()
	return resp
}
func ConvertResponseToJsonArray(resp *http.Response) []map[string]interface{} {
	// Depending on the request, you may not need an array
	//var results = make(map[string]interface{})
	var mapp = make([]map[string]interface{}, 0)
	if err := json.NewDecoder(resp.Body).Decode(&mapp); err != nil {
		log.Fatalf("Could not parse results: %q", err.Error())
	}
	defer resp.Body.Close()
	return mapp
}

func GetPcaps(answer2 string) {
	for cont == true {
		time.Sleep(2 * time.Second)
		response := CreateEhopRequest("GET", "packetcaptures", "none")
		results := ConvertResponseToJsonArray(response)
		for _, value := range results {
			if value["name"] == answer2 {
				if set[value["id"].(string)] == "" {
					set[value["id"].(string)] = value["ipaddr1"].(string) + " " + fmt.Sprint(float64(value["port1"].(float64))) + " --- " + value["ipaddr2"].(string) + " " + fmt.Sprint(float64(value["port2"].(float64))) + " " + value["l7proto"].(string)
					//fmt.Sprint(float64(triggerID))
					count = count + 1
					fmt.Printf("%d %s \n", count, set[value["id"].(string)])
				}
			}
		}
	}
}

var count = 0
var set = make(map[string]string)
var cont = true

func main() {
	triggerID := 0
	response := CreateEhopRequest("GET", "devices?search_type=any", "none")
	results := ConvertResponseToJsonArray(response)
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Please enter a name to be used for this session. (Single Word Only Please)")
	answer2, _ := reader.ReadString('\n')
	answer2 = strings.TrimSpace(answer2)
	fmt.Println("\nThank You")
	time.Sleep(2 * time.Second)
	fmt.Println("A -- > To capture all packets to a single IP address")
	fmt.Println("B -- > To capture all packets sent between 2 IP addresses")
	answer5, _ := reader.ReadString('\n')
	//script := ""

	if strings.TrimSpace(answer5) == "A" {
		fmt.Println("Please enter the IP address of the server you would like to do a packet capture on")
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(answer)
		fmt.Println("\nThank You")
		time.Sleep(2 * time.Second)
		code := `if(Flow.client.ipaddr.toString() == '` + answer + `' || Flow.server.ipaddr.toString() == '` + answer + `'){\nFlow.captureStart('` + answer2 + `');\n}`
		var script string = `{ "apply_all": true, "author": "GO", "debug": false, "description": "Scripted PCAP", "disabled": false, "event": "FLOW_CLASSIFY", "hints": {"packetCapture": true}, "name": "` + answer2 + `", "priority": 0, "script": "` + code + `" }`
		response = CreateEhopRequest("POST", "triggers", script)
		response = CreateEhopRequest("GET", "triggers", "none")
		results = ConvertResponseToJsonArray(response)
		for _, value := range results {
			if value["name"] == answer2 {
				triggerID = int(value["id"].(float64))
			}
		}
	} else if strings.TrimSpace(answer5) == "B" {
		fmt.Println("Please enter the first IP address of the server you would like to do a packet capture on")
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(answer)
		fmt.Println("\nThank You")
		time.Sleep(2 * time.Second)
		fmt.Println("Please enter the second IP address of the server you would like to do a packet capture on")
		answer6, _ := reader.ReadString('\n')
		answer6 = strings.TrimSpace(answer6)
		fmt.Println("\nThank You")
		time.Sleep(2 * time.Second)
		code := `if(Flow.client.ipaddr.toString() == '` + answer + `' && Flow.server.ipaddr.toString() == '` + answer6 + `'){\nFlow.captureStart('` + answer2 + `');\n}\nif(Flow.client.ipaddr.toString() == '` + answer6 + `' && Flow.server.ipaddr.toString() == '` + answer + `'){\nFlow.captureStart('` + answer2 + `');\n }`
		var script string = `{ "apply_all": true, "author": "GO", "debug": false, "description": "Scripted PCAP", "disabled": false, "event": "FLOW_CLASSIFY", "hints": {"packetCapture": true}, "name": "` + answer2 + `", "priority": 0, "script": "` + code + `" }`
		response = CreateEhopRequest("POST", "triggers", script)
		response = CreateEhopRequest("GET", "triggers", "none")
		results = ConvertResponseToJsonArray(response)
		for _, value := range results {
			if value["name"] == answer2 {
				triggerID = int(value["id"].(float64))
			}
		}

	} else {

		fmt.Println("Need to select either A or B")
	}
	fmt.Printf("Waiting a bit for captures to show up... Press 1 to Quit\n")
	go GetPcaps(answer2)
	answer3, _ := reader.ReadString('\n')
	answer3 = strings.TrimSpace(answer3)
	if answer3 == "1" {
		cont = false
	}
	filename := ""
	counter := 1
	os.Mkdir("."+string(filepath.Separator)+"pcap", 0777)
	for value, _ := range set {
		filename = set[value]
		//		fmt.Println("Downloading " + filename)
		response = CreateEhopRequest("GET", "packetcaptures/"+value, "none")
		filename = filename + strconv.Itoa(counter) + ".pcap"
		counter = counter + 1
		buf := new(bytes.Buffer)
		buf.ReadFrom(response.Body)
		//file, _ := os.OpenFile("."+string(filepath.Separator)+"pcap"+string(filepath.Separator)+filename, os.O_CREATE, 0777)
		//bufferedWriter := bufio.NewWriter(file)
		//bufferedWriter.Write(buf.Bytes())
		//bufferedWriter.Flush()
		//file.Close()
		ioutil.WriteFile("."+string(filepath.Separator)+"pcap"+string(filepath.Separator)+filename, buf.Bytes(), 0777)
		defer response.Body.Close()
	}
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
				fmt.Println(args[y])
			}
		}
		//		cmd := exec.Command("mergecap", "-w", "combined.pcap", "pcap"+string(filepath.Separator)+"*")
		cmd := exec.Command(mergecap, args...)
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		//test
		err := cmd.Run()
		if err != nil {
			fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
		} else {
			fmt.Println("Successfully combined pcaps")
		}
	}
	response = CreateEhopRequest("DELETE", "triggers/"+fmt.Sprint(float64(triggerID)), "none")
}
