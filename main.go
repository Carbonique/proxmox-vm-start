package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	proxmoxAPIURL string
	proxmoxUser   string
	proxmoxPass   string
	proxmoxNode   string
	vmID          string
	client        *http.Client
	ticket        string
	csrfToken     string
)

func init() {
	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}
}

func loadEnvVariables() error {
	proxmoxAPIURL = os.Getenv("PROXMOX_API_URL")
	proxmoxUser = os.Getenv("PROXMOX_USER")
	proxmoxPass = os.Getenv("PROXMOX_PASS")
	proxmoxNode = os.Getenv("PROXMOX_NODE")
	vmID = os.Getenv("VM_ID")

	if proxmoxAPIURL == "" || proxmoxUser == "" || proxmoxPass == "" || proxmoxNode == "" || vmID == "" {
		return fmt.Errorf("one or more required environment variables are unset")
	}
	return nil
}

func authenticate() error {
	url := fmt.Sprintf("%s/access/ticket", proxmoxAPIURL)
	data := fmt.Sprintf(`username=%s&password=%s`, proxmoxUser, proxmoxPass)
	req, err := http.NewRequest("POST", url, strings.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return err
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		ticket = data["ticket"].(string)
		csrfToken = data["CSRFPreventionToken"].(string)
	} else {
		return fmt.Errorf("failed to get ticket and CSRF token")
	}
	return nil
}

func getVMStatus(vmid string) (string, error) {
	url := fmt.Sprintf("%s/nodes/%s/qemu/%s/status/current", proxmoxAPIURL, proxmoxNode, vmid)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Cookie", "PVEAuthCookie="+ticket)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", err
	}

	if data, ok := result["data"].(map[string]interface{}); ok {
		return data["status"].(string), nil
	}
	return "", fmt.Errorf("failed to get VM status")
}

func startVM(vmid string) error {
	url := fmt.Sprintf("%s/nodes/%s/qemu/%s/status/start", proxmoxAPIURL, proxmoxNode, vmid)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", "PVEAuthCookie="+ticket)
	req.Header.Set("CSRFPreventionToken", csrfToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to start VM, response: %s", body)
	}
	return nil
}

func stopVM(vmid string) error {
	url := fmt.Sprintf("%s/nodes/%s/qemu/%s/status/stop", proxmoxAPIURL, proxmoxNode, vmid)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", "PVEAuthCookie="+ticket)
	req.Header.Set("CSRFPreventionToken", csrfToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to stop VM, response: %s", body)
	}
	return nil
}

func startVMHandler(w http.ResponseWriter, r *http.Request) {
	if ticket == "" || csrfToken == "" {
		if err := authenticate(); err != nil {
			http.Error(w, "Authentication failed", http.StatusInternalServerError)
			return
		}
	}

	status, err := getVMStatus(vmID)
	if err != nil {
		http.Error(w, "Failed to get VM status", http.StatusInternalServerError)
		return
	}

	if status == "running" {
		fmt.Fprintln(w, "VM is already running")
	} else {
		if err := startVM(vmID); err != nil {
			http.Error(w, "Failed to start VM", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "VM is starting")
	}
}

func stopVMHandler(w http.ResponseWriter, r *http.Request) {
	if ticket == "" || csrfToken == "" {
		if err := authenticate(); err != nil {
			http.Error(w, "Authentication failed", http.StatusInternalServerError)
			return
		}
	}

	status, err := getVMStatus(vmID)
	if err != nil {
		http.Error(w, "Failed to get VM status", http.StatusInternalServerError)
		return
	}

	if status == "stopped" {
		fmt.Fprintln(w, "VM is already stopped")
	} else {
		if err := stopVM(vmID); err != nil {
			http.Error(w, "Failed to stop VM", http.StatusInternalServerError)
			return
		}
		fmt.Fprintln(w, "VM is stopping")
	}
}

func main() {
	if err := loadEnvVariables(); err != nil {
		log.Fatalf("Error loading environment variables: %v", err)
	}

	http.HandleFunc("/start-vm", startVMHandler)
	http.HandleFunc("/stop-vm", stopVMHandler)
	log.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
