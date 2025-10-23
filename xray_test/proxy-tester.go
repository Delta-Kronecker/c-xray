package main

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ============================================================================
// TYPES & CONSTANTS
// ============================================================================

type TestResult string

const (
	ResultSuccess             TestResult = "success"
	ResultParseError          TestResult = "parse_error"
	ResultSyntaxError         TestResult = "syntax_error"
	ResultConnectionError     TestResult = "connection_error"
	ResultTimeout             TestResult = "timeout"
	ResultPortConflict        TestResult = "port_conflict"
	ResultInvalidConfig       TestResult = "invalid_config"
	ResultNetworkError        TestResult = "network_error"
	ResultUnsupportedProtocol TestResult = "unsupported_protocol"
)

type ProxyProtocol string

const (
	ProtocolShadowsocks  ProxyProtocol = "shadowsocks"
	ProtocolShadowsocksR ProxyProtocol = "shadowsocksr"
	ProtocolVMess        ProxyProtocol = "vmess"
	ProtocolVLESS        ProxyProtocol = "vless"
	ProtocolTrojan       ProxyProtocol = "trojan"
	ProtocolHysteria     ProxyProtocol = "hysteria"
	ProtocolHysteria2    ProxyProtocol = "hysteria2"
	ProtocolTUIC         ProxyProtocol = "tuic"
)

var AllProtocols = []ProxyProtocol{
	ProtocolShadowsocks, ProtocolShadowsocksR, ProtocolVMess, ProtocolVLESS,
	ProtocolTrojan, ProtocolHysteria, ProtocolHysteria2, ProtocolTUIC,
}

// ============================================================================
// CONFIG MANAGEMENT
// ============================================================================

type Config struct {
	SingboxPath     string
	MaxWorkers      int
	Timeout         time.Duration
	BatchSize       int
	IncrementalSave bool
	DataDir         string
	ConfigDir       string
	LogDir          string
	StartPort       int
	EndPort         int
}

func NewDefaultConfig() *Config {
	return &Config{
		SingboxPath:     getEnvOrDefault("SINGBOX_PATH", ""),
		MaxWorkers:      getEnvIntOrDefault("PROXY_MAX_WORKERS", 500),
		Timeout:         time.Duration(getEnvIntOrDefault("PROXY_TIMEOUT", 10)) * time.Second,
		BatchSize:       getEnvIntOrDefault("PROXY_BATCH_SIZE", 500),
		IncrementalSave: getEnvBoolOrDefault("PROXY_INCREMENTAL_SAVE", true),
		DataDir:         getEnvOrDefault("PROXY_DATA_DIR", "../data"),
		ConfigDir:       getEnvOrDefault("PROXY_CONFIG_DIR", "../data/Config"),
		LogDir:          getEnvOrDefault("PROXY_LOG_DIR", "../log"),
		StartPort:       getEnvIntOrDefault("PROXY_START_PORT", 10000),
		EndPort:         getEnvIntOrDefault("PROXY_END_PORT", 20000),
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

// ============================================================================
// PROXY CONFIG
// ============================================================================

type ProxyConfig struct {
	Protocol ProxyProtocol `json:"protocol"`
	Server   string        `json:"server"`
	Port     int           `json:"port"`
	Remarks  string        `json:"remarks"`

	// Common fields
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	AlterID  int    `json:"alterId,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
	Flow     string `json:"flow,omitempty"`
	Encrypt  string `json:"encryption,omitempty"`

	// Transport fields
	Network     string `json:"network,omitempty"`
	TLS         string `json:"tls,omitempty"`
	SNI         string `json:"sni,omitempty"`
	Path        string `json:"path,omitempty"`
	Host        string `json:"host,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	HeaderType  string `json:"headerType,omitempty"`
	ServiceName string `json:"serviceName,omitempty"`

	// SSR fields
	Protocol_Param string `json:"protocol_param,omitempty"`
	Obfs           string `json:"obfs,omitempty"`
	ObfsParam      string `json:"obfs_param,omitempty"`

	// Hysteria/TUIC fields
	UpMbps         int    `json:"up_mbps,omitempty"`
	DownMbps       int    `json:"down_mbps,omitempty"`
	AuthStr        string `json:"auth_str,omitempty"`
	Insecure       bool   `json:"insecure,omitempty"`
	CongestionCtrl string `json:"congestion_control,omitempty"`
}

func (pc *ProxyConfig) IsValid() bool {
	if pc.Server == "" || pc.Port <= 0 || pc.Port > 65535 {
		return false
	}

	switch pc.Protocol {
	case ProtocolShadowsocks, ProtocolShadowsocksR:
		return pc.Method != "" && pc.Password != ""
	case ProtocolVMess, ProtocolVLESS:
		return isValidUUID(pc.UUID)
	case ProtocolTrojan:
		return pc.Password != ""
	case ProtocolHysteria:
		return pc.AuthStr != ""
	case ProtocolHysteria2:
		return pc.Password != ""
	case ProtocolTUIC:
		return pc.UUID != "" && pc.Password != ""
	}
	return false
}

func (pc *ProxyConfig) Hash() string {
	var hashStr string
	switch pc.Protocol {
	case ProtocolShadowsocks:
		hashStr = fmt.Sprintf("ss://%s:%d:%s:%s", pc.Server, pc.Port, pc.Method, pc.Password)
	case ProtocolShadowsocksR:
		hashStr = fmt.Sprintf("ssr://%s:%d:%s:%s:%s:%s", pc.Server, pc.Port, pc.Method, pc.Password, pc.Protocol_Param, pc.Obfs)
	case ProtocolVMess:
		hashStr = fmt.Sprintf("vmess://%s:%d:%s:%d:%s", pc.Server, pc.Port, pc.UUID, pc.AlterID, pc.Network)
	case ProtocolVLESS:
		hashStr = fmt.Sprintf("vless://%s:%d:%s:%s", pc.Server, pc.Port, pc.UUID, pc.Network)
	case ProtocolTrojan:
		hashStr = fmt.Sprintf("trojan://%s:%d:%s:%s", pc.Server, pc.Port, pc.Password, pc.Network)
	case ProtocolHysteria:
		hashStr = fmt.Sprintf("hysteria://%s:%d:%s", pc.Server, pc.Port, pc.AuthStr)
	case ProtocolHysteria2:
		hashStr = fmt.Sprintf("hysteria2://%s:%d:%s", pc.Server, pc.Port, pc.Password)
	case ProtocolTUIC:
		hashStr = fmt.Sprintf("tuic://%s:%d:%s:%s", pc.Server, pc.Port, pc.UUID, pc.Password)
	}
	hash := md5.Sum([]byte(hashStr))
	return fmt.Sprintf("%x", hash)
}

func isValidUUID(uuid string) bool {
	re := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return re.MatchString(uuid)
}

// ============================================================================
// TEST RESULT
// ============================================================================

type TestResultData struct {
	Config       ProxyConfig `json:"config"`
	Result       TestResult  `json:"result"`
	TestTime     float64     `json:"test_time"`
	ResponseTime *float64    `json:"response_time,omitempty"`
	ErrorMessage string      `json:"error_message,omitempty"`
	ExternalIP   string      `json:"external_ip,omitempty"`
	ProxyPort    *int        `json:"proxy_port,omitempty"`
	BatchID      *int        `json:"batch_id,omitempty"`
}

// ============================================================================
// PORT MANAGER
// ============================================================================

type PortManager struct {
	startPort      int
	endPort        int
	availablePorts chan int
	usedPorts      sync.Map
	mu             sync.Mutex
	initialized    int32
}

func NewPortManager(startPort, endPort int) *PortManager {
	pm := &PortManager{
		startPort:      startPort,
		endPort:        endPort,
		availablePorts: make(chan int, endPort-startPort+1),
	}
	pm.initialize()
	return pm
}

func (pm *PortManager) initialize() {
	if !atomic.CompareAndSwapInt32(&pm.initialized, 0, 1) {
		return
	}

	log.Printf("Initializing port pool (%d-%d)...", pm.startPort, pm.endPort)
	count := 0
	for port := pm.startPort; port <= pm.endPort; port++ {
		if pm.isAvailable(port) {
			select {
			case pm.availablePorts <- port:
				count++
			default:
			}
		}
	}
	log.Printf("Port pool initialized with %d available ports", count)
}

func (pm *PortManager) isAvailable(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
	if err != nil {
		return true
	}
	conn.Close()
	return false
}

func (pm *PortManager) Get() (int, bool) {
	select {
	case port := <-pm.availablePorts:
		pm.usedPorts.Store(port, time.Now())
		return port, true
	case <-time.After(100 * time.Millisecond):
		return pm.findEmergency(), true
	}
}

func (pm *PortManager) findEmergency() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := 0; i < 100; i++ {
		port := rand.Intn(pm.endPort-pm.startPort+1) + pm.startPort
		if _, used := pm.usedPorts.Load(port); !used && pm.isAvailable(port) {
			pm.usedPorts.Store(port, time.Now())
			return port
		}
	}
	return 0
}

func (pm *PortManager) Release(port int) {
	pm.usedPorts.Delete(port)
	go func() {
		time.Sleep(50 * time.Millisecond)
		select {
		case pm.availablePorts <- port:
		default:
		}
	}()
}

func (pm *PortManager) Cleanup() {
	pm.usedPorts.Range(func(key, value interface{}) bool {
		pm.usedPorts.Delete(key)
		return true
	})
}

// ============================================================================
// PROCESS MANAGER
// ============================================================================

type ProcessManager struct {
	processes sync.Map
	mu        sync.Mutex
}

func NewProcessManager() *ProcessManager {
	return &ProcessManager{}
}

func (pm *ProcessManager) Register(pid int, cmd *exec.Cmd) {
	pm.processes.Store(pid, cmd)
}

func (pm *ProcessManager) Unregister(pid int) {
	pm.processes.Delete(pid)
}

func (pm *ProcessManager) Kill(pid int) error {
	if value, ok := pm.processes.Load(pid); ok {
		if cmd, ok := value.(*exec.Cmd); ok && cmd.Process != nil {
			cmd.Process.Kill()
			pm.Unregister(pid)
			return nil
		}
	}
	return fmt.Errorf("process not found")
}

func (pm *ProcessManager) Count() int {
	count := 0
	pm.processes.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

func (pm *ProcessManager) KillAll() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	var cmds []*exec.Cmd
	pm.processes.Range(func(key, value interface{}) bool {
		if cmd, ok := value.(*exec.Cmd); ok && cmd.Process != nil {
			cmds = append(cmds, cmd)
		}
		pm.processes.Delete(key)
		return true
	})

	for _, cmd := range cmds {
		cmd.Process.Kill()
		go cmd.Wait()
	}

	return len(cmds)
}

// ============================================================================
// NETWORK TESTER
// ============================================================================

type NetworkTester struct {
	timeout  time.Duration
	testURLs []string
	client   *http.Client
}

func NewNetworkTester(timeout time.Duration) *NetworkTester {
	return &NetworkTester{
		timeout: timeout,
		testURLs: []string{
			"http://httpbin.org/ip",
			"http://icanhazip.com",
			"http://ifconfig.me/ip",
			"http://api.ipify.org",
			"http://ipinfo.io/ip",
			"http://checkip.amazonaws.com",
			"https://httpbin.org/ip",
			"https://icanhazip.com",
		},
		client: &http.Client{Timeout: timeout},
	}
}

func (nt *NetworkTester) Test(proxyPort int) (bool, string, float64) {
	startTime := time.Now()

	if !nt.isResponsive(proxyPort) {
		return false, "", time.Since(startTime).Seconds()
	}

	testCount := 4
	if len(nt.testURLs) < testCount {
		testCount = len(nt.testURLs)
	}

	shuffled := make([]string, len(nt.testURLs))
	copy(shuffled, nt.testURLs)
	rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})

	for i := 0; i < testCount; i++ {
		if success, ip, responseTime := nt.singleTest(proxyPort, shuffled[i]); success {
			return true, ip, responseTime
		}
	}

	return false, "", time.Since(startTime).Seconds()
}

func (nt *NetworkTester) isResponsive(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (nt *NetworkTester) singleTest(proxyPort int, testURL string) (bool, string, float64) {
	startTime := time.Now()

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), nil, proxy.Direct)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}

	transport := &http.Transport{
		Dial:                dialer.Dial,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		IdleConnTimeout:     time.Second,
	}

	client := &http.Client{Transport: transport, Timeout: nt.timeout}
	resp, err := client.Get(testURL)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, "", time.Since(startTime).Seconds()
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", time.Since(startTime).Seconds()
	}

	responseTime := time.Since(startTime).Seconds()
	ipText := strings.TrimSpace(string(body))

	if strings.Contains(resp.Header.Get("Content-Type"), "json") {
		var data map[string]interface{}
		if json.Unmarshal(body, &data) == nil {
			if origin, ok := data["origin"].(string); ok {
				ipText = origin
			} else if ip, ok := data["ip"].(string); ok {
				ipText = ip
			}
		}
	}

	if net.ParseIP(ipText) != nil {
		return true, ipText, responseTime
	}

	return false, "", responseTime
}

// ============================================================================
// SINGBOX CONFIG GENERATOR
// ============================================================================

type SingboxConfigGenerator struct {
	singboxPath string
}

func NewSingboxConfigGenerator(path string) *SingboxConfigGenerator {
	if path == "" {
		path = findSingboxExecutable()
	}
	return &SingboxConfigGenerator{singboxPath: path}
}

func findSingboxExecutable() string {
	paths := []string{"sing-box", "./sing-box", "/usr/local/bin/sing-box", "/usr/bin/sing-box"}
	for _, path := range paths {
		if _, err := exec.LookPath(path); err == nil {
			return path
		}
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return "sing-box"
}

func (scg *SingboxConfigGenerator) Validate() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, scg.singboxPath, "version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("sing-box validation failed: %w", err)
	}

	log.Printf("Sing-box version: %s", strings.TrimSpace(string(output)))
	return nil
}

func (scg *SingboxConfigGenerator) Generate(config *ProxyConfig, listenPort int) (map[string]interface{}, error) {
	singboxConfig := map[string]interface{}{
		"log": map[string]interface{}{"level": "error"},
		"inbounds": []map[string]interface{}{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": listenPort,
			},
		},
	}

	outbound, err := scg.generateOutbound(config)
	if err != nil {
		return nil, err
	}

	singboxConfig["outbounds"] = []map[string]interface{}{outbound}
	return singboxConfig, nil
}

func (scg *SingboxConfigGenerator) generateOutbound(config *ProxyConfig) (map[string]interface{}, error) {
	var outbound map[string]interface{}

	switch config.Protocol {
	case ProtocolShadowsocks:
		outbound = scg.generateShadowsocks(config)
	case ProtocolShadowsocksR:
		return nil, fmt.Errorf("shadowsocksr not supported by sing-box")
	case ProtocolVMess:
		outbound = scg.generateVMess(config)
	case ProtocolVLESS:
		outbound = scg.generateVLESS(config)
	case ProtocolTrojan:
		outbound = scg.generateTrojan(config)
	case ProtocolHysteria2:
		outbound = scg.generateHysteria2(config)
	case ProtocolTUIC:
		outbound = scg.generateTUIC(config)
	case ProtocolHysteria:
		return nil, fmt.Errorf("hysteria not supported (use hysteria2)")
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", config.Protocol)
	}

	scg.addTransport(outbound, config)
	scg.addTLS(outbound, config)

	return outbound, nil
}

func (scg *SingboxConfigGenerator) generateShadowsocks(config *ProxyConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         "proxy",
		"server":      config.Server,
		"server_port": config.Port,
		"method":      config.Method,
		"password":    config.Password,
	}
}

func (scg *SingboxConfigGenerator) generateVMess(config *ProxyConfig) map[string]interface{} {
	security := config.Cipher
	if security == "" {
		security = "auto"
	}
	return map[string]interface{}{
		"type":        "vmess",
		"tag":         "proxy",
		"server":      config.Server,
		"server_port": config.Port,
		"uuid":        config.UUID,
		"alter_id":    config.AlterID,
		"security":    security,
	}
}

func (scg *SingboxConfigGenerator) generateVLESS(config *ProxyConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"type":        "vless",
		"tag":         "proxy",
		"server":      config.Server,
		"server_port": config.Port,
		"uuid":        config.UUID,
	}
	if config.Flow != "" {
		outbound["flow"] = config.Flow
	}
	return outbound
}

func (scg *SingboxConfigGenerator) generateTrojan(config *ProxyConfig) map[string]interface{} {
	return map[string]interface{}{
		"type":        "trojan",
		"tag":         "proxy",
		"server":      config.Server,
		"server_port": config.Port,
		"password":    config.Password,
	}
}

func (scg *SingboxConfigGenerator) generateHysteria2(config *ProxyConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         "proxy",
		"server":      config.Server,
		"server_port": config.Port,
		"password":    config.Password,
	}
	if config.Obfs != "" {
		outbound["obfs"] = map[string]interface{}{
			"type":     config.Obfs,
			"password": config.Password,
		}
	}
	return outbound
}

func (scg *SingboxConfigGenerator) generateTUIC(config *ProxyConfig) map[string]interface{} {
	outbound := map[string]interface{}{
		"type":        "tuic",
		"tag":         "proxy",
		"server":      config.Server,
		"server_port": config.Port,
		"uuid":        config.UUID,
		"password":    config.Password,
	}
	if config.CongestionCtrl != "" {
		outbound["congestion_control"] = config.CongestionCtrl
	}
	return outbound
}

func (scg *SingboxConfigGenerator) addTransport(outbound map[string]interface{}, config *ProxyConfig) {
	if config.Network == "" || config.Network == "tcp" {
		return
	}

	transport := map[string]interface{}{"type": config.Network}

	switch config.Network {
	case "ws":
		if config.Path != "" {
			transport["path"] = config.Path
		}
		if config.Host != "" {
			transport["headers"] = map[string]interface{}{"Host": config.Host}
		}
	case "h2", "http":
		if config.Path != "" {
			transport["path"] = config.Path
		}
		if config.Host != "" {
			transport["host"] = []string{config.Host}
		}
	case "grpc":
		if config.ServiceName != "" {
			transport["service_name"] = config.ServiceName
		}
	}

	outbound["transport"] = transport
}

func (scg *SingboxConfigGenerator) addTLS(outbound map[string]interface{}, config *ProxyConfig) {
	if config.TLS == "" || (config.Protocol != ProtocolVMess && config.Protocol != ProtocolVLESS && config.Protocol != ProtocolTrojan) {
		return
	}

	tlsConfig := map[string]interface{}{
		"enabled":  true,
		"insecure": true,
	}

	if config.SNI != "" {
		tlsConfig["server_name"] = config.SNI
	} else if config.Host != "" {
		tlsConfig["server_name"] = config.Host
	}

	if config.ALPN != "" {
		tlsConfig["alpn"] = strings.Split(config.ALPN, ",")
	}

	if config.Fingerprint != "" {
		tlsConfig["utls"] = map[string]interface{}{
			"enabled":     true,
			"fingerprint": config.Fingerprint,
		}
	}

	if config.TLS == "reality" {
		tlsConfig["reality"] = map[string]interface{}{"enabled": true}
	}

	outbound["tls"] = tlsConfig
}

func (scg *SingboxConfigGenerator) CheckSyntax(configFile string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, scg.singboxPath, "check", "-c", configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("syntax check failed: %s", string(output))
	}
	return nil
}

func (scg *SingboxConfigGenerator) Start(configFile string) (*exec.Cmd, error) {
	cmd := exec.Command(scg.singboxPath, "run", "-c", configFile)
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// ============================================================================
// CONFIG LOADER
// ============================================================================

type ConfigLoader struct {
	seenHashes map[string]bool
	mu         sync.Mutex
}

func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{seenHashes: make(map[string]bool)}
}

func (cl *ConfigLoader) LoadFromDirectory(dirPath string) ([]ProxyConfig, error) {
	files, err := filepath.Glob(filepath.Join(dirPath, "*.json"))
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		return nil, fmt.Errorf("no JSON files found in: %s", dirPath)
	}

	log.Printf("Found %d JSON files in: %s", len(files), dirPath)

	var allConfigs []ProxyConfig
	for _, filePath := range files {
		config, err := cl.loadCollectorJSON(filePath)
		if err != nil {
			log.Printf("Warning: Failed to load %s: %v", filepath.Base(filePath), err)
			continue
		}
		if config != nil {
			allConfigs = append(allConfigs, *config)
		}
	}

	log.Printf("Loaded %d configurations from %d files", len(allConfigs), len(files))
	return allConfigs, nil
}

func (cl *ConfigLoader) loadCollectorJSON(filePath string) (*ProxyConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rawConfig map[string]interface{}
	if err := json.NewDecoder(file).Decode(&rawConfig); err != nil {
		return nil, err
	}

	configType, ok := rawConfig["type"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid 'type' field")
	}

	config := ProxyConfig{
		Remarks: getString(rawConfig, "name"),
		Server:  getString(rawConfig, "server"),
		Port:    getInt(rawConfig, "port"),
	}

	switch configType {
	case "vmess":
		config.Protocol = ProtocolVMess
		config.UUID = getString(rawConfig, "uuid")
		config.AlterID = getInt(rawConfig, "alterId")
		config.Cipher = getString(rawConfig, "cipher")
		config.Network = getStringOrDefault(rawConfig, "network", "tcp")
		config.TLS = getString(rawConfig, "tls")
		config.SNI = getString(rawConfig, "sni")
		config.Host = getString(rawConfig, "host")
		config.Path = getString(rawConfig, "path")

	case "vless":
		config.Protocol = ProtocolVLESS
		config.UUID = getString(rawConfig, "password")
		config.Flow = getString(rawConfig, "flow")
		config.Network = getStringOrDefault(rawConfig, "network", "tcp")
		config.TLS = getString(rawConfig, "security")
		config.SNI = getString(rawConfig, "sni")
		config.Host = getString(rawConfig, "host")
		config.Path = getString(rawConfig, "path")
		config.Encrypt = "none"

	case "trojan":
		config.Protocol = ProtocolTrojan
		config.Password = getString(rawConfig, "password")
		config.Network = getStringOrDefault(rawConfig, "network", "tcp")
		config.TLS = getStringOrDefault(rawConfig, "security", "tls")
		config.SNI = getString(rawConfig, "sni")
		config.Host = getString(rawConfig, "host")
		config.Path = getString(rawConfig, "path")

	case "shadowsocks", "ss":
		config.Protocol = ProtocolShadowsocks
		config.Method = getString(rawConfig, "method")
		config.Password = getString(rawConfig, "password")
		config.Network = "tcp"

	default:
		return nil, fmt.Errorf("unsupported protocol: %s", configType)
	}

	if !config.IsValid() {
		return nil, fmt.Errorf("invalid config")
	}

	return &config, nil
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getStringOrDefault(data map[string]interface{}, key, defaultValue string) string {
	if str := getString(data, key); str != "" {
		return str
	}
	return defaultValue
}

func getInt(data map[string]interface{}, key string) int {
	if val, ok := data[key]; ok {
		switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			if intVal, err := strconv.Atoi(v); err == nil {
				return intVal
			}
		}
	}
	return 0
}

// ============================================================================
// STATISTICS MANAGER
// ============================================================================

type StatisticsManager struct {
	stats sync.Map
}

func NewStatisticsManager() *StatisticsManager {
	sm := &StatisticsManager{}
	sm.initialize()
	return sm
}

func (sm *StatisticsManager) initialize() {
	for _, protocol := range AllProtocols {
		sm.stats.Store(protocol, map[string]*int64{
			"total":   new(int64),
			"success": new(int64),
			"failed":  new(int64),
		})
	}
	sm.stats.Store("overall", map[string]*int64{
		"total":             new(int64),
		"success":           new(int64),
		"failed":            new(int64),
		"parse_errors":      new(int64),
		"syntax_errors":     new(int64),
		"connection_errors": new(int64),
		"timeouts":          new(int64),
		"network_errors":    new(int64),
	})
}

func (sm *StatisticsManager) Update(result *TestResultData) {
	if protocolStats, ok := sm.stats.Load(result.Config.Protocol); ok {
		stats := protocolStats.(map[string]*int64)
		atomic.AddInt64(stats["total"], 1)
		if result.Result == ResultSuccess {
			atomic.AddInt64(stats["success"], 1)
		} else {
			atomic.AddInt64(stats["failed"], 1)
		}
	}

	if overallStats, ok := sm.stats.Load("overall"); ok {
		stats := overallStats.(map[string]*int64)
		atomic.AddInt64(stats["total"], 1)

		switch result.Result {
		case ResultSuccess:
			atomic.AddInt64(stats["success"], 1)
		case ResultParseError:
			atomic.AddInt64(stats["parse_errors"], 1)
			atomic.AddInt64(stats["failed"], 1)
		case ResultSyntaxError:
			atomic.AddInt64(stats["syntax_errors"], 1)
			atomic.AddInt64(stats["failed"], 1)
		case ResultConnectionError:
			atomic.AddInt64(stats["connection_errors"], 1)
			atomic.AddInt64(stats["failed"], 1)
		case ResultTimeout:
			atomic.AddInt64(stats["timeouts"], 1)
			atomic.AddInt64(stats["failed"], 1)
		case ResultNetworkError:
			atomic.AddInt64(stats["network_errors"], 1)
			atomic.AddInt64(stats["failed"], 1)
		default:
			atomic.AddInt64(stats["failed"], 1)
		}
	}
}

func (sm *StatisticsManager) PrintSummary(results []*TestResultData) {
	successCount := 0
	totalCount := len(results)
	var successTimes []float64

	for _, result := range results {
		if result.Result == ResultSuccess {
			successCount++
			if result.ResponseTime != nil {
				successTimes = append(successTimes, *result.ResponseTime)
			}
		}
	}

	log.Println("=" + strings.Repeat("=", 59))
	log.Println("FINAL TESTING SUMMARY")
	log.Println("=" + strings.Repeat("=", 59))
	log.Printf("Total configurations tested: %d", totalCount)
	log.Printf("Successful connections: %d", successCount)
	log.Printf("Failed connections: %d", totalCount-successCount)
	if totalCount > 0 {
		log.Printf("Success rate: %.2f%%", float64(successCount)/float64(totalCount)*100)
	}

	log.Println("\nProtocol Breakdown:")
	for _, protocol := range AllProtocols {
		if statsValue, ok := sm.stats.Load(protocol); ok {
			stats := statsValue.(map[string]*int64)
			total := atomic.LoadInt64(stats["total"])
			success := atomic.LoadInt64(stats["success"])
			if total > 0 {
				log.Printf("  %-12s: %4d/%4d (%.1f%%)",
					strings.ToUpper(string(protocol)), success, total,
					float64(success)/float64(total)*100)
			}
		}
	}

	if len(successTimes) > 0 {
		var sum, min, max float64
		min, max = successTimes[0], successTimes[0]

		for _, t := range successTimes {
			sum += t
			if t < min {
				min = t
			}
			if t > max {
				max = t
			}
		}

		log.Println("\nResponse Times (successful only):")
		log.Printf("  Average: %.3fs", sum/float64(len(successTimes)))
		log.Printf("  Minimum: %.3fs", min)
		log.Printf("  Maximum: %.3fs", max)
	}

	log.Println("=" + strings.Repeat("=", 59))
}

// ============================================================================
// FILE MANAGER
// ============================================================================

type FileManager struct {
	config          *Config
	outputFiles     map[ProxyProtocol]*os.File
	urlFiles        map[ProxyProtocol]*os.File
	generalJSONFile *os.File
	generalURLFile  *os.File
	mu              sync.Mutex
}

func NewFileManager(config *Config) (*FileManager, error) {
	fm := &FileManager{
		config:      config,
		outputFiles: make(map[ProxyProtocol]*os.File),
		urlFiles:    make(map[ProxyProtocol]*os.File),
	}

	if config.IncrementalSave {
		if err := fm.initialize(); err != nil {
			log.Printf("Warning: Failed to setup incremental save: %v", err)
			config.IncrementalSave = false
		}
	}

	return fm, nil
}

func (fm *FileManager) initialize() error {
	if err := os.MkdirAll(filepath.Join(fm.config.DataDir, "working_json"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(fm.config.DataDir, "working_url"), 0755); err != nil {
		return err
	}

	protocols := map[ProxyProtocol]string{
		ProtocolShadowsocks:  "shadowsocks",
		ProtocolShadowsocksR: "shadowsocksr",
		ProtocolVMess:        "vmess",
		ProtocolVLESS:        "vless",
		ProtocolTrojan:       "trojan",
		ProtocolHysteria:     "hysteria",
		ProtocolHysteria2:    "hysteria2",
		ProtocolTUIC:         "tuic",
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	for protocol, name := range protocols {
		jsonFile, err := os.Create(filepath.Join(fm.config.DataDir, "working_json", fmt.Sprintf("working_%s.txt", name)))
		if err != nil {
			return err
		}
		jsonFile.WriteString(fmt.Sprintf("# Working %s Configurations (JSON Format)\n", strings.ToUpper(name)))
		jsonFile.WriteString(fmt.Sprintf("# Generated at: %s\n\n", timestamp))
		fm.outputFiles[protocol] = jsonFile

		urlFile, err := os.Create(filepath.Join(fm.config.DataDir, "working_url", fmt.Sprintf("working_%s_urls.txt", name)))
		if err != nil {
			return err
		}
		urlFile.WriteString(fmt.Sprintf("# Working %s Configurations (URL Format)\n", strings.ToUpper(name)))
		urlFile.WriteString(fmt.Sprintf("# Generated at: %s\n\n", timestamp))
		fm.urlFiles[protocol] = urlFile
	}

	generalJSONFile, err := os.Create(filepath.Join(fm.config.DataDir, "working_json", "working_all_configs.txt"))
	if err != nil {
		return err
	}
	generalJSONFile.WriteString("# All Working Configurations (JSON Format)\n")
	generalJSONFile.WriteString(fmt.Sprintf("# Generated at: %s\n\n", timestamp))
	fm.generalJSONFile = generalJSONFile

	generalURLFile, err := os.Create(filepath.Join(fm.config.DataDir, "working_url", "working_all_urls.txt"))
	if err != nil {
		return err
	}
	generalURLFile.WriteString("# All Working Configurations (URL Format)\n")
	generalURLFile.WriteString(fmt.Sprintf("# Generated at: %s\n\n", timestamp))
	fm.generalURLFile = generalURLFile

	log.Println("Incremental save files initialized")
	return nil
}

func (fm *FileManager) SaveResult(result *TestResultData) {
	if result.Result != ResultSuccess || !fm.config.IncrementalSave {
		return
	}

	fm.mu.Lock()
	defer fm.mu.Unlock()

	protocol := result.Config.Protocol
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	header := fmt.Sprintf("# Tested at: %s | Response: %.3fs | IP: %s\n",
		timestamp, *result.ResponseTime, result.ExternalIP)

	if file, ok := fm.outputFiles[protocol]; ok {
		configLine := createWorkingConfigJSON(result)
		fmt.Fprintf(file, "%s%s\n\n", header, configLine)
		file.Sync()
	}

	if file, ok := fm.urlFiles[protocol]; ok {
		configURL := createConfigURL(&result.Config)
		fmt.Fprintf(file, "%s%s\n\n", header, configURL)
		file.Sync()
	}

	if fm.generalJSONFile != nil {
		configLine := createWorkingConfigJSON(result)
		fmt.Fprintf(fm.generalJSONFile, "# [%s] %s%s\n\n",
			strings.ToUpper(string(protocol)), header, configLine)
		fm.generalJSONFile.Sync()
	}

	if fm.generalURLFile != nil {
		configURL := createConfigURL(&result.Config)
		fmt.Fprintf(fm.generalURLFile, "# [%s] %s%s\n\n",
			strings.ToUpper(string(protocol)), header, configURL)
		fm.generalURLFile.Sync()
	}
}

func (fm *FileManager) SaveResults(results []*TestResultData, logDir string) error {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	file, err := os.Create(filepath.Join(logDir, "test_results.json"))
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

func (fm *FileManager) Close() {
	for _, file := range fm.outputFiles {
		if file != nil {
			file.Close()
		}
	}
	for _, file := range fm.urlFiles {
		if file != nil {
			file.Close()
		}
	}
	if fm.generalJSONFile != nil {
		fm.generalJSONFile.Close()
	}
	if fm.generalURLFile != nil {
		fm.generalURLFile.Close()
	}
}

func createWorkingConfigJSON(result *TestResultData) string {
	config := &result.Config
	data := map[string]interface{}{
		"protocol":    string(config.Protocol),
		"server":      config.Server,
		"port":        config.Port,
		"network":     config.Network,
		"tls":         config.TLS,
		"remarks":     config.Remarks,
		"test_time":   result.ResponseTime,
		"external_ip": result.ExternalIP,
	}

	switch config.Protocol {
	case ProtocolShadowsocks, ProtocolShadowsocksR:
		data["method"] = config.Method
		data["password"] = config.Password
		if config.Protocol == ProtocolShadowsocksR {
			data["protocol"] = config.Protocol_Param
			data["obfs"] = config.Obfs
			data["obfs_param"] = config.ObfsParam
		}
	case ProtocolVMess:
		data["uuid"] = config.UUID
		data["alterId"] = config.AlterID
		data["cipher"] = config.Cipher
		data["path"] = config.Path
		data["host"] = config.Host
		data["sni"] = config.SNI
	case ProtocolVLESS:
		data["uuid"] = config.UUID
		data["flow"] = config.Flow
		data["encryption"] = config.Encrypt
		data["path"] = config.Path
		data["host"] = config.Host
		data["sni"] = config.SNI
	case ProtocolTrojan:
		data["password"] = config.Password
		data["path"] = config.Path
		data["host"] = config.Host
		data["sni"] = config.SNI
		data["alpn"] = config.ALPN
		data["fingerprint"] = config.Fingerprint
	case ProtocolHysteria:
		data["auth_str"] = config.AuthStr
		data["up_mbps"] = config.UpMbps
		data["down_mbps"] = config.DownMbps
		data["obfs"] = config.Obfs
		data["sni"] = config.SNI
		data["alpn"] = config.ALPN
		data["insecure"] = config.Insecure
	case ProtocolHysteria2:
		data["password"] = config.Password
		data["obfs"] = config.Obfs
		data["sni"] = config.SNI
		data["insecure"] = config.Insecure
	case ProtocolTUIC:
		data["uuid"] = config.UUID
		data["password"] = config.Password
		data["congestion_control"] = config.CongestionCtrl
		data["alpn"] = config.ALPN
		data["sni"] = config.SNI
		data["insecure"] = config.Insecure
	}

	jsonBytes, _ := json.Marshal(data)
	return string(jsonBytes)
}

func createConfigURL(config *ProxyConfig) string {
	remarks := url.QueryEscape(config.Remarks)
	if remarks == "" {
		remarks = fmt.Sprintf("%s-%s", strings.ToUpper(string(config.Protocol)), config.Server)
	}

	switch config.Protocol {
	case ProtocolShadowsocks:
		return fmt.Sprintf("ss://%s@%s:%d#%s",
			base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", config.Method, config.Password))),
			config.Server, config.Port, remarks)
	default:
		return ""
	}
}

func main() {
	log.Println("Starting Proxy Tester...")

	// Load configuration
	config := NewDefaultConfig()
	log.Printf("Configuration loaded: MaxWorkers=%d, Timeout=%v, BatchSize=%d",
		config.MaxWorkers, config.Timeout, config.BatchSize)

	// Initialize components
	portManager := NewPortManager(config.StartPort, config.EndPort)
	configLoader := NewConfigLoader()
	networkTester := NewNetworkTester(config.Timeout)
	statisticsManager := NewStatisticsManager()

	// Create directories if they don't exist
	if err := os.MkdirAll(config.DataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}
	if err := os.MkdirAll(config.ConfigDir, 0755); err != nil {
		log.Fatalf("Failed to create config directory: %v", err)
	}
	if err := os.MkdirAll(config.LogDir, 0755); err != nil {
		log.Fatalf("Failed to create log directory: %v", err)
	}

	// Load proxy configurations
	configs, err := configLoader.LoadFromDirectory(config.ConfigDir)
	if err != nil {
		log.Printf("Warning: Failed to load configurations from directory: %v", err)
		log.Println("No configurations to test. Exiting.")
		return
	}

	if len(configs) == 0 {
		log.Println("No valid configurations found. Exiting.")
		return
	}

	log.Printf("Loaded %d configurations for testing", len(configs))

	// Test configurations
	var results []*TestResultData
	for i, proxyConfig := range configs {
		log.Printf("Testing configuration %d/%d: %s (%s)",
			i+1, len(configs), proxyConfig.Remarks, proxyConfig.Protocol)

		// Get a port for testing
		port, ok := portManager.Get()
		if !ok {
			log.Printf("Failed to get port for config %s", proxyConfig.Remarks)
			continue
		}

		// Test the proxy
		success, ip, responseTime := networkTester.Test(port)

		result := &TestResultData{
			Config:       proxyConfig,
			Result:       ResultSuccess,
			ResponseTime: &responseTime,
			ExternalIP:   ip,
			ProxyPort:    &port,
		}

		if !success {
			result.Result = ResultConnectionError
		}

		results = append(results, result)
		statisticsManager.Update(result)

		// Return the port
		portManager.Release(port)

		// Log result
		if success {
			log.Printf("✓ %s - Success (%.3fs, IP: %s)", proxyConfig.Remarks, responseTime, ip)
		} else {
			log.Printf("✗ %s - Failed (%.3fs)", proxyConfig.Remarks, responseTime)
		}
	}

	// Print summary
	statisticsManager.PrintSummary(results)

	// Save results
	fileManager, err := NewFileManager(config)
	if err != nil {
		log.Printf("Warning: Failed to create file manager: %v", err)
	} else {
		if err := fileManager.SaveResults(results, config.LogDir); err != nil {
			log.Printf("Warning: Failed to save results: %v", err)
		} else {
			log.Printf("Results saved to: %s", config.LogDir)
		}
	}

	log.Println("Proxy testing completed.")
}