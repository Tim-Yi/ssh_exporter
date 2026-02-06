// Copyright 2020 Trey Dockendorf
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/treydock/ssh_exporter/config"
	"github.com/treydock/ssh_exporter/expect"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const (
	namespace = "ssh"
)

type counterMetric struct {
	labelValues []string
	value       float64
}

type expectPoll struct {
	connection *ssh.Client
	sshExpect  *expect.GExpect
}

var (
	// Global map to track counter values based on label combination
	counterValues = make(map[string]map[string]float64)
	counterMutex  sync.RWMutex

	expectPolls = make(map[string]expectPoll)
	PollMutex   sync.RWMutex
)

// getCounter retrieves counterMetric for a given counter name
func getCounter(name string) []counterMetric {
	counterMutex.RLock()
	defer counterMutex.RUnlock()

	if counterValues[name] == nil {
		return nil
	}
	metrics := make([]counterMetric, 0, len(counterValues[name]))
	for labelValues, value := range counterValues[name] {
		if labelValues == "|" {
			metrics = append(metrics, counterMetric{
				labelValues: nil,
				value:       value,
			})
			continue
		}
		metrics = append(metrics, counterMetric{
			labelValues: strings.Split(labelValues, "|"),
			value:       value,
		})
	}
	return metrics
}

// setCounterValue sets a counter value based on label combination key
func setCounterValue(name string, labelValues []string, value float64) {
	var key string
	if labelValues == nil {
		key = "|"
	} else {
		key = strings.Join(labelValues, "|")
	}
	counterMutex.Lock()
	defer counterMutex.Unlock()

	if counterValues[name] == nil {
		counterValues[name] = make(map[string]float64)
	}
	counterValues[name][key] = value
}

// incrementCounter increments a counter value based on label combination key
func incrementCounter(name string, labelValues []string) {
	var key string
	if labelValues == nil {
		key = "|"
	} else {
		key = strings.Join(labelValues, "|")
	}
	counterMutex.Lock()
	defer counterMutex.Unlock()

	if counterValues[name] == nil {
		counterValues[name] = make(map[string]float64)
	}
	if val, exists := counterValues[name][key]; exists {
		counterValues[name][key] = val + 1
	} else {
		counterValues[name][key] = 1
	}
}

func getExpectPoll(target *config.Target) (expectPoll, bool) {
	PollMutex.RLock()
	defer PollMutex.RUnlock()

	poll, exists := expectPolls[target.ModuleName+"_"+target.Host]
	return poll, exists
}

func setExpectPoll(target *config.Target, poll expectPoll) {
	PollMutex.Lock()
	defer PollMutex.Unlock()

	expectPolls[target.ModuleName+"_"+target.Host] = poll
}

// isSSHConnectionAlive checks if an SSH connection is still alive
func isSSHConnectionAlive(client *ssh.Client) bool {
	if client == nil {
		return false
	}
	// Send a request to check if the connection is alive
	// Using "keepalive@openssh.com" as a standard keepalive request
	_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
	return err == nil
}

// drainSSHOutput drains all available output from an expect session
func drainSSHOutput(e *expect.GExpect, expect_prompt *regexp.Regexp) string {
	var output strings.Builder
	for range 10 {
		o, _, _ := e.Expect(expect_prompt, 100*time.Millisecond)
		if strings.TrimSpace(o) == "" {
			break
		}
		output.WriteString(o)
	}
	return output.String()
}

type Metric struct {
	Success       float64
	FailureReason string
	Output        string
}

type Collector struct {
	Success  *prometheus.Desc
	Duration *prometheus.Desc
	Failure  *prometheus.Desc
	Counters []*prometheus.Desc
	Output   *prometheus.Desc
	target   *config.Target
	logger   log.Logger
}

func NewCollector(target *config.Target, logger log.Logger) *Collector {
	var counters []*prometheus.Desc
	if target.Counters != nil {
		counters = make([]*prometheus.Desc, 0, len(target.Counters))
		for _, counter := range target.Counters {
			// Extract label names from RegexpLabels
			var labelNames []string
			for _, label := range counter.RegexpLabels {
				labelNames = append(labelNames, label.Name)
			}
			counters = append(counters, prometheus.NewDesc(prometheus.BuildFQName("", "", counter.Name),
				counter.Desc, labelNames, nil))
		}
	}
	return &Collector{
		Success: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "success"),
			"SSH connection was successful", nil, nil),
		Duration: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "duration_seconds"),
			"How long the SSH check took in seconds", nil, nil),
		Failure: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "failure"),
			"Indicates a failure", []string{"reason"}, nil),
		Counters: counters,
		Output: prometheus.NewDesc(prometheus.BuildFQName(namespace, "", "output"),
			"The output of the executed command", []string{"output"}, nil),
		target: target,
		logger: logger,
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.Success
	ch <- c.Duration
	ch <- c.Failure
	for _, counter := range c.Counters {
		ch <- counter
	}
	ch <- c.Output
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	level.Debug(c.logger).Log("msg", "Collecting SSH metrics")
	failureReasons := []string{"error", "timeout", "command-error", "command-output"}
	collectTime := time.Now()

	metric := c.collect()

	ch <- prometheus.MustNewConstMetric(c.Success, prometheus.GaugeValue, metric.Success)
	for _, reason := range failureReasons {
		var value float64
		if reason == metric.FailureReason {
			value = 1
		}
		ch <- prometheus.MustNewConstMetric(c.Failure, prometheus.GaugeValue, value, reason)
	}
	if c.target.Counters != nil {
		for i, counter := range c.target.Counters {
			if metric.Output != "" {
				pattern := regexp.MustCompile(counter.Regexp)
				matches := pattern.FindAllStringSubmatch(metric.Output, -1)
				for _, match := range matches {
					var value float64
					var labelValues []string

					// Extract label values from RegexpLabels
					for _, label := range counter.RegexpLabels {
						if label.Group >= 1 && label.Group < len(match) {
							labelValue := match[label.Group]
							labelValues = append(labelValues, labelValue)
						} else {
							labelValues = append(labelValues, "")
						}
					}
					// Extract metric value from the specified group
					valueGroup := counter.RegexpValue.Group
					if valueGroup >= 1 && valueGroup < len(match) {
						if counter.RegexpValue.ValueMap != nil {
							if mappedValue, ok := counter.RegexpValue.ValueMap[match[valueGroup]]; ok {
								value = mappedValue
							}
						} else {
							fmt.Sscanf(match[valueGroup], "%f", &value)
						}
						setCounterValue(counter.Name, labelValues, value)
					} else {
						incrementCounter(counter.Name, labelValues)
					}
				}
			}

			// Determine metric type based on counter type
			var metricType prometheus.ValueType
			if counter.Type == "gauge" {
				metricType = prometheus.GaugeValue
			} else {
				metricType = prometheus.CounterValue
			}
			for _, cm := range getCounter(counter.Name) {
				ch <- prometheus.MustNewConstMetric(c.Counters[i], metricType, cm.value, cm.labelValues...)
			}
		}
	}
	if c.target.OutputMetric {
		output := truncateString(metric.Output, c.target.OutputTruncate)
		ch <- prometheus.MustNewConstMetric(c.Output, prometheus.GaugeValue, 1, strings.TrimSuffix(output, "\n"))
	}
	ch <- prometheus.MustNewConstMetric(c.Duration, prometheus.GaugeValue, time.Since(collectTime).Seconds())
}

func (c *Collector) collect() Metric {
	c1 := make(chan int, 1)
	timeout := false
	var metric Metric
	var auth []ssh.AuthMethod
	var sessionerror, commanderror error
	var connection *ssh.Client
	var sshExpect *expect.GExpect

	if c.target.Mode == "expect_poll" {
		poll, exists := getExpectPoll(c.target)
		if exists {
			// Check if connection is still alive before closing
			if poll.connection != nil && isSSHConnectionAlive(poll.connection) {
				level.Debug(c.logger).Log("msg", "Using existing alive expect poll connection", "module", c.target.ModuleName)
				connection = poll.connection
				sshExpect = poll.sshExpect
			} else {
				if poll.sshExpect != nil {
					poll.sshExpect.Close()
				}
				if poll.connection != nil {
					poll.connection.Close()
				}
				level.Info(c.logger).Log("msg", "Expect poll connection not alive", "module", c.target.ModuleName)
				setExpectPoll(c.target, expectPoll{})
			}
		}
	}

	if connection == nil {
		if c.target.Certificate != "" {
			authMethod, autherror := getCertificateAuth(c.target.PrivateKey, c.target.Certificate)
			if autherror != nil {
				metric.FailureReason = "error"
				level.Error(c.logger).Log("msg", "Error setting up certificate auth", "err", autherror)
				return metric
			}
			auth = []ssh.AuthMethod{authMethod}
		} else if c.target.PrivateKey != "" {
			authMethod, autherror := getPrivateKeyAuth(c.target.PrivateKey)
			if autherror != nil {
				metric.FailureReason = "error"
				level.Error(c.logger).Log("msg", "Error setting up private key auth", "err", autherror)
				return metric
			}
			auth = []ssh.AuthMethod{authMethod}
		} else {
			auth = []ssh.AuthMethod{
				ssh.KeyboardInteractiveChallenge(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
					// assumes password is the only answer to everything
					answers := make([]string, len(questions))
					for i := range answers {
						answers[i] = c.target.Password
					}
					return answers, nil
				}),
				ssh.Password(c.target.Password),
			}
		}

		sshConfig := &ssh.ClientConfig{
			User:              c.target.User,
			Auth:              auth,
			HostKeyCallback:   hostKeyCallback(&metric, c.target, c.logger),
			HostKeyAlgorithms: c.target.HostKeyAlgorithms,
			Timeout:           time.Duration(c.target.Timeout) * time.Second,
		}
		var err error
		connection, err = ssh.Dial("tcp", c.target.Host, sshConfig)
		if err != nil {
			if strings.Contains(err.Error(), "timeout") {
				metric.FailureReason = "timeout"
			} else {
				metric.FailureReason = "error"
			}
			level.Error(c.logger).Log("msg", "Failed to establish SSH connection", "err", err)
			return metric
		}
		if c.target.Mode != "expect_poll" {
			defer connection.Close()
		}
	}

	go func(conn *ssh.Client) {
		switch c.target.Mode {
		case "expect_poll":
			expect_prompt := regexp.MustCompile(c.target.ExpectPrompt)
			if sshExpect == nil {
				expect_timeout := 3 * time.Second
				sshExpect, _, sessionerror = expect.SpawnSSH(conn, expect_timeout)
				if sessionerror != nil {
					return
				}
				if c.target.Command != "" {
					sshExpect.Expect(expect_prompt, expect_timeout)
					drainSSHOutput(sshExpect, expect_prompt)
					commands := strings.SplitSeq(c.target.Command, "\n")
					for cmd := range commands {
						sshExpect.Send(cmd + "\n")
						output, _, _ := sshExpect.Expect(expect_prompt, expect_timeout)
						metric.Output += output
						metric.Output += drainSSHOutput(sshExpect, expect_prompt)
					}
					level.Debug(c.logger).Log("msg", "Finished first expect_poll command execution",
						"module", c.target.ModuleName, "output", metric.Output)
				}
				setExpectPoll(c.target, expectPoll{
					connection: conn,
					sshExpect:  sshExpect,
				})
			} else {
				sshExpect.Send("\n")
				metric.Output += drainSSHOutput(sshExpect, expect_prompt)
				level.Debug(c.logger).Log("msg", "Finished subsequent expect_poll fetch",
					"module", c.target.ModuleName, "output", metric.Output)
			}
		case "expect":
			expect_timeout := 3 * time.Second
			expect_prompt := regexp.MustCompile(c.target.ExpectPrompt)
			sshExpect, _, sessionerror = expect.SpawnSSH(conn, expect_timeout)
			if sessionerror != nil {
				return
			}
			defer sshExpect.Close()
			if c.target.Command != "" {
				sshExpect.Expect(expect_prompt, expect_timeout)
				drainSSHOutput(sshExpect, expect_prompt)
				commands := strings.SplitSeq(c.target.Command, "\n")
				for cmd := range commands {
					sshExpect.Send(cmd + "\n")
					output, _, _ := sshExpect.Expect(expect_prompt, expect_timeout)
					metric.Output += output
					metric.Output += drainSSHOutput(sshExpect, expect_prompt)
				}
				level.Debug(c.logger).Log("msg", "Finished expect command execution", "module", c.target.ModuleName, "output", metric.Output)
			}
		default: // default to shell mode
			var session *ssh.Session
			session, sessionerror = conn.NewSession()
			if sessionerror != nil {
				return
			}
			defer session.Close()
			if c.target.Command != "" {
				var cmdBuffer bytes.Buffer
				session.Stdout = &cmdBuffer
				commanderror = session.Run(c.target.Command)
				metric.Output = cmdBuffer.String()
			}
		}
		if !timeout {
			c1 <- 1
		}
	}(connection)

	select {
	case <-c1:
	case <-time.After(time.Duration(c.target.Timeout) * time.Second):
		timeout = true
		close(c1)
		metric.FailureReason = "timeout"
		level.Error(c.logger).Log("msg", "Timeout establishing SSH session")
		return metric
	}
	close(c1)
	if sessionerror != nil {
		metric.FailureReason = "error"
		level.Error(c.logger).Log("msg", "Error establishing SSH session", "err", sessionerror)
		return metric
	}
	if commanderror != nil {
		metric.FailureReason = "command-error"
		level.Error(c.logger).Log("msg", "Error executing command", "err", commanderror, "command", c.target.Command, "output", metric.Output)
		return metric
	}
	if c.target.Command != "" && c.target.CommandExpect != "" {
		commandExpectPattern := regexp.MustCompile(c.target.CommandExpect)
		if !commandExpectPattern.MatchString(metric.Output) {
			level.Error(c.logger).Log("msg", "Command output did not match expected value",
				"output", metric.Output, "command", c.target.Command)
			metric.FailureReason = "command-output"
			return metric
		}
	}
	metric.Success = 1
	return metric
}

func getPrivateKeyAuth(privatekey string) (ssh.AuthMethod, error) {
	buffer, err := os.ReadFile(privatekey)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(key), nil
}

func getCertificateAuth(privatekey string, certificate string) (ssh.AuthMethod, error) {
	key, err := os.ReadFile(privatekey)
	if err != nil {
		return nil, fmt.Errorf("Unable to read private key: '%s' %v", privatekey, err)
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse private key: '%s' %v", privatekey, err)
	}

	// Load the certificate
	cert, err := os.ReadFile(certificate)
	if err != nil {
		return nil, fmt.Errorf("Unable to read certificate file: '%s' %v", certificate, err)
	}

	pk, _, _, _, err := ssh.ParseAuthorizedKey(cert)
	if err != nil {
		return nil, fmt.Errorf("Unable to parse public key: '%s' %v", certificate, err)
	}

	certSigner, err := ssh.NewCertSigner(pk.(*ssh.Certificate), signer)
	if err != nil {
		return nil, fmt.Errorf("Unable to create cert signer: %v", err)
	}

	return ssh.PublicKeys(certSigner), nil
}

func hostKeyCallback(metric *Metric, target *config.Target, logger log.Logger) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		var hostKeyCallback ssh.HostKeyCallback
		var err error
		if target.KnownHosts != "" {
			publicKey := base64.StdEncoding.EncodeToString(key.Marshal())
			level.Debug(logger).Log("msg", "Verify SSH known hosts", "hostname", hostname, "remote", remote.String(), "key", publicKey)
			hostKeyCallback, err = knownhosts.New(target.KnownHosts)
			if err != nil {
				metric.FailureReason = "error"
				level.Error(logger).Log("msg", "Error creating hostkeycallback function", "err", err)
				return err
			}
		} else {
			hostKeyCallback = ssh.InsecureIgnoreHostKey()
		}
		return hostKeyCallback(hostname, remote, key)
	}
}

func truncateString(str string, num int) string {
	bnoden := str
	if num == -1 {
		return bnoden
	}
	if len(str) > num {
		if num > 3 {
			num -= 3
		}
		bnoden = str[0:num] + "..."
	}
	return bnoden
}
