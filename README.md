[![Build Status](https://circleci.com/gh/treydock/ssh_exporter/tree/master.svg?style=shield)](https://circleci.com/gh/treydock/ssh_exporter)
[![GitHub release](https://img.shields.io/github/v/release/treydock/ssh_exporter?include_prereleases&sort=semver)](https://github.com/treydock/ssh_exporter/releases/latest)
![GitHub All Releases](https://img.shields.io/github/downloads/treydock/ssh_exporter/total)
![Docker Pulls](https://img.shields.io/docker/pulls/treydock/ssh_exporter)
[![Go Report Card](https://goreportcard.com/badge/github.com/treydock/ssh_exporter)](https://goreportcard.com/report/github.com/treydock/ssh_exporter)
[![codecov](https://codecov.io/gh/treydock/ssh_exporter/branch/master/graph/badge.svg)](https://codecov.io/gh/treydock/ssh_exporter)

# SSH exporter

The SSH exporter attempts to make an SSH connection to a remote system and optionally run a command and test output.

This exporter is intended to query multiple SSH servers from an external host.

The `/ssh` metrics endpoint exposes SSH metrics and requires the `target` parameter.
The `module` parameter can also be used to select which configuration module to use, the default module is `default`.

The `/metrics` endpoint exposes Go and process metrics for this exporter.

## Configuration

The configuration defines modules that are used to configure the SSH client for a given target.

Example:

```yaml
modules:
  default:
    user: prometheus
    private_key: /home/prometheus/.ssh/id_rsa
    command: uptime
    command_expect: "load average"
    timeout: 5
  password:
    user: prometheus
    password: secret
  certificate:
    user: prometheus
    private_key: /home/prometheus/.ssh/id_ed25519
    certificate: /home/prometheus/.ssh/id_ed25519-cert.pub
  verify:
    user: prometheus
    private_key: /home/prometheus/.ssh/id_rsa
    known_hosts: /etc/ssh/ssh_known_hosts
    host_key_algorithms:
    - ssh-rsa
    command: uptime
    command_expect: "load average"
    timeout: 5
  capture:
    user: prometheus
    private_key: /home/prometheus/.ssh/id_rsa
    command: /some/command/with/output
    output_metric: true
    output_truncate: 50
  fetch-counter:
    user: username
    password: secret
    command: uptime
    counters:
      - name: "load1"
        regexp: "load average: ([0-9]+\\.[0-9]+),"
      - name: "load5"
        regexp: "load average: [0-9]+\\.[0-9]+, ([0-9]+\\.[0-9]+),"
      - name: "load15"
        regexp: "load average: [0-9]+\\.[0-9]+, [0-9]+\\.[0-9]+, ([0-9]+\\.[0-9]+)"
  expect-opensm-log:
    user: username
    password: secret
    command: "enable;show ib sm log continue"
    mode: expect_poll
    timeout: 30
    counters:
      - name: "ib_opensm_link_change_total"
        type: "counter"
        desc: "IB Link state changes total"
        regexp: 'osm_spst_rcv_process: Switch (\S+) (.*) port (\d+) changed state from (ACTIVE|DOWN)'
        regexp_labels:
          - group: 1
            name: "guid"
          - group: 2
            name: "dev"
          - group: 3
            name: "ifindex"
          - group: 4
            name: "state"
        regexp_value:
          group: -1
      - name: "ib_opensm_link_state"
        type: "gauge"
        desc: "IB Link state"
        regexp: 'osm_spst_rcv_process: Switch (\S+) (.*) port (\d+) changed state from (ACTIVE|DOWN)'
        regexp_labels:
          - group: 1
            name: "guid"
          - group: 2
            name: "dev"
          - group: 3
            name: "ifindex"
        regexp_value:
          group: 4
          value_map:
            ACTIVE: 0
            DOWN: 1
```

Example with curl would query host1 with the password module and host2 with the default module.

```
curl "http://localhost:9312/ssh?target=host1.example.com:22&module=password"
curl http://localhost:9312/ssh?target=host2.example.com:22
```

Configuration options for each module:

* `user` - The username for the SSH connection
* `password` - The password for the SSH connection, required if `private_key` is not specified
* `private_key` - The SSH private key for the SSH connection, required if `password` is not specified
* `certificate` - The SSH certificate for the private key for the SSH connection
* `known_hosts` - Optional SSH known hosts file to use to verify hosts
* `host_key_algorithms` - Optional list of SSH host key algorithms to use
  * See constants beginning with `KeyAlgo*` in [crypto/ssh](https://godoc.org/golang.org/x/crypto/ssh#pkg-constants)
* `timeout` - Optional timeout of the SSH connection, session and optional command.
    * The default comes from the `--collector.ssh.default-timeout` flag.
* `command` - Optional command to run.
* `command_expect` - Optional regular expression of output to expect from the command.
* `output_metric` - If `true` the exporter will expose the `command` output via `ssh_output{output="<output here>"}` metric.
* `output_truncate` - Sets the max length for a string in `ssh_output` metric's `output` label. Set to `-1` to disable truncating.
* `mode` - Enhancement for run command in interactive shell
    * shell       - default mode for run command in non-interactive shell.
    * expect      - run command in interactive shell, use expect to wait output, and close connection after finished.
    * expect_poll - run command in interactive shell, use expect to poll output continuously, and keep connection.
* `expect_prompt` - Optional prompt's regular expression of output to expect in expect/expect_poll mode
* `counters` - Optional list to parse output from command
    * name - the prometheus metric name
    * type - counter or gauge
    * desc - the prometheus metric description, default to name
    * regexp - regular expression to match output
    * regexp_labels - optional list, the match groups of regexp to fill metric labels
        * group - match group index in regexp, starts from 1
        * name  - label name
    * regexp_value - the match group of regexp to fill metric value
        * group - match group index in regexp, default is 1; if index < 0, set value to a increment counter from 1
        * value_map - optional map the value string to float
## Docker

Example of running the Docker container

```
docker run -d -p 9312:9312 -v "ssh_exporter.yaml:/ssh_exporter.yaml:ro" treydock/ssh_exporter
```

Example of running the Docker container and making SSH private key available.
This requires setting `private_key` value to `/.ssh/id_rsa`.

```
docker run -d -p 9312:9312 \
-v "ssh_exporter.yaml:/ssh_exporter.yaml:ro" \
-v "/home/prometheus/.ssh/id_rsa:/.ssh/id_rsa:ro" \
treydock/ssh_exporter
```

## Install

Download the [latest release](https://github.com/treydock/ssh_exporter/releases)

Add the user that will run `ssh_exporter`

```
groupadd -r ssh_exporter
useradd -r -d /var/lib/ssh_exporter -s /sbin/nologin -M -g ssh_exporter -M ssh_exporter
```

Install compiled binaries after extracting tar.gz from release page.

```
cp /tmp/ssh_exporter /usr/local/bin/ssh_exporter
```

Add the necessary config, see [configuration section](#configuration)

Add systemd unit file and start service. Modify the `ExecStart` with desired flags.

```
cp systemd/ssh_exporter.service /etc/systemd/system/ssh_exporter.service
systemctl daemon-reload
systemctl start ssh_exporter
```

## Build from source

To produce the `ssh_exporter` binary:

```
make build
```

Or

```
go get github.com/treydock/ssh_exporter
```

## Prometheus configs

The following example assumes this exporter is running on the Prometheus server and communicating to the remote SSH hosts.

```yaml
- job_name: ssh
  metrics_path: /ssh
  static_configs:
  - targets:
    - host1.example.com:22
    - host2.example.com:22
    labels:
      module: default
  - targets:
    - host3.example.com:22
    - host4.example.com:22
    labels:
      module: verify
  relabel_configs:
  - source_labels: [__address__]
    target_label: __param_target
  - source_labels: [__param_target]
    target_label: instance
  - target_label: __address__
    replacement: 127.0.0.1:9312
  - source_labels: [module]
    target_label: __param_module
  metric_relabel_configs:
  - regex: "^(module)$"
    action: labeldrop
- job_name: ssh-metrics
  metrics_path: /metrics
  static_configs:
  - targets:
    - localhost:9312
```
