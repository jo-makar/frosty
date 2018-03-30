# osint-suricata
Open Source threat Intel with Suricata (an Intrusion Detection System)

The intention of this project is to automate the use of
[Suricata](https://suricata-ids.org/) with freely available threat intel to
identify potential indicators of compromise/intrusion in local network traffic.

Implemented as a Docker container it will automatically refresh and deploy intel
and report the generated alerts via mail (originally a local mail spool).

# Intel feeds
- [x] [Emerging Threats (open ruleset)](https://www.proofpoint.com/us/products/et-intelligence)
  - Emerging Threats Pro is supported with a provided oinkcode
  - NB Emerging Threats Open is 30 days behind Emerging Threats Pro

# Setup
## Suricata
Naturally Suricata must be installed and configured properly, the defaults for
most installations should be adequate though be certain the af-packet interface
is set appropriately for the host machine.

For monitoring several interfaces reference: http://pevma.blogspot.com/2015/05/suricata-multiple-interface.html

Back up existing rules and the config file:
```sh
sudo mv /etc/suricata/rules /etc/suricata/rules.orig && sudo mkdir /etc/suricata/rules
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.orig
```

In the Suricata config file ensure that the eve-log format output is enabled:
```yaml
outputs:
  - eve-log:
      enabled: yes
```

Modify the Suricata config file rules section to have the following wildcard:
```yaml
default-rule-path: /etc/suricata/rules
rules-files:
  - "osint-suricata-*.rules"
```
Reference: http://pevma.blogspot.com/2015/05/suricata-wildcard-rule-loading.html

Also this relies on suricatasc (socket client) to communicate with the Suricata,
ensure that the unix-command option is enabled in the Suricata config file:
```yaml
unix-comand:
  enabled: yes
  filename: /var/run/suricata-command.socket
```

## osint-suricata
Modify the osint-suricata config.json as needed.

Build the docker image: `docker build -t osint-suricata:latest .`.

Launch the docker container with `docker-run` (which is essentially
`docker run osint-suricata:latest` with bind mounts).

# Try it out!
FIXME Lookup an alert that can be generated via curl

# License
This work is released to the public domain.

<!-- vim: set textwidth=80: -->
