# osint-suricata
Automated alerting with open source threat intel and the Suricata IDS

The intention of this project is to automate the use of [Suricata](https://suricata-ids.org/) with freely available threat intel to identify potential indicators of compromise/intrusion in local network traffic.

Implemented as a Docker container it will automatically refresh and deploy intel and report the generated alerts via mail (originally a local mail spool).

# Intel feeds
- [x] [Emerging Threats (open ruleset)](https://www.proofpoint.com/us/products/et-intelligence)
  - Emerging Threats Pro is supported with a provided oinkcode

# Setup
## Suricata
Naturally Suricata must be installed and configured properly, the defaults for most installations should be adequate though be certain the af-packet interface is set appropriately for the host machine.

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

Also ensure that the unix-command option is enabled:
```yaml
unix-comand:
  enabled: yes
  filename: /var/run/suricata-command.socket
```

Finally modify the rules section to have the following wildcard:
```yaml
default-rule-path: /etc/suricata/rules
rule-files:
  - "osint-suricata-*.rules"
```
Reference: http://pevma.blogspot.com/2015/05/suricata-wildcard-rule-loading.html

If necessary restart Suricata with `systemctl restart suricata`.

## Mail transfer agent
An MTA must be enabled on the Docker host to relay mails (even if it ultimately goes to a local mail spool).

As an example, on Debian Exim4 can be configured to relay mails from Docker containers by updating the following lines in /etc/exim4/update-exim4.conf.conf:
```
dc_local_interfaces='127.0.0.1 ; ::1 ; 172.17.0.1'
...
dc_relay_nets='172.17.0.0/16'
```
Where 172.17.0.1 is the address assigned to the docker0 interface on the host.

Restart Exim4 with `systemctl restart exim4`.

Verify sending mail from within the container with the following: `contid=$(./docker-run); docker exec -it $contid python3`
```pycon
<python banner elided>
>>> import smtplib
>>> smtp = smtplib.SMTP('172.17.0.1')
>>> smtp.set_debuglevel(True)
>>> smtp.sendmail('cont@docker', 'user@host', 'mail body')
send: 'ehlo [172.17.0.2]\r\n'
reply: b'250-host Hello [172.17.0.2] [172.17.0.2]\r\n'
reply: b'250-SIZE 52428800\r\n'
reply: b'250-8BITMIME\r\n'
reply: b'250-PIPELINING\r\n'
reply: b'250-CHUNKING\r\n'
reply: b'250-PRDR\r\n'
reply: b'250 HELP\r\n'
reply: retcode (250); Msg: b'host Hello [172.17.0.2] [172.17.0.2]\nSIZE 52428800\n8BITMIME\nPIPELINING\nCHUNKING\nPRDR\nHELP'
send: 'mail FROM:<cont@docker> size=9\r\n'
reply: b'250 OK\r\n'
reply: retcode (250); Msg: b'OK'
send: 'rcpt TO:<user@host>\r\n'
reply: b'250 Accepted\r\n'
reply: retcode (250); Msg: b'Accepted'
send: 'data\r\n'
reply: b'354 Enter message, ending with "." on a line by itself\r\n'
reply: retcode (354); Msg: b'Enter message, ending with "." on a line by itself'
data: (354, b'Enter message, ending with "." on a line by itself')
send: b'mail body\r\n.\r\n'
reply: b'250 OK id=1f2JWh-0000Yv-HM\r\n'
reply: retcode (250); Msg: b'OK id=1f2JWh-0000Yv-HM'
data: (250, b'OK id=1f2JWh-0000Yv-HM')
{}
>>>
```

The test mail should now appear in local mail spool for the specified user.

Reference: https://gehrcke.de/2014/07/discourse-docker-container-send-mail-through-exim/

## osint-suricata
Modify the osint-suricata config.json as needed.

Build the docker image: `docker build -t osint-suricata:latest .`.

Launch the docker container with `docker-run` (which is essentially `docker run osint-suricata:latest` with bind mounts).

# Try it out!
```sh
$ grep 'TOR Known Tor Exit Node' /etc/suricata/rules/osint-suricata-et.rules | head -1
alert ip [103.234.220.195,103.234.220.197,103.236.201.110,103.250.73.13,103.27.124.82,103.28.52.93,103.29.70.23,103.3.61.114,103.8.79.229,104.192.0.58] any -> $HOME_NET any (msg:"ET TOR Known Tor Exit Node Traffic group 1"; reference:url,doc.emergingthreats.net/bin/view/Main/TorRules; threshold: type limit, track by_src, seconds 60, count 1; classtype:misc-attack; flowbits:set,ET.TorIP; sid:2520000; rev:3281;)
$ ping -c 1 103.234.220.195
PING 103.234.220.195 (103.234.220.195) 56(84) bytes of data.
64 bytes from 103.234.220.195: icmp_seq=1 ttl=45 time=264 ms

--- 103.234.220.195 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 264.849/264.849/264.849/0.000 ms
$
```

There should now be a mail with the alert in the configured (config.json) mail spool.
```sh
$ mail
"/var/mail/jom": 1 message 1 new
>N   1 jom@bravo          Sat Mar 31 18:28  44/1300
?
Return-path: <jom@bravo>
Envelope-to: jom@bravo
Delivery-date: Sat, 31 Mar 2018 18:28:53 -0400
Received: from [172.17.0.2]
        by bravo with esmtp (Exim 4.89)
        (envelope-from <jom@bravo>)
        id 1f2OzU-0000wq-K8
        for jom@bravo; Sat, 31 Mar 2018 18:28:52 -0400
Message-Id: <E1f2OzU-0000wq-K8@bravo>
From: jom@bravo
Date: Sat, 31 Mar 2018 18:28:52 -0400

{'alert': {'action': 'allowed',
           'category': 'Misc Attack',
           'gid': 1,
           'rev': 3281,
           'severity': 2,
           'signature': 'ET TOR Known Tor Exit Node Traffic group 1',
           'signature_id': 2520000},
 'dest_ip': '192.168.0.109',
 'event_type': 'alert',
 'icmp_code': 0,
 'icmp_type': 0,
 'in_iface': 'wls3',
 'proto': 'ICMP',
 'src_ip': '103.234.220.195',
 'timestamp': '2018-03-31T18:28:51.845763-0400'}
? d
? q
Held 0 messages in /var/mail/jom
$
```

# License
This work is released to the public domain.
