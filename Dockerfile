FROM debian:latest

RUN apt-get update && \
    apt-get install -y python3 python3-pip python3-requests python3-tz python3-tzlocal &&  \
    python3 -m pip install inotify

RUN mkdir -p /osint-suricata/intel
COPY *.py config.json /osint-suricata/
COPY intel/*.py /osint-suricata/intel/

WORKDIR /osint-suricata
CMD ["python3", "main.py"]
