FROM debian:latest

RUN apt-get update && apt-get install -y python3 python3-requests

RUN mkdir -p /osint-suricata/intel
COPY *.py config.json /osint-suricata/
COPY intel/*.py /osint-suricata/intel/

WORKDIR /osint-suricata
CMD ["python3", "main.py"]
