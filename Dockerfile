FROM debian:latest

RUN apt-get update && apt-get install -y python3

RUN mkdir /osint-suricata
COPY main.py config.json /osint-suricata/

WORKDIR /osint-suricata
CMD ["python3", "main.py"]
