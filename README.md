# Prometheus ACI Exporter

Cisco ACI exporter for Prometheus

Pulls information from an APIC using the REST API.

## Docker Image

https://hub.docker.com/r/ravualhemio/prometheus_aci_exporter

### Running the Docker Image

...and mounting a custom `aci.yml` file.

```bash
docker run --rm -v ${PWD}/examples/aci.yml:/etc/prometheus_aci_exporter/aci.yml -p 9377:9377 -it ravualhemio/prometheus_aci_exporter
```

### Building the Docker Image locally

```bash
docker build . -t ravualhemio/prometheus_aci_exporter
```
