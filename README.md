# Prometheus ACI Exporter

Cisco ACI exporter for Prometheus

Pulls information from an APIC using the REST API.

## Docker Image

**TODO(@RavuAlHemio):** Auto-build image using Docker Hub account controlled by @RavuAlHemio.

https://hub.docker.com/r/josdotso/prometheus_aci_exporter

## Running the Docker Image

...and mounting a custom `aci.yml` file.

```bash
docker run --rm -v ${PWD}/examples/aci.yml:/etc/aci.yml -p 9377:9377 -it josdotso/prometheus_aci_exporter
```

## Building the Docker Image locally

```bash
docker build . -t josdotso/prometheus_aci_exporter
```
