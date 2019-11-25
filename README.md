# Prometheus ACI Exporter

Cisco ACI exporter for Prometheus

Pulls information from an APIC using the REST API.

## OpenMetrics support

Initial OpenMetrics support is available. OpenMetrics output is provided if the exporter has been started with the
`--web.openmetrics` option and the client supplies an `Accept:` header including `application/openmetrics-text`.
Otherwise, data is output in the Prometheus exposition format.

If OpenMetrics output is requested, the names of counter metrics are modified on-the-fly to match the new convention
(the suffix `_total` is appended unless the metric name already ends with `_total`). **It is strongly recommended to
include the `_total` suffix in counter metric names in preparation for the eventual transition from the Prometheus
exposition format to OpenMetrics.**

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
