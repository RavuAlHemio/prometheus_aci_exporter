FROM python:3

WORKDIR /opt/prometheus_aci_exporter

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

## Standardize on a config path that is appropriate for overriding with a volume-mount.
COPY examples/aci.yml /etc/aci.yml

ENTRYPOINT [ "python", "./prometheus_aci_exporter.py" ]

CMD [ "--config.file", "/etc/aci.yml" ]
