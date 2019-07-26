FROM python:3-slim

ENV PYTHONWARNINGS "ignore:Unverified HTTPS request"


WORKDIR /opt/prometheus_aci_exporter

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir /etc/prometheus_aci_exporter
COPY examples/aci.yml /etc/prometheus_aci_exporter/aci.yml

ENTRYPOINT [ "python", "./prometheus_aci_exporter.py" ]

CMD [ "--config.file", "/etc/prometheus_aci_exporter/aci.yml" ]
