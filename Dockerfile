FROM python:3-buster
RUN pip install requests boto3
RUN apt-get update && apt-get install -y syslog-ng-core
WORKDIR /app
ADD IDN2radar.py /app/
ADD config.ini /app/
CMD [ "python", "/app/IDN2radar.py" ]
