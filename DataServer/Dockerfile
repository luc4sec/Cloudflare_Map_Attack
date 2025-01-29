FROM python:alpine3.13

WORKDIR /opt/bbts/app

COPY ./requirements.txt .

COPY ./DataServer/ .

RUN pip3 install -r requirements.txt

RUN apk add --update ca-certificates

ENV TZ="America/Sao_Paulo"

CMD [ "python3", "-u", "CloudFlareData_V1.py" ]