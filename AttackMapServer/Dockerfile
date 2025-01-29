FROM python:3.13

WORKDIR /opt/bbts/app

COPY ../requirements.txt .

RUN pip3 install -r requirements.txt

ENV TZ="America/Sao_Paulo"

CMD [ "python3", "-u", "AttackMapServer.py" ]