FROM python:3.9

WORKDIR /rautee

COPY connection ./connection
COPY rules ./rules
COPY *.py requirements.txt ./

RUN pip install -r requirements.txt

ENTRYPOINT ["python", "rautee.py"]
CMD ["-h"]
