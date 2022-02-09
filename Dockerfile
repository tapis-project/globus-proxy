FROM tapis/flaskbase-plugins


ADD requirements.txt /home/tapis/requirements.txt
RUN pip install -r /home/tapis/requirements.txt

WORKDIR /home/tapis

COPY configschema.json /home/tapis/configschema.json
COPY config-local.json /home/tapis/config.json
COPY service /home/tapis/service
COPY pytest.ini /home/tapis

RUN chown -R tapis:tapis /home/tapis
USER tapis
