ARG BUILD_FROM
FROM $BUILD_FROM

ENV LANG=C.UTF-8

# Copy data for add-on
COPY run.sh ip150.py ip150_mqtt.py requirements.txt /

# py3-pip (rather than ensurepip) is the reliable way to get pip on Alpine.
# --break-system-packages is needed since Python 3.12/PEP 668 marks the
# system interpreter as externally managed; safe here since the container
# is dedicated to this single app.
RUN apk add --no-cache python3 py3-pip &&\
    pip3 install --no-cache-dir --break-system-packages -r requirements.txt

RUN chmod a+x /run.sh

CMD [ "/run.sh" ]