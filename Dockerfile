FROM alpine:3.10

MAINTAINER Karim Boumedhel <karimboumedhel@gmail.com>

LABEL name="karmab/aicli" \
      maintainer="karimboumedhel@gmail.com" \
      vendor="Karmalabs" \
      version="latest" \
      release="0" \
      summary="Assisted installer cli" \
      description="Assisted installer wrapper"

RUN apk add --update --no-cache python3-dev

# Group the pip installation
RUN mkdir /root/aicli
ADD ailib /root/aicli/ailib
COPY setup.py /root/aicli
RUN pip3 install -U pip && pip3 install -e /root/aicli
RUN touch /i_am_a_container

#RUN echo eval \"\$\(register-python-argcomplete kcli\)\" >> /root/.bashrc && apk del g++ gcc libvirt-dev curl-dev libressl-dev libxml2-dev linux-headers libffi-dev

ENTRYPOINT ["/usr/bin/aicli"]
CMD ["-h"]
