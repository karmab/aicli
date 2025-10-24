FROM alpine:3.17

MAINTAINER Karim Boumedhel <karimboumedhel@gmail.com>

LABEL name="karmab/aicli" \
      maintainer="karimboumedhel@gmail.com" \
      vendor="Karmalabs" \
      version="latest" \
      release="0" \
      summary="Assisted installer cli" \
      description="Assisted installer wrapper"

RUN apk add --update --no-cache python3-dev openssl py3-pip

RUN mkdir /root/aicli
ADD README.md /root/aicli
ADD src /root/aicli/src
COPY pyproject.toml /root/aicli
RUN pip3 install --ignore-installed -U pip setuptools wheel build && pip3 install -e /root/aicli
RUN touch /i_am_a_container

ENTRYPOINT ["/usr/bin/aicli"]
CMD ["-h"]
