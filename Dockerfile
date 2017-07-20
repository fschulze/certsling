FROM python:3-alpine

RUN apk add --no-cache openssl libffi

RUN apk add --no-cache openssl-dev musl-dev libffi-dev gcc \
    && pip install certsling \
    && apk del --no-cache openssl-dev musl-dev libffi-dev gcc

EXPOSE 8080 8053

WORKDIR /certsling
VOLUME /certsling

ENTRYPOINT ["certsling"]
CMD ["--help"]
