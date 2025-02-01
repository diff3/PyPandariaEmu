ARG VERSION
ARG OS
ARG TZ

FROM ${OS}:${VERSION}

ENV TZ=${TZ}

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

CMD ["python", "proxyserver.py"]