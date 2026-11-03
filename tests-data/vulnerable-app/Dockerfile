FROM ubuntu:latest
USER root
ADD . /app
RUN apt-get update && apt-get install -y curl
CMD ["python3", "/app/app.py"]
