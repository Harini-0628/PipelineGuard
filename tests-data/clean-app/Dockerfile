FROM python:3.12-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000
RUN useradd --create-home app
USER app
HEALTHCHECK CMD python -c "print(1)"
COPY app.py /home/app/app.py
CMD ["python", "/home/app/app.py"]
