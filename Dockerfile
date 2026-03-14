FROM python:3.11-slim

COPY dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

EXPOSE 8080

ENTRYPOINT ["uvicorn", "katran.api.rest.app:create_app", \
            "--host", "0.0.0.0", "--port", "8080", "--factory"]
