FROM python:3.13-slim-bookworm

# Set python default environment variables
ENV PYTHONIOENCODING=UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Create a non-root user and set home
ENV APP_USER=appuser
ENV HOME=/home/$APP_USER
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    make \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" --home $HOME $APP_USER \
    && chown -R $APP_USER:$APP_USER /app

# Install dependencies
COPY requirements.txt ./

RUN pip install "pip==25.1.1" --no-cache-dir && \
    pip install -r requirements.txt --no-cache-dir

# Copy Makefile and test-related files
COPY Makefile pytest.ini .coveragerc ./

# Copy the application code
COPY pov_manager/ ./pov_manager/

# Copy pytest.ini to pov_manager directory for test execution
COPY pytest.ini ./pov_manager/pytest.ini

RUN chown -R $APP_USER:$APP_USER /app

# Switch to non-root user
USER $APP_USER

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl --fail http://localhost:8000/ || exit 1

CMD ["gunicorn", "--chdir", "pov_manager", "--bind", "0.0.0.0:8000", "pov_manager.wsgi:application", "--timeout", "90"]
