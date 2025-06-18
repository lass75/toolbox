FROM python:3.11-slim

WORKDIR /app
COPY . /app

# Installer les outils système nécessaires
RUN apt-get update && apt-get install -y \
    nmap \
    hydra \
    aircrack-ng \
    tshark \
    curl \
    git \
    gnupg \
    lsb-release \
    ca-certificates \
    wget \
    openjdk-17-jre-headless \
    build-essential \
    libpcap-dev \
    && apt-get clean

# Installer Nikto
RUN git clone https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /usr/local/bin/nikto

# Installer OWASP ZAP (version 2.16.0 depuis SourceForge)
RUN mkdir -p /opt/zap && \
    wget https://sourceforge.net/projects/zap.mirror/files/v2.16.0/ZAP_2.16.0_Linux.tar.gz/download -O /opt/zap/zap.tar.gz && \
    tar -xzf /opt/zap/zap.tar.gz -C /opt/zap --strip-components=1 && \
    ln -s /opt/zap/zap.sh /usr/local/bin/zap

# Installer Metasploit via Kali
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list.d/kali.list && \
    curl -fsSL https://archive.kali.org/archive-key.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/kali.gpg && \
    apt-get update && apt-get install -y metasploit-framework && \
    ln -s /usr/bin/msfconsole /usr/local/bin/msfconsole && \
    ln -s /usr/bin/msfvenom /usr/local/bin/msfvenom

# Installer les dépendances Python
RUN pip install --upgrade pip && pip install -r requirements.txt

EXPOSE 5000
CMD ["python", "app.py"]

# Copie les certificats
COPY certs/ certs/

