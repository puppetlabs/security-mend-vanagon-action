FROM ubuntu:focal
RUN apt update
RUN apt upgrade -y
RUN apt-get install -y build-essential
# install dependencies
RUN apt install -y ruby ruby-bundler ruby-dev git
RUN gem install vanagon
# install java
RUN apt-get install -y wget apt-transport-https gnupg
RUN wget -O - https://packages.adoptium.net/artifactory/api/gpg/key/public | apt-key add -
RUN echo "deb https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" | tee /etc/apt/sources.list.d/adoptium.list
RUN apt update
RUN apt install temurin-17-jdk -y
# move over the executables
ADD https://github.com/puppetlabs/security-mend-vanagon-action/releases/latest/download/vanagon_action /usr/local/bin/vanagon_action
# ADD vanagon_action /usr/local/bin/vanagon_action
RUN chmod +x /usr/local/bin/vanagon_action
# download mend unified agent
RUN wget -O /root/wss-unified-agent.jar https://unified-agent.s3.amazonaws.com/wss-unified-agent.jar
# startup script and startup
ADD docker_confs/start_script.sh /usr/local/bin/start_script.sh
RUN chmod +x /usr/local/bin/start_script.sh
CMD ["start_script.sh"]
