FROM alpine:3.10

ADD aws-sg-updater /usr/local/bin/aws-sg-updater

CMD "/usr/local/bin/draft"
