#!/bin/bash

# exit when any command fails
set -e
# keep track of the last executed command
trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
# echo an error message before exiting
trap 'echo "\"${last_command}\" command failed with exit code $?."' ERR

# copy ngrok agent bin
unzip ngrok*.zip
rm ngrok*.zip
chmod +x ngrok
# TODO remove in next cleep version (after v0.1.1)
mkdir -p /var/opt/cleep/modules/bin/ngrok/
cp -f ngrok /var/opt/cleep/modules/bin/ngrok/

# The running process keeps the previous binary until the service restarts.
if systemctl is-active --quiet ngrok.service 2>/dev/null; then
    systemctl restart ngrok.service || echo "ngrok service restart failed"
fi

