#!/bin/bash

# Command to be executed
command_to_run="./tls_client"

# Maximum execution time in seconds (2 hours)
max_execution_time=20

# Function to handle interrupt signal (Ctrl+C)
cleanup() {
    echo "Execution interrupted. Exiting."
    exit 1
}

# Set up trap to catch interrupt signal
trap cleanup INT

while true; do
    # Run the command with a timeout
    timeout $max_execution_time $command_to_run

    # Check the exit status of the command
    case $? in
        0) echo "Execution completed within the time limit."; break ;;
        124) echo "Execution time exceeded the limit. Repeating the execution." ;;
        *) echo "Command terminated with an unexpected exit status. Repeating the execution." ;;
    esac
done
