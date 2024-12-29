#!/bin/bash

# Enhanced Password Manager in Bash
# Requires: openssl, whiptail

SAFE_DIR="./safe"
INDEX_FILE="./safe/index.enc"
PASS_PHRASE="YourSuperSecurePassphrase"  # Change this to your secure passphrase

# Ensure the safe directory exists
mkdir -p "$SAFE_DIR"

# Function to initialize safe directory and index
initialize() {
    if [[ ! -f "$INDEX_FILE" ]]; then
        touch "$SAFE_DIR/index.tmp"
        openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/index.tmp" -out "$INDEX_FILE"
        rm -f "$SAFE_DIR/index.tmp"
    fi
}

# Function to display the main menu
menu() {
    whiptail --title "Password Manager" --menu "Choose an option:" 20 60 5 \
        "1" "Add a new password" \
        "2" "Retrieve a password" \
        "3" "View all saved services" \
        "4" "Delete a password" \
        "5" "Exit" 3>&1 1>&2 2>&3
}

# Function to add a password
add_password() {
    service=$(whiptail --inputbox "Enter the service name (e.g., Gmail):" 10 60 3>&1 1>&2 2>&3)
    username=$(whiptail --inputbox "Enter the username:" 10 60 3>&1 1>&2 2>&3)
    password=$(whiptail --passwordbox "Enter the password:" 10 60 3>&1 1>&2 2>&3)

    if [[ -z $service || -z $username || -z $password ]]; then
        whiptail --msgbox "All fields are required!" 10 60
        return
    fi

    file_name=$(openssl rand -hex 12)
    echo "$password" | openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -out "$SAFE_DIR/$file_name"
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$INDEX_FILE" -out "$SAFE_DIR/index.tmp"
    echo "$service:$username:$file_name" >> "$SAFE_DIR/index.tmp"
    openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/index.tmp" -out "$INDEX_FILE"
    rm -f "$SAFE_DIR/index.tmp"

    whiptail --msgbox "Password for $service added successfully!" 10 60
}

# Function to retrieve a password
retrieve_password() {
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$INDEX_FILE" -out "$SAFE_DIR/index.tmp"
    services=$(cut -d: -f1 "$SAFE_DIR/index.tmp" | sort | uniq)
    service=$(whiptail --menu "Choose a service:" 20 60 10 $(echo "$services" | nl -w2 -s' ') 3>&1 1>&2 2>&3)
    selected_service=$(echo "$services" | sed -n "${service}p")

    if [[ -z $selected_service ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    username_file=$(grep "^$selected_service:" "$SAFE_DIR/index.tmp" | head -n 1 | cut -d: -f2,3 --output-delimiter=' ')
    username=$(echo "$username_file" | awk '{print $1}')
    file_name=$(echo "$username_file" | awk '{print $2}')
    password=$(openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/$file_name")

    whiptail --msgbox "Service: $selected_service\nUsername: $username\nPassword: $password" 15 60
    rm -f "$SAFE_DIR/index.tmp"
}

# Function to view all saved services
view_services() {
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$INDEX_FILE" -out "$SAFE_DIR/index.tmp"
    services=$(cut -d: -f1 "$SAFE_DIR/index.tmp" | sort | uniq)
    whiptail --msgbox "Saved services:\n\n$services" 20 60
    rm -f "$SAFE_DIR/index.tmp"
}

# Function to delete a password
delete_password() {
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$INDEX_FILE" -out "$SAFE_DIR/index.tmp"
    services=$(cut -d: -f1 "$SAFE_DIR/index.tmp" | sort | uniq)
    service=$(whiptail --menu "Choose a service to delete:" 20 60 10 $(echo "$services" | nl -w2 -s' ') 3>&1 1>&2 2>&3)
    selected_service=$(echo "$services" | sed -n "${service}p")

    if [[ -z $selected_service ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    username_file=$(grep "^$selected_service:" "$SAFE_DIR/index.tmp" | head -n 1 | cut -d: -f2,3 --output-delimiter=' ')
    file_name=$(echo "$username_file" | awk '{print $2}')

    sed -i "/^$selected_service:/d" "$SAFE_DIR/index.tmp"
    rm -f "$SAFE_DIR/$file_name"
    openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/index.tmp" -out "$INDEX_FILE"
    rm -f "$SAFE_DIR/index.tmp"

    whiptail --msgbox "Password for $selected_service deleted successfully!" 10 60
}

# Main loop
initialize
while true; do
    choice=$(menu)
    case $choice in
        1) add_password ;;
        2) retrieve_password ;;
        3) view_services ;;
        4) delete_password ;;
        5) exit ;;
        *) whiptail --msgbox "Invalid option!" 10 60 ;;
    esac
done