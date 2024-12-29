#!/bin/bash

SAFE_DIR="./safe"
INDEX_FILE="./safe/index.enc"
PASS_PHRASE_FILE="./safe/passphrase"
PASS_PHRASE=""

# Function to check and install required packages
check_dependencies() {
    for pkg in openssl whiptail; do
        if ! command -v "$pkg" &>/dev/null; then
            echo "Installing $pkg..."
            if command -v apt &>/dev/null; then
                sudo apt update && sudo apt install -y "$pkg"
            elif command -v dnf &>/dev/null; then
                sudo dnf install -y "$pkg"
            elif command -v pacman &>/dev/null; then
                sudo pacman -Syu --noconfirm "$pkg"
            else
                echo "Error: Package manager not supported. Install $pkg manually." >&2
                exit 1
            fi
        fi
    done
}

# Function to initialize safe directory and passphrase
initialize() {
    mkdir -p "$SAFE_DIR"

    if [[ ! -f "$PASS_PHRASE_FILE" ]]; then
        PASS_PHRASE=$(whiptail --passwordbox "Set a secure passphrase for the password manager:" 10 60 3>&1 1>&2 2>&3)
        echo "$PASS_PHRASE" > "$PASS_PHRASE_FILE"
        chmod 600 "$PASS_PHRASE_FILE"
    else
        PASS_PHRASE=$(cat "$PASS_PHRASE_FILE")
    fi

    if [[ ! -f "$INDEX_FILE" ]]; then
        touch "$SAFE_DIR/index.tmp"
        openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/index.tmp" -out "$INDEX_FILE"
        rm -f "$SAFE_DIR/index.tmp"
    fi
}

# Function to display the main menu
menu() {
    whiptail --title "Password Manager" --menu "Choose an option:" 20 60 6 \
        "1" "Add a new password" \
        "2" "Retrieve a password" \
        "3" "View all saved services" \
        "4" "Delete a password" \
        "5" "Generate a unique password" \
        "6" "Exit" 3>&1 1>&2 2>&3 || echo "exit"
}

# Function to handle cancellations
handle_cancel() {
    [[ -z $1 ]] && return 1 || return 0
}

# Function to add a password
add_password() {
    valid_input=true

    while true; do
        service=$(whiptail --inputbox "Enter the service name (e.g., Gmail):" 10 60 3>&1 1>&2 2>&3 || echo "")
        handle_cancel "$service" || { valid_input=false; break; }
        service=$(echo "$service" | xargs)
        if [[ -z "$service" ]]; then
            whiptail --msgbox "Service name cannot be empty or only spaces. Please try again." 10 60
        elif [[ ! "$service" =~ ^[a-zA-Z0-9._-]+$ ]]; then
            whiptail --msgbox "Service name can only contain letters, numbers, dots, dashes, and underscores. Please try again." 10 60
        else
            break
        fi
    done

    if ! $valid_input; then return; fi

    while true; do
        username=$(whiptail --inputbox "Enter the username:" 10 60 3>&1 1>&2 2>&3 || echo "")
        handle_cancel "$username" || { valid_input=false; break; }
        username=$(echo "$username" | xargs)
        if [[ -z "$username" ]]; then
            whiptail --msgbox "Username cannot be empty or only spaces. Please try again." 10 60
        elif [[ ! "$username" =~ ^[a-zA-Z0-9._@+-]+$ ]]; then
            whiptail --msgbox "Username can only contain letters, numbers, dots, underscores, @, dashes, and plus signs. Please try again." 10 60
        else
            break
        fi
    done

    if ! $valid_input; then return; fi

    while true; do
        password=$(whiptail --passwordbox "Enter the password:" 10 60 3>&1 1>&2 2>&3 || echo "")
        handle_cancel "$password" || { valid_input=false; break; }
        password=$(echo "$password" | xargs)
        if [[ -z "$password" ]]; then
            whiptail --msgbox "Password cannot be empty or only spaces. Please try again." 10 60
        else
            break
        fi
    done

    if ! $valid_input; then return; fi

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
    if [[ ! -s "$INDEX_FILE" ]]; then
        whiptail --msgbox "No passwords have been saved yet. Please save a password first!" 10 60
        return
    fi

    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$INDEX_FILE" -out "$SAFE_DIR/index.tmp" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        whiptail --msgbox "Failed to decrypt index file. Check your passphrase!" 10 60
        return
    fi

    services=$(cut -d: -f1 "$SAFE_DIR/index.tmp" | sort | uniq)
    if [[ -z "$services" ]]; then
        whiptail --msgbox "No passwords have been saved yet. Please save a password first!" 10 60
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    service=$(whiptail --menu "Choose a service:" 20 60 10 $(echo "$services" | nl -w2 -s' ') 3>&1 1>&2 2>&3)
    selected_service=$(echo "$services" | sed -n "${service}p")

    if [[ -z $selected_service ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    username_file=$(grep "^$selected_service:" "$SAFE_DIR/index.tmp" | head -n 1 | cut -d: -f2,3 --output-delimiter=' ')
    username=$(echo "$username_file" | awk '{print $1}')
    file_name=$(echo "$username_file" | awk '{print $2}')
    password=$(openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/$file_name" 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        whiptail --msgbox "Failed to decrypt the password for $selected_service. Check your passphrase!" 10 60
    else
        whiptail --msgbox "Service:  $selected_service\nUsername: $username\nPassword: $password" 15 60
    fi
    rm -f "$SAFE_DIR/index.tmp"
}

# Function to view all saved services
view_services() {
    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$INDEX_FILE" -out "$SAFE_DIR/index.tmp" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        whiptail --msgbox "Failed to decrypt index file. Check your passphrase!" 10 60
        return
    fi

    services=$(cut -d: -f1 "$SAFE_DIR/index.tmp" | sort | uniq)
    if [[ -z $services ]]; then
        whiptail --msgbox "No services found!" 10 60
    else
        whiptail --msgbox "Saved services:\n\n$services" 20 60
    fi

    rm -f "$SAFE_DIR/index.tmp"
}

# Function to delete a password
delete_password() {
    if [[ ! -s "$INDEX_FILE" ]]; then
        whiptail --msgbox "No passwords have been saved yet. Please save a password first!" 10 60
        return
    fi

    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$INDEX_FILE" -out "$SAFE_DIR/index.tmp" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        whiptail --msgbox "Failed to decrypt index file. Check your passphrase!" 10 60
        return
    fi

    services=$(cut -d: -f1 "$SAFE_DIR/index.tmp" | sort | uniq)
    if [[ -z "$services" ]]; then
        whiptail --msgbox "No passwords have been saved yet. Please save a password first!" 10 60
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    service=$(whiptail --menu "Choose a service to delete:" 20 60 10 $(echo "$services" | nl -w2 -s' ') 3>&1 1>&2 2>&3)
    selected_service=$(echo "$services" | sed -n "${service}p")

    if [[ -z $selected_service ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    entry=$(grep "^$selected_service:" "$SAFE_DIR/index.tmp" | head -n 1)
    username=$(echo "$entry" | cut -d: -f2)
    file_name=$(echo "$entry" | cut -d: -f3)

    # Remove entry from index
    grep -v "^$selected_service:" "$SAFE_DIR/index.tmp" > "$SAFE_DIR/index.updated.tmp"
    mv "$SAFE_DIR/index.updated.tmp" "$SAFE_DIR/index.tmp"

    # Re-encrypt the index
    openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/index.tmp" -out "$INDEX_FILE"
    rm -f "$SAFE_DIR/index.tmp"

    # Remove the password file
    if [[ -f "$SAFE_DIR/$file_name" ]]; then
        rm -f "$SAFE_DIR/$file_name"
        whiptail --msgbox "Password for $selected_service deleted successfully!" 10 60
    else
        whiptail --msgbox "Failed to find the password file for $selected_service!" 10 60
    fi
}

# Function to generate a unique password
generate_password() {
    length=$(whiptail --inputbox "Enter the desired password length (minimum 8):" 10 60 3>&1 1>&2 2>&3 || echo "")
    handle_cancel "$length" || return

    if ! [[ "$length" =~ ^[0-9]+$ ]] || [[ "$length" -lt 8 ]]; then
        whiptail --msgbox "Invalid length. Please enter a number greater than or equal to 8." 10 60
        return
    fi

    # Generate a cryptographically secure password
    password=$(openssl rand -base64 $((length * 3 / 4)) | tr -d '\n' | head -c "$length")

    whiptail --msgbox "Generated Password:\n$password" 10 60
}

# Main script
check_dependencies
initialize

while true; do
    choice=$(menu)
    [[ $choice == "exit" ]] && break
    case $choice in
        1) add_password ;;
        2) retrieve_password ;;
        3) view_services ;;
        4) delete_password ;;
        5) generate_password ;;
        6) exit ;;
        *) whiptail --msgbox "Invalid option!" 10 60 ;;
    esac
done
