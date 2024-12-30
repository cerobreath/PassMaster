#!/bin/bash

SAFE_DIR="$HOME/.local/share/passmaster"
INDEX_FILE="$SAFE_DIR/index.enc"
PASS_PHRASE_FILE="$SAFE_DIR/passphrase.enc"

# Function to initialize safe directory and passphrase
initialize() {
    # Secure the directory
    mkdir -p "$SAFE_DIR"
    chmod 700 "$SAFE_DIR"

    if [[ ! -f "$PASS_PHRASE_FILE" ]]; then
        local user_passphrase=$(whiptail --passwordbox "Set a secure passphrase for the password manager:" 10 60 3>&1 1>&2 2>&3)
        if [[ -z "$user_passphrase" ]]; then
            whiptail --msgbox "Passphrase cannot be empty. Initialization failed!" 10 60
            exit 1
        fi

        local master_key
        master_key=$(openssl rand -hex 32)
        echo "$master_key" | openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$user_passphrase" -out "$PASS_PHRASE_FILE"
        chmod 600 "$PASS_PHRASE_FILE"
    fi

    if [[ ! -f "$INDEX_FILE" ]]; then
        touch "$SAFE_DIR/index.tmp"
        local master_key
        master_key=$(decrypt_passphrase)
        openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$master_key" -in "$SAFE_DIR/index.tmp" -out "$INDEX_FILE"
        rm -f "$SAFE_DIR/index.tmp"
    fi
}

# Function to decrypt passphrase
decrypt_passphrase() {
    local user_passphrase
    user_passphrase=$(whiptail --passwordbox "Enter your secure passphrase to unlock the manager:" 10 60 3>&1 1>&2 2>&3)
    if [[ -z "$user_passphrase" ]]; then
        whiptail --msgbox "Passphrase cannot be empty. Access denied!" 10 60
        exit 1
    fi

    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$user_passphrase" -in "$PASS_PHRASE_FILE" 2>/dev/null || {
        whiptail --msgbox "Failed to decrypt passphrase. Access denied!" 10 60
        exit 1
    }
}

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

# Function to display the main menu
menu() {
    whiptail --title "Password Manager" --menu "Choose an option:" 20 60 6 \
        "1" "Add a new password" \
        "2" "Retrieve a password" \
        "3" "Edit a saved password" \
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

    # Validate service name
    while true; do
        service=$(whiptail --inputbox "Enter the service name (e.g., Gmail):" 10 60 3>&1 1>&2 2>&3 || echo "")
        handle_cancel "$service" || { valid_input=false; break; }
        service=$(echo "$service" | xargs)
        if [[ -z "$service" ]]; then
            whiptail --msgbox "Service name cannot be empty or only spaces. Please try again." 10 60
        elif [[ ${#service} -gt 30 ]]; then
            whiptail --msgbox "Service name cannot exceed 30 characters. Please try again." 10 60
        elif [[ ! "$service" =~ ^[a-zA-Z0-9._-]+$ ]]; then
            whiptail --msgbox "Service name can only contain letters, numbers, dots, dashes, and underscores. Please try again." 10 60
        else
            break
        fi
    done

    if ! $valid_input; then return; fi

    # Validate username
    while true; do
        username=$(whiptail --inputbox "Enter the username:" 10 60 3>&1 1>&2 2>&3 || echo "")
        handle_cancel "$username" || { valid_input=false; break; }
        username=$(echo "$username" | xargs)
        if [[ -z "$username" ]]; then
            whiptail --msgbox "Username cannot be empty or only spaces. Please try again." 10 60
        elif [[ ${#username} -gt 50 ]]; then
            whiptail --msgbox "Username cannot exceed 50 characters. Please try again." 10 60
        elif [[ ! "$username" =~ ^[a-zA-Z0-9._@+-]+$ ]]; then
            whiptail --msgbox "Username can only contain letters, numbers, dots, underscores, @, dashes, and plus signs. Please try again." 10 60
        else
            break
        fi
    done

    if ! $valid_input; then return; fi

    # Validate password and confirm it
    while true; do
        password=$(whiptail --passwordbox "Enter the password:" 10 60 3>&1 1>&2 2>&3 || echo "")
        handle_cancel "$password" || { valid_input=false; break; }
        password=$(echo "$password" | xargs)
        if [[ -z "$password" ]]; then
            whiptail --msgbox "Password cannot be empty or only spaces. Please try again." 10 60
        elif [[ ${#password} -lt 8 ]]; then
            whiptail --msgbox "Password must be at least 8 characters long. Please try again." 10 60
        elif [[ ${#password} -gt 64 ]]; then
            whiptail --msgbox "Password cannot exceed 64 characters. Please try again." 10 60
        else
            confirm_password=$(whiptail --passwordbox "Re-enter the password to confirm:" 10 60 3>&1 1>&2 2>&3 || echo "")
            handle_cancel "$confirm_password" || { valid_input=false; break; }
            confirm_password=$(echo "$confirm_password" | xargs)
            if [[ "$password" != "$confirm_password" ]]; then
                whiptail --msgbox "Passwords do not match. Please try again." 10 60
            else
                break
            fi
        fi
    done

    if ! $valid_input; then return; fi

    # Encrypt and store password
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

    services_and_users=$(cut -d: -f1,2 "$SAFE_DIR/index.tmp" | sort | uniq)
    if [[ -z "$services_and_users" ]]; then
        whiptail --msgbox "No passwords have been saved yet. Please save a password first!" 10 60
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    menu_items=()
    while IFS= read -r line; do
        service=$(echo "$line" | cut -d: -f1)
        username=$(echo "$line" | cut -d: -f2)
        display_name="$service ($username)"
        menu_items+=("$display_name" "")  # Додаємо лише опис для вибору
    done <<< "$services_and_users"

    choice=$(whiptail --menu "Choose a service:" 20 60 10 "${menu_items[@]}" 3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    selected_service=$(echo "$choice" | sed -E 's/\s+\(.*\)$//')
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

# Function to edit a password
edit_password() {
    if [[ ! -s "$INDEX_FILE" ]]; then
        whiptail --msgbox "No passwords have been saved yet. Please save a password first!" 10 60
        return
    fi

    openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$INDEX_FILE" -out "$SAFE_DIR/index.tmp" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        whiptail --msgbox "Failed to decrypt index file. Check your passphrase!" 10 60
        return
    fi

    services_and_users=$(cut -d: -f1,2 "$SAFE_DIR/index.tmp" | sort | uniq)
    if [[ -z "$services_and_users" ]]; then
        whiptail --msgbox "No passwords have been saved yet. Please save a password first!" 10 60
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    menu_items=()
    while IFS= read -r line; do
        service=$(echo "$line" | cut -d: -f1)
        username=$(echo "$line" | cut -d: -f2)
        display_name="$service ($username)"
        menu_items+=("$display_name" "")
    done <<< "$services_and_users"

    choice=$(whiptail --menu "Choose a service to edit:" 20 60 10 "${menu_items[@]}" 3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    selected_service=$(echo "$choice" | sed -E 's/\s+\(.*\)$//')

    entry=$(grep "^$selected_service:" "$SAFE_DIR/index.tmp" | head -n 1)
    username=$(echo "$entry" | cut -d: -f2)
    file_name=$(echo "$entry" | cut -d: -f3)
    old_password=$(openssl enc -aes-256-cbc -d -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/$file_name" 2>/dev/null)

    if [[ $? -ne 0 ]]; then
        whiptail --msgbox "Failed to decrypt the password for $selected_service. Check your passphrase!" 10 60
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    input_password=$(whiptail --passwordbox "Enter the current password for $selected_service:" 10 60 3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    if [[ "$input_password" != "$old_password" ]]; then
        whiptail --msgbox "Incorrect password. Edit operation canceled." 10 60
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    valid_input=true

    new_service=$(whiptail --inputbox "Enter new service name (or press OK to keep \"$selected_service\"):" 10 60 "$selected_service" 3>&1 1>&2 2>&3 || echo "")
    handle_cancel "$new_service" || { valid_input=false; rm -f "$SAFE_DIR/index.tmp"; return; }
    new_service=$(echo "$new_service" | xargs)

    new_username=$(whiptail --inputbox "Enter new username (or press OK to keep \"$username\"):" 10 60 "$username" 3>&1 1>&2 2>&3 || echo "")
    handle_cancel "$new_username" || { valid_input=false; rm -f "$SAFE_DIR/index.tmp"; return; }
    new_username=$(echo "$new_username" | xargs)

    while true; do
        new_password=$(whiptail --passwordbox "Enter new password:" 10 60 3>&1 1>&2 2>&3)
        if [[ $? -ne 0 ]]; then
            rm -f "$SAFE_DIR/index.tmp"
            return
        fi

        new_password_confirm=$(whiptail --passwordbox "Confirm new password:" 10 60 3>&1 1>&2 2>&3)
        if [[ $? -ne 0 ]]; then
            rm -f "$SAFE_DIR/index.tmp"
            return
        fi

        if [[ "$new_password" != "$new_password_confirm" ]]; then
            whiptail --msgbox "Passwords do not match. Please try again." 10 60
        else
            break
        fi
    done

    echo "$new_password" | openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -out "$SAFE_DIR/$file_name"

    sed -i "/^$selected_service:/d" "$SAFE_DIR/index.tmp"
    echo "$new_service:$new_username:$file_name" >> "$SAFE_DIR/index.tmp"

    openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/index.tmp" -out "$INDEX_FILE"
    rm -f "$SAFE_DIR/index.tmp"

    whiptail --msgbox "Password for $selected_service successfully updated!" 10 60
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

    services_and_users=$(cut -d: -f1,2 "$SAFE_DIR/index.tmp" | sort | uniq)
    if [[ -z "$services_and_users" ]]; then
        whiptail --msgbox "No passwords have been saved yet. Please save a password first!" 10 60
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    menu_items=()
    while IFS= read -r line; do
        service=$(echo "$line" | cut -d: -f1)
        username=$(echo "$line" | cut -d: -f2)
        display_name="$service ($username)"
        menu_items+=("$display_name" "")
    done <<< "$services_and_users"

    choice=$(whiptail --menu "Choose a service to delete:" 20 60 10 "${menu_items[@]}" 3>&1 1>&2 2>&3)
    if [[ $? -ne 0 ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    selected_service=$(echo "$choice" | sed -E 's/\s+\(.*\)$//')

    entry=$(grep "^$selected_service:" "$SAFE_DIR/index.tmp" | head -n 1)
    username=$(echo "$entry" | cut -d: -f2)
    file_name=$(echo "$entry" | cut -d: -f3)

    whiptail --yesno "Are you sure you want to delete the password for the service:\n\nService: $selected_service\nUsername: $username" 15 60
    if [[ $? -ne 0 ]]; then
        rm -f "$SAFE_DIR/index.tmp"
        return
    fi

    grep -v "^$selected_service:" "$SAFE_DIR/index.tmp" > "$SAFE_DIR/index.updated.tmp"
    mv "$SAFE_DIR/index.updated.tmp" "$SAFE_DIR/index.tmp"

    openssl enc -aes-256-cbc -salt -pbkdf2 -pass pass:"$PASS_PHRASE" -in "$SAFE_DIR/index.tmp" -out "$INDEX_FILE"
    rm -f "$SAFE_DIR/index.tmp"

    if [[ -f "$SAFE_DIR/$file_name" ]]; then
        rm -f "$SAFE_DIR/$file_name"
        whiptail --msgbox "Password for $selected_service deleted successfully!" 10 60
    else
        whiptail --msgbox "Failed to find the password file for $selected_service!" 10 60
    fi
}

# Function to generate a unique password
generate_password() {
    while true; do
            length=$(whiptail --inputbox "Enter the desired password length (minimum 8, maximum 50):" 10 60 3>&1 1>&2 2>&3 || echo "")
            handle_cancel "$length" || return

            if [[ "$length" =~ ^[0-9]+$ ]] && [[ "$length" -ge 8 ]] && [[ "$length" -le 50 ]]; then
                break
            else
                whiptail --msgbox "Invalid length. Please enter a number between 8 and 50." 10 60
            fi
    done

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
        3) edit_password ;;
        4) delete_password ;;
        5) generate_password ;;
        6) exit ;;
        *) whiptail --msgbox "Invalid option!" 10 60 ;;
    esac
done
