#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "hash_utils.h"

#define MAX_LINE_LENGTH 200
#define MAX_USERNAME_LENGTH 50
#define MAX_PASSWORD_LENGTH 50
#define MAX_COMMAND_LENGTH 50
//#define FILE_USERS "users.txt"
#define FILE_HASHED_USERS "hashed_users.txt"

// Function to trim newline characters
void trim_newline(char* str) {
    char* pos;
    if ((pos = strchr(str, '\n')) != NULL)
        *pos = '\0';
}

// Function to write the counter value back to the file
void update_counter_in_file(FILE* file, long position, int counter) {
    fseek(file, position, SEEK_SET);
    fprintf(file, "%d", counter);
}

int hex_to_salt_bytes(const char* hex_salt, unsigned char* salt, size_t salt_len) {
    if (hex_salt == NULL || strlen(hex_salt) != salt_len * 2) {
        return 0;
    }

    for (size_t i = 0; i < salt_len; i++) {
        if (sscanf(hex_salt + (2 * i), "%2hhx", &salt[i]) != 1) {
            return 0;
        }
    }

    return 1;
}

// Function to check if username and password match an entry in users.txt
int check_login(const char* username, const char* password) {

    FILE* file = fopen(FILE_HASHED_USERS, "r+");
    if (file == NULL) {
        printf("Could not open hashed_users.txt\n");
        return 0;
    }

    char line[MAX_LINE_LENGTH];
    char file_username[MAX_USERNAME_LENGTH];
    char file_salt_hex[SALT_LENGTH * 2 + 1];
    char file_hashed_password[MAX_HASH_LENGTH];
    char file_counter[2];
    char hashed_password[MAX_HASH_LENGTH];
    unsigned char file_salt[SALT_LENGTH];

    while (fgets(line, sizeof(line), file)) {
        // Remove the newline character
        trim_newline(line);

        // Split the line into username and password
        char* token = strtok(line, ":");
        if (token != NULL) {
            strncpy(file_username, token, sizeof(file_username) - 1);
            file_username[sizeof(file_username) - 1] = '\0';
            token = strtok(NULL, ":");
            if (token != NULL) {
                strncpy(file_salt_hex, token, sizeof(file_salt_hex) - 1);
                file_salt_hex[sizeof(file_salt_hex) - 1] = '\0';
                token = strtok(NULL, ":");
                if (token != NULL) {
                    strncpy(file_hashed_password, token, sizeof(file_hashed_password) - 1);
                    file_hashed_password[sizeof(file_hashed_password) - 1] = '\0';
                    token = strtok(NULL, ":");
                    if (token != NULL) {
                        strncpy(file_counter, token, sizeof(file_counter) - 1);
                        file_counter[sizeof(file_counter) - 1] = '\0';
                    }
                }
            }
        }
        
        // Compare entered username and password with the file's values
        if (strcmp(username, file_username) == 0){
            if (!hex_to_salt_bytes(file_salt_hex, file_salt, SALT_LENGTH)) {
                fclose(file);
                return 0;
            }

            // Compute hashed salted password from user input
            hash_password(password, file_salt, hashed_password);
            
            if (strcmp(hashed_password, file_hashed_password) == 0) {
                //write back the counter value to 0 in the file
                long position = ftell(file) - strlen(file_counter) - 1;
                update_counter_in_file(file, position, 0);
                fclose(file);
                return 1;  // Login successful
            }
            else {
                // Increment the counter for failed login attempts
                int counter = atoi(file_counter);
                if (counter < 3) {
                    counter++;
                }
                //write back the new counter value to the file
                long position = ftell(file) - strlen(file_counter) - 1;
                update_counter_in_file(file, position, counter);
                if (counter >= 3) {
                    printf("Too many failed login attempts.\n");
                    sleep(5);
                }
                fclose(file);
                return 0;  // Wrong password for matched username
            }
        }
    }

    fclose(file);
    return 0;  // Login failed
}

int main() {
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char command[MAX_COMMAND_LENGTH];

    // Prompt user for username and password
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    trim_newline(username);  // Remove newline character

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    trim_newline(password);  // Remove newline character

    // Check login credentials
    if (check_login(username, password)) {
        printf("Login successful!\n");

        // Command prompt loop
        while (1) {
            printf("> ");
            scanf("%s", command);

            if (strcmp(command, "exit") == 0) {
                break;
            } else {
                printf("Unknown command.\nAllowed command is exit.\n");
            }
        }
    } else {
        printf("Login failed.\n");
    }

    return 0;
}