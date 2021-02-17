#include "conn_handler.h"
#include "interface.h"
#include "log_handler.h"
#include "rules_handler.h"

#define RULES_PATH "/sys/class/fw/rules/rules"
#define LOG_SYS_PATH "/sys/class/fw/fw_log/reset"
#define LOG_DEV_PATH "/dev/fw_log"
#define CONN_SYS_PATH "/sys/class/fw/conns/conns"

// Just to make sure :)
#define MAX_RULE_LINE 200
#define MAX_LOG_LINE 200
#define MAX_CONN_LINE 100

const uint8_t RULE_BUF_SIZE =
    20 + sizeof(direction_t) + sizeof(ack_t) + 2 * sizeof(uint32_t) + 2 * sizeof(uint16_t) + 4 * sizeof(uint8_t);

const uint8_t LOG_ROW_BUF_SIZE = sizeof(unsigned long) + 2 * sizeof(uint8_t) + 2 * sizeof(uint32_t) +
                                 2 * sizeof(uint16_t) + sizeof(reason_t) + sizeof(unsigned int);

const uint8_t CONN_BUF_SIZE = 2 * sizeof(uint32_t) + 2 * sizeof(uint16_t) + sizeof(tcp_state_t);

int main(int argc, char *argv[])
{
    FILE *fw_file;
    if (argc > 1)
    {
        char *command = argv[1];

        DINFO("command = %s", command)

        if (strcmp(command, "show_rules") == 0 && argc == 2)
        {
            char rule_buf[RULE_BUF_SIZE];
            rule_t rule;
            char rule_str[MAX_RULE_LINE];

            DINFO("Showing rules...")

            fw_file = fopen(RULES_PATH, "rb");
            if (fw_file == NULL)
            {
                INFO("Can't open (on read mode) rules device in /sys")
                return EXIT_FAILURE;
            }

            uint8_t rules_amount;
            if (fread(&rules_amount, 1, 1, fw_file) == 0)
            {
                INFO("Rule table isn't active")
                return EXIT_SUCCESS;
            }

            for (uint8_t i = 0; i < rules_amount; i++)
            {
                // Read buffer from rules device
                if (fread(rule_buf, RULE_BUF_SIZE, 1, fw_file) != 1)
                {
                    INFO("An reading error from rules device has occurred")
                }

                // Convert buffer to rule struct
                buf2rule(&rule, rule_buf);

                // Convert rule struct to a human-readable string
                rule2str(&rule, rule_str);

                // Print the string to the user
                printf("%s", rule_str);
            }
            fclose(fw_file);

            return EXIT_SUCCESS;
        }

        else if (strcmp(command, "load_rules") == 0 && argc == 3)
        {
            rule_t rules[MAX_RULES];
            char rule_str[MAX_RULE_LINE];
            uint8_t rules_ind;

            DINFO("Loading rules...")

            const char *load_path = argv[2];
            FILE *rules_file = fopen(load_path, "r");
            if (rules_file == NULL)
            {
                INFO("Can't load rules from: %s", load_path)
                return EXIT_FAILURE;
            }

            for (rules_ind = 0; rules_ind < MAX_RULES; rules_ind++)
            {
                // Get a line from the rules file
                if (fgets(rule_str, MAX_RULE_LINE, rules_file) == NULL)
                {

                    break;
                }
                DINFO("Rule %d : %s", rules_ind + 1, rule_str)

                // Convert rule human-readable string to a rule struct
                uint8_t valid_rule = str2rule(rules + rules_ind, rule_str);
                if (!valid_rule)
                {
                    INFO("Rule number %d is unvalid!", rules_ind)
                    return EXIT_FAILURE;
                }
            }

            // We have finished reading the rules, lets write them to the device
            fw_file = fopen(RULES_PATH, "wb");
            if (fw_file == NULL)
            {
                INFO("Can't open (on write mode) rules device in /sys")
            }

            // Writing the amount of rules first
            if (fwrite(&rules_ind, 1, 1, fw_file) != 1)
            {
                INFO("An writing error to rules device has occurred")
            }

            char rule_buf[RULE_BUF_SIZE];
            for (uint8_t i = 0; i < rules_ind; i++)
            {
                // Convert rule struct to buffer
                rule2buf(rules + i, rule_buf);

                // Write buffer to rules device
                if (fwrite(rule_buf, RULE_BUF_SIZE, 1, fw_file) != 1)
                {
                    INFO("An writing error to rules device has occurred")
                }
            }

            INFO("The rules have been loaded successfuly")
            return EXIT_SUCCESS;
        }

        else if (strcmp(command, "show_log") == 0)
        {
            char log_row_buf[LOG_ROW_BUF_SIZE];
            log_row_t log_row;
            char log_row_str[MAX_LOG_LINE];

            DINFO("Showing log...")

            fw_file = fopen(LOG_DEV_PATH, "rb");
            if (fw_file == NULL)
            {
                INFO("Can't open (on read mode) log device in /dev")
                return EXIT_FAILURE;
            }

            uint32_t rows_amount;
            if (fread(&rows_amount, sizeof(uint32_t), 1, fw_file) != 1)
            {
                INFO("An reading error from log device has occurred")
                return EXIT_FAILURE;
            }
            DINFO("Amount of rows in log: %d", rows_amount);

            // Print the log headline to the user
            log_headline(log_row_str);
            printf("%s", log_row_str);

            for (uint8_t i = 0; i < rows_amount; i++)
            {
                // Read buffer from log device
                if (fread(log_row_buf, LOG_ROW_BUF_SIZE, 1, fw_file) != 1)
                {
                    INFO("An reading error from log device has occurred")
                }

                // Convert buffer to log_row struct
                buf2log_row(&log_row, log_row_buf);

                // Convert log_row struct to a human-readable string
                log_row2str(&log_row, log_row_str);

                // Print the string to the user
                printf("%s", log_row_str);
            }

            fclose(fw_file);
            return EXIT_SUCCESS;
        }

        else if (strcmp(command, "clear_log") == 0)
        {
            DINFO("Clearing log...")

            fw_file = fopen(LOG_SYS_PATH, "w");
            if (fw_file == NULL)
            {
                INFO("Can't open (on write mode) log device in /sys")
                return EXIT_FAILURE;
            }

            if (fputc('$', fw_file) == EOF)
            {
                INFO("An writing error to log device has occurred")
                return EXIT_FAILURE;
            }

            fclose(fw_file);

            INFO("The log has been cleared successfuly")
            return EXIT_SUCCESS;
        }

        else if (strcmp(command, "show_conns") == 0)
        {
            char conn_buf[CONN_BUF_SIZE];
            connection_t conn;
            char conn_str[MAX_CONN_LINE];

            DINFO("showing connections");

            fw_file = fopen(CONN_SYS_PATH, "rb");
            if (fw_file == NULL)
            {
                INFO("Can't open (on read mode) conns device in /dev")
                return EXIT_FAILURE;
            }

            uint32_t connections_amount;
            if (fread(&connections_amount, sizeof(uint32_t), 1, fw_file) != 1)
            {
                INFO("An reading error from conns device has occurred")
                return EXIT_FAILURE;
            }
            DINFO("Amount of connections: %d", connections_amount);

            // Print the connection headline to the user
            conn_headline(conn_str);
            printf("%s", conn_str);

            for (uint8_t i = 0; i < connections_amount; i++)
            {
                // Read buffer from log device
                if (fread(conn_buf, CONN_BUF_SIZE, 1, fw_file) != 1)
                {
                    INFO("An reading error from conns device has occurred")
                }

                // Convert buffer to connection struct
                buf2conn(&conn, conn_buf);

                // Convert connection struct to a human-readable string
                conn2str(&conn, conn_str);

                // Print the string to the user
                printf("%s", conn_str);
            }

            fclose(fw_file);
            return EXIT_SUCCESS;
        }

        else
        {
            INFO("Unrecognized command\n")
            return EXIT_FAILURE;
        }
    }
    INFO("Invalid argument amount\n")
    return EXIT_FAILURE;
}