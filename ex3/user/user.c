#include "interface.h"
#include "log_handler.h"
#include "rules_handler.h"

#define RULES_PATH "/sys/class/fw/rules/rules"
#define LOG_SYS_PATH "/sys/class/fw/log/reset"
#define LOG_DEV_PATH "/sys/class/fw/log/reset"

const uint8_t RULE_BUF_SIZE =
    20 + sizeof(direction_t) + sizeof(ack_t) + 2 * sizeof(uint32_t) + 2 * sizeof(uint16_t) + 4 * sizeof(uint8_t);

const uint8_t LOG_ROW_BUF_SIZE = sizeof(unsigned long) + 2 * sizeof(uint8_t) + 2 * sizeof(uint32_t) +
                                 2 * sizeof(uint16_t) + sizeof(reason_t) + sizeof(unsigned int);

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

            INFO("Showing rules...")

            fw_file = fopen(RULES_PATH, "rb");
            if (fw_file == NULL)
            {
                INFO("Can't read from rules device in sysfs")
                return EXIT_FAILURE;
            }

            uint8_t rules_amount;
            if (fread(&rules_amount, 1, 1, fw_file) == 0)
            {
                INFO("Rule table isn't active")
                return EXIT_FAILURE;
            }

            for (uint8_t i = 0; i < rules_amount; i++)
            {
                // Read buffer from rules device
                if (fread(rule_buf, RULE_BUF_SIZE, 1, fw_file) != 1)
                {
                    INFO("An reading error from rules device occurred")
                }

                // Convert buffer to rule struct
                buf2rule(&rule, rule_buf);

                // Convert rule struct to human-readable string
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

            INFO("Loading rules...")

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
                INFO("Can't write to rules device in sysfs")
            }

            // Writing the amount of rules first
            fwrite(&rules_ind, 1, 1, fw_file);

            char rule_buf[RULE_BUF_SIZE];
            for (uint8_t i = 0; i < rules_ind; i++)
            {
                // Convert rule struct to buffer
                rule2buf(rules + i, rule_buf);

                // Write buffer to rules device
                fwrite(rule_buf, RULE_BUF_SIZE, 1, fw_file);
            }

            INFO("Rules loaded successfuly")
            return EXIT_SUCCESS;
        }

        else if (strcmp(command, "show_log") == 0) // Unhandled
        {
            INFO("Showing log...")

            fw_file = fopen(LOG_DEV_PATH, "r");

            fclose(fw_file);

            DINFO("unhandled")
            return EXIT_SUCCESS;
        }

        else if (strcmp(command, "clear_log") == 0) // Unhandled
        {
            INFO("Clearing log...")

            fw_file = fopen(LOG_SYS_PATH, "w");

            fclose(fw_file);

            INFO("Log has been cleared")
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