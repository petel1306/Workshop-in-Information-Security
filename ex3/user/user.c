#include "interface.h"
#include "rules_handler.h"

#define RULES_PATH "/sys/class/fw/rules/rules"
#define LOG_SYS_PATH "/sys/class/fw/log/reset"
#define LOG_DEV_PATH "/sys/class/fw/log/reset"

int main(int argc, char *argv[])
{
    FILE *fw_file;
    if (argc > 1)
    {
        char *command = argv[1];

        if (strcmp(command, "show_rules") && argc == 2)
        {
            char rule_buf[RULE_SIZE];
            rule_t rule;
            char rule_str[MAX_RULE_LINE];

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
                fread(rule_buf, RULE_SIZE, 1, fw_file);

                // Convert buffer to rule struct
                buf2rule(&rule, rule_buf);

                // Convert rule struct to human-readable string
                rule2str(&rule, rule_str);

                // Print the string to the user
                printf("%s", rule_str);
            }

            fclose(fw_file);
        }

        else if (strcmp(command, "load_rules") && argc == 3)
        {
            rule_t rules[MAX_RULES];
            char rule_str[MAX_RULE_LINE];
            uint8_t rules_ind;

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
                char *read_ptr = fgets(rule_str, MAX_RULE_LINE, rules_file);
                if (fscanf(rules_file, "%100s", rule_str) != 1)
                {
                    break;
                }

                // Convert rule human-readable string to a rule struct
                uint8_t valid_rule = str2rule(rules + rules_ind, rule_str);
                if (!valid_rule)
                {
                    INFO("Rule number %d is unvalid!", rules_ind)
                    return EXIT_FAILURE;
                }
            }

            // Validates the file dosn't contain any additional non whitespace characters
            if (fscanf(rules_file, "%1s", rule_str) == 1)
            {
                INFO("To much rules! (number of rules greater than %d", MAX_RULES)
                return EXIT_FAILURE;
            }

            // We have finished read, lets write!
            fw_file = fopen(RULES_PATH, "wb");
            if (rules_file == NULL)
            {
                INFO("Can't write to rules device in sysfs")
            }

            fwrite(&rules_ind, 1, 1, fw_file);

            char rule_buf[RULE_SIZE];
            for (uint8_t i = 0; i < rules_ind; i++)
            {
                // Convert rule struct to buffer
                rule2buf(rules + i, rule_buf);

                // Write buffer to rules device
                fwrite(rule_buf, RULE_SIZE, 1, fw_file);
            }

            INFO("Rules loaded successfuly")
            return EXIT_SUCCESS;
        }

        else if (strcmp(command, "show_log"))
        {
            fw_file = fopen(LOG_DEV_PATH, "r");

            INFO("unhandled")
        }

        else if (strcmp(command, "clear_log"))
        {
            fw_file = fopen(LOG_SYS_PATH, "w");

            INFO("unhandled")
        }

        return EXIT_SUCCESS;
    }
    INFO("Invalid argument amount\n")
    return EXIT_FAILURE;
}