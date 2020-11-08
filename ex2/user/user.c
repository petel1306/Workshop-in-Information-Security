#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FILE_PATH "/sys/class/Top_Class/Top_Class_NF_stats/sysfs_att"
#define UINT_SIZE sizeof(unsigned int)
#define UINT_2SIZE (sizeof(unsigned int) << 1) //  == UINT_SIZE * 2

int main(int argc, char *argv[])
{
    FILE *sysfs_fp;
    if (argc == 1)
    {
        sysfs_fp = fopen(FILE_PATH, "rb");
        if (sysfs_fp == NULL)
        {
            printf("Can't open sysfs_device file\n");
            return EXIT_FAILURE;
        }

        char buf[8];
        unsigned int accept_cnt, drop_cnt;

        if (fread(buf, UINT_2SIZE, 1, sysfs_fp) != UINT_2SIZE)
        {
            printf("Can't read from sysfs_device file\n");
        }
        memcpy((char *)&accept_cnt, buf, UINT_SIZE);
        memcpy((char *)&drop_cnt, buf + UINT_SIZE, UINT_SIZE);

        fclose(sysfs_fp);

        printf("Firewall Packets Summary:\n");
        printf("Number of accepted packets: %u\n", accept_cnt);
        printf("Number of dropped packets: %u\n", drop_cnt);
        printf("Total number of packets: %u\n", accept_cnt + drop_cnt);

        return EXIT_SUCCESS;
    }
    if (argc == 2)
    {
        char *input = argv[1];
        if (input[0] == '0' && input[1] == '\0')
        {
            sysfs_fp = fopen(FILE_PATH, "w");
            if (sysfs_fp == NULL)
            {
                printf("Can't open sysfs_device file\n");
                return EXIT_FAILURE;
            }

            if (fputc('*', sysfs_fp) == EOF)
            {
                printf("Can't write into sysfs_device file\n");
                return EXIT_FAILURE;
            }

            fclose(sysfs_fp);
            return EXIT_SUCCESS;
        }
        else
        {
            printf("Invalid argument value\n");
            return EXIT_FAILURE;
        }
    }
    printf("Invalid argument amount\n");
    return EXIT_FAILURE;
}