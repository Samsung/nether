#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h> 
#include <time.h>

#define MAX_SAMPLES	100000
#define MAX_LABELS	10000
#define MAX_LABEL	255

char labels[MAX_LABELS][MAX_LABEL];

int change_label(const int n)
{
    FILE *fp = fopen ("/proc/self/attr/current", "w");
    
    if (fp == NULL)
    {
        perror("/proc/self/attr/current");
        return (1);
    }
    
    if (fwrite (labels[n], strlen(labels[n]), 1, fp) == 0)
    {
        perror("/proc/self/attr/current");
        fclose(fp);
        return (1);
    }
    
    fclose (fp);
    return (0);
}

int read_labels(const char *labels_file)
{
    FILE *fp = fopen(labels_file, "r");
    int nl = 0;

    if (fp == NULL)
    {
        perror(labels_file);
        return (1);
    }    
    
    while (!feof(fp))
    {
        if (fgets(labels[nl++], MAX_LABEL, fp) == NULL)
        {
            printf ("Read %d labels\n", nl);
            break;
        }
    }
    
    fclose(fp);
    return (0);
}

int con(const char *ip, const int n)
{
    int sockfd = 0;
    struct sockaddr_in serv_addr;
    
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        return 1;
    } 

    memset(&serv_addr, '0', sizeof(serv_addr)); 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(80); 

    if(inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0)
    {
        perror("inet_pton");
        return 1;
    } 

    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
       perror ("connect");
       return 1;
    }

    close (sockfd);
    
    return (0);
}

int main(int argc, char *argv[])
{
    int n = 0, conn_all = 0, avg_n = 0;
    long avg_every = 0;
    long avg_samples[MAX_SAMPLES] = {0};
    long elapsed_samples[MAX_SAMPLES] = {0};
    unsigned long avg_accumulator = 0;
    struct timespec tp_start, tp_end;
    
    if(argc != 5)
    {
        printf("Usage: %s <ip> <iter> <avg_every> <labels_file>\n", argv[0]);
        return (1);
    }

    if (read_labels(argv[4]))
    {
        printf("Can't read labels %s\n", argv[4]);
        return (1);
    }    
    
    conn_all = atol(argv[2]);
    avg_every = atol(argv[3]);

    for (n = 0; n < conn_all; n++)
    {	
        if (change_label(n))
        {
            printf ("change_label failed\n");
            return (1);
        }
        
        clock_gettime (CLOCK_REALTIME, &tp_start);
        
        if (con(argv[1], n))
        {
             printf ("con() failed\n");
             return (1);
        }
        
        clock_gettime (CLOCK_REALTIME, &tp_end);
        
        elapsed_samples[n] 	= tp_end.tv_nsec - tp_start.tv_nsec;
        avg_accumulator 	+= elapsed_samples[n];
        
        if (avg_n++ == avg_every)
        {
            avg_n = 0;
            avg_samples[n] = avg_accumulator / avg_every;
            
            if (avg_samples[n] < 0)
            {
                printf ("Bad avg: start:%u end:%u diff:%u accumulator:%u div:%u\n", tp_start.tv_nsec, tp_end.tv_nsec, tp_end.tv_nsec - tp_start.tv_nsec, avg_accumulator, avg_accumulator / avg_every);
            }
            avg_accumulator = 0;
            
            
            
            printf ("Average over %d samples %.4f ms\n", avg_every, avg_samples[n]/1000000.0f);
        }
        
        
    }
    
    return (0);
}
