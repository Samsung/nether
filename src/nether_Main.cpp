/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Roman Kubiak (r.kubiak@samsung.com)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */

/**
 * @file
 * @author  Roman Kubiak (r.kubiak@samsung.com)
 * @brief   nether main program
 */

#include "nether_Types.h"
#include "nether_Utils.h"
#include "nether_Manager.h"

using namespace std;
void showHelp(char *arg);

int main(int argc, char *argv[])
{
    int optionIndex, c;
    struct NetherConfig netherConfig;

    static struct option longOptions[] =
    {
          {"nodaemon",		        no_argument,		&netherConfig.nodaemonMode,	1},
          {"log",                   required_argument,  0,              'l'},
          {"log-args",              required_argument,  0,              'L'},
          {"default-verdict",	    required_argument, 	0, 				'V'},
          {"primary-backend",  	    required_argument, 	0, 				'p'},
          {"primary-backend-args",  required_argument,  0,              'P'},
          {"backup-backend",  	    required_argument, 	0, 				'b'},
          {"backup-backend-args",   required_argument, 	0, 				'B'},
          {"queue-num",		        required_argument,	0,				'q'},
          {"mark-deny",             required_argument,  0,              'm'},
          {"mark-allow-log",        required_argument,  0,              'M'},
          {"help",		            no_argument,		0,				'h'},
          {0, 0, 0, 0}
    };

    while (1)
    {
        c = getopt_long (argc, argv, ":nl:L:V:p:P:b:B:q:m:M:h", longOptions, &optionIndex);

        if (c == -1)
            break;

        switch (c)
        {
            case 0:
              break;

            case 'n':
                netherConfig.nodaemonMode           = 1;
                break;

            case 'l':
                netherConfig.logBackend             = stringToLogBackendType(optarg);
                break;

            case 'L':
                netherConfig.logBackendArgs         = optarg;
                break;

            case 'V':
                netherConfig.defaultVerdict         = stringToVerdict (optarg);
                break;

            case 'p':
                netherConfig.primaryBackendType     = stringToBackendType (optarg);
                break;

            case 'P':
                netherConfig.primaryBackendArgs     = optarg;
                break;

            case 'b':
                netherConfig.backupBackendType      = stringToBackendType (optarg);
                break;

            case 'B':
                netherConfig.backupBackendArgs      = optarg;
                break;

            case 'q':
                if (atoi(optarg) < 0 || atoi(optarg) >= 65535)
                {
                    cerr << "Queue number is invalid (must be >= 0 and < 65535): " << atoi(optarg);
                    exit (1);
                }
                netherConfig.queueNumber            = atoi(optarg);
                break;

            case 'm':
                if (atoi(optarg) <= 0 || atoi(optarg) >= 255)
                {
                    cerr << "Packet mark for DENY is invalid (must be > 0 and < 255): " << atoi(optarg);
                    exit (1);
                }
                netherConfig.markDeny               = atoi(optarg);
                break;

            case 'M':
                if (atoi(optarg) <= 0 || atoi(optarg) >= 255)
                {
                    cerr << "Packet mark for ALLOW_LOG is invalid (must be > 0 and < 255): " << atoi(optarg);
                    exit (1);
                }
                netherConfig.markAllowAndLog        = atoi(optarg);
                break;

            case 'h':
              showHelp (argv[0]);
              exit (1);
        }
    }
    switch (netherConfig.logBackend)
    {
        case stderrBackend:
            logger::Logger::setLogBackend (new logger::StderrBackend(false));
            break;
        case syslogBackend:
            logger::Logger::setLogBackend (new logger::SyslogBackend());
            break;
        case logfileBackend:
            logger::Logger::setLogBackend (new logger::FileBackend(netherConfig.logBackendArgs));
            break;
#if defined(HAVE_SYSTEMD_JOURNAL)
        case journalBackend:
            logger::Logger::setLogBackend (new logger::SystemdJournalBackend());
            break;
#endif
        default:
            logger::Logger::setLogBackend (new logger::StderrBackend(false));
            break;
    }

    LOGD("NETHER OPTIONS:"
#if defined(_DEBUG)
        << " debug"
#endif
        << " nodaemon="              << netherConfig.nodaemonMode
        << " queue="                 << netherConfig.queueNumber);
    LOGD("primary-backend="       << backendTypeToString (netherConfig.primaryBackendType)
        << " primary-backend-args="  << netherConfig.primaryBackendArgs);
    LOGD("backup-backend="        << backendTypeToString (netherConfig.backupBackendType)
        << " backup-backend-args="   << netherConfig.backupBackendArgs);
    LOGD("default-verdict="       << verdictToString(netherConfig.defaultVerdict)
        << " mark-deny="             << (int)netherConfig.markDeny
        << " mark-allow-log="        << (int)netherConfig.markAllowAndLog);
    LOGD("log-backend="           << logBackendTypeToString(netherConfig.logBackend)
        << " log-backend-args="      << netherConfig.logBackendArgs);

    NetherManager manager (netherConfig);

    if (!manager.initialize())
    {
        LOGE("NetherManager failed to initialize, exiting");
        return (1);
    }

    manager.process();

    return (0);
}

void showHelp(char *arg)
{
    cout<< "Usage:\t"<< arg << " [OPTIONS]\n\n";
    cout<< "  -n,--nodaemon\t\t\t\tDon't run as daemon in the background\n";
    cout<< "  -d,--debug\t\t\t\tRun in debug mode (implies --nodaemon)\n";
    cout<< "  -l,--log=<backend>\t\t\tSet logging backend STDERR,SYSLOG,JOURNAL (default:"<< logBackendTypeToString(NETHER_LOG_BACKEND) << ")\n";
    cout<< "  -L,--log-args=<arguments>\t\tSet logging backend arguments\n";
    cout<< "  -V,--verdict=<verdict>\t\tWhat verdict to cast when policy backend is not available\n\t\t\t\t\tACCEPT,ALLOW_LOG,DENY (default:"<<verdictToString(NETHER_DEFAULT_VERDICT)<<")\n";
    cout<< "  -p,--primary-backend=<module>\t\tPrimary policy backend\n\t\t\t\t\tCYNARA,FILE,NONE (defualt:"<< backendTypeToString(NETHER_PRIMARY_BACKEND)<<")\n";
    cout<< "  -P,--primary-backend-args=<arguments>\tPrimary policy backend arguments\n";
    cout<< "  -b,--backup-backend=<module>\t\tBackup policy backend\n\t\t\t\t\tCYNARA,FILE,NONE (defualt:"<< backendTypeToString(NETHER_BACKUP_BACKEND)<< ")\n";
    cout<< "  -B,--backup-backend-args=<arguments>\tBackup policy backend arguments\n";
    cout<< "  -q,--queue-num=<queue number>\t\tNFQUEUE queue number to use for receiving packets\n";
    cout<< "  -m,--mark-deny=<mark>\t\t\tPacket mark to use for DENY verdicts (default:"<< NETLINK_DROP_MARK << ")\n";
    cout<< "  -M,--mark-allow-log=<mark>\t\tPacket mark to use for ALLOW_LOG verdicts (default:" << NETLINK_ALLOWLOG_MARK << ")\n";
    cout<< "  -h,--help\t\t\t\tshow help information\n";
}
