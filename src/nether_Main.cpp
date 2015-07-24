/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include "nether_Daemon.h"

using namespace std;
void showHelp(char *arg);

int main(int argc, char *argv[])
{
	int optionIndex, c;
	struct NetherConfig netherConfig;

	static struct option longOptions[] =
	{
#if defined(HAVE_AUDIT)
		{"enable-audit",            no_argument,        &netherConfig.enableAudit,  0},
#endif
		{"daemon",                  no_argument,        &netherConfig.daemonMode,   0},
		{"no-rules",                no_argument,        &netherConfig.noRules,      0},
		{"log",                     required_argument,  0,                          'l'},
		{"log-args",                required_argument,  0,                          'L'},
		{"default-verdict",         required_argument,  0,                          'V'},
		{"primary-backend",         required_argument,  0,                          'p'},
		{"primary-backend-args",    required_argument,  0,                          'P'},
		{"backup-backend",          required_argument,  0,                          'b'},
		{"backup-backend-args",     required_argument,  0,                          'B'},
		{"queue-num",               required_argument,  0,                          'q'},
		{"mark-deny",               required_argument,  0,                          'm'},
		{"mark-allow-log",          required_argument,  0,                          'M'},
		{"rules-path",              required_argument,  0,                          'r'},
		{"iptables-restore-path",   required_argument,  0,                          'i'},
		{"help",                    no_argument,        0,                          'h'},
		{0, 0, 0, 0}
	};

	while(1)
	{
		c = getopt_long(argc, argv, ":daxl:L:V:p:P:b:B:q:m:M:a:r:i:h", longOptions, &optionIndex);

		if(c == -1)
			break;

		switch(c)
		{
			case 0:
				break;

			case 'd':
				netherConfig.daemonMode             = 1;
				break;
			case 'x':
				netherConfig.noRules                = 1;
				break;

#if defined(HAVE_AUDIT)
			case 'a':
				netherConfig.enableAudit            = 1;
				break;
#endif
			case 'l':
				netherConfig.logBackend             = stringToLogBackendType(optarg);
				break;

			case 'L':
				netherConfig.logBackendArgs         = optarg;
				break;

			case 'V':
				netherConfig.defaultVerdict         = stringToVerdict(optarg);
				break;

			case 'p':
				netherConfig.primaryBackendType     = stringToBackendType(optarg);
				break;

			case 'P':
				netherConfig.primaryBackendArgs     = optarg;
				break;

			case 'b':
				netherConfig.backupBackendType      = stringToBackendType(optarg);
				break;

			case 'B':
				netherConfig.backupBackendArgs      = optarg;
				break;

			case 'q':
				if(atoi(optarg) < 0 || atoi(optarg) >= 65535)
				{
					cerr << "Queue number is invalid (must be >= 0 and < 65535): " << atoi(optarg);
					exit(1);
				}
				netherConfig.queueNumber            = atoi(optarg);
				break;

			case 'm':
				if(atoi(optarg) <= 0 || atoi(optarg) >= 255)
				{
					cerr << "Packet mark for DENY is invalid (must be > 0 and < 255): " << atoi(optarg);
					exit(1);
				}
				netherConfig.markDeny               = atoi(optarg);
				break;

			case 'M':
				if(atoi(optarg) <= 0 || atoi(optarg) >= 255)
				{
					cerr << "Packet mark for ALLOW_LOG is invalid (must be > 0 and < 255): " << atoi(optarg);
					exit(1);
				}
				netherConfig.markAllowAndLog        = atoi(optarg);
				break;

			case 'r':
				netherConfig.rulesPath              = optarg;
				break;

			case 'i':
				netherConfig.iptablesRestorePath    = optarg;
				break;

			case 'h':
				showHelp(argv[0]);
				exit(1);
		}
	}
	switch(netherConfig.logBackend)
	{
		case NetherLogBackendType::stderrBackend:
			logger::Logger::setLogBackend(new logger::StderrBackend(false));
			break;
		case NetherLogBackendType::syslogBackend:
			logger::Logger::setLogBackend(new logger::SyslogBackend());
			break;
		case NetherLogBackendType::logfileBackend:
			logger::Logger::setLogBackend(new logger::FileBackend(netherConfig.logBackendArgs));
			break;
#if defined(HAVE_SYSTEMD_JOURNAL)
		case NetherLogBackendType::journalBackend:
			logger::Logger::setLogBackend(new logger::SystemdJournalBackend());
			break;
#endif
		default:
			logger::Logger::setLogBackend(new logger::StderrBackend(false));
			break;
	}

	LOGD("NETHER OPTIONS:"
#if defined(_DEBUG)
		 << " debug"
#endif
		 << " daemon="                << netherConfig.daemonMode
		 << " queue="                 << netherConfig.queueNumber);
	LOGD("primary-backend="       << backendTypeToString(netherConfig.primaryBackendType)
		 << " primary-backend-args="  << netherConfig.primaryBackendArgs);
	LOGD("backup-backend="        << backendTypeToString(netherConfig.backupBackendType)
		 << " backup-backend-args="   << netherConfig.backupBackendArgs);
	LOGD("default-verdict="       << verdictToString(netherConfig.defaultVerdict)
		 << " mark-deny="             << (int)netherConfig.markDeny
		 << " mark-allow-log="        << (int)netherConfig.markAllowAndLog);
	LOGD("log-backend="           << logBackendTypeToString(netherConfig.logBackend)
		 << " log-backend-args="      << netherConfig.logBackendArgs);
	LOGD("enable-audit="          << (netherConfig.enableAudit ? "yes" : "no")
		 << " rules-path="            << netherConfig.rulesPath);
	LOGD("no-rules="              << (netherConfig.noRules ? "yes" : "no")
		 << " iptables-restore-path=" << netherConfig.iptablesRestorePath);

	NetherManager manager(netherConfig);

	if(!manager.initialize())
	{
		LOGE("NetherManager failed to initialize, exiting");
		return (1);
	}

	if(netherConfig.daemonMode)
	{
		if(!runAsDaemon())
		{
			LOGE("Failed to run as daemon: " << strerror(errno));
			exit(1);
		}
	}

	manager.process();

	return (0);
}

void showHelp(char *arg)
{
	cout<< "Usage:\t"<< arg << " [OPTIONS]\n\n";
	cout<< "  -d,--daemon\t\t\t\tRun as daemon in the background (default:no)\n";
	cout<< "  -x,--no-rules\t\t\t\tDon't load iptables rules on start (default:no)\n";
	cout<< "  -l,--log=<backend>\t\t\tSet logging backend STDERR,SYSLOG";
#if defined(HAVE_SYSTEMD_JOURNAL)
	cout << ",JOURNAL\n";
#endif
	cout<< "(default:"<< logBackendTypeToString(NETHER_LOG_BACKEND) << ")\n";
	cout<< "  -L,--log-args=<arguments>\t\tSet logging backend arguments\n";
	cout<< "  -V,--verdict=<verdict>\t\tWhat verdict to cast when policy backend is not available\n\t\t\t\t\tACCEPT,ALLOW_LOG,DENY (default:"<<verdictToString(NETHER_DEFAULT_VERDICT)<<")\n";
	cout<< "  -p,--primary-backend=<module>\t\tPrimary policy backend\n\t\t\t\t\t";
#if defined(HAVE_CYNARA)
	cout << "CYNARA";
#endif
	cout<< ",FILE,NONE (defualt:"<< backendTypeToString(NETHER_PRIMARY_BACKEND)<<")\n";
	cout<< "  -P,--primary-backend-args=<arguments>\tPrimary policy backend arguments\n";
	cout<< "  -b,--backup-backend=<module>\t\tBackup policy backend\n\t\t\t\t\t";
#if defined(HAVE_CYNARA)
	cout<< "CYNARA";
#endif
	cout<< ",FILE,NONE (defualt:"<< backendTypeToString(NETHER_BACKUP_BACKEND)<< ")\n";
	cout<< "  -B,--backup-backend-args=<arguments>\tBackup policy backend arguments (default:" << NETHER_POLICY_FILE << ")\n";
	cout<< "  -q,--queue-num=<queue number>\t\tNFQUEUE queue number to use for receiving packets\n";
	cout<< "  -m,--mark-deny=<mark>\t\t\tPacket mark to use for DENY verdicts (default:"<< NETLINK_DROP_MARK << ")\n";
	cout<< "  -M,--mark-allow-log=<mark>\t\tPacket mark to use for ALLOW_LOG verdicts (default:" << NETLINK_ALLOWLOG_MARK << ")\n";
#if defined(HAVE_AUDIT)
	cout<< "  -a,--enable-audit\t\t\tEnable the auditing subsystem (default: no)\n";
#endif
	cout<< "  -r,--rules-path=<path>\t\tPath to iptables rules file (default:" << NETHER_RULES_PATH << ")\n";
	cout<< "  -i,--iptables-restore-path=<path>\tPath to iptables-restore command (default:" << NETHER_IPTABLES_RESTORE_PATH << ")\n";
	cout<< "  -h,--help\t\t\t\tshow help information\n";
}
