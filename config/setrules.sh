#
#  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
#
#  Contact: Roman Kubiak (r.kubiak@samsung.com)
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License
#
#!/bin/bash
DENY_CHAIN="NETHER-DENY"
ALLOWLOG_CHAIN="NETHER-ALLOWLOG"
TEST_HOST="198.145.20.7"
TEST_PORT=443
TEST_PROTO="tcp"
TEST_QUEUE=0
AUDITCTL=auditctl
DENY_MARK="0x3"
ALLOWLOG_MARK="0x4"

function runcmd {
	echo -ne "\t>> $@\n"
	$@
}

function clean {
	echo "Cleanup"
	echo
	iptables -t mangle -D OUTPUT -m state --state NEW -p $TEST_PROTO -d $TEST_HOST --dport $TEST_PORT -j NFQUEUE --queue-num 0 --queue-bypass 2> /dev/null
	iptables -D OUTPUT -m mark --mark $DENY_MARK -j $DENY_CHAIN 2> /dev/null
	iptables -D OUTPUT -m mark --mark $ALLOWLOG_MARK -j $ALLOWLOG_CHAIN 2> /dev/null
	iptables -F $DENY_CHAIN 2> /dev/null
	iptables -F $ALLOWLOG_CHAIN 2> /dev/null
	iptables -X $DENY_CHAIN 2> /dev/null
	iptables -X $ALLOWLOG_CHAIN 2> /dev/null
	echo
}

function create {
	echo "Creating chain"
	echo
	runcmd iptables -N $DENY_CHAIN
	runcmd iptables -N $ALLOWLOG_CHAIN
	runcmd iptables -A $DENY_CHAIN -j AUDIT --type REJECT
	runcmd iptables -A $DENY_CHAIN -j REJECT
	runcmd iptables -A $ALLOWLOG_CHAIN -j AUDIT --type ACCEPT
	echo
}

function create_rules {
	echo "Writing rules to output chain $OUTPUT_CHAIN"
	echo
	runcmd iptables -t mangle -A OUTPUT -m state --state NEW -p $TEST_PROTO -d $TEST_HOST --dport $TEST_PORT -j NFQUEUE --queue-num 0 --queue-bypass
	runcmd iptables -A OUTPUT -m mark --mark $DENY_MARK -j $DENY_CHAIN
	runcmd iptables -A OUTPUT -m mark --mark $ALLOWLOG_MARK -j $ALLOWLOG_CHAIN
	echo
}

function enable_audit {
	if type $AUDITCTL; then
		echo -n "Enable audit: "
		runcmd $AUDITCTL -e 1 >/dev/null
		if [ $? == 0 ]; then
			echo "OK"
		else
			echo "Failed"
		fi
	else
		echo "$AUDITCTL does not exist, can't enable audit"
	fi
	echo
}

clean
create
create_rules
enable_audit
