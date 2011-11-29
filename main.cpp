/*
 *  radiusplugin -- An OpenVPN plugin for do radius authentication 
 *					and accounting.
 * 
 *  Copyright (C) 2005 EWE TEL GmbH/Ralf Luebben <ralfluebben@gmx.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

//#include "openvpn-plugin.h"
#include "RadiusClass/RadiusPacket.h"
#include "radiusplugin.h"

#include <stdlib.h>
#include <stdio.h>

/** Only for testing the plugin!*/

/* Testcases: 
 1) AUTH_USER_PASS_VERIFY, CLIENT_CONNECT, CLIENT_DISCONNECT when auth_control_file is not specified
 2) AUTH_USER_PASS_VERIFY, CLIENT_CONNECT, CLIENT_DISCONNECT when auth_control_file is specified
 This testcase is more difficult:
 CLIENT_CONNECT can occur before AUTH_USER_PASS_VERIFY finishes, normally OpenVPN should take of this.
 AUTH_USER_PASS_VERIFY is called again for the same user during the first authentication happens.
 3) The radius server doesn't respond: 1) & 2)
 4) Slow response of the radius server (add delay sudo tc qdisc add dev [$iftoradius] root netem delay 300ms)
 */
int main(void) {
	openvpn_plugin_handle_t context;
	//success* variables save return values of the functions
	int success;
	unsigned int type_mask = 0;

	const char *env[10];
	const char *argv[3];
	
	env[0] = "username=testuser";
	env[1] = "password=test123";
	env[2] = "verb=10";
	env[3] = "untrusted_ip=127.0.0.1";
	env[4] = "common_name=R-VPNGateway1";
	env[5] = "trusted_ip=127.0.0.1";
	env[6] = "ifconfig_pool_remote_ip=10.8.0.100";
	env[7] = "untrusted_port=111";
	env[8] = NULL;
	env[9] = NULL;
	
	argv[0] = "radiusplugin.so";
	argv[1] = "./radiusplugin.cnf";
	argv[2] = NULL;

	context = openvpn_plugin_open_v2(&type_mask, (const char **) argv, (const char **) env, NULL);
	if (context == NULL) {
		return -1;
	}
	// AUTH
	success = openvpn_plugin_func_v2(context, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY, (const char **) argv, (const char **) env, NULL, NULL);
	sleep(1);

	if (success == OPENVPN_PLUGIN_FUNC_DEFERRED) {
		char c;
		ifstream file(get_env("auth_control_file", env));
		do {
			if (file.is_open()) {
				file.read(&c, 1);
			} else
				file.open(get_env("auth_control_file", env));

			sleep(1);
		} while (!file.is_open());
		success = c - '0';
		file.close();
		system("rm acfuser*"); //remove the acf files
	}

	if (success != 0) {
		cerr << getTime() << "AUTH FALSE\n";
		return 1;
	}

	// CONNECT
	success = openvpn_plugin_func_v2(context, OPENVPN_PLUGIN_CLIENT_CONNECT, (const char **) argv, (const char **) env, NULL, NULL);
	sleep(1);

	if (success != 0) {
		cerr << getTime() << "CLIENT_CONNECT FALSE\n";
		return 1;
	}

	// re-keying AUTH
	success = openvpn_plugin_func_v2(context, OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY, (const char **) argv, (const char **) env, NULL, NULL);
	sleep(1);

	if (success == OPENVPN_PLUGIN_FUNC_DEFERRED) {
		char c;
		ifstream file(get_env("auth_control_file", env));
		do {
			if (file.is_open()) {
				file.read(&c, 1);
			} else
				file.open(get_env("auth_control_file", env));
			sleep(1);
		} while (!file.is_open());
		success = c - '0';
		file.close();
		system("rm acfuser*"); //remove the acf files
	}

	if (success != 0) {
		cerr << getTime() << "AUTH 2 FALSE\n";
		return 1;
	}

	// DISCONNECT
	success = openvpn_plugin_func_v2(context, OPENVPN_PLUGIN_CLIENT_DISCONNECT, (const char **) argv, (const char **) env, NULL, NULL);

	if (success != 0) {
		cerr << getTime() << "CLIENT_DISCONNECT FALSE\n";
		return 1;
	}

	openvpn_plugin_close_v1(context);
	
	cerr << getTime() << "ALL OK\n";
	return 0;
}
