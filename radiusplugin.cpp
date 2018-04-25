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

//The callback functions of the plugin infrastructure.

#include "radiusplugin.h"

//define extern "C", so the c++ compiler generate a shared library
//which is compatible with c programms
extern "C" {


	/** The function is needed by the OpenVpn plugin model. The function is called
	 * when OpenVpn starts. In this case here two background process are
	 * started. One for authentication and one for accounting. The communication
	 * between the processes is made via sockets.
	 * You need a background process for accounting, because the interval
	 * in which accounting information is sent to the radius server in independent
	 * from the main OpenVpn-process, so it is done by another process which schedule
	 * the accounting intervals. This process holds his root rights and it can set and
	 * deletes routes in the system routing table.
	 * The authentication process is a own process, too. So there is clear separation
	 * and it is independent from the openvpn process.
	 * @param The type of plugin, maybe client_connect, client_disconnect, user_auth_pass_verify...
	 * @param A list of arguments which are set in the configuration file of openvpn in plugin line.
	 * @param The list of environment variables, it is created by the OpenVpn-Process.
	 */
	OPENVPN_PLUGIN_DEF openvpn_plugin_handle_t OPENVPN_PLUGIN_FUNC(openvpn_plugin_open_v2)(unsigned int *type_mask, const char *argv[], const char *envp[], struct openvpn_plugin_string_list **return_list) {

		/** process number*/
		pid_t pid;

		/** An array for the socket pair of the authentication process.*/
		int fd_auth[2];

		/** An array for the socket pair of the accounting process.*/
		int fd_acct[2];

		/** The accounting background process object.*/
		AccountingProcess Acct;

		/** The authentication background process object.*/
		AuthenticationProcess Auth;

		/** The context for this functions.*/
		PluginContext *context = NULL;

		// Create the context.
		context = new PluginContext;

		// List for additional arguments
		struct name_value_list name_value_list;

		// There must be one param, the name of the plugin file
		const int base_parms = 1;

		// Get verbosity level from the environment.
		const char *verb_string = get_env("verb", envp);

		if(verb_string)
			context->setVerbosity(atoi(verb_string));

		if(DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: Start AUTH-RADIUS-PLUGIN\n";

		// Make sure we have one string argument: the .so name.
		if(string_array_len(argv) < base_parms) {
			cerr << getTime() << "RADIUS-PLUGIN: no .so name\n";

			delete context;
			return 0;
		}

		if(DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: Found " << string_array_len(argv) << " params.\n";


		// See if we have optional name/value pairs for
		// the plugin, this can only be the config file.
		// path (default: -c /etc/openvpn/radiusplugin.conf)
		name_value_list.len = 0;
		if(string_array_len(argv) > base_parms) {
			if(DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Find params.\n";

			// just a work around because argv[1] is the filename
			name_value_list.data[0].name = "-c";
			name_value_list.data[0].value = argv[1];

			// parse the radiusplugin config file
			cerr << getTime() << "RADIUS-PLUGIN: Config filename: " << name_value_list.data[0].value << ".\n";
			if (context->radiusconf.parseConfigFile(name_value_list.data[0].value) != 0 or context->conf.parseConfigFile(name_value_list.data[0].value) != 0) {
				cerr << getTime() << "RADIUS-PLUGIN: Bad config file or error in config.\n";

				delete context;
				return 0;
			}
		} else {
			// if there is no filename, use the default
			cerr << getTime() << "RADIUS-PLUGIN: Config filename: /etc/openvpn/radiusplugin.cnf.\n";
			if (context->radiusconf.parseConfigFile("/etc/openvpn/radiusplugin.cnf") != 0 or context->conf.parseConfigFile("/etc/openvpn/radiusplugin.cnf") != 0) {
				cerr << getTime() << "RADIUS-PLUGIN: Bad config file or error in config.\n";

				delete context;
				return 0;
			}

		}

		// Intercept the --auth-user-pass-verify, --client-connect and --client-disconnect callback.
		if (context->conf.getAccountingOnly() == false) {
			*type_mask =	OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY) |
							OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT) |
							OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT);
		} else { //just do the accounting
			*type_mask =	OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_CONNECT) |
							OPENVPN_PLUGIN_MASK(OPENVPN_PLUGIN_CLIENT_DISCONNECT);
		}

		// Make a socket for foreground and background processes
		// to communicate.
		// Authentication process:
		if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fd_auth) == -1) {
			cerr << getTime() << "RADIUS-PLUGIN: socketpair call failed for authentication process\n";

			delete context;
			return 0;
		}

		//Accounting process:
		if (socketpair(PF_UNIX, SOCK_DGRAM, 0, fd_acct) == -1) {
			cerr << getTime() << "RADIUS-PLUGIN: socketpair call failed for accounting process\n";

			delete context;
			return 0;
		}

		//  Fork off the privileged processes.  It will remain privileged
		//  even after the foreground process drops its privileges.


		// 	Fork the authentication process
		pid = fork();
		if (pid) {
			// Foreground Process (Parent)
			int status;

			// save the process id
			context->setAuthPid(pid);

			// close our copy of child's socket
			close(fd_auth[1]);

			// don't let future subprocesses inherit child socket
			if (fcntl(fd_auth[0], F_SETFD, FD_CLOEXEC ) < 0)
				cerr << getTime() << "RADIUS-PLUGIN: Set FD_CLOEXEC flag on socket file descriptor failed\n";

			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Start BACKGROUND Process for authentication with PID " << context->getAuthPid() << ".\n";

			// save the socket number in the context
			context->authsocketbackgr.setSocket(fd_auth[0]);

			// wait for background child process to initialize */
			status = context->authsocketbackgr.recvInt();

			// set the socket to -1 if the initialization failed
			if (status != RESPONSE_INIT_SUCCEEDED)
				context->authsocketbackgr.setSocket(-1);

			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Start AUTH-RADIUS-PLUGIN\n";
		} else {
			// Background Process

			// close all parent fds except our socket back to parent
			close_fds_except(fd_auth[1]);

			// Ignore most signals (the parent will receive them)
			set_signals();

			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Start BACKGROUND Process for authentication\n";

			// save the socket number in the context
			context->authsocketforegr.setSocket(fd_auth[1]);

			// start the background event loop for accounting
			Auth.Authentication(context);

			// close the socket
			close(fd_auth[1]);

			// free the context of the background process
			delete context;

			exit(0);
		}

		// 	Fork the accounting process
		pid = fork();
		if (pid) {
			// Foreground Process (Parent)
			int status;

			// save the process id
			context->setAcctPid(pid);

			// close our copy of child's socket
			close(fd_acct[1]);

			// don't let future subprocesses inherit child socket
			if (fcntl(fd_acct[0], F_SETFD, FD_CLOEXEC ) < 0)
				cerr << getTime() << "RADIUS-PLUGIN: Set FD_CLOEXEC flag on socket file descriptor failed\n";

			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Start BACKGROUND Process for accounting with PID " << context->getAcctPid() << ".\n";


			// save the socket number in the context
			context->acctsocketbackgr.setSocket(fd_acct[0]);

			// wait for background child process to initialize */
			status = context->acctsocketbackgr.recvInt();

			//set the socket to -1 if the initialization failed
			if (status != RESPONSE_INIT_SUCCEEDED)
				context->acctsocketbackgr.setSocket(-1);

			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Start ACCT-RADIUS-PLUGIN\n";
		} else {
			// Background Process

			// close all parent fds except our socket back to parent
			close_fds_except(fd_acct[1]);

			// Ignore most signals (the parent will receive them)
			set_signals();

			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Start BACKGROUND Process for accounting\n";

			// save the socket in the context
			context->acctsocketforegr.setSocket(fd_acct[1]);

			//start the background event loop for accounting
			Acct.Accounting(context);

			//close the socket
			close(fd_acct[1]);

			//free the context of the background process
			delete context;

			exit(0);
		}

		// return the context, this is used between the functions
		return (openvpn_plugin_handle_t) context;
	}


	/** This function is called from the OpenVpn process everytime
	 * a event happens. The function handle the events (plugins)
	 * AUTH_USER_PASS_VERIFY, CLIENT_CONNECT, CLIENT_DISCONNECT.
	 * The function reads the information from the environment
	 * variable and sends the relevant information to the
	 * background processes.
	 * AUTH_USER_PASS_VERIFY: The user is authenticated by a radius server,
	 * if it succeeded the background sends back the framed ip, the routes and the acct_interim_interval
	 * for the user. Than the user is added to the context.
	 * CLIENT_CONNECT: The user is added to the accounting by
	 * sending the information to the background process.
	 * CLIENT_DISCONNECT: The user is deleted from the
	 * accounting by sending the information to the background process.
	 * @param The handle which was allocated in the open function.
	 * @param The type of plugin, maybe client_conect, client_disconnect, auth_user_pass_verify
	 * @param A list of arguments which are set in the openvpn configuration file.
	 * @param The list of environment variables, it is created by the OpenVpn-Process.
	 * @return A integer with the status of the function (OPENVPN_PLUGIN_FUNC_SUCCESS or OPENVPN_PLUGIN_FUNC_ERROR).
	 */

	OPENVPN_PLUGIN_DEF int OPENVPN_PLUGIN_FUNC(openvpn_plugin_func_v2)(openvpn_plugin_handle_t handle, const int type, const char *argv[], const char *envp[], void *per_client_context, struct openvpn_plugin_string_list **return_list) {
		// restore the context which was created at the function openvpn_plugin_open_v1
		PluginContext *context = (struct PluginContext *) handle;

		if (context->getStartThread()) {
			pthread_cond_init(context->getCondSend(), NULL);
			pthread_mutex_init(context->getMutexSend(), NULL);
			pthread_cond_init(context->getCondRecv(), NULL);
			pthread_mutex_init(context->getMutexRecv(), NULL);

			if (context->conf.getAccountingOnly() == false && pthread_create(context->getThread(), NULL, &auth_user_pass_verify, (void *) context) != 0) {
				cerr << getTime() << "RADIUS-PLUGIN: Thread creation failed.\n";
				return OPENVPN_PLUGIN_FUNC_ERROR;
			}
			pthread_mutex_lock(context->getMutexRecv());
			context->setStartThread(false);
			pthread_mutex_unlock(context->getMutexRecv());
		}

		string common_name; /**<A string for the common_name from the enviroment.*/
		string untrusted_ip; /** untrusted_ip for ipv6 support **/

		///////////// OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY
		if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY && (context->authsocketbackgr.getSocket()) >= 0) {
			if (DEBUG ( context->getVerbosity() ))
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY is called." << endl;

			try {
				// create a new user
				UserPlugin* newuser = new UserPlugin();
				get_user_env(context, type, envp, newuser);

				if (newuser->getAuthControlFile().length() > 0 && context->conf.getUseAuthControlFile()) {
					pthread_mutex_lock(context->getMutexSend());
					context->addNewUser(newuser);
					pthread_cond_signal(context->getCondSend());
					pthread_mutex_unlock(context->getMutexSend());
					return OPENVPN_PLUGIN_FUNC_DEFERRED;
				} else {
					pthread_mutex_lock(context->getMutexRecv());
					pthread_mutex_lock(context->getMutexSend());
					context->addNewUser(newuser);
					pthread_cond_signal(context->getCondSend());
					pthread_mutex_unlock(context->getMutexSend());

					pthread_cond_wait(context->getCondRecv(), context->getMutexRecv());
					pthread_mutex_unlock(context->getMutexRecv());

					return context->getResult();
				}
			} catch (Exception &e) {
				cerr << getTime() << e;
			} catch (...) {
				cerr << getTime() << "Unknown Exception!";
			}
		}

		///////////// CLIENT_CONNECT
		if (type == OPENVPN_PLUGIN_CLIENT_CONNECT && context->acctsocketbackgr.getSocket() >= 0) {
			if (DEBUG ( context->getVerbosity() ))
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: OPENVPN_PLUGIN_CLIENT_CONNECT is called.\n";

			try {
				UserPlugin* tmpuser = new UserPlugin();
				get_user_env(context, type, envp, tmpuser);

				// find the user in the context, he was added at the OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY
				UserPlugin* newuser = context->findUser(tmpuser->getKey());
				if (newuser == NULL) {
					if (context->conf.getAccountingOnly() == true) { //Authentication part is missing, where this is done else
						newuser = tmpuser;
						newuser->setAuthenticated(true); //the plugin does not care about it
						newuser->setPortnumber(context->addNasPort());
						newuser->setSessionId(createSessionId(newuser));
						//add the user to the context
						context->addUser(newuser);
					} else {
						throw Exception("RADIUS-PLUGIN: FOREGROUND: User should be accounted but is unknown, should only occur if accountingonly=true.\n");
					}
				} else {
					delete (tmpuser);
				}

				// set the assigned ip as Framed-IP-Attribute of the user (see RFC2866, chapter 4.1 for more information)
				if (get_env("ifconfig_pool_remote_ip", envp) != NULL)
					newuser->setFramedIp(string(get_env("ifconfig_pool_remote_ip", envp)));

				if (DEBUG(context->getVerbosity()))
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Set FramedIP to the IP (" << newuser->getFramedIp() << ") OpenVPN assigned to the user " << newuser->getUsername() << "\n";

				// the user must be there and must be authenticated but not accounted
				// isAccounted and isAuthenticated is true it is client connect for re-negotiation, the user is already in the accounting process
				if (newuser != NULL && newuser->isAccounted() == false && newuser->isAuthenticated()) {
					// transform the integers to strings to send them over the socket

					if (DEBUG(context->getVerbosity()))
						cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Add user for accounting: username: " << newuser->getUsername() << ", commonname: "<< newuser->getCommonname() << "\n";

					//send information to the background process
					context->acctsocketbackgr.send(ADD_USER);
					context->acctsocketbackgr.send(newuser->getUsername());
					context->acctsocketbackgr.send(newuser->getSessionId());
					context->acctsocketbackgr.send(newuser->getPortnumber());
					context->acctsocketbackgr.send(newuser->getCallingStationId());
					context->acctsocketbackgr.send(newuser->getFramedIp());
					context->acctsocketbackgr.send(newuser->getCommonname());
					context->acctsocketbackgr.send(newuser->getAcctInterimInterval());
					context->acctsocketbackgr.send(newuser->getFramedRoutes());
					context->acctsocketbackgr.send(newuser->getKey());
					context->acctsocketbackgr.send(newuser->getStatusFileKey());
					context->acctsocketbackgr.send(newuser->getUntrustedPort());
					context->acctsocketbackgr.send(newuser->getVsaBuf(), newuser->getVsaBufLen());

					//get the response
					const int status = context->acctsocketbackgr.recvInt();
					if (status == RESPONSE_SUCCEEDED) {
						newuser->setAccounted(true);

						if (DEBUG(context->getVerbosity()))
							cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Accounting succeeded!\n";

						return OPENVPN_PLUGIN_FUNC_SUCCESS;
					} else {
						// free the nasport
						context->delNasPort(newuser->getPortnumber());

						string error;
						error = "RADIUS-PLUGIN: FOREGROUND: Accounting failed for user:";
						error += newuser->getUsername();
						error += "!\n";

						//delete user from context
						context->delUser(newuser->getKey());
						throw Exception(error);
					}
				} else {
					string error;
					error = "RADIUS-PLUGIN: FOREGROUND: No user with this commonname or it is already authenticated: ";
					error += common_name;
					error += "!\n";
					throw Exception(error);

				}
			} catch (Exception &e) {
				cerr << getTime() << e;
			} catch (...) {
				cerr << getTime() << "Unknown Exception!";
			}
		}

		///////////// OPENVPN_PLUGIN_CLIENT_DISCONNECT
		if (type == OPENVPN_PLUGIN_CLIENT_DISCONNECT && context->acctsocketbackgr.getSocket() >= 0) {
			if (DEBUG ( context->getVerbosity() ))
				cerr << getTime() << "\n\nRADIUS-PLUGIN: FOREGROUND: OPENVPN_PLUGIN_CLIENT_DISCONNECT is called.\n";

			try {
				UserPlugin* tmpuser = new UserPlugin();
				get_user_env(context, type, envp, tmpuser);

				// find the user in the context, he was added at the OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY
				UserPlugin* newuser = context->findUser(tmpuser->getKey());

				// we only do a simple check here as we do not care for disconnects
				delete (tmpuser);

				if (newuser != NULL) {
					if (DEBUG ( context->getVerbosity() ))
						cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Delete user from accounting: commonname: " << newuser->getKey() << "\n";

					//send the information to the background process
					context->acctsocketbackgr.send(DEL_USER);
					context->acctsocketbackgr.send(newuser->getKey());

					//get the response
					const int status = context->acctsocketbackgr.recvInt();
					if (status == RESPONSE_SUCCEEDED) {
						if (DEBUG(context->getVerbosity()))
							cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Accounting for user with key" << newuser->getKey() << " stopped!\n";

						//free the nasport
						context->delNasPort(newuser->getPortnumber());

						//delete user from context
						context->delUser(newuser->getKey());
						return OPENVPN_PLUGIN_FUNC_SUCCESS;
					} else {
						//free the nasport
						context->delNasPort(newuser->getPortnumber());

						//delete user from context
						context->delUser(newuser->getKey());
						cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Error in ACCT Background Process!\n";
					}
				} else {
					throw Exception("No user with this common_name!\n");
				}
			} catch (Exception &e) {
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND:" << e;
			} catch (...) {
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND:" << "Unknown Exception!\n";
			}
		}
		return OPENVPN_PLUGIN_FUNC_ERROR;
	}


	/** The function is called when the OpenVpn process exits.
	 * A exit command is send to the background processes and
	 * the context is freed which was allocted in the open function.
	 * @param The handle which was allocated in the open function.
	 */
	OPENVPN_PLUGIN_DEF void OPENVPN_PLUGIN_FUNC(openvpn_plugin_close_v1)(openvpn_plugin_handle_t handle) {
		//restore the context
		PluginContext *context = (PluginContext *) handle;

		if (DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: close\n";

		if (context->authsocketbackgr.getSocket() >= 0) {
			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: close auth background process\n";

			// tell background process to exit
			try {
				context->authsocketbackgr.send(COMMAND_EXIT);
			} catch (Exception &e) {
				cerr << getTime() << e;
			}

			// wait for background process to exit
			if (context->getAuthPid() > 0)
				waitpid(context->getAuthPid(), NULL, 0);

		}

		if (context->acctsocketbackgr.getSocket() >= 0) {
			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: close acct background process.\n";


			//tell background process to exit
			try {
				context->acctsocketbackgr.send(COMMAND_EXIT);
			} catch (Exception &e) {
				cerr << getTime() << e;
			}

			// wait for background process to exit
			if (context->getAcctPid() > 0)
				waitpid(context->getAcctPid(), NULL, 0);

		}

		if (context->getStartThread() == false) {
			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Stop auth thread .\n";

			// stop the thread
			pthread_mutex_lock(context->getMutexSend());
			context->setStopThread(true);
			pthread_cond_signal(context->getCondSend());
			pthread_mutex_unlock(context->getMutexSend());

			// wait for the thread to exit
			pthread_join(*context->getThread(), NULL);
			pthread_cond_destroy(context->getCondSend());
			pthread_cond_destroy(context->getCondRecv());
			pthread_mutex_destroy(context->getMutexSend());
			pthread_mutex_destroy(context->getMutexRecv());
		} else {
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Auth thread was not started so far.\n";
		}

		delete context;
		cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: DONE.\n";
	}
}

/** Original function from the openvpn auth-pam plugin.
 * Given an environmental variable name, search
 * the envp array for its value, returning it
 * if found or NULL otherwise.
 * A field in the envp-array looks like: name=user1
 * @param The name of the variable.
 * @param The array with the enviromental variables.
 * @return A poniter to the variable value or NULL, if the varaible was not found.
 */
const char * get_env(const char *name, const char *envp[]) {
	if (envp) {
		int i;
		const int namelen = strlen(name);

		for (i = 0; envp[i]; ++i) {
			// compare the environment names
			if (!strncmp(envp[i], name, namelen)) {
				//if the variable is found
				const char *cp = envp[i] + namelen;

				//return the value behind the =
				if (*cp == '=')
					return cp + 1;
			}
		}
	}
	return NULL;
}

/** Original function from the openvpn auth-pam plugin.
 * Return the length of a string array.
 * @param Array
 * @return The length of the arry.
 */
int string_array_len(const char *array[]) {
	int i = 0;
	if (array) {
		while (array[i])
			++i;
	}
	return i;
}

/** Original function from the openvpn auth-pam plugin.
 * Close most of parent's fds.
 * Keep stdin/stdout/stderr, plus one
 * other fd which is presumed to be
 * our pipe back to parent.
 * Admittedly, a bit of a kludge,
 * but posix doesn't give us a kind
 * of FD_CLOEXEC which will stop
 * fds from crossing a fork().
 * @param The socket number which should not be closed.
 */
void close_fds_except(int keep) {
	int i;
	closelog();
	for (i = 3; i <= 100; ++i) {
		if (i != keep)
			close(i);
	}
}

/** Original function from the openvpn auth-pam plugin.
 * Usually we ignore signals, because our parent will
 * deal with them.
 */
void set_signals(void) {
	signal(SIGTERM,	SIG_DFL);

	signal(SIGINT,	SIG_IGN);
	signal(SIGHUP,	SIG_IGN);
	signal(SIGUSR1,	SIG_IGN);
	signal(SIGUSR2,	SIG_IGN);
	signal(SIGPIPE,	SIG_IGN);
}

/** The function creates a md5 hash string as session ID over
 * - user->commonname
 * - user->callingstationid
 * - user->untrustedport
 * - time string from ctime(...)
 * @param A pointer to the user for which the session ID is created.
 * @return A string with the hash.
 */
string createSessionId(UserPlugin * user) {
	unsigned char digest[16];
	char text[33]; //The digest.
	gcry_md_hd_t context; //the hash context
	int i;
	time_t rawtime;
	string strtime;
	ostringstream portnumber;
	memset(digest, 0, 16);

	//build the hash
	gcry_md_open(&context, GCRY_MD_MD5, 0);
	gcry_md_write(context, user->getCommonname().c_str(), user->getCommonname().length());
	gcry_md_write(context, user->getCallingStationId().c_str(), user->getCallingStationId().length());
	gcry_md_write(context, user->getUntrustedPort().c_str(), user->getUntrustedPort().length());
	gcry_md_write(context, user->getUntrustedPort().c_str(), user->getUntrustedPort().length());

	portnumber << user->getPortnumber();
	gcry_md_write(context, portnumber.str().c_str(), portnumber.str().length());
	time(&rawtime);
	strtime = ctime(&rawtime);
	gcry_md_write(context, strtime.c_str(), strtime.length());
	memcpy(digest, gcry_md_read(context, GCRY_MD_MD5), 16);
	gcry_md_close(context);

	unsigned int h, l;
	char *p = text;
	unsigned char *c = digest;
	for (i = 0; i < 16; i++) {
		h = *c / 16;
		l = *c % 16;
		c++;
		*p++ = "01234567890ABCDEF"[h];
		*p++ = "01234567890ABCDEF"[l];
	}
	text[32] = '\0';
	return string(text);
}

/** The function implements the thread for authentication. If the auth_control_file is specified the thread writes the results in the
 * auth_control_file, if the file is not specified the thread forward the OPENVPN_PLUGIN_FUNC_SUCCESS or OPENVPN_PLUGIN_FUNC_ERROR
 * to the main process.
 * @param _context The context pointer from OpenVPN.
 */

void* auth_user_pass_verify(void* c) {
	PluginContext * context = (PluginContext *) c;

	if (DEBUG(context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Auth_user_pass_verify thread started." << endl;

	//pthread_mutex_lock(context->getMutexSend());

	//ignore signals
	static sigset_t signal_mask;
	sigemptyset(&signal_mask);
	sigaddset(&signal_mask, SIGINT);
	sigaddset(&signal_mask, SIGTERM);
	sigaddset(&signal_mask, SIGHUP);
	sigaddset(&signal_mask, SIGUSR1);
	sigaddset(&signal_mask, SIGUSR2);
	sigaddset(&signal_mask, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

	//main thread loop for authentication
	while (!context->getStopThread()) {
		if (context->UserWaitingtoAuth() == false) {
			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Waiting for new user." << endl;

			pthread_mutex_lock(context->getMutexSend());
			pthread_cond_wait(context->getCondSend(), context->getMutexSend());
			pthread_mutex_unlock(context->getMutexSend());
		}

		if (context->getStopThread() == true) {
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Stop signal received." << endl;
			break;
		}

		if (DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: New user from OpenVPN!" << endl;

		/** A context for the new user.*/
		UserPlugin* newuser = context->getNewUser();

		/** A context for an already known user.*/
		UserPlugin* olduser = context->findUser(newuser->getKey());

		// probably key re-negotiation
		if (olduser != NULL) {
			if (DEBUG(context->getVerbosity() ))
				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Renegotiation: username: " << olduser->getUsername()
						<< "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t olduser ip: " << olduser->getCallingStationId()
						<< "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t olduser port: " << olduser->getUntrustedPort()
						<< "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t olduser FramedIP: " << olduser->getFramedIp()
						<< "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t newuser ip: " << olduser->getCallingStationId()
						<< "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t newuser port: " << olduser->getUntrustedPort() << endl;
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: isAuthenticated()" << olduser->isAuthenticated() << endl;
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: isAcct()" << olduser->isAccounted() << endl;

			// update password and username, can happen when a new connection is established from the same client with the same port before the timeout in the openvpn server occurs!
			olduser->setPassword(newuser->getPassword());
			olduser->setUsername(newuser->getUsername());
			olduser->setAuthControlFile(newuser->getAuthControlFile());

			//delete the newuser and use the olduser
			delete newuser;
			newuser = olduser;
			//TODO: for threading check if the user is already accounted (He must be for re-negotiation)
		} else { //new user for authentication, no re-negotiation
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: New user." << endl;
			newuser->setPortnumber(context->addNasPort());
			newuser->setSessionId(createSessionId(newuser));
			//add the user to the context
			context->addUser(newuser);
		}

		if (DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: New user: username: " << newuser->getUsername()
				<< "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t password: *****"
				<< "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t newuser ip: " << newuser->getCallingStationId()
				<< "\nRADIUS-PLUGIN: FOREGROUND THREAD:\t newuser port: " << newuser->getUntrustedPort() << endl;


		// there must be a username
		if (newuser->getUsername().size() > 0) { //&& olduser==NULL)
			//send the informations to the background process
			context->authsocketbackgr.send(COMMAND_VERIFY);
			context->authsocketbackgr.send(newuser->getUsername());
			context->authsocketbackgr.send(newuser->getPassword());
			context->authsocketbackgr.send(newuser->getPortnumber());
			context->authsocketbackgr.send(newuser->getSessionId());
			context->authsocketbackgr.send(newuser->getCallingStationId());
			context->authsocketbackgr.send(newuser->getCommonname());
			context->authsocketbackgr.send(newuser->getFramedIp());


			//get the response
			const int status = context->authsocketbackgr.recvInt();
			if (status == RESPONSE_SUCCEEDED) {
				if (DEBUG(context->getVerbosity()))
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Authentication succeeded!" << endl;

				// get the routes from background process
				newuser->setFramedRoutes(context->authsocketbackgr.recvStr());
				if (DEBUG(context->getVerbosity()))
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Received routes for user: " << newuser->getFramedRoutes() << "." << endl;

				// get the framed ip
				newuser->setFramedIp(context->authsocketbackgr.recvStr());
				if (DEBUG(context->getVerbosity()))
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Received framed ip for user: " << newuser->getFramedIp() << "." << endl;


				// get the interval from the background process
				newuser->setAcctInterimInterval(context->authsocketbackgr.recvInt());
				if (DEBUG(context->getVerbosity()))
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Receive acctinteriminterval " << newuser->getAcctInterimInterval() << " sec from backgroundprocess." << endl;

				// clear the buffer if it isn't empty
				if (newuser->getVsaBuf() != NULL) {
					delete[] newuser->getVsaBuf();
					newuser->setVsaBuf(NULL);
				}

				// get the vendor specific attribute buffer from the background process
				context->authsocketbackgr.recvBuf(newuser);

				//add the user to the context
				// if the is already in the map, addUser will throw an exception
				// only add the user if he it not known already

				if (newuser->isAuthenticated() == false) {
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Add user to map." << endl;
					newuser->setAuthenticated(true);
				} else if (newuser->isAuthenticated() && olduser != NULL) {
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Don't add the user to the map, it is a re-keying." << endl;
				}

				if (newuser->getAuthControlFile().length() > 0 && context->conf.getUseAuthControlFile()) {
					write_auth_control_file(context, newuser->getAuthControlFile(), '1');
				} else {
					pthread_mutex_lock(context->getMutexRecv());
					context->setResult(OPENVPN_PLUGIN_FUNC_SUCCESS);

					pthread_cond_signal(context->getCondRecv());
					pthread_mutex_unlock(context->getMutexRecv());

				}
			} else { //AUTH failed
				// user is already known, delete him from the accounting
				if (newuser->isAccounted()) {
					cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Error at re-keying!" << endl;

					// error on authenticate user at re-keying -> delete the user!
					// send the information to the background process
					context->acctsocketbackgr.send(DEL_USER);
					context->acctsocketbackgr.send(newuser->getKey());

					//get the response
					const int status = context->acctsocketbackgr.recvInt();
					if (status == RESPONSE_SUCCEEDED) {
						if (DEBUG(context->getVerbosity()))
							cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Accounting for user with key" << newuser->getKey() << " stopped!" << endl;
					} else {
						cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Error in ACCT Background Process!" << endl;
						cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: User is deleted from the user map!" << endl;
					}
				}

				cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Error receiving auth confirmation from background process." << endl;

				//clean up: nas port, context, memory
				context->delNasPort(newuser->getPortnumber());
				context->delUser(newuser->getKey());

				if (newuser->getAuthControlFile().length() > 0 && context->conf.getUseAuthControlFile()) {
					write_auth_control_file(context, newuser->getAuthControlFile(), '0');
				} else {
					pthread_mutex_lock(context->getMutexRecv());
					context->setResult(OPENVPN_PLUGIN_FUNC_ERROR);
					pthread_cond_signal(context->getCondRecv());
					pthread_mutex_unlock(context->getMutexRecv());

				}
				delete newuser;
			}
		} else {
			//clean up: nas port, context, memory
			context->delNasPort(newuser->getPortnumber());
			context->delUser(newuser->getKey());


			//return OPENVPN_PLUGIN_FUNC_ERROR;
			if (newuser->getAuthControlFile().length() > 0 && context->conf.getUseAuthControlFile()) {
				write_auth_control_file(context, newuser->getAuthControlFile(), '0');
			} else {
				pthread_mutex_lock(context->getMutexRecv());
				context->setResult(OPENVPN_PLUGIN_FUNC_ERROR);

				pthread_cond_signal(context->getCondRecv());
				pthread_mutex_unlock(context->getMutexRecv());
			}
			delete newuser;
		}
	}
	pthread_mutex_unlock(context->getMutexSend());
	cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND THREAD: Thread finished.\n";
	pthread_exit(NULL);
}

/** Writes the result of the authentication to the auth control file (0: failure, 1: success).
 * @param filename The auth control file.
 * @param c The authentication result.
 */
void write_auth_control_file(PluginContext * context, string filename, char c) {
	ofstream file;
	file.open(filename.c_str(), ios::out);
	if (DEBUG ( context->getVerbosity() ))
		cerr << getTime() << "RADIUS-PLUGIN: Write " << c << " to auth_control_file " << filename << ".\n";
	if (file.is_open()) {
		file << c;
		file.close();
	} else {
		cerr << getTime() << "RADIUS-PLUGIN: Could not open auth_control_file " << filename << ".\n";
	}

}

/** Returns the current time:
 * @return The current time as a string.
 */
string getTime() {
	time_t rawtime;
	struct tm * timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	string t(ctime(&rawtime));
	t.replace(t.find("\n"), 1, " ");
	return t;
}

void get_user_env(PluginContext * context, const int type, const char * envp[], UserPlugin * user) {
	if (get_env("username", envp) == NULL) {
		if (context->conf.getAccountingOnly() == false) {
			throw Exception("RADIUS-PLUGIN: FOREGROUND: username is not defined\n");
		}

	} else if (get_env("password", envp) == NULL) {
		if (type == OPENVPN_PLUGIN_AUTH_USER_PASS_VERIFY && context->conf.getAccountingOnly() == false) {
			throw Exception("RADIUS-PLUGIN: FOREGROUND: password is not defined\n");
		}

	} else if (get_env("untrusted_ip", envp) == NULL && get_env("untrusted_ip6", envp) == NULL) {
		throw Exception("RADIUS-PLUGIN: FOREGROUND: untrusted_ip and untrusted_ip6 is not defined\n");

	} else if (get_env("common_name", envp) == NULL && context->conf.getUsernameAsCommonname() == false) {
		if (context->conf.getClientCertNotRequired() == false) {
			throw Exception("RADIUS-PLUGIN: FOREGROUND: common_name is not defined\n");
		}

	} else if (get_env("untrusted_port", envp) == NULL) {
		throw Exception("RADIUS-PLUGIN: FOREGROUND: untrusted_port is not defined\n");
	}

	if (get_env("auth_control_file", envp) != NULL) {
		user->setAuthControlFile(get_env("auth_control_file", envp));
	}

	// get username, password, unrusted_ip and common_name from envp string array
	// if the username is not defined and only accounting is used, set the username to the commonname
	if (get_env("username", envp) != NULL)
		user->setUsername(get_env("username", envp));
	else if (context->conf.getAccountingOnly() == true)
		user->setUsername(get_env("common_name", envp));

	if (get_env("password", envp) != NULL)
		user->setPassword(get_env("password", envp));

	// rewrite the username if OpenVPN use the option username-as-comon-name
	if (context->conf.getUsernameAsCommonname() == true) {
		if (DEBUG ( context->getVerbosity() ))
			cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Commonname set to Username\n";
		user->setCommonname(get_env("username", envp));
	}

	if (get_env("common_name", envp) != NULL) {
		user->setCommonname(get_env("common_name", envp));
	}

	string untrusted_ip;
	if (get_env("untrusted_ip", envp) != NULL) {
		// it's ipv4
		untrusted_ip = get_env("untrusted_ip", envp);
	} else {
		// it's ipv6
		untrusted_ip = get_env("untrusted_ip6", envp);
	}
	user->setCallingStationId(untrusted_ip);

	//for OpenVPN option client cert not required, common_name is "UNDEF", see status.log
	user->setUntrustedPort(get_env("untrusted_port", envp));
	user->setStatusFileKey(user->getCommonname() + string(",") + untrusted_ip + string(":") + get_env("untrusted_port", envp));
	user->setKey(untrusted_ip + string(":") + get_env("untrusted_port", envp));
	if (DEBUG ( context->getVerbosity() ))
		cerr << getTime() << "RADIUS-PLUGIN: FOREGROUND: Key: " << user->getKey() << ".\n";
}
