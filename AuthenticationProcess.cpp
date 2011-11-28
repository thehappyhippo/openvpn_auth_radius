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

#include "AuthenticationProcess.h"

/** This method is the background process for authentication.
 * After it is called it is in a endless loop until it get's an EXIT-command.
 * Otherwise it waits the command COMMAND_VERIFY to authenticate
 * an user. It authenticates the user with the radius protocol and
 * sends the result back to the foreground process. If the response
 * is an access accept ticket, 
 * it parses the response from the radius server for the following attributes and 
 * send them to the foregroundprocess too.:
 * - FramedIpAddress
 * - FramedRoutes
 * - AcctInterimInterval
 * @param context The plugin context as an object from the class PluginContext.
 */

void AuthenticationProcess::Authentication(PluginContext * context) {
	/** The user to authenticate.*/
	UserAuth * user;

	/** A command from the parent process.*/
	int command;

	/** Whether the command loop should keep running */
	running = true;

	// Tell the parent everything is ok.
	try {
		context->authsocketforegr.send(RESPONSE_INIT_SUCCEEDED);
	} catch (Exception &e) {
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH:" << e << "\n";
		return;
	}

	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND  AUTH: Started, RESPONSE_INIT_SUCCEEDED was sent to Foreground Process.\n";

	// Event loop
	while (this->running) {
		// get a command from foreground process
		command = context->authsocketforegr.recvInt();

		switch (command) {
			// authenticate the user
			case COMMAND_VERIFY:
				// allocate memory for the new user
				user = new UserAuth();
				
				try {
					//get the user informations
					user->setUsername(context->authsocketforegr.recvStr());
					user->setPassword(context->authsocketforegr.recvStr());
					user->setPortnumber(context->authsocketforegr.recvInt());
					user->setSessionId(context->authsocketforegr.recvStr());
					user->setCallingStationId(context->authsocketforegr.recvStr());
					user->setCommonname(context->authsocketforegr.recvStr());

					// framed-ip is an @IP if we're re-negotiating, "" otherwise
					user->setFramedIp(context->authsocketforegr.recvStr());

					if (DEBUG(context->getVerbosity()) && (user->getFramedIp().compare("") == 0))
						cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND  AUTH: New user auth: username: " << user->getUsername()
								<< "\nRADIUS-PLUGIN: BACKGROUND  AUTH: password: *****"
								<< "\nRADIUS-PLUGIN: BACKGROUND  AUTH: calling station: " << user->getCallingStationId()
								<< "\nRADIUS-PLUGIN: BACKGROUND  AUTH: commonname: " << user->getCommonname() << endl;

					if (DEBUG(context->getVerbosity()) && (user->getFramedIp().compare("") != 0))
						cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND  AUTH: Old user ReAuth: username: " << user->getUsername()
								<< "\nRADIUS-PLUGIN: BACKGROUND  AUTH: password: *****"
								<< "\nRADIUS-PLUGIN: BACKGROUND  AUTH: calling station: " << user->getCallingStationId()
								<< "\nRADIUS-PLUGIN: BACKGROUND  AUTH: commonname: " << user->getCommonname() << endl;
					
					// send the AcceptRequestPacket
					if (user->sendAcceptRequestPacket(context) == 0) { /* Succeeded */
						// if the authentication succeeded
						// create the user configuration file
						// Unless this is a renegotiation (ie: if FramedIP is already set)
						if (user->createCcdFile(context) > 0 && (user->getFramedIp().compare("") == 0)) {
							throw Exception("RADIUS-PLUGIN: BACKGROUND AUTH: Ccd-file could not created for user with commonname: " + user->getCommonname() + "!\n");
						}

						// tell the parent process
						context->authsocketforegr.send(RESPONSE_SUCCEEDED);


						// send the routes to the parent process
						context->authsocketforegr.send(user->getFramedRoutes());


						// send the framed ip to the parent process
						context->authsocketforegr.send(user->getFramedIp());


						// send the interval to the parent process
						context->authsocketforegr.send(user->getAcctInterimInterval());


						// send the vsa buffer
						context->authsocketforegr.send(user->getVsaBuf(), user->getVsaBufLen());


						// free user_context_auth
						delete user;

						if (DEBUG (context->getVerbosity()))
							cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND  AUTH: Auth succeeded in radius_server().\n";

					} else { /* Failed */
						context->authsocketforegr.send(RESPONSE_FAILED);
						throw Exception("RADIUS-PLUGIN: BACKGROUND  AUTH: Auth failed!.\n");
					}
				} catch (Exception &e) {
					cerr << getTime() << e;
					delete user;

					if (e.getErrnum() == Exception::SOCKETSEND || e.getErrnum() == Exception::SOCKETRECV) {
						this->running = false;
					}
				} catch (...) {
					delete user;
					this->running = false;
				}

				break;


			//exit the loop
			case COMMAND_EXIT:
				this->running = false;
				break;

			case -1:
				cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: read error on command channel.\n";
				this->running = false;
				break;

			default:
				cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: unknown command code: code=" << command << ", exiting.\n";
				this->running = false;
				break;
		}
	}

	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: EXIT\n";

	return;
}

