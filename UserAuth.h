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

#ifndef _USER_AUTH_H_
#define _USER_AUTH_H_
#include <cmath>
#include "RadiusClass/RadiusPacket.h"
#include "RadiusClass/RadiusServer.h"
#include "RadiusClass/RadiusAttribute.h"
#include "RadiusClass/RadiusVendorSpecificAttribute.h"
#include "RadiusClass/error.h"
#include "RadiusClass/vsa.h"
#include "User.h"
#include "PluginContext.h"
#include "radiusplugin.h"
#include <string.h>
#include <fstream>
#include <list>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

/**The class represents an user for the authentication process.**/
class UserAuth: public User {
public:
	UserAuth() : User() { };
	~UserAuth() {};

	/** The getter method for the password.
	 * @return The password as a string.
	 */
	string getPassword(void) { return this->password; };

	/**The setter method for the password.
	 * @param passwd The password.
	 */
	void setPassword(string passwd) { this->password = passwd; };

	string getClass(void) { return this->klass; };

	void setClass(string cls) { this->klass = cls; };

	/**The method send an authentication packet to the radius server and
	 * calls the method parseResponsePacket(). The following attributes are in the packet:
	 * - User_Name,
	 * - User_Password
	 * - NAS_PortCalling_Station_Id,
	 * - NAS_Identifier,
	 * - NAS_IP_Address,
	 * - NAS_Port_Type
	 * - Service_Type.
	 * @param context The context of the background process.
	 * @return An integer, 0 if the authentication succeded, else 1.*/
	int sendAcceptRequestPacket(PluginContext *);

	/** The method creates the client config file in the client config dir (ccd).
	 * The path is set in the radiusplugin config file.
	 * Radius attributes which written to the file are FramedIP as ifconfig-push option and FramedRoutes as iroute option.
	 * TODO: not IPv6 ready
	 * @param context : The plugin context.
	 * @return An integer, if everything is ok 0, else 1.
	 */
	int createCcdFile(PluginContext *);

private:
	/** The password of the user.*/
	string password;

	/** The classes of the user as returned by the server */
	string klass;

	/** The method parse the authentication response packet for
	 * the attributes framed ip, framed routes and accinteriminterval
	 * and saves the values in the UserAuth object. The there is no acctinteriminterval
	 * it is set to 0.
	 * @param packet A pointer to the radius packet to parse.
	 * @param context The plugin context.
	 */
	void parseResponsePacket(RadiusPacket *, PluginContext *);
};

#endif //_USER_CONTEXT_AUTH_H_
