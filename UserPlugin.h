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

#ifndef _USERPLUGIN_H_
#define _USERPLUGIN_H_

#include "User.h"
#include <time.h>
#include <string.h>
#include <string>
#include <iostream>
using std::string;

/** This class represents an user of the foreground process. 
 * It is derived from the class User.*/
class UserPlugin: public User {
public:
	UserPlugin(int);
	UserPlugin();
	~UserPlugin();

	string getSessionId(void);
	void setSessionId(string);

	string getPassword(void);
	void setPassword(string);

	string getAuthControlFile(void);
	void setAuthControlFile(string);

	UserPlugin & operator=(const UserPlugin &);

	UserPlugin(const UserPlugin &);

	bool isAuthenticated(void);
	void setAuthenticated(bool);

	bool isAccounted(void);
	void setAccounted(bool);

private:
	/** The user password.*/
	string password;

	/** The auth control file of the user.*/
	string authcontrolfile;

	/** Indicates if a user is authenticated.*/
	bool authenticated;

	/** Indicates if a user is accounted.*/
	bool accounted;
};

#endif //_USERPLUGIN_H_
