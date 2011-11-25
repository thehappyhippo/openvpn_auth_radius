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

#ifndef _USER_H_
#define _USER_H_

#include <string>
#include <iostream>
#include <cstdio>
#include <cstring>
//#include "openvpn-plugin.h"

/** The datatype for sending and receiving data to and from the network */
typedef unsigned char Octet;

using namespace std;

/** The user class represents a general user for the three different processes (foreground,
 * authentication background, accounting background). Here are defined the
 * common attributes and functions.*/
class User {
public:
	User();
	//User(int);
	~User();

	User & operator=(const User &);
	User(const User &);

	string getUsername(void);
	void setUsername(string);

	string getCommonname(void);
	void setCommonname(string);

	string getFramedRoutes(void);
	void setFramedRoutes(string);

	string getFramedIp(void);
	void setFramedIp(string);

	string getKey(void);
	void setKey(string);

	string getStatusFileKey(void);
	void setStatusFileKey(string);

	string getCallingStationId(void);
	void setCallingStationId(string);

	int getPortnumber(void);
	void setPortnumber(int);

	time_t getAcctInterimInterval(void);
	void setAcctInterimInterval(time_t);

	string getUntrustedPort(void);
	void setUntrustedPort(string);

	int appendVsaBuf(Octet *, unsigned int len);
	Octet * getVsaBuf();
	void setVsaBuf(Octet *);

	unsigned int getVsaBufLen();
	void setVsaBufLen(unsigned int);

	string getSessionId(void);
	void setSessionId(string);

	//void setTrustedPort ( const string& theValue );
	//string getTrustedPort() const;

	//void setTrustedIp ( const string& theValue );
	//string getTrustedIp() const;

protected:
	/** The username.*/
	string username;

	/** The common name.*/
	string commonname;

	/** The framed-routes, they are stored as a string. if there are more routes, they must be delimited by an ';'*/
	string framedroutes;

	/** The framed ip.*/
	string framedip;

	/** The calling station id, in this case the real ip address of the client.*/
	string callingstationid;

	/** A unique key to find the user in a map. */
	string key;

	/** Unique identifier in the status log file (version 1) "commonname,untrusted_ip:untrusted_port"*/
	string statusfilekey;

	/** The port number.*/
	int portnumber;

	/** The accounting interim interval.*/
	time_t acctinteriminterval;

	/** The untrusted port number from OpenVPN for a client.*/
	string untrustedport;

	/** The trusted port number from OpenVPN for a client.*/
	//string trustedport;

	/** The trusted ip from OpenVPN for a client.*/
	//string trustedip;

	/** Buffer for all VSA attributes.*/
	Octet * vsabuf;

	/** Length of vsabuf.*/
	unsigned int vsabuflen;

	/** The user sessionid.*/
	string sessionid;
};

#endif //_USER_H_
