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

#include "UserAuth.h"


int UserAuth::sendAcceptRequestPacket(PluginContext * context) {
	list<RadiusServer> * serverlist;
	list<RadiusServer>::iterator server;

	RadiusPacket packet(ACCESS_REQUEST);
	RadiusAttribute ra1(ATTRIB_User_Name, this->getUsername().c_str());
	RadiusAttribute ra2(ATTRIB_User_Password, this->password);
	RadiusAttribute ra3(ATTRIB_NAS_Port, this->getPortnumber());
	RadiusAttribute ra4(ATTRIB_Calling_Station_Id, this->getCallingStationId());
	RadiusAttribute ra5(ATTRIB_NAS_Identifier);
	RadiusAttribute ra6(ATTRIB_NAS_IP_Address);
	RadiusAttribute ra7(ATTRIB_NAS_Port_Type);
	RadiusAttribute ra8(ATTRIB_Service_Type);
	RadiusAttribute ra9(ATTRIB_Framed_IP_Address);
	RadiusAttribute ra10(ATTRIB_Acct_Session_ID, this->getSessionId());
	RadiusAttribute ra12(ATTRIB_Framed_Protocol);

	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: radius_server()." << endl;
	
	// get the server list
	serverlist = context->radiusconf.getRadiusServer();

	// set server to the first server
	server = serverlist->begin();
	
	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: Build password packet:  password: *****, sharedSecret: *****." << endl;

	// add the attributes
	if (packet.addRadiusAttribute(&ra1))
		cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_User_Name." << endl;

	if (packet.addRadiusAttribute(&ra2))
		cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_User_Password." << endl;

	if (packet.addRadiusAttribute(&ra3))
		cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_NAS_Port." << endl;

	if (packet.addRadiusAttribute(&ra4))
		cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_Calling_Station_Id." << endl;

	if (packet.addRadiusAttribute(&ra10))
		cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_Acct_Session_ID." << endl;

	// get information from the config and add it to the packet
	if (strcmp(context->radiusconf.getNASIdentifier(), "")) {
		ra5.setValue(context->radiusconf.getNASIdentifier());
		if (packet.addRadiusAttribute(&ra5))
			cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_NAS_Identifier." << endl;
	}

	if (strcmp(context->radiusconf.getNASIpAddress(), "")) {
		ra6.setValue(context->radiusconf.getNASIpAddress());
		if (packet.addRadiusAttribute(&ra6))
			cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_NAS_Ip_Address." << endl;
	}

	if (strcmp(context->radiusconf.getNASPortType(), "")) {
		ra7.setValue(context->radiusconf.getNASPortType());
		if (packet.addRadiusAttribute(&ra7))
			cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_NAS_Port_Type." << endl;
	}

	if (strcmp(context->radiusconf.getServiceType(), "")) {
		ra8.setValue(context->radiusconf.getServiceType());
		if (packet.addRadiusAttribute(&ra8))
			cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_Service_Type." << endl;
	}

	if (strcmp(context->radiusconf.getFramedProtocol(), "")) {
		ra12.setValue(context->radiusconf.getFramedProtocol());
		if (packet.addRadiusAttribute(&ra12))
			cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute ATTRIB_Framed_Protocol." << endl;
	}

	if (this->getFramedIp().compare("") != 0) {
		if (DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: Send packet Re-Auth packet for framedIP=" << this->getFramedIp().c_str() << "." << endl;

		ra9.setValue(this->getFramedIp());
		if (packet.addRadiusAttribute(&ra9))
			cerr << getTime() << "RADIUS-PLUGIN: Fail to add attribute Framed-IP-Address." << endl;
	}

	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: Send packet to " << server->getName().c_str() << "." << endl;

	// send the packet
	if (packet.radiusSend(server) < 0) {
		cerr << getTime() << "RADIUS-PLUGIN: Packet was not sent." << endl;
		return 1;
	}

	// receive the packet
	if (packet.radiusReceive(serverlist) == 0) {
		// is it a accept?
		if (packet.getCode() == ACCESS_ACCEPT) {
			if (DEBUG (context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Get ACCESS_ACCEPT-Packet." << endl;

			// parse the attributes
			this->parseResponsePacket(&packet, context);

			// check class
			list<string> confClassList = context->conf.getClassList();
			if (!context->conf.getClassList().empty()) {
				for (list<string>::iterator iter = confClassList.begin(); iter!=confClassList.end(); iter++ ) {
					string d = *iter;
					if (DEBUG(context->getVerbosity())) {
						cerr << getTime() << "RADIUS-PLUGIN: Checking against '" << d.c_str() << "'" << endl;
					}

					if(strncmp(d.c_str(), this->getClass().c_str(), min(d.size(), this->getClass().size())) == 0) {
						return 0;
					}
				}

				if (DEBUG(context->getVerbosity()))
					cerr << getTime() << "RADIUS-PLUGIN: Did not find a valid class in Radius packet." << endl;

				return 1;
			} else {
				return 0;
			}
		} else if (packet.getCode() == ACCESS_REJECT) {
			if (DEBUG(context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: Get ACCESS_REJECT-Packet." << endl;

			// parse the attributes for replay message
			this->parseResponsePacket(&packet, context);
			return 1;
		} else {
			cerr << getTime() << "RADIUS-PLUGIN: Get ACCESS_REJECT or ACCESS_CHALLENGE-Packet.->ACCESS-DENIED." << endl;
		}
	} else {
		cerr << getTime() << "RADIUS-PLUGIN: Got no response from radius server." << endl;
	}
	
	return 1;
}

void UserAuth::parseResponsePacket(RadiusPacket *packet, PluginContext * context) {
	pair<multimap<Octet, RadiusAttribute>::iterator, multimap<Octet, RadiusAttribute>::iterator> range;
	multimap<Octet, RadiusAttribute>::iterator iter1, iter2;
	RadiusVendorSpecificAttribute vsa;

	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: parse_response_packet()." << endl;
	
	// extract framed routes
	range = packet->findAttributes(ATTRIB_Framed_Route);
	iter1 = range.first;
	iter2 = range.second;
	string froutes;
	while (iter1 != iter2) {
		froutes.append((char *) iter1->second.getValue(), iter1->second.getLength() - 2);
		froutes.append(";");
		iter1++;
	}
	this->setFramedRoutes(froutes);
	
	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: routes: " << this->getFramedRoutes() << "." << endl;
	
	// extract framed IP address
	range = packet->findAttributes(ATTRIB_Framed_IP_Address);
	iter1 = range.first;
	iter2 = range.second;
	
	if (iter1 != iter2) {
		this->setFramedIp(iter1->second.ipFromBuf());
	}

	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: framed ip: " << this->getFramedIp() << "." << endl;
	
	// extract accounting interim interval
	range = packet->findAttributes(ATTRIB_Acct_Interim_Interval);
	iter1 = range.first;
	iter2 = range.second;
	if (iter1 != iter2) {
		this->setAcctInterimInterval(iter1->second.intFromBuf());
	}

	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Acct Interim Interval: " << this->getAcctInterimInterval() << "." << endl;
	
	// extract vendor specific attribute (VSA)
	range = packet->findAttributes(ATTRIB_Vendor_Specific);
	iter1 = range.first;
	iter2 = range.second;
	while (iter1 != iter2) {
		this->appendVsaBuf(iter1->second.getValue(), iter1->second.getLength() - 2);
		iter1++;
	}

	// extract reply message
	range = packet->findAttributes(ATTRIB_Reply_Message);
	iter1 = range.first;
	iter2 = range.second;
	string msg;
	while (iter1 != iter2) {
		msg.append((char*) iter1->second.getValue(), iter1->second.getLength() - 2);
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Reply-Message:" << msg << "" << endl;
		iter1++;
	}

	// extract class
	range = packet->findAttributes(ATTRIB_Class);
	iter1 = range.first;
	iter2 = range.second;
	if (iter1 != iter2) {
		string klass((char*) iter1->second.getValue());
		this->setClass(klass);
	}

	if (DEBUG (context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: class: " << this->getClass() << "." << endl;
}


int UserAuth::createCcdFile(PluginContext *context) {
	ofstream ccdfile;
	
	char framedip[16];
	char ipstring[100];
	string filename;
	char framedroutes[4096];
	char framednetmask_cidr[3]; // ->/24
	char framednetmask[16]; // ->255.255.255.0
	char mask_part[6];
	char framedgw[16];
	char framedmetric[5]; //what is the biggest metric? 

	double d1, d2;
	
	int j = 0, k = 0;
	

	// check whether we really should write the config file
	if (!(context->conf.getOverWriteCCFiles() == true && (this->getFramedIp().length() > 0 || this->getFramedRoutes().length() > 0))) {
		cerr << getTime() << "RADIUS-PLUGIN: Client config file was not written, overwriteccfiles is false \n.";
		return 0;
	}

	memset(ipstring, 0, 100);
	memset(framedip, 0, 16);
	memset(framedroutes, 0, 4096);


	// create the filename, ccd-path + commonname
	filename = context->conf.getCcdPath() + this->getCommonname();

	if (DEBUG(context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Try to open ccd file." << endl;

	// open the file
	ccdfile.open(filename.c_str(), ios::out);

	if (!ccdfile.is_open()) {
		cerr << getTime() << "RADIUS-PLUGIN: Could not open file " << filename << "." << endl;
		return 1;
	}

	if (DEBUG(context->getVerbosity()))
		cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Opened ccd file." << endl;


	// copy in a temp-string, becaue strtok deletes the delimiter, if it is used anywhere
	strncpy(framedroutes, this->getFramedRoutes().c_str(), 4095);

	// set the ip address in the file
	if (this->framedip[0] != '\0') {
		if (DEBUG (context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Write framed ip to ccd-file." << endl;

		// build the ifconfig
		strncat(ipstring, "ifconfig-push ", 14);
		strncat(ipstring, this->getFramedIp().c_str(), 15);
		strncat(ipstring, " ", 1);

		if (context->conf.getSubnet()[0] != '\0') {
			strncat(ipstring, context->conf.getSubnet(), 15);

			if (DEBUG (context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Create ifconfig-push for topology subnet." << endl;

		} else if (context->conf.getP2p()[0] != '\0') {
			strncat(ipstring, context->conf.getP2p(), 15);

			if (DEBUG (context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Create ifconfig-push for topology p2p." << endl;

		} else {
			// increment the last byte of the ip address
			// in interface needs two addresses because it is a
			// convert from string to integer in network byte order
			in_addr_t ip2 = inet_addr(this->getFramedIp().c_str());

			// convert from network byte order to host byte order
			ip2 = ntohl(ip2);

			// increment
			ip2++;

			// convert from host byte order to network byte order
			ip2 = htonl(ip2);

			// copy from one unsigned int to another (casting don't work with these struct!?) FIXME
			in_addr ip3;
			memcpy(&ip3, &ip2, 4);

			// append the new ip address to the string
			strncat(ipstring, inet_ntoa(ip3), 15);

			if (DEBUG (context->getVerbosity()))
				cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Create ifconfig-push for topology net30." << endl;
		}
		if (DEBUG (context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: Write " << ipstring << " ccd-file." << endl;

		ccdfile << ipstring << "" << endl;
	}

	// set the framed routes in the file
	if (framedroutes[0] != '\0') {
		if (DEBUG(context->getVerbosity()))
			cerr << getTime() << "RADIUS-PLUGIN: BACKGROUND AUTH: Write framed routes to ccd-file." << endl;

		char* route = strtok(framedroutes, ";");
		int len = strlen(route);
		if (len > 50) { //this is too big! but the length is variable
			cerr << getTime() << "RADIUS-PLUGIN: Argument for Framed Route is to long (>50 Characters)." << endl;
			return 1;
		} else {
			while (route != NULL) {
				j = 0;
				k = 0;
				// set everything back for the next route entry
				memset(mask_part, 0, 6);
				memset(framednetmask_cidr, 0, 3);
				memset(framedip, 0, 16);
				memset(framednetmask, 0, 16);
				memset(framedgw, 0, 16);
				memset(framedmetric, 0, 5);
				
				// add ip address to string
				while (route[j] != '/' && j < len) {
					if (route[j] != ' ') {
						framedip[k] = route[j];
						k++;
					}
					j++;
				}
				k = 0;
				j++;

				// add netmask
				while (route[j] != ' ' && j <= len) {
					framednetmask_cidr[k] = route[j];
					k++;
					j++;
				}
				k = 0;

				// jump spaces
				while (route[j] == ' ' && j < len) {
					j++;
				}

				// find gateway
				while (route[j] != '/' && j < len) {
					if (route[j] != ' ') {
						framedgw[k] = route[j];
						k++;
					}
					j++;
				}
				j++;

				// find gateway netmask (this isn't used at the command route under linux)
				while (route[j] != ' ' && j < len) {
					j++;
				}

				// jump spaces
				while (route[j] == ' ' && j < len) {
					j++;
				}

				//find the metric
				if (j <= len) {
					k = 0;
					while (route[j] != ' ' && j < len) {
						framedmetric[k] = route[j];
						k++;
						j++;
					}
				}

				// create string for client config file
				// transform framednetmask_cidr
				d2 = 7;
				d1 = 0;
				memset(framednetmask, 0, 16);
				if (atoi(framednetmask_cidr) > 32) {
					cerr << getTime() << "RADIUS-PLUGIN: Bad net CIDR netmask." << endl;
				} else {
					for (k = 1; k <= atoi(framednetmask_cidr); k++) {
						d1 = d1 + pow(2, d2);
						d2--;

						if (k == 8) {
							sprintf(mask_part, "%.0lf.", d1);
							d1 = 0;
							d2 = 7;
							strncat(framednetmask, mask_part, 4);
							memset(mask_part, 0, 6);
						}
						if (k == 16) {
							sprintf(mask_part, "%.0lf.", d1);
							d1 = 0;
							d2 = 7;
							strncat(framednetmask, mask_part, 4);
							memset(mask_part, 0, 6);
						}
						if (k == 24) {
							sprintf(mask_part, "%.0lf.", d1);
							d1 = 0;
							d2 = 7;
							strncat(framednetmask, mask_part, 4);
							memset(mask_part, 0, 6);
						}
					}
					if (j < 8) {
						sprintf(mask_part, "%.0lf.", d1);
						d1 = 0;
						strncat(framednetmask, mask_part, 4);
						strncat(framednetmask, "0.0.0", 5);
						memset(mask_part, 0, 6);
					} else if (j < 16) {
						sprintf(mask_part, "%.0lf.", d1);
						d1 = 0;
						strncat(framednetmask, mask_part, 4);
						strncat(framednetmask, "0.0", 3);
						memset(mask_part, 0, 6);
					} else if (j < 24) {
						sprintf(mask_part, "%.0lf.", d1);
						d1 = 0;
						strncat(framednetmask, mask_part, 4);
						strncat(framednetmask, "0", 1);
						memset(mask_part, 0, 6);
					} else if (j > 24) {
						sprintf(mask_part, "%.0lf", d1);
						d1 = 0;
						strncat(framednetmask, mask_part, 4);
						memset(mask_part, 0, 6);
					}

				}

				if (DEBUG(context->getVerbosity()))
					cerr << getTime() << "RADIUS-PLUGIN: Write route string: iroute " << framedip << framednetmask << " to ccd-file." << endl;

				// write iroute to client file
				ccdfile << "iroute " << framedip << " " << framednetmask << endl;

				route = strtok(NULL, ";");
			}
		}
	}

	ccdfile.close();
	
	return 0;
}

