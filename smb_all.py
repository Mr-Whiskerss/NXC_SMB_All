#!/usr/bin/env python3
"""
SMB_All - Comprehensive SMB Enumeration Module for NetExec
Author: Dan
Description: Enumerates everything available via SMB protocol including shares, sessions,
             disks, logged-on users, local users/groups, domain info, password policy, and more.

Usage: nxc smb <target> -u <user> -p <pass> -M smb_all
       nxc smb <target> -u <user> -p <pass> -M smb_all -o OUTPUT=results.txt
"""

from datetime import datetime
from impacket.dcerpc.v5 import transport, srvs, wkst, samr, lsat, lsad
from impacket.dcerpc.v5.dtypes import NULL, MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SessionError
from impacket.dcerpc.v5.samr import DCERPCSessionError
import json


class NXCModule:
    """
    Comprehensive SMB enumeration module
    """

    name = "smb_all"
    description = "Enumerate everything via SMB - shares, users, groups, sessions, disks, password policy, and more"
    supported_protocols = ["smb"]
    opsec_safe = True
    multiple_hosts = True

    def options(self, context, module_options):
        """
        OUTPUT    Save results to a file (optional)
        JSON      Output in JSON format (optional, set to 'true')
        VERBOSE   Show verbose output including errors (optional, set to 'true')
        """
        self.output_file = module_options.get("OUTPUT", None)
        self.json_output = module_options.get("JSON", "false").lower() == "true"
        self.verbose = module_options.get("VERBOSE", "false").lower() == "true"
        self.results = {}

    def on_login(self, context, connection):
        """Main execution method after successful authentication"""
        host = connection.host
        self.results[host] = {
            "host": host,
            "hostname": connection.hostname,
            "domain": connection.domain,
            "timestamp": datetime.now().isoformat(),
            "shares": [],
            "sessions": [],
            "disks": [],
            "logged_on_users": [],
            "local_users": [],
            "local_groups": [],
            "domain_users": [],
            "domain_groups": [],
            "password_policy": {},
            "os_info": {},
            "server_info": {},
            "errors": []
        }

        context.log.display(f"Starting comprehensive SMB enumeration on {host}")
        context.log.display("=" * 60)

        # Gather OS/Server info first
        self._enum_os_info(context, connection)

        # Enumerate shares
        self._enum_shares(context, connection)

        # Enumerate sessions
        self._enum_sessions(context, connection)

        # Enumerate disks
        self._enum_disks(context, connection)

        # Enumerate logged-on users
        self._enum_logged_on_users(context, connection)

        # Enumerate local users and groups via SAM
        self._enum_local_users(context, connection)
        self._enum_local_groups(context, connection)

        # Enumerate domain info if domain-joined
        if connection.domain:
            self._enum_domain_users(context, connection)
            self._enum_domain_groups(context, connection)

        # Enumerate password policy
        self._enum_password_policy(context, connection)

        # Save results if output file specified
        if self.output_file:
            self._save_results(context)

        context.log.display("=" * 60)
        context.log.success(f"SMB enumeration complete for {host}")

    def _enum_os_info(self, context, connection):
        """Enumerate OS and server information"""
        context.log.display("")
        context.log.highlight("[*] OS/Server Information")
        context.log.display("-" * 40)

        try:
            os_info = {
                "os": connection.os if hasattr(connection, 'os') else "Unknown",
                "hostname": connection.hostname,
                "domain": connection.domain,
                "signing": connection.signing if hasattr(connection, 'signing') else "Unknown",
                "smb_version": str(connection.smbv1) if hasattr(connection, 'smbv1') else "Unknown"
            }

            self.results[connection.host]["os_info"] = os_info

            context.log.display(f"  OS: {os_info['os']}")
            context.log.display(f"  Hostname: {os_info['hostname']}")
            context.log.display(f"  Domain: {os_info['domain']}")
            context.log.display(f"  Signing: {os_info['signing']}")

        except Exception as e:
            self._log_error(context, connection.host, "OS Info", e)

    def _enum_shares(self, context, connection):
        """Enumerate SMB shares with permissions"""
        context.log.display("")
        context.log.highlight("[*] SMB Shares")
        context.log.display("-" * 40)

        try:
            shares = connection.shares()
            for share in shares:
                share_name = share["name"]
                share_remark = share.get("remark", "")

                # Check permissions
                readable = False
                writable = False

                try:
                    connection.conn.listPath(share_name, "\\*")
                    readable = True
                except SessionError:
                    pass

                try:
                    # Try to create a temp file to check write access
                    connection.conn.createDirectory(share_name, "\\nxc_test_write_" + str(datetime.now().timestamp()))
                    connection.conn.deleteDirectory(share_name, "\\nxc_test_write_" + str(datetime.now().timestamp()))
                    writable = True
                except SessionError:
                    pass

                permissions = []
                if readable:
                    permissions.append("READ")
                if writable:
                    permissions.append("WRITE")

                perm_str = ",".join(permissions) if permissions else "NO ACCESS"

                share_info = {
                    "name": share_name,
                    "remark": share_remark,
                    "readable": readable,
                    "writable": writable,
                    "permissions": perm_str
                }

                self.results[connection.host]["shares"].append(share_info)

                # Color-coded output
                if writable:
                    context.log.success(f"  {share_name:<20} [{perm_str}] {share_remark}")
                elif readable:
                    context.log.highlight(f"  {share_name:<20} [{perm_str}] {share_remark}")
                else:
                    context.log.display(f"  {share_name:<20} [{perm_str}] {share_remark}")

        except Exception as e:
            self._log_error(context, connection.host, "Shares", e)

    def _enum_sessions(self, context, connection):
        """Enumerate active sessions"""
        context.log.display("")
        context.log.highlight("[*] Active Sessions")
        context.log.display("-" * 40)

        try:
            rpctransport = transport.SMBTransport(
                connection.host,
                445,
                r"\srvsvc",
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)

            resp = srvs.hNetrSessionEnum(dce, NULL, NULL, 10)

            for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
                session_user = session["sesi10_username"]
                session_client = session["sesi10_cname"]
                session_time = session["sesi10_time"]
                session_idle = session["sesi10_idle_time"]

                session_info = {
                    "user": session_user,
                    "client": session_client,
                    "time": session_time,
                    "idle_time": session_idle
                }

                self.results[connection.host]["sessions"].append(session_info)
                context.log.display(f"  {session_user}@{session_client} (Active: {session_time}s, Idle: {session_idle}s)")

            dce.disconnect()

            if not self.results[connection.host]["sessions"]:
                context.log.display("  No active sessions found")

        except DCERPCException as e:
            if "ACCESS_DENIED" in str(e):
                context.log.display("  Access denied - insufficient privileges")
            else:
                self._log_error(context, connection.host, "Sessions", e)
        except Exception as e:
            self._log_error(context, connection.host, "Sessions", e)

    def _enum_disks(self, context, connection):
        """Enumerate server disks"""
        context.log.display("")
        context.log.highlight("[*] Server Disks")
        context.log.display("-" * 40)

        try:
            rpctransport = transport.SMBTransport(
                connection.host,
                445,
                r"\srvsvc",
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(srvs.MSRPC_UUID_SRVS)

            resp = srvs.hNetrServerDiskEnum(dce, 0)

            for disk in resp["DiskInfoStruct"]["Buffer"]:
                disk_name = disk["Disk"]
                if disk_name:
                    self.results[connection.host]["disks"].append(disk_name)
                    context.log.display(f"  {disk_name}")

            dce.disconnect()

            if not self.results[connection.host]["disks"]:
                context.log.display("  No disks enumerated")

        except DCERPCException as e:
            if "ACCESS_DENIED" in str(e):
                context.log.display("  Access denied - insufficient privileges")
            else:
                self._log_error(context, connection.host, "Disks", e)
        except Exception as e:
            self._log_error(context, connection.host, "Disks", e)

    def _enum_logged_on_users(self, context, connection):
        """Enumerate logged-on users via Workstation Service"""
        context.log.display("")
        context.log.highlight("[*] Logged-On Users")
        context.log.display("-" * 40)

        try:
            rpctransport = transport.SMBTransport(
                connection.host,
                445,
                r"\wkssvc",
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(wkst.MSRPC_UUID_WKST)

            resp = wkst.hNetrWkstaUserEnum(dce, 1)

            for user in resp["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
                username = user["wkui1_username"]
                logon_domain = user["wkui1_logon_domain"]
                logon_server = user["wkui1_logon_server"]

                user_info = {
                    "username": username,
                    "logon_domain": logon_domain,
                    "logon_server": logon_server
                }

                self.results[connection.host]["logged_on_users"].append(user_info)
                context.log.display(f"  {logon_domain}\\{username} (Server: {logon_server})")

            dce.disconnect()

            if not self.results[connection.host]["logged_on_users"]:
                context.log.display("  No logged-on users found")

        except DCERPCException as e:
            if "ACCESS_DENIED" in str(e):
                context.log.display("  Access denied - insufficient privileges")
            else:
                self._log_error(context, connection.host, "Logged-On Users", e)
        except Exception as e:
            self._log_error(context, connection.host, "Logged-On Users", e)

    def _enum_local_users(self, context, connection):
        """Enumerate local users via SAM"""
        context.log.display("")
        context.log.highlight("[*] Local Users")
        context.log.display("-" * 40)

        try:
            rpctransport = transport.SMBTransport(
                connection.host,
                445,
                r"\samr",
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]

            for domain in domains:
                domain_name = domain["Name"]

                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
                domain_sid = resp["DomainId"]

                resp = samr.hSamrOpenDomain(dce, server_handle, samr.DOMAIN_LOOKUP | samr.DOMAIN_READ_PASSWORD_PARAMETERS | MAXIMUM_ALLOWED, domain_sid)
                domain_handle = resp["DomainHandle"]

                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle)
                    for user in resp["Buffer"]["Buffer"]:
                        rid = user["RelativeId"]
                        user_name = user["Name"]

                        # Get user details
                        try:
                            resp2 = samr.hSamrOpenUser(dce, domain_handle, MAXIMUM_ALLOWED, rid)
                            user_handle = resp2["UserHandle"]
                            resp3 = samr.hSamrQueryInformationUser(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
                            user_info_data = resp3["Buffer"]["All"]

                            user_info = {
                                "username": user_name,
                                "rid": rid,
                                "domain": domain_name,
                                "description": str(user_info_data["AdminComment"]),
                                "last_logon": str(user_info_data["LastLogon"]["LowPart"]),
                                "password_last_set": str(user_info_data["PasswordLastSet"]["LowPart"]),
                                "account_expires": str(user_info_data["AccountExpires"]["LowPart"]),
                                "user_account_control": user_info_data["UserAccountControl"]
                            }

                            samr.hSamrCloseHandle(dce, user_handle)
                        except Exception:
                            user_info = {
                                "username": user_name,
                                "rid": rid,
                                "domain": domain_name
                            }

                        self.results[connection.host]["local_users"].append(user_info)

                        # Format output
                        desc = user_info.get("description", "")[:30] if user_info.get("description") else ""
                        context.log.display(f"  {domain_name}\\{user_name} (RID: {rid}) {desc}")

                except DCERPCSessionError:
                    pass

                samr.hSamrCloseHandle(dce, domain_handle)

            samr.hSamrCloseHandle(dce, server_handle)
            dce.disconnect()

            if not self.results[connection.host]["local_users"]:
                context.log.display("  No local users enumerated")

        except DCERPCException as e:
            if "ACCESS_DENIED" in str(e):
                context.log.display("  Access denied - insufficient privileges")
            else:
                self._log_error(context, connection.host, "Local Users", e)
        except Exception as e:
            self._log_error(context, connection.host, "Local Users", e)

    def _enum_local_groups(self, context, connection):
        """Enumerate local groups via SAM"""
        context.log.display("")
        context.log.highlight("[*] Local Groups")
        context.log.display("-" * 40)

        try:
            rpctransport = transport.SMBTransport(
                connection.host,
                445,
                r"\samr",
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]

            for domain in domains:
                domain_name = domain["Name"]

                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
                domain_sid = resp["DomainId"]

                resp = samr.hSamrOpenDomain(dce, server_handle, MAXIMUM_ALLOWED, domain_sid)
                domain_handle = resp["DomainHandle"]

                try:
                    # Enumerate aliases (local groups)
                    resp = samr.hSamrEnumerateAliasesInDomain(dce, domain_handle)
                    for group in resp["Buffer"]["Buffer"]:
                        rid = group["RelativeId"]
                        group_name = group["Name"]

                        # Get group members
                        members = []
                        try:
                            resp2 = samr.hSamrOpenAlias(dce, domain_handle, MAXIMUM_ALLOWED, rid)
                            alias_handle = resp2["AliasHandle"]
                            resp3 = samr.hSamrGetMembersInAlias(dce, alias_handle)

                            for member_sid in resp3["Members"]["Sids"]:
                                members.append(str(member_sid["SidPointer"]))

                            samr.hSamrCloseHandle(dce, alias_handle)
                        except Exception:
                            pass

                        group_info = {
                            "name": group_name,
                            "rid": rid,
                            "domain": domain_name,
                            "members": members,
                            "member_count": len(members)
                        }

                        self.results[connection.host]["local_groups"].append(group_info)

                        member_str = f"({len(members)} members)" if members else ""
                        context.log.display(f"  {domain_name}\\{group_name} (RID: {rid}) {member_str}")

                except DCERPCSessionError:
                    pass

                samr.hSamrCloseHandle(dce, domain_handle)

            samr.hSamrCloseHandle(dce, server_handle)
            dce.disconnect()

            if not self.results[connection.host]["local_groups"]:
                context.log.display("  No local groups enumerated")

        except DCERPCException as e:
            if "ACCESS_DENIED" in str(e):
                context.log.display("  Access denied - insufficient privileges")
            else:
                self._log_error(context, connection.host, "Local Groups", e)
        except Exception as e:
            self._log_error(context, connection.host, "Local Groups", e)

    def _enum_domain_users(self, context, connection):
        """Enumerate domain users (if domain-joined)"""
        context.log.display("")
        context.log.highlight("[*] Domain Users (sample)")
        context.log.display("-" * 40)

        try:
            rpctransport = transport.SMBTransport(
                connection.host,
                445,
                r"\samr",
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            # Look for the actual domain (not Builtin)
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]

            for domain in domains:
                domain_name = domain["Name"]
                if domain_name.upper() == "BUILTIN":
                    continue

                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
                domain_sid = resp["DomainId"]

                resp = samr.hSamrOpenDomain(dce, server_handle, MAXIMUM_ALLOWED, domain_sid)
                domain_handle = resp["DomainHandle"]

                try:
                    resp = samr.hSamrEnumerateUsersInDomain(dce, domain_handle)
                    count = 0
                    for user in resp["Buffer"]["Buffer"]:
                        if count >= 20:  # Limit to first 20 for performance
                            context.log.display(f"  ... (limited to 20 users)")
                            break

                        rid = user["RelativeId"]
                        user_name = user["Name"]

                        user_info = {
                            "username": user_name,
                            "rid": rid,
                            "domain": domain_name
                        }

                        self.results[connection.host]["domain_users"].append(user_info)
                        context.log.display(f"  {domain_name}\\{user_name} (RID: {rid})")
                        count += 1

                except DCERPCSessionError:
                    pass

                samr.hSamrCloseHandle(dce, domain_handle)

            samr.hSamrCloseHandle(dce, server_handle)
            dce.disconnect()

            if not self.results[connection.host]["domain_users"]:
                context.log.display("  No domain users enumerated")

        except DCERPCException as e:
            if "ACCESS_DENIED" in str(e):
                context.log.display("  Access denied - insufficient privileges")
            else:
                self._log_error(context, connection.host, "Domain Users", e)
        except Exception as e:
            self._log_error(context, connection.host, "Domain Users", e)

    def _enum_domain_groups(self, context, connection):
        """Enumerate domain groups"""
        context.log.display("")
        context.log.highlight("[*] Domain Groups (sample)")
        context.log.display("-" * 40)

        try:
            rpctransport = transport.SMBTransport(
                connection.host,
                445,
                r"\samr",
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]

            for domain in domains:
                domain_name = domain["Name"]
                if domain_name.upper() == "BUILTIN":
                    continue

                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
                domain_sid = resp["DomainId"]

                resp = samr.hSamrOpenDomain(dce, server_handle, MAXIMUM_ALLOWED, domain_sid)
                domain_handle = resp["DomainHandle"]

                try:
                    resp = samr.hSamrEnumerateGroupsInDomain(dce, domain_handle)
                    count = 0
                    for group in resp["Buffer"]["Buffer"]:
                        if count >= 20:  # Limit for performance
                            context.log.display(f"  ... (limited to 20 groups)")
                            break

                        rid = group["RelativeId"]
                        group_name = group["Name"]

                        group_info = {
                            "name": group_name,
                            "rid": rid,
                            "domain": domain_name
                        }

                        self.results[connection.host]["domain_groups"].append(group_info)
                        context.log.display(f"  {domain_name}\\{group_name} (RID: {rid})")
                        count += 1

                except DCERPCSessionError:
                    pass

                samr.hSamrCloseHandle(dce, domain_handle)

            samr.hSamrCloseHandle(dce, server_handle)
            dce.disconnect()

            if not self.results[connection.host]["domain_groups"]:
                context.log.display("  No domain groups enumerated")

        except DCERPCException as e:
            if "ACCESS_DENIED" in str(e):
                context.log.display("  Access denied - insufficient privileges")
            else:
                self._log_error(context, connection.host, "Domain Groups", e)
        except Exception as e:
            self._log_error(context, connection.host, "Domain Groups", e)

    def _enum_password_policy(self, context, connection):
        """Enumerate password policy"""
        context.log.display("")
        context.log.highlight("[*] Password Policy")
        context.log.display("-" * 40)

        try:
            rpctransport = transport.SMBTransport(
                connection.host,
                445,
                r"\samr",
                username=connection.username,
                password=connection.password,
                domain=connection.domain,
                lmhash=connection.lmhash,
                nthash=connection.nthash
            )

            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp = samr.hSamrConnect(dce)
            server_handle = resp["ServerHandle"]

            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)
            domains = resp["Buffer"]["Buffer"]

            for domain in domains:
                domain_name = domain["Name"]
                if domain_name.upper() == "BUILTIN":
                    continue

                resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)
                domain_sid = resp["DomainId"]

                resp = samr.hSamrOpenDomain(dce, server_handle, MAXIMUM_ALLOWED, domain_sid)
                domain_handle = resp["DomainHandle"]

                # Get password policy
                resp = samr.hSamrQueryInformationDomain(dce, domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
                policy = resp["Buffer"]["Password"]

                # Convert to readable format
                min_pwd_length = policy["MinPasswordLength"]
                pwd_history_length = policy["PasswordHistoryLength"]

                # MaxPasswordAge is in 100-nanosecond intervals (negative)
                max_age = policy["MaxPasswordAge"]["LowPart"]
                min_age = policy["MinPasswordAge"]["LowPart"]

                # Convert to days (approximate)
                max_age_days = abs(max_age) / (10000000 * 60 * 60 * 24) if max_age else 0
                min_age_days = abs(min_age) / (10000000 * 60 * 60 * 24) if min_age else 0

                # Get lockout policy
                resp2 = samr.hSamrQueryInformationDomain(dce, domain_handle, samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
                lockout = resp2["Buffer"]["Lockout"]

                lockout_threshold = lockout["LockoutThreshold"]
                lockout_duration = abs(lockout["LockoutDuration"]["LowPart"]) / (10000000 * 60) if lockout["LockoutDuration"]["LowPart"] else 0
                lockout_window = abs(lockout["LockoutObservationWindow"]["LowPart"]) / (10000000 * 60) if lockout["LockoutObservationWindow"]["LowPart"] else 0

                password_policy = {
                    "domain": domain_name,
                    "min_password_length": min_pwd_length,
                    "password_history_length": pwd_history_length,
                    "max_password_age_days": round(max_age_days, 1),
                    "min_password_age_days": round(min_age_days, 1),
                    "lockout_threshold": lockout_threshold,
                    "lockout_duration_minutes": round(lockout_duration, 1),
                    "lockout_observation_window_minutes": round(lockout_window, 1)
                }

                self.results[connection.host]["password_policy"] = password_policy

                context.log.display(f"  Domain: {domain_name}")
                context.log.display(f"  Minimum Password Length: {min_pwd_length}")
                context.log.display(f"  Password History Length: {pwd_history_length}")
                context.log.display(f"  Maximum Password Age: {round(max_age_days, 1)} days")
                context.log.display(f"  Minimum Password Age: {round(min_age_days, 1)} days")
                context.log.display(f"  Lockout Threshold: {lockout_threshold}")
                context.log.display(f"  Lockout Duration: {round(lockout_duration, 1)} minutes")
                context.log.display(f"  Lockout Observation Window: {round(lockout_window, 1)} minutes")

                samr.hSamrCloseHandle(dce, domain_handle)
                break  # Only need first non-Builtin domain

            samr.hSamrCloseHandle(dce, server_handle)
            dce.disconnect()

        except DCERPCException as e:
            if "ACCESS_DENIED" in str(e):
                context.log.display("  Access denied - insufficient privileges")
            else:
                self._log_error(context, connection.host, "Password Policy", e)
        except Exception as e:
            self._log_error(context, connection.host, "Password Policy", e)

    def _log_error(self, context, host, component, error):
        """Log error and optionally display verbose output"""
        error_info = {
            "component": component,
            "error": str(error)
        }
        self.results[host]["errors"].append(error_info)

        if self.verbose:
            context.log.fail(f"  Error enumerating {component}: {error}")

    def _save_results(self, context):
        """Save results to file"""
        try:
            if self.json_output:
                with open(self.output_file, "w") as f:
                    json.dump(self.results, f, indent=2, default=str)
            else:
                with open(self.output_file, "w") as f:
                    for host, data in self.results.items():
                        f.write(f"{'=' * 60}\n")
                        f.write(f"Host: {host}\n")
                        f.write(f"Hostname: {data['hostname']}\n")
                        f.write(f"Domain: {data['domain']}\n")
                        f.write(f"Timestamp: {data['timestamp']}\n")
                        f.write(f"{'=' * 60}\n\n")

                        f.write("SHARES:\n")
                        for share in data["shares"]:
                            f.write(f"  {share['name']} [{share['permissions']}] {share.get('remark', '')}\n")

                        f.write("\nSESSIONS:\n")
                        for session in data["sessions"]:
                            f.write(f"  {session['user']}@{session['client']}\n")

                        f.write("\nLOGGED-ON USERS:\n")
                        for user in data["logged_on_users"]:
                            f.write(f"  {user['logon_domain']}\\{user['username']}\n")

                        f.write("\nLOCAL USERS:\n")
                        for user in data["local_users"]:
                            f.write(f"  {user.get('domain', '')}\\{user['username']} (RID: {user['rid']})\n")

                        f.write("\nLOCAL GROUPS:\n")
                        for group in data["local_groups"]:
                            f.write(f"  {group.get('domain', '')}\\{group['name']} (RID: {group['rid']}) Members: {group.get('member_count', 0)}\n")

                        f.write("\nPASSWORD POLICY:\n")
                        if data["password_policy"]:
                            pp = data["password_policy"]
                            f.write(f"  Min Length: {pp.get('min_password_length')}\n")
                            f.write(f"  History: {pp.get('password_history_length')}\n")
                            f.write(f"  Max Age: {pp.get('max_password_age_days')} days\n")
                            f.write(f"  Lockout Threshold: {pp.get('lockout_threshold')}\n")

                        f.write("\n")

            context.log.success(f"Results saved to {self.output_file}")

        except Exception as e:
            context.log.fail(f"Error saving results: {e}")
