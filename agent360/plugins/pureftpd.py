#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure-FTPd monitoring plugin for 360Monitoring
Author: @itomicspaceman
Version: 1.0.0
Created: 2025-06-20
Purpose: Comprehensive Pure-FTPd service monitoring including authentication tracking,
         transfer analytics, and security intelligence

Metrics provided:
- Service health monitoring
- Real-time connection tracking
- Transfer statistics (uploads/downloads)
- Authentication success/failure tracking
- Security event detection (failed auth disconnects, technical disconnects)
- User activity monitoring
- Data volume tracking

Requirements:
- Pure-FTPd service running
- Read access to /var/log/messages for authentication tracking
- Optional: xferlog for transfer statistics (falls back to system log parsing)
"""

import os
import subprocess
import re
import time
from datetime import datetime
import plugins


class Plugin(plugins.BasePlugin):
    __name__ = 'pureftpd'

    def run(self, config):
        """
        Monitor Pure-FTPd service and activity
        
        Returns dictionary with the following metrics:
        - active_connections: Current established FTP connections
        - service_running: Service status (0/1)
        - uptime_hours: Service uptime in hours
        - recent_transfers: Total transfers in last hour
        - recent_uploads: Upload count in last hour
        - recent_downloads: Download count in last hour
        - recent_bytes_transferred: Data volume in MB (last hour)
        - unique_users_recent: Number of unique users (last hour)
        - login_attempts_failed: Failed authentication attempts (last hour)
        - login_attempts_successful: Successful authentications (last hour)
        - failed_auth_disconnects: Immediate disconnects without auth (last hour)
        - successful_auth_disconnects: Immediate disconnects after auth (last hour)
        """
        data = {}
        
        # Core monitoring metrics
        data.update(self._get_active_connections())
        data.update(self._get_service_health())
        
        # Transfer analytics with fallback support
        data.update(self._analyze_transfer_activity())
        
        # Security and authentication tracking
        data.update(self._analyze_authentication_events())
        
        return data

    def _get_active_connections(self):
        """Count current established FTP connections on port 21"""
        try:
            result = subprocess.run(['ss', '-tn'], capture_output=True, text=True, timeout=5)
            connections = 0
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':21 ' in line and 'ESTAB' in line:
                        connections += 1
            
            return {'active_connections': connections}
        except Exception:
            return {'active_connections': 0}

    def _get_service_health(self):
        """
        Get Pure-FTPd service health metrics
        Returns both boolean status and uptime in hours for different dashboard needs
        """
        try:
            # Check service status
            result = subprocess.run(['systemctl', 'is-active', 'pure-ftpd'], 
                                   capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip() == 'active':
                # Get service uptime
                status_result = subprocess.run(
                    ['systemctl', 'show', 'pure-ftpd', '--property=ActiveEnterTimestamp'], 
                    capture_output=True, text=True, timeout=5
                )
                
                if status_result.returncode == 0:
                    timestamp_match = re.search(r'ActiveEnterTimestamp=(.+)', status_result.stdout.strip())
                    if timestamp_match:
                        timestamp_str = timestamp_match.group(1)
                        try:
                            # Parse systemd timestamp format
                            time_parts = timestamp_str.split()
                            if len(time_parts) >= 3:
                                date_time = f"{time_parts[1]} {time_parts[2]}"
                                start_time = datetime.strptime(date_time, '%Y-%m-%d %H:%M:%S')
                                uptime_seconds = (datetime.now() - start_time).total_seconds()
                                uptime_hours = round(uptime_seconds / 3600, 2)
                                
                                return {
                                    'service_running': 1,
                                    'uptime_hours': uptime_hours
                                }
                        except (ValueError, IndexError):
                            pass
                
                return {'service_running': 1, 'uptime_hours': 0}
            
            return {'service_running': 0, 'uptime_hours': 0}
        except Exception:
            return {'service_running': 0, 'uptime_hours': 0}

    def _analyze_transfer_activity(self):
        """
        Analyze FTP transfer activity with dual-source support
        
        Primary: Parse Pure-FTPd xferlog for detailed statistics
        Fallback: Parse system log when xferlog unavailable (OSSEC truncation)
        
        Returns transfer counts, data volumes, and user activity metrics
        """
        # Try xferlog first (more detailed format)
        result = self._parse_xferlog()
        
        # If no data from xferlog, use system log as backup
        if result['recent_transfers'] == 0:
            result = self._parse_system_log_transfers()
        
        return result

    def _parse_xferlog(self):
        """Parse Pure-FTPd xferlog in standard format"""
        log_file = '/etc/apache2/logs/domlogs/ftpxferlog'
        
        try:
            if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
                return self._empty_transfer_result()
            
            one_hour_ago = time.time() - 3600
            upload_count = download_count = total_bytes = 0
            unique_users = set()
            
            with open(log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Parse xferlog format: timestamp session user ip direction size complete path
                    parts = line.split(' ', 7)
                    if len(parts) >= 7:
                        try:
                            timestamp = int(parts[0])
                            user = parts[2]
                            direction = parts[4]  # U=upload, D=download
                            size_bytes = int(parts[5])
                            complete = int(parts[6])  # 1=complete, 0=incomplete
                            
                            # Only count completed transfers from last hour
                            if timestamp >= one_hour_ago and complete == 1:
                                if direction == 'U':
                                    upload_count += 1
                                elif direction == 'D':
                                    download_count += 1
                                
                                total_bytes += size_bytes
                                unique_users.add(user)
                        except (ValueError, IndexError):
                            continue
            
            return {
                'recent_transfers': upload_count + download_count,
                'recent_uploads': upload_count,
                'recent_downloads': download_count,
                'recent_bytes_transferred': round(total_bytes / (1024 * 1024), 2),
                'unique_users_recent': len(unique_users)
            }
        except (IOError, OSError):
            return self._empty_transfer_result()

    def _parse_system_log_transfers(self):
        """
        Backup method: Parse system log for transfer activity
        Used when xferlog is unavailable (e.g., OSSEC log management)
        """
        log_file = '/var/log/messages'
        
        try:
            if not os.path.exists(log_file):
                return self._empty_transfer_result()
            
            one_hour_ago = time.time() - 3600
            upload_count = download_count = total_bytes = 0
            unique_users = set()
            
            with open(log_file, 'r') as f:
                for line in f:
                    if 'pure-ftpd' not in line or not any(word in line for word in ['uploaded', 'downloaded']):
                        continue
                    
                    try:
                        # Parse syslog timestamp
                        timestamp_match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                        if not timestamp_match:
                            continue
                        
                        timestamp_str = timestamp_match.group(1)
                        current_year = datetime.now().year
                        full_timestamp = f"{current_year} {timestamp_str}"
                        timestamp = datetime.strptime(full_timestamp, '%Y %b %d %H:%M:%S').timestamp()
                        
                        if timestamp >= one_hour_ago:
                            # Extract user and transfer details
                            user_match = re.search(r'\(([^@]+)@[^)]+\)', line)
                            size_match = re.search(r'\((\d+) bytes', line)
                            
                            if user_match:
                                unique_users.add(user_match.group(1))
                            
                            if size_match:
                                total_bytes += int(size_match.group(1))
                            
                            if 'uploaded' in line:
                                upload_count += 1
                            elif 'downloaded' in line:
                                download_count += 1
                    except (ValueError, AttributeError):
                        continue
            
            return {
                'recent_transfers': upload_count + download_count,
                'recent_uploads': upload_count,
                'recent_downloads': download_count,
                'recent_bytes_transferred': round(total_bytes / (1024 * 1024), 2),
                'unique_users_recent': len(unique_users)
            }
        except (IOError, OSError):
            return self._empty_transfer_result()

    def _analyze_authentication_events(self):
        """
        Analyze Pure-FTPd authentication and security events
        
        Tracks:
        - Failed authentication attempts
        - Successful user authentications
        - Failed auth disconnects (scanning attempts)
        - Successful auth disconnects (technical issues)
        
        Returns hourly counts for security monitoring
        """
        log_file = '/var/log/messages'
        
        try:
            if not os.path.exists(log_file):
                return self._empty_auth_result()
            
            one_hour_ago = time.time() - 3600
            failed_logins = successful_logins = 0
            failed_auth_disconnects = successful_auth_disconnects = 0
            
            # Track connection states by PID for disconnect analysis
            connection_states = {}
            authenticated_pids = set()
            
            with open(log_file, 'r') as f:
                for line in f:
                    if 'pure-ftpd' not in line:
                        continue
                    
                    try:
                        # Parse timestamp
                        timestamp_match = re.match(r'(\w+\s+\d+\s+\d+:\d+:\d+)', line)
                        if not timestamp_match:
                            continue
                        
                        timestamp_str = timestamp_match.group(1)
                        current_year = datetime.now().year
                        full_timestamp = f"{current_year} {timestamp_str}"
                        timestamp = datetime.strptime(full_timestamp, '%Y %b %d %H:%M:%S').timestamp()
                        
                        if timestamp >= one_hour_ago:
                            # Extract PID for connection tracking
                            pid_match = re.search(r'pure-ftpd\[(\d+)\]', line)
                            pid = pid_match.group(1) if pid_match else None
                            
                            # Track different event types
                            if '[WARNING] Authentication failed' in line:
                                failed_logins += 1
                            
                            elif (re.search(r'\([^?][^@]*@[^)]+\)', line) and 
                                  any(keyword in line for keyword in ['uploaded', 'downloaded', 'TLS'])):
                                # Successful authentication with activity
                                if pid and pid not in authenticated_pids:
                                    successful_logins += 1
                                    authenticated_pids.add(pid)
                                    if pid in connection_states:
                                        connection_states[pid]['authenticated'] = True
                            
                            elif '[INFO] New connection from' in line and pid:
                                connection_states[pid] = {
                                    'timestamp': timestamp,
                                    'authenticated': False
                                }
                            
                            elif '[INFO] Logout.' in line and pid and pid in connection_states:
                                conn_data = connection_states[pid]
                                # Check for immediate disconnect (within 1 second)
                                if timestamp - conn_data['timestamp'] <= 1:
                                    if conn_data['authenticated']:
                                        successful_auth_disconnects += 1
                                    else:
                                        failed_auth_disconnects += 1
                                del connection_states[pid]
                    except (ValueError, AttributeError):
                        continue
            
            return {
                'login_attempts_failed': failed_logins,
                'login_attempts_successful': successful_logins,
                'failed_auth_disconnects': failed_auth_disconnects,
                'successful_auth_disconnects': successful_auth_disconnects
            }
        except (IOError, OSError):
            return self._empty_auth_result()

    def _empty_transfer_result(self):
        """Return empty transfer statistics"""
        return {
            'recent_transfers': 0,
            'recent_uploads': 0,
            'recent_downloads': 0,
            'recent_bytes_transferred': 0,
            'unique_users_recent': 0
        }

    def _empty_auth_result(self):
        """Return empty authentication statistics"""
        return {
            'login_attempts_failed': 0,
            'login_attempts_successful': 0,
            'failed_auth_disconnects': 0,
            'successful_auth_disconnects': 0
        }


if __name__ == '__main__':
    Plugin().execute() 