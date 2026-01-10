#!/usr/bin/env python3
"""
Zabbix Alert Dashboard - A comprehensive external alerting platform for Zabbix
"""

import sqlite3
import requests
import json
import os
from datetime import datetime
from flask import Flask, render_template, request, jsonify, g
from functools import wraps
import time
import threading

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, 
            template_folder=os.path.join(BASE_DIR, 'templates'),
            static_folder=os.path.join(BASE_DIR, 'static'))
app.config['DATABASE'] = os.path.join(BASE_DIR, 'zabbix_alerts.db')

# Global settings stored in memory (loaded from DB on startup)
settings_cache = {
    'zabbix_url': '',
    'api_key': '',
    'username': '',
    'password': '',
    'auth_token': '',  # Session token from user/pass auth
    'auto_refresh': False,
    'refresh_interval': 30
}

# Rate limiting for API calls
last_api_call = 0
MIN_API_INTERVAL = 2  # Minimum seconds between API calls


def get_db():
    """Get database connection for current request context"""
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    """Close database connection at end of request"""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY,
            zabbix_url TEXT,
            api_key TEXT,
            username TEXT,
            password TEXT,
            auto_refresh INTEGER DEFAULT 0,
            refresh_interval INTEGER DEFAULT 30,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Categories table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            color TEXT DEFAULT '#6366f1',
            icon TEXT DEFAULT 'folder',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Alerts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT UNIQUE NOT NULL,
            problem_id TEXT,
            host_name TEXT,
            host_id TEXT,
            trigger_name TEXT,
            trigger_id TEXT,
            severity INTEGER,
            severity_name TEXT,
            status INTEGER,
            acknowledged INTEGER DEFAULT 0,
            clock TIMESTAMP,
            r_clock TIMESTAMP,
            category_id INTEGER,
            custom_comment TEXT,
            is_read INTEGER DEFAULT 0,
            is_archived INTEGER DEFAULT 0,
            raw_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (category_id) REFERENCES categories(id)
        )
    ''')
    
    # Comments table for multiple comments per alert
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            author TEXT DEFAULT 'User',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (alert_id) REFERENCES alerts(id)
        )
    ''')
    
    # Insert default settings if not exists
    cursor.execute('SELECT COUNT(*) FROM settings')
    if cursor.fetchone()[0] == 0:
        cursor.execute('INSERT INTO settings (id, zabbix_url, api_key) VALUES (1, "", "")')
    
    # Insert default categories
    cursor.execute('SELECT COUNT(*) FROM categories')
    if cursor.fetchone()[0] == 0:
        default_categories = [
            ('Critical', '#ef4444', 'alert-triangle', 'Critical severity alerts'),
            ('Network', '#3b82f6', 'wifi', 'Network related issues'),
            ('Server', '#8b5cf6', 'server', 'Server related issues'),
            ('Database', '#f59e0b', 'database', 'Database related issues'),
            ('Application', '#10b981', 'code', 'Application related issues'),
            ('Uncategorized', '#6b7280', 'folder', 'Uncategorized alerts')
        ]
        cursor.executemany(
            'INSERT INTO categories (name, color, icon, description) VALUES (?, ?, ?, ?)',
            default_categories
        )
    
    conn.commit()
    conn.close()


def load_settings():
    """Load settings from database into cache"""
    global settings_cache
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Check if username/password columns exist, if not add them
    cursor.execute("PRAGMA table_info(settings)")
    columns = [col[1] for col in cursor.fetchall()]
    if 'username' not in columns:
        cursor.execute('ALTER TABLE settings ADD COLUMN username TEXT')
        cursor.execute('ALTER TABLE settings ADD COLUMN password TEXT')
        conn.commit()
    
    cursor.execute('SELECT zabbix_url, api_key, auto_refresh, refresh_interval, username, password FROM settings WHERE id = 1')
    row = cursor.fetchone()
    if row:
        settings_cache = {
            'zabbix_url': row[0] or '',
            'api_key': row[1] or '',
            'auto_refresh': bool(row[2]),
            'refresh_interval': row[3] or 30,
            'username': row[4] or '',
            'password': row[5] or '',
            'auth_token': ''
        }
    conn.close()


def get_severity_name(severity):
    """Convert Zabbix severity number to name"""
    severity_map = {
        0: 'Not classified',
        1: 'Information',
        2: 'Warning',
        3: 'Average',
        4: 'High',
        5: 'Disaster'
    }
    return severity_map.get(severity, 'Unknown')


def get_severity_color(severity):
    """Get color for severity level"""
    color_map = {
        0: '#97AAB3',
        1: '#7499FF',
        2: '#FFC859',
        3: '#FFA059',
        4: '#E97659',
        5: '#E45959'
    }
    return color_map.get(severity, '#6b7280')


def authenticate_with_credentials():
    """Authenticate with Zabbix using username/password and get auth token"""
    global settings_cache
    
    if not settings_cache['zabbix_url'] or not settings_cache['username'] or not settings_cache['password']:
        return None
    
    url = settings_cache['zabbix_url'].rstrip('/') + '/api_jsonrpc.php'
    
    payload = {
        'jsonrpc': '2.0',
        'method': 'user.login',
        'params': {
            'username': settings_cache['username'],
            'password': settings_cache['password']
        },
        'id': 1
    }
    
    # For older Zabbix versions (< 5.4), use 'user' instead of 'username'
    try:
        response = requests.post(url, json=payload, headers={'Content-Type': 'application/json-rpc'}, timeout=30)
        data = response.json()
        
        if 'error' in data:
            # Try with old parameter name for older Zabbix versions
            payload['params'] = {
                'user': settings_cache['username'],
                'password': settings_cache['password']
            }
            response = requests.post(url, json=payload, headers={'Content-Type': 'application/json-rpc'}, timeout=30)
            data = response.json()
        
        if 'result' in data and data['result']:
            settings_cache['auth_token'] = data['result']
            return data['result']
        
        return None
    except Exception as e:
        print(f"Authentication error: {e}")
        return None


def fetch_zabbix_problems():
    """Fetch current problems from Zabbix API with rate limiting"""
    global last_api_call
    
    # Rate limiting
    current_time = time.time()
    if current_time - last_api_call < MIN_API_INTERVAL:
        time.sleep(MIN_API_INTERVAL - (current_time - last_api_call))
    
    if not settings_cache['zabbix_url']:
        return {'error': 'Zabbix URL not configured. Please go to Settings and configure your Zabbix connection.'}
    
    # Check if we have any auth method configured
    has_api_key = bool(settings_cache.get('api_key'))
    has_credentials = bool(settings_cache.get('username') and settings_cache.get('password'))
    
    if not has_api_key and not has_credentials:
        return {'error': 'No authentication configured. Please provide either an API key OR username/password in Settings.'}
    
    url = settings_cache['zabbix_url'].rstrip('/') + '/api_jsonrpc.php'
    auth_method_used = None
    
    # Try API key first if available
    if has_api_key:
        headers = {
            'Content-Type': 'application/json-rpc',
            'Authorization': f'Bearer {settings_cache["api_key"]}'
        }
        auth_method_used = 'api_key'
        auth_param = None
    else:
        headers = {'Content-Type': 'application/json-rpc'}
        auth_param = None
    
    # Fetch current problems
    payload = {
        'jsonrpc': '2.0',
        'method': 'problem.get',
        'params': {
            'output': 'extend',
            'selectAcknowledges': 'extend',
            'selectTags': 'extend',
            'selectSuppressionData': 'extend',
            'recent': True,
            'sortfield': ['eventid'],
            'sortorder': 'DESC',
            'limit': 100
        },
        'id': 1
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        last_api_call = time.time()
        response.raise_for_status()
        data = response.json()
        
        # If API key failed with auth error and we have credentials, try username/password
        if 'error' in data and has_credentials:
            error_msg = str(data['error'].get('message', '')) + str(data['error'].get('data', ''))
            if 'Not authorized' in error_msg or 'Authentication' in error_msg or 'Session' in error_msg:
                print("API key auth failed, trying username/password...")
                
                # Authenticate with credentials
                auth_token = authenticate_with_credentials()
                if auth_token:
                    # Retry with auth token
                    payload['auth'] = auth_token
                    headers = {'Content-Type': 'application/json-rpc'}
                    
                    response = requests.post(url, json=payload, headers=headers, timeout=30)
                    data = response.json()
                    auth_method_used = 'credentials'
                else:
                    return {'error': 'API key failed and username/password authentication also failed. Please check your credentials in Settings.'}
        
        if 'error' in data:
            error_msg = data['error'].get('message', 'Unknown error')
            error_data = data['error'].get('data', '')
            if 'Not authorized' in str(error_msg) or 'Not authorized' in str(error_data):
                if auth_method_used == 'api_key':
                    return {'error': 'API key not authorized. Please check your API key has read permissions, or configure username/password as fallback in Settings.'}
                else:
                    return {'error': 'Not authorized. Please check your credentials have proper permissions.'}
            return {'error': f'Zabbix API Error: {error_msg} - {error_data}'}
        
        problems = data.get('result', [])
        
        # Fetch host information for problems
        if problems:
            trigger_ids = list(set([p.get('objectid') for p in problems if p.get('objectid')]))
            
            if trigger_ids:
                host_payload = {
                    'jsonrpc': '2.0',
                    'method': 'trigger.get',
                    'params': {
                        'output': ['triggerid', 'description'],
                        'triggerids': trigger_ids,
                        'selectHosts': ['hostid', 'host', 'name'],
                        'expandDescription': True
                    },
                    'id': 2
                }
                
                # Add auth token if using credentials
                if auth_method_used == 'credentials' and settings_cache.get('auth_token'):
                    host_payload['auth'] = settings_cache['auth_token']
                
                time.sleep(0.5)  # Small delay between API calls
                host_response = requests.post(url, json=host_payload, headers=headers, timeout=30)
                host_data = host_response.json()
                
                if 'error' not in host_data:
                    trigger_info = {}
                    for trigger in host_data.get('result', []):
                        hosts = trigger.get('hosts', [])
                        if hosts:
                            trigger_info[trigger['triggerid']] = {
                                'host_name': hosts[0].get('name', hosts[0].get('host', 'Unknown')),
                                'host_id': hosts[0].get('hostid', ''),
                                'trigger_name': trigger.get('description', '')
                            }
                    
                    # Enrich problems with host info
                    for problem in problems:
                        trigger_id = problem.get('objectid')
                        if trigger_id in trigger_info:
                            problem['host_info'] = trigger_info[trigger_id]
        
        auth_info = f" (using {'API key' if auth_method_used == 'api_key' else 'username/password'})"
        return {'problems': problems, 'auth_method': auth_method_used}
    
    except requests.exceptions.Timeout:
        return {'error': 'Connection timeout - Zabbix server took too long to respond. Check your URL and network connection.'}
    except requests.exceptions.ConnectionError as e:
        return {'error': f'Connection failed - Cannot reach Zabbix server. Check the URL: {settings_cache["zabbix_url"]}'}
    except requests.exceptions.HTTPError as e:
        return {'error': f'HTTP Error: {e.response.status_code} - Check your Zabbix URL'}
    except json.JSONDecodeError:
        return {'error': 'Invalid response from Zabbix - The URL might not be pointing to a Zabbix API endpoint'}
    except Exception as e:
        return {'error': f'Unexpected error: {str(e)}'}


def store_problems(problems):
    """Store problems in the database"""
    if not problems:
        return {'new': 0, 'updated': 0}
    
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    new_count = 0
    updated_count = 0
    
    for problem in problems:
        try:
            event_id = problem.get('eventid')
            if not event_id:
                continue
                
            host_info = problem.get('host_info', {})
            
            # Check if alert already exists
            cursor.execute('SELECT id, status FROM alerts WHERE event_id = ?', (event_id,))
            existing = cursor.fetchone()
            
            severity = int(problem.get('severity', 0)) if problem.get('severity', '').strip() else 0
            r_eventid = problem.get('r_eventid', '0') or '0'
            status = int(r_eventid) > 0 if r_eventid.strip() else False  # Has recovery event
            
            clock_val = problem.get('clock', '0') or '0'
            clock_timestamp = int(clock_val) if clock_val.strip() else 0
            
            if existing:
                # Update existing alert
                r_clock_val = problem.get('r_clock', '0') or '0'
                r_clock_timestamp = int(r_clock_val) if r_clock_val.strip() and r_clock_val != '0' else None
                
                cursor.execute('''
                    UPDATE alerts SET
                        status = ?,
                        acknowledged = ?,
                        r_clock = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE event_id = ?
                ''', (
                    1 if status else 0,
                    1 if problem.get('acknowledged') == '1' else 0,
                    datetime.fromtimestamp(r_clock_timestamp) if r_clock_timestamp else None,
                    event_id
                ))
                updated_count += 1
            else:
                # Insert new alert
                cursor.execute('''
                    INSERT INTO alerts (
                        event_id, problem_id, host_name, host_id, trigger_name, trigger_id,
                        severity, severity_name, status, acknowledged, clock, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event_id,
                    problem.get('objectid', ''),
                    host_info.get('host_name', 'Unknown'),
                    host_info.get('host_id', ''),
                    host_info.get('trigger_name', problem.get('name', 'Unknown')),
                    problem.get('objectid', ''),
                    severity,
                    get_severity_name(severity),
                    0,  # Active problem
                    1 if problem.get('acknowledged') == '1' else 0,
                    datetime.fromtimestamp(clock_timestamp) if clock_timestamp else datetime.now(),
                    json.dumps(problem)
                ))
                new_count += 1
        except Exception as e:
            print(f"Error processing problem {problem.get('eventid', 'unknown')}: {e}")
            continue
    
    conn.commit()
    conn.close()
    
    return {'new': new_count, 'updated': updated_count}


# Routes

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    """Get or update settings"""
    if request.method == 'GET':
        # Don't expose full API key or password
        safe_settings = settings_cache.copy()
        if safe_settings['api_key']:
            safe_settings['api_key_masked'] = '*' * 8 + safe_settings['api_key'][-4:]
        else:
            safe_settings['api_key_masked'] = ''
        if safe_settings.get('password'):
            safe_settings['password_masked'] = '*' * 8
        else:
            safe_settings['password_masked'] = ''
        # Don't send actual password
        safe_settings.pop('password', None)
        safe_settings.pop('auth_token', None)
        return jsonify(safe_settings)
    
    elif request.method == 'POST':
        data = request.get_json()
        
        db = get_db()
        cursor = db.cursor()
        
        # Update settings
        if 'zabbix_url' in data:
            settings_cache['zabbix_url'] = data['zabbix_url']
        if 'api_key' in data and data['api_key']:  # Only update if provided
            settings_cache['api_key'] = data['api_key']
        if 'username' in data:
            settings_cache['username'] = data['username']
        if 'password' in data and data['password']:  # Only update if provided
            settings_cache['password'] = data['password']
        if 'auto_refresh' in data:
            settings_cache['auto_refresh'] = bool(data['auto_refresh'])
        if 'refresh_interval' in data:
            settings_cache['refresh_interval'] = int(data['refresh_interval'])
        
        # Clear auth token when credentials change
        settings_cache['auth_token'] = ''
        
        cursor.execute('''
            UPDATE settings SET
                zabbix_url = ?,
                api_key = ?,
                username = ?,
                password = ?,
                auto_refresh = ?,
                refresh_interval = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = 1
        ''', (
            settings_cache['zabbix_url'],
            settings_cache['api_key'],
            settings_cache['username'],
            settings_cache['password'],
            1 if settings_cache['auto_refresh'] else 0,
            settings_cache['refresh_interval']
        ))
        
        db.commit()
        
        return jsonify({'status': 'success', 'message': 'Settings updated'})


@app.route('/api/fetch-alerts', methods=['POST'])
def fetch_alerts():
    """Fetch alerts from Zabbix and store in database"""
    result = fetch_zabbix_problems()
    
    if 'error' in result:
        return jsonify({'status': 'error', 'message': result['error']}), 400
    
    problems = result.get('problems', [])
    auth_method = result.get('auth_method', 'unknown')
    store_result = store_problems(problems)
    
    return jsonify({
        'status': 'success',
        'message': f'Fetched {len(problems)} problems. New: {store_result["new"]}, Updated: {store_result["updated"]}',
        'auth_method': auth_method
    })


@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Get all alerts with filtering and pagination"""
    db = get_db()
    cursor = db.cursor()
    
    # Get filter parameters
    severity = request.args.get('severity')
    status = request.args.get('status')
    category_id = request.args.get('category_id')
    is_archived = request.args.get('archived', '0')
    search = request.args.get('search', '')
    page = int(request.args.get('page', 1) or 1)
    per_page = int(request.args.get('per_page', 50) or 50)
    
    # Build query
    query = 'SELECT a.*, c.name as category_name, c.color as category_color FROM alerts a LEFT JOIN categories c ON a.category_id = c.id WHERE 1=1'
    params = []
    
    if severity and severity.strip():
        query += ' AND a.severity = ?'
        params.append(int(severity))
    
    if status is not None and status != '' and status.strip():
        query += ' AND a.status = ?'
        params.append(int(status))
    
    if category_id and category_id.strip():
        query += ' AND a.category_id = ?'
        params.append(int(category_id))
    
    if is_archived != '1':
        query += ' AND a.is_archived = 0'
    
    if search and search.strip():
        query += ' AND (a.host_name LIKE ? OR a.trigger_name LIKE ?)'
        params.extend([f'%{search}%', f'%{search}%'])
    
    # Get total count
    count_query = query.replace('SELECT a.*, c.name as category_name, c.color as category_color', 'SELECT COUNT(*)')
    cursor.execute(count_query, params)
    total = cursor.fetchone()[0]
    
    # Add pagination and ordering
    query += ' ORDER BY a.clock DESC LIMIT ? OFFSET ?'
    params.extend([per_page, (page - 1) * per_page])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    alerts = []
    for row in rows:
        try:
            alert = dict(row)
            # Safely get severity with default
            sev = alert.get('severity')
            if sev is None or sev == '':
                sev = 0
            else:
                sev = int(sev) if isinstance(sev, str) else sev
            alert['severity'] = sev
            alert['severity_color'] = get_severity_color(sev)
            
            # Get comments count
            cursor.execute('SELECT COUNT(*) FROM comments WHERE alert_id = ?', (alert['id'],))
            alert['comments_count'] = cursor.fetchone()[0]
            
            alerts.append(alert)
        except Exception as e:
            print(f"Error processing alert {row}: {e}")
            continue
    
    return jsonify({
        'alerts': alerts,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page if total > 0 else 1
    })


@app.route('/api/alerts/<int:alert_id>', methods=['GET', 'PATCH', 'DELETE'])
def alert_detail(alert_id):
    """Get, update, or delete a specific alert"""
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'GET':
        cursor.execute('''
            SELECT a.*, c.name as category_name, c.color as category_color 
            FROM alerts a 
            LEFT JOIN categories c ON a.category_id = c.id 
            WHERE a.id = ?
        ''', (alert_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'Alert not found'}), 404
        
        alert = dict(row)
        alert['severity_color'] = get_severity_color(alert['severity'])
        
        # Get comments
        cursor.execute('SELECT * FROM comments WHERE alert_id = ? ORDER BY created_at DESC', (alert_id,))
        alert['comments'] = [dict(c) for c in cursor.fetchall()]
        
        return jsonify(alert)
    
    elif request.method == 'PATCH':
        data = request.get_json()
        
        updates = []
        params = []
        
        if 'category_id' in data:
            updates.append('category_id = ?')
            params.append(data['category_id'] if data['category_id'] else None)
        
        if 'custom_comment' in data:
            updates.append('custom_comment = ?')
            params.append(data['custom_comment'])
        
        if 'is_read' in data:
            updates.append('is_read = ?')
            params.append(1 if data['is_read'] else 0)
        
        if 'is_archived' in data:
            updates.append('is_archived = ?')
            params.append(1 if data['is_archived'] else 0)
        
        if updates:
            updates.append('updated_at = CURRENT_TIMESTAMP')
            params.append(alert_id)
            
            cursor.execute(f'UPDATE alerts SET {", ".join(updates)} WHERE id = ?', params)
            db.commit()
        
        return jsonify({'status': 'success', 'message': 'Alert updated'})
    
    elif request.method == 'DELETE':
        cursor.execute('DELETE FROM comments WHERE alert_id = ?', (alert_id,))
        cursor.execute('DELETE FROM alerts WHERE id = ?', (alert_id,))
        db.commit()
        
        return jsonify({'status': 'success', 'message': 'Alert deleted'})


@app.route('/api/alerts/<int:alert_id>/comments', methods=['GET', 'POST'])
def alert_comments(alert_id):
    """Get or add comments for an alert"""
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'GET':
        cursor.execute('SELECT * FROM comments WHERE alert_id = ? ORDER BY created_at DESC', (alert_id,))
        comments = [dict(c) for c in cursor.fetchall()]
        return jsonify(comments)
    
    elif request.method == 'POST':
        data = request.get_json()
        
        cursor.execute('''
            INSERT INTO comments (alert_id, comment, author)
            VALUES (?, ?, ?)
        ''', (alert_id, data.get('comment', ''), data.get('author', 'User')))
        
        db.commit()
        
        return jsonify({'status': 'success', 'message': 'Comment added', 'id': cursor.lastrowid})


@app.route('/api/categories', methods=['GET', 'POST'])
def categories():
    """Get all categories or create a new one"""
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'GET':
        cursor.execute('SELECT * FROM categories ORDER BY name')
        cats = [dict(c) for c in cursor.fetchall()]
        
        # Get alert count per category
        for cat in cats:
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE category_id = ? AND is_archived = 0', (cat['id'],))
            cat['alert_count'] = cursor.fetchone()[0]
        
        return jsonify(cats)
    
    elif request.method == 'POST':
        data = request.get_json()
        
        try:
            cursor.execute('''
                INSERT INTO categories (name, color, icon, description)
                VALUES (?, ?, ?, ?)
            ''', (
                data.get('name'),
                data.get('color', '#6366f1'),
                data.get('icon', 'folder'),
                data.get('description', '')
            ))
            
            db.commit()
            
            return jsonify({'status': 'success', 'message': 'Category created', 'id': cursor.lastrowid})
        except sqlite3.IntegrityError:
            return jsonify({'status': 'error', 'message': 'Category name already exists'}), 400


@app.route('/api/categories/<int:category_id>', methods=['GET', 'PATCH', 'DELETE'])
def category_detail(category_id):
    """Get, update, or delete a category"""
    db = get_db()
    cursor = db.cursor()
    
    if request.method == 'GET':
        cursor.execute('SELECT * FROM categories WHERE id = ?', (category_id,))
        row = cursor.fetchone()
        
        if not row:
            return jsonify({'error': 'Category not found'}), 404
        
        return jsonify(dict(row))
    
    elif request.method == 'PATCH':
        data = request.get_json()
        
        updates = []
        params = []
        
        if 'name' in data:
            updates.append('name = ?')
            params.append(data['name'])
        
        if 'color' in data:
            updates.append('color = ?')
            params.append(data['color'])
        
        if 'icon' in data:
            updates.append('icon = ?')
            params.append(data['icon'])
        
        if 'description' in data:
            updates.append('description = ?')
            params.append(data['description'])
        
        if updates:
            params.append(category_id)
            cursor.execute(f'UPDATE categories SET {", ".join(updates)} WHERE id = ?', params)
            db.commit()
        
        return jsonify({'status': 'success', 'message': 'Category updated'})
    
    elif request.method == 'DELETE':
        # Set alerts in this category to uncategorized
        cursor.execute('UPDATE alerts SET category_id = NULL WHERE category_id = ?', (category_id,))
        cursor.execute('DELETE FROM categories WHERE id = ?', (category_id,))
        db.commit()
        
        return jsonify({'status': 'success', 'message': 'Category deleted'})


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get dashboard statistics"""
    db = get_db()
    cursor = db.cursor()
    
    stats = {}
    
    try:
        # Total active alerts
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE status = 0 AND is_archived = 0')
        stats['active_alerts'] = cursor.fetchone()[0] or 0
        
        # Total resolved alerts
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE status = 1 AND is_archived = 0')
        stats['resolved_alerts'] = cursor.fetchone()[0] or 0
        
        # Alerts by severity
        cursor.execute('''
            SELECT COALESCE(severity, 0) as severity, severity_name, COUNT(*) as count 
            FROM alerts 
            WHERE is_archived = 0 
            GROUP BY COALESCE(severity, 0)
            ORDER BY severity DESC
        ''')
        stats['by_severity'] = []
        for r in cursor.fetchall():
            stats['by_severity'].append({
                'severity': r[0] if r[0] is not None else 0,
                'severity_name': r[1] or 'Unknown',
                'count': r[2] or 0
            })
        
        # Unread alerts
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE is_read = 0 AND is_archived = 0')
        stats['unread'] = cursor.fetchone()[0] or 0
        
        # Recent activity (last 24 hours)
        cursor.execute('''
            SELECT COUNT(*) FROM alerts 
            WHERE created_at >= datetime('now', '-1 day')
        ''')
        stats['recent_24h'] = cursor.fetchone()[0] or 0
    except Exception as e:
        print(f"Error getting stats: {e}")
        stats = {
            'active_alerts': 0,
            'resolved_alerts': 0,
            'by_severity': [],
            'unread': 0,
            'recent_24h': 0
        }
    
    return jsonify(stats)


@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Get comprehensive analytics data"""
    db = get_db()
    cursor = db.cursor()
    
    analytics = {}
    
    try:
        # Top hosts by alert count
        cursor.execute('''
            SELECT host_name, host_id, COUNT(*) as total_alerts,
                   SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as active_alerts,
                   SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as resolved_alerts,
                   MAX(COALESCE(severity, 0)) as max_severity,
                   MAX(clock) as last_alert_time
            FROM alerts 
            WHERE is_archived = 0 AND host_name IS NOT NULL AND host_name != ''
            GROUP BY host_name 
            ORDER BY total_alerts DESC 
            LIMIT 20
        ''')
        analytics['top_hosts'] = []
        for r in cursor.fetchall():
            analytics['top_hosts'].append({
                'host_name': r[0],
                'host_id': r[1],
                'total_alerts': r[2] or 0,
                'active_alerts': r[3] or 0,
                'resolved_alerts': r[4] or 0,
                'max_severity': r[5] or 0,
                'last_alert_time': r[6],
                'severity_color': get_severity_color(r[5] or 0)
            })
        
        # Alert types (by trigger name patterns)
        cursor.execute('''
            SELECT trigger_name, COUNT(*) as count,
                   SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as active,
                   AVG(COALESCE(severity, 0)) as avg_severity
            FROM alerts 
            WHERE is_archived = 0 AND trigger_name IS NOT NULL AND trigger_name != ''
            GROUP BY trigger_name 
            ORDER BY count DESC 
            LIMIT 15
        ''')
        analytics['alert_types'] = []
        for r in cursor.fetchall():
            analytics['alert_types'].append({
                'trigger_name': r[0],
                'count': r[1] or 0,
                'active': r[2] or 0,
                'avg_severity': round(r[3] or 0, 1)
            })
        
        # Alerts by severity distribution
        cursor.execute('''
            SELECT COALESCE(severity, 0) as severity, severity_name, COUNT(*) as count,
                   SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as active
            FROM alerts 
            WHERE is_archived = 0 
            GROUP BY COALESCE(severity, 0)
            ORDER BY severity DESC
        ''')
        analytics['severity_distribution'] = []
        for r in cursor.fetchall():
            sev = r[0] if r[0] is not None else 0
            analytics['severity_distribution'].append({
                'severity': sev,
                'severity_name': r[1] or get_severity_name(sev),
                'count': r[2] or 0,
                'active': r[3] or 0,
                'color': get_severity_color(sev)
            })
        
        # Hourly distribution (when alerts occur)
        cursor.execute('''
            SELECT strftime('%H', clock) as hour, COUNT(*) as count
            FROM alerts 
            WHERE is_archived = 0 AND clock IS NOT NULL
            GROUP BY strftime('%H', clock)
            ORDER BY hour
        ''')
        hourly_data = {str(i).zfill(2): 0 for i in range(24)}
        for r in cursor.fetchall():
            if r[0]:
                hourly_data[r[0]] = r[1] or 0
        analytics['hourly_distribution'] = [{'hour': h, 'count': c} for h, c in hourly_data.items()]
        
        # Daily trend (last 30 days)
        cursor.execute('''
            SELECT date(clock) as day, COUNT(*) as count,
                   SUM(CASE WHEN status = 0 THEN 1 ELSE 0 END) as active,
                   SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END) as resolved
            FROM alerts 
            WHERE is_archived = 0 AND clock >= datetime('now', '-30 days')
            GROUP BY date(clock)
            ORDER BY day DESC
            LIMIT 30
        ''')
        analytics['daily_trend'] = []
        for r in cursor.fetchall():
            analytics['daily_trend'].append({
                'day': r[0],
                'count': r[1] or 0,
                'active': r[2] or 0,
                'resolved': r[3] or 0
            })
        analytics['daily_trend'].reverse()  # Oldest first for chart
        
        # Host health summary
        cursor.execute('''
            SELECT 
                COUNT(DISTINCT host_name) as total_hosts,
                COUNT(DISTINCT CASE WHEN status = 0 AND COALESCE(severity, 0) >= 4 THEN host_name END) as critical_hosts,
                COUNT(DISTINCT CASE WHEN status = 0 AND COALESCE(severity, 0) BETWEEN 2 AND 3 THEN host_name END) as warning_hosts,
                COUNT(DISTINCT CASE WHEN status = 0 AND COALESCE(severity, 0) <= 1 THEN host_name END) as info_hosts
            FROM alerts 
            WHERE is_archived = 0 AND host_name IS NOT NULL AND host_name != ''
        ''')
        r = cursor.fetchone()
        analytics['host_health'] = {
            'total_hosts': r[0] or 0,
            'critical_hosts': r[1] or 0,
            'warning_hosts': r[2] or 0,
            'info_hosts': r[3] or 0,
            'healthy_hosts': max(0, (r[0] or 0) - (r[1] or 0) - (r[2] or 0) - (r[3] or 0))
        }
        
        # Mean Time to Resolution (for resolved alerts)
        cursor.execute('''
            SELECT AVG(
                CAST((julianday(r_clock) - julianday(clock)) * 24 * 60 AS INTEGER)
            ) as avg_mttr_minutes
            FROM alerts 
            WHERE status = 1 AND r_clock IS NOT NULL AND clock IS NOT NULL
        ''')
        r = cursor.fetchone()
        analytics['mttr_minutes'] = round(r[0] or 0, 1) if r[0] else 0
        
        # Repeat offenders (hosts with most recurring issues)
        cursor.execute('''
            SELECT host_name, trigger_name, COUNT(*) as occurrences,
                   MIN(clock) as first_seen, MAX(clock) as last_seen
            FROM alerts 
            WHERE is_archived = 0 AND host_name IS NOT NULL AND trigger_name IS NOT NULL
            GROUP BY host_name, trigger_name
            HAVING COUNT(*) > 1
            ORDER BY occurrences DESC
            LIMIT 10
        ''')
        analytics['repeat_offenders'] = []
        for r in cursor.fetchall():
            analytics['repeat_offenders'].append({
                'host_name': r[0],
                'trigger_name': r[1],
                'occurrences': r[2] or 0,
                'first_seen': r[3],
                'last_seen': r[4]
            })
        
        # Category breakdown
        cursor.execute('''
            SELECT c.name, c.color, COUNT(a.id) as count,
                   SUM(CASE WHEN a.status = 0 THEN 1 ELSE 0 END) as active
            FROM categories c
            LEFT JOIN alerts a ON c.id = a.category_id AND a.is_archived = 0
            GROUP BY c.id
            ORDER BY count DESC
        ''')
        analytics['category_breakdown'] = []
        for r in cursor.fetchall():
            analytics['category_breakdown'].append({
                'name': r[0],
                'color': r[1],
                'count': r[2] or 0,
                'active': r[3] or 0
            })
        
        # Uncategorized count
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE category_id IS NULL AND is_archived = 0')
        analytics['uncategorized_count'] = cursor.fetchone()[0] or 0
        
        # Overall stats
        cursor.execute('SELECT COUNT(*), MIN(clock), MAX(clock) FROM alerts WHERE is_archived = 0')
        r = cursor.fetchone()
        analytics['overall'] = {
            'total_alerts': r[0] or 0,
            'oldest_alert': r[1],
            'newest_alert': r[2]
        }
        
    except Exception as e:
        print(f"Error getting analytics: {e}")
        import traceback
        traceback.print_exc()
        analytics = {'error': str(e)}
    
    return jsonify(analytics)


@app.route('/api/host/<host_name>/alerts', methods=['GET'])
def get_host_alerts(host_name):
    """Get all alerts for a specific host"""
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('''
        SELECT a.*, c.name as category_name, c.color as category_color 
        FROM alerts a 
        LEFT JOIN categories c ON a.category_id = c.id 
        WHERE a.host_name = ? AND a.is_archived = 0
        ORDER BY a.clock DESC
    ''', (host_name,))
    
    alerts = []
    for row in cursor.fetchall():
        try:
            alert = dict(row)
            sev = alert.get('severity')
            if sev is None or sev == '':
                sev = 0
            else:
                sev = int(sev) if isinstance(sev, str) else sev
            alert['severity'] = sev
            alert['severity_color'] = get_severity_color(sev)
            alerts.append(alert)
        except Exception as e:
            continue
    
    return jsonify({'alerts': alerts, 'host_name': host_name})


@app.route('/api/bulk-action', methods=['POST'])
def bulk_action():
    """Perform bulk actions on alerts"""
    db = get_db()
    cursor = db.cursor()
    
    data = request.get_json()
    action = data.get('action')
    alert_ids = data.get('alert_ids', [])
    
    if not alert_ids:
        return jsonify({'error': 'No alerts selected'}), 400
    
    placeholders = ','.join(['?' for _ in alert_ids])
    
    if action == 'archive':
        cursor.execute(f'UPDATE alerts SET is_archived = 1, updated_at = CURRENT_TIMESTAMP WHERE id IN ({placeholders})', alert_ids)
    elif action == 'unarchive':
        cursor.execute(f'UPDATE alerts SET is_archived = 0, updated_at = CURRENT_TIMESTAMP WHERE id IN ({placeholders})', alert_ids)
    elif action == 'mark_read':
        cursor.execute(f'UPDATE alerts SET is_read = 1, updated_at = CURRENT_TIMESTAMP WHERE id IN ({placeholders})', alert_ids)
    elif action == 'mark_unread':
        cursor.execute(f'UPDATE alerts SET is_read = 0, updated_at = CURRENT_TIMESTAMP WHERE id IN ({placeholders})', alert_ids)
    elif action == 'set_category':
        category_id = data.get('category_id')
        cursor.execute(f'UPDATE alerts SET category_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id IN ({placeholders})', [category_id] + alert_ids)
    elif action == 'delete':
        cursor.execute(f'DELETE FROM comments WHERE alert_id IN ({placeholders})', alert_ids)
        cursor.execute(f'DELETE FROM alerts WHERE id IN ({placeholders})', alert_ids)
    else:
        return jsonify({'error': 'Invalid action'}), 400
    
    db.commit()
    
    return jsonify({'status': 'success', 'message': f'Action {action} applied to {len(alert_ids)} alerts'})


if __name__ == '__main__':
    init_db()
    load_settings()
    print("🚀 Zabbix Alert Dashboard starting...")
    print("📊 Open http://localhost:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5000)