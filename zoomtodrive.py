#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import datetime
import json
import logging
import os
import time
import urllib.parse

import flask
import jmespath
import requests

from google.auth.exceptions import RefreshError
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

import rq
from redis import Redis

#import oauthlib
#oauthlib.set_debug(True)
#log = logging.getLogger('oauthlib')
#log.addHandler(logging.StreamHandler(sys.stdout))
#log.setLevel(logging.DEBUG)

import requests_oauthlib
#log = logging.getLogger('requests-oauthlib')
#log.addHandler(logging.StreamHandler(sys.stdout))
#log.setLevel(logging.DEBUG)

from tasks import drive_upload, zoom_download

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
GOOGLE_CLIENT_SECRETS_FILE = "client_secret.json"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
GOOGLE_SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/drive',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

# Zoom OAuth 2.0
ZOOM_CLIENT_ID = os.environ.get('ZOOM_CLIENT_ID')
ZOOM_CLIENT_SECRET = os.environ.get('ZOOM_CLIENT_SECRET')
ZOOM_TOKEN_URL = 'https://zoom.us/oauth/token'
ZOOM_AUTHORIZATION_URL = 'https://zoom.us/oauth/authorize'
ZOOM_RECORDINGS_URI = 'https://api.zoom.us/v2/users/me/recordings'

# Local cache directory for moving files between Zoom and Google Drive
CACHE_DIRECTORY = os.environ.get("ZOOMTODRIVE_CACHE_DIR") or \
    '/var/cache/zoomtodrive'

# Google settings
DRIVE_FOLDER_NAME = os.environ.get('DRIVE_FOLDER_NAME') or "Zoom to Drive"

app = flask.Flask(__name__)

# Setup redis
REDIS_URL = os.environ.get('REDIS_URL') or 'redis://'
REDIS_QUEUE = os.environ.get('REDIS_QUEUE') or 'zoomtodrive'
app.redis = Redis.from_url(REDIS_URL)
app.task_queue = rq.Queue(REDIS_QUEUE, connection=app.redis)

app.secret_key = os.environ.get('FLASK_SECRET_KEY')


## Cache ##
def get_cache_directory():
    # FIXME: use zoom's email
    email = flask.session['google-email']
    directory = os.path.join(CACHE_DIRECTORY, email)
    if not os.path.exists(directory):
        os.mkdir(directory)
    return directory

def get_cache_files():
    if not os.path.exists(CACHE_DIRECTORY):
        raise Exception(f"No such directory: {CACHE_DIRECTORY}")
    directory = get_cache_directory()
    return os.listdir(directory)

@app.route('/cache/files')
def api_get_cache_files():
    return flask.jsonify(get_cache_files())

## Google ##
@app.route('/google/files')
def get_our_drive_files():
    folder_id = get_drive_folder_id(DRIVE_FOLDER_NAME)
    files = get_drive_files(folder_id)
    return flask.jsonify(files)

def get_google_userinfo():
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials']
    )
    service = googleapiclient.discovery.build(
        'oauth2', 'v2', credentials=credentials
    )
    return service.userinfo().get().execute()

def get_drive_folder_id(name):
    '''Given a folder name, return the ID of the first folder
       found with that name. Creates the directory if it doesn't exist.'''
    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials']
    )
    drive = googleapiclient.discovery.build(
        'drive', 'v3', credentials=credentials
    )

    folder_id = None
    page_token = None
    query = f"mimeType='application/vnd.google-apps.folder' and name='{name}'"
    while True:
        response = drive.files().list(
            q=query, spaces='drive', fields='nextPageToken, files(id)',
            pageToken=page_token
        ).execute()
        for f in response.get('files', []):
            folder_id = f.get('id')
            break
        page_token = response.get('nextPageToken', None)
        if page_token is None:
            break

    if not folder_id:
        app.logger.info(f"Could not find folder named {name}")
        folder_id = create_drive_folder(name)

    # Save credentials back to session in case access token was refreshed.
    flask.session['credentials'] = credentials_to_dict(credentials)
    flask.session.modified = True

    return folder_id

def create_drive_folder(folder_name):
    '''Create a folder in Google Drive with the specified name.'''
    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials']
    )
    drive = googleapiclient.discovery.build(
        'drive', 'v3', credentials=credentials
    )
    body = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder',
    }
    response = drive.files().create(body=body, fields='id').execute()
    return response.get('id')

def get_drive_files(folder_id):
    '''Given a folder id, return files inside the folder.'''

    if 'credentials' not in flask.session:
        return flask.redirect('google_authorize')

    # Load credentials from the session.
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials']
    )
    drive = googleapiclient.discovery.build(
        'drive', 'v3', credentials=credentials
    )

    page_token = None
    files = []
    our_folder_member = f"mimeType != 'application/vnd.google-apps.folder' and '{folder_id}' in parents"
    while True:
        response = drive.files().list(
            q = our_folder_member,
            spaces='drive',
            fields='nextPageToken, files(id, name, size)',
            pageToken=page_token
        ).execute()
        for f in response.get('files', []):
            files.append(f)
        page_token = response.get('nextPageToken', None)
        if page_token is None:
            break

    return sorted(files, key = lambda x: x['name'])

#@app.route('/google/upload', methods=['GET', 'POST'])
def google_upload():
    '''Upload files from local cache to Google Drive.'''
    directory = get_cache_directory()
    cache_files = get_cache_files()

    # drive files is json with id, name, size
    folder_id = get_drive_folder_id(DRIVE_FOLDER_NAME)
    drive_files = get_drive_files(folder_id)
    drive_file_names = jmespath.search('[].name', drive_files)

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials']
    )
    access_token = credentials.token

    new_jobs = []
    for cache_file in cache_files:
        if cache_file in drive_file_names:
            continue
        cache_file_path = os.path.join(directory, cache_file)
        job = app.task_queue.enqueue(
            'tasks.drive_upload', cache_file_path, folder_id, access_token
        )
        new_jobs.append(job.get_id())
        app.logger.info(f'Started {job.get_id()}. len q: {len(app.task_queue)}')
    return flask.jsonify(new_jobs)

def my_registry_job_ids(username, registry):
    registry = rq.registry.StartedJobRegistry(queue=app.task_queue)
    job_ids = registry.get_job_ids()
    my_job_ids = list(
        filter(
            lambda x: x.startswith(username), job_ids
        )
    )
    return my_job_ids

@app.route('/status')
def status():
    workers = rq.Worker.all(queue=app.task_queue)
    if len(workers) == 0:
        app.logger.info("No workers available.")
        return flask.jsonify(state="no workers", job_ids=[])

    state = workers[0].get_state()
    email = flask.session['google-email']
    username = email.split('@')[0]

    my_started_job_ids = my_registry_job_ids(
        username,
        rq.registry.StartedJobRegistry(queue=app.task_queue)
    )
    my_scheduled_job_ids = my_registry_job_ids(
        username,
        rq.registry.ScheduledJobRegistry(queue=app.task_queue)
    )
    my_deferred_job_ids = my_registry_job_ids(
        username,
        rq.registry.DeferredJobRegistry(queue=app.task_queue)
    )

    all_job_ids = my_started_job_ids + my_scheduled_job_ids + \
        my_deferred_job_ids
    app.logger.info(f'status: {username} job ids({len(all_job_ids)}): {all_job_ids}')
    my_state = 'busy' if len(all_job_ids) > 0 else 'idle'
    return flask.jsonify(state=my_state, job_ids=all_job_ids)

@app.route('/google/authorize')
def google_authorize():
    '''Authenticate with Google. From Google's example code.'''

    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow
    # steps.
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE, scopes=GOOGLE_SCOPES
    )

    # The URI created here must exactly match one of the authorized redirect
    # URIs for the OAuth 2.0 client, which you configured in the API Console.
    # If this value doesn't match an authorized URI, you will get a
    # 'redirect_uri_mismatch' error.
    flow.redirect_uri = flask.url_for('google_oauth2callback', _external=True)

    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true'
    )

    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state
    flask.session.modified = True

    return flask.redirect(authorization_url)

@app.route('/google/oauth2callback')
def google_oauth2callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE, scopes=GOOGLE_SCOPES, state=state
    )
    flow.redirect_uri = flask.url_for('google_oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    flask.session['credentials'] = credentials_to_dict(credentials)
    flask.session.modified = True

    return flask.redirect(flask.url_for('main_view'))


@app.route('/google/revoke')
def google_revoke():
    '''
    Revoke the access token associated with the current user session. After
    revoking credentials, API calls will produce an `invalid_grant` error.
    '''

    if 'credentials' not in flask.session:
        return ('You need to <a href="/google/authorize">authorize</a> before ' +
                'testing the code to revoke credentials.')

    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials']
    )

    revoke = requests.post(
        'https://oauth2.googleapis.com/revoke',
        params = {'token': credentials.token},
        headers = {'content-type': 'application/x-www-form-urlencoded'}
    )

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return('Credentials successfully revoked.' + print_index_table())
    else:
        return('An error occurred.' + print_index_table())


@app.route('/google/clear')
def clear_credentials():
    '''Clear Google credentials stored in the user session.'''
    if 'credentials' in flask.session:
        del flask.session['credentials']
    return ('Credentials have been cleared.<br><br>' + print_index_table())


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

## Zoom ##
@app.route('/zoom/token')
def zoom_token():
    return flask.jsonify(flask.session['zoom_token'])

@app.route('/zoom/refresh')
def zoom_refresh():
    '''Return our Zoom access token, refreshing it if it has expired.'''
    zoom_token = flask.session['zoom_token']
    # Return our access token if it isn't expired
    if 'expires_at' in zoom_token and time.time() < zoom_token['expires_at']:
        return zoom_token['access_token']

    # Return our access token if there is no refresh token.
    # We'll need a new access token some other way.
    refresh_token = zoom_token.get('refresh_token', None)
    if not refresh_token:
        return zoom_token['access_token']

    # Ask zoom for a new access token. They update the refresh token too.
    msg = ZOOM_CLIENT_ID + ':' + ZOOM_CLIENT_SECRET
    zoom_authz_basic = base64.b64encode(msg.encode('ascii')).decode('ascii')
    headers=dict(Authorization="Basic " + zoom_authz_basic)
    data = dict(
        grant_type="refresh_token",
        refresh_token=refresh_token
    )
    r = requests.post(ZOOM_TOKEN_URL, headers=headers, data=data)
    response = r.json()
    if 'error' in response:
        app.logger.info(f"Error refreshing token: {response['reason']}")
        flask.redirect(flask.url_for('zoom_auth'))
    elif 'access_token' not in response:
        app.logger.info(f"No access token in zoom response: {response}")
        flask.redirect(flask.url_for('zoom_auth'))

    expires_in = response.get('expires_in', None)
    if expires_in:
        flask.session['zoom_token']['expires_at'] = expires_in + time.time() - 1
    flask.session['zoom_token']['access_token'] = response['access_token']
    flask.session['zoom_token']['refresh_token'] = response['refresh_token']
    # Update the session cookie.
    flask.session.modified = True
    return zoom_token['access_token']

    #oauth = requests_oauthlib.OAuth2Session(
    #    ZOOM_CLIENT_ID,
    #    state=flask.session['zoom_state'],
    #    redirect_uri=flask.url_for('zoom_auth', _external=True)
    #)
    #token = oauth.refresh_token(
    #    ZOOM_TOKEN_URL,
    #    client_secret=ZOOM_CLIENT_SECRET,
    #    refresh_token=refresh_token,
    #    headers=dict(Authorization="Basic " + zoom_authz_token())
    #)
    #flask.session['zoom_token']['access_token'] = token['access_token']
    #flask.session['zoom_token']['refresh_token'] = token['refresh_token']
    #flask.session.modified = True

def zoom_authz_token():
    '''Create the Zoom Authorization Bearer token.'''
    msg = ZOOM_CLIENT_ID + ':' + ZOOM_CLIENT_SECRET
    return base64.b64encode(msg.encode('ascii')).decode('ascii')

@app.route('/zoom/auth')
def zoom_auth():
    '''Do the Zoom OAuth 2.0 dance.
    
    Zoom requires that the authz and oauth callback handlers have the
    same redirect uri.'''
    code = flask.request.args.get('code', None)
    if not code:
        oauth = requests_oauthlib.OAuth2Session(
            ZOOM_CLIENT_ID,
            redirect_uri=flask.url_for('zoom_auth', _external=True)
        )
        authorization_url, state = oauth.authorization_url(
            ZOOM_AUTHORIZATION_URL
        )
        flask.session['zoom_state'] = state
        flask.session.modified = True
        app.logger.info(f'zoom authz url {authorization_url}')
        app.logger.info(f'zoom_state {state}')
        return flask.redirect(authorization_url)
        
    else:
        app.logger.info(f'zoom auth code: mark 0')
        oauth = requests_oauthlib.OAuth2Session(
            ZOOM_CLIENT_ID,
            state=flask.session['zoom_state'],
            redirect_uri=flask.url_for('zoom_auth', _external=True)
        )
        app.logger.info(f'zoom auth code: mark 10')
        token = oauth.fetch_token(
            ZOOM_TOKEN_URL,
            client_secret=ZOOM_CLIENT_SECRET,
            authorization_response=flask.request.url
        )
        app.logger.info(f'zoom_token {token}')
        flask.session['zoom_token'] = token
        flask.session.modified = True
        return flask.redirect(flask.url_for('main_view'))

def call_zoom_api(url, params={}):
    '''Call Zoom API.'''
    access_token = zoom_refresh()
    try:
        r = requests.get(
            url,
            params=params,
            headers=dict(Authorization = f"Bearer {access_token}")
        )
    except Exception as e:
        app.logger.info(f"Error on {url}: {e}")
        raise
    return r.json()

@app.route('/zoom/profile')
def zoom_profile():
    '''Get user data.'''
    data = call_zoom_api('https://api.zoom.us/v2/users/me')
    app.logger.info(f"about me data: {data}")
    return flask.jsonify(data)

def get_zoom_recordings():
    '''Get Zoom recording files, going back a number of months.
    
    The Zoom API only lets us get data 30 days at a time so
    we must loop.'''
    day_chunks = 30 ; months = 6
    url = 'https://api.zoom.us/v2/users/me/recordings'
    recordings = []
    date_to = datetime.date.today()
    for i in range(months):
        params = {
            'from': date_to - datetime.timedelta(days=day_chunks),
            'to': date_to,
            'page_size': 100
        }
        data = call_zoom_api(url, params)
        if not data: # api call failed
            break
        recording_files = jmespath.search(
            'meetings[].recording_files[]', data
        )
        if not recording_files:
            break
        recordings += recording_files
        date_to = params.get('from') - datetime.timedelta(days=1)
    return recordings

@app.route('/zoom/recordings')
def zoom_recordings():
    data = get_zoom_recordings()
    return flask.jsonify(data)

def format_start_time(timestamp):
    '''Reformat time from 2020-10-07T20:42:57Z to 20201007-204257.'''
    _ = time.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')
    return time.strftime("%Y%m%d-%H%M%S", _)

def format_recording_filename(f):
    i = f.get('id')
    start = format_start_time(f.get('recording_start'))
    t = f.get('file_type', None)
    if not t:
        return f'{start}.'
    ext = {
        'TIMELINE': 'json',
        'TRANSCRIPT':'vtt',
        'CHAT':'chat.txt',
    }.get(t, t.lower())
    if not i:
        return f'{start}.{ext}'
    else:
        return f'{start}_{i}.{ext}'

@app.route('/zoom/files')
def zoom_files():
    recording_files = get_zoom_recordings()
    filenames = []
    for rf in recording_files:
        filenames.append(format_recording_filename(rf))
    filenames.sort()
    return flask.jsonify(filenames)

@app.route('/zoom/download')
def zoom_download():
    access_token = zoom_refresh()
    recording_files = get_zoom_recordings()
    cache_directory = get_cache_directory()
    jobs = []
    for rf in recording_files:
        file_path = os.path.join(
            cache_directory,
            format_recording_filename(rf)
        )
        if os.path.exists(file_path):
            app.logger.info(f'File exists: {file_path}')
            continue

        cloudsize = rf.get('file_size', 1)

        app.logger.info(f'creating job for {file_path} at {cloudsize}')
        job = app.task_queue.enqueue(
            'tasks.zoom_download',
            access_token, rf['download_url'], file_path, cloudsize
        )
        app.logger.info(f'Started {job.get_id()}. len q: {len(app.task_queue)}')
        jobs.append(job.get_id())
        
    return flask.jsonify(jobs)

@app.route('/sync', methods=['POST'])
def sync():
    # zoom
    zoom_access_token = zoom_refresh()
    recording_files = get_zoom_recordings()
    # local
    cache_directory = get_cache_directory()
    # google
    folder_id = get_drive_folder_id(DRIVE_FOLDER_NAME)
    credentials = google.oauth2.credentials.Credentials(
        **flask.session['credentials']
    )
    google_access_token = credentials.token
    email = flask.session['google-email']
    username = email.split('@')[0]
    drive_files = get_drive_files(folder_id)
    drive_file_names = jmespath.search('[].name', drive_files)

    jobs = []
    for rf in recording_files:
        filename = format_recording_filename(rf)
        if filename in drive_file_names:
            app.logger.debug(f"Drive file exists: {username}/{filename}")
            continue
        else:
            app.logger.debug(f"Drive file doesn't exist: {username}/{filename}")
        
        cache_file_path = os.path.join(cache_directory, filename)
        if not os.path.exists(cache_file_path):
            app.logger.info(f'Cache file does NOT exist: {cache_file_path}')
            size = rf.get('file_size', 1)
            app.logger.info(f'JOB: zoom download to {cache_file_path} at {size}')
            zoom_dl_job = app.task_queue.enqueue(
                'tasks.zoom_download',
                job_id=f'{username}-zoom-{filename}',
                args=(
                    zoom_access_token, rf['download_url'], cache_file_path, size
                )
            )
            jobs.append(zoom_dl_job.get_id())
        else:
            app.logger.info(f'Cache file exists: {cache_file_path}')
            zoom_dl_job = None

        app.logger.info(f'JOB: drive upload from {cache_file_path}')
        drive_ul_job = app.task_queue.enqueue(
            'tasks.drive_upload',
            job_id=f'{username}-google-{filename}',
            depends_on=zoom_dl_job,
            args=(cache_file_path, folder_id, google_access_token)
        )
        jobs.append(drive_ul_job.get_id())

    return flask.jsonify(jobs)

@app.route('/')
def main_view():
    # redirect to zoom auth if we haven't already
    if 'zoom_token' not in flask.session or \
        'access_token' not in flask.session['zoom_token']:
        return flask.redirect(flask.url_for('zoom_auth'))

    # redirect to google auth if we haven't already
    if 'credentials' not in flask.session:
        return flask.redirect(flask.url_for('google_authorize'))
        
    try:
        userinfo = get_google_userinfo()
    except RefreshError as e:
        return flask.redirect(flask.url_for('google_authorize'))

    if 'email' not in userinfo:
        return flask.render_template(
            'error.html',
            msg="Could not get your Google email address."
        )

    try:
        zoomprofile = zoom_profile()
    except Exception as e:
        app.logger.info('Error getting Zoom profile: {e}')
        return flask.redirect(flask.url_for('zoom_auth'))

    # save the user's email address. we use it for their cache storage path
    if 'google-email' not in flask.session:
        flask.session['google-email'] = userinfo.get('email')
        flask.session.modified = True
    if 'google-drive-folder-id' not in flask.session:
        flask.session['google-drive-folder-id'] = get_drive_folder_id(
            DRIVE_FOLDER_NAME
        )
        flask.session.modified = True

    return flask.render_template(
        'zoomtodrive.html',
        folder_name=DRIVE_FOLDER_NAME
    )

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = 1
    port = int(os.environ.get('FLASK_PORT', '5000'))
    app.run('0.0.0.0', port=port, debug=True)
