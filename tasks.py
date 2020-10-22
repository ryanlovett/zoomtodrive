import json
import os
import time

import requests
from rq import get_current_job

def example(seconds):
    job = get_current_job()
    print('Starting task')
    for i in range(seconds):
        job.meta['progress'] = 100.0 * i / seconds
        job.save_meta()
        print(i)
        time.sleep(1)
    job.meta['progress'] = 100
    job.save_meta()
    print('Task completed')


def drive_upload(path, folder_id, access_token):
    '''Upload a local file to the Google Drive folder specified by an ID.
       Requires an access token to invoke the Google API.'''
    job = get_current_job()
    print('Starting task')

    job.meta['progress'] = 0 ; job.save_meta()
    mime_type = "application/octet-stream"
    filesize = os.path.getsize(path)

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    params = {
        "name": os.path.basename(path),
        "mimeType": mime_type,
        'description': "Uploaded by Zoom to Drive.",
        "parents": [folder_id],
    }
    r = requests.post(
        "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",
        headers=headers,
        data=json.dumps(params)
    )
    print(f'upload headers: {r.headers}')
    if 'Location' not in r.headers:
        print(f'no location: {r.text}')
        return r.text

    location = r.headers['Location']

    # FIXME: chunk the uploads?
    headers = {
        "Content-Range": f"bytes 0-{filesize - 1}/{filesize}"
    }
    job.meta['progress'] = 1 ; job.save_meta()
    r = requests.put(location, headers=headers, data=open(path, 'rb'))

    job.meta['progress'] = 100 ; job.save_meta()
    return r.text

def zoom_download(access_token, download_url, file_path, cloudsize=0):
    '''Download a zoom recording file to the local cache folder specified by
       a path.
       Requires an access token to invoke the Zoom API.'''
    job = get_current_job()
    print('Starting task')

    job.meta['progress'] = 0 ; job.save_meta()

    params = { "access_token": access_token }
    with requests.get(download_url, params=params, stream=True) as r:
        r.raise_for_status()
        with open(file_path, 'wb') as f:
            written = 0
            for chunk in r.iter_content(chunk_size=1048576):
                written += f.write(chunk)
                job.meta['progress'] = written / cloudsize
                job.save_meta()

    job.meta['progress'] = 100 ; job.save_meta()
    return "done"