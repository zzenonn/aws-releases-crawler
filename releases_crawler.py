#!/usr/bin/env python3
import requests
import json
import os
import argparse
import time


from datetime import datetime
import boto3
from botocore.signers import RequestSigner
from botocore.awsrequest import AWSRequest
from botocore.auth import SigV4Auth
from botocore.session import Session
from tqdm import tqdm

current_time = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')

def invoke_aws_service(url, method='GET', data=None, headers=None, region_name='us-east-1', access_key=None, secret_key=None, session_token=None):
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name='us-east-1'
    )
    credentials = session.get_credentials()
    
    aws_request = AWSRequest(method=method, url=url, data=data, headers=headers)
    SigV4Auth(credentials, 'execute-api', region_name).add_auth(aws_request)

    response = requests.request(method=method, url=aws_request.url, headers=dict(aws_request.headers), data=aws_request.body)

    return response

def get_credentials():
    post_headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'X-Amz-User-Agent': 'aws-sdk-js/2.1046.0 callback',
        'Content-Type': 'application/x-amz-json-1.1',
        'X-Amz-Target': 'AWSCognitoIdentityService.GetCredentialsForIdentity',
        'X-Amz-Content-Sha256': '30b25aa4bff7c40d559ea61540f4719c0220da1eb8229d81bed44c6c671f270d',
        'Origin': 'https://releases.awstc.com',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'TE': 'trailers',
    }
    post_data = {
        'IdentityId': 'us-east-1:f396c7d1-55a0-48d8-b3bc-49ec6ba70434'
    }
    post_url = 'https://cognito-identity.us-east-1.amazonaws.com/'
    response = requests.post(post_url, headers=post_headers, json=post_data)
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        exit()
    return response.json()["Credentials"]


def get_args():
    parser = argparse.ArgumentParser(description='Script to get and save data from AWS.')
    parser.add_argument('--jigsaw_cookie', required=True, help='The value of the jigsaw cookie.')
    return parser.parse_args()

def fetch_course_list(access_key, secret_key, session_token):
    get_headers = {
        'Origin': 'https://releases.awstc.com',
    }
    endpoint = 'https://api.releases.prod.awstc.com/releases?target=COM&versions=3'
    response = invoke_aws_service(endpoint, 'GET', headers=get_headers, access_key=access_key, secret_key=secret_key, session_token=session_token)
    if response.status_code != 200:
        # print(response.json())
        print(f"Error: {response.status_code}")
        exit()
    return response.json()

def download_course_zips(data, access_key, secret_key, session_token, get_headers, jigsaw_cookie):
    MAX_RETRIES = 3
    jigsaw_headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Alt-Used': 'jigsaw.vitalsource.com',
        'Connection': 'keep-alive',
        'Cookie': jigsaw_cookie,
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'TE': 'trailers'
    }
    for course in data:
        if course['language'] == 'EN':
            sku = course['versions'][0]['sku']
            course_name = course['course']
            sku_endpoint = "https://api.releases.prod.awstc.com/vbid?sku=" + sku
            retries = 0

            # Get the course difficulty number
            segments = sku.split('-')
            if len(segments) > 2:
                prefix_number = segments[2]
            else:
                print(f"Unexpected SKU format for {sku}. Skipping...")
                continue    

            dir_name = f"zip/{prefix_number}-{course_name}/"
            while retries < MAX_RETRIES:
                try:
                    sku_response = invoke_aws_service(sku_endpoint, 'GET', headers=get_headers, access_key=access_key, secret_key=secret_key, session_token=session_token).json()
                    latest_zip_url = sku_response['vbid'][-1]['zips'][0]['zip']
                    filename = sku_response['vbid'][-1]['vbid']
                    response = requests.get(latest_zip_url, headers=jigsaw_headers)
                    
                    if not os.path.exists(dir_name):
                        os.makedirs(dir_name)

                    file_path = os.path.join(dir_name, filename + ".zip")

                    if os.path.exists(file_path):
                        print(f"File {file_path} already exists. Skipping...")
                        break

                    # Use tqdm for download progress
                    total_size = int(response.headers.get('content-length', 0))
                    block_size = 1024  # 1 Kbyte
                    t = tqdm(total=total_size, unit='B', unit_scale=True, desc=filename)
                    
                    with open(file_path, 'wb') as f:
                        for data in response.iter_content(block_size):
                            t.update(len(data))
                            f.write(data)
                    t.close()

                    if total_size != 0 and t.n != total_size:
                        print("ERROR, something went wrong")

                    print(f"Successfully downloaded slides for SKU: {sku}")
                    break

                except Exception as e:
                    retries += 1
                    print(f"Error downloading slides for SKU: {sku}. Attempt {retries}/{MAX_RETRIES}.")
                    print(f"Error details: {str(e)}")
                    if retries < MAX_RETRIES:
                        time.sleep(2 ** retries)  # Exponential backoff delay
                    else:
                        print(f"Max retries reached for SKU: {sku}. Skipping...")


if __name__ == "__main__":
    credentials = get_credentials()
    session_token = credentials["SessionToken"]
    access_key = credentials["AccessKeyId"]
    secret_key = credentials["SecretKey"]

    args = get_args()


    # Sending the GET request with obtained SessionToken
    get_headers = {
            'Origin': 'https://releases.awstc.com',
        }

    response_data = fetch_course_list(access_key, secret_key, session_token)

    download_course_zips(response_data, access_key, secret_key, session_token, get_headers, args.jigsaw_cookie)
