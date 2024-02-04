# This is a sample Python script.
import base64
import concurrent.futures
import datetime
import logging
import os
import platform
import queue
import subprocess
import sys
import time
import traceback
from functools import partial
from logging.handlers import RotatingFileHandler
from typing import Tuple, Any

import requests
from github import Github
from peewee import SqliteDatabase, Model, IntegerField, TextField, DateTimeField, FloatField, ForeignKeyField, BooleanField, AutoField, fn
from requests import RequestException
from requests.adapters import HTTPAdapter, Retry

from url_to_json import convert_uri_json



# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

subscription_urls = ["https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vmess.txt",
                     "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/vless.txt",
                     "https://raw.githubusercontent.com/barry-far/V2ray-Configs/main/Splitted-By-Protocol/trojan.txt",
                     "https://raw.githubusercontent.com/yebekhe/TVC/main/subscriptions/xray/normal/mix"]

db = SqliteDatabase('db.sqlite')
deep_test_timeout = 2
deep_test_size = 1024
max_concurrent_deep_tests = 10
max_retries_per_uri = 2
level2_test_iteration = 2
level2_test_timeout = 3
level2_test_size = 100
level2_inconclusive_test_weight = 60
level2_test_latency_weight = 0.2
level2_test_count = 250
subscription_config_count = 30
inbound_port_start = 2200

# ----- github settings if you want the subscription list be uploaded to github, leave empty if not -----

remote_file_path = ''
repo_owner = ''
repo_name = ''
branch_name = ''
github_token = ''


# ----- end of github settings ------


class Configs(Model):
    uri = TextField(primary_key=True)
    date_added = DateTimeField(null=True)
    date_removed = DateTimeField(null=True)
    fail_count = IntegerField(null=True)
    success_count = IntegerField(null=True)
    last_download_speed = FloatField(null=True)
    type = TextField(null=True)

    class Meta:
        database = db


class Performance(Model):
    id = AutoField(primary_key=True)
    config_uri = ForeignKeyField(Configs, to_field="uri", backref="performance", column_name="config_uri")
    medium_file_download_speed = FloatField(null=True)
    medium_file_upload_speed = FloatField(null=True)
    latency = IntegerField(null=True)
    test_date = DateTimeField(null=True)
    inconclusive = BooleanField(null=True)

    class Meta:
        database = db


def write_to_db(uri: str, download_speed: float):
    if uri.startswith("vmess://"):
        config_type = "vmess"
    elif uri.startswith("vless://"):
        config_type = "vless"
    elif uri.startswith("trojan://"):
        config_type = "trojan"
    elif uri.startswith("ss://"):
        config_type = "ss"
    else:
        config_type = ""

    query = Configs.insert(
        uri=uri,
        date_added=datetime.datetime.now(),
        fail_count=download_speed is None,
        success_count=download_speed is not None,
        last_download_speed=download_speed,
        type=config_type
    ).on_conflict(
        conflict_target=[Configs.uri],
        update={
            'fail_count': Configs.fail_count + (download_speed is None),
            'success_count': Configs.success_count + (download_speed is not None),
            'last_download_speed': download_speed
        }
    )
    query.execute()


def get_data_from_url(url, logger: logging.Logger):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad responses
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Error: {e}")
        return None


def get_uri_list(url: str, logger: logging.Logger):
    response = get_data_from_url(url, logger)
    lines = response.text.split('\n')
    return lines


def get_uri_list_base64(url: str, logger: logging.Logger):
    response = get_data_from_url(url, logger)
    try:
        decoded_response = base64.b64decode(response.text).decode('utf-8')
    except:
        decoded_response = response.text
        logger.info("not base64 encoded subscription.")

    lines = decoded_response.splitlines()
    return lines


# Press the green button in the gutter to run the script.
def start_v2ray(file_name: str, logger: logging.Logger):
    try:
        if platform.system() == "Windows":
            process = subprocess.Popen(f'xray.exe run -config="config/{file_name}"', stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        else:
            process = subprocess.Popen(['./xray', 'run', f'-config=/root/v2ray_config_tester/config/{file_name}'], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
        time.sleep(1.5)

        was_success = process.poll() is None and process.returncode is None
        logger.info(f"xray.exe executed success: {was_success}")
        if was_success:
            return process
        else:
            return None


    except:
        logger.error("starting v2ray unsuccessful")
        return None


def test_download_speed(inbound_port: int, timeout: int, file_size: int, logger: logging.Logger):
    proxy_address = f"socks5://127.0.0.1:{inbound_port}"
    handler = requests.Session()
    handler.proxies = {
        "http": proxy_address,
        "https": proxy_address
    }

    handler.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    handler.timeout = timeout
    handler.mount("https://", HTTPAdapter(max_retries=Retry(total=max_retries_per_uri)))
    logger.info("\n----- Download Test -----")
    logger.info(f"Start check dl speed, proxy port: {inbound_port}, timeout: {timeout} sec")

    try:
        dl_url = "https://speed.cloudflare.com/__down?bytes=" + f"{file_size}"
        logger.info(f"Starting dl url: {dl_url}")
        response = handler.get(dl_url, timeout=timeout)
        response.raise_for_status()
        data = response.text
        # print("Download request response:", data)
        logger.info(f"*** Download success in {response.elapsed.total_seconds() * 1000} ms, dl size: {len(data)} bytes ")
        return len(data) / response.elapsed.total_seconds() / 1024
    except RequestException as e:
        logger.error(e)
        return None
    except:
        logger.error("other exception while download testing")
        return None
    finally:
        handler.close()


def test_upload_speed(inbound_port: int, timeout: int, file_size: int, logger: logging.Logger):
    proxy_address = f"socks5://127.0.0.1:{inbound_port}"
    handler = requests.Session()
    handler.proxies = {
        "http": proxy_address,
        "https": proxy_address
    }

    handler.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    handler.timeout = timeout

    logger.info("\n----- Upload Test -----")
    logger.info(f"Start check up speed, proxy port: {inbound_port}, timeout: {timeout} sec")

    url = 'https://speed.cloudflare.com/__up'
    headers = {'Content-Type': 'multipart/form-data', 'Host': 'speed.cloudflare.com'}
    # params = {'resolve': f"speed.cloudflare.com:443:{ip}"}
    files = {'file': ('sample.bin', b"\x00" * file_size)}
    handler.mount("https://", HTTPAdapter(max_retries=Retry(total=max_retries_per_uri)))
    try:
        response = handler.post(url, headers=headers, files=files, timeout=timeout)
        if response.status_code == 200:
            upload_speed = file_size / 1024 / response.elapsed.total_seconds()
            logger.info(f"*** Upload success in {response.elapsed.total_seconds() * 1000} ms")
            return upload_speed
        else:
            return None
    except requests.Timeout:
        logger.error("Upload timed out.")
        return None
    except Exception as ex:
        message = str(ex)
        if isinstance(ex, requests.exceptions.RequestException):
            logger.error(f"Upload had exception: {message}")
        return None
    finally:
        handler.close()


def has_failed_too_many_times(config_uri: str, logger: logging.Logger):
    try:
        config = Configs.get(Configs.uri == config_uri)
        if config.success_count == 0:
            return config.fail_count > 5
        else:
            return config.fail_count / config.success_count > 5
    except Configs.DoesNotExist:
        logger.info(f"no previous record found for {config_uri}")
        return False


def upload_sub_to_github(logger: logging.Logger):
    local_file_path = 'sub.txt'

    # Create a Github instance using the token
    g = Github(github_token)

    # Get the repository
    repo = g.get_repo(f'{repo_owner}/{repo_name}')

    # Read the content of the local file
    with open(local_file_path, 'r', encoding='utf-8') as local_file:
        file_content = local_file.read()

    # Encode the content to Base64
    encoded_content = base64.b64encode(file_content.encode()).decode()

    # Get the current content of the file from the repository
    file_contents = repo.get_contents(remote_file_path, ref=branch_name)

    # Compare local content with GitHub content
    if file_contents.content == encoded_content:
        logger.info("Local file content matches GitHub content. No update needed.")
    else:
        # Update the file
        repo.update_file(
            path=remote_file_path,
            message='Update file via Python script',
            content=encoded_content,
            branch=branch_name,
            sha=file_contents.sha
        )
        logger.info(f"File {remote_file_path} successfully updated on GitHub.")


def init_logging():
    if not os.path.exists("./logs"):
        os.makedirs("./logs")
    should_rollover = os.path.isfile("./logs/log")
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(message)s'))
    handler = RotatingFileHandler("./logs/log", maxBytes=100 * 1024 * 1024, backupCount=2, encoding='utf-8')
    handler.setFormatter(logging.Formatter('%(asctime)s:%(levelname)s:%(message)s'))
    logging.basicConfig(level=logging.NOTSET, handlers=[handler, console_handler])
    if should_rollover:
        handler.doRollover()
    return logging.getLogger(__name__)


def create_partial_test_task(port_queue: queue.Queue, logger: logging.Logger):
    return partial(test_config, port_queue=port_queue, logger=logger)


def deep_test(logger: logging.Logger):
    port_queue = queue.Queue()
    for port in range(inbound_port_start, inbound_port_start + max_concurrent_deep_tests*2):
        port_queue.put(port)

    for url in subscription_urls:
        uri_list = get_uri_list(url, logger)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent_deep_tests) as executor:
            # Submit tasks to the executor
            futures = {executor.submit(create_partial_test_task(port_queue, logger), uri): uri for uri in uri_list}
            # Wait for all tasks to complete
            concurrent.futures.wait(futures)


def write_performance_data_to_db(uri: str, download_speeed: float, upload_speed: float, latency: int, ):
    performance_data = Performance()
    performance_data.test_date = datetime.datetime.now()
    performance_data.latency = latency
    performance_data.config_uri = uri
    performance_data.medium_file_download_speed = download_speeed
    performance_data.medium_file_upload_speed = upload_speed
    performance_data.save()


def write_inconclusive_performance_to_db(uri):
    performance_data = Performance()
    performance_data.inconclusive = True
    performance_data.test_date = datetime.datetime.now()
    performance_data.config_uri = uri
    performance_data.save()


def test_latency(inbound_port: int, timeout: int, logger: logging.Logger):
    proxy_address = f"socks5://127.0.0.1:{inbound_port}"
    handler = requests.Session()
    handler.proxies = {
        "http": proxy_address,
        "https": proxy_address
    }

    handler.headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }
    handler.timeout = timeout
    handler.mount("https://", HTTPAdapter(max_retries=Retry(total=max_retries_per_uri)))
    logger.info("\n----- Download Test -----")
    logger.info(f"Start check dl speed, proxy port: {inbound_port}, timeout: {timeout} sec")

    try:
        dl_url = "https://speed.cloudflare.com/__down?bytes=0"
        logger.info(f"Starting dl url: {dl_url}")
        response = handler.get(dl_url, timeout=timeout)
        response.raise_for_status()
        if 'Server-Timing' in response.headers:
            # Extract the server request duration from the 'Server-Timing' header
            server_timing_header = response.headers['Server-Timing']

            # Parse the 'Server-Timing' header to extract the duration
            duration_start = server_timing_header.find('dur=') + len('dur=')
            duration_end = server_timing_header.find(',', duration_start)
            duration_str = server_timing_header[duration_start:duration_end].strip()

            # Convert the duration string to a float (in seconds)
            server_duration_ms = float(duration_str)

            logger.info(f'Server request duration: {server_duration_ms} seconds')
        else:
            server_duration_ms = 0
            logger.info('Server-Timing header not found in the response')
        latency = response.elapsed.total_seconds() * 1000 - server_duration_ms
        logger.info(f"*** Latency success in {latency} ms")
        return latency
    except RequestException as e:
        logger.error(e)
        return None
    except:
        logger.error("other exception while download testing")
        return None
    finally:
        handler.close()


def level2_test(logger: logging.Logger):
    inbound_port = 2222
    query = Configs.select(Configs.uri).order_by(Configs.last_download_speed.desc(), Configs.fail_count.asc(), Configs.success_count.asc()).limit(level2_test_count)
    uris = [record.uri for record in query]
    for uri in uris:
        logger.info(uri)
        try:
            if convert_uri_json(uri=uri, socksport=inbound_port, port=2223) is False:
                continue
        except Exception as e:
            logger.error(f"----Exception during uri conversion type {type(e).__name__} : {str(e)}----\n {traceback.format_exc()}")
            continue
        process = start_v2ray("config.json", logger)
        download_speed_array = []
        upload_speed_array = []
        latency_array = []
        if process is not None:
            for _ in range(level2_test_iteration):
                download_speed = test_download_speed(inbound_port, level2_test_timeout, level2_test_size * 1024, logger)
                if download_speed is None:
                    break
                else:
                    download_speed_array.append(download_speed)
                    upload_speed = test_upload_speed(inbound_port, level2_test_timeout, level2_test_size * 1024, logger)
                    if upload_speed is None:
                        break
                    else:
                        upload_speed_array.append(upload_speed)
                        latency = test_latency(inbound_port, level2_test_timeout, logger)
                        if latency is None:
                            break
                        else:
                            latency_array.append(latency)
        else:
            logger.error("cannot run xray, exiting test...")
            return
        if len(download_speed_array) == level2_test_iteration and len(upload_speed_array) == level2_test_iteration and len(latency_array) == level2_test_iteration:
            write_performance_data_to_db(uri, sum(download_speed_array) / len(download_speed_array), sum(upload_speed_array) / len(upload_speed_array), int(sum(latency_array) / len(latency_array)))
        else:
            write_inconclusive_performance_to_db(uri)

        process.kill()


def main():
    logger = init_logging()
    # Connect to the database
    db.connect()
    db.create_tables([Configs, Performance], safe=True)
    arguments = sys.argv[1:]
    if "--all" in arguments:
        deep_test(logger)
        level2_test(logger)
    elif "--level2" in arguments:
        level2_test(logger)
    elif "--update_sub" in arguments:
        generate_subscription_list(logger)
        if github_token != "":
            upload_sub_to_github(logger)
    else:
        logger.error("one these command line arguments must be provided: --all, --level2, --update_sub")


def test_config(uri: str, port_queue: queue.Queue, logger: logging.Logger):
    if has_failed_too_many_times(uri, logger):
        logger.info(f"skipping {uri}")
        return
    logger.info(uri)
    inbound_socks_port = port_queue.get()
    inbound_http_port = port_queue.get()
    try:
        if convert_uri_json(uri=uri, socksport=inbound_socks_port, port=inbound_http_port, file_name=f"config-{inbound_socks_port}.json") is False:
            port_queue.put(inbound_socks_port)
            port_queue.put(inbound_http_port)
            return
    except Exception as e:
        logger.error(f"----Exception during uri conversion type {type(e).__name__} : {str(e)}----\n {traceback.format_exc()}")
        port_queue.put(inbound_socks_port)
        port_queue.put(inbound_http_port)
        return
    process = start_v2ray(f"config-{inbound_socks_port}.json", logger)
    if process is not None:
        download_speed = test_download_speed(inbound_socks_port, deep_test_timeout, deep_test_size, logger)
        process.kill()
        write_to_db(uri, download_speed)
    port_queue.put(inbound_socks_port)
    port_queue.put(inbound_http_port)


def generate_subscription_list(logger: logging.Logger):
    ten_days_ago = datetime.datetime.now() - datetime.timedelta(days=10)

    kpi_query = (
        Performance
        .select(
            Performance.config_uri,
            fn.AVG(Performance.medium_file_download_speed).alias('avg_download_speed'),
            fn.AVG(Performance.medium_file_upload_speed).alias('avg_upload_speed'),
            fn.AVG(Performance.latency).alias('avg_latency'),
            fn.COALESCE(fn.SUM(Performance.inconclusive.cast('integer')), 0).alias('total_inconclusive')
        )
        .where(Performance.test_date >= ten_days_ago)
        .group_by(Performance.config_uri)
    )

    # Fetch the KPIs and store them in a list of dictionaries
    kpi_results = [result for result in kpi_query.dicts()]

    # Assuming you already have the results from your query stored in kpi_results

    # Now you can sort the kpi_results based on the adjusted average speeds
    sorted_results = sorted(
        kpi_results,
        key=lambda x: (x['avg_download_speed'] or 0) + (x['avg_upload_speed'] or 0) - (x['avg_latency'] or 0) * level2_test_latency_weight - x['total_inconclusive'] * level2_inconclusive_test_weight,
        reverse=True
    )
    records = []
    for i, record in enumerate(sorted_results):
        try:
            records.append(record['config_uri'])
        except KeyError:
            logger.error("Error retrieving records with specified conditions")

        if i >= subscription_config_count - 1:
            break

    # Write the records to a file
    output_file_path = 'sub.txt'
    with open(output_file_path, 'w', encoding='utf-8') as output_file:
        for uri in records:
            output_file.write(f"{uri}\n")


if __name__ == '__main__':
    main()
