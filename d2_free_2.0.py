import os
import sys
import time
import threading
import concurrent.futures
import boto3
import signal
from botocore.client import Config
from botocore.exceptions import ClientError
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from tqdm import tqdm
import argparse
import logging
from logging.handlers import RotatingFileHandler
import configparser
from queue import Queue, Empty
import warnings
import pickle
import subprocess
from urllib3.exceptions import InsecureRequestWarning
from dotenv import load_dotenv

load_dotenv()

warnings.simplefilter('ignore', InsecureRequestWarning)
sync_manager = None

def start_flask_server():
    """Start the Flask server as a subprocess."""
    python_executable = sys.executable
    return subprocess.Popen([python_executable, "flask_server.py"])

def stop_flask_server(process):
    """Gracefully stop the Flask server subprocess."""
    if process.poll() is None:  # Check if the process is still running
        process.terminate()
        process.wait()

def handle_signal(signal, frame):
    print("Signal received, stopping Flask server...")
    global sync_manager
    if sync_manager:
        stop_flask_server(sync_manager.flask_process)
        sync_manager.stop_monitoring()
    sys.exit(0)

class SyncManager:
    CONFIG_FILE = 'config.ini'
    LOG_FILE = 'sync.log'
    DEFAULT_WATCH_FOLDER = os.getenv("UPLOAD_FOLDER")
    SYNC_INTERVAL = 300  # 5 minutes
    S3_ENDPOINT_URL = os.getenv("S3_ENDPOINT_URL")
    S3_USE_PATH_STYLE = True
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    BUCKET_NAME = os.getenv("BUCKET_NAME")
    PROCESSED_FILES_FILE = 'processed_files.pkl'
    MAX_BATCH_SIZE_BYTES = 10 * 1024 * 1024 * 1024  # 10 GB
    MIN_BATCH_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB

    def __init__(self):
        try:
            self.flask_process = start_flask_server()
            self.start_time = time.time()
            self.file_queue = Queue()
            self.observer = None
            self.tqdm_lock = threading.Lock()
            self.initial_scan_complete = threading.Event()
            self.min_upload_speed = 10 * 1024 * 1024  # 50 MB/s as a threshold for high-speed internet
            self.current_batch_size_bytes = self.MIN_BATCH_SIZE_BYTES  # Start with a smaller batch size
            self.max_batch_size_bytes = self.MAX_BATCH_SIZE_BYTES  # Allow for larger batches
            self.speeds = []  # To store recent upload speeds for averaging
            self.speeds_max_length = 10  # Maximum number of speeds to keep for averaging
            self.is_batch_processing = False
            self.WATCH_FOLDER = self.DEFAULT_WATCH_FOLDER
            self.s3 = self.create_s3_client()
            self.setup_logging()
            self.processed_files = self.load_processed_files()
            self.load_config()
            self.load_queue_from_file()  # Load the queue from file on startup
            self.SOFT_DELETE_FOLDER = os.path.join(self.WATCH_FOLDER, 'soft_delete')
            self.create_folder_if_not_exists(self.SOFT_DELETE_FOLDER)
            print("Initialization complete.")
        except Exception as e:
            print(f"Error during initialization: {e}")

    def should_ignore_file(self, file_path):
        ignored_extensions = ['.log', '.pkl', '.json']
        ignored_files = [self.LOG_FILE, self.PROCESSED_FILES_FILE]
        # Add a check for temporary files
        if os.path.basename(file_path).startswith('.goutputstream-'):
            return True
        if os.path.basename(file_path) in ignored_files:
            return True
        if any(file_path.endswith(ext) for ext in ignored_extensions):
            return True
        return False

    def list_s3_contents(self):
        try:
            paginator = self.s3.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=self.BUCKET_NAME)
            print(f"Listing contents of S3 bucket: {self.BUCKET_NAME}")
            for page in page_iterator:
                if "Contents" in page:
                    for obj in page['Contents']:
                        print(f"{obj['Key']} (Last Modified: {obj['LastModified']})")
                else:
                    print("No contents found in the bucket.")
        except ClientError as e:
            logging.error(f"Failed to list bucket contents: {e}")
            print(f"Error: {e}")

    def check_s3_presence(self, s3_files):
        local_file_paths = [os.path.join(self.WATCH_FOLDER, f) for f in os.listdir(self.WATCH_FOLDER)]
        for local_file in local_file_paths:
            rel_path = os.path.relpath(local_file, self.WATCH_FOLDER)
            if rel_path in s3_files:
                logging.debug(f"File {rel_path} is present in both local and S3.")
            else:
                logging.info(f"File {rel_path} missing in S3; needs upload.")

    def clear_queue(self):
        self.file_queue = Queue()  # Reinitialize the queue
        self.save_queue_to_file()  # Save the cleared state
        print("Queue cleared and saved.")

    def clear_processed_files(self):
        self.processed_files = set()  # Reinitialize the processed files set
        self.save_processed_files()  # Save the cleared state
        print("Processed files cleared and saved.")

    def load_processed_files(self):
        if os.path.exists(self.PROCESSED_FILES_FILE):
            try:
                with open(self.PROCESSED_FILES_FILE, 'rb') as f:
                    return pickle.load(f)
            except EOFError:
                return set()
        return set()

    def save_processed_files(self):
        with open(self.PROCESSED_FILES_FILE, 'wb') as f:
            pickle.dump(self.processed_files, f)
    
    def queue_size(self):
        return self.file_queue.qsize()
    
    def clean_incomplete_uploads(self):
        try:
            multipart_uploads = self.s3.list_multipart_uploads(Bucket=self.BUCKET_NAME)
            for upload in multipart_uploads.get('Uploads', []):
                upload_id = upload['UploadId']
                key = upload['Key']
                self.s3.abort_multipart_upload(Bucket=self.BUCKET_NAME, Key=key, UploadId=upload_id)
                logging.info(f"Aborted incomplete multi-part upload for {key} with UploadId {upload_id}")
        except ClientError as e:
            logging.error(f"Error listing or aborting incomplete multi-part uploads: {e}")

    def add_to_processed_files(self, file_path):
        self.processed_files.add(file_path)
        logging.info(f"File added to processed set: {file_path}")
        self.save_processed_files()

    def upload_file_multipart(self, file_path, pbar):
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        def upload_progress(chunk):
            with self.tqdm_lock:
                pbar.update(chunk)

        try:
            response = self.s3.create_multipart_upload(Bucket=self.BUCKET_NAME, Key=file_name)
            upload_id = response['UploadId']
        except ClientError as e:
            logging.error(f"Failed to initiate multi-part upload for {file_path}: {e}")
            return False

        parts = []
        part_number = 1
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(5 * 1024 * 1024):  # 5MB chunks
                    part_response = self.s3.upload_part(
                        Bucket=self.BUCKET_NAME, Key=file_name, PartNumber=part_number, UploadId=upload_id, Body=chunk
                    )
                    parts.append({'PartNumber': part_number, 'ETag': part_response['ETag']})
                    upload_progress(len(chunk))
                    part_number += 1

            self.s3.complete_multipart_upload(
                Bucket=self.BUCKET_NAME, Key=file_name, UploadId=upload_id, MultipartUpload={'Parts': parts}
            )
            logging.info(f"Successfully uploaded {file_name} in multi-part")
            self.add_to_processed_files(file_path)
            return True
        except ClientError as e:
            self.s3.abort_multipart_upload(Bucket=self.BUCKET_NAME, Key=file_name, UploadId=upload_id)
            logging.error(f"Failed to upload {file_name} in multi-part: {e}")
            return False


    def should_ignore_file(self, file_path):
        ignored_extensions = ['.log', '.pkl', '.json']
        ignored_files = [self.LOG_FILE, self.PROCESSED_FILES_FILE]
        # Add a check for temporary files
        if os.path.basename(file_path).startswith('.goutputstream-'):
            return True
        if os.path.basename(file_path) in ignored_files:
            return True
        if any(file_path.endswith(ext) for ext in ignored_extensions):
            return True
        return False

    def delete_from_s3(self, file_path, reason="Unspecified"):
        try:
            self.s3.delete_object(Bucket=self.BUCKET_NAME, Key=os.path.relpath(file_path, self.WATCH_FOLDER))
            logging.info(f"Deleted {file_path} from S3 due to: {reason}")
            print(f"Deleted {file_path} from S3 due to: {reason}")
        except ClientError as e:
            logging.error(f"Error deleting {file_path} from S3: {e}")
            print(f"Error deleting {file_path} from S3: {e}")

    def delete_s3_contents(self):
        logging.info("Deleting all contents in the S3 bucket...")
        print("Deleting all contents in the S3 bucket...")  # Added print statement for immediate feedback
        try:
            paginator = self.s3.get_paginator('list_objects_v2')
            pages = paginator.paginate(Bucket=self.BUCKET_NAME)

            # Count the total number of objects in the bucket
            total_objects = 0
            for page in pages:
                if 'Contents' in page:
                    total_objects += len(page['Contents'])

            # Reset the paginator to delete objects
            pages = paginator.paginate(Bucket=self.BUCKET_NAME)

            total_deleted = 0

            with tqdm(total=total_objects, unit='file', desc='Deleting files') as pbar:
                for page in pages:
                    if 'Contents' in page:
                        objects_to_delete = [{'Key': obj['Key']} for obj in page['Contents']]
                        response = self.s3.delete_objects(
                            Bucket=self.BUCKET_NAME,
                            Delete={'Objects': objects_to_delete}
                        )
                        deleted = response.get('Deleted', [])
                        total_deleted += len(deleted)
                        pbar.update(len(deleted))  # Update the progress bar
                    else:
                        logging.info("No objects found in the S3 bucket.")
                        print("No objects found in the S3 bucket.")

            logging.info(f"Total deleted objects: {total_deleted}")
            print(f"Total deleted objects: {total_deleted}")  # Summary of deleted objects

        except ClientError as e:
            logging.error(f"Error deleting contents in the S3 bucket: {e}")
            print(f"Error deleting contents in the S3 bucket: {e}")

    def adjust_batch_size(self, average_speed):
        logging.info(f"Adjusting batch size. Current average speed: {average_speed} B/s")

        if average_speed < self.min_upload_speed / 2:  # Use a lower threshold to avoid rapid decrease
            self.current_batch_size_bytes = max(self.MIN_BATCH_SIZE_BYTES, self.current_batch_size_bytes // 2)
        else:
            self.current_batch_size_bytes = min(self.MAX_BATCH_SIZE_BYTES, self.current_batch_size_bytes * 2)

        logging.info(f"Adjusted batch size to: {self.current_batch_size_bytes / (1024 * 1024)} MB")


    def setup_logging(self):
        log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        log_file = self.LOG_FILE
    
        # Set up a rotating file handler
        handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)  # 10MB per file, keep 5 backups
        handler.setFormatter(log_formatter)
    
        logger = logging.getLogger()
        logger.setLevel(logging.ERROR)  # Set the desired log level here
        logger.addHandler(handler)
    
        logging.info("Logging is set up with rotation.")
        print("Logging is set up with rotation.")


    def load_config(self):
        config = configparser.ConfigParser()
        if os.path.exists(self.CONFIG_FILE):
            config.read(self.CONFIG_FILE)
            if 'DEFAULT' in config and 'WatchFolder' in config['DEFAULT']:
                self.WATCH_FOLDER = config['DEFAULT']['WatchFolder']
        else:
            config['DEFAULT'] = {'WatchFolder': self.WATCH_FOLDER}
            with open(self.CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
        logging.info(f"Configuration loaded. Watching folder: {self.WATCH_FOLDER}")
        print(f"Configuration loaded. Watching folder: {self.WATCH_FOLDER}")

    def create_s3_client(self):
        return boto3.client(
            's3',
            endpoint_url=self.S3_ENDPOINT_URL,
            aws_access_key_id=self.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=self.AWS_SECRET_ACCESS_KEY,
            config=Config(signature_version='s3v4') if not self.S3_USE_PATH_STYLE else None,
            use_ssl=False if self.S3_ENDPOINT_URL.startswith('http://') else True,
            verify=False  # Disable SSL certificate verification
        )

    def is_file_in_queue(self, file_path):
        return any(file_path == item[1] for item in self.file_queue.queue)

    def upload_to_s3(self, file_path, pbar):
        file_name = os.path.basename(file_path)
        file_size = os.path.getsize(file_path)

        def upload_progress(chunk):
            with self.tqdm_lock:
                pbar.update(chunk)

        max_retries = 5
        for attempt in range(max_retries):
            try:
                self.s3.upload_file(file_path, self.BUCKET_NAME, file_name, Callback=upload_progress)
                logging.info(f"Uploaded {file_name} to S3")
                self.add_to_processed_files(file_path)  # Mark as processed immediately after successful upload
                return True
            except ClientError as e:
                logging.error(f"Error uploading {file_name} to S3: {e}, Attempt: {attempt + 1}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                else:
                    logging.error(f"Failed to upload {file_name} after {max_retries} attempts.")
        return False

    def upload_batch_to_s3(self, batch):
        try:
            total_size = sum(os.path.getsize(file_path) for _, file_path in batch if os.path.exists(file_path))
            start_time = time.time()

            with tqdm(total=total_size, unit='B', unit_scale=True, desc='Uploading batch', disable=False) as pbar:
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    futures = {
                        executor.submit(self.upload_file_multipart, file_path, pbar): file_path
                        for _, file_path in batch if os.path.exists(file_path)
                    }
                    for future in concurrent.futures.as_completed(futures):
                        file_path = futures[future]
                        try:
                            future.result()
                            logging.info(f"Uploaded: {file_path}")
                        except Exception as e:
                            logging.error(f"Error uploading {file_path} to S3: {e}")
                            print(f"Error uploading {file_path} to S3: {e}")

            end_time = time.time()
            elapsed_time = end_time - start_time

            min_batch_size_for_speed_calc = 1024 * 1024  # 1 MB
            if total_size >= min_batch_size_for_speed_calc:
                current_speed = total_size / elapsed_time
                self.speeds.append(current_speed)
                if len(self.speeds) > self.speeds_max_length:
                    self.speeds.pop(0)
                average_speed = sum(self.speeds) / len(self.speeds)
                logging.info(f"Average upload speed: {average_speed} B/s")
                self.adjust_batch_size(average_speed)

            logging.info(f"Batch processed. Total size: {total_size} bytes. Queue size: {self.queue_size()}")
            print(f"Batch processed. Total size: {total_size} bytes. Queue size: {self.queue_size()}")
        except Exception as e:
            logging.error(f"Error processing batch: {e}")
            print(f"Error processing batch: {e}")
        finally:
            self.is_batch_processing = False
            logging.info("Batch processing flag reset.")
            print("Batch processing flag reset.")

    class Watcher(FileSystemEventHandler):
        def __init__(self, manager):
            self.manager = manager

        def on_created(self, event):
            if not event.is_directory and not self.manager.should_ignore_file(event.src_path):
                if event.src_path not in self.manager.processed_files:
                    logging.info(f"Detected file creation: {event.src_path}")
                    self.manager.file_queue.put(('upload', event.src_path))

        def on_deleted(self, event):
            if not event.is_directory and not self.manager.should_ignore_file(event.src_path):
                logging.info(f"Detected file deletion: {event.src_path}")
                reason = "File deleted from local folder"
                self.manager.delete_from_s3(event.src_path, reason)  # Pass the reason for deletion
                if event.src_path in self.manager.processed_files:
                    self.manager.processed_files.remove(event.src_path)
                    self.manager.save_processed_files()

        def on_modified(self, event):
            if not event.is_directory and not self.manager.should_ignore_file(event.src_path):
                if event.src_path not in self.manager.processed_files:
                    logging.info(f"Detected file modification: {event.src_path}")
                    self.manager.file_queue.put(('upload', event.src_path))

    def create_folder_if_not_exists(self, folder):
        if not os.path.exists(folder):
            os.makedirs(folder)
            logging.info(f"Folder '{folder}' created")
            print(f"Folder '{folder}' created")

    def save_queue_to_file(self, filename='file_queue.pkl'):
        with open(filename, 'wb') as f:
            pickle.dump(list(self.file_queue.queue), f)

    def load_queue_from_file(self, filename='file_queue.pkl'):
        if os.path.exists(filename):
            try:
                with open(filename, 'rb') as f:
                    for item in pickle.load(f):
                        self.file_queue.put(item)
            except EOFError:
                print(f"File {filename} is empty or corrupted.")
                logging.error(f"File {filename} is empty or corrupted.")

    def handle_file_operations(self):
        print("File operations handler started.")  # Add this line
        while not self.initial_scan_complete.is_set():
            time.sleep(1)  # Wait for initial scan to complete

        while True:
            batch = []
            batch_size_bytes = 0
            while batch_size_bytes < self.current_batch_size_bytes:
                try:
                    operation, file_path = self.file_queue.get(timeout=1)
                    if not os.path.exists(file_path):
                        logging.warning(f"File not found: {file_path}. Skipping.")
                        self.file_queue.task_done()
                        continue
                    file_size = os.path.getsize(file_path)
                    if batch_size_bytes + file_size <= self.current_batch_size_bytes:
                        batch.append((operation, file_path))
                        batch_size_bytes += file_size
                    else:
                        self.file_queue.put((operation, file_path))
                        break
                except Empty:
                    break

            if batch:
                logging.info(f"Processing a batch of size: {len(batch)} files, {batch_size_bytes / (1024 * 1024):.2f} MB")
                print(f"Processing a batch of size: {len(batch)} files, {batch_size_bytes / (1024 * 1024):.2f} MB")
                self.upload_batch_to_s3(batch)
                for operation, file_path in batch:
                    self.file_queue.task_done()
                    logging.info(f"Marked task done for {file_path}")
            else:
                time.sleep(1)  # Sleep for a short duration before checking again

    def process_file_queue(self):
        batch = []
        batch_size_bytes = 0
        while batch_size_bytes < self.current_batch_size_bytes and not self.file_queue.empty():
            action, file_path = self.file_queue.get()
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0

            if file_size + batch_size_bytes <= self.current_batch_size_bytes:
                batch.append((action, file_path))
                batch_size_bytes += file_size
            else:
                self.file_queue.put((action, file_path))  # Re-queue the file for next batch

        if batch:
            self.upload_batch_to_s3(batch)

    def initial_sync(self):
        logging.info("Performing initial synchronization...")
        print("Performing initial synchronization...")

        try:
            paginator = self.s3.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(Bucket=self.BUCKET_NAME)
            s3_files = {}
            for page in page_iterator:
                for obj in page.get('Contents', []):
                    s3_files[obj['Key']] = obj['LastModified']
            logging.debug(f"S3 files detected during initial sync: {s3_files}")
        except ClientError as e:
            logging.error(f"Error listing objects in bucket: {e}")
            print(f"Error listing objects in bucket: {e}")
            s3_files = set()

        local_files_detected = set()
        for root, dirs, files in os.walk(self.WATCH_FOLDER):
            for file_name in files:
                if self.should_ignore_file(file_name):
                    continue  # Skip the ignored files
                file_path = os.path.join(root, file_name)
                rel_file_path = os.path.relpath(file_path, self.WATCH_FOLDER)
                local_files_detected.add(rel_file_path)
                if rel_file_path not in s3_files or file_path not in self.processed_files:
                    self.file_queue.put(('upload', file_path))
                    logging.info(f"Added {file_path} to queue for upload: Not found in S3 or processed files.")

        logging.debug(f"Local files detected during initial sync: {local_files_detected}")
        logging.info("Initial synchronization complete.")
        print("Initial synchronization complete.")
        self.initial_scan_complete.set()

    def clean_soft_delete_folder(self, retention_period_days=30):
        try:
            now = time.time()
            for root, dirs, files in os.walk(self.SOFT_DELETE_FOLDER):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    file_mtime = os.path.getmtime(file_path)
                    if (now - file_mtime) > (retention_period_days * 86400):  # 86400 seconds in a day
                        os.remove(file_path)
                        logging.info(f"Permanently deleted {file_path} from soft delete folder")
                        print(f"Permanently deleted {file_path} from soft delete folder")
        except Exception as e:
            logging.error(f"Error cleaning soft delete folder: {e}")
            print(f"Error cleaning soft delete folder: {e}")

    def start_monitoring(self, folder):
        self.WATCH_FOLDER = folder
        self.create_folder_if_not_exists(self.WATCH_FOLDER)
        self.initial_sync()
        self.observer = Observer()
        self.observer.schedule(self.Watcher(self), path=self.WATCH_FOLDER, recursive=True)
        self.observer.start()
        logging.info(f"Monitoring folder '{self.WATCH_FOLDER}' for changes...")
        print(f"Monitoring folder '{self.WATCH_FOLDER}' for changes...")

        # Start the file operations thread
        file_operations_thread = threading.Thread(target=self.handle_file_operations, daemon=True)
        file_operations_thread.start()
        logging.info("Started file operations thread.")
        print("Started file operations thread.")

        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()
            stop_flask_server(self.flask_process)

    def stop_monitoring(self):
        self.save_queue_to_file()  # Save the queue state on stop
        if self.observer:
            self.observer.stop()
            self.observer.join()
            logging.info("Stopped monitoring")
            print("Stopped monitoring")
        else:
            print("Monitoring is not running")
        if self.flask_process:
            stop_flask_server(self.flask_process)  # Terminate the Flask server process
            logging.info("Flask server stopped")
            print("Flask server stopped")

    def check_status(self):
        if self.observer and self.observer.is_alive():
            print(f"Monitoring folder '{self.WATCH_FOLDER}'")
        else:
            print("Monitoring is not running")

    def update_config(self, folder):
        self.WATCH_FOLDER = folder
        config = configparser.ConfigParser()
        config['DEFAULT'] = {'WatchFolder': self.WATCH_FOLDER}
        with open(self.CONFIG_FILE, 'w') as configfile:
            config.write(configfile)
        print(f"Configuration updated. Monitoring folder set to '{self.WATCH_FOLDER}'")
        if self.observer and self.observer.is_alive():
            self.observer.stop()
            self.observer.join()
            self.observer = Observer()
            self.observer.schedule(self.Watcher(self), path=self.WATCH_FOLDER, recursive=True)
            self.observer.start()
            logging.info(f"Updated monitoring folder to '{self.WATCH_FOLDER}'")
            print(f"Updated monitoring folder to '{self.WATCH_FOLDER}'")

    def view_logs(self):
        with open(self.LOG_FILE, 'r') as log_file:
            logs = log_file.readlines()[-10:]  # Show last 10 log entries
            for log in logs:
                print(log.strip())

def interactive_cli():
    global sync_manager
    parser = argparse.ArgumentParser(description="Interactive CLI for file synchronization")
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    start_parser = subparsers.add_parser('start', help='Start monitoring')
    start_parser.add_argument('--folder', type=str, help='Folder to monitor', default=SyncManager.DEFAULT_WATCH_FOLDER)

    subparsers.add_parser('stop', help='Stop monitoring')
    subparsers.add_parser('status', help='Check status')

    config_parser = subparsers.add_parser('config', help='Update configuration')
    config_parser.add_argument('--folder', type=str, help='Folder to monitor')

    subparsers.add_parser('sync', help='Manual synchronization')
    subparsers.add_parser('logs', help='View recent logs')
    subparsers.add_parser('clear_queue', help='Clear the file queue')
    subparsers.add_parser('clear_processed', help='Clear the processed files record')
    subparsers.add_parser('delete_s3', help='Delete all contents in the S3 bucket')
    list_s3_parser = subparsers.add_parser('list_s3', help='List all contents in the S3 bucket')

    args = parser.parse_args()

    # Initialize SyncManager without dry_run status
    sync_manager = SyncManager()
    print("SyncManager initialized.")

    if args.command is None:
        parser.print_help()
        return

    # Handle the commands
    if args.command == 'start':
        sync_manager.start_monitoring(args.folder if 'folder' in args else sync_manager.WATCH_FOLDER)
    elif args.command == 'stop':
        sync_manager.stop_monitoring()
    elif args.command == 'status':
        sync_manager.check_status()
    elif args.command == 'config':
        if 'folder' in args:
            sync_manager.update_config(args.folder)
    elif args.command == 'sync':
        threading.Thread(target=sync_manager.periodic_sync, daemon=True).start()
    elif args.command == 'logs':
        sync_manager.view_logs()
    elif args.command == 'clear_queue':
        sync_manager.clear_queue()
        print("Queue cleared.")
    elif args.command == 'clear_processed':
        sync_manager.clear_processed_files()
        print("Processed files record cleared.")
    elif args.command == 'delete_s3':
        sync_manager.delete_s3_contents()
        print("All contents in the S3 bucket have been deleted.")
    elif args.command == 'list_s3':
        sync_manager.list_s3_contents()  # This will invoke the new method to list contents

if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_signal)
    interactive_cli()
