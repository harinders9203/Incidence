import os
import glob
from datetime import datetime

def find_and_print_logs():
    # List of common log file extensions
    log_extensions = ['*.log', '*.txt', '*.log.*']
    found_logs = []
    
    # Search in Windows common log locations
    search_paths = [
        os.environ.get('SYSTEMROOT', 'C:\\Windows'),
        os.environ.get('PROGRAMDATA', 'C:\\ProgramData'),
        os.environ.get('USERPROFILE'),
        'C:\\Logs',
        'C:\\Program Files',
        'C:\\Program Files (x86)'
    ]
    
    print("Searching for log files...")
    
    for path in search_paths:
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for ext in log_extensions:
                    log_pattern = os.path.join(root, ext)
                    found_logs.extend(glob.glob(log_pattern))
    
    if not found_logs:
        print("No log files found.")
        return
        
    print(f"\nFound {len(found_logs)} log files.\n")
    
    for log_file in found_logs:
        try:
            # Get file stats
            file_stats = os.stat(log_file)
            modified_time = datetime.fromtimestamp(file_stats.st_mtime)
            file_size = file_stats.st_size / 1024  # Convert to KB
            
            print(f"\nLog File: {log_file}")
            print(f"Size: {file_size:.2f} KB")
            print(f"Last Modified: {modified_time}")
            print("-" * 80)
            
            # Read and print file contents
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as file:
                print(file.read())
                
        except PermissionError:
            print(f"Permission denied: {log_file}")
        except Exception as e:
            print(f"Error reading {log_file}: {str(e)}")
        
        print("=" * 80 + "\n")

if __name__ == "__main__":
    find_and_print_logs()