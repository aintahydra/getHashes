import os
import argparse
import hashlib
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

class GetHashes:

    def init(self):
        pass

    def is_winex(self, file):
        with open(file, 'rb') as f:
            magic = f.read(2)
        return (magic == b'MZ')
    
    def is_linex(self, file):
        with open(file, 'rb') as f:
            magic = f.read(4)
        return (magic == b'\x7fELF')
    
    def process_or_not(self, fpath, f_filter):
        if f_filter == 'all':
            return True
        elif f_filter == 'xinex':
            return (self.is_winex(fpath) or self.is_linex(fpath))
        elif f_filter == 'winex':
            return self.is_winex(fpath)
        elif f_filter == 'linex':
            return self.is_linex(fpath)
        else:
            return False

    def calc_hashes(self, filepath):
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)
        
        return sha256.hexdigest(), md5.hexdigest(), sha1.hexdigest()
    
    def process_file(self, fpath, f_filter):
        if os.path.isfile(fpath) and self.process_or_not(fpath, f_filter):
            sha256, md5, sha1 = self.calc_hashes(fpath)
            return os.path.basename(fpath), os.path.abspath(fpath), sha256, md5, sha1
        return None

    def process_dir(self, dir, f_recur, f_filter):
        merged_results = []
        with ThreadPoolExecutor() as executor:
            futures = []
            if f_recur:
                for root, _, files in os.walk(dir):
                    for file in files:
                        fpath = os.path.join(root, file)
                        futures.append(executor.submit(self.process_file, fpath, f_filter))
            else:
                for file in os.listdir(dir):
                    fpath = os.path.join(dir, file)
                    futures.append(executor.submit(self.process_file, fpath, f_filter))

            for future in as_completed(futures):
                fres = future.result()
                if fres:
                    merged_results.append(fres)

        return merged_results

    def write_csv(self, results, outfile):
        with open(outfile, 'w', encoding='UTF-8', newline='') as csvfile:
            csvwriter = csv.writer(csvfile)
            csvwriter.writerow(['FILE NAME', 'FILE PATH', 'SHA256', 'MD5', 'SHA1'])
            csvwriter.writerows(results)

    def start(self, dir, frecursive, outfile, f_filter):
        results = self.process_dir(dir, frecursive, f_filter)
        self.write_csv(results, outfile)
        print(f"Done. The Results have been written to {outfile}")

#############################
# main
#############################
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="calculate file hashes(SHA256, MD5, SHA1)")
    parser.add_argument('--dir', required=True, help="directory where files are")
    parser.add_argument('-r', '--recursive', action='store_true', help="run recursively")
    parser.add_argument('-o', '--output', default='file_hashes.csv', help="output file name(.csv)")
    parser.add_argument('--winex', action='store_true', help="get hashes of Windows PE executables only")
    parser.add_argument('--linex', action='store_true', help="get hashes of Linux ELF files only")
    parser.add_argument('--xinex', action='store_true', help="get hashes of Windows PE and Linux ELF files only")

    args = parser.parse_args()

    if args.xinex:
        f_filter = 'xinex'
    elif args.winex:
        f_filter = 'winex'
    elif args.linex:
        f_filter = 'linex'
    else:
        f_filter = 'all'

    g = GetHashes()
    g.start(args.dir, args.recursive, args.output, f_filter)
 
