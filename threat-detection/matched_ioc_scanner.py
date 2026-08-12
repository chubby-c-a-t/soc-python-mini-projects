"""
Matched IoC Scanner
Description: A SOC utility that correlates parallel streams of file hashes
and filenames. It safely calculates boundaries for mismatched data logs, scans for
known malware signatures (IoCs), and isolates orphaned data for separate review.
"""

def scan_matched_files(file_hashes, filenames, signatures):

    flagged_results = []
    clean_results = []
    
    safe_list = min(len(file_hashes), len(filenames))

    leftover_hashes = file_hashes[safe_list:]
    lefover_filenames = filenames[safe_list:]

    for i in range(safe_list):
        is_malicious = False

        for signature in signatures:
            if signature in file_hashes[i] or signature in filenames[i]:
                is_malicious = True
                break
        
        if is_malicious == True:
            flagged_results.append([file_hashes[i], filenames[i]])
        if is_malicious == False:
            clean_results.append([file_hashes[i], filenames[i]])

    return clean_results, flagged_results, leftover_hashes, lefover_filenames

if __name__ == "__main__":
    # MOCK DATA
    raw_hashes = ["a91-safe", "xx-TROJAN-7", "clean-hash-01"]
    raw_filenames = ["notes.txt", "report.txt", "extra.log", "orphaned_file.exe"]
    malware_sigs = ["TROJAN", "WORM", "RANSOM"]

    clean, flagged, un_hashes, un_files = scan_matched_files(raw_hashes, raw_filenames, malware_sigs)

    print("--- THREAT DETECTION RESULTS ---")
    print(f"Flagged Pairs:      {flagged}")
    print(f"Clean Pairs:        {clean}")
    print(f"Orphaned Hashes:    {un_hashes}")
    print(f"Orphaned Filenames: {un_files}")
            