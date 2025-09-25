import argparse
import sys
from detector import PhishingDetector
from preprocessing import file_checksum, crc32_folder_in_zip

def main():
    parser = argparse.ArgumentParser(description="Phishing Detector")

    parser.add_argument("--mode", "-m", choices=["only", "all"], default="all", required=True,
                        help="Scanning mode: only zip file or all zip files in directory")

    parser.add_argument("--path", "-p", required=True,
                        help="Path to the zip file or directory containing zip files")

    parser.add_argument("--detail", "-d", default=False,
                        help="Print details file name is phishing or non-phishing letters")

    args = parser.parse_args()
    try:
        detector = PhishingDetector()
        if args.mode == "only":
            ph, no_ph, namesPh, namesNoPh = detector.classify_zip(zip_path=args.path)
            print("[*] Mode:", args.mode)
            print("[*] Path to zip file:", args.path)
            print(f"[*] Total phishing letters in {args.path}: {ph}")
            if args.detail and ph > 0:
                print(f"    [**] Phishing letters are:\n    {'\n    '.join(namesPh)}")
            print(f"[*] Total non-phishing letters in {args.path}: {no_ph}")
            if args.detail and no_ph > 0:
                print(f"    [**] Non-phishing letters are:\n    {'\n    '.join(namesNoPh)}")


        else:
            results = detector.classify_all_zips_in_directory(directory_path=args.path)
            print("[*] Mode:", args.mode)
            print("[*] Path to directory with zip files:", args.path)
            for zip_file, (ph, no_ph, namesPh, namesNoPh) in results.items():
                print(f"[*] In {zip_file}: Phishing letters: {ph}, Non-phishing letters: {no_ph}")
                if args.detail:
                    if ph > 0:
                        print(f"    [**] Phishing letters are:\n    {'\n    '.join(namesPh)}")
                    if no_ph > 0:
                        print(f"    [**] Non-phishing letters are:\n    {'\n    '.join(namesNoPh)}")

    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # main()
    Hash1 = crc32_folder_in_zip('test1.zip', 'test1')
    Hash2 = crc32_folder_in_zip('test2.zip', 'test2')
    print(Hash1)
    print(Hash2)






