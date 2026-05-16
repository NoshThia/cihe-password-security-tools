import hashlib
import os
import subprocess
import tempfile


HASHCAT_EXE = r"C:\Users\nilap\Downloads\hashcat-7.1.2\hashcat.exe"
HASHCAT_DIR = os.path.dirname(HASHCAT_EXE)


def is_hashcat_available():
    return os.path.exists(HASHCAT_EXE)


def password_exists_in_wordlist(password, wordlist_path):
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                if line.strip() == password:
                    return True
    except Exception:
        return False

    return False


def run_hashcat_demo(password, wordlist_path):
    if not password:
        return {
            "available": is_hashcat_available(),
            "cracked": False,
            "message": "No password provided.",
            "tool": "Hashcat",
            "hash_type": "MD5 demo hash",
            "attack_mode": "Dictionary attack using common_passwords.txt"
        }

    wordlist_path = os.path.abspath(wordlist_path)

    if not is_hashcat_available():
        return {
            "available": False,
            "cracked": False,
            "message": "Hashcat was not found. Check the HASHCAT_EXE path in services/hashcat_demo.py.",
            "tool": "Hashcat",
            "hash_type": "MD5 demo hash",
            "attack_mode": "Dictionary attack using common_passwords.txt"
        }

    if not os.path.exists(wordlist_path):
        return {
            "available": True,
            "cracked": False,
            "message": f"Wordlist not found at: {wordlist_path}",
            "tool": "Hashcat",
            "hash_type": "MD5 demo hash",
            "attack_mode": "Dictionary attack using common_passwords.txt"
        }

    demo_hash = hashlib.md5(password.encode("utf-8")).hexdigest()

    with tempfile.TemporaryDirectory() as temp_dir:
        hash_file = os.path.join(temp_dir, "demo_hash.txt")
        potfile = os.path.join(temp_dir, "hashcat_demo.potfile")
        outfile = os.path.join(temp_dir, "cracked.txt")

        with open(hash_file, "w", encoding="utf-8") as file:
            file.write(demo_hash + "\n")

        try:
            crack_process = subprocess.run(
                [
                    HASHCAT_EXE,
                    "-m", "0",
                    "-a", "0",
                    hash_file,
                    wordlist_path,
                    "--potfile-path", potfile,
                    "--outfile", outfile,
                    "--outfile-format", "2",
                    "--quiet",
                    "--force"
                ],
                cwd=HASHCAT_DIR,
                capture_output=True,
                text=True,
                timeout=30
            )

            cracked_by_hashcat = False

            if os.path.exists(outfile):
                with open(outfile, "r", encoding="utf-8", errors="ignore") as file:
                    cracked_output = file.read().strip()
                    if password in cracked_output:
                        cracked_by_hashcat = True

            wordlist_match = password_exists_in_wordlist(password, wordlist_path)

            if cracked_by_hashcat:
                message = "Hashcat cracked this temporary MD5 hash using common_passwords.txt."
                cracked = True
            elif wordlist_match:
                message = (
                    "The password exists in common_passwords.txt, but Hashcat did not return the cracked result. "
                    "This means the wordlist is correct, but Hashcat may have a runtime/OpenCL issue on this device."
                )
                cracked = True
            else:
                message = "Hashcat did not crack this temporary hash because the password was not found in the wordlist."
                cracked = False

            if crack_process.stderr:
                message += f" Hashcat note: {crack_process.stderr.strip()[:300]}"

            return {
                "available": True,
                "cracked": cracked,
                "message": message,
                "tool": "Hashcat",
                "hash_type": "MD5 demo hash",
                "attack_mode": "Dictionary attack using common_passwords.txt"
            }

        except subprocess.TimeoutExpired:
            return {
                "available": True,
                "cracked": False,
                "message": "Hashcat demo timed out before finishing.",
                "tool": "Hashcat",
                "hash_type": "MD5 demo hash",
                "attack_mode": "Dictionary attack using common_passwords.txt"
            }

        except Exception as e:
            return {
                "available": True,
                "cracked": False,
                "message": f"Hashcat error: {str(e)}",
                "tool": "Hashcat",
                "hash_type": "MD5 demo hash",
                "attack_mode": "Dictionary attack using common_passwords.txt"
            }