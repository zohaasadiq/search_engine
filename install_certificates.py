#!/usr/bin/env python3
# Script to install SSL certificates for Python on macOS
import os
import ssl
import subprocess
import sys

def install_certificates():
    """Install certificates for macOS Python."""
    print("Installing SSL certificates for Python...")
    
    # Get the path to the certificate file
    cert_file = os.path.expanduser("~/Library/Python/install_certifi.py")
    
    # Create the certificate installer script
    with open(cert_file, "w") as f:
        f.write("""
import os
import os.path
import ssl
import stat
import subprocess
import sys

STAT_0o775 = (stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR |
               stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
               stat.S_IROTH | stat.S_IXOTH)

def main():
    openssl_dir, openssl_cafile = os.path.split(
        ssl.get_default_verify_paths().openssl_cafile)

    print(" -- pip install --upgrade certifi")
    subprocess.check_call([sys.executable,
        "-E", "-s", "-m", "pip", "install", "--upgrade", "certifi"])

    import certifi

    # move existing certificates aside (if any)
    target_path = os.path.join(openssl_dir, openssl_cafile)
    if os.path.exists(target_path):
        backup_path = target_path + ".old"
        print(f" -- Backing up {target_path} to {backup_path}")
        os.rename(target_path, backup_path)

    # copy certifi's cacert.pem to the standard location
    source_path = certifi.where()
    print(f" -- Copying {source_path} to {target_path}")
    os.symlink(source_path, target_path)

    # update permissions
    print(f" -- Setting permissions on {target_path}")
    os.chmod(target_path, STAT_0o775)
    print(" -- Complete!")

if __name__ == '__main__':
    main()
""")
    
    # Execute the certificate installer script
    subprocess.check_call([sys.executable, cert_file])
    print("SSL certificates installed successfully.")

if __name__ == "__main__":
    install_certificates() 