# passman

passman is an open-source, minimal password manager built with ruby. it uses aes-256-cbc encryption to securely store passwords and allows users to search, add, and delete passwords. the system relies on a master password and encryption keys to protect the stored data.

## features

- add and store passwords securely
- search for passwords by site
- delete saved passwords
- generate random salt for encryption
- aes-256-cbc encryption
- local file storage (json format)

## installation

### 1. install ruby

ensure ruby is installed on your system. you can verify it by running:

```bash
ruby --version

if ruby is not installed, follow the instructions for your platform:

# install ruby dependencies
gem install openssl json base64 highline colorize

# clone the repository
git clone https://github.com/yourusername/passman.git
cd passman

# run the password manager
ruby passman.rb

disclaimer
this is a personal password manager for local use only. use at your own risk. we are not responsible for data loss or unauthorized access to passwords. ensure you back up your data and follow good security practices.

