# passman

passman is an open-source, minimal password manager built with ruby, it uses aes-256-cbc encryption to securely store passwords and allows users to search, add, and delete passwords, the system relies on a master password and encryption keys to protect the stored data

## features

- add and store passwords securely
- search for passwords by site
- delete saved passwords
- generate random salt for encryption
- generate random passwords
- backup saved passwords
- restore passwords from a backup
- password strenght test
- password tips
- aes-256-cbc encryption
- local file storage (json format)

## showcase
![menu](passmanmenu.png)

## installation

### 1. install ruby

ensure ruby is installed on your system. you can verify it by running:

```bash
ruby --version
```

if ruby is not installed, follow the instructions below for each platform

### 2. clone the repository

clone the passman repository from github:

```bash
git clone https://github.com/saphingus/passman.git
cd passman
```

### 3. install dependencies

install required ruby gems:

```bash
gem install openssl json base64 highline colorize securerandom fileutils zxcvbn tty-prompt
```

### 4. run passman

launch the password manager:

```bash
ruby passman.rb
```

## platform support

linux (including all distros)
for linux distributions (including ubuntu, debian, arch, etc.), follow the steps below:

install ruby:
```bash
sudo apt-get install ruby       # for debian-based distros
sudo pacman -S ruby             # for arch-based distros
sudo dnf install ruby           # for fedora
```

install dependencies:
```bash
gem install openssl json base64 highline colorize securerandom fileutils zxcvbn tty-prompt
```

run passman:
```bash
ruby passman.rb
```

### macOS

for macOS, follow these steps:

install ruby using homebrew:

```bash
brew install ruby
```

### install dependencies:

```bash
gem install openssl json base64 highline colorize securerandom fileutils zxcvbn tty-prompt
```

run passman:

```bash
ruby passman.rb
```

### windows (native installation or wsl)

download and install ruby from rubyinstaller.org

install dependencies:

```bash
gem install openssl json base64 highline colorize securerandom fileutils zxcvbn tty-prompt
```

run passman:

```bash
ruby passman.rb
```

install ruby on wsl:

```bash
sudo apt-get install ruby
```

install dependencies:

```bash
gem install openssl json base64 highline colorize securerandom fileutils zxcvbn tty-prompt
```

run passman:

```bash
ruby passman.rb
```

## contributing
passman is open-source, and contributions are welcome, please fork the repository, create a new branch, and submit a pull request

## license
this project is licensed under the MIT License

## credits
passman is developed and maintained by saphingus, special thanks to anyone who has contributed or provided valuable feedback
