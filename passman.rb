require 'openssl'
require 'json'
require 'base64'
require 'highline/import'
require 'colorize'
require 'tty-prompt'

# constants
password_file = 'passwords.json'
algorithm = 'aes-256-cbc'

# encrypt text using the derived key
def encrypt(text, key)
  cipher = OpenSSL::Cipher.new(algorithm).tap(&:encrypt)
  cipher.key = key
  iv = cipher.random_iv
  encrypted = cipher.update(text) + cipher.final
  { iv: Base64.encode64(iv), data: Base64.encode64(encrypted) }
end

# decrypt the encrypted password
def decrypt(enc_hash, key)
  decipher = OpenSSL::Cipher.new(algorithm).tap(&:decrypt)
  decipher.key = key
  decipher.iv = Base64.decode64(enc_hash[:iv])
  decipher.update(Base64.decode64(enc_hash[:data])) + decipher.final
end

# save the encrypted passwords to a file
def save_passwords(data)
  File.write(password_file, JSON.pretty_generate(data))
end

# load passwords from file
def load_passwords
  unless File.exist?(password_file)
    # If the file doesn't exist, create it with an empty array
    save_passwords([])
  end
  JSON.parse(File.read(password_file), symbolize_names: true)
rescue JSON::ParserError => e
  puts "error loading passwords: #{e.message}".colorize(:red)
  []
end

# get the master password (hidden input)
def get_master_password
  master_password = ask("enter your master password: ".colorize(:light_blue)) { |q| q.echo = "." }
  return master_password unless master_password.empty?

  puts "master password cannot be empty, please try again".colorize(:red)
  exit
end

# show loading spinner
def show_loading_spinner
  spinner = ['|', '/', '-', '\\']
  i = 0
  spinner_thread = Thread.new do
    while true
      print "\r#{spinner[i]}"
      i = (i + 1) % spinner.length
      sleep(0.1)
    end
  end
  return spinner_thread
end

# add a new password entry
def add_password(key)
  puts "\n" + "-"*50
  site = ask("enter the site: ".colorize(:light_green))
  username = ask("enter the username: ".colorize(:light_green))
  password = ask("enter the password: ".colorize(:light_green)) { |q| q.echo = "." }

  encrypted_password = encrypt(password, key)
  data = load_passwords
  data << { site: site, username: username, encrypted_password: encrypted_password }

  spinner_thread = show_loading_spinner
  save_passwords(data) # Save immediately after adding
  spinner_thread.kill

  puts "\rpassword saved successfully".colorize(:green)
  puts "-"*50
end

# search for a password by site
def search_passwords(key)
  puts "\n" + "-"*50
  search_term = ask("enter the site to search for: ".colorize(:light_yellow))
  data = load_passwords
  results = data.select { |entry| entry[:site].include?(search_term) }

  if results.empty?
    puts "no results found".colorize(:yellow)
  else
    results.each do |entry|
      decrypted_password = decrypt(entry[:encrypted_password], key)
      puts "\n" + "*"*50
      puts "site: ".colorize(:blue) + entry[:site].colorize(:light_blue)
      puts "username: ".colorize(:blue) + entry[:username].colorize(:cyan)
      puts "password: ".colorize(:blue) + decrypted_password.colorize(:magenta)
      puts "*"*50
    end
  end
end

# generate a new salt
def generate_salt
  salt = OpenSSL::Random.random_bytes(16) # 16-byte salt
  encoded_salt = Base64.encode64(salt)
  puts "\ngenerated salt: ".colorize(:green) + encoded_salt.colorize(:green)
  puts "-"*50
  encoded_salt
end

# delete a password entry
def delete_password(key)
  puts "\n" + "-"*50
  site = ask("enter the site to delete: ".colorize(:light_red))
  data = load_passwords
  entry_to_delete = data.find { |entry| entry[:site] == site }

  if entry_to_delete
    spinner_thread = show_loading_spinner
    data.delete(entry_to_delete)
    save_passwords(data) # Save immediately after deleting
    spinner_thread.kill
    puts "\rpassword deleted successfully".colorize(:red)
  else
    puts "no entry found for that site".colorize(:yellow)
  end
  puts "-"*50
end

# simple scrollable menu using TTY Prompt
def menu
  prompt = TTY::Prompt.new
  choices = [
    { name: "add", value: 1 },
    { name: "search", value: 2 },
    { name: "generate", value: 3 },
    { name: "delete", value: 4 },
    { name: "exit", value: 5 }
  ]

  prompt.select("passman", choices)
end

# Gracefully handle exit to ensure passwords are saved before closing
at_exit do
  save_passwords(load_passwords)
  puts "\ndata saved before exiting".colorize(:green)
end

# main program loop
def main
  master_password = get_master_password
  key = OpenSSL::PKCS5.pbkdf2_hmac(master_password, "", 10000, 32, "sha256")

  loop do
    choice = menu

    case choice
    when 1
      add_password(key)
    when 2
      search_passwords(key)
    when 3
      generate_salt
    when 4
      delete_password(key)
    when 5
      puts "\ngoodbye".colorize(:light_red)
      break
    else
      puts "invalid option, try again".colorize(:red)
    end
  end
end

main
