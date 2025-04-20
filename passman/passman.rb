require 'openssl'
require 'json'
require 'base64'
require 'highline/import'
require 'colorize'
require 'securerandom' # Added to generate random passwords

# simple ascii header with colors
header = <<~HEADER
  #{'[____   __    ___  ___  __  __    __    _  _]'.colorize(:light_cyan)}
  #{'[  _ \\ /__\\  / __)/ __)(  \\/  )  /__\\  ( \\( )]'.colorize(:light_green)}
  #{'[)___//(__)\\ \\__ \\\__ \\ )    (  /(__)\\  )  ( ]'.colorize(:light_yellow)}
  #{'[(__) (__)(__)(___/(___/(_/\\/\\_)(__)(__)(_)\_)]'.colorize(:light_red)}
HEADER

# output header before the rest of the program
puts header

# constants
$passfile = 'passwords.json' # global variable for password file
$algorithm = 'aes-256-cbc'

# encrypt the text using the derived key
def encrypt(text, key)
  cipher = OpenSSL::Cipher.new($algorithm).tap(&:encrypt)
  cipher.key = key
  iv = cipher.random_iv
  encrypted_data = cipher.update(text) + cipher.final
  { iv: Base64.encode64(iv), data: Base64.encode64(encrypted_data) }
end

# decrypt the encrypted password
def decrypt(enc_hash, key)
  decipher = OpenSSL::Cipher.new($algorithm).tap(&:decrypt)
  decipher.key = key
  decipher.iv = Base64.decode64(enc_hash[:iv]) # decode iv properly
  decrypted_data = decipher.update(Base64.decode64(enc_hash[:data])) + decipher.final # decode encrypted data and handle errors

  decrypted_data
rescue OpenSSL::Cipher::CipherError => e
  puts "\n[ - ] error: decryption failed".colorize(:light_red)
  nil
end

# save the encrypted passwords to a file
def save_passwords(data)
  File.write($passfile, JSON.pretty_generate(data))
end

# load passwords from the file
def load_passwords
  return [] unless File.exist?($passfile)
  JSON.parse(File.read($passfile), symbolize_names: true)
rescue JSON::ParserError
  puts "[ - ] error: file format is corrupted".colorize(:light_yellow)
  []
end

# get the master password (hidden input)
def get_master_password
  master_password = ask("[ * ] enter master password: ") { |q| q.echo = "." }
  return master_password unless master_password.empty?

  puts "[ - ] error: master password cannot be empty".colorize(:light_red)
  exit
end

# add a new password entry
def add_password(key)
  site = ask("[ * ] enter site: ") 
  username = ask("[ * ] enter username: ") 
  password = ask("[ * ] enter password: ") { |q| q.echo = "." }

  encrypted_password = encrypt(password, key)
  data = load_passwords
  data << { site: site, username: username, encrypted_password: encrypted_password }
  save_passwords(data)

  puts "\n[ * ] password for #{site} saved".colorize(:light_green)
end

# search for a password by site
def search_passwords(key)
  search_term = ask("[ * ] enter site to search: ") 
  data = load_passwords
  results = data.select { |entry| entry[:site].include?(search_term) }

  if results.empty?
    puts "[ - ] no results found".colorize(:light_yellow)
  else
    results.each do |entry|
      decrypted_password = decrypt(entry[:encrypted_password], key)
      if decrypted_password
        puts "\n[ * ] site: #{entry[:site]}"
        puts "[ * ] username: #{entry[:username]}"
        puts "[ * ] password: #{decrypted_password}"
        puts "[------------------------------]"
      end
    end
  end
end

# generate a random salt
def generate_salt
  salt = OpenSSL::Random.random_bytes(16) # 16-byte salt
  encoded_salt = Base64.encode64(salt)
  puts "\n[ * ] salt: #{encoded_salt}".colorize(:light_green)
  encoded_salt
end

# generate a random password
def generate_password
  password_length = ask("[ * ] enter password length: ").to_i
  if password_length < 6
    puts "[ - ] error: password length must be at least 6 characters".colorize(:light_red)
    return
  end
  password = SecureRandom.alphanumeric(password_length) # Generates a random password
  puts "\n[ * ] generated password: #{password}".colorize(:light_green)
end

# delete a password entry
def delete_password(key)
  site = ask("[ * ] enter site to delete: ")
  data = load_passwords
  entry_to_delete = data.find { |entry| entry[:site] == site }

  if entry_to_delete
    data.delete(entry_to_delete)
    save_passwords(data)
    puts "\n[ * ] password for #{site} has been deleted".colorize(:light_red)
  else
    puts "[ - ] error: no entry found for #{site}".colorize(:light_yellow)
  end
end

# simple menu with actions
def menu
  puts "\n[========================================]"
  puts "[password manager]".center(40).colorize(:light_magenta)
  puts "[========================================]"
  puts "[ [1] ] add new password".colorize(:light_green)
  puts "[ [2] ] search for password".colorize(:light_cyan)
  puts "[ [3] ] generate random salt".colorize(:light_blue)
  puts "[ [4] ] generate random password".colorize(:light_yellow)
  puts "[ [5] ] delete password".colorize(:light_red)
  puts "[ [6] ] exit".colorize(:light_magenta)
  print "\n[ * ] choose option: ".colorize(:white)
end

# ensure passwords are saved when the program exits
at_exit { save_passwords(load_passwords) }

# main program loop
def main
  puts "\n[ * ] welcome to passman - password manager".colorize(:light_green)
  puts "[========================================]"
  master_password = get_master_password
  key = OpenSSL::PKCS5.pbkdf2_hmac(master_password, "", 10000, 32, "sha256")

  loop do
    menu
    choice = gets.chomp.to_i

    case choice
    when 1
      add_password(key)
    when 2
      search_passwords(key)
    when 3
      generate_salt
    when 4
      generate_password
    when 5
      delete_password(key)
    when 6
      puts "\n[ * ] goodbye".colorize(:light_magenta)
      break
    else
      puts "[ - ] error: invalid option".colorize(:light_yellow)
    end
  end
end

main
